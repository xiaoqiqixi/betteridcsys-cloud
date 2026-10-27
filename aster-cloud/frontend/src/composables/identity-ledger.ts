import { ApiError, record } from "../api/client";
import {
  identityActions,
  identityEmail,
  identityID,
  normalizedIdentityEmail,
  sameIdentityIntent,
  validActionIntent,
  validIdentityOperation,
  type IdentityAction,
  type IdentityIntent,
  type IdentityOperation,
} from "../api/identity";

export interface PendingIdentity {
  owner: string;
  key: string;
  action: IdentityAction;
  target: string;
  target_email: string;
  intent: IdentityIntent;
}
export const identityStorageKey = "aster.cloud.identity.pending.v1";
const entryKeys = [
  "owner",
  "key",
  "action",
  "target",
  "target_email",
  "intent",
];
const byteBudget = 1024 * 1024;
const withinBudget = (s: string) =>
  s.length <= byteBudget && new TextEncoder().encode(s).length <= byteBudget;
function validEntry(x: unknown): x is PendingIdentity {
  return (
    record(x) &&
    Object.keys(x).length === entryKeys.length &&
    Object.keys(x).every((k) => entryKeys.includes(k)) &&
    identityID(x.owner) &&
    identityID(x.key) &&
    identityActions.includes(x.action as IdentityAction) &&
    identityEmail(x.target_email) &&
    normalizedIdentityEmail(x.target_email) === x.target_email &&
    validActionIntent(x.action as IdentityAction, x.intent) &&
    (x.action === "identity.user_created"
      ? x.target === x.target_email &&
        normalizedIdentityEmail(x.intent.email!) === x.target_email
      : identityID(x.target))
  );
}
function targetsOverlap(a: PendingIdentity, b: PendingIdentity) {
  return (
    a.owner === b.owner &&
    (a.target === b.target ||
      ((a.action === "identity.user_created" ||
        b.action === "identity.user_created") &&
        a.target_email === b.target_email))
  );
}
export function matchesIdentityReceipt(
  p: PendingIdentity,
  op: IdentityOperation,
) {
  return (
    validEntry(p) &&
    validIdentityOperation(op) &&
    p.key === op.id &&
    p.owner === op.actor_id &&
    p.action === op.action &&
    (p.action === "identity.user_created"
      ? normalizedIdentityEmail(op.intent.email!) === p.target
      : p.target === op.target_id) &&
    p.intent.revision === op.base_revision &&
    sameIdentityIntent(p.intent, op.intent)
  );
}

// Re-read and validate the complete ledger for every operation. Never truncate,
// evict, repair or overwrite malformed uncertainty. Failed setItem also leaves
// the last durable version intact; there is no optimistic in-memory deletion.
export class IdentityLedger {
  constructor(
    private storage: () => Pick<Storage, "getItem" | "setItem"> = () =>
      sessionStorage,
  ) {}
  read(): PendingIdentity[] {
    try {
      const raw = this.storage().getItem(identityStorageKey) ?? "[]";
      if (!withinBudget(raw)) throw new Error();
      const entries: unknown = JSON.parse(raw);
      if (!Array.isArray(entries) || !entries.every(validEntry))
        throw new Error();
      const seen = new Set<string>(),
        targets = new Set<string>(),
        creates = new Set<string>(),
        existingEmails = new Set<string>();
      for (const e of entries) {
        const slot = `${e.owner}:${e.target}`,
          email = `${e.owner}:${e.target_email}`;
        if (
          seen.has(e.key) ||
          targets.has(slot) ||
          creates.has(email) ||
          (e.action === "identity.user_created" && existingEmails.has(email))
        )
          throw new Error();
        seen.add(e.key);
        targets.add(slot);
        if (e.action === "identity.user_created") creates.add(email);
        else existingEmails.add(email);
      }
      return entries;
    } catch {
      throw new ApiError("unavailable", "IDENTITY_STORAGE_BLOCKED");
    }
  }
  private save(entries: PendingIdentity[]) {
    const raw = JSON.stringify(entries);
    if (!withinBudget(raw))
      throw new ApiError("unavailable", "IDENTITY_STORAGE_BLOCKED");
    try {
      this.storage().setItem(identityStorageKey, raw);
    } catch {
      throw new ApiError("unavailable", "IDENTITY_STORAGE_BLOCKED");
    }
  }
  add(p: PendingIdentity) {
    if (!validEntry(p)) throw new ApiError("invalid", "INVALID_INPUT");
    const all = this.read();
    const prior = all.find((v) => targetsOverlap(v, p));
    if (prior) return structuredClone(prior);
    if (all.some((v) => v.key === p.key))
      throw new ApiError("unavailable", "IDENTITY_STORAGE_BLOCKED");
    this.save([...all, structuredClone(p)]);
    return null;
  }
  acknowledge(p: PendingIdentity, op: IdentityOperation) {
    if (!matchesIdentityReceipt(p, op)) return false;
    return this.remove(p);
  }
  // Only call after a matching immutable receipt or an explicit non-commit
  // response to THIS fresh request. A 404, current profile or VM receipt is not
  // proof and has no route to this method through the public UI.
  remove(p: PendingIdentity) {
    const all = this.read(),
      index = all.findIndex(
        (v) =>
          v.key === p.key &&
          v.owner === p.owner &&
          v.target === p.target &&
          v.target_email === p.target_email &&
          v.action === p.action &&
          sameIdentityIntent(v.intent, p.intent),
      );
    if (index < 0) return false;
    all.splice(index, 1);
    this.save(all);
    return true;
  }
}
export const identityLedger = new IdentityLedger();

import { shallowRef } from "vue";
import { ApiError, key32, record, validOperation } from "../api/client";
import { useConsole } from "../context";
import type { Operation } from "../api/types";
import { matchesNetworkIntent, type NetworkKind } from "../api/network";
const bindingKeys = [
  "id",
  "action",
  "instance_id",
  "node_id",
  "artifact_id",
  "target_node_id",
  "actor_id",
] as const;
type OperationBinding = Record<(typeof bindingKeys)[number], string>;
interface OperationIntent {
  action?: string;
  instanceId?: string;
  nodeId?: string;
  artifactId?: string;
  targetNodeId?: string;
  actorId?: string;
}
function validBinding(value: unknown): value is OperationBinding {
  return (
    record(value) &&
    bindingKeys.every(
      (key) => Object.hasOwn(value, key) && typeof value[key] === "string",
    ) &&
    /^[a-f0-9]{32}$/.test(value.id as string) &&
    ["action", "instance_id", "node_id", "actor_id"].every(
      (key) => value[key] !== "",
    )
  );
}
function copyBinding(value: OperationBinding): OperationBinding {
  return Object.fromEntries(
    bindingKeys.map((key) => [key, value[key]]),
  ) as OperationBinding;
}
function matchesBinding(value: unknown, binding: OperationBinding) {
  return (
    validBinding(value) &&
    bindingKeys.every((key) => value[key] === binding[key])
  );
}
const progressed = (state: string) =>
  ["sending", "dispatched", "uncertain", "succeeded", "rejected"].includes(
    state,
  );
interface Pending {
  owner: string;
  fingerprint: string;
  key: string;
  purpose?: "creation" | "dispatch" | "reconcile" | "other";
  binding?: OperationBinding;
}
const ledger = new Map<string, Pending>();
// Bound the serialized uncertainty, not the number of operations performed.
// Never evict an unresolved intent to make room for another write.
const ledgerBudget = 1024 * 1024;
function withinBudget(raw: string) {
  return (
    raw.length <= ledgerBudget &&
    new TextEncoder().encode(raw).byteLength <= ledgerBudget
  );
}
let loaded = false;
function loadLedger() {
  if (loaded) return true;
  try {
    const raw = sessionStorage.getItem("aster.cloud.pending.v1");
    if (raw !== null && !withinBudget(raw)) return false;
    const value: unknown = raw === null ? [] : JSON.parse(raw);
    if (!Array.isArray(value)) return false;
    const next = new Map<string, Pending>();
    for (const p of value) {
      if (
        !record(p) ||
        typeof p.owner !== "string" ||
        p.owner.length === 0 ||
        typeof p.fingerprint !== "string" ||
        typeof p.key !== "string" ||
        !/^[a-f0-9]{64}$/.test(p.fingerprint) ||
        !/^[a-f0-9]{32}$/.test(p.key) ||
        (Object.hasOwn(p, "purpose") &&
          !["creation", "dispatch", "reconcile", "other"].includes(
            p.purpose as string,
          )) ||
        (Object.hasOwn(p, "binding") &&
          (!validBinding(p.binding) || p.binding.id !== p.key))
      )
        return false;
      const slot = `${p.owner}:${p.fingerprint}`;
      if (next.has(slot)) return false;
      next.set(slot, {
        owner: p.owner,
        fingerprint: p.fingerprint,
        key: p.key,
        ...(Object.hasOwn(p, "purpose")
          ? { purpose: p.purpose as Pending["purpose"] }
          : {}),
        ...(validBinding(p.binding) ? { binding: copyBinding(p.binding) } : {}),
      });
    }
    // Restore only after EVERY entry passes. A corrupt tail cannot silently
    // discard prior uncertainty, nor can a duplicate replace its original key.
    ledger.clear();
    for (const [slot, entry] of next) ledger.set(slot, entry);
    loaded = true;
    return true;
  } catch {
    // Do not overwrite unknown entries that could not be read. A later attempt
    // must successfully reload the original ledger before any write is sent.
    return false;
  }
}
function saveLedger(next: Map<string, Pending>) {
  if (!loaded) return false;
  try {
    const raw = JSON.stringify([...next.values()]);
    if (!withinBudget(raw)) return false;
    sessionStorage.setItem("aster.cloud.pending.v1", raw);
    // Commit memory only after persistence. Failed inserts were never sent;
    // failed removals retain the original uncertainty in both stores.
    ledger.clear();
    for (const [slot, entry] of next) ledger.set(slot, entry);
    return true;
  } catch {
    return false;
  }
}
function removePending(slot: string) {
  const next = new Map(ledger);
  next.delete(slot);
  return saveLedger(next);
}
// Legacy identity writes shared this opaque ledger with other operations.
// Their fingerprints cannot be mapped back to an account or reconciled using
// the new receipt protocol. Preserve them and fail closed, rather than permit
// a changed reason/revision to bypass an unknown pre-upgrade write.
export function legacyIdentityBarrier(
  owner: string,
): "blocked" | "legacy" | "" {
  try {
    const raw = sessionStorage.getItem("aster.cloud.pending.v1") ?? "[]";
    if (!withinBudget(raw)) return "blocked";
    const value: unknown = JSON.parse(raw);
    if (!Array.isArray(value)) return "blocked";
    const slots = new Set<string>();
    let barrier = false;
    for (const p of value) {
      if (
        !record(p) ||
        typeof p.owner !== "string" ||
        !p.owner ||
        typeof p.fingerprint !== "string" ||
        !/^[a-f0-9]{64}$/.test(p.fingerprint) ||
        typeof p.key !== "string" ||
        !/^[a-f0-9]{32}$/.test(p.key) ||
        (p.purpose !== undefined &&
          !["creation", "dispatch", "reconcile", "other"].includes(
            p.purpose as string,
          )) ||
        (p.binding !== undefined &&
          (!validBinding(p.binding) || p.binding.id !== p.key))
      )
        return "blocked";
      const slot = `${p.owner}:${p.fingerprint}`;
      if (slots.has(slot)) return "blocked";
      slots.add(slot);
      if (
        p.owner === owner &&
        (!p.purpose || p.purpose === "other") &&
        !p.binding
      )
        barrier = true;
    }
    return barrier ? "legacy" : "";
  } catch {
    return "blocked";
  }
}
// The owner is the requester of this pending write, not necessarily the task's
// immutable creator. Legacy writes without a full binding remain unresolved.
export function acknowledgeOperations(
  owner: string,
  operations: readonly Operation[],
) {
  if (!loadLedger()) return;
  const next = new Map(ledger);
  let changed = false;
  for (const [slot, entry] of ledger) {
    if (entry.owner !== owner) continue;
    const operation = operations.find(
      (value) =>
        validOperation(value) &&
        value.id === entry.key &&
        (entry.purpose === "creation"
          ? value.actor_id === owner
          : (entry.purpose === "dispatch" || entry.purpose === "reconcile") &&
            validBinding(entry.binding) &&
            entry.binding.id === entry.key &&
            matchesBinding(value, entry.binding) &&
            progressed(value.state)),
    );
    if (operation) {
      next.delete(slot);
      changed = true;
    }
  }
  if (changed) saveLedger(next);
}
export async function fingerprint(path: string, body: unknown) {
  // Network inputs are canonical objects; pool address order is set-like at
  // both API boundaries. Do not create another intent after a cosmetic reorder.
  const canonical =
    /^\/networks\/(vpcs|pools|leases)$/.test(path) && record(body)
      ? Object.fromEntries(
          Object.entries(body)
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([k, v]) => [
              k,
              path === "/networks/pools" &&
              k === "addresses" &&
              Array.isArray(v)
                ? [...v].sort()
                : v,
            ]),
        )
      : body;
  const bytes = new TextEncoder().encode(
    JSON.stringify([path, canonical], (key, value) =>
      /^(password|token|csrf_token|secret)$/i.test(key) ? "[private]" : value,
    ),
  );
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(hash)]
    .map((v) => v.toString(16).padStart(2, "0"))
    .join("");
}
// Network reservations are not resource-operation DTOs. Resolve a lost ACK
// only after a read of the original ID matches its complete frozen payload.
export async function acknowledgeNetwork(
  owner: string,
  kind: NetworkKind,
  body: unknown,
  key: string,
  value: unknown,
  isCurrent: () => boolean,
) {
  if (
    !isCurrent() ||
    !loadLedger() ||
    !matchesNetworkIntent(kind, value, key, body)
  )
    return false;
  const path = `/networks/${kind}`,
    digest = await fingerprint(path, body),
    slot = `${owner}:${digest}`;
  const entry = ledger.get(slot);
  if (!isCurrent()) return false;
  if (
    !entry ||
    entry.owner !== owner ||
    entry.key !== key ||
    entry.purpose !== "other"
  )
    return false;
  return removePending(slot);
}
export function useMutation() {
  const { api, session } = useConsole();
  const busy = shallowRef(false),
    error = shallowRef(""),
    pendingKey = shallowRef("");
  loadLedger();
  async function execute<T>(
    method: "POST" | "PATCH",
    path: string,
    body: unknown,
    guard: (x: unknown) => x is T,
    options: {
      key?: string;
      expectedStatus?: number;
      allowUncertainReconcile?: boolean;
      bindOperation?: OperationIntent;
      isCurrent?: () => boolean;
    } = {},
  ): Promise<T | null> {
    if (busy.value) return null;
    const owner = session.user.value?.id,
      identity = session.epoch.value;
    const stillCurrent = () => !options.isCurrent || options.isCurrent();
    if (!owner) {
      error.value = "unauthorized";
      return null;
    }
    busy.value = true;
    error.value = "";
    const {
      key: requestedKey,
      expectedStatus,
      allowUncertainReconcile,
    } = options;
    const operationWrite =
        /^\/operations\/([a-f0-9]{32})\/(dispatch|reconcile)$/.exec(path),
      intent = options.bindOperation ? { ...options.bindOperation } : undefined;
    const candidateBinding = operationWrite && {
      id: requestedKey,
      action: intent?.action,
      instance_id: intent?.instanceId,
      node_id: intent?.nodeId,
      artifact_id: intent?.artifactId,
      target_node_id: intent?.targetNodeId,
      actor_id: intent?.actorId,
    };
    const binding = validBinding(candidateBinding)
      ? copyBinding(candidateBinding)
      : undefined;
    try {
      if (!loadLedger()) {
        error.value = "unavailable";
        return null;
      }
      if (
        requestedKey !== undefined &&
        (typeof requestedKey !== "string" ||
          !/^[a-f0-9]{32}$/.test(requestedKey))
      ) {
        // Do not persist an invalid key and rely on the HTTP client to reject
        // it later: failed cleanup would make the durable ledger unreadable.
        error.value = "invalid";
        return null;
      }
      if (
        operationWrite &&
        (method !== "POST" ||
          !binding ||
          binding.id !== operationWrite[1] ||
          !record(body) ||
          Object.keys(body).length !== 0)
      ) {
        error.value = "invalid";
        return null;
      }
      const digest = await fingerprint(path, body),
        slot = `${owner}:${digest}`;
      const prior = ledger.get(slot);
      const allowReconcile =
        allowUncertainReconcile &&
        operationWrite?.[2] === "reconcile" &&
        !!binding &&
        (!prior ||
          (prior.purpose === "reconcile" &&
            prior.owner === owner &&
            prior.key === binding.id &&
            validBinding(prior.binding) &&
            prior.binding.id === prior.key &&
            matchesBinding(prior.binding, binding)));
      if (prior && !allowReconcile) {
        pendingKey.value = prior.key;
        error.value = "unknown";
        return null;
      }
      if (
        identity !== session.epoch.value ||
        session.user.value?.id !== owner ||
        !stillCurrent()
      )
        return null;
      const key = prior?.key || requestedKey || key32();
      const purpose =
        path === "/instances" ||
        /^\/instances\/[a-f0-9]{32}\/operations$/.test(path)
          ? "creation"
          : operationWrite?.[2] === "dispatch"
            ? "dispatch"
            : operationWrite?.[2] === "reconcile"
              ? "reconcile"
              : "other";
      const next = new Map(ledger);
      next.set(slot, {
        owner,
        fingerprint: digest,
        key,
        purpose,
        ...(binding ? { binding } : {}),
      });
      if (!saveLedger(next)) {
        pendingKey.value = prior?.key || "";
        error.value = "unavailable";
        return null;
      }
      pendingKey.value = key;
      try {
        const result = await api.write(
          method,
          path,
          body,
          key,
          guard,
          expectedStatus,
        );
        if (
          binding &&
          (!record(result) ||
            !validOperation(result.operation) ||
            !matchesBinding(result.operation, binding) ||
            !progressed(result.operation.state))
        )
          throw new ApiError("unknown");
        if (
          purpose === "creation" &&
          (!record(result) ||
            !validOperation(result.operation) ||
            result.operation.id !== key ||
            result.operation.actor_id !== owner)
        )
          throw new ApiError("unknown");
        if (intent) {
          if (
            !record(result) ||
            !validOperation(result.operation) ||
            result.operation.id !== key ||
            (intent.action !== undefined &&
              result.operation.action !== intent.action) ||
            (intent.instanceId !== undefined &&
              result.operation.instance_id !== intent.instanceId) ||
            (intent.artifactId !== undefined &&
              result.operation.artifact_id !== intent.artifactId) ||
            (intent.targetNodeId !== undefined &&
              result.operation.target_node_id !== intent.targetNodeId)
          )
            throw new ApiError("unknown");
        }
        if (
          identity !== session.epoch.value ||
          session.user.value?.id !== owner ||
          !stillCurrent()
        )
          return null;
        removePending(slot);
        if (binding && record(result) && validOperation(result.operation))
          acknowledgeOperations(owner, [result.operation]);
        pendingKey.value = ledger.has(slot) ? key : "";
        return result;
      } catch (cause) {
        const kind = cause instanceof ApiError ? cause.kind : "unknown";
        if (
          identity !== session.epoch.value ||
          session.user.value?.id !== owner ||
          !stillCurrent()
        )
          return null;
        if (kind !== "unknown") {
          removePending(slot);
          pendingKey.value = ledger.has(slot) ? key : "";
        }
        if (identity === session.epoch.value) {
          error.value = kind;
          if (kind === "unauthorized") session.invalidate();
        }
        return null;
      }
    } catch {
      error.value = "unavailable";
      return null;
    } finally {
      busy.value = false;
    }
  }
  function clearMessage() {
    if (!busy.value) {
      error.value = "";
      pendingKey.value = "";
    }
  }
  return { busy, error, pendingKey, execute, clearMessage };
}

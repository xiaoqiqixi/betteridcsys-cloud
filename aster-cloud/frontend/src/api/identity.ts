import { record, validUser } from "./client";
import type { User } from "./types";

export const identityID = (x: unknown): x is string =>
  typeof x === "string" && /^[a-f0-9]{32}$/.test(x);
export const identityRevision = (x: unknown): x is number =>
  typeof x === "number" && Number.isSafeInteger(x) && x >= 1;
export const identityActions = [
  "identity.user_created",
  "identity.user_updated",
  "identity.sessions_revoked",
] as const;
export type IdentityAction = (typeof identityActions)[number];
const intentKeys = [
  "email",
  "name",
  "role",
  "enabled",
  "permissions",
  "revision",
  "reason",
  "password_changed",
];
const publicFields = [
  "email",
  "name",
  "role",
  "enabled",
  "permissions",
] as const;
const permissions = [
  "audit.read",
  "instances.dangerous",
  "instances.manage",
  "instances.read",
  "migration.manage",
  "nodes.manage",
  "nodes.read",
  "settings.manage",
  "storage.manage",
  "storage.read",
  "storage.restore",
  "users.manage",
];
export const identityReason = (x: unknown): x is string =>
  typeof x === "string" &&
  x === x.trim() &&
  [...x].length >= 1 &&
  [...x].length <= 500 &&
  !/[\p{Cc}\p{Cs}\u2028\u2029]/u.test(x);
export const identityEmail = (x: unknown): x is string =>
  typeof x === "string" && x.length <= 254 && /^[\x21-\x7e]+@[^\s@]+$/.test(x);
export const normalizedIdentityEmail = (x: string) => x.trim().toLowerCase();
export interface IdentityIntent {
  email?: string;
  name?: string;
  role?: string;
  enabled?: boolean;
  permissions?: string[];
  revision: number;
  reason: string;
  password_changed: boolean;
}
export function validIdentityIntent(x: unknown): x is IdentityIntent {
  return (
    record(x) &&
    Object.keys(x).every((k) => intentKeys.includes(k)) &&
    typeof x.revision === "number" &&
    Number.isSafeInteger(x.revision) &&
    x.revision >= 0 &&
    identityReason(x.reason) &&
    typeof x.password_changed === "boolean" &&
    (!Object.hasOwn(x, "email") || identityEmail(x.email)) &&
    (!Object.hasOwn(x, "name") ||
      (typeof x.name === "string" &&
        x.name.trim() === x.name &&
        [...x.name].length >= 1 &&
        [...x.name].length <= 100 &&
        !/[\u0000\r\n\p{Cs}]/u.test(x.name))) &&
    (!Object.hasOwn(x, "role") ||
      (typeof x.role === "string" &&
        ["admin", "operator", "viewer", "custom"].includes(x.role))) &&
    (!Object.hasOwn(x, "enabled") || typeof x.enabled === "boolean") &&
    (!Object.hasOwn(x, "permissions") ||
      (Array.isArray(x.permissions) &&
        x.permissions.every(
          (v) => typeof v === "string" && permissions.includes(v),
        ) &&
        new Set(x.permissions).size === x.permissions.length))
  );
}
export function validActionIntent(
  action: IdentityAction,
  x: unknown,
): x is IdentityIntent {
  if (!validIdentityIntent(x)) return false;
  if (action === "identity.user_created")
    return (
      x.revision === 0 &&
      x.password_changed &&
      x.email !== undefined &&
      x.name !== undefined &&
      x.role !== undefined &&
      x.enabled === undefined &&
      (x.role === "custom"
        ? x.permissions !== undefined
        : x.permissions === undefined)
    );
  if (!identityRevision(x.revision) || x.revision === Number.MAX_SAFE_INTEGER)
    return false;
  if (action === "identity.sessions_revoked")
    return (
      !x.password_changed && publicFields.every((k) => !Object.hasOwn(x, k))
    );
  return (
    action === "identity.user_updated" &&
    (x.password_changed || publicFields.some((k) => Object.hasOwn(x, k)))
  );
}
export interface IdentityOperation {
  id: string;
  actor_id: string;
  target_id: string;
  action: IdentityAction;
  base_revision: number;
  result_revision: number;
  intent: IdentityIntent;
  request_sha256: string;
  reason: string;
  audit_id: string;
  completed_at: string;
}
const operationKeys = [
  "id",
  "actor_id",
  "target_id",
  "action",
  "base_revision",
  "result_revision",
  "intent",
  "request_sha256",
  "reason",
  "audit_id",
  "completed_at",
];
export function validIdentityOperation(x: unknown): x is IdentityOperation {
  return (
    record(x) &&
    Object.keys(x).length === operationKeys.length &&
    Object.keys(x).every((k) => operationKeys.includes(k)) &&
    identityID(x.id) &&
    identityID(x.actor_id) &&
    identityID(x.target_id) &&
    identityActions.includes(x.action as IdentityAction) &&
    validActionIntent(x.action as IdentityAction, x.intent) &&
    x.base_revision === x.intent.revision &&
    identityRevision(x.result_revision) &&
    x.result_revision === x.intent.revision + 1 &&
    typeof x.request_sha256 === "string" &&
    /^[a-f0-9]{64}$/.test(x.request_sha256) &&
    x.reason === x.intent.reason &&
    typeof x.audit_id === "string" &&
    /^[1-9][0-9]{0,18}$/.test(x.audit_id) &&
    BigInt(x.audit_id) <= 9223372036854775807n &&
    typeof x.completed_at === "string" &&
    /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z$/.test(x.completed_at) &&
    Number.isFinite(Date.parse(x.completed_at))
  );
}
export const identityOperationResponse = (
  x: unknown,
): x is { operation: IdentityOperation } =>
  record(x) &&
  Object.keys(x).length === 1 &&
  validIdentityOperation(x.operation);
export const identityWriteResponse = (
  x: unknown,
): x is { user: User; operation: IdentityOperation } =>
  record(x) &&
  Object.keys(x).length === 2 &&
  validUser(x.user) &&
  validIdentityOperation(x.operation) &&
  x.user.id === x.operation.target_id &&
  x.user.revision === x.operation.result_revision;

// Keep the original public projection, not a digest of credentials. The server
// canonical JSON digest is integrity metadata; semantic matching avoids a
// second, subtly different Go-JSON serializer in the browser.
export function publicIdentityIntent(body: unknown): IdentityIntent | null {
  if (
    !record(body) ||
    Object.keys(body).some(
      (k) => ![...publicFields, "revision", "reason", "password"].includes(k),
    )
  )
    return null;
  const out: Record<string, unknown> = {
    revision: body.revision ?? 0,
    reason: body.reason,
    password_changed: Object.hasOwn(body, "password"),
  };
  for (const k of publicFields) if (Object.hasOwn(body, k)) out[k] = body[k];
  if (Object.hasOwn(body, "password")) {
    if (
      typeof body.password !== "string" ||
      new TextEncoder().encode(body.password).length < 12 ||
      new TextEncoder().encode(body.password).length > 1024
    )
      return null;
    if (
      [out.email, out.name, out.role, out.reason].some(
        (v) => typeof v === "string" && v.includes(body.password as string),
      )
    )
      return null;
  }
  return validIdentityIntent(out) ? structuredClone(out) : null;
}
export function sameIdentityIntent(a: IdentityIntent, b: IdentityIntent) {
  return intentKeys.every(
    (k) =>
      Object.hasOwn(a, k) === Object.hasOwn(b, k) &&
      (k === "permissions"
        ? JSON.stringify(a.permissions) === JSON.stringify(b.permissions)
        : a[k as keyof IdentityIntent] === b[k as keyof IdentityIntent]),
  );
}

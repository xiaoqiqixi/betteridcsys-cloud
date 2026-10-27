import { record } from "./client";
import { ipv4, networkID } from "./network";

export interface PublicIngressRule {
  id: string;
  protocol: "tcp" | "udp" | "icmp";
  source_cidr: string;
  port_start: number;
  port_end: number;
}
export interface PublicIngressPolicy {
  schema: 1;
  instance_id: string;
  owner_ref: string;
  revision: number;
  sha256: string;
  rules: PublicIngressRule[];
  effective_revision: number | null;
  state: "default" | "active" | "pending" | "blocked";
  epoch_id: string;
  operation_id: string;
  bound_resource_id: string;
  legacy_unrestricted: boolean;
  updated_at: string | null;
  supported: boolean;
  unsupported_reason: string;
}
export interface PublicIngressRequest {
  expected_revision: number;
  rules: PublicIngressRule[];
}
export interface PublicIngressOperation {
  id: string;
  actor_id: string;
  action: "public_ingress.update";
  target_instance_id: string;
  request_sha256: string;
  request: PublicIngressRequest;
  result: { policy: PublicIngressPolicy };
  created_at: string;
}
export const ingressRevision = (v: unknown): v is number =>
  typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
const sha = (v: unknown): v is string =>
  typeof v === "string" && /^[a-f0-9]{64}$/.test(v);
const maybeID = (v: unknown): v is string => v === "" || networkID(v);
const time = (v: unknown): v is string =>
  typeof v === "string" && Number.isFinite(Date.parse(v));
export function ingressSource(v: unknown): v is string {
  if (typeof v !== "string") return false;
  const [address, bits, extra] = v.split("/");
  if (
    extra !== undefined ||
    !ipv4(address) ||
    !bits ||
    !/^(?:[0-9]|[12][0-9]|3[0-2])$/.test(bits)
  )
    return false;
  const n = address.split(".").reduce((a, part) => a * 256 + Number(part), 0);
  return n % 2 ** (32 - Number(bits)) === 0;
}
export function validPublicIngressRule(v: unknown): v is PublicIngressRule {
  return (
    record(v) &&
    Object.keys(v).length === 5 &&
    networkID(v.id) &&
    ["tcp", "udp", "icmp"].includes(String(v.protocol)) &&
    ingressSource(v.source_cidr) &&
    ingressRevision(v.port_start) &&
    ingressRevision(v.port_end) &&
    (v.protocol === "icmp"
      ? v.port_start === 0 && v.port_end === 0
      : v.port_start >= 1 && v.port_end <= 65535 && v.port_start <= v.port_end)
  );
}
export const validIngressRules = (v: unknown): v is PublicIngressRule[] =>
  Array.isArray(v) &&
  v.length <= 64 &&
  v.every(validPublicIngressRule) &&
  new Set(v.map((r) => r.id)).size === v.length &&
  new Set(
    v.map((r) =>
      JSON.stringify([r.protocol, r.source_cidr, r.port_start, r.port_end]),
    ),
  ).size === v.length;
export function validPublicIngressPolicy(v: unknown): v is PublicIngressPolicy {
  return (
    record(v) &&
    v.schema === 1 &&
    networkID(v.instance_id) &&
    networkID(v.owner_ref) &&
    ingressRevision(v.revision) &&
    sha(v.sha256) &&
    validIngressRules(v.rules) &&
    (v.revision !== 0 || v.rules.length === 0) &&
    (v.effective_revision === null ||
      (ingressRevision(v.effective_revision) &&
        v.effective_revision <= v.revision)) &&
    ["default", "active", "pending", "blocked"].includes(String(v.state)) &&
    maybeID(v.epoch_id) &&
    maybeID(v.operation_id) &&
    maybeID(v.bound_resource_id) &&
    typeof v.legacy_unrestricted === "boolean" &&
    (v.updated_at === null || time(v.updated_at)) &&
    typeof v.supported === "boolean" &&
    typeof v.unsupported_reason === "string" &&
    /^[A-Z0-9_]{0,80}$/.test(v.unsupported_reason)
  );
}
export const publicIngressPolicyResponse = (
  v: unknown,
): v is { policy: PublicIngressPolicy } =>
  record(v) && validPublicIngressPolicy(v.policy);
export function validPublicIngressRequest(
  v: unknown,
): v is PublicIngressRequest {
  return (
    record(v) &&
    Object.keys(v).length === 2 &&
    ingressRevision(v.expected_revision) &&
    v.expected_revision < Number.MAX_SAFE_INTEGER &&
    validIngressRules(v.rules)
  );
}
export function sameIngressRules(
  a: PublicIngressRule[],
  b: PublicIngressRule[],
) {
  const canonical = (rules: PublicIngressRule[]) =>
    rules
      .map((r) => [r.id, r.protocol, r.source_cidr, r.port_start, r.port_end])
      .sort((a, b) => String(a[0]).localeCompare(String(b[0])));
  return JSON.stringify(canonical(a)) === JSON.stringify(canonical(b));
}
export function validPublicIngressOperation(
  v: unknown,
): v is PublicIngressOperation {
  if (
    !record(v) ||
    !networkID(v.id) ||
    !networkID(v.actor_id) ||
    v.action !== "public_ingress.update" ||
    !networkID(v.target_instance_id) ||
    !sha(v.request_sha256) ||
    !validPublicIngressRequest(v.request) ||
    !record(v.result) ||
    Object.keys(v.result).length !== 1 ||
    !validPublicIngressPolicy(v.result.policy) ||
    !time(v.created_at)
  )
    return false;
  const p = v.result.policy;
  return (
    p.instance_id === v.target_instance_id &&
    p.operation_id === v.id &&
    p.revision === v.request.expected_revision + 1 &&
    sameIngressRules(p.rules, v.request.rules) &&
    p.updated_at !== null &&
    Date.parse(p.updated_at) === Date.parse(v.created_at) &&
    ((p.state === "active" &&
      p.effective_revision === p.revision &&
      p.epoch_id === "" &&
      p.bound_resource_id === "") ||
      (p.state === "pending" &&
        p.effective_revision === null &&
        networkID(p.epoch_id) &&
        networkID(p.bound_resource_id)))
  );
}
export function matchesPublicIngressOperation(
  v: unknown,
  key: string,
  actor: string,
  target: string,
  request: PublicIngressRequest,
): v is PublicIngressOperation {
  return (
    validPublicIngressOperation(v) &&
    v.id === key &&
    v.actor_id === actor &&
    v.target_instance_id === target &&
    v.request.expected_revision === request.expected_revision &&
    sameIngressRules(v.request.rules, request.rules)
  );
}
export function matchesPublicIngressResponse(
  v: unknown,
  key: string,
  actor: string,
  target: string,
  request: PublicIngressRequest,
): v is {
  policy: PublicIngressPolicy;
  operation: PublicIngressOperation;
  replay: boolean;
} {
  return (
    record(v) &&
    typeof v.replay === "boolean" &&
    matchesPublicIngressOperation(v.operation, key, actor, target, request) &&
    validPublicIngressPolicy(v.policy) &&
    samePublicIngressPolicy(v.policy, v.operation.result.policy)
  );
}

export function samePublicIngressPolicy(
  a: PublicIngressPolicy,
  b: PublicIngressPolicy,
) {
  const fields = [
    "schema",
    "instance_id",
    "owner_ref",
    "revision",
    "sha256",
    "effective_revision",
    "state",
    "epoch_id",
    "operation_id",
    "bound_resource_id",
    "legacy_unrestricted",
    "updated_at",
    "supported",
    "unsupported_reason",
  ] as const;
  return (
    fields.every((k) => a[k] === b[k]) && sameIngressRules(a.rules, b.rules)
  );
}

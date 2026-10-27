import { record, validPage } from "./client";
import { ipv4, networkID } from "./network";
import {
  clusterID,
  containsPrefix,
  prefix,
  publicIPv4,
  sha256,
} from "./overlay";
import {
  validPublicIPOptions,
  samePublicIPRequest,
  type PublicIPOptions,
} from "./public-ip";

export type PublicIPResourceMode = "direct" | "floating";
export interface PublicIPResource {
  id: string;
  cluster_id: string;
  pool_id: string;
  owner_ref: string;
  mode: PublicIPResourceMode;
  node_id: string;
  profile_id: string;
  vpc_id: string;
  address: string;
  state: "reserved" | "released";
  binding_state: "unbound" | "pending" | "bound" | "blocked" | "released";
  instance_id: string;
  epoch_id: string;
  operation_id: string;
  binding_generation: number;
  releasable: boolean;
  release_reason: string;
  created_at: string;
  updated_at: string;
}
export interface DirectPublicApproval {
  cluster_id: string;
  node_id: string;
  profile_id: string;
  profile_sha256: string;
  cidr: string;
  gateway_ipv4: string;
  public_ipv4s: string[];
}
export interface PublicIPResourceTarget {
  instance_id: string;
  owner_ref: string;
  node_id: string;
  mode: PublicIPResourceMode;
  vpc_id: string;
  cluster_id: string;
  ipv4: string;
  state: string;
}
export interface PublicIPResourceOptions extends PublicIPOptions {
  direct_approvals: DirectPublicApproval[];
  resource_targets: PublicIPResourceTarget[];
}
export type PublicIPResourceAction =
  | "resource.allocate"
  | "resource.release"
  | "resource.bind"
  | "resource.unbind"
  | "resource.recover";
export interface PublicIPResourceOperation {
  id: string;
  actor_id: string;
  action: PublicIPResourceAction;
  target_resource_id: string;
  resource_id: string;
  request_sha256: string;
  request: Record<string, unknown>;
  result: { resource: PublicIPResource };
  created_at: string;
}
const time = (v: unknown): v is string =>
  typeof v === "string" && Number.isFinite(Date.parse(v));
const unique = <T>(items: T[], key: (value: T) => string) =>
  new Set(items.map(key)).size === items.length;
const maybeID = (v: unknown): v is string => v === "" || networkID(v);
const generation = (v: unknown): v is number =>
  typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
const mode = (v: unknown): v is PublicIPResourceMode =>
  v === "direct" || v === "floating";
const actions: PublicIPResourceAction[] = [
  "resource.allocate",
  "resource.release",
  "resource.bind",
  "resource.unbind",
  "resource.recover",
];
const modeVPC = (m: unknown, v: unknown) =>
  m === "direct" ? v === "" : m === "floating" && networkID(v);

export function validPublicIPResource(v: unknown): v is PublicIPResource {
  return (
    record(v) &&
    [v.id, v.pool_id, v.owner_ref].every(networkID) &&
    [v.cluster_id, v.node_id, v.profile_id].every(clusterID) &&
    mode(v.mode) &&
    modeVPC(v.mode, v.vpc_id) &&
    publicIPv4(v.address) &&
    (v.state === "reserved" || v.state === "released") &&
    ["unbound", "pending", "bound", "blocked", "released"].includes(
      v.binding_state as string,
    ) &&
    maybeID(v.instance_id) &&
    maybeID(v.epoch_id) &&
    maybeID(v.operation_id) &&
    generation(v.binding_generation) &&
    typeof v.releasable === "boolean" &&
    typeof v.release_reason === "string" &&
    time(v.created_at) &&
    time(v.updated_at) &&
    Date.parse(v.updated_at) >= Date.parse(v.created_at) &&
    (v.state !== "released" ||
      (v.binding_state === "released" && !v.releasable)) &&
    (v.binding_state !== "bound" ||
      (v.state === "reserved" && networkID(v.instance_id) && !v.releasable)) &&
    (v.binding_state !== "unbound" || v.instance_id === "") &&
    (!v.releasable || (v.state === "reserved" && v.binding_state === "unbound"))
  );
}
export function validPublicIPResourceTarget(
  v: unknown,
): v is PublicIPResourceTarget {
  return (
    record(v) &&
    [v.instance_id, v.owner_ref].every(networkID) &&
    [v.node_id, v.cluster_id].every(clusterID) &&
    mode(v.mode) &&
    modeVPC(v.mode, v.vpc_id) &&
    (ipv4(v.ipv4) || (v.mode === "direct" && v.ipv4 === "")) &&
    typeof v.state === "string" &&
    v.state.length > 0 &&
    v.state.length <= 64
  );
}
export function validPublicIPResourceOptions(
  v: unknown,
): v is PublicIPResourceOptions {
  return (
    validPublicIPOptions(v) &&
    record(v) &&
    Array.isArray(v.direct_approvals) &&
    v.direct_approvals.length <= 256 &&
    v.direct_approvals.every(
      (p) =>
        record(p) &&
        [p.cluster_id, p.node_id, p.profile_id].every(clusterID) &&
        sha256(p.profile_sha256) &&
        prefix(p.cidr) &&
        Number(p.cidr.split("/")[1]) >= 1 &&
        Number(p.cidr.split("/")[1]) <= 30 &&
        ipv4(p.gateway_ipv4) &&
        containsPrefix(p.cidr, `${p.gateway_ipv4}/32`) &&
        Array.isArray(p.public_ipv4s) &&
        p.public_ipv4s.length > 0 &&
        p.public_ipv4s.length <= 4096 &&
        p.public_ipv4s.every(
          (a) =>
            publicIPv4(a) &&
            a !== p.gateway_ipv4 &&
            containsPrefix(p.cidr as string, `${a}/32`),
        ) &&
        unique(p.public_ipv4s, (a) => a),
    ) &&
    unique(
      v.direct_approvals,
      (p) => `${p.cluster_id}:${p.node_id}:${p.profile_id}`,
    ) &&
    Array.isArray(v.resource_targets) &&
    v.resource_targets.length <= 4096 &&
    v.resource_targets.every(validPublicIPResourceTarget) &&
    unique(v.resource_targets, (p) => `${p.instance_id}:${p.mode}`) &&
    v.approvals.every(
      (p) =>
        !Object.hasOwn(p, "allow_floating_ip") ||
        typeof (p as unknown as Record<string, unknown>).allow_floating_ip ===
          "boolean",
    )
  );
}
export const publicIPResourcePage = (
  v: unknown,
): v is { items: PublicIPResource[]; next_cursor: string | null } =>
  validPage(v, validPublicIPResource) &&
  (v.next_cursor === null || networkID(v.next_cursor)) &&
  v.items.length <= 100 &&
  unique(v.items, (r) => r.id);
export function publicIPResourcePath(
  action: PublicIPResourceAction,
  target: string,
) {
  return action === "resource.allocate"
    ? "/public-ips/resources"
    : `/public-ips/resources/${target}/${action === "resource.bind" ? "binding" : action === "resource.unbind" ? "unbind" : action === "resource.recover" ? "recover" : "release"}`;
}
export function validPublicIPResourceRequest(
  action: PublicIPResourceAction,
  target: string,
  v: unknown,
): v is Record<string, unknown> {
  if (
    !actions.includes(action) ||
    !record(v) ||
    (action === "resource.allocate" ? target !== "" : !networkID(target))
  )
    return false;
  if (action === "resource.release" || action === "resource.unbind")
    return (
      Object.keys(v).length === 1 &&
      generation(v.expected_generation) &&
      (action === "resource.release" ||
        v.expected_generation < Number.MAX_SAFE_INTEGER)
    );
  if (action === "resource.recover")
    return (
      Object.keys(v).length === 2 &&
      generation(v.expected_generation) &&
      v.expected_generation < Number.MAX_SAFE_INTEGER &&
      sha256(v.expected_snapshot_sha256)
    );
  if (action === "resource.bind")
    return (
      (Object.keys(v).length === 2 || Object.keys(v).length === 3) &&
      Object.keys(v).every((k) =>
        [
          "instance_id",
          "expected_generation",
          "expected_ingress_revision",
        ].includes(k),
      ) &&
      networkID(v.instance_id) &&
      generation(v.expected_generation) &&
      v.expected_generation < Number.MAX_SAFE_INTEGER &&
      (!Object.hasOwn(v, "expected_ingress_revision") ||
        generation(v.expected_ingress_revision))
    );
  const keys = [
    "pool_id",
    "owner_ref",
    "mode",
    "node_id",
    "profile_id",
    "vpc_id",
    "address",
  ];
  return (
    Object.keys(v).length === keys.length &&
    keys.every((k) => Object.hasOwn(v, k)) &&
    [v.pool_id, v.owner_ref].every(networkID) &&
    [v.node_id, v.profile_id].every(clusterID) &&
    mode(v.mode) &&
    modeVPC(v.mode, v.vpc_id) &&
    (v.address === "" || publicIPv4(v.address))
  );
}
export function validPublicIPResourceOperation(
  v: unknown,
): v is PublicIPResourceOperation {
  if (
    !record(v) ||
    ![v.id, v.actor_id, v.resource_id].every(networkID) ||
    !actions.includes(v.action as PublicIPResourceAction) ||
    typeof v.target_resource_id !== "string" ||
    !sha256(v.request_sha256) ||
    !time(v.created_at) ||
    !validPublicIPResourceRequest(
      v.action as PublicIPResourceAction,
      v.target_resource_id,
      v.request,
    ) ||
    !record(v.result) ||
    Object.keys(v.result).length !== 1 ||
    !validPublicIPResource(v.result.resource) ||
    v.result.resource.id !== v.resource_id
  )
    return false;
  const r = v.result.resource,
    request = v.request;
  if (Date.parse(r.updated_at) > Date.parse(v.created_at)) return false;
  if (v.action === "resource.allocate")
    return (
      v.target_resource_id === "" &&
      v.resource_id === v.id &&
      ["pool_id", "owner_ref", "mode", "node_id", "profile_id", "vpc_id"].every(
        (k) => request[k] === (r as unknown as Record<string, unknown>)[k],
      ) &&
      (request.address === "" || request.address === r.address) &&
      r.state === "reserved" &&
      r.binding_state === "unbound" &&
      r.binding_generation === 0
    );
  if (v.target_resource_id !== r.id) return false;
  if (v.action === "resource.release")
    return (
      r.state === "released" &&
      r.binding_state === "released" &&
      r.binding_generation === request.expected_generation
    );
  if (v.action === "resource.bind")
    return (
      r.state === "reserved" &&
      r.binding_state === "pending" &&
      r.instance_id === request.instance_id &&
      r.operation_id === v.id &&
      r.binding_generation === Number(request.expected_generation) + 1
    );
  return (
    (v.action !== "resource.recover" ||
      (r.mode === "floating" && networkID(r.epoch_id))) &&
    r.state === "reserved" &&
    r.binding_state === "pending" &&
    r.instance_id === "" &&
    r.operation_id === v.id &&
    r.binding_generation === Number(request.expected_generation) + 1
  );
}
export function matchesPublicIPResourceOperation(
  v: unknown,
  key: string,
  actor: string,
  action: PublicIPResourceAction,
  target: string,
  body: unknown,
): v is PublicIPResourceOperation {
  return (
    validPublicIPResourceOperation(v) &&
    v.id === key &&
    v.actor_id === actor &&
    v.action === action &&
    v.target_resource_id === target &&
    samePublicIPRequest(v.request, body)
  );
}
export function matchesPublicIPResourceResponse(
  v: unknown,
  key: string,
  actor: string,
  action: PublicIPResourceAction,
  target: string,
  body: unknown,
): v is {
  resource: PublicIPResource;
  operation: PublicIPResourceOperation;
  replay: boolean;
} {
  return (
    record(v) &&
    typeof v.replay === "boolean" &&
    matchesPublicIPResourceOperation(
      v.operation,
      key,
      actor,
      action,
      target,
      body,
    ) &&
    validPublicIPResource(v.resource) &&
    samePublicIPRequest(v.resource, v.operation.result.resource)
  );
}
// Targets are convenience metadata, not permission. The backend repeats every
// owner/mode/network/IP check before freezing a binding or migration intent.
export function targetsForPublicIP(
  resource: PublicIPResource,
  options: PublicIPResourceOptions,
) {
  return options.resource_targets.filter(
    (t) =>
      t.owner_ref === resource.owner_ref &&
      t.cluster_id === resource.cluster_id &&
      t.mode === resource.mode &&
      ["created", "running", "shutoff"].includes(t.state) &&
      (resource.mode === "direct"
        ? t.node_id === resource.node_id &&
          (t.ipv4 === resource.address || t.ipv4 === "") &&
          t.state === "shutoff"
        : t.vpc_id === resource.vpc_id),
  );
}

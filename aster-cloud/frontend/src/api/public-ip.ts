import { record, validPage } from "./client";
import { networkID } from "./network";
import {
  clusterID,
  prefix,
  publicIPv4,
  sha256,
  validOverlayVPC,
  containsPrefix,
  type OverlayVPC,
} from "./overlay";
export interface PublicIPPool {
  id: string;
  cluster_id: string;
  name: string;
  cidr: string;
  addresses: string[];
  enabled: boolean;
  created_at: string;
  updated_at: string;
}
export interface PublicIPLease {
  id: string;
  pool_id: string;
  cluster_id: string;
  owner_ref: string;
  vpc_id: string;
  node_id: string;
  profile_id: string;
  address: string;
  state: "reserved" | "released";
  created_at: string;
  updated_at: string;
  binding_state: string;
  releasable: boolean;
  release_reason: string;
}
export interface PublicIPApproval {
  cluster_id: string;
  node_id: string;
  vpc_id: string;
  owner_ref: string;
  profile_id: string;
  profile_sha256: string;
  public_ipv4s: string[];
  allow_internet_egress: boolean;
  allow_floating_ip?: boolean;
}
export interface PublicIPOptions {
  complete: true;
  clusters: { id: string }[];
  approvals: PublicIPApproval[];
  vpcs: OverlayVPC[];
}
export type PublicIPAction =
  | "pool.create"
  | "pool.extend"
  | "pool.state"
  | "lease.allocate"
  | "lease.release";
export interface PublicIPOperation {
  id: string;
  actor_id: string;
  action: PublicIPAction;
  target_resource_id: string;
  resource_id: string;
  request_sha256: string;
  request: Record<string, unknown>;
  result: { pool?: PublicIPPool; lease?: PublicIPLease };
  created_at: string;
}
const time = (v: unknown): v is string =>
  typeof v === "string" && Number.isFinite(Date.parse(v));
const unique = <T>(v: T[], key: (x: T) => string) =>
  new Set(v.map(key)).size === v.length;
const addresses = (v: unknown): v is string[] =>
  Array.isArray(v) &&
  v.length > 0 &&
  v.length <= 4096 &&
  v.every(publicIPv4) &&
  unique(v, (x) => x);
export function validPublicIPPool(v: unknown): v is PublicIPPool {
  return (
    record(v) &&
    networkID(v.id) &&
    clusterID(v.cluster_id) &&
    typeof v.name === "string" &&
    [...v.name].length >= 1 &&
    [...v.name].length <= 80 &&
    prefix(v.cidr) &&
    addresses(v.addresses) &&
    v.addresses.every((ip) => containsPrefix(v.cidr as string, `${ip}/32`)) &&
    typeof v.enabled === "boolean" &&
    time(v.created_at) &&
    time(v.updated_at)
  );
}
export function validPublicIPLease(v: unknown): v is PublicIPLease {
  return (
    record(v) &&
    [v.id, v.pool_id, v.owner_ref, v.vpc_id].every(networkID) &&
    [v.cluster_id, v.node_id, v.profile_id].every(clusterID) &&
    publicIPv4(v.address) &&
    (v.state === "reserved" || v.state === "released") &&
    time(v.created_at) &&
    time(v.updated_at) &&
    typeof v.binding_state === "string" &&
    ["reserved", "bound", "pending", "release_blocked", "released"].includes(
      v.binding_state,
    ) &&
    typeof v.releasable === "boolean" &&
    typeof v.release_reason === "string" &&
    (v.state !== "released" || !v.releasable)
  );
}
export function validPublicIPOptions(v: unknown): v is PublicIPOptions {
  return (
    record(v) &&
    v.complete === true &&
    Array.isArray(v.clusters) &&
    v.clusters.length <= 128 &&
    v.clusters.every((x) => record(x) && clusterID(x.id)) &&
    unique(v.clusters, (x) => x.id) &&
    Array.isArray(v.vpcs) &&
    v.vpcs.length <= 4096 &&
    v.vpcs.every(validOverlayVPC) &&
    unique(v.vpcs, (x) => x.id) &&
    Array.isArray(v.approvals) &&
    v.approvals.length <= 4096 &&
    v.approvals.every(
      (x) =>
        record(x) &&
        [x.cluster_id, x.node_id, x.profile_id].every(clusterID) &&
        [x.vpc_id, x.owner_ref].every(networkID) &&
        sha256(x.profile_sha256) &&
        Array.isArray(x.public_ipv4s) &&
        x.public_ipv4s.every(publicIPv4) &&
        unique(x.public_ipv4s, (ip) => ip) &&
        x.public_ipv4s.length <= 65 &&
        typeof x.allow_internet_egress === "boolean" &&
        (x.allow_floating_ip === undefined ||
          typeof x.allow_floating_ip === "boolean"),
    )
  );
}
export function publicIPPage(kind: "pools" | "leases") {
  return (
    v: unknown,
  ): v is {
    items: (PublicIPPool | PublicIPLease)[];
    next_cursor: string | null;
  } =>
    validPage(v, (x): x is PublicIPPool | PublicIPLease =>
      kind === "pools" ? validPublicIPPool(x) : validPublicIPLease(x),
    ) &&
    (v.next_cursor === null || networkID(v.next_cursor)) &&
    v.items.length <= 100 &&
    unique(v.items, (x) => x.id);
}
export function publicIPPath(action: PublicIPAction, target: string) {
  if (action === "pool.extend") return `/public-ips/pools/${target}/addresses`;
  return action === "pool.create"
    ? "/public-ips/pools"
    : action === "lease.allocate"
      ? "/public-ips/leases"
      : action === "pool.state"
        ? `/public-ips/pools/${target}/state`
        : `/public-ips/leases/${target}/release`;
}
export function validPublicIPRequest(
  action: PublicIPAction,
  target: string,
  v: unknown,
): v is Record<string, unknown> {
  if (!record(v)) return false;
  if (action === "pool.extend")
    return (
      networkID(target) && Object.keys(v).length === 1 && addresses(v.addresses)
    );
  const keys =
    action === "pool.create"
      ? ["cluster_id", "name", "cidr", "addresses", "enabled"]
      : action === "pool.state"
        ? ["enabled"]
        : action === "lease.allocate"
          ? [
              "pool_id",
              "owner_ref",
              "vpc_id",
              "node_id",
              "profile_id",
              "address",
            ]
          : [];
  if (
    Object.keys(v).length !== keys.length ||
    !keys.every((k) => Object.hasOwn(v, k))
  )
    return false;
  if (
    action === "pool.state" || action === "lease.release"
      ? !networkID(target)
      : target !== ""
  )
    return false;
  if (action === "lease.release") return true;
  if (action === "pool.state") return typeof v.enabled === "boolean";
  if (action === "pool.create")
    return (
      clusterID(v.cluster_id) &&
      typeof v.name === "string" &&
      [...v.name].length >= 1 &&
      [...v.name].length <= 80 &&
      !/[\p{Cc}\p{Cf}]/u.test(v.name) &&
      v.name.trim() === v.name &&
      prefix(v.cidr) &&
      !v.cidr.endsWith("/0") &&
      addresses(v.addresses) &&
      v.addresses.every((ip) => containsPrefix(v.cidr as string, `${ip}/32`)) &&
      typeof v.enabled === "boolean"
    );
  return (
    [v.pool_id, v.owner_ref, v.vpc_id].every(networkID) &&
    [v.node_id, v.profile_id].every(clusterID) &&
    (v.address === "" || publicIPv4(v.address))
  );
}
function canonical(v: unknown, key = ""): unknown {
  if (Array.isArray(v))
    return key === "addresses" ? [...v].sort() : v.map((x) => canonical(x));
  return record(v)
    ? Object.fromEntries(
        Object.keys(v)
          .sort()
          .map((k) => [k, canonical(v[k], k)]),
      )
    : v;
}
export function samePublicIPRequest(a: unknown, b: unknown) {
  return JSON.stringify(canonical(a)) === JSON.stringify(canonical(b));
}
export function validPublicIPOperation(v: unknown): v is PublicIPOperation {
  if (
    !record(v) ||
    !networkID(v.id) ||
    !networkID(v.actor_id) ||
    !networkID(v.resource_id) ||
    !sha256(v.request_sha256) ||
    !time(v.created_at) ||
    ![
      "pool.create",
      "pool.extend",
      "pool.state",
      "lease.allocate",
      "lease.release",
    ].includes(v.action as string) ||
    typeof v.target_resource_id !== "string" ||
    !validPublicIPRequest(
      v.action as PublicIPAction,
      v.target_resource_id,
      v.request,
    ) ||
    !record(v.result)
  )
    return false;
  const isPool = String(v.action).startsWith("pool.");
  const result = isPool ? v.result.pool : v.result.lease;
  if (
    !record(result) ||
    Object.keys(v.result).length !== 1 ||
    !record(v.request)
  )
    return false;
  const request = v.request;
  if (
    v.action === "pool.extend" &&
    (!Array.isArray(result.addresses) ||
      !(request.addresses as string[]).every((ip) =>
        (result.addresses as string[]).includes(ip),
      ))
  )
    return false;
  if (
    v.action === "pool.create" &&
    !samePublicIPRequest(
      v.request,
      Object.fromEntries(
        ["cluster_id", "name", "cidr", "addresses", "enabled"].map((k) => [
          k,
          result[k],
        ]),
      ),
    )
  )
    return false;
  if (v.action === "pool.state" && v.request.enabled !== result.enabled)
    return false;
  if (
    v.action === "lease.allocate" &&
    (!["pool_id", "owner_ref", "vpc_id", "node_id", "profile_id"].every(
      (k) => request[k] === result[k],
    ) ||
      (v.request.address !== "" && v.request.address !== result.address) ||
      result.state !== "reserved")
  )
    return false;
  if (v.action === "lease.release" && result.state !== "released") return false;
  return (
    record(result) &&
    (isPool ? validPublicIPPool(result) : validPublicIPLease(result)) &&
    result.id === v.resource_id &&
    (v.target_resource_id
      ? v.target_resource_id === v.resource_id
      : v.id === v.resource_id)
  );
}
export function matchesPublicIPOperation(
  v: unknown,
  key: string,
  actor: string,
  action: PublicIPAction,
  target: string,
  body: unknown,
): v is PublicIPOperation {
  return (
    validPublicIPOperation(v) &&
    v.id === key &&
    v.actor_id === actor &&
    v.action === action &&
    v.target_resource_id === target &&
    samePublicIPRequest(v.request, body)
  );
}
// Bounded convenience only. The server still independently checks every address,
// root approval, CIDR membership, global inventory and active reservations.
export function expandPublicIPRange(first: string, last: string): string[] {
  if (!publicIPv4(first) || !publicIPv4(last)) return [];
  const number = (v: string) =>
    v.split(".").reduce((n, x) => n * 256 + Number(x), 0);
  const start = number(first),
    end = number(last);
  if (end < start || end - start >= 4096) return [];
  const result = Array.from({ length: end - start + 1 }, (_, i) =>
    [24, 16, 8, 0].map((s) => Math.floor((start + i) / 2 ** s) % 256).join("."),
  );
  return result.every(publicIPv4) ? result : [];
}

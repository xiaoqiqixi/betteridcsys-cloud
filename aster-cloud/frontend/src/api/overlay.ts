import {
  ingressRevision,
  validIngressRules,
  type PublicIngressPolicy,
} from "./public-ingress";
import { validPublicIPLease, type PublicIPLease } from "./public-ip";
import { record } from "./client";
import { ipv4, networkID } from "./network";
export const clusterID = (v: unknown): v is string =>
  typeof v === "string" && /^[a-z0-9][a-z0-9_-]{0,63}$/.test(v);
export const sha256 = (v: unknown): v is string =>
  typeof v === "string" && /^[a-f0-9]{64}$/.test(v);
const text = (v: unknown): v is string => typeof v === "string";
const integer = (
  v: unknown,
  min = 0,
  max = Number.MAX_SAFE_INTEGER,
): v is number =>
  typeof v === "number" && Number.isSafeInteger(v) && v >= min && v <= max;
const time = (v: unknown): v is string =>
  text(v) && Number.isFinite(Date.parse(v));
export const prefix = (v: unknown): v is string => {
  if (!text(v)) return false;
  const [ip, bits, extra] = v.split("/");
  if (
    extra !== undefined ||
    !ipv4(ip) ||
    !bits ||
    !/^(?:[0-9]|[12][0-9]|3[0-2])$/.test(bits)
  )
    return false;
  const value = ip.split(".").reduce((n, part) => n * 256 + Number(part), 0);
  return value % 2 ** (32 - Number(bits)) === 0;
};
// Keep this fixed special-use list aligned with the node's public-egress guard.
// Legacy prefix-only NAT may intentionally use a private or benchmark address.
const nonPublicIPv4Prefixes = [
  "0.0.0.0/8",
  "10.0.0.0/8",
  "100.64.0.0/10",
  "127.0.0.0/8",
  "169.254.0.0/16",
  "172.16.0.0/12",
  "192.0.0.0/24",
  "192.0.2.0/24",
  "192.88.99.0/24",
  "192.168.0.0/16",
  "198.18.0.0/15",
  "198.51.100.0/24",
  "203.0.113.0/24",
  "224.0.0.0/4",
  "240.0.0.0/4",
];
export const publicIPv4 = (v: unknown): v is string =>
  ipv4(v) && !nonPublicIPv4Prefixes.some((p) => containsPrefix(p, `${v}/32`));
const privateSubnet = (v: unknown): v is string => {
  if (!prefix(v)) return false;
  const [address, bits] = v.split("/");
  const [a, b] = address!.split(".").map(Number);
  return (
    Number(bits) >= 8 &&
    Number(bits) <= 30 &&
    (a === 10 ||
      (a === 172 && b! >= 16 && b! <= 31) ||
      (a === 192 && b === 168))
  );
};
const array = <T>(
  v: unknown,
  guard: (x: unknown) => x is T,
  max: number,
): v is T[] => Array.isArray(v) && v.length <= max && v.every(guard);
export interface OverlayCluster {
  id: string;
  node_ids: string[];
}
export interface OverlayVPCInput {
  cluster_id: string;
  owner_ref: string;
  name: string;
  cidr: string;
  vni: number;
}
export interface OverlayVPC extends OverlayVPCInput {
  id: string;
  created_at: string;
}
export interface OverlayMemberInput {
  instance_id: string;
  vpc_id: string;
  enabled: boolean;
  reserved: boolean;
}
export interface OverlayMember extends OverlayMemberInput {
  node_id: string;
  interface_id: string;
  owner_ref: string;
  local_vpc_id: string;
  lease_id: string;
  pool_id: string;
  network_sha256: string;
  ipv4: string;
  mac: string;
  inbound_mbps: number;
  outbound_mbps: number;
}
export interface OverlayGateway {
  node_id: string;
  instance_id: string;
  interface_id: string;
  owner_ref: string;
  vpc_id: string;
  ipv4: string;
  mac: string;
  allowed_prefixes: string[];
}
export interface NATForwarding {
  id: string;
  protocol: "tcp" | "udp";
  public_port: number;
  target_instance_id: string;
  target_port: number;
  source_cidr: string;
}
export interface NATPolicy {
  id: string;
  node_id: string;
  vpc_id: string;
  gateway_instance_id: string;
  profile_id: string;
  profile_sha256: string;
  snat_enabled: boolean;
  internet_egress_enabled?: boolean;
  public_ipv4?: string;
  forwardings: NATForwarding[];
}
export interface NATProfile {
  node_id: string;
  vpc_id: string;
  gateway_instance_id: string;
  profile_id: string;
  profile_sha256: string;
  public_ipv4: string;
  public_ipv4s?: string[];
  allow_snat: boolean;
  allow_internet_egress?: boolean;
  allowed_source_cidrs: string[];
  allowed_ports: { protocol: "tcp" | "udp"; start: number; end: number }[];
}
export interface OverlaySelection {
  members: OverlayMemberInput[];
  gateways: OverlayGateway[];
  nat_policies?: NATPolicy[];
}
export interface OverlayEpochInput extends OverlaySelection {
  cluster_id: string;
  expected_epoch: number;
}
export type FloatingIngressPolicy = Pick<
  PublicIngressPolicy,
  "schema" | "instance_id" | "owner_ref" | "revision" | "sha256" | "rules"
>;
export interface FloatingIP {
  resource_id: string;
  node_id: string;
  vpc_id: string;
  owner_ref: string;
  profile_id: string;
  profile_sha256: string;
  gateway_instance_id: string;
  instance_id: string;
  target_ipv4: string;
  public_ipv4: string;
  ingress?: FloatingIngressPolicy;
}
export interface OverlaySnapshot {
  protocol: "aster.overlay/1";
  cluster_id: string;
  epoch: number;
  previous_sha256: string;
  profiles: { node_id: string; profile_id: string; profile_sha256: string }[];
  vpcs: { id: string; owner_ref: string; cidr: string; vni: number }[];
  members: OverlayMember[];
  gateways: OverlayGateway[];
  nat_policies?: NATPolicy[];
  floating_ips?: FloatingIP[];
}
export interface OverlayHead {
  node_id: string;
  cluster_id: string;
  epoch: number;
  snapshot_sha256: string;
}
export interface OverlayEpoch {
  id: string;
  cluster_id: string;
  epoch: number;
  snapshot_sha256: string;
  snapshot: OverlaySnapshot;
  phase: "prepare" | "program" | "release";
  state: "pending" | "uncertain" | "rejected" | "succeeded" | "superseded";
  created_at: string;
  updated_at: string;
  superseded_by: string;
  recovery?: { epoch: number; snapshot_sha256: string; heads: OverlayHead[] };
}
export interface OverlayReceipt {
  protocol: "aster.overlay/1";
  operation_id: string;
  node_id: string;
  cluster_id: string;
  epoch: number;
  phase: OverlayEpoch["phase"];
  snapshot_sha256: string;
  request_sha256: string;
  status: string;
  code: string;
}
export interface OverlayTask {
  operation_id: string;
  epoch_id: string;
  node_id: string;
  phase: OverlayEpoch["phase"];
  state: "pending" | "sending" | "uncertain" | "succeeded" | "rejected";
  request_sha256: string;
  updated_at: string;
  result?: OverlayReceipt;
}
export interface OverlayInstanceOption {
  instance_id: string;
  hostname: string;
  node_id: string;
  owner_ref: string;
  ipv4: string;
  local_vpc_id: string;
  vpc_id: string;
  enabled: boolean;
  reserved: boolean;
  eligible: boolean;
  state: string;
  reason: string;
}
export interface OverlayOptions {
  cluster_id: string;
  profile_migration_required: boolean;
  profile_migration_approved: boolean;
  profiles: OverlaySnapshot["profiles"];
  mappings: { node_id: string; local_vpc_id: string; vpc_id: string }[];
  instances: OverlayInstanceOption[];
  gateways: OverlayGateway[];
  nat_profiles: NATProfile[];
  public_ip_leases?: PublicIPLease[];
  latest_epoch: OverlayEpoch | null;
}
const unique = <T>(v: T[], key: (x: T) => string) =>
  new Set(v.map(key)).size === v.length;
export const validOverlayVPCInput = (v: unknown): v is OverlayVPCInput =>
  record(v) &&
  clusterID(v.cluster_id) &&
  networkID(v.owner_ref) &&
  text(v.name) &&
  v.name.trim() === v.name &&
  [...v.name].length >= 1 &&
  [...v.name].length <= 80 &&
  !/[\p{Cc}\p{Cf}]/u.test(v.name) &&
  privateSubnet(v.cidr) &&
  integer(v.vni, 1, 16777215);
export const validOverlayVPC = (v: unknown): v is OverlayVPC =>
  validOverlayVPCInput(v) && record(v) && networkID(v.id) && time(v.created_at);
export const validMemberInput = (v: unknown): v is OverlayMemberInput =>
  record(v) &&
  networkID(v.instance_id) &&
  networkID(v.vpc_id) &&
  typeof v.enabled === "boolean" &&
  typeof v.reserved === "boolean";
export const validGateway = (v: unknown): v is OverlayGateway =>
  record(v) &&
  clusterID(v.node_id) &&
  [v.instance_id, v.owner_ref, v.vpc_id].every(networkID) &&
  text(v.interface_id) &&
  /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(v.interface_id) &&
  ipv4(v.ipv4) &&
  text(v.mac) &&
  /^(?:[a-f0-9]{2}:){5}[a-f0-9]{2}$/.test(v.mac) &&
  array(v.allowed_prefixes, prefix, 32) &&
  !v.allowed_prefixes.includes("0.0.0.0/0") &&
  unique(v.allowed_prefixes, (x) => x);
export const validMember = (v: unknown): v is OverlayMember =>
  validMemberInput(v) &&
  record(v) &&
  clusterID(v.node_id) &&
  [v.owner_ref, v.local_vpc_id, v.lease_id, v.pool_id].every(networkID) &&
  sha256(v.network_sha256) &&
  text(v.interface_id) &&
  /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(v.interface_id) &&
  ipv4(v.ipv4) &&
  text(v.mac) &&
  /^(?:[a-f0-9]{2}:){5}[a-f0-9]{2}$/.test(v.mac) &&
  integer(v.inbound_mbps, 1, 100000) &&
  integer(v.outbound_mbps, 1, 100000);
const validProfile = (p: unknown): p is OverlaySnapshot["profiles"][number] =>
  record(p) &&
  clusterID(p.node_id) &&
  clusterID(p.profile_id) &&
  sha256(p.profile_sha256);
export function validFloatingIP(v: unknown): v is FloatingIP {
  if (
    !record(v) ||
    !Object.keys(v).every((k) =>
      [
        "resource_id",
        "node_id",
        "vpc_id",
        "owner_ref",
        "profile_id",
        "profile_sha256",
        "gateway_instance_id",
        "instance_id",
        "target_ipv4",
        "public_ipv4",
        "ingress",
      ].includes(k),
    ) ||
    ![
      v.resource_id,
      v.vpc_id,
      v.owner_ref,
      v.gateway_instance_id,
      v.instance_id,
    ].every(networkID) ||
    !clusterID(v.node_id) ||
    !clusterID(v.profile_id) ||
    !sha256(v.profile_sha256) ||
    !ipv4(v.target_ipv4) ||
    !publicIPv4(v.public_ipv4)
  )
    return false;
  if (Object.hasOwn(v, "ingress")) {
    const p = v.ingress;
    if (
      !record(p) ||
      Object.keys(p).length !== 6 ||
      p.schema !== 1 ||
      p.instance_id !== v.instance_id ||
      p.owner_ref !== v.owner_ref ||
      !ingressRevision(p.revision) ||
      !sha256(p.sha256) ||
      !validIngressRules(p.rules) ||
      (p.revision === 0 && p.rules.length !== 0)
    )
      return false;
  }
  return true;
}
function floatingSnapshot(v: OverlaySnapshot): boolean {
  if (v.floating_ips === undefined) return true;
  if (
    !array(v.floating_ips, validFloatingIP, 128) ||
    !unique(v.floating_ips, (f) => f.resource_id) ||
    !unique(v.floating_ips, (f) => f.public_ipv4) ||
    !unique(v.floating_ips, (f) => f.instance_id)
  )
    return false;
  return v.floating_ips.every((f) => {
    const m = v.members.find((m) => m.instance_id === f.instance_id),
      g = v.gateways.find((g) => g.instance_id === f.gateway_instance_id),
      p = v.vpcs.find((p) => p.id === f.vpc_id);
    return (
      !!m &&
      !!g &&
      !!p &&
      m.enabled &&
      !m.reserved &&
      m.owner_ref === f.owner_ref &&
      g.owner_ref === f.owner_ref &&
      p.owner_ref === f.owner_ref &&
      m.vpc_id === f.vpc_id &&
      g.vpc_id === f.vpc_id &&
      g.node_id === f.node_id &&
      m.ipv4 === f.target_ipv4 &&
      !v.nat_policies?.some((n) => n.public_ipv4 === f.public_ipv4)
    );
  });
}
export const validSnapshot = (v: unknown): v is OverlaySnapshot =>
  record(v) &&
  v.protocol === "aster.overlay/1" &&
  clusterID(v.cluster_id) &&
  integer(v.epoch, 1) &&
  (v.epoch === 1 ? v.previous_sha256 === "" : sha256(v.previous_sha256)) &&
  array(v.profiles, validProfile, 32) &&
  v.profiles.length > 0 &&
  unique(v.profiles, (p) => p.node_id) &&
  array(
    v.vpcs,
    (p): p is OverlaySnapshot["vpcs"][number] =>
      record(p) &&
      networkID(p.id) &&
      networkID(p.owner_ref) &&
      privateSubnet(p.cidr) &&
      integer(p.vni, 1, 16777215),
    32,
  ) &&
  v.vpcs.length > 0 &&
  unique(v.vpcs, (p) => p.id) &&
  array(v.members, validMember, 128) &&
  unique(v.members, (p) => p.instance_id) &&
  array(v.gateways, validGateway, 32) &&
  unique(v.gateways, (p) => p.vpc_id) &&
  (v.nat_policies === undefined || array(v.nat_policies, validNATPolicy, 32)) &&
  floatingSnapshot(v as unknown as OverlaySnapshot);
const phase = (v: unknown): v is OverlayEpoch["phase"] =>
  v === "prepare" || v === "program" || v === "release";
const validHead = (v: unknown): v is OverlayHead =>
  record(v) &&
  clusterID(v.node_id) &&
  integer(v.epoch) &&
  (v.epoch === 0
    ? v.cluster_id === "" && v.snapshot_sha256 === ""
    : clusterID(v.cluster_id) && sha256(v.snapshot_sha256));
export const validEpoch = (v: unknown): v is OverlayEpoch =>
  record(v) &&
  networkID(v.id) &&
  clusterID(v.cluster_id) &&
  integer(v.epoch, 1) &&
  sha256(v.snapshot_sha256) &&
  validSnapshot(v.snapshot) &&
  v.snapshot.cluster_id === v.cluster_id &&
  v.snapshot.epoch === v.epoch &&
  phase(v.phase) &&
  text(v.state) &&
  ["pending", "uncertain", "rejected", "succeeded", "superseded"].includes(
    v.state,
  ) &&
  time(v.created_at) &&
  time(v.updated_at) &&
  (v.superseded_by === "" || networkID(v.superseded_by)) &&
  (v.state !== "superseded" || networkID(v.superseded_by)) &&
  (v.recovery === undefined ||
    (record(v.recovery) &&
      integer(v.recovery.epoch, 1) &&
      sha256(v.recovery.snapshot_sha256) &&
      array(v.recovery.heads, validHead, 32)));
export const validTask = (v: unknown): v is OverlayTask =>
  record(v) &&
  networkID(v.operation_id) &&
  networkID(v.epoch_id) &&
  clusterID(v.node_id) &&
  phase(v.phase) &&
  text(v.state) &&
  ["pending", "sending", "uncertain", "succeeded", "rejected"].includes(
    v.state,
  ) &&
  sha256(v.request_sha256) &&
  time(v.updated_at) &&
  (v.result === undefined ||
    (validReceipt(v.result) &&
      v.result.operation_id === v.operation_id &&
      v.result.node_id === v.node_id &&
      v.result.phase === v.phase &&
      v.result.request_sha256 === v.request_sha256));
export const validReceipt = (v: unknown): v is OverlayReceipt =>
  record(v) &&
  v.protocol === "aster.overlay/1" &&
  networkID(v.operation_id) &&
  clusterID(v.node_id) &&
  clusterID(v.cluster_id) &&
  integer(v.epoch, 1) &&
  phase(v.phase) &&
  sha256(v.snapshot_sha256) &&
  sha256(v.request_sha256) &&
  text(v.status) &&
  ["succeeded", "uncertain", "rejected"].includes(v.status) &&
  text(v.code) &&
  /^[A-Z0-9_]{1,80}$/.test(v.code);
export const clusterList = (v: unknown): v is { items: OverlayCluster[] } =>
  record(v) &&
  array(
    v.items,
    (x): x is OverlayCluster =>
      record(x) &&
      clusterID(x.id) &&
      array(x.node_ids, clusterID, 32) &&
      x.node_ids.length > 0 &&
      unique(x.node_ids, (x) => x),
    128,
  ) &&
  unique(v.items, (x) => x.id);
export const vpcList = (v: unknown): v is { items: OverlayVPC[] } =>
  record(v) &&
  array(v.items, validOverlayVPC, 32) &&
  unique(v.items, (x) => x.id);
export const epochList = (
  v: unknown,
): v is { items: OverlayEpoch[]; next_before_epoch: number | null } =>
  record(v) &&
  array(v.items, validEpoch, 20) &&
  unique(v.items, (x) => x.id) &&
  (v.next_before_epoch === null || integer(v.next_before_epoch, 1));
export const epochDetail = (
  v: unknown,
): v is { epoch: OverlayEpoch; tasks: OverlayTask[] } =>
  record(v) &&
  validEpoch(v.epoch) &&
  array(v.tasks, validTask, 96) &&
  unique(v.tasks, (x) => x.node_id + ":" + x.phase) &&
  v.tasks.every(
    (t) =>
      t.epoch_id === (v.epoch as OverlayEpoch).id &&
      (v.epoch as OverlayEpoch).snapshot.profiles.some(
        (p) => p.node_id === t.node_id,
      ) &&
      (!t.result ||
        (t.result.cluster_id === (v.epoch as OverlayEpoch).cluster_id &&
          t.result.epoch === (v.epoch as OverlayEpoch).epoch &&
          t.result.snapshot_sha256 ===
            (v.epoch as OverlayEpoch).snapshot_sha256)),
  );
export const epochResponse = (v: unknown): v is { epoch: OverlayEpoch } =>
  record(v) && validEpoch(v.epoch);
export const overlayOptions = (v: unknown): v is OverlayOptions =>
  record(v) &&
  clusterID(v.cluster_id) &&
  typeof v.profile_migration_required === "boolean" &&
  typeof v.profile_migration_approved === "boolean" &&
  array(v.profiles, validProfile, 32) &&
  array(
    v.mappings,
    (m): m is OverlayOptions["mappings"][number] =>
      record(m) &&
      clusterID(m.node_id) &&
      networkID(m.local_vpc_id) &&
      networkID(m.vpc_id),
    1024,
  ) &&
  array(
    v.instances,
    (x): x is OverlayInstanceOption =>
      record(x) &&
      networkID(x.instance_id) &&
      text(x.hostname) &&
      clusterID(x.node_id) &&
      networkID(x.owner_ref) &&
      ipv4(x.ipv4) &&
      networkID(x.local_vpc_id) &&
      (x.vpc_id === "" || networkID(x.vpc_id)) &&
      typeof x.reserved === "boolean" &&
      typeof x.enabled === "boolean" &&
      typeof x.eligible === "boolean" &&
      text(x.state) &&
      text(x.reason),
    256,
  ) &&
  unique(v.instances, (x) => x.instance_id) &&
  array(v.gateways, validGateway, 32) &&
  array(v.nat_profiles, validNATProfile, 32) &&
  (v.public_ip_leases === undefined ||
    (array(v.public_ip_leases, validPublicIPLease, 4096) &&
      v.public_ip_leases.every(
        (l) => l.state === "reserved" && l.cluster_id === v.cluster_id,
      ) &&
      unique(v.public_ip_leases, (l) => l.address))) &&
  (v.latest_epoch === null || validEpoch(v.latest_epoch));
export function canonicalSelection(v: OverlaySelection): OverlaySelection {
  return {
    members: v.members
      .map((x) => ({
        instance_id: x.instance_id,
        vpc_id: x.vpc_id,
        enabled: x.enabled,
        reserved: x.reserved,
      }))
      .sort((a, b) => a.instance_id.localeCompare(b.instance_id)),
    ...{
      nat_policies: (v.nat_policies || [])
        .map((p) => ({
          id: p.id,
          node_id: p.node_id,
          vpc_id: p.vpc_id,
          gateway_instance_id: p.gateway_instance_id,
          profile_id: p.profile_id,
          profile_sha256: p.profile_sha256,
          snat_enabled: p.snat_enabled,
          ...(p.public_ipv4 ? { public_ipv4: p.public_ipv4 } : {}),
          ...(p.internet_egress_enabled === true
            ? { internet_egress_enabled: true }
            : {}),
          forwardings: p.forwardings
            .map((f) => ({
              id: f.id,
              protocol: f.protocol,
              public_port: f.public_port,
              target_instance_id: f.target_instance_id,
              target_port: f.target_port,
              source_cidr: f.source_cidr.trim(),
            }))
            .sort((a, b) => a.id.localeCompare(b.id)),
        }))
        .sort((a, b) => a.id.localeCompare(b.id)),
    },
    gateways: v.gateways
      .map((x) => ({
        node_id: x.node_id,
        instance_id: x.instance_id,
        interface_id: x.interface_id,
        owner_ref: x.owner_ref,
        vpc_id: x.vpc_id,
        ipv4: x.ipv4,
        mac: x.mac,
        allowed_prefixes: x.allowed_prefixes
          .map((p) => p.trim())
          .filter(Boolean)
          .sort(),
      }))
      .sort((a, b) => a.vpc_id.localeCompare(b.vpc_id)),
  };
}
export function sameSelection(a: OverlaySelection, b: OverlaySelection) {
  return (
    JSON.stringify(canonicalSelection(a)) ===
    JSON.stringify(canonicalSelection(b))
  );
}
export function matchesVPC(
  value: unknown,
  key: string,
  input: OverlayVPCInput,
): value is OverlayVPC {
  return (
    validOverlayVPC(value) &&
    value.id === key &&
    (["cluster_id", "owner_ref", "name", "cidr", "vni"] as const).every(
      (k) => value[k] === input[k],
    )
  );
}
export function matchesEpoch(
  value: unknown,
  key: string,
  input: OverlayEpochInput,
): value is OverlayEpoch {
  return (
    validEpoch(value) &&
    value.id === key &&
    value.cluster_id === input.cluster_id &&
    value.epoch === input.expected_epoch + 1 &&
    value.recovery === undefined &&
    sameSelection(value.snapshot, input)
  );
}

export const validNATForwarding = (v: unknown): v is NATForwarding =>
  record(v) &&
  networkID(v.id) &&
  (v.protocol === "tcp" || v.protocol === "udp") &&
  integer(v.public_port, 1, 65535) &&
  networkID(v.target_instance_id) &&
  integer(v.target_port, 1, 65535) &&
  prefix(v.source_cidr);
export const validNATPolicy = (v: unknown): v is NATPolicy =>
  record(v) &&
  networkID(v.id) &&
  clusterID(v.node_id) &&
  networkID(v.vpc_id) &&
  networkID(v.gateway_instance_id) &&
  clusterID(v.profile_id) &&
  sha256(v.profile_sha256) &&
  typeof v.snat_enabled === "boolean" &&
  (v.public_ipv4 === undefined || publicIPv4(v.public_ipv4)) &&
  (v.internet_egress_enabled === undefined ||
    typeof v.internet_egress_enabled === "boolean") &&
  (v.internet_egress_enabled !== true || v.snat_enabled === true) &&
  array(v.forwardings, validNATForwarding, 128) &&
  unique(v.forwardings, (f) => f.id);
export const validNATProfile = (v: unknown): v is NATProfile =>
  record(v) &&
  clusterID(v.node_id) &&
  networkID(v.vpc_id) &&
  networkID(v.gateway_instance_id) &&
  clusterID(v.profile_id) &&
  sha256(v.profile_sha256) &&
  ipv4(v.public_ipv4) &&
  (v.public_ipv4s === undefined ||
    (array(v.public_ipv4s, publicIPv4, 64) &&
      unique(v.public_ipv4s, (x) => x) &&
      !v.public_ipv4s.includes(v.public_ipv4))) &&
  typeof v.allow_snat === "boolean" &&
  (v.allow_internet_egress === undefined ||
    typeof v.allow_internet_egress === "boolean") &&
  (v.allow_internet_egress !== true || publicIPv4(v.public_ipv4)) &&
  array(v.allowed_source_cidrs, prefix, 32) &&
  array(
    v.allowed_ports,
    (p): p is NATProfile["allowed_ports"][number] =>
      record(p) &&
      (p.protocol === "tcp" || p.protocol === "udp") &&
      integer(p.start, 1, 65535) &&
      integer(p.end, Number(p.start), 65535),
    64,
  );
export function containsPrefix(parent: string, child: string) {
  if (!prefix(parent) || !prefix(child)) return false;
  const [p, pb] = parent.split("/"),
    [c, cb] = child.split("/");
  const ip = (v: string) =>
    v.split(".").reduce((n, x) => n * 256 + Number(x), 0);
  const size = 2 ** (32 - Number(pb));
  return (
    Number(cb) >= Number(pb) &&
    Math.floor(ip(p!) / size) === Math.floor(ip(c!) / size)
  );
}
export function validSelection(
  selection: OverlaySelection,
  options: OverlayOptions,
  recovering = false,
) {
  if (
    !selection.members.every(validMemberInput) ||
    !selection.gateways.every(validGateway) ||
    !unique(selection.members, (m) => m.instance_id) ||
    !unique(selection.gateways, (g) => g.vpc_id)
  )
    return false;
  if (
    !selection.members.every((m) =>
      options.instances.some(
        (i) =>
          i.instance_id === m.instance_id &&
          i.vpc_id === m.vpc_id &&
          i.reserved === m.reserved &&
          (i.eligible ||
            (recovering &&
              [
                "INSTANCE_STATE_UNCONFIRMED",
                "INSTANCE_OPERATION_PENDING",
              ].includes(i.reason) &&
              options.latest_epoch?.snapshot.members.some(
                (old) =>
                  old.instance_id === m.instance_id &&
                  old.vpc_id === m.vpc_id &&
                  old.reserved === m.reserved,
              ))),
      ),
    )
  )
    return false;
  if (
    options.latest_epoch?.snapshot.members.some(
      (old) =>
        options.instances.find((i) => i.instance_id === old.instance_id)
          ?.state !== "deleted" &&
        !selection.members.some((m) => m.instance_id === old.instance_id),
    )
  )
    return false;
  if (
    !selection.gateways.every((g) =>
      options.gateways.some(
        (a) =>
          a.node_id === g.node_id &&
          a.instance_id === g.instance_id &&
          a.vpc_id === g.vpc_id &&
          a.interface_id === g.interface_id &&
          a.owner_ref === g.owner_ref &&
          a.ipv4 === g.ipv4 &&
          a.mac === g.mac &&
          g.allowed_prefixes.every((p) =>
            a.allowed_prefixes.some((allow) => containsPrefix(allow, p)),
          ),
      ),
    )
  )
    return false;
  const policies = selection.nat_policies || [];
  if (
    !policies.every(validNATPolicy) ||
    !unique(policies, (p) => p.vpc_id) ||
    !unique(policies, (p) => p.id)
  )
    return false;
  return policies.every((p) => {
    const approved = options.nat_profiles.find(
      (a) =>
        a.node_id === p.node_id &&
        a.vpc_id === p.vpc_id &&
        a.gateway_instance_id === p.gateway_instance_id &&
        a.profile_id === p.profile_id &&
        a.profile_sha256 === p.profile_sha256,
    );
    if (
      !approved ||
      (p.snat_enabled && !approved.allow_snat) ||
      (p.public_ipv4 !== undefined &&
        ((!approved.public_ipv4s?.includes(p.public_ipv4) &&
          approved.public_ipv4 !== p.public_ipv4) ||
          !options.public_ip_leases?.some(
            (l) =>
              l.state === "reserved" &&
              options.gateways.some(
                (g) =>
                  g.node_id === p.node_id &&
                  g.vpc_id === p.vpc_id &&
                  g.owner_ref === l.owner_ref,
              ) &&
              l.address === p.public_ipv4 &&
              l.node_id === p.node_id &&
              l.vpc_id === p.vpc_id &&
              l.profile_id === p.profile_id &&
              l.cluster_id === options.cluster_id,
          ))) ||
      (p.internet_egress_enabled === true &&
        (approved.allow_internet_egress !== true ||
          !publicIPv4(approved.public_ipv4))) ||
      !selection.gateways.some(
        (g) =>
          g.node_id === p.node_id &&
          g.vpc_id === p.vpc_id &&
          g.instance_id === p.gateway_instance_id,
      ) ||
      !unique(
        p.forwardings,
        (f) => `${f.protocol}:${f.public_port}:${f.source_cidr}`,
      )
    )
      return false;
    return p.forwardings.every(
      (f) =>
        approved.allowed_ports.some(
          (a) =>
            a.protocol === f.protocol &&
            f.public_port >= a.start &&
            f.public_port <= a.end,
        ) &&
        approved.allowed_source_cidrs.some((a) =>
          containsPrefix(a, f.source_cidr),
        ) &&
        selection.gateways.some(
          (g) =>
            g.vpc_id === p.vpc_id &&
            g.allowed_prefixes.some((a) => containsPrefix(a, f.source_cidr)),
        ) &&
        selection.members.some(
          (m) =>
            m.instance_id === f.target_instance_id &&
            m.vpc_id === p.vpc_id &&
            m.enabled,
        ),
    );
  });
}
export function matchesRecovery(
  value: unknown,
  key: string,
  original: OverlayEpoch,
  selection: OverlaySelection,
): value is OverlayEpoch {
  return (
    validEpoch(value) &&
    value.id === key &&
    value.cluster_id === original.cluster_id &&
    value.epoch === original.epoch + 1 &&
    value.snapshot.previous_sha256 === original.snapshot_sha256 &&
    value.recovery?.epoch === original.epoch &&
    value.recovery.snapshot_sha256 === original.snapshot_sha256 &&
    sameSelection(value.snapshot, selection)
  );
}
export const phaseNames: Record<OverlayEpoch["phase"], [string, string]> = {
  prepare: ["隔离与准备", "Fence & prepare"],
  program: ["应用配置", "Apply configuration"],
  release: ["确认并放行", "Confirm & release"],
};

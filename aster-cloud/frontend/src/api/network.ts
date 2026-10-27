import { record, validPage } from "./client";
import type { Page } from "./types";

export type NetworkKind = "vpcs" | "pools" | "leases";
export interface VPC {
  id: string;
  owner_ref: string;
  node_id: string;
  name: string;
  cidr: string;
  vlan_id: number;
  state: "planned";
  created_at: string;
}
export interface IPPool {
  id: string;
  node_id: string;
  vpc_id: string;
  name: string;
  cidr: string;
  gateway: string;
  addresses: string[];
  enabled: boolean;
}
export interface IPLease {
  id: string;
  pool_id: string;
  vpc_id: string;
  node_id: string;
  instance_id: string;
  owner_ref: string;
  address: string;
  state: "reserved";
  created_at: string;
}
export type NetworkRecord = VPC | IPPool | IPLease;
export const networkID = (v: unknown): v is string =>
  typeof v === "string" && /^[a-f0-9]{32}$/.test(v);
const nodeID = (v: unknown): v is string =>
  typeof v === "string" && /^[a-z0-9][a-z0-9_-]{0,63}$/.test(v);
export const ipv4 = (v: unknown): v is string =>
  typeof v === "string" &&
  v.split(".").length === 4 &&
  v
    .split(".")
    .every((part) => /^(0|[1-9][0-9]{0,2})$/.test(part) && Number(part) <= 255);
const cidr = (v: unknown) => {
  if (typeof v !== "string") return false;
  const [address, prefix, extra] = v.split("/");
  return (
    extra === undefined &&
    ipv4(address) &&
    !!prefix &&
    /^(?:[0-9]|[12][0-9]|3[0-2])$/.test(prefix)
  );
};
const name = (v: unknown): v is string =>
  typeof v === "string" && v.length > 0 && v.length <= 256;
const time = (v: unknown): v is string =>
  typeof v === "string" && !Number.isNaN(Date.parse(v));
export const validVPC = (v: unknown): v is VPC =>
  record(v) &&
  networkID(v.id) &&
  networkID(v.owner_ref) &&
  nodeID(v.node_id) &&
  name(v.name) &&
  cidr(v.cidr) &&
  Number.isInteger(v.vlan_id) &&
  (v.vlan_id as number) >= 1 &&
  (v.vlan_id as number) <= 4094 &&
  v.state === "planned" &&
  time(v.created_at);
export const validPool = (v: unknown): v is IPPool =>
  record(v) &&
  networkID(v.id) &&
  nodeID(v.node_id) &&
  (v.vpc_id === "" || networkID(v.vpc_id)) &&
  name(v.name) &&
  cidr(v.cidr) &&
  ipv4(v.gateway) &&
  typeof v.enabled === "boolean" &&
  Array.isArray(v.addresses) &&
  v.addresses.length > 0 &&
  v.addresses.length <= 4096 &&
  v.addresses.every(ipv4) &&
  new Set(v.addresses).size === v.addresses.length;
export const validLease = (v: unknown): v is IPLease =>
  record(v) &&
  [v.id, v.pool_id, v.instance_id, v.owner_ref].every(networkID) &&
  (v.vpc_id === "" || networkID(v.vpc_id)) &&
  nodeID(v.node_id) &&
  ipv4(v.address) &&
  v.state === "reserved" &&
  time(v.created_at);
export function validNetworkRecord(
  kind: NetworkKind,
  v: unknown,
): v is NetworkRecord {
  return kind === "vpcs"
    ? validVPC(v)
    : kind === "pools"
      ? validPool(v)
      : validLease(v);
}
export const networkField = (kind: NetworkKind) =>
  kind === "vpcs" ? "vpc" : kind === "pools" ? "pool" : "lease";
export function networkPage(kind: NetworkKind) {
  return (v: unknown): v is Page<NetworkRecord> =>
    validPage(v, (x): x is NetworkRecord => validNetworkRecord(kind, x)) &&
    (v.next_cursor === null || networkID(v.next_cursor));
}
// A read after a lost acknowledgement must match the *whole original intent*,
// not just its ID. Pool address order is set-like at the database boundary.
export function matchesNetworkIntent(
  kind: NetworkKind,
  value: unknown,
  key: string,
  body: unknown,
): value is NetworkRecord {
  if (!validNetworkRecord(kind, value) || value.id !== key || !record(body))
    return false;
  const keys =
    kind === "vpcs"
      ? ["owner_ref", "node_id", "name", "cidr", "vlan_id"]
      : kind === "pools"
        ? [
            "node_id",
            "vpc_id",
            "name",
            "cidr",
            "gateway",
            "addresses",
            "enabled",
          ]
        : ["pool_id", "instance_id", "owner_ref", "address"];
  if (
    Object.keys(body).length !== keys.length ||
    !keys.every((k) => Object.hasOwn(body, k))
  )
    return false;
  const inputValid =
    kind === "vpcs"
      ? validVPC({
          ...body,
          id: key,
          state: "planned",
          created_at: "2000-01-01T00:00:00Z",
        })
      : kind === "pools"
        ? validPool({ ...body, id: key })
        : networkID(body.pool_id) &&
          networkID(body.instance_id) &&
          networkID(body.owner_ref) &&
          (body.address === "" || ipv4(body.address));
  if (!inputValid) return false;
  const actual = value as unknown as Record<string, unknown>;
  return Object.entries(body).every(([k, expected]) => {
    if (kind === "leases" && k === "address" && expected === "")
      return ipv4(actual.address);
    if (
      k === "addresses" &&
      Array.isArray(expected) &&
      Array.isArray(actual[k])
    )
      return (
        JSON.stringify([...expected].sort()) ===
        JSON.stringify([...(actual[k] as string[])].sort())
      );
    return actual[k] === expected;
  });
}

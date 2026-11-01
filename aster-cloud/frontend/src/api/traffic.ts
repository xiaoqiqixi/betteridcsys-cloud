import { record, validOperation } from "./client";
import type { Operation } from "./types";

export interface TrafficPolicy {
  reset_day: number;
  direction: "in" | "out" | "both";
  limit_bytes: string | null;
  overage_policy: string;
}
export interface TrafficView {
  reset_day_locked: boolean;
  policy: TrafficPolicy;
  rx_bytes: string;
  tx_bytes: string;
  period_start: string;
  period_end: string;
  observed_at: string | null;
  inbound_mbps: number;
  outbound_mbps: number;
  accounting_supported: boolean;
  throttle_supported: boolean;
  suspend_supported: boolean;
  enforcement: Operation | null;
}
export function trafficCounter(x: unknown): x is string {
  return (
    typeof x === "string" &&
    /^(0|[1-9][0-9]{0,19})$/.test(x) &&
    BigInt(x) <= 18446744073709551615n
  );
}
const stamp = (x: unknown): x is string =>
  typeof x === "string" && Number.isFinite(Date.parse(x));
export function validTraffic(x: unknown): x is TrafficView {
  if (
    !record(x) ||
    !record(x.policy) ||
    typeof x.reset_day_locked !== "boolean"
  )
    return false;
  const p = x.policy;
  return (
    Number.isInteger(p.reset_day) &&
    Number(p.reset_day) >= 1 &&
    Number(p.reset_day) <= 31 &&
    ["in", "out", "both"].includes(String(p.direction)) &&
    (p.limit_bytes === null || trafficCounter(p.limit_bytes)) &&
    typeof p.overage_policy === "string" &&
    /^(none|suspend|throttle:[1-9][0-9]{0,5})$/.test(p.overage_policy) &&
    trafficCounter(x.rx_bytes) &&
    trafficCounter(x.tx_bytes) &&
    stamp(x.period_start) &&
    stamp(x.period_end) &&
    (x.observed_at === null || stamp(x.observed_at)) &&
    [x.inbound_mbps, x.outbound_mbps].every(
      (v) => Number.isInteger(v) && Number(v) >= 0 && Number(v) <= 100000,
    ) &&
    [x.accounting_supported, x.throttle_supported, x.suspend_supported].every(
      (v) => typeof v === "boolean",
    ) &&
    (x.enforcement === null || validOperation(x.enforcement))
  );
}
export function trafficGiB(value: string): string {
  const bytes = BigInt(value),
    unit = 1073741824n;
  return `${bytes / unit}.${(((bytes % unit) * 100n) / unit).toString().padStart(2, "0")} GiB`;
}

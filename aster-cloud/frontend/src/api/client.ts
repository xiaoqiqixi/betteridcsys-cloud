import type {
  Action,
  Artifact,
  Audit,
  Instance,
  InstanceDetail,
  InstanceMetrics,
  InstanceObservation,
  Node,
  Operation,
  Page,
  Resources,
  Role,
  Session,
  User,
  UsersResult,
} from "./types";
export type FailureKind =
  | "network"
  | "unknown"
  | "unauthorized"
  | "forbidden"
  | "conflict"
  | "invalid"
  | "unavailable";
export class ApiError extends Error {
  constructor(
    public kind: FailureKind,
    public code = "",
    public status = 0,
  ) {
    super(kind);
    this.name = "ApiError";
  }
}
export const record = (x: unknown): x is Record<string, unknown> =>
  x !== null && typeof x === "object" && !Array.isArray(x);
const text = (x: unknown): x is string => typeof x === "string";
const finite = (x: unknown): x is number =>
  typeof x === "number" && Number.isSafeInteger(x) && x >= 0;
export const validUser = (x: unknown): x is User =>
  record(x) &&
  text(x.id) &&
  text(x.email) &&
  text(x.name) &&
  text(x.role) &&
  typeof x.enabled === "boolean" &&
  finite(x.revision) &&
  x.revision >= 1 &&
  Array.isArray(x.permissions) &&
  x.permissions.every(text);
export const validSession = (x: unknown): x is Session =>
  record(x) &&
  validUser(x.user) &&
  text(x.csrf_token) &&
  x.csrf_token.length > 0;
export const validResources = (x: unknown): x is Resources =>
  record(x) &&
  [
    "cpu_cores",
    "memory_mib",
    "system_disk_gib",
    "data_disk_gib",
    "ipv4_count",
    "ipv6_count",
    "bandwidth_mbps",
    "inbound_bandwidth_mbps",
    "transfer_gib",
  ].every((k) => finite(x[k])) &&
  [
    "image_id",
    "datacenter_id",
    "compute_node_id",
    "node_group_id",
    "system_storage_id",
    "data_storage_id",
    "network_type",
    "traffic_direction",
  ].every((k) => text(x[k]));
export const validInstance = (x: unknown): x is Instance =>
  record(x) &&
  [
    "id",
    "owner_ref",
    "node_id",
    "hostname",
    "state",
    "created_at",
    "updated_at",
  ].every((k) => text(x[k])) &&
  validResources(x.resources);
export const validOperation = (x: unknown): x is Operation =>
  record(x) &&
  [
    "id",
    "instance_id",
    "node_id",
    "action",
    "state",
    "artifact_id",
    "target_node_id",
    "created_at",
    "updated_at",
  ].every((k) => text(x[k]));
export const validArtifact = (x: unknown): x is Artifact =>
  record(x) &&
  ["id", "instance_id", "state", "created_at"].every((k) => text(x[k])) &&
  (x.kind === "snapshot" || x.kind === "backup");
export const validNode = (x: unknown): x is Node =>
  record(x) &&
  text(x.id) &&
  text(x.datacenter_id) &&
  typeof x.online === "boolean" &&
  typeof x.maintenance === "boolean" &&
  (x.heartbeat_at === null || text(x.heartbeat_at)) &&
  [
    "free_cpu",
    "free_memory_mib",
    "free_disk_gib",
    "reserved_cpu",
    "reserved_memory_mib",
    "reserved_disk_gib",
  ].every((k) => finite(x[k]));
export const validAudit = (x: unknown): x is Audit =>
  record(x) &&
  (text(x.id) || finite(x.id)) &&
  (x.source === "identity" || x.source === "resource") &&
  ["actor", "action", "target", "created_at"].every((k) => text(x[k])) &&
  (x.identity_detail === undefined ||
    (x.source === "identity" &&
      record(x.identity_detail) &&
      text(x.identity_detail.operation_id) &&
      /^[a-f0-9]{32}$/.test(x.identity_detail.operation_id) &&
      finite(x.identity_detail.base_revision) &&
      finite(x.identity_detail.result_revision) &&
      x.identity_detail.result_revision ===
        x.identity_detail.base_revision + 1 &&
      text(x.identity_detail.reason) &&
      x.identity_detail.reason.trim() === x.identity_detail.reason &&
      [...x.identity_detail.reason].length >= 1 &&
      [...x.identity_detail.reason].length <= 500 &&
      !/[\p{Cc}\u2028\u2029]/u.test(x.identity_detail.reason)));
export function validPage<T>(
  x: unknown,
  guard: (v: unknown) => v is T,
): x is Page<T> {
  return (
    record(x) &&
    Array.isArray(x.items) &&
    x.items.every(guard) &&
    (x.next_cursor === null || text(x.next_cursor))
  );
}
export const validDetail = (x: unknown): x is InstanceDetail =>
  record(x) &&
  validInstance(x.instance) &&
  Array.isArray(x.operations) &&
  x.operations.every(validOperation) &&
  Array.isArray(x.artifacts) &&
  x.artifacts.every(validArtifact) &&
  Array.isArray(x.migrations) &&
  x.migrations.every(
    (v) =>
      record(v) &&
      [
        "id",
        "instance_id",
        "source_node_id",
        "target_node_id",
        "phase",
        "created_at",
        "updated_at",
      ].every((k) => text(v[k])) &&
      (v.source_retirement_state === undefined ||
        ["required", "pending", "succeeded", "blocked"].includes(
          String(v.source_retirement_state),
        )) &&
      (v.source_retirement_operation_id === undefined ||
        /^[a-f0-9]{32}$/.test(String(v.source_retirement_operation_id))),
  );
export const validObservation = (x: unknown): x is InstanceObservation =>
  record(x) &&
  x.protocol === "aster.node.instance/1" &&
  [
    "node_id",
    "instance_id",
    "owner_ref",
    "hostname",
    "state",
    "ipv4",
    "mac",
    "observed_at",
  ].every((k) => text(x[k])) &&
  /^\d{4}-\d\d-\d\dT/.test(String(x.observed_at)) &&
  Number.isFinite(Date.parse(String(x.observed_at))) &&
  typeof x.source_fenced === "boolean" &&
  typeof x.target_pending === "boolean";
export const observationResponse = (
  x: unknown,
): x is { observation: InstanceObservation } =>
  record(x) && validObservation(x.observation);
const metricCounters = [
  "cpu_time_ns",
  "memory_rss_kib",
  "memory_actual_kib",
  "memory_unused_kib",
  "block_read_bytes",
  "block_write_bytes",
  "network_receive_bytes",
  "network_transmit_bytes",
] as const;
function uint64Counter(value: unknown): value is string | null {
  return (
    value === null ||
    (text(value) &&
      /^(0|[1-9][0-9]{0,19})$/.test(value) &&
      BigInt(value) <= 18446744073709551615n)
  );
}
export function metricObservedNanos(value: unknown): bigint | null {
  if (!text(value)) return null;
  const parts =
    /^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d{1,9}))?Z$/.exec(value);
  if (!parts) return null;
  const year = Number(parts[1]),
    month = Number(parts[2]),
    day = Number(parts[3]),
    hour = Number(parts[4]),
    minute = Number(parts[5]),
    second = Number(parts[6]);
  if (
    year < 1 ||
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > 31 ||
    hour > 23 ||
    minute > 59 ||
    second > 59
  )
    return null;
  // Date.parse normalizes February 30. Check the local calendar separately,
  // including years 1..99, which Date.UTC otherwise maps into 1900..1999.
  const calendar = new Date(0);
  calendar.setUTCFullYear(year, month - 1, day);
  calendar.setUTCHours(hour, minute, second, 0);
  if (!(
    calendar.getUTCFullYear() === year &&
    calendar.getUTCMonth() === month - 1 &&
    calendar.getUTCDate() === day
  ))
    return null;
  return (
    BigInt(calendar.valueOf()) * 1000000n +
    BigInt((parts[7] || "").padEnd(9, "0"))
  );
}
export const validMetrics = (x: unknown): x is InstanceMetrics =>
  record(x) &&
  Object.keys(x).length === 16 &&
  x.protocol === "aster.node.metrics/1" &&
  ["node_id", "instance_id", "owner_ref", "hostname"].every(
    (key) => text(x[key]) && x[key].length > 0,
  ) &&
  text(x.state) &&
  [
    "running",
    "shutoff",
    "paused",
    "in_shutdown",
    "crashed",
    "pmsuspended",
    "idle",
    "blocked",
  ].includes(x.state) &&
  metricObservedNanos(x.observed_at) !== null &&
  finite(x.vcpus) &&
  x.vcpus > 0 &&
  x.vcpus <= 4096 &&
  metricCounters.every((key) => uint64Counter(x[key]));
export function metricsResponse(instance: Instance) {
  // Capture the request's expected identity, never a later mutable page prop.
  const { id, node_id, owner_ref, hostname } = instance,
    vcpus = instance.resources.cpu_cores;
  return (x: unknown): x is { metrics: InstanceMetrics } =>
    record(x) &&
    Object.keys(x).length === 1 &&
    validMetrics(x.metrics) &&
    x.metrics.instance_id === id &&
    x.metrics.node_id === node_id &&
    x.metrics.owner_ref === owner_ref &&
    x.metrics.hostname === hostname &&
    x.metrics.vcpus === vcpus;
}
export const validRoles = (x: unknown): x is { items: Role[] } =>
  record(x) &&
  Array.isArray(x.items) &&
  x.items.every(
    (v) =>
      record(v) &&
      text(v.id) &&
      text(v.name) &&
      Array.isArray(v.permissions) &&
      v.permissions.every(text),
  );
export const validUsers = (x: unknown): x is UsersResult =>
  record(x) &&
  Array.isArray(x.items) &&
  x.items.length <= 100 &&
  x.items.every(validUser) &&
  new Set(x.items.map((item) => item.id)).size === x.items.length &&
  x.limit === 100 &&
  typeof x.truncated_possible === "boolean" &&
  (x.next_cursor === null
    ? !x.truncated_possible
    : typeof x.next_cursor === "string" &&
      x.next_cursor.length <= 512 &&
      /^u1\.[A-Za-z0-9_-]+$/.test(x.next_cursor) &&
      x.items.length === 100 &&
      x.truncated_possible);
export function key32(): string {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return [...b].map((v) => v.toString(16).padStart(2, "0")).join("");
}
export interface ApiClient {
  get<T>(
    path: string,
    guard: (v: unknown) => v is T,
    signal?: AbortSignal,
  ): Promise<T>;
  write<T>(
    method: "POST" | "PATCH",
    path: string,
    body: unknown,
    key: string,
    guard: (v: unknown) => v is T,
    expectedStatus?: number | readonly number[],
  ): Promise<T>;
  setCSRF(value: string): void;
}
export function createApiClient(
  fetcher: typeof fetch = (...args) => fetch(...args),
): ApiClient {
  let csrf = "";
  async function request<T>(
    method: "GET" | "POST" | "PATCH",
    path: string,
    body: unknown,
    key: string,
    guard: (v: unknown) => v is T,
    signal?: AbortSignal,
    expectedStatus?: number | readonly number[],
  ): Promise<T> {
    if (
      !/^\/[a-z0-9/?=&_%.-]+$/i.test(path) ||
      path.includes("..") ||
      path.startsWith("//")
    )
      throw new ApiError("invalid");
    const writing = method !== "GET";
    if (writing && (!csrf || !/^([a-f0-9]{32})$/.test(key)))
      throw new ApiError("invalid");
    const controller = new AbortController();
    const abort = () => controller.abort();
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted) controller.abort();
    const timer = setTimeout(abort, writing ? 30000 : 15000);
    try {
      const response = await fetcher(`/console/v1${path}`, {
        method,
        credentials: "same-origin",
        mode: "same-origin",
        redirect: "error",
        cache: "no-store",
        signal: controller.signal,
        headers: writing
          ? {
              "Content-Type": "application/json",
              "X-CSRF-Token": csrf,
              "Idempotency-Key": key,
            }
          : { Accept: "application/json" },
        ...(writing ? { body: JSON.stringify(body) } : {}),
      });
      if (expectedStatus === 204 && response.status === 204) {
        const data: unknown = {};
        if ((await response.text()) !== "" || !guard(data))
          throw new ApiError(writing ? "unknown" : "invalid");
        return data;
      }
      if (
        !/^application\/json(?:;|$)/i.test(
          response.headers.get("Content-Type") || "",
        )
      )
        throw new ApiError(writing ? "unknown" : "invalid");
      let data: unknown;
      const raw = await response.text();
      if (raw.length > 2 * 1024 * 1024)
        throw new ApiError(writing ? "unknown" : "invalid");
      try {
        data = JSON.parse(raw);
      } catch {
        throw new ApiError(writing ? "unknown" : "invalid");
      }
      if (!response.ok) {
        const code =
          record(data) &&
          record(data.error) &&
          typeof data.error.code === "string" &&
          /^[A-Z0-9_]{1,80}$/.test(data.error.code)
            ? data.error.code
            : "";
        throw new ApiError(
          response.status === 401
            ? "unauthorized"
            : response.status === 403
              ? "forbidden"
              : response.status === 409
                ? "conflict"
                : response.status >= 500
                  ? writing
                    ? "unknown"
                    : "unavailable"
                  : "invalid",
          code,
          response.status,
        );
      }
      if (
        expectedStatus !== undefined &&
        !(typeof expectedStatus === "number"
          ? response.status === expectedStatus
          : expectedStatus.includes(response.status))
      )
        throw new ApiError(writing ? "unknown" : "invalid");
      if (!guard(data)) throw new ApiError(writing ? "unknown" : "invalid");
      return data;
    } catch (error) {
      if (error instanceof ApiError) throw error;
      throw new ApiError(writing ? "unknown" : "network");
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
    }
  }
  return {
    get: (p, g, s) => request("GET", p, undefined, "", g, s),
    write: (m, p, b, k, g, status) => request(m, p, b, k, g, undefined, status),
    setCSRF: (v) => {
      csrf = v;
    },
  };
}
export const operationResponse = (x: unknown): x is { operation: Operation } =>
  record(x) && validOperation(x.operation);
export const userResponse = (x: unknown): x is { user: User } =>
  record(x) && validUser(x.user);
export const emptyResponse = (x: unknown): x is Record<string, never> =>
  record(x) && Object.keys(x).length === 0;
export const actions: readonly Action[] = [
  "start",
  "shutdown",
  "reboot",
  "force_off",
  "delete",
  "snapshot_create",
  "snapshot_restore",
  "snapshot_delete",
  "backup_create",
  "backup_verify",
  "backup_restore",
  "backup_delete",
  "migrate_prepare",
  "migrate_transfer",
  "migrate_import",
  "migrate_activate",
];

import { computed, shallowRef } from "vue";
import { ApiError, key32, record } from "../api/client";
import { networkID } from "../api/network";
import {
  clusterID,
  sha256,
  validGateway,
  validMemberInput,
  validNATPolicy,
  validOverlayVPCInput,
} from "../api/overlay";
function selection(value: unknown) {
  return (
    record(value) &&
    Array.isArray(value.members) &&
    value.members.length <= 128 &&
    value.members.every(validMemberInput) &&
    Array.isArray(value.gateways) &&
    value.gateways.length <= 32 &&
    value.gateways.every(validGateway) &&
    (value.nat_policies === undefined ||
      (Array.isArray(value.nat_policies) &&
        value.nat_policies.length <= 32 &&
        value.nat_policies.every(validNATPolicy)))
  );
}
function validPayload(
  path: string,
  scope: string,
  key: string,
  body: Record<string, unknown>,
) {
  if (path === "/overlays/vpcs")
    return validOverlayVPCInput(body) && scope === `vpc:${body.cluster_id}`;
  if (path === "/overlays/epochs")
    return (
      clusterID(body.cluster_id) &&
      Number.isSafeInteger(body.expected_epoch) &&
      Number(body.expected_epoch) >= 0 &&
      selection(body) &&
      scope === `epoch:${body.cluster_id}:${body.expected_epoch}`
    );
  if (/^\/overlays\/epochs\/[a-f0-9]{32}\/recover$/.test(path))
    return (
      sha256(body.expected_snapshot_sha256) &&
      (body.replacement === undefined || selection(body.replacement)) &&
      /^epoch:[a-z0-9][a-z0-9_-]{0,63}:[1-9][0-9]*$/.test(scope)
    );
  const action =
    /^\/overlays\/epochs\/([a-f0-9]{32})\/(advance|reconcile)$/.exec(path);
  return (
    !!action &&
    key === action[1] &&
    scope === `${action[2]}:${key}` &&
    Object.keys(body).length === 0
  );
}
import { useConsole } from "../context";
interface Intent {
  owner: string;
  scope: string;
  path: string;
  key: string;
  body: unknown;
}
const storageKey = "aster.cloud.overlay-intents.v1";
const maximumStoredBytes = 1024 * 1024;
function validIntent(value: unknown): value is Intent {
  return (
    record(value) &&
    networkID(value.owner) &&
    typeof value.scope === "string" &&
    value.scope.length <= 200 &&
    typeof value.path === "string" &&
    /^\/overlays\/[a-z0-9/]+$/.test(value.path) &&
    networkID(value.key) &&
    record(value.body) &&
    validPayload(value.path, value.scope, value.key, value.body)
  );
}
function withinStorageBudget(raw: string) {
  // Bound the raw input before parsing. The UTF-8 byte budget does not replace
  // the browser's storage quota: setItem must still succeed before any POST.
  return (
    raw.length <= maximumStoredBytes &&
    new TextEncoder().encode(raw).byteLength <= maximumStoredBytes
  );
}
// Persist the complete non-secret intent before sending. A cluster/version lock
// survives closing, navigation and reload, even if the user edits the selection.
// Never erase malformed storage: that could erase an unresolved operation.
function read(): Intent[] {
  const stored = sessionStorage.getItem(storageKey) ?? "[]";
  if (!withinStorageBudget(stored)) throw new ApiError("unavailable");
  const raw: unknown = JSON.parse(stored);
  if (!Array.isArray(raw) || raw.length > 128 || !raw.every(validIntent))
    throw new ApiError("unavailable");
  if (new Set(raw.map((v) => `${v.owner}:${v.scope}`)).size !== raw.length)
    throw new ApiError("unavailable");
  return raw;
}
function save(items: Intent[]) {
  const raw = JSON.stringify(items);
  if (!withinStorageBudget(raw)) throw new ApiError("unavailable");
  sessionStorage.setItem(storageKey, raw);
}
export function useOverlayMutation(scope: () => string) {
  const { api, session } = useConsole(),
    busy = shallowRef(false),
    error = shallowRef(""),
    pending = shallowRef<Intent | null>(null);
  const pendingKey = computed(() => pending.value?.key || "");
  function load() {
    try {
      pending.value =
        read().find(
          (v) => v.owner === session.user.value?.id && v.scope === scope(),
        ) || null;
      error.value = pending.value ? "unknown" : "";
    } catch {
      error.value = "unavailable";
    }
  }
  load();
  function remove(expected: Intent) {
    const all = read();
    save(
      all.filter(
        (v) =>
          !(
            v.owner === expected.owner &&
            v.scope === expected.scope &&
            v.key === expected.key
          ),
      ),
    );
    pending.value = null;
  }
  async function execute<T>(
    path: string,
    body: unknown,
    guard: (v: unknown, key: string) => v is T,
    isCurrent: () => boolean,
    options: { key?: string; status?: number } = {},
  ) {
    if (busy.value || !session.user.value) return null;
    const owner = session.user.value.id,
      identity = session.epoch.value,
      target = scope();
    const valid = () =>
      identity === session.epoch.value &&
      session.user.value?.id === owner &&
      scope() === target &&
      isCurrent();
    busy.value = true;
    error.value = "";
    try {
      const all = read(),
        prior = all.find((v) => v.owner === owner && v.scope === target);
      if (prior) {
        pending.value = prior;
        error.value = "unknown";
        return null;
      }
      if (!valid()) return null;
      if (all.length >= 128) throw new ApiError("unavailable");
      const intent = {
        owner,
        scope: target,
        path,
        key: options.key ?? key32(),
        body: structuredClone(body),
      };
      // A new intent must satisfy the same contract that reload will enforce.
      // Otherwise a rejected POST could leave a ledger that cannot be read.
      if (!validIntent(intent)) throw new ApiError("invalid");
      save([...all, intent]);
      pending.value = intent;
      try {
        const value = await api.write(
          "POST",
          intent.path,
          intent.body,
          intent.key,
          (v): v is T => guard(v, intent.key),
          options.status,
        );
        if (!valid()) return null;
        remove(intent);
        return value;
      } catch (cause) {
        if (!valid()) return null;
        const kind = cause instanceof ApiError ? cause.kind : "unknown";
        if (kind !== "unknown") remove(intent);
        error.value = kind;
        if (kind === "unauthorized") session.invalidate();
        return null;
      }
    } catch (cause) {
      if (valid())
        error.value = cause instanceof ApiError ? cause.kind : "unavailable";
      return null;
    } finally {
      busy.value = false;
    }
  }
  function acknowledge(key: string, isCurrent: () => boolean) {
    if (
      !isCurrent() ||
      pending.value?.key !== key ||
      pending.value.owner !== session.user.value?.id
    )
      return false;
    try {
      remove(pending.value);
      error.value = "";
      return true;
    } catch {
      error.value = "unavailable";
      return false;
    }
  }
  return { busy, error, pending, pendingKey, execute, acknowledge, load };
}

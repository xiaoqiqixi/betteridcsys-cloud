import { shallowRef, watch, onScopeDispose } from "vue";
import { ApiError, key32, record } from "../api/client";
import { networkID } from "../api/network";
import {
  matchesPublicIPOperation,
  publicIPPath,
  validPublicIPRequest,
  type PublicIPAction,
  type PublicIPOperation,
} from "../api/public-ip";
import { useConsole } from "../context";
interface Intent {
  owner: string;
  key: string;
  action: PublicIPAction;
  target: string;
  body: Record<string, unknown>;
}
const storage = "aster.cloud.public-ip-intents.v1";
const maximumStoredBytes = 1024 * 1024;
function withinStorageBudget(raw: string) {
  return (
    raw.length <= maximumStoredBytes &&
    new TextEncoder().encode(raw).byteLength <= maximumStoredBytes
  );
}
function save(items: Intent[]) {
  const raw = JSON.stringify(items);
  if (!withinStorageBudget(raw)) throw new ApiError("unavailable");
  // Browser quotas vary. A successful size check alone never authorizes POST.
  sessionStorage.setItem(storage, raw);
}
function read(): Intent[] {
  const raw = sessionStorage.getItem(storage) ?? "[]";
  // Empty/corrupt/oversized storage is not an empty ledger. Keep it untouched.
  if (!withinStorageBudget(raw)) throw new ApiError("unavailable");
  const v: unknown = JSON.parse(raw);
  if (
    !Array.isArray(v) ||
    v.length > 128 ||
    !v.every(
      (x) =>
        record(x) &&
        networkID(x.owner) &&
        networkID(x.key) &&
        typeof x.target === "string" &&
        [
          "pool.create",
          "pool.extend",
          "pool.state",
          "lease.allocate",
          "lease.release",
        ].includes(x.action as string) &&
        validPublicIPRequest(x.action as PublicIPAction, x.target, x.body),
    ) ||
    new Set(v.map((x) => x.owner)).size !== v.length
  )
    throw new ApiError("unavailable");
  return v as Intent[];
}
export function usePublicIPMutation() {
  const { api, session } = useConsole();
  const busy = shallowRef(false),
    error = shallowRef(""),
    pending = shallowRef<Intent | null>(null);
  let alive = true;
  const current = (identity: number, owner: string) =>
    alive &&
    session.epoch.value === identity &&
    session.user.value?.id === owner;
  function load() {
    try {
      pending.value =
        read().find((x) => x.owner === session.user.value?.id) || null;
      error.value = pending.value ? "unknown" : "";
    } catch {
      error.value = "unavailable";
    }
  }
  function remove(intent: Intent) {
    save(
      read().filter((x) => x.owner !== intent.owner || x.key !== intent.key),
    );
    pending.value = null;
    error.value = "";
  }
  load();
  watch(session.epoch, load);
  onScopeDispose(() => {
    alive = false;
  });
  async function reconcile(): Promise<PublicIPOperation | null> {
    if (busy.value || !pending.value || !session.user.value) return null;
    const intent = pending.value,
      identity = session.epoch.value;
    busy.value = true;
    try {
      const result = await api.get(
        `/public-ips/operations/${intent.key}`,
        (v): v is { operation: PublicIPOperation } =>
          record(v) &&
          matchesPublicIPOperation(
            v.operation,
            intent.key,
            intent.owner,
            intent.action,
            intent.target,
            intent.body,
          ),
      );
      if (!current(identity, intent.owner)) return null;
      remove(intent);
      return result.operation;
    } catch (cause) {
      if (current(identity, intent.owner)) {
        error.value = cause instanceof ApiError ? cause.kind : "unknown";
        if (error.value === "unauthorized") session.invalidate();
      }
      return null;
    } finally {
      busy.value = false;
    }
  }
  async function execute(
    action: PublicIPAction,
    target: string,
    body: Record<string, unknown>,
  ): Promise<PublicIPOperation | null> {
    if (
      busy.value ||
      !session.user.value ||
      !session.can("nodes.manage") ||
      !session.can("instances.manage")
    )
      return null;
    const identity = session.epoch.value,
      owner = session.user.value.id;
    busy.value = true;
    error.value = "";
    try {
      const all = read();
      const prior = all.find((x) => x.owner === owner);
      if (prior) {
        pending.value = prior;
        error.value = "unknown";
        return null;
      }
      if (all.length >= 128 || !validPublicIPRequest(action, target, body))
        throw new ApiError("invalid");
      const intent: Intent = {
        owner,
        key: key32(),
        action,
        target,
        body: structuredClone(body),
      };
      save([...all, intent]);
      pending.value = intent;
      try {
        const value = await api.write(
          "POST",
          publicIPPath(action, target),
          body,
          intent.key,
          (v): v is { operation: PublicIPOperation } =>
            record(v) &&
            typeof v.replay === "boolean" &&
            matchesPublicIPOperation(
              v.operation,
              intent.key,
              owner,
              action,
              target,
              body,
            ),
          action === "pool.create" || action === "lease.allocate" ? 201 : 200,
        );
        if (!current(identity, owner)) return null;
        remove(intent);
        return value.operation;
      } catch (cause) {
        if (!current(identity, owner)) return null;
        const kind = cause instanceof ApiError ? cause.kind : "unknown";
        if (kind !== "unknown") remove(intent);
        error.value =
          cause instanceof ApiError && cause.code === "PUBLIC_IP_EXHAUSTED"
            ? "public_ip_exhausted"
            : kind;
        if (kind === "unauthorized") session.invalidate();
        return null;
      }
    } catch (cause) {
      if (current(identity, owner))
        error.value = cause instanceof ApiError ? cause.kind : "unavailable";
      return null;
    } finally {
      busy.value = false;
    }
  }
  return { busy, error, pending, load, execute, reconcile };
}

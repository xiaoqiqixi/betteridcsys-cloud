import { onScopeDispose, shallowRef, watch } from "vue";
import { ApiError, key32, record } from "../api/client";
import { networkID } from "../api/network";
import { useConsole } from "../context";
import {
  matchesPublicIPResourceOperation,
  matchesPublicIPResourceResponse,
  publicIPResourcePath,
  validPublicIPResourceRequest,
  type PublicIPResourceAction,
  type PublicIPResourceOperation,
} from "../api/public-ip-resource";

interface Intent {
  owner: string;
  key: string;
  action: PublicIPResourceAction;
  target: string;
  body: Record<string, unknown>;
}
const storage = "aster.cloud.public-ip-resource-intents.v1";
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
  const value: unknown = JSON.parse(raw);
  if (
    !Array.isArray(value) ||
    value.length > 128 ||
    !value.every(
      (v) =>
        record(v) &&
        networkID(v.owner) &&
        networkID(v.key) &&
        typeof v.target === "string" &&
        validPublicIPResourceRequest(
          v.action as PublicIPResourceAction,
          v.target,
          v.body,
        ),
    ) ||
    new Set(value.map((v) => v.owner)).size !== value.length
  )
    throw new ApiError("unavailable");
  return value as Intent[];
}
// Resource operation acknowledgement means the immutable intent was saved.
// It never establishes that a pending node/overlay change is already applied.
export function usePublicIPResourceMutation() {
  const { api, session } = useConsole();
  const busy = shallowRef(false),
    error = shallowRef(""),
    pending = shallowRef<Intent | null>(null);
  let alive = true;
  const allowed = () =>
    session.can("nodes.manage") && session.can("instances.manage");
  const current = (epoch: number, owner: string) =>
    alive &&
    session.epoch.value === epoch &&
    session.user.value?.id === owner &&
    allowed();
  function load() {
    try {
      pending.value =
        read().find((v) => v.owner === session.user.value?.id) || null;
      error.value = pending.value ? "unknown" : "";
    } catch {
      error.value = "unavailable";
    }
  }
  function remove(intent: Intent) {
    save(
      read().filter((v) => v.owner !== intent.owner || v.key !== intent.key),
    );
    pending.value = null;
    error.value = "";
  }
  load();
  watch(session.epoch, load);
  onScopeDispose(() => {
    alive = false;
  });
  async function reconcile(): Promise<PublicIPResourceOperation | null> {
    if (busy.value || !pending.value || !session.user.value || !allowed())
      return null;
    const intent = pending.value,
      epoch = session.epoch.value;
    busy.value = true;
    try {
      const result = await api.get(
        `/public-ips/resource-operations/${intent.key}`,
        (v): v is { operation: PublicIPResourceOperation } =>
          record(v) &&
          matchesPublicIPResourceOperation(
            v.operation,
            intent.key,
            intent.owner,
            intent.action,
            intent.target,
            intent.body,
          ),
      );
      if (!current(epoch, intent.owner)) return null;
      remove(intent);
      return result.operation;
    } catch (cause) {
      if (current(epoch, intent.owner)) {
        error.value = cause instanceof ApiError ? cause.kind : "unknown";
        if (error.value === "unauthorized") session.invalidate();
      }
      return null;
    } finally {
      busy.value = false;
    }
  }
  async function execute(
    action: PublicIPResourceAction,
    target: string,
    body: Record<string, unknown>,
  ): Promise<PublicIPResourceOperation | null> {
    if (busy.value || !session.user.value || !allowed()) return null;
    const owner = session.user.value.id,
      epoch = session.epoch.value;
    busy.value = true;
    error.value = "";
    try {
      const all = read(),
        prior = all.find((v) => v.owner === owner);
      if (prior) {
        pending.value = prior;
        error.value = "unknown";
        return null;
      }
      if (
        all.length >= 128 ||
        !validPublicIPResourceRequest(action, target, body)
      )
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
        const response = await api.write(
          "POST",
          publicIPResourcePath(action, target),
          body,
          intent.key,
          (
            v,
          ): v is {
            resource: import("../api/public-ip-resource").PublicIPResource;
            operation: PublicIPResourceOperation;
            replay: boolean;
          } =>
            matchesPublicIPResourceResponse(
              v,
              intent.key,
              owner,
              action,
              target,
              body,
            ),
          action === "resource.allocate"
            ? [201, 200]
            : action === "resource.bind" ||
                action === "resource.unbind" ||
                action === "resource.recover"
              ? [202, 200]
              : 200,
        );
        if (!current(epoch, owner)) return null;
        remove(intent);
        return response.operation;
      } catch (cause) {
        if (!current(epoch, owner)) return null;
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
      if (current(epoch, owner))
        error.value = cause instanceof ApiError ? cause.kind : "unavailable";
      return null;
    } finally {
      busy.value = false;
    }
  }
  return { busy, error, pending, execute, reconcile };
}

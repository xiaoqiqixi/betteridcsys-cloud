import { computed, onScopeDispose, shallowRef, watch } from "vue";
import { ApiError, key32 } from "../api/client";
import {
  identityOperationResponse,
  identityWriteResponse,
  normalizedIdentityEmail,
  publicIdentityIntent,
  validActionIntent,
  type IdentityAction,
} from "../api/identity";
import type { User } from "../api/types";
import { useConsole } from "../context";
import { identityLedger, type PendingIdentity } from "./identity-ledger";
import { legacyIdentityBarrier } from "./mutation";

const ledgerVersion = shallowRef(0);
function explicitNonCommit(cause: unknown) {
  if (!(cause instanceof ApiError)) return false;
  return (
    (cause.status === 400 &&
      ["INVALID_INPUT", "INVALID_QUERY"].includes(cause.code)) ||
    (cause.status === 401 && cause.code === "AUTH_REQUIRED") ||
    (cause.status === 403 &&
      ["FORBIDDEN", "CSRF_INVALID", "ORIGIN_INVALID"].includes(cause.code)) ||
    (cause.status === 409 &&
      ["CONFLICT", "REVISION_CONFLICT", "REVISION_LIMIT"].includes(cause.code))
  );
}
export function useIdentityMutation() {
  const { api, session } = useConsole();
  const pending = shallowRef<PendingIdentity[]>([]),
    busy = shallowRef(false),
    inspecting = shallowRef(""),
    error = shallowRef(""),
    blocked = shallowRef("");
  let active = true;
  function refresh() {
    pending.value = [];
    blocked.value = "";
    const owner = session.user.value?.id;
    if (!owner || !session.can("users.manage")) return;
    try {
      pending.value = identityLedger.read().filter((p) => p.owner === owner);
      blocked.value = legacyIdentityBarrier(owner);
    } catch {
      blocked.value = "blocked";
    }
  }
  watch([() => session.epoch.value, ledgerVersion], refresh, {
    immediate: true,
    flush: "sync",
  });
  watch(
    () => session.epoch.value,
    () => {
      error.value = "";
    },
    { flush: "sync" },
  );
  onScopeDispose(() => {
    active = false;
  });
  const unavailable = computed(
    () => !!blocked.value || !session.can("users.manage"),
  );

  async function execute(
    action: IdentityAction,
    target: User | null,
    input: unknown,
    isCurrent = () => true,
  ) {
    if (busy.value || inspecting.value || unavailable.value) return null;
    const owner = session.user.value?.id,
      epoch = session.epoch.value;
    if (!owner) return null;
    const current = () =>
      active &&
      isCurrent() &&
      session.epoch.value === epoch &&
      session.user.value?.id === owner;
    // Copy once, before any async work. Caller edits/closing cannot alter the
    // wire payload or the already persisted non-secret projection.
    const body: unknown = structuredClone(input),
      intent = publicIdentityIntent(body);
    if (
      !intent ||
      !validActionIntent(action, intent) ||
      (action === "identity.user_created"
        ? target !== null
        : !target || target.revision !== intent.revision)
    ) {
      error.value = "invalid";
      return null;
    }
    const entry: PendingIdentity = {
      owner,
      key: key32(),
      action,
      target: target?.id ?? normalizedIdentityEmail(intent.email!),
      target_email: normalizedIdentityEmail(target?.email ?? intent.email!),
      intent,
    };
    busy.value = true;
    error.value = "";
    let persisted = false;
    try {
      // Revalidate both ledgers immediately before the write, including a
      // component opened before another unknown operation was added.
      if (legacyIdentityBarrier(owner)) {
        blocked.value = legacyIdentityBarrier(owner);
        return null;
      }
      const prior = identityLedger.add(entry);
      ledgerVersion.value++;
      if (prior) {
        error.value = "unknown";
        return null;
      }
      persisted = true;
      const path =
        action === "identity.user_created"
          ? "/users"
          : `/users/${target!.id}${action === "identity.sessions_revoked" ? "/revoke-sessions" : ""}`;
      const selfSensitive =
        target?.id === owner &&
        (action === "identity.sessions_revoked" ||
          intent.password_changed ||
          (intent.email !== undefined &&
            normalizedIdentityEmail(intent.email) !== target.email));
      // createApiClient captures CSRF and constructs the actual fetch before
      // this invalidation. Never carry an uncertain self-revocation forward as
      // an authenticated management UI.
      const request = api.write(
        action === "identity.user_updated" ? "PATCH" : "POST",
        path,
        body,
        entry.key,
        identityWriteResponse,
        action === "identity.user_created" ? 201 : 200,
      );
      if (selfSensitive) session.invalidate();
      const result = await request;
      if (!identityLedger.acknowledge(entry, result.operation))
        throw new ApiError("unknown");
      ledgerVersion.value++;
      // A late receipt may clear its own frozen record, but never populate a
      // different account's screen or emit a success notification there.
      return current() ? result : null;
    } catch (cause) {
      if (persisted && explicitNonCommit(cause)) {
        try {
          identityLedger.remove(entry);
          ledgerVersion.value++;
        } catch {
          if (current()) blocked.value = "blocked";
        }
      }
      if (current()) {
        if (
          cause instanceof ApiError &&
          cause.code === "IDENTITY_STORAGE_BLOCKED"
        )
          blocked.value = "blocked";
        error.value =
          explicitNonCommit(cause) && cause instanceof ApiError
            ? cause.code === "REVISION_CONFLICT"
              ? "revision"
              : cause.kind
            : persisted
              ? "unknown"
              : "unavailable";
        if (cause instanceof ApiError && cause.kind === "unauthorized")
          session.invalidate();
      }
      return null;
    } finally {
      busy.value = false;
      refresh();
    }
  }
  async function inspect(entry: PendingIdentity) {
    const owner = session.user.value?.id,
      epoch = session.epoch.value;
    if (
      busy.value ||
      inspecting.value ||
      entry.owner !== owner ||
      !session.can("users.manage")
    )
      return false;
    const current = () =>
      active &&
      session.epoch.value === epoch &&
      session.user.value?.id === owner;
    inspecting.value = entry.key;
    error.value = "";
    try {
      // Never use current user fields or VM operation DTOs as acknowledgement.
      const result = await api.get(
        `/identity-operations/${entry.key}`,
        identityOperationResponse,
      );
      if (!current()) return false;
      if (!identityLedger.acknowledge(entry, result.operation))
        throw new ApiError("invalid");
      ledgerVersion.value++;
      return true;
    } catch (cause) {
      if (current()) {
        error.value =
          cause instanceof ApiError && cause.kind === "unauthorized"
            ? "unauthorized"
            : "unknown";
        if (error.value === "unauthorized") session.invalidate();
      }
      return false;
    } finally {
      inspecting.value = "";
      refresh();
    }
  }
  function clearError() {
    if (!busy.value && !inspecting.value) error.value = "";
  }
  return {
    pending,
    busy,
    inspecting,
    error,
    blocked,
    unavailable,
    execute,
    inspect,
    refresh,
    clearError,
  };
}

import { onScopeDispose, shallowRef, watch, type WatchSource } from "vue";
import { ApiError, record, validOperation } from "../api/client";
import { acknowledgeOperations } from "./mutation";
import { useConsole } from "../context";
export function useQuery<T>(
  path: () => string,
  guard: (value: unknown) => value is T,
  dependencies: WatchSource[] = [],
) {
  const { api, session } = useConsole();
  const data = shallowRef<T | null>(null),
    loading = shallowRef(false),
    error = shallowRef("");
  let revision = 0,
    abort: AbortController | undefined;
  async function reload() {
    abort?.abort();
    abort = new AbortController();
    const ticket = ++revision,
      identity = session.epoch.value;
    data.value = null;
    error.value = "";
    if (!session.user.value) {
      loading.value = false;
      return;
    }
    loading.value = true;
    try {
      const result = await api.get(path(), guard, abort.signal);
      if (ticket === revision && identity === session.epoch.value) {
        data.value = result;
        const value: unknown = result;
        if (record(value)) {
          const operations = Array.isArray(value.operations)
            ? value.operations
            : Array.isArray(value.items)
              ? value.items
              : [value.operation];
          acknowledgeOperations(
            session.user.value?.id || "",
            operations.filter(validOperation),
          );
        }
      }
    } catch (cause) {
      if (ticket === revision && identity === session.epoch.value) {
        error.value = cause instanceof ApiError ? cause.kind : "network";
        if (cause instanceof ApiError && cause.kind === "unauthorized")
          session.invalidate();
      }
    } finally {
      if (ticket === revision) loading.value = false;
    }
  }
  watch([() => path(), session.epoch, ...dependencies], () => void reload(), {
    immediate: true,
  });
  onScopeDispose(() => {
    revision++;
    abort?.abort();
  });
  return { data, loading, error, reload };
}

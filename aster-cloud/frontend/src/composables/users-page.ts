import { computed, onScopeDispose, shallowRef, watch } from "vue";
import { ApiError, validUsers } from "../api/client";
import type { UsersResult } from "../api/types";
import { useConsole } from "../context";

// Pagination owns its request lifetime and only commits navigation on success.
// Cursors stay in this component scope, never in a URL or persistent storage.
export function useUsersPage() {
  const { api, session } = useConsole();
  const data = shallowRef<UsersResult | null>(null);
  const loading = shallowRef(false),
    error = shallowRef("");
  const history = shallowRef<(string | null)[]>([null]);
  let requested: (string | null)[] = [null];
  let generation = 0,
    abort: AbortController | undefined;
  const allowed = computed(() => session.can("users.manage"));
  const denied = computed(
    () =>
      !allowed.value ||
      error.value === "forbidden" ||
      error.value === "unauthorized",
  );
  const page = computed(() => history.value.length);
  const canPrevious = computed(
    () => !loading.value && !denied.value && history.value.length > 1,
  );
  const canNext = computed(
    () =>
      !loading.value &&
      !error.value &&
      !denied.value &&
      !!data.value?.next_cursor,
  );
  function clear() {
    generation++;
    abort?.abort();
    data.value = null;
    history.value = [null];
    requested = [null];
    loading.value = false;
    error.value = "";
  }
  async function load(target: (string | null)[]) {
    abort?.abort();
    abort = new AbortController();
    const ticket = ++generation,
      epoch = session.epoch.value;
    requested = [...target];
    if (!allowed.value) {
      clear();
      error.value = session.user.value ? "forbidden" : "unauthorized";
      return;
    }
    loading.value = true;
    error.value = "";
    const cursor = target[target.length - 1];
    try {
      const result = await api.get(
        cursor ? `/users?cursor=${encodeURIComponent(cursor)}` : "/users",
        validUsers,
        abort.signal,
      );
      if (
        ticket !== generation ||
        epoch !== session.epoch.value ||
        !allowed.value
      )
        return;
      // A repeated next position would trap navigation in a loop.
      if (result.next_cursor && target.includes(result.next_cursor))
        throw new ApiError("invalid");
      data.value = result;
      history.value = [...target];
    } catch (cause) {
      if (ticket !== generation || epoch !== session.epoch.value) return;
      const kind = cause instanceof ApiError ? cause.kind : "network";
      if (kind === "unauthorized" || kind === "forbidden") {
        data.value = null;
        history.value = [null];
        requested = [null];
        if (kind === "unauthorized") session.invalidate();
      }
      error.value = kind;
    } finally {
      if (ticket === generation) loading.value = false;
    }
  }
  watch(
    [
      () => session.epoch.value,
      () => session.user.value?.id,
      () => allowed.value,
    ],
    () => {
      clear();
      void load([null]);
    },
    { immediate: true, flush: "sync" },
  );
  onScopeDispose(clear);
  return {
    data,
    loading,
    error,
    denied,
    page,
    canPrevious,
    canNext,
    refreshFirst: () => load([null]),
    reload: () => load(error.value ? requested : history.value),
    previous: () =>
      canPrevious.value ? load(history.value.slice(0, -1)) : Promise.resolve(),
    next: () =>
      canNext.value
        ? load([...history.value, data.value!.next_cursor])
        : Promise.resolve(),
  };
}

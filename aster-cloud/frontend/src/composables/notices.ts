import { onScopeDispose, readonly, shallowRef, watch, type Ref } from "vue";
import type { Notice } from "../context";

// Notices supplement durable page/task state; they never confirm a backend
// operation themselves. Keep transient information from covering a workflow.
export function useNotices(
  locale: Readonly<Ref<string>>,
  sessionEpoch: Readonly<Ref<number>>,
) {
  const notices = shallowRef<Notice[]>([]);
  const timers = new Map<number, ReturnType<typeof setTimeout>>();
  let nextID = 0;

  function pause(id: number) {
    const timer = timers.get(id);
    if (timer !== undefined) clearTimeout(timer);
    timers.delete(id);
  }
  function dismiss(id: number) {
    pause(id);
    notices.value = notices.value.filter((notice) => notice.id !== id);
  }
  function resume(id: number) {
    if (
      timers.has(id) ||
      !notices.value.some(
        (notice) => notice.id === id && notice.kind === "info",
      )
    )
      return;
    timers.set(
      id,
      setTimeout(() => dismiss(id), 5000),
    );
  }
  function clear() {
    for (const id of timers.keys()) pause(id);
    notices.value = [];
  }
  function notify(title: string, kind: "info" | "error" = "info") {
    if (kind === "info") {
      for (const notice of notices.value)
        if (notice.kind === "info") dismiss(notice.id);
    } else {
      if (
        notices.value.some(
          (notice) => notice.kind === kind && notice.title === title,
        )
      )
        return;
      const errors = notices.value.filter((notice) => notice.kind === "error");
      if (errors.length >= 3) dismiss(errors[0]!.id);
    }
    const notice = { id: ++nextID, title, kind };
    notices.value = [...notices.value, notice];
    resume(notice.id);
  }

  // A translated string is a snapshot of its original locale. Never leave it
  // visible in a different language or under a different signed-in identity.
  watch([locale, sessionEpoch], clear, { flush: "sync" });
  onScopeDispose(clear);
  return { notices: readonly(notices), notify, dismiss, pause, resume };
}

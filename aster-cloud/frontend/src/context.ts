import { inject, type InjectionKey } from "vue";
import type { ApiClient } from "./api/client";
import type { usePreferences } from "./composables/preferences";
import type { useSession } from "./composables/session";
export interface Notice {
  id: number;
  title: string;
  kind: "info" | "error";
}
export interface ConsoleContext {
  api: ApiClient;
  session: ReturnType<typeof useSession>;
  prefs: ReturnType<typeof usePreferences>;
  notify: (title: string, kind?: "info" | "error") => void;
}
export const consoleKey: InjectionKey<ConsoleContext> = Symbol("aster-console");
export function useConsole() {
  const context = inject(consoleKey);
  if (!context) throw new Error("Console provider required");
  return context;
}

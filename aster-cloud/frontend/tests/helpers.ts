import { shallowRef } from "vue";
import { vi } from "vitest";
import { ApiError, type ApiClient } from "../src/api/client";
import type { ConsoleContext } from "../src/context";
import { useSession } from "../src/composables/session";
import type { Appearance, Locale } from "../src/composables/preferences";
import { admin } from "./fixtures";
export interface Call {
  method: string;
  path: string;
  body: unknown;
  key: string;
}
export function mockContext(
  resolver: (
    method: string,
    path: string,
    body: unknown,
    key: string,
  ) => unknown | Promise<unknown>,
) {
  const calls: Call[] = [];
  const api: ApiClient = {
    get: async <T>(path: string, guard: (v: unknown) => v is T) => {
      const result = await resolver("GET", path, undefined, "");
      if (!guard(result)) throw new ApiError("invalid");
      return result;
    },
    write: async <T>(
      method: "POST" | "PATCH",
      path: string,
      body: unknown,
      key: string,
      guard: (v: unknown) => v is T,
    ) => {
      calls.push({ method, path, body: structuredClone(body), key });
      const result = await resolver(method, path, body, key);
      if (!guard(result)) throw new ApiError("unknown");
      return result;
    },
    setCSRF: vi.fn(),
  };
  const session = useSession(api);
  session.user.value = structuredClone(admin);
  session.ready.value = true;
  const locale = shallowRef<Locale>("zh-CN"),
    appearance = shallowRef<Appearance>("light");
  const context: ConsoleContext = {
    api,
    session,
    prefs: {
      locale,
      appearance,
      tr: (zh, en) => (locale.value === "en" ? en : zh),
      dispose: () => {},
    },
    notify: vi.fn(),
  };
  return { context, calls };
}
export function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

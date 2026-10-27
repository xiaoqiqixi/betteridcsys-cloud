import { shallowRef } from "vue";
import {
  ApiError,
  emptyResponse,
  key32,
  record,
  validSession,
  type ApiClient,
} from "../api/client";
import type { User } from "../api/types";
export function useSession(api: ApiClient) {
  const user = shallowRef<User | null>(null),
    ready = shallowRef(false),
    busy = shallowRef(false),
    error = shallowRef(""),
    epoch = shallowRef(0),
    pendingAuth = shallowRef<"login" | "logout" | null>(null);
  let generation = 0;
  function invalidate() {
    generation++;
    epoch.value++;
    user.value = null;
    busy.value = false;
    api.setCSRF("");
  }
  async function refresh() {
    const ticket = ++generation;
    error.value = "";
    try {
      const data = await api.get("/auth/me", validSession);
      if (ticket !== generation) return false;
      pendingAuth.value = null;
      api.setCSRF(data.csrf_token);
      const changed =
        JSON.stringify(user.value) !==
        JSON.stringify(data.user.enabled ? data.user : null);
      user.value = data.user.enabled ? data.user : null;
      if (!data.user.enabled) api.setCSRF("");
      if (changed) epoch.value++;
      return !!user.value;
    } catch (cause) {
      if (ticket !== generation) return false;
      invalidate();
      if (cause instanceof ApiError && cause.kind === "unauthorized") {
        pendingAuth.value = null;
      } else error.value = pendingAuth.value ? "unknown" : "network";
      return false;
    } finally {
      if (ticket === generation || !user.value) ready.value = true;
    }
  }
  async function login(email: string, password: string) {
    if (busy.value || pendingAuth.value) return false;
    busy.value = true;
    error.value = "";
    const ticket = ++generation;
    try {
      const csrf = await api.get(
        "/auth/csrf",
        (v): v is { csrf_token: string } =>
          record(v) &&
          typeof v.csrf_token === "string" &&
          v.csrf_token.length > 0,
      );
      if (ticket !== generation) return false;
      api.setCSRF(csrf.csrf_token);
      pendingAuth.value = "login";
      const data = await api.write(
        "POST",
        "/auth/login",
        { email, password },
        key32(),
        validSession,
      );
      if (ticket !== generation) return false;
      if (!data.user.enabled) throw new ApiError("forbidden");
      pendingAuth.value = null;
      user.value = data.user;
      api.setCSRF(data.csrf_token);
      epoch.value++;
      return true;
    } catch (cause) {
      if (ticket === generation) {
        api.setCSRF("");
        error.value = cause instanceof ApiError ? cause.kind : "unknown";
        if (error.value !== "unknown") pendingAuth.value = null;
      }
      return false;
    } finally {
      if (ticket === generation) busy.value = false;
    }
  }
  async function logout() {
    if (busy.value || pendingAuth.value) return;
    busy.value = true;
    error.value = "";
    try {
      pendingAuth.value = "logout";
      await api.write("POST", "/auth/logout", {}, key32(), emptyResponse, 204);
      pendingAuth.value = null;
      invalidate();
    } catch (cause) {
      const kind = cause instanceof ApiError ? cause.kind : "unknown";
      if (kind === "unknown") {
        invalidate();
        error.value = "unknown";
      } else {
        pendingAuth.value = null;
        error.value = kind;
        if (kind === "unauthorized") invalidate();
      }
    } finally {
      busy.value = false;
    }
  }
  return {
    user,
    ready,
    busy,
    error,
    epoch,
    pendingAuth,
    invalidate,
    refresh,
    login,
    logout,
    can: (permission: string) =>
      !!user.value?.enabled && user.value.permissions.includes(permission),
  };
}

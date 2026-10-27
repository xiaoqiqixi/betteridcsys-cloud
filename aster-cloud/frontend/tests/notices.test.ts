import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { flushPromises, mount } from "@vue/test-utils";
import { defineComponent } from "vue";
import { createMemoryHistory, createRouter } from "vue-router";
import { webcrypto } from "node:crypto";
import App from "../src/App.vue";
import * as client from "../src/api/client";
import { useConsole, type ConsoleContext } from "../src/context";
import { admin } from "./fixtures";
import { mockContext } from "./helpers";

const cleanups: Array<() => void> = [];
beforeEach(() => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
  vi.stubGlobal("crypto", webcrypto);
  vi.stubGlobal("matchMedia", () => ({
    matches: false,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  }));
  localStorage.clear();
});
afterEach(() => {
  cleanups
    .splice(0)
    .reverse()
    .forEach((cleanup) => cleanup());
  document.body.innerHTML = "";
  document.body.style.overflow = "";
  history.replaceState(null, "");
  localStorage.clear();
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});
async function fixture() {
  let context!: ConsoleContext;
  const page = defineComponent({
    setup() {
      context = useConsole();
      return () => "Network page";
    },
  });
  const fake = mockContext(() => ({ user: admin, csrf_token: "test-csrf" }));
  vi.spyOn(client, "createApiClient").mockReturnValue(fake.context.api);
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      "/",
      "/instances",
      "/nodes",
      "/networks/overlays",
      "/operations",
      "/audit",
      "/users",
    ].map((path) => ({ path, component: page })),
  });
  await router.push("/");
  await router.isReady();
  const app = document.createElement("div");
  app.id = "app";
  document.body.append(app);
  const wrapper = mount(App, { attachTo: app, global: { plugins: [router] } });
  cleanups.push(() => wrapper.unmount());
  await flushPromises();
  const notices = () => wrapper.findAll(".toast-item");
  return { wrapper, context, notices };
}

describe("non-obstructing app notices", () => {
  it("replaces old informational notices instead of accumulating over the mobile page", async () => {
    const f = await fixture();
    for (const message of ["已受理", "已继续", "已核对", "已恢复"])
      f.context.notify(message);
    await flushPromises();
    expect(f.notices()).toHaveLength(1);
    expect(f.notices()[0]!.text()).toContain("已恢复");
  });
  it("automatically dismisses information after five seconds", async () => {
    const f = await fixture();
    f.context.notify("已核对，请查看任务状态");
    await flushPromises();
    expect(f.notices()).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(4999);
    expect(f.notices()).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(f.notices()).toHaveLength(0);
  });
  it("does not let an old notice timer dismiss its replacement", async () => {
    const f = await fixture();
    f.context.notify("第一个提示");
    await vi.advanceTimersByTimeAsync(4900);
    f.context.notify("新的提示");
    await flushPromises();
    await vi.advanceTimersByTimeAsync(100);
    expect(f.notices()).toHaveLength(1);
    expect(f.notices()[0]!.text()).toContain("新的提示");
    await vi.advanceTimersByTimeAsync(4900);
    expect(f.notices()).toHaveLength(0);
  });
  it("clears old-language text when the interface language changes", async () => {
    const f = await fixture();
    f.context.notify("网络变更已受理");
    await flushPromises();
    f.context.prefs.locale.value = "en";
    await flushPromises();
    expect(f.notices()).toHaveLength(0);
  });
  it("does not show a previous identity's notice after the session changes", async () => {
    const f = await fixture();
    f.context.notify("原身份的操作已受理");
    await flushPromises();
    f.context.session.invalidate();
    await flushPromises();
    expect(f.notices()).toHaveLength(0);
  });
  it("keeps errors until dismissed and does not replace them with a success notice", async () => {
    const f = await fixture();
    f.context.notify("连接失败，请重新加载", "error");
    f.context.notify("另一个操作已受理");
    await flushPromises();
    await vi.advanceTimersByTimeAsync(5000);
    expect(f.notices()).toHaveLength(1);
    expect(f.notices()[0]!.classes()).toContain("error");
    await f.notices()[0]!.get("button").trigger("click");
    expect(f.notices()).toHaveLength(0);
  });
  it("pauses dismissal while a notice is being read with a pointer or keyboard", async () => {
    const f = await fixture();
    f.context.notify("网络变更已受理，请查看任务进度");
    await flushPromises();
    await f.notices()[0]!.trigger("pointerenter");
    await vi.advanceTimersByTimeAsync(10000);
    expect(f.notices()).toHaveLength(1);
    await f.notices()[0]!.trigger("pointerleave");
    await f.notices()[0]!.trigger("focusin");
    await vi.advanceTimersByTimeAsync(10000);
    expect(f.notices()).toHaveLength(1);
    await f.notices()[0]!.trigger("focusout", { relatedTarget: document.body });
    await vi.advanceTimersByTimeAsync(5000);
    expect(f.notices()).toHaveLength(0);
  });
  it("deduplicates persistent errors and bounds their queue", async () => {
    const f = await fixture();
    for (let i = 0; i < 10; i++) f.context.notify("同一错误", "error");
    await flushPromises();
    expect(f.notices()).toHaveLength(1);
    for (const message of ["第二个错误", "第三个错误", "第四个错误"])
      f.context.notify(message, "error");
    await flushPromises();
    expect(f.notices()).toHaveLength(3);
    expect(
      f
        .notices()
        .map((notice) => notice.text())
        .join(),
    ).not.toContain("同一错误");
  });
  it("does not resume the timer on pointer exit while the dismiss button still has keyboard focus", async () => {
    const f = await fixture();
    f.context.notify("正在阅读的提示");
    await flushPromises();
    const notice = f.notices()[0]!;
    (notice.get("button").element as HTMLButtonElement).focus();
    await notice.trigger("pointerenter");
    await notice.trigger("pointerleave");
    await vi.advanceTimersByTimeAsync(10000);
    expect(f.notices()).toHaveLength(1);
    (notice.get("button").element as HTMLButtonElement).blur();
    await vi.advanceTimersByTimeAsync(5000);
    expect(f.notices()).toHaveLength(0);
  });
  it("removes all dismissal timers when the app is unmounted", async () => {
    const f = await fixture();
    f.context.notify("已受理");
    await flushPromises();
    expect(vi.getTimerCount()).toBe(1);
    f.wrapper.unmount();
    cleanups.pop();
    expect(vi.getTimerCount()).toBe(0);
  });
});

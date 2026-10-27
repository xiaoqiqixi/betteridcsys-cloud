import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mount, flushPromises } from "@vue/test-utils";
import { defineComponent, onBeforeUnmount, provide, shallowRef } from "vue";
import { createRouter, createWebHashHistory } from "vue-router";
import { webcrypto } from "node:crypto";
import NavLinks from "../src/components/NavLinks.vue";
import UiOverlay from "../src/components/UiOverlay.vue";
import { usePreferences } from "../src/composables/preferences";
import { consoleKey } from "../src/context";
import { mockContext } from "./helpers";

const cleanups: Array<() => void> = [];
const id = "a".repeat(32);
beforeEach(() => {
  vi.stubGlobal("crypto", webcrypto);
  vi.stubGlobal("matchMedia", () => ({
    matches: false,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  }));
  vi.spyOn(history, "back").mockImplementation(() => {});
  vi.spyOn(HTMLElement.prototype, "getClientRects").mockImplementation(
    () => [new DOMRect(0, 0, 100, 44)] as unknown as DOMRectList,
  );
  localStorage.clear();
  localStorage.setItem(
    "aster.cloud.ui.v1",
    JSON.stringify({ locale: "en", appearance: "dark" }),
  );
  history.replaceState(null, "", `/#/instances/${id}`);
});
afterEach(() => {
  cleanups
    .splice(0)
    .reverse()
    .forEach((fn) => fn());
  document.body.innerHTML = "";
  document.body.style.overflow = "";
  history.replaceState(null, "", "/");
  localStorage.clear();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});
async function navigationFixture(initial = `/instances/${id}`, open = true) {
  const routeHistory = createWebHashHistory();
  cleanups.push(() => routeHistory.destroy());
  const router = createRouter({
    history: routeHistory,
    routes: [
      { path: "/instances/:id", component: { template: "<h1>Instance</h1>" } },
      ...["instances", "nodes", "operations", "audit", "users"].map((name) => ({
        path: `/${name}`,
        component: { template: "<h1>Page</h1>" },
      })),
    ],
  });
  await router.push(initial);
  await router.isReady();
  const { context } = mockContext(() => ({}));
  const shell = defineComponent({
    components: { NavLinks, UiOverlay },
    setup() {
      const open = shallowRef(false);
      const prefs = usePreferences();
      context.prefs = prefs;
      provide(consoleKey, context);
      onBeforeUnmount(prefs.dispose);
      return { open };
    },
    template:
      '<button id="open-navigation" @click="open = true">Open navigation</button>' +
      '<UiOverlay :open="open" title="Navigation" drawer @close="open = false">' +
      '<NavLinks tone="surface" @navigate="open = false" /></UiOverlay><RouterView />',
  });
  const app = document.createElement("div");
  app.id = "app";
  document.body.append(app);
  const wrapper = mount(shell, {
    attachTo: app,
    global: { plugins: [router] },
  });
  cleanups.push(() => wrapper.unmount());
  const baseState = { ...history.state };
  async function openNavigation() {
    (wrapper.get("#open-navigation").element as HTMLButtonElement).focus();
    await wrapper.get("#open-navigation").trigger("click");
    await flushPromises();
    expect(app.inert).toBe(true);
  }
  if (open) await openNavigation();
  return { router, wrapper, app, baseState, openNavigation };
}
async function actualBack() {
  await new Promise<void>((resolve, reject) => {
    const pop = () => {
      clearTimeout(timer);
      window.removeEventListener("popstate", pop);
      resolve();
    };
    const timer = setTimeout(() => {
      window.removeEventListener("popstate", pop);
      reject(new Error("History traversal did not emit popstate"));
    }, 1000);
    window.addEventListener("popstate", pop);
    history.back();
  });
  await flushPromises();
}
describe("hash navigation while the mobile overlay owns history", () => {
  it("commits the new route before closing and never backs out of the destination or resets preferences", async () => {
    const { router, wrapper, app } = await navigationFixture();
    const saved = localStorage.getItem("aster.cloud.ui.v1");
    await wrapper
      .findComponent(NavLinks)
      .get('a[href="#/operations"]')
      .trigger("click");
    await flushPromises();
    expect(router.currentRoute.value.path).toBe("/operations");
    expect(location.hash).toBe("#/operations");
    expect(history.back).not.toHaveBeenCalled();
    expect(document.querySelector('[role="dialog"]')).toBeNull();
    expect(app.inert).toBe(false);
    expect(localStorage.getItem("aster.cloud.ui.v1")).toBe(saved);
    expect(document.documentElement.lang).toBe("en");
    expect(document.documentElement.dataset.theme).toBe("dark");
  });
  it("closes an already-current destination and preserves first Back-to-close behavior", async () => {
    const { router, wrapper, app, baseState } =
      await navigationFixture("/instances");
    await wrapper
      .findComponent(NavLinks)
      .get('a[href="#/instances"]')
      .trigger("click");
    await flushPromises();
    expect(router.currentRoute.value.path).toBe("/instances");
    expect(document.querySelector('[role="dialog"]')).toBeNull();
    expect(app.inert).toBe(false);
    expect(history.back).toHaveBeenCalledTimes(1);
    // The back spy records the requested consumption; emulate its committed state.
    history.replaceState(baseState, "", location.href);
    (wrapper.get("#open-navigation").element as HTMLButtonElement).focus();
    await wrapper.get("#open-navigation").trigger("click");
    await flushPromises();
    history.replaceState(baseState, "", location.href);
    window.dispatchEvent(new PopStateEvent("popstate", { state: baseState }));
    await flushPromises();
    expect(document.querySelector('[role="dialog"]')).toBeNull();
    expect(app.inert).toBe(false);
    expect(history.back).toHaveBeenCalledTimes(1);
    expect(document.activeElement).toBe(
      wrapper.get("#open-navigation").element,
    );
  });
  it("keeps the drawer open if the router rejects the destination", async () => {
    const { router, wrapper, app } = await navigationFixture();
    router.beforeEach((to) => to.path !== "/operations");
    await wrapper
      .findComponent(NavLinks)
      .get('a[href="#/operations"]')
      .trigger("click");
    await flushPromises();
    expect(router.currentRoute.value.path).toBe(`/instances/${id}`);
    expect(document.querySelector('[role="dialog"]')).not.toBeNull();
    expect(app.inert).toBe(true);
    expect(history.back).not.toHaveBeenCalled();
  });
  it("keeps the drawer open when a thrown guard is swallowed by RouterLink.navigate", async () => {
    const { router, wrapper, app } = await navigationFixture();
    const rejected = new Error("synthetic navigation guard failure");
    const onError = vi.fn();
    router.onError(onError);
    router.beforeEach(() => {
      throw rejected;
    });
    await wrapper
      .findComponent(NavLinks)
      .get('a[href="#/operations"]')
      .trigger("click");
    await flushPromises();
    expect(onError).toHaveBeenCalledWith(
      rejected,
      expect.anything(),
      expect.anything(),
    );
    expect(router.currentRoute.value.path).toBe(`/instances/${id}`);
    expect(document.querySelector('[role="dialog"]')).not.toBeNull();
    expect(app.inert).toBe(true);
    expect(history.back).not.toHaveBeenCalled();
  });
  it("does not close or navigate an already-cancelled link click", async () => {
    const { router, wrapper, app } = await navigationFixture();
    const guard = vi.fn();
    router.beforeEach(guard);
    const click = new MouseEvent("click", { bubbles: true, cancelable: true });
    click.preventDefault();
    wrapper
      .findComponent(NavLinks)
      .get('a[href="#/operations"]')
      .element.dispatchEvent(click);
    await flushPromises();
    expect(guard).not.toHaveBeenCalled();
    expect(router.currentRoute.value.path).toBe(`/instances/${id}`);
    expect(document.querySelector('[role="dialog"]')).not.toBeNull();
    expect(app.inert).toBe(true);
    expect(history.back).not.toHaveBeenCalled();
  });
  it("replaces only the surface overlay entry so real Back returns to A and then its previous route", async () => {
    vi.mocked(history.back).mockRestore();
    const { router, wrapper, app, openNavigation } = await navigationFixture(
      "/nodes",
      false,
    );
    await router.push(`/instances/${id}`);
    const lengthAtA = history.length;
    await openNavigation();
    expect(history.length).toBe(lengthAtA + 1);
    await wrapper
      .findComponent(NavLinks)
      .get('a[href="#/operations"]')
      .trigger("click");
    await flushPromises();
    expect(router.currentRoute.value.path).toBe("/operations");
    expect(location.hash).toBe("#/operations");
    expect(history.length).toBe(lengthAtA + 1);
    expect(history.state.asterOverlay).toBeUndefined();
    expect(history.state.current).toBe("/operations");
    expect(typeof history.state.position).toBe("number");
    expect(app.inert).toBe(false);
    await actualBack();
    expect(router.currentRoute.value.path).toBe(`/instances/${id}`);
    expect(location.hash).toBe(`#/instances/${id}`);
    await actualBack();
    expect(router.currentRoute.value.path).toBe("/nodes");
    expect(location.hash).toBe("#/nodes");
    expect(document.querySelector('[role="dialog"]')).toBeNull();
    expect(JSON.parse(localStorage.getItem("aster.cloud.ui.v1")!)).toEqual({
      locale: "en",
      appearance: "dark",
    });
  });
});

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { flushPromises, mount } from "@vue/test-utils";
import { createRouter, createWebHashHistory } from "vue-router";
import { webcrypto } from "node:crypto";
import App from "../src/App.vue";
import * as client from "../src/api/client";
import type { User } from "../src/api/types";
import { mockContext } from "./helpers";

const compactQuery = "(max-width: 1024px)";
const darkQuery = "(prefers-color-scheme: dark)";
const detailPath = `/instances/${"a".repeat(32)}`;
const cleanups: Array<() => void> = [];

// This models media-query change events, not CSS layout. Real command-rail geometry,
// reachability and zoom behavior belong to the mandatory browser acceptance.
function controlledMedia(media: string, initial: boolean) {
  let matches = initial;
  const target = new EventTarget();
  return {
    media,
    get matches() {
      return matches;
    },
    addEventListener: vi.fn(
      (type: string, listener: EventListenerOrEventListenerObject) =>
        target.addEventListener(type, listener),
    ),
    removeEventListener: vi.fn(
      (type: string, listener: EventListenerOrEventListenerObject) =>
        target.removeEventListener(type, listener),
    ),
    change(value: boolean) {
      matches = value;
      target.dispatchEvent(
        Object.assign(new Event("change"), { matches, media }),
      );
    },
  };
}

beforeEach(() => {
  vi.stubGlobal("crypto", webcrypto);
  vi.spyOn(history, "back").mockImplementation(() => {});
  // The overlay uses rect presence to choose an initial focus target. These
  // synthetic rects only enable that logic; they do not prove visual dimensions.
  vi.spyOn(HTMLElement.prototype, "getClientRects").mockImplementation(
    () => [new DOMRect(0, 0, 100, 44)] as unknown as DOMRectList,
  );
  localStorage.clear();
  localStorage.setItem(
    "aster.cloud.ui.v1",
    JSON.stringify({ locale: "en", appearance: "light" }),
  );
  history.replaceState(null, "", `/#${detailPath}`);
  document.body.style.overflow = "auto";
});
afterEach(() => {
  cleanups
    .splice(0)
    .reverse()
    .forEach((cleanup) => cleanup());
  document.body.innerHTML = "";
  document.body.style.overflow = "";
  document.documentElement.removeAttribute("data-theme");
  history.replaceState(null, "", "/");
  localStorage.clear();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

async function shellFixture(
  compact = true,
  startupState?: Record<string, unknown>,
) {
  const compactMedia = controlledMedia(compactQuery, compact);
  const darkMedia = controlledMedia(darkQuery, false);
  const matchMedia = vi.fn((query: string) => {
    if (query === compactQuery) return compactMedia;
    if (query === darkQuery) return darkMedia;
    throw new Error(`Unexpected test media query: ${query}`);
  });
  vi.stubGlobal("matchMedia", matchMedia);
  const viewer: User = {
    revision: 1,
    id: "d".repeat(32),
    email: "shell-viewer@example.invalid",
    name: "Synthetic read-only member",
    role: "viewer",
    enabled: true,
    permissions: ["instances.read", "nodes.read", "audit.read"],
  };
  const resolve = vi.fn((method: string, path: string) => {
    if (method === "GET" && path === "/auth/me")
      return {
        user: structuredClone(viewer),
        csrf_token: "synthetic-shell-csrf",
      };
    throw new Error("The responsive shell must not make a resource mutation");
  });
  const fake = mockContext(resolve);
  vi.spyOn(client, "createApiClient").mockReturnValue(fake.context.api);
  const routeHistory = createWebHashHistory();
  cleanups.push(() => routeHistory.destroy());
  const router = createRouter({
    history: routeHistory,
    routes: [
      "/instances/:id",
      "/instances",
      "/nodes",
      "/networks/overlays",
      "/operations",
      "/audit",
      "/users",
    ].map((path) => ({
      path,
      meta: {
        permission:
          path === "/users"
            ? "users.manage"
            : path === "/audit"
              ? "audit.read"
              : path === "/nodes" || path.startsWith("/networks/")
                ? "nodes.read"
                : "instances.read",
      },
      component: {
        template:
          '<div><h1>Synthetic read-only page</h1><label>Read-only filter<input aria-label="Synthetic read-only filter"></label></div>',
      },
    })),
  });
  await router.push(detailPath);
  await router.isReady();
  if (startupState)
    history.replaceState({ ...history.state, ...startupState }, "");
  const startupHistoryLength = history.length;
  const app = document.createElement("div");
  app.id = "app";
  document.body.append(app);
  const wrapper = mount(App, { attachTo: app, global: { plugins: [router] } });
  let mounted = true;
  function unmount() {
    if (!mounted) return;
    mounted = false;
    wrapper.unmount();
  }
  cleanups.push(unmount);
  await flushPromises();
  const menu = () => wrapper.get<HTMLButtonElement>("button.aw-menu-trigger");
  const dialog = () => document.querySelector<HTMLElement>('[role="dialog"]');
  async function openNavigation() {
    menu().element.focus();
    await menu().trigger("click");
    await flushPromises();
    expect(menu().attributes("aria-expanded")).toBe("true");
    expect(dialog()).not.toBeNull();
  }
  async function destination(path: string) {
    const link = dialog()?.querySelector<HTMLAnchorElement>(
      `a[href="#${path}"]`,
    );
    expect(link).not.toBeNull();
    link!.click();
    await flushPromises();
  }
  return {
    wrapper,
    app,
    router,
    compactMedia,
    darkMedia,
    matchMedia,
    menu,
    dialog,
    openNavigation,
    destination,
    writes: fake.calls,
    unmount,
    startupHistoryLength,
  };
}

// Synthetic rectangles/insets exercise only focus-reveal arithmetic and
// lifecycle cancellation. They are not evidence of real CSS visibility or scroll.
function clippedNavigation(
  f: Awaited<ReturnType<typeof shellFixture>>,
  rowLeft: number,
  scrollLeft: number,
  focusVisible = true,
) {
  const navigation = f.wrapper.get<HTMLElement>("nav.aw-rail-nav").element;
  const link = f.wrapper.get<HTMLAnchorElement>(
    '.aw-rail-nav a[href="#/operations"]',
  ).element;
  // Explicitly control keyboard-focus intent as well as rects. This is not
  // a claim that jsdom reproduces the browser's :focus-visible heuristics.
  const nativeMatches = link.matches.bind(link);
  const matches = vi
    .spyOn(link, "matches")
    .mockImplementation((selector) =>
      selector === ":focus-visible" ? focusVisible : nativeMatches(selector),
    );
  navigation.style.paddingLeft = "8px";
  navigation.style.paddingRight = "8px";
  navigation.scrollLeft = scrollLeft;
  const region = vi
    .spyOn(navigation, "getBoundingClientRect")
    .mockReturnValue(new DOMRect(100, 4, 161, 44));
  const row = vi
    .spyOn(link, "getBoundingClientRect")
    .mockReturnValue(new DOMRect(rowLeft, 4, 46, 44));
  const oldBodyScroll = document.body.scrollLeft;
  const oldRootScroll = document.documentElement.scrollLeft;
  document.body.scrollLeft = 210;
  document.documentElement.scrollLeft = 210;
  cleanups.push(() => {
    document.body.scrollLeft = oldBodyScroll;
    document.documentElement.scrollLeft = oldRootScroll;
  });
  const scrollTo = vi.spyOn(window, "scrollTo").mockImplementation(() => {});
  const scrollBy = vi.spyOn(window, "scrollBy").mockImplementation(() => {});
  function onlyNavigationScrolled() {
    expect(document.body.scrollLeft).toBe(210);
    expect(document.documentElement.scrollLeft).toBe(210);
    expect(scrollTo).not.toHaveBeenCalled();
    expect(scrollBy).not.toHaveBeenCalled();
    expect(f.writes).toEqual([]);
  }
  return { navigation, link, region, row, matches, onlyNavigationScrolled };
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
      reject(new Error("Expected real history traversal to emit popstate"));
    }, 1000);
    window.addEventListener("popstate", pop);
    history.back();
  });
  await flushPromises();
}

describe("real app responsive navigation lifecycle", () => {
  it("forgets only a reload-orphaned dialog marker without navigating or clearing pending work", async () => {
    const opaquePending = "unresolved original intent bytes";
    sessionStorage.setItem("aster.cloud.identity.pending.v1", opaquePending);
    const f = await shellFixture(true, {
      asterOverlay: `cloud-${"a".repeat(32)}`,
      unrelatedState: { preserve: "router and caller state" },
    });
    expect(history.state.asterOverlay).toBeUndefined();
    expect(history.state.unrelatedState).toEqual({
      preserve: "router and caller state",
    });
    expect(location.hash).toBe(`#${detailPath}`);
    expect(history.length).toBe(f.startupHistoryLength);
    expect(history.back).not.toHaveBeenCalled();
    expect(sessionStorage.getItem("aster.cloud.identity.pending.v1")).toBe(
      opaquePending,
    );
    sessionStorage.removeItem("aster.cloud.identity.pending.v1");
  });
  it("does not strip another application's history state on startup", async () => {
    await shellFixture(true, { asterOverlay: "unrelated-dialog-marker" });
    expect(history.state.asterOverlay).toBe("unrelated-dialog-marker");
    expect(history.back).not.toHaveBeenCalled();
  });
  it("preserves the real deep-link permission gate without inventing an allowed current destination", async () => {
    const f = await shellFixture();
    await f.router.push("/users");
    await flushPromises();
    expect(f.router.currentRoute.value.path).toBe("/users");
    expect(f.wrapper.get(".aw-mobile-current-label").text()).toBe(
      "Members & access",
    );
    expect(f.wrapper.find('nav.aw-rail-nav a[href="#/users"]').exists()).toBe(
      false,
    );
    expect(
      f.wrapper.findAll('nav.aw-rail-nav a[aria-current="page"]'),
    ).toHaveLength(0);
    expect(f.wrapper.get("#main-content").text()).not.toContain(
      "Synthetic read-only page",
    );
    expect(f.writes).toEqual([]);
  });
  it("uses the compact media query and exposes a modal disclosure with background and scroll isolation", async () => {
    const f = await shellFixture();
    expect(f.matchMedia).toHaveBeenCalledWith(compactQuery);
    expect(f.compactMedia.addEventListener).toHaveBeenCalledWith(
      "change",
      expect.any(Function),
    );
    expect(f.menu().attributes("aria-haspopup")).toBe("dialog");
    expect(f.menu().attributes("aria-expanded")).toBe("false");
    expect(f.dialog()).toBeNull();
    expect(f.app.inert).not.toBe(true);
    await f.openNavigation();
    expect(f.dialog()?.getAttribute("aria-modal")).toBe("true");
    expect(f.app.inert).toBe(true);
    expect(document.body.style.overflow).toBe("hidden");
    expect(f.dialog()?.contains(document.activeElement)).toBe(true);
    expect(f.dialog()?.querySelector('a[href="#/users"]')).toBeNull();
    expect(f.writes).toEqual([]);
  });

  it("keeps only the desktop scrollport out of sequential focus while its real links remain keyboard destinations", async () => {
    const f = await shellFixture(false);
    const desktopNav = f.wrapper.get<HTMLElement>("nav.aw-rail-nav");
    expect(desktopNav.attributes("tabindex")).toBe("-1");
    expect(desktopNav.element.tabIndex).toBe(-1);
    const desktopLinks = desktopNav.findAll<HTMLAnchorElement>("a[href]");
    expect(desktopLinks.length).toBeGreaterThan(0);
    const validLink = (link: HTMLAnchorElement) => {
      expect(link.tabIndex).toBe(0);
      const href = link.getAttribute("href");
      expect(href).toMatch(/^#\//);
      expect(new URL(link.href).origin).toBe(location.origin);
      expect(f.router.resolve(href!.slice(1)).matched.length).toBeGreaterThan(
        0,
      );
    };
    for (const link of desktopLinks) validLink(link.element);
    f.compactMedia.change(true);
    await flushPromises();
    await f.openNavigation();
    const surfaceNav = f
      .dialog()
      ?.querySelector<HTMLElement>("nav.tone-surface");
    expect(surfaceNav).toBeInstanceOf(HTMLElement);
    expect(surfaceNav!.hasAttribute("tabindex")).toBe(false);
    expect(surfaceNav!.classList.contains("aw-rail-nav")).toBe(false);
    const surfaceLinks = [
      ...surfaceNav!.querySelectorAll<HTMLAnchorElement>("a[href]"),
    ];
    expect(surfaceLinks.map((link) => link.getAttribute("href"))).toEqual(
      desktopLinks.map((link) => link.attributes("href")),
    );
    for (const link of surfaceLinks) validLink(link);
    expect(f.writes).toEqual([]);
    // Native Firefox Tab order is checked strictly by the browser harness;
    // jsdom only proves that the actual App attributes reach the intended nav.
  });

  it.each([
    { direction: "right", rowLeft: 230.4, initial: 35, delta: 24 },
    { direction: "left", rowLeft: 83.7, initial: 70, delta: -25 },
  ])(
    "reveals a $direction-clipped focused link using integer padding-aware navigation-only scroll",
    async ({ rowLeft, initial, delta }) => {
      const f = await shellFixture(false);
      const proof = clippedNavigation(f, rowLeft, initial);
      proof.link.focus();
      expect(document.activeElement).toBe(proof.link);
      await flushPromises();
      // Right: ceil(276.4 - (261 - 8)) = 24.
      // Left: floor(83.7 - (100 + 8)) = -25.
      expect(proof.navigation.scrollLeft).toBe(initial + delta);
      expect(proof.row).toHaveBeenCalledTimes(1);
      expect(proof.region).toHaveBeenCalledTimes(1);
      proof.onlyNavigationScrolled();
    },
  );

  it("does not scroll a focused link when modeled pointer-focus intent is not focus-visible", async () => {
    const f = await shellFixture(false);
    const proof = clippedNavigation(f, 230.4, 35, false);
    proof.link.focus();
    await flushPromises();
    expect(document.activeElement).toBe(proof.link);
    expect(proof.matches).toHaveBeenCalledWith(":focus-visible");
    expect(proof.navigation.scrollLeft).toBe(35);
    expect(proof.row).not.toHaveBeenCalled();
    expect(proof.region).not.toHaveBeenCalled();
    proof.onlyNavigationScrolled();
  });

  it("cancels a queued link reveal when focus moves to the main input before the next tick", async () => {
    const f = await shellFixture(false);
    const proof = clippedNavigation(f, 230.4, 35);
    proof.link.focus();
    f.wrapper
      .get<HTMLInputElement>(
        'main input[aria-label="Synthetic read-only filter"]',
      )
      .element.focus();
    await flushPromises();
    expect(document.activeElement).not.toBe(proof.link);
    expect(proof.navigation.scrollLeft).toBe(35);
    expect(proof.row).not.toHaveBeenCalled();
    expect(proof.region).not.toHaveBeenCalled();
    proof.onlyNavigationScrolled();
  });

  it("does not reveal a detached old link after the app unmounts before the next tick", async () => {
    const f = await shellFixture(false);
    const proof = clippedNavigation(f, 230.4, 35);
    proof.link.focus();
    f.unmount();
    expect(proof.link.isConnected).toBe(false);
    await flushPromises();
    expect(proof.navigation.scrollLeft).toBe(35);
    expect(proof.row).not.toHaveBeenCalled();
    expect(proof.region).not.toHaveBeenCalled();
    proof.onlyNavigationScrolled();
  });

  it("closes at the desktop boundary, restores main focus and never resurrects the drawer when compact returns", async () => {
    const f = await shellFixture();
    await f.openNavigation();
    f.compactMedia.change(false);
    await flushPromises();
    expect(f.dialog()).toBeNull();
    expect(f.menu().attributes("aria-expanded")).toBe("false");
    expect(f.app.inert).toBe(false);
    expect(document.body.style.overflow).toBe("auto");
    expect(document.activeElement).toBe(f.wrapper.get("#main-content").element);
    f.compactMedia.change(true);
    await flushPromises();
    expect(f.dialog()).toBeNull();
    expect(f.menu().attributes("aria-expanded")).toBe("false");
    expect(f.app.inert).toBe(false);
    expect(document.body.style.overflow).toBe("auto");
    expect(f.writes).toEqual([]);
  });

  it("moves focus from a desktop rail link to the compact menu without opening navigation", async () => {
    const f = await shellFixture(false);
    const link = f.wrapper.get<HTMLAnchorElement>(
      '.aw-rail-nav a[href="#/nodes"]',
    ).element;
    link.focus();
    expect(document.activeElement).toBe(link);
    f.compactMedia.change(true);
    await flushPromises();
    expect(document.activeElement).toBe(f.menu().element);
    expect(f.dialog()).toBeNull();
    expect(f.menu().attributes("aria-expanded")).toBe("false");
    expect(f.app.inert).not.toBe(true);
    expect(document.body.style.overflow).toBe("auto");
  });

  it("restores compact menu focus when CSS has already blurred the rail link to BODY", async () => {
    const f = await shellFixture(false);
    const link = f.wrapper.get<HTMLAnchorElement>(
      '.aw-rail-nav a[href="#/nodes"]',
    ).element;
    link.focus();
    expect(document.activeElement).toBe(link);
    // A real browser may apply display:none before dispatching the media event.
    // Simulate that ordering explicitly instead of relying on jsdom CSS layout.
    link.blur();
    expect(document.activeElement).toBe(document.body);
    f.compactMedia.change(true);
    await flushPromises();
    expect(document.activeElement).toBe(f.menu().element);
    expect(f.dialog()).toBeNull();
    expect(f.menu().attributes("aria-expanded")).toBe("false");
    expect(document.body.style.overflow).toBe("auto");
    expect(f.writes).toEqual([]);
  });

  it("restores main focus when CSS has already blurred the compact trigger before desktop media arrives", async () => {
    const f = await shellFixture();
    f.menu().element.focus();
    expect(document.activeElement).toBe(f.menu().element);
    f.menu().element.blur();
    expect(document.activeElement).toBe(document.body);
    f.compactMedia.change(false);
    await flushPromises();
    expect(document.activeElement).toBe(f.wrapper.get("#main-content").element);
    expect(f.dialog()).toBeNull();
    expect(f.menu().attributes("aria-expanded")).toBe("false");
    expect(document.body.style.overflow).toBe("auto");
    expect(f.writes).toEqual([]);
  });

  it("does not steal focus from a main-content input after the user leaves the desktop rail", async () => {
    const f = await shellFixture(false);
    const link = f.wrapper.get<HTMLAnchorElement>(
      '.aw-rail-nav a[href="#/nodes"]',
    ).element;
    const input = f.wrapper.get<HTMLInputElement>(
      'main input[aria-label="Synthetic read-only filter"]',
    ).element;
    link.focus();
    expect(document.activeElement).toBe(link);
    input.focus();
    expect(document.activeElement).toBe(input);
    f.compactMedia.change(true);
    await flushPromises();
    expect(document.activeElement).toBe(input);
    expect(f.dialog()).toBeNull();
    expect(f.menu().attributes("aria-expanded")).toBe("false");
    expect(f.app.inert).not.toBe(true);
    expect(f.writes).toEqual([]);
  });

  it("does not revive old rail focus after an outside pointer interaction followed by blur", async () => {
    const f = await shellFixture(false);
    const link = f.wrapper.get<HTMLAnchorElement>(
      '.aw-rail-nav a[href="#/nodes"]',
    ).element;
    link.focus();
    expect(document.activeElement).toBe(link);
    f.wrapper
      .get("#main-content")
      .element.dispatchEvent(new Event("pointerdown", { bubbles: true }));
    link.blur();
    expect(document.activeElement).toBe(document.body);
    f.compactMedia.change(true);
    await flushPromises();
    expect(document.activeElement).toBe(document.body);
    expect(f.dialog()).toBeNull();
    expect(f.menu().attributes("aria-expanded")).toBe("false");
    expect(f.app.inert).not.toBe(true);
    expect(f.writes).toEqual([]);
  });

  it("uses the skip link to focus main without replacing the hash-router destination", async () => {
    const f = await shellFixture();
    const originalPath = f.router.currentRoute.value.fullPath;
    const originalHash = location.hash;
    const skip = f.wrapper.get<HTMLAnchorElement>("a.skip-link").element;
    skip.focus();
    expect(document.activeElement).toBe(skip);
    // The native click is also the activation emitted by Enter on an anchor;
    // do not trigger a private handler or fake a route update in this test.
    let prevented = false;
    skip.addEventListener(
      "click",
      (event) => {
        prevented = event.defaultPrevented;
      },
      { once: true },
    );
    skip.click();
    expect(prevented).toBe(true);
    await new Promise((resolve) => setTimeout(resolve, 0));
    await flushPromises();
    expect(document.activeElement).toBe(f.wrapper.get("#main-content").element);
    expect(f.router.currentRoute.value.fullPath).toBe(originalPath);
    expect(location.hash).toBe(originalHash);
    expect(f.dialog()).toBeNull();
    expect(f.app.inert).not.toBe(true);
    expect(document.body.style.overflow).toBe("auto");
    expect(f.writes).toEqual([]);
  });

  it("commits successful drawer navigation before closing without backing out of the destination", async () => {
    const f = await shellFixture();
    await f.openNavigation();
    await f.destination("/operations");
    expect(f.router.currentRoute.value.path).toBe("/operations");
    expect(location.hash).toBe("#/operations");
    expect(f.dialog()).toBeNull();
    expect(f.menu().attributes("aria-expanded")).toBe("false");
    expect(f.app.inert).toBe(false);
    expect(document.body.style.overflow).toBe("auto");
    expect(history.back).not.toHaveBeenCalled();
    expect(f.writes).toEqual([]);
  });

  it("also closes after a successful route change that did not originate from a drawer link", async () => {
    const f = await shellFixture();
    await f.openNavigation();
    await f.router.push("/nodes");
    await flushPromises();
    expect(f.router.currentRoute.value.path).toBe("/nodes");
    expect(f.dialog()).toBeNull();
    expect(f.menu().attributes("aria-expanded")).toBe("false");
    expect(f.app.inert).toBe(false);
    expect(document.body.style.overflow).toBe("auto");
  });

  it.each(["aborted", "thrown"] as const)(
    "retains the open drawer and background isolation after a %s route failure",
    async (failure) => {
      const f = await shellFixture();
      const onError = vi.fn();
      f.router.onError(onError);
      f.router.beforeEach(() => {
        if (failure === "thrown") throw new Error("Synthetic read-only guard");
        return false;
      });
      await f.openNavigation();
      await f.destination("/operations");
      expect(f.router.currentRoute.value.path).toBe(detailPath);
      expect(f.dialog()).not.toBeNull();
      expect(f.menu().attributes("aria-expanded")).toBe("true");
      expect(f.app.inert).toBe(true);
      expect(document.body.style.overflow).toBe("hidden");
      expect(history.back).not.toHaveBeenCalled();
      expect(onError).toHaveBeenCalledTimes(failure === "thrown" ? 1 : 0);
      expect(f.writes).toEqual([]);
    },
  );

  it("closes on Escape and returns focus and the previous overflow mode to the trigger", async () => {
    const f = await shellFixture();
    await f.openNavigation();
    document.dispatchEvent(
      new KeyboardEvent("keydown", { key: "Escape", bubbles: true }),
    );
    await flushPromises();
    expect(f.dialog()).toBeNull();
    expect(f.menu().attributes("aria-expanded")).toBe("false");
    expect(f.app.inert).toBe(false);
    expect(document.body.style.overflow).toBe("auto");
    expect(document.activeElement).toBe(f.menu().element);
    expect(history.back).toHaveBeenCalledTimes(1);
  });

  it("consumes a real Back traversal to close the drawer without leaving the current route", async () => {
    vi.mocked(history.back).mockRestore();
    const f = await shellFixture();
    await f.openNavigation();
    expect(history.state.asterOverlay).toMatch(/^cloud-/);
    await actualBack();
    expect(f.router.currentRoute.value.path).toBe(detailPath);
    expect(location.hash).toBe(`#${detailPath}`);
    expect(f.dialog()).toBeNull();
    expect(f.menu().attributes("aria-expanded")).toBe("false");
    expect(f.app.inert).toBe(false);
    expect(document.body.style.overflow).toBe("auto");
    expect(document.activeElement).toBe(f.menu().element);
  });

  it("removes compact, appearance and remembered-focus listeners and releases an open overlay when unmounted", async () => {
    const documentAdded = vi.spyOn(document, "addEventListener");
    const documentRemoved = vi.spyOn(document, "removeEventListener");
    const windowAdded = vi.spyOn(window, "addEventListener");
    const windowRemoved = vi.spyOn(window, "removeEventListener");
    const f = await shellFixture();
    // Capture the app-owned listeners before opening UiOverlay adds its own trap.
    const navigationListeners = documentAdded.mock.calls.filter(
      ([event]) => event === "focusin" || event === "pointerdown",
    );
    const windowFocusListeners = windowAdded.mock.calls.filter(
      ([event]) => event === "focus",
    );
    expect(navigationListeners.some(([event]) => event === "focusin")).toBe(
      true,
    );
    expect(navigationListeners.some(([event]) => event === "pointerdown")).toBe(
      true,
    );
    expect(windowFocusListeners.length).toBeGreaterThan(0);
    await f.openNavigation();
    const compactListener = f.compactMedia.addEventListener.mock.calls.find(
      ([event]) => event === "change",
    )?.[1];
    const appearanceListener = f.darkMedia.addEventListener.mock.calls.find(
      ([event]) => event === "change",
    )?.[1];
    expect(compactListener).toBeTypeOf("function");
    expect(appearanceListener).toBeTypeOf("function");
    f.unmount();
    for (const args of navigationListeners)
      expect(documentRemoved).toHaveBeenCalledWith(...args);
    for (const args of windowFocusListeners)
      expect(windowRemoved).toHaveBeenCalledWith(...args);
    expect(f.compactMedia.removeEventListener).toHaveBeenCalledWith(
      "change",
      compactListener,
    );
    expect(f.darkMedia.removeEventListener).toHaveBeenCalledWith(
      "change",
      appearanceListener,
    );
    expect(f.dialog()).toBeNull();
    expect(f.app.inert).toBe(false);
    expect(document.body.style.overflow).toBe("auto");
    f.compactMedia.change(false);
    f.darkMedia.change(true);
    await flushPromises();
    expect(f.dialog()).toBeNull();
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(document.body.style.overflow).toBe("auto");
  });
});

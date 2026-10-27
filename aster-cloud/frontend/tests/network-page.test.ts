import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DOMWrapper, flushPromises, mount } from "@vue/test-utils";
import {
  createMemoryHistory,
  createRouter,
  createWebHashHistory,
} from "vue-router";
import { webcrypto } from "node:crypto";
import { deferred } from "./helpers";
import { node } from "./fixtures";

const vpc = {
  id: "1".repeat(32),
  owner_ref: "2".repeat(32),
  node_id: "node-with-a-long-name-that-remains-readable",
  name: "客户专属网络".repeat(10),
  cidr: "10.20.0.0/24",
  vlan_id: 42,
  state: "planned",
  created_at: "2026-10-23T00:00:00Z",
};
const pool = {
  id: "3".repeat(32),
  node_id: vpc.node_id,
  vpc_id: vpc.id,
  name: "地址池甲",
  cidr: vpc.cidr,
  gateway: "10.20.0.1",
  addresses: ["10.20.0.2", "10.20.0.3"],
  enabled: true,
};
const lease = {
  id: "4".repeat(32),
  node_id: vpc.node_id,
  vpc_id: vpc.id,
  pool_id: pool.id,
  instance_id: "a".repeat(32),
  owner_ref: vpc.owner_ref,
  address: "10.20.0.2",
  state: "reserved",
  created_at: vpc.created_at,
};
const cleanups: Array<() => void> = [];
beforeEach(() => {
  vi.resetModules();
  vi.stubGlobal("crypto", webcrypto);
  sessionStorage.clear();
  Element.prototype.scrollIntoView = vi.fn();
  vi.spyOn(history, "back").mockImplementation(() => {});
  vi.spyOn(HTMLElement.prototype, "getClientRects").mockImplementation(
    () => [new DOMRect(0, 0, 100, 44)] as unknown as DOMRectList,
  );
});
afterEach(() => {
  cleanups
    .splice(0)
    .reverse()
    .forEach((cleanup) => cleanup());
  document.body.innerHTML = "";
  document.body.style.overflow = "";
  history.replaceState(null, "", "/");
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});
const json = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
async function page(
  resolve: (path: string, init?: RequestInit) => Response | Promise<Response>,
  path = "/networks/vpcs",
  hashHistory = false,
) {
  const [
    { default: Page },
    { consoleKey },
    { mockContext },
    { createApiClient },
  ] = await Promise.all([
    import("../src/pages/NetworksPage.vue"),
    import("../src/context"),
    import("./helpers"),
    import("../src/api/client"),
  ]);
  const { context } = mockContext(() => ({}));
  const fetcher = vi
    .fn<typeof fetch>()
    .mockImplementation((url, init) =>
      Promise.resolve(resolve(String(url).replace("/console/v1", ""), init)),
    );
  context.api = createApiClient(fetcher);
  const router = createRouter({
    history: hashHistory ? createWebHashHistory() : createMemoryHistory(),
    routes: [
      { path: "/", redirect: "/networks/vpcs" },
      { path: "/networks/:kind(vpcs|pools|leases)", component: Page },
      { path: "/instances/:id", component: { template: "<div />" } },
    ],
  });
  cleanups.push(() => router.options.history.destroy());
  await router.push(path);
  await router.isReady();
  const wrapper = mount(
    { template: "<RouterView />" },
    {
      attachTo: document.body,
      global: {
        provide: { [consoleKey as symbol]: context },
        plugins: [router],
        stubs: { teleport: true },
      },
    },
  );
  cleanups.push(() => wrapper.unmount());
  return { context, fetcher, router, wrapper, pageComponent: Page };
}
function button(
  wrapper: { findAll(s: string): DOMWrapper<Element>[] },
  text: string,
) {
  const value = wrapper.findAll("button").find((item) => item.text() === text);
  expect(value, text).toBeDefined();
  return value!;
}

describe("network inventory loading and read-only navigation", () => {
  it.each([
    { hashHistory: false, outcome: "success", target: "/networks/pools" },
    { hashHistory: false, outcome: "failure", target: "/networks/pools" },
    { hashHistory: true, outcome: "success", target: "/networks/pools" },
    { hashHistory: true, outcome: "failure", target: "/networks/pools" },
    {
      hashHistory: true,
      outcome: "success",
      target: `/networks/vpcs?cursor=${"f".repeat(32)}`,
    },
  ])(
    "disposes a pending dialog on same-record route reuse (hash: $hashHistory, late: $outcome, to: $target) and resolves only by original-ID GET",
    async ({ hashHistory, outcome, target }) => {
      const pending = deferred<Response>();
      let original: Record<string, unknown> | undefined;
      let originalKey = "";
      const fixture = await page(
        (path, init) => {
          if (path === "/nodes")
            return json({
              items: [{ ...node, id: vpc.node_id }],
              next_cursor: null,
            });
          if (init?.method === "POST") {
            originalKey = (init.headers as Record<string, string>)[
              "Idempotency-Key"
            ]!;
            original = {
              ...vpc,
              ...JSON.parse(String(init.body)),
              id: originalKey,
            };
            return pending.promise;
          }
          if (path === `/networks/vpcs/${originalKey}`)
            return json({ vpc: original });
          return json({
            items: [path === "/networks/pools" ? pool : vpc],
            next_cursor: null,
          });
        },
        "/networks/vpcs",
        hashHistory,
      );
      fixture.context.api.setCSRF("fixture-csrf");
      await flushPromises();
      // Vue Test Utils can create different public proxies for the same setup
      // component. The internal UID is unique per mount and proves real reuse.
      const pageUID = fixture.wrapper.getComponent(fixture.pageComponent).vm.$
        .uid;
      const routeRecord = fixture.router.currentRoute.value.matched.at(-1);
      const fillVPC = async () => {
        const dialog = fixture.wrapper.get('[role="dialog"]');
        for (const [label, value] of [
          ["名称", "慢请求网络"],
          ["客户归属 ID", vpc.owner_ref],
          ["IPv4 网段", vpc.cidr],
          ["VLAN ID", String(vpc.vlan_id)],
        ]) {
          const field = dialog
            .findAll("label.field")
            .find((item) => item.text().startsWith(label!));
          expect(field).toBeDefined();
          await field!.get("input").setValue(value);
        }
        const select = dialog.get('[role="combobox"][aria-label="计算节点"]');
        await select.trigger("keydown", { key: "ArrowDown" });
        await select.trigger("keydown", { key: "Home" });
        await select.trigger("keydown", { key: "Enter" });
      };
      await button(fixture.wrapper, "新建网络").trigger("click");
      await flushPromises();
      await fillVPC();
      await fixture.wrapper.get("form").trigger("submit");
      const postCalls = () =>
        fixture.fetcher.mock.calls.filter(
          ([, init]) => init?.method === "POST",
        );
      await vi.waitFor(() => expect(postCalls()).toHaveLength(1));
      expect(
        fixture.wrapper.get('[role="dialog"] input').attributes("disabled"),
      ).toBeDefined();
      const pendingBefore = sessionStorage.getItem("aster.cloud.pending.v1");
      expect(JSON.parse(pendingBefore!)).toHaveLength(1);

      await fixture.router.push(target);
      await flushPromises();
      expect(fixture.wrapper.getComponent(fixture.pageComponent).vm.$.uid).toBe(
        pageUID,
      );
      expect(
        fixture.router.currentRoute.value.matched.at(-1) === routeRecord,
      ).toBe(true);
      expect(fixture.wrapper.get("h1").text()).toBe(
        target.startsWith("/networks/pools") ? "IP 地址池" : "私有网络",
      );
      if (hashHistory) expect(location.hash).toBe(`#${target}`);
      expect(fixture.wrapper.find('[role="dialog"]').exists()).toBe(false);
      const callsAfterNavigation = fixture.fetcher.mock.calls.length;
      if (outcome === "success")
        pending.resolve(json({ vpc: original, replay: false }, 201));
      else pending.reject(new TypeError("synthetic lost ACK"));
      await flushPromises();
      expect(postCalls()).toHaveLength(1);
      expect(fixture.fetcher.mock.calls).toHaveLength(callsAfterNavigation);
      expect(sessionStorage.getItem("aster.cloud.pending.v1")).toBe(
        pendingBefore,
      );
      expect(fixture.context.notify).not.toHaveBeenCalled();
      expect(fixture.wrapper.find('[role="dialog"]').exists()).toBe(false);

      // Returning to the old form must recover the original key, not POST again.
      await fixture.router.push("/networks/vpcs");
      await flushPromises();
      await button(fixture.wrapper, "新建网络").trigger("click");
      await flushPromises();
      await fillVPC();
      await fixture.wrapper.get("form").trigger("submit");
      await vi.waitFor(() =>
        expect(fixture.wrapper.text()).toContain("结果尚未确认"),
      );
      expect(fixture.wrapper.text()).toContain(originalKey);
      expect(postCalls()).toHaveLength(1);
      await button(fixture.wrapper, "只读核对原记录").trigger("click");
      await vi.waitFor(() =>
        expect(
          JSON.parse(sessionStorage.getItem("aster.cloud.pending.v1") || "[]"),
        ).toHaveLength(0),
      );
      expect(postCalls()).toHaveLength(1);
      expect(
        fixture.fetcher.mock.calls.some(
          ([url, init]) =>
            url === `/console/v1/networks/vpcs/${originalKey}` &&
            init?.method === "GET",
        ),
      ).toBe(true);
      expect(fixture.context.notify).toHaveBeenCalledExactlyOnceWith(
        "已找到原记录。",
      );
    },
  );
  it("shows loading rather than empty data while a real GET is pending", async () => {
    const pending = deferred<Response>();
    const fixture = await page(() => pending.promise);
    expect(fixture.wrapper.find("[role=status]").exists()).toBe(true);
    expect(fixture.wrapper.text()).not.toContain("暂无记录");
    expect(fixture.wrapper.find(".network-record").exists()).toBe(false);
    pending.resolve(json({ items: [vpc], next_cursor: null }));
    await flushPromises();
    expect(fixture.wrapper.find("[role=status]").exists()).toBe(false);
    expect(fixture.wrapper.get(".network-state").text()).toBe("待应用");
  });
  it("has a useful empty state, no fabricated counters and an explicit refresh", async () => {
    const fixture = await page(() => json({ items: [], next_cursor: null }));
    await flushPromises();
    expect(fixture.wrapper.text()).toContain("暂无记录");
    expect(fixture.wrapper.text()).toContain("添加地址池");
    expect(fixture.wrapper.findAll(".network-record")).toHaveLength(0);
    await button(fixture.wrapper, "刷新").trigger("click");
    await flushPromises();
    expect(fixture.fetcher).toHaveBeenCalledTimes(2);
    expect(
      fixture.fetcher.mock.calls.every(([, init]) => init!.method === "GET"),
    ).toBe(true);
  });
  it("keeps a failed request distinct from an empty list and recovers only on reload", async () => {
    let first = true;
    const fixture = await page(() => {
      if (first) {
        first = false;
        return json({ error: { code: "NETWORK_UNAVAILABLE" } }, 503);
      }
      return json({ items: [vpc], next_cursor: null });
    });
    await flushPromises();
    expect(fixture.wrapper.find("[role=alert]").exists()).toBe(true);
    expect(fixture.wrapper.text()).not.toContain("暂无记录");
    await button(fixture.wrapper, "重新加载").trigger("click");
    await flushPromises();
    expect(fixture.wrapper.find("[role=alert]").exists()).toBe(false);
    expect(fixture.wrapper.get(".network-record h2").text()).toBe(vpc.name);
  });
  it.each([
    ["vpcs", vpc, "Not applied"],
    ["leases", lease, "Reserved"],
  ] as const)(
    "does not paint %s plans/reservations as live connectivity",
    async (kind, item, state) => {
      const fixture = await page(
        () => json({ items: [item], next_cursor: null }),
        `/networks/${kind}`,
      );
      fixture.context.prefs.locale.value = "en";
      await flushPromises();
      expect(fixture.wrapper.get(".network-state").text()).toBe(state);
      expect(fixture.wrapper.get(".network-boundary").text()).toContain(
        "do not confirm connectivity",
      );
      expect(fixture.wrapper.get(".network-record code").text()).toBe(item.id);
      expect(fixture.wrapper.text()).toContain(item.owner_ref);
      expect(fixture.wrapper.get(".network-state").classes()).not.toContain(
        "tone-good",
      );
      expect(fixture.fetcher).toHaveBeenCalledOnce();
    },
  );
  it("shows full long identifiers and chosen names, and escaped content, without requiring a tooltip", async () => {
    const item = { ...vpc, name: "客户网络 <img src=x onerror=alert(1)>" };
    const fixture = await page(() =>
      json({ items: [item], next_cursor: null }),
    );
    await flushPromises();
    expect(fixture.wrapper.get("h2").text()).toBe(item.name);
    expect(fixture.wrapper.find("img").exists()).toBe(false);
    expect(fixture.wrapper.text()).toContain(vpc.node_id);
    expect(fixture.wrapper.text()).toContain(vpc.id);
    expect(fixture.wrapper.text()).toContain(vpc.owner_ref);
  });
  it("pages by the exact original cursor, preserves back navigation, and never writes", async () => {
    const reads: string[] = [];
    const next = "f".repeat(32);
    const fixture = await page((path) => {
      reads.push(path);
      return json({
        items: [vpc],
        next_cursor: path.includes("cursor") ? null : next,
      });
    });
    await flushPromises();
    await button(fixture.wrapper, "下一页").trigger("click");
    await flushPromises();
    expect(fixture.router.currentRoute.value.query).toEqual({ cursor: next });
    expect(reads).toEqual(["/networks/vpcs", `/networks/vpcs?cursor=${next}`]);
    fixture.router.back();
    await vi.waitFor(() =>
      expect(fixture.router.currentRoute.value.query).toEqual({}),
    );
    await flushPromises();
    expect(reads.at(-1)).toBe("/networks/vpcs");
    expect(
      fixture.fetcher.mock.calls.every(([, init]) => init!.method === "GET"),
    ).toBe(true);
  });
  it.each([
    "?cursor=ABC",
    "?cursor=",
    "?cursor=" + "a".repeat(32) + "&cursor=" + "b".repeat(32),
    "?ignored=1",
  ])("rejects malformed pagination %s before the transport", async (query) => {
    const fixture = await page(
      () => json({ items: [vpc], next_cursor: null }),
      `/networks/vpcs${query}`,
    );
    await flushPromises();
    expect(fixture.fetcher).not.toHaveBeenCalled();
    expect(fixture.wrapper.find("[role=alert]").exists()).toBe(true);
    expect(fixture.wrapper.find(".network-record").exists()).toBe(false);
  });
  it("discards a late old-kind list when navigating to a different kind", async () => {
    const first = deferred<Response>();
    const fixture = await page((path) =>
      path === "/networks/vpcs"
        ? first.promise
        : json({ items: [pool], next_cursor: null }),
    );
    await fixture.router.push("/networks/pools");
    await flushPromises();
    first.resolve(json({ items: [vpc], next_cursor: null }));
    await flushPromises();
    expect(fixture.wrapper.get("h1").text()).toBe("IP 地址池");
    expect(fixture.wrapper.get("h2").text()).toBe(pool.name);
    expect(fixture.wrapper.text()).not.toContain(vpc.name);
    expect(fixture.fetcher).toHaveBeenCalledTimes(2);
  });
  it("drops a late old-session list after logout", async () => {
    const pending = deferred<Response>();
    const fixture = await page(() => pending.promise);
    fixture.context.session.invalidate();
    pending.resolve(json({ items: [vpc], next_cursor: null }));
    await flushPromises();
    expect(fixture.wrapper.find(".network-record").exists()).toBe(false);
    expect(fixture.wrapper.text()).not.toContain(vpc.name);
    expect(fixture.fetcher).toHaveBeenCalledOnce();
  });
  it("hides creation for read-only staff and exposes pool addresses without a write", async () => {
    const fixture = await page(
      () => json({ items: [pool], next_cursor: null }),
      "/networks/pools",
    );
    fixture.context.session.user.value = {
      ...fixture.context.session.user.value!,
      permissions: ["nodes.read"],
    };
    await flushPromises();
    expect(
      fixture.wrapper
        .findAll("button")
        .some((item) => item.text().includes("新建")),
    ).toBe(false);
    expect(fixture.wrapper.get("details summary").text()).toBe("查看地址");
    expect(fixture.wrapper.get(".address-list").text()).toBe(
      pool.addresses.join(" · "),
    );
    expect(
      fixture.fetcher.mock.calls.every(([, init]) => init!.method === "GET"),
    ).toBe(true);
  });
});

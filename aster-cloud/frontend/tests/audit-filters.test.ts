import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mount, flushPromises } from "@vue/test-utils";
import { createMemoryHistory, createRouter } from "vue-router";
import AuditPage from "../src/pages/AuditPage.vue";
import { ApiError } from "../src/api/client";
import { consoleKey } from "../src/context";
import { deferred, mockContext } from "./helpers";

const wrappers: Array<{ unmount(): void }> = [];
beforeEach(() => {
  Element.prototype.scrollIntoView = vi.fn();
});
afterEach(() => {
  wrappers.splice(0).forEach((wrapper) => wrapper.unmount());
  document.body.innerHTML = "";
  vi.restoreAllMocks();
});
async function fixture(
  initial = "/audit",
  resolver: (path: string) => unknown | Promise<unknown> = () => ({
    items: [],
    next_cursor: null,
  }),
) {
  const reads: string[] = [];
  const { context } = mockContext((_method, path) => {
    reads.push(path);
    return resolver(path);
  });
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [{ path: "/audit", component: AuditPage }],
  });
  await router.push(initial);
  await router.isReady();
  const wrapper = mount(AuditPage, {
    attachTo: document.body,
    global: {
      plugins: [router],
      provide: { [consoleKey as symbol]: context },
    },
  });
  wrappers.push(wrapper);
  await flushPromises();
  return { wrapper, router, context, reads };
}
describe("audit filtering and route history", () => {
  it("reads the exact applied URL filters and displays a filtered empty state", async () => {
    const { wrapper, reads } = await fixture(
      "/audit?source=identity&action=identity.login&from=2026-10-23T08%3A00%3A00%2B08%3A00",
    );
    expect(reads).toEqual([
      "/audit?source=identity&action=identity.login&from=2026-10-23T00%3A00%3A00Z",
    ]);
    expect(wrapper.text()).toContain("没有符合条件的记录");
    expect(wrapper.get('input[name="from"]').element).toHaveProperty(
      "value",
      "2026-10-23T00:00:00Z",
    );
    expect(wrapper.find('input[type="datetime-local"]').exists()).toBe(false);
  });
  it("shows invalid link parameters as an error without fetching or claiming no records", async () => {
    const { wrapper, reads } = await fixture(
      "/audit?source=identity&source=resource",
    );
    expect(reads).toEqual([]);
    expect(wrapper.get('[role="alert"]').text()).toContain("筛选链接无效");
    expect(wrapper.text()).not.toContain("暂无审计记录");
    expect(wrapper.text()).not.toContain("没有符合条件的记录");
  });
  it("applies draft filters with Enter submission, removes the old cursor and can go Back", async () => {
    const { wrapper, router, reads } = await fixture(
      "/audit?action=operation.succeeded&cursor=opaque-old",
    );
    await wrapper.get('input[name="actor"]').setValue("user:ABC123");
    await wrapper
      .get('input[name="actor"]')
      .trigger("keydown", { key: "Enter" });
    await wrapper.get("form").trigger("submit");
    await flushPromises();
    expect(router.currentRoute.value.query).toEqual({
      action: "operation.succeeded",
      actor: "user:ABC123",
    });
    expect(reads.at(-1)).toBe(
      "/audit?action=operation.succeeded&actor=user%3AABC123",
    );
    router.back();
    await flushPromises();
    expect(router.currentRoute.value.query.cursor).toBe("opaque-old");
    expect(wrapper.get('input[name="actor"]').element).toHaveProperty(
      "value",
      "",
    );
  });
  it("supports keyboard category selection without sending until the form is applied", async () => {
    const { wrapper, router, reads } = await fixture();
    await wrapper.get(".filter-toggle").trigger("click");
    const select = wrapper.get('[role="combobox"]');
    expect(select.attributes("aria-label")).toBe("事件类别");
    await select.trigger("keydown", { key: "ArrowDown" });
    await select.trigger("keydown", { key: "ArrowDown" });
    await select.trigger("keydown", { key: "Enter" });
    expect(select.text()).toContain("账户安全");
    expect(reads).toEqual(["/audit"]);
    await wrapper.get("form").trigger("submit");
    await flushPromises();
    expect(router.currentRoute.value.query).toEqual({ source: "identity" });
    expect(reads.at(-1)).toBe("/audit?source=identity");
    expect(wrapper.find("select").exists()).toBe(false);
  });
  it("keeps exact draft input and focuses an invalid field without changing the applied route", async () => {
    const { wrapper, router, reads } = await fixture("/audit?source=resource");
    await wrapper.get('input[name="actor"]').setValue(" user:ABC ");
    await wrapper.get("form").trigger("submit");
    await flushPromises();
    expect(wrapper.get('[role="alert"]').text()).toContain("不含空格");
    expect(wrapper.get('input[name="actor"]').attributes("aria-invalid")).toBe(
      "true",
    );
    expect(document.activeElement).toBe(
      wrapper.get('input[name="actor"]').element,
    );
    expect(router.currentRoute.value.query).toEqual({ source: "resource" });
    expect(reads).toEqual(["/audit?source=resource"]);
  });
  it("paginates with the same filters and clearing them removes every parameter", async () => {
    const { wrapper, router, reads } = await fixture(
      "/audit?actor=user%3AABC",
      () => ({ items: [], next_cursor: "opaque~cursor" }),
    );
    const button = (label: string) =>
      wrapper.findAll("button").find((b) => b.text() === label)!;
    await button("下一页").trigger("click");
    await flushPromises();
    expect(router.currentRoute.value.query).toEqual({
      actor: "user:ABC",
      cursor: "opaque~cursor",
    });
    expect(reads.at(-1)).toBe("/audit?actor=user%3AABC&cursor=opaque%7Ecursor");
    await button("回到首页").trigger("click");
    await flushPromises();
    expect(router.currentRoute.value.query).toEqual({ actor: "user:ABC" });
    await button("清除筛选").trigger("click");
    await flushPromises();
    expect(router.currentRoute.value.query).toEqual({});
    expect(reads.at(-1)).toBe("/audit");
  });
  it("shows rejected cursor or filters as an error, not an empty result", async () => {
    const { wrapper, router } = await fixture(
      "/audit?action=identity.login&cursor=opaque",
      (path) => {
        if (path.includes("cursor="))
          throw new ApiError("invalid", "INVALID_QUERY", 400);
        return { items: [], next_cursor: null };
      },
    );
    expect(wrapper.get('[role="alert"]').text()).toContain("筛选链接无效");
    expect(wrapper.text()).not.toContain("没有符合条件的记录");
    const first = wrapper
      .findAll("button")
      .find((b) => b.text() === "回到结果首页")!;
    await first.trigger("click");
    await flushPromises();
    expect(router.currentRoute.value.query).toEqual({
      action: "identity.login",
    });
    expect(wrapper.text()).toContain("没有符合条件的记录");
  });
  it("retains a network error and retries only the explicit filtered read", async () => {
    let failed = true;
    const { wrapper, reads } = await fixture("/audit?target=Node-A", () => {
      if (failed) throw new ApiError("network");
      return { items: [], next_cursor: null };
    });
    expect(wrapper.get('[role="alert"]').text()).toContain("连接失败");
    expect(wrapper.text()).not.toContain("没有符合条件的记录");
    failed = false;
    await wrapper
      .findAll("button")
      .find((b) => b.text() === "重新加载")!
      .trigger("click");
    await flushPromises();
    expect(reads).toEqual(["/audit?target=Node-A", "/audit?target=Node-A"]);
    expect(wrapper.text()).toContain("没有符合条件的记录");
  });
  it("does not replace a newer filter result with a late old response", async () => {
    const old = deferred<unknown>();
    const { wrapper, router } = await fixture(
      "/audit?action=identity.login",
      (path) =>
        path.includes("identity.login")
          ? old.promise
          : { items: [], next_cursor: null },
    );
    expect(wrapper.find('[role="status"]').exists()).toBe(true);
    await router.push("/audit?action=identity.logout");
    await flushPromises();
    old.resolve({
      items: [
        {
          id: 1,
          source: "identity",
          action: "identity.login",
          actor: "stale-actor",
          target: "old",
          created_at: "2026-10-23T00:00:00Z",
        },
      ],
      next_cursor: null,
    });
    await flushPromises();
    expect(wrapper.text()).not.toContain("stale-actor");
    expect(wrapper.text()).toContain("没有符合条件的记录");
  });
  it("uses English copy and explicit UTC record times without rewriting event values", async () => {
    const { wrapper, context } = await fixture(
      "/audit?source=resource",
      () => ({
        items: [
          {
            id: 3,
            source: "resource",
            action: "Vendor.Exact",
            actor: "user:ABC",
            target: "Node-A",
            created_at: "2026-10-23T23:59:59Z",
          },
        ],
        next_cursor: null,
      }),
    );
    context.prefs.locale.value = "en";
    await flushPromises();
    expect(wrapper.text()).toContain("Resource operations");
    expect(wrapper.text()).toContain("All conditions apply together");
    expect(wrapper.get("time").text()).toContain("23:59:59");
    expect(wrapper.text()).toContain("UTC");
    expect(wrapper.get(".audit-action").text()).toBe("Vendor.Exact");
    expect(wrapper.text()).toContain("user:ABC");
  });
  it("clears an active result and never fetches an invalid Back or linked query", async () => {
    const { wrapper, router, reads } = await fixture();
    await router.push("/audit?from=2026-02-30T00%3A00%3A00Z");
    await flushPromises();
    expect(reads).toEqual(["/audit"]);
    expect(wrapper.get('[role="alert"]').text()).toContain("开始时间");
    expect(wrapper.text()).not.toContain("暂无审计记录");
  });
  it("compares UTC microseconds before applying a time range", async () => {
    const { wrapper, reads } = await fixture();
    await wrapper.get(".filter-toggle").trigger("click");
    await wrapper
      .get('input[name="from"]')
      .setValue("2026-10-23T08:00:00.123456+08:00");
    await wrapper
      .get('input[name="until"]')
      .setValue("2026-10-23T00:00:00.123456Z");
    await wrapper.get("form").trigger("submit");
    await flushPromises();
    expect(wrapper.get('[role="alert"]').text()).toContain(
      "结束时间必须晚于开始时间",
    );
    expect(document.activeElement).toBe(
      wrapper.get('input[name="until"]').element,
    );
    expect(reads).toEqual(["/audit"]);
    await wrapper
      .get('input[name="until"]')
      .setValue("2026-10-23T00:00:00.123457Z");
    await wrapper.get("form").trigger("submit");
    await flushPromises();
    expect(reads.at(-1)).toBe(
      "/audit?from=2026-10-23T00%3A00%3A00.123456Z&until=2026-10-23T00%3A00%3A00.123457Z",
    );
  });
  it("does not expose a pending audit read after the session is invalidated", async () => {
    const response = deferred<unknown>();
    const { wrapper, context, reads } = await fixture(
      "/audit",
      () => response.promise,
    );
    context.session.invalidate();
    await flushPromises();
    response.resolve({
      items: [
        {
          id: 1,
          source: "identity",
          action: "identity.login",
          actor: "revoked-secret",
          target: "account",
          created_at: "2026-10-23T00:00:00Z",
        },
      ],
      next_cursor: null,
    });
    await flushPromises();
    expect(wrapper.text()).not.toContain("revoked-secret");
    expect(reads).toEqual(["/audit"]);
  });
});

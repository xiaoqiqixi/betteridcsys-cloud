import { afterEach, describe, expect, it, vi } from "vitest";
import { flushPromises, mount } from "@vue/test-utils";
import { webcrypto } from "node:crypto";
import InstanceLedger from "../src/components/InstanceLedger.vue";
import InstancesPage from "../src/pages/InstancesPage.vue";
import { consoleKey } from "../src/context";
import { ApiError } from "../src/api/client";
import { instance } from "./fixtures";
import { deferred, mockContext } from "./helpers";

const cleanups: Array<() => void> = [];
const labels = {
  colInstance: "Instance",
  colState: "State",
  colSpec: "CPU / memory / disk",
  colNode: "Node",
  viewDetails: "View details",
  fullId: "Instance ID",
  copyId: "Copy ID",
  expandId: "Show full ID",
  collapseId: "Collapse full ID",
};
const row = {
  id: instance.id,
  href: `#/instances/${instance.id}`,
  hostname: "api-server-01",
  stateLabel: "Sending",
  stateTone: "info" as const,
  cpuLabel: "2 vCPU",
  memoryLabel: "4 GiB",
  diskLabel: "40 GiB",
  nodeLabel: "node-a",
};
afterEach(() => {
  cleanups
    .splice(0)
    .reverse()
    .forEach((fn) => fn());
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  document.body.innerHTML = "";
});
function ledger(overrides = {}) {
  const wrapper = mount(InstanceLedger, {
    props: { items: [row], labels, ...overrides },
  });
  cleanups.push(() => wrapper.unmount());
  return wrapper;
}
async function page(
  resolver: Parameters<typeof mockContext>[0] = () => ({
    items: [instance],
    next_cursor: "",
  }),
  viewer = false,
) {
  vi.stubGlobal("crypto", webcrypto);
  const state = mockContext(resolver);
  if (viewer)
    state.context.session.user.value = {
      ...state.context.session.user.value!,
      role: "viewer",
      permissions: ["instances.read"],
    };
  const wrapper = mount(InstancesPage, {
    global: { provide: { [consoleKey as symbol]: state.context } },
  });
  cleanups.push(() => wrapper.unmount());
  await flushPromises();
  return { wrapper, ...state };
}

describe("Gemini instance ledger presentation", () => {
  it("keeps configuration, node and actionable links in both responsive views", () => {
    const w = ledger();
    for (const selector of [".aw-ledger-desktop", ".aw-ledger-mobile"]) {
      const view = w.get(selector);
      for (const text of [
        row.hostname,
        row.cpuLabel,
        row.memoryLabel,
        row.diskLabel,
        row.nodeLabel,
        row.stateLabel,
      ])
        expect(view.text()).toContain(text);
      for (const link of view.findAll("a"))
        expect(link.attributes("href")).toBe(row.href);
      expect(view.find('button[aria-expanded="false"]').exists()).toBe(true);
    }
    expect(w.emitted()).toEqual({});
    expect(w.find("tr[tabindex]").exists()).toBe(false);
  });
  it("expands the actual complete identifier and only emits the explicitly clicked copy", async () => {
    const w = ledger();
    await w
      .get('.aw-ledger-mobile button[aria-expanded="false"]')
      .trigger("click");
    expect(w.get(".aw-mobile-id-drawer code").text()).toBe(row.id);
    expect(
      w.find('.aw-ledger-desktop button[aria-expanded="true"]').exists(),
    ).toBe(true);
    expect(w.emitted("copy-id")).toBeUndefined();
    await w.get(".aw-ledger-mobile .aw-copy-btn").trigger("click");
    expect(w.emitted("copy-id")).toEqual([[row.id]]);
  });
  it("escapes names and preserves ordinary anchor modifier behaviour", async () => {
    const w = ledger({
      items: [{ ...row, hostname: '<img src=x onerror="alert(1)">' }],
    });
    expect(w.find("img").exists()).toBe(false);
    const link = w.get("a");
    expect(link.attributes("title")).toContain("<img");
    const event = new MouseEvent("click", { ctrlKey: true, cancelable: true });
    link.element.dispatchEvent(event);
    expect(event.defaultPrevented).toBe(false);
    expect(w.emitted("copy-id")).toBeUndefined();
  });
});

describe("real API adapter is read-only", () => {
  it("maps validated backend fields and uses the original permission gate", async () => {
    const gets: string[] = [];
    const { wrapper, calls } = await page((method, path) => {
      gets.push(`${method} ${path}`);
      return { items: [instance], next_cursor: "" };
    }, true);
    expect(gets).toEqual(["GET /instances"]);
    expect(wrapper.find(".aw-instance-ledger").exists()).toBe(true);
    expect(wrapper.text()).toContain(instance.node_id);
    expect(wrapper.text()).toContain("2 vCPU");
    expect(wrapper.text()).toContain("4 GiB");
    expect(wrapper.text()).not.toContain("创建实例");
    expect(calls).toEqual([]);
  });
  it("does not replace backend errors with a fake empty/success list", async () => {
    const { wrapper, calls } = await page(() => {
      throw new ApiError("unavailable");
    });
    expect(wrapper.find(".aw-instance-ledger").exists()).toBe(false);
    expect(wrapper.text()).toContain("服务暂时不可用");
    expect(calls).toEqual([]);
  });
  it("copy reports success only after the browser confirms the actual clipboard write", async () => {
    const pending = deferred<void>();
    const writeText = vi.fn(() => pending.promise);
    vi.stubGlobal("navigator", { clipboard: { writeText } });
    const { wrapper, context, calls } = await page();
    await wrapper.get(".aw-ledger-mobile .aw-copy-btn").trigger("click");
    expect(writeText).toHaveBeenCalledExactlyOnceWith(instance.id);
    expect(context.notify).not.toHaveBeenCalled();
    pending.resolve();
    await flushPromises();
    expect(context.notify).toHaveBeenCalledExactlyOnceWith("实例 ID 已复制。");
    expect(calls).toEqual([]);
  });
  it("never leaks a late copy notice into a different session", async () => {
    const pending = deferred<void>();
    vi.stubGlobal("navigator", {
      clipboard: { writeText: () => pending.promise },
    });
    const { wrapper, context } = await page();
    await wrapper.get(".aw-ledger-mobile .aw-copy-btn").trigger("click");
    context.session.epoch.value++;
    pending.resolve();
    await flushPromises();
    expect(context.notify).not.toHaveBeenCalled();
  });
  it("offers manual full-ID copying on browser clipboard refusal without any API write", async () => {
    vi.stubGlobal("navigator", {
      clipboard: { writeText: () => Promise.reject(new Error("denied")) },
    });
    const { wrapper, context, calls } = await page();
    await wrapper.get(".aw-ledger-mobile .aw-copy-btn").trigger("click");
    await flushPromises();
    expect(context.notify).toHaveBeenCalledWith(
      expect.stringContaining("手动复制"),
      "error",
    );
    expect(calls).toEqual([]);
  });
});

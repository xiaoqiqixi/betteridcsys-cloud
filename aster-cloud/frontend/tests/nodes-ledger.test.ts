import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { flushPromises, mount, type VueWrapper } from "@vue/test-utils";
import { webcrypto } from "node:crypto";
import NodesPage from "../src/pages/NodesPage.vue";
import InlineError from "../src/components/InlineError.vue";
import { ApiError } from "../src/api/client";
import type { Node } from "../src/api/types";
import { consoleKey } from "../src/context";
import { dateText, sizeMiB } from "../src/format";
import { node } from "./fixtures";
import { mockContext } from "./helpers";

const mounted: VueWrapper[] = [];
beforeEach(() => {
  vi.stubGlobal("crypto", webcrypto);
  sessionStorage.clear();
});
afterEach(() => {
  mounted.splice(0).forEach((wrapper) => wrapper.unmount());
  vi.unstubAllGlobals();
  sessionStorage.clear();
});

async function page(
  write: (body: unknown) => unknown = () => ({ maintenance: true }),
  read: (() => unknown) | undefined = undefined,
  readonly = false,
  row: Node = node,
) {
  const fixture = mockContext((method, path, body) => {
    if (method === "GET" && path === "/nodes")
      return read ? read() : { items: [row], next_cursor: null };
    if (method === "POST" && path === `/nodes/${row.id}/maintenance`)
      return write(body);
    throw new Error("Unexpected node request");
  });
  if (readonly && fixture.context.session.user.value) {
    fixture.context.session.user.value = {
      ...fixture.context.session.user.value,
      role: "viewer",
      permissions: ["nodes.read"],
    };
  }
  const wrapper = mount(NodesPage, {
    global: {
      provide: { [consoleKey as symbol]: fixture.context },
      // Overlay behavior has its own tests. This test retains the real page's
      // confirmation and mutation logic while rendering its slots locally.
      stubs: {
        UiOverlay: {
          props: ["open"],
          template:
            '<section v-if="open"><slot /><slot name="footer" /></section>',
        },
      },
    },
  });
  mounted.push(wrapper);
  await flushPromises();
  return { ...fixture, wrapper };
}

describe("node resource ledger presentation preserves existing controls", () => {
  it("keeps semantic desktop columns and every free/reserved resource", async () => {
    const { wrapper, calls } = await page();
    const table = wrapper.get(".node-table");
    expect(table.get("caption").text()).toBe("节点资源与维护状态");
    expect(table.findAll('thead th[scope="col"]')).toHaveLength(7);
    expect(table.get('tbody th[scope="row"]').text()).toContain(node.id);
    expect(table.text()).toContain(node.datacenter_id);
    for (const text of [
      String(node.free_cpu),
      String(node.reserved_cpu),
      sizeMiB(node.free_memory_mib),
      sizeMiB(node.reserved_memory_mib),
      String(node.free_disk_gib),
      String(node.reserved_disk_gib),
      dateText(node.heartbeat_at, "zh-CN"),
    ])
      expect(table.text()).toContain(text);
    expect(calls).toHaveLength(0);
  });

  it("keeps all mobile capacity values without hiding a column or inventing utilization", async () => {
    const { wrapper } = await page();
    const entry = wrapper.get(".node-entry");
    expect(entry.text()).toContain(node.id);
    expect(entry.text()).toContain(node.datacenter_id);
    expect(entry.get(".capacity-column-labels").text()).toContain("已预留");
    expect(entry.findAll(".node-budget > div")).toHaveLength(3);
    expect(
      entry.findAll(".node-budget dd").map((value) => value.text()),
    ).toEqual([
      `可用${node.free_cpu}`,
      `已预留${node.reserved_cpu}`,
      `可用${sizeMiB(node.free_memory_mib)}`,
      `已预留${sizeMiB(node.reserved_memory_mib)}`,
      `可用${node.free_disk_gib}`,
      `已预留${node.reserved_disk_gib}`,
    ]);
    expect(entry.text()).toContain(dateText(node.heartbeat_at, "zh-CN"));
    expect(entry.text()).not.toContain("%");
  });

  it("retains disabled maintenance for read-only staff in both layouts", async () => {
    const { wrapper, calls } = await page(undefined, undefined, true);
    const buttons = wrapper
      .findAll("button")
      .filter((button) => button.text() === "维护");
    expect(buttons).toHaveLength(2);
    expect(
      buttons.every((button) => button.attributes("disabled") !== undefined),
    ).toBe(true);
    expect(calls).toHaveLength(0);
  });

  it("does not write until exact existing node-ID confirmation", async () => {
    const { wrapper, calls } = await page();
    await wrapper.get(".node-ledger-mobile .ui-button").trigger("click");
    const confirm = () =>
      wrapper.findAll("button").find((button) => button.text() === "确认更改")!;
    expect(confirm().attributes("disabled")).toBeDefined();
    await wrapper.get("input").setValue(node.id + "-wrong");
    expect(confirm().attributes("disabled")).toBeDefined();
    expect(calls).toHaveLength(0);
    await wrapper.get("input").setValue(node.id);
    await confirm().trigger("click");
    // Native WebCrypto hashing can outlive flushPromises under parallel load.
    // Observe the actual request and completed page state, not a timer tick.
    await expect.poll(() => calls.length, { timeout: 5000 }).toBe(1);
    expect(calls[0]?.method).toBe("POST");
    expect(calls[0]?.path).toBe(`/nodes/${node.id}/maintenance`);
    expect(calls[0]?.body).toEqual({ enabled: true });
    await expect
      .poll(() => wrapper.find("input").exists(), { timeout: 5000 })
      .toBe(false);
  });

  it.each([
    {
      outcome: "empty",
      read: () => ({ items: [], next_cursor: null }),
      text: "暂无节点",
    },
    {
      outcome: "error",
      read: () => {
        throw new ApiError("network");
      },
      text: "暂时无法加载",
    },
  ])("keeps the existing $outcome state", async ({ read, text }) => {
    const { wrapper, calls } = await page(undefined, read);
    expect(wrapper.text()).toContain(text);
    expect(wrapper.find(".node-table").exists()).toBe(false);
    expect(calls).toHaveLength(0);
  });

  it("preserves unknown-result lock and never sends a second maintenance POST", async () => {
    const unknownNode = { ...node, id: "node-unknown-ledger" };
    const { wrapper, calls } = await page(
      () => {
        throw new ApiError("unknown");
      },
      undefined,
      false,
      unknownNode,
    );
    await wrapper.get(".node-ledger-desktop .ui-button").trigger("click");
    await wrapper.get("input").setValue(unknownNode.id);
    const confirm = () =>
      wrapper.findAll("button").find((button) => button.text() === "确认更改")!;
    await confirm().trigger("click");
    await expect.poll(() => calls.length, { timeout: 5000 }).toBe(1);
    await expect
      .poll(() => wrapper.findComponent(InlineError).props("error"), {
        timeout: 5000,
      })
      .toBe("unknown");
    expect(calls[0]?.path).toBe(`/nodes/${unknownNode.id}/maintenance`);
    expect(confirm().attributes("disabled")).toBeDefined();
    await confirm().trigger("click");
    await flushPromises();
    expect(calls).toHaveLength(1);
    expect(wrapper.find("input").exists()).toBe(true);
  });
});

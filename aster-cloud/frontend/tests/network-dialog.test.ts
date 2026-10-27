import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DOMWrapper, flushPromises, mount } from "@vue/test-utils";
import { webcrypto } from "node:crypto";
import { createMemoryHistory, createRouter } from "vue-router";
import type { NetworkKind } from "../src/api/network";
import { deferred } from "./helpers";
import { node } from "./fixtures";

const owner = "2".repeat(32),
  vpcID = "1".repeat(32),
  poolID = "3".repeat(32),
  instanceID = "a".repeat(32);
const vpc = {
  id: vpcID,
  owner_ref: owner,
  node_id: node.id,
  name: "网络甲",
  cidr: "10.20.0.0/24",
  vlan_id: 42,
  state: "planned",
  created_at: "2026-10-23T00:00:00Z",
};
const pool = {
  id: poolID,
  node_id: node.id,
  vpc_id: vpcID,
  name: "地址池甲",
  cidr: vpc.cidr,
  gateway: "10.20.0.1",
  addresses: ["10.20.0.2", "10.20.0.3"],
  enabled: true,
};
const pendingStorage = "aster.cloud.pending.v1";
const cleanups: Array<() => void> = [];
beforeEach(() => {
  vi.resetModules();
  sessionStorage.clear();
  vi.stubGlobal("crypto", webcrypto);
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
  history.replaceState(null, "");
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});
function response(
  kind: NetworkKind,
  key: string,
  body: Record<string, unknown>,
) {
  return kind === "vpcs"
    ? { vpc: { ...vpc, ...body, id: key }, replay: false }
    : kind === "pools"
      ? { pool: { ...pool, ...body, id: key }, replay: false }
      : {
          lease: {
            id: key,
            node_id: node.id,
            vpc_id: vpcID,
            ...body,
            address: body.address || "10.20.0.2",
            state: "reserved",
            created_at: vpc.created_at,
          },
          replay: false,
        };
}
async function dialog(
  kind: NetworkKind,
  resolve?: (
    method: string,
    path: string,
    body: unknown,
    key: string,
  ) => unknown | Promise<unknown>,
) {
  const [{ default: Dialog }, { consoleKey }, { mockContext }, client] =
    await Promise.all([
      import("../src/components/NetworkCreateDialog.vue"),
      import("../src/context"),
      import("./helpers"),
      import("../src/api/client"),
    ]);
  const reads: string[] = [];
  const result = mockContext((method, path, body, key) => {
    if (method === "GET") reads.push(path);
    if (resolve) return resolve(method, path, body, key);
    if (method === "GET" && path === "/nodes")
      return { items: [node], next_cursor: null };
    if (method === "GET" && path === "/networks/vpcs")
      return { items: [vpc], next_cursor: null };
    if (method === "GET" && path === "/networks/pools")
      return { items: [pool], next_cursor: null };
    return response(kind, key, body as Record<string, unknown>);
  });
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [{ path: "/", component: { template: "<div />" } }],
  });
  await router.push("/");
  await router.isReady();
  const wrapper = mount(Dialog, {
    attachTo: document.body,
    props: { open: true, kind },
    global: {
      provide: { [consoleKey as symbol]: result.context },
      plugins: [router],
      stubs: { teleport: true },
    },
  });
  cleanups.push(() => wrapper.unmount());
  await flushPromises();
  return { ...result, ...client, wrapper, reads };
}
function button(
  wrapper: { findAll(s: string): DOMWrapper<Element>[] },
  text: string,
) {
  const value = wrapper.findAll("button").find((item) => item.text() === text);
  expect(value, text).toBeDefined();
  return value!;
}
async function input(
  wrapper: { findAll(s: string): DOMWrapper<Element>[] },
  label: string,
  value: string,
) {
  const field = wrapper
    .findAll("label.field")
    .find((item) => item.text().startsWith(label));
  expect(field, label).toBeDefined();
  await field!.get("input,textarea").setValue(value);
}
async function choose(
  wrapper: { get(s: string): Pick<DOMWrapper<Element>, "trigger"> },
  label: string,
) {
  const select = wrapper.get(`[role=combobox][aria-label="${label}"]`);
  await select.trigger("keydown", { key: "ArrowDown" });
  await select.trigger("keydown", { key: "Home" });
  await select.trigger("keydown", { key: "Enter" });
}
async function fill(
  wrapper: Parameters<typeof input>[0] & Parameters<typeof choose>[0],
  kind: NetworkKind,
) {
  if (kind !== "leases") {
    await input(wrapper, "名称", "测试配置");
    await choose(wrapper, "计算节点");
    await input(wrapper, "IPv4 网段", "10.20.0.0/24");
  }
  if (kind !== "pools") await input(wrapper, "客户归属 ID", owner);
  if (kind === "vpcs") await input(wrapper, "VLAN ID", "42");
  if (kind === "pools") {
    await input(wrapper, "网关", "10.20.0.1");
    await input(wrapper, "可分配地址", "10.20.0.3\n10.20.0.2");
  }
  if (kind === "leases") {
    await choose(wrapper, "IP 地址池");
    await input(wrapper, "实例 ID", instanceID);
  }
}
const entries = () =>
  JSON.parse(sessionStorage.getItem(pendingStorage) || "[]") as Array<
    Record<string, unknown>
  >;

describe("network configuration stays separate from host/VM actions", () => {
  it.each(["vpcs", "pools", "leases"] as const)(
    "loads approved options and sends one explicit %s intent only",
    async (kind) => {
      const fixture = await dialog(kind);
      expect(fixture.calls).toHaveLength(0);
      expect(fixture.wrapper.find("select").exists()).toBe(false);
      expect(
        fixture.wrapper.get("form").attributes("novalidate"),
      ).toBeDefined();
      expect(fixture.wrapper.text()).toContain("保存后为待应用状态");
      expect(fixture.wrapper.text()).toContain("地址会保持预留");
      await fill(fixture.wrapper, kind);
      await fixture.wrapper.get("form").trigger("submit");
      await vi.waitFor(() => expect(fixture.calls).toHaveLength(1));
      await flushPromises();
      expect(fixture.calls[0]).toMatchObject({
        method: "POST",
        path: `/networks/${kind}`,
      });
      expect(fixture.calls[0]!.key).toMatch(/^[a-f0-9]{32}$/);
      expect(fixture.wrapper.emitted("saved")).toHaveLength(1);
      expect(fixture.context.notify).toHaveBeenCalledWith(
        expect.stringContaining("尚未应用到节点"),
      );
      expect(
        fixture.calls.every((call) => call.path.startsWith("/networks/")),
      ).toBe(true);
      expect(entries()).toHaveLength(0);
    },
  );
  it("blocks a submit without nodes.manage even if a form event is forged", async () => {
    const fixture = await dialog("vpcs");
    await fill(fixture.wrapper, "vpcs");
    fixture.context.session.user.value = {
      ...fixture.context.session.user.value!,
      permissions: ["nodes.read"],
    };
    await fixture.wrapper.get("form").trigger("submit");
    await flushPromises();
    expect(fixture.calls).toHaveLength(0);
    expect(
      button(fixture.wrapper, "保存").attributes("disabled"),
    ).toBeDefined();
  });
  it("shows custom validation and preserves the draft without native browser validity UI", async () => {
    const fixture = await dialog("vpcs");
    await input(fixture.wrapper, "名称", "未完成草稿");
    await fixture.wrapper.get("form").trigger("submit");
    await flushPromises();
    expect(fixture.calls).toHaveLength(0);
    expect(fixture.wrapper.find("[role=alert]").exists()).toBe(true);
    expect(
      (fixture.wrapper.get("input").element as HTMLInputElement).value,
    ).toBe("未完成草稿");
  });
  it.each(["QuotaExceededError", "SecurityError"])(
    "write-ahead %s sends zero POSTs",
    async (name) => {
      const fixture = await dialog("vpcs");
      await fill(fixture.wrapper, "vpcs");
      vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
        throw new DOMException("private storage issue", name);
      });
      await fixture.wrapper.get("form").trigger("submit");
      await vi.waitFor(() =>
        expect(fixture.wrapper.text()).toContain("服务暂时不可用"),
      );
      expect(fixture.calls).toHaveLength(0);
      expect(fixture.wrapper.emitted("saved")).toBeUndefined();
    },
  );
  it("retains an unknown write and recovers only by reading its original ID", async () => {
    let fixture: Awaited<ReturnType<typeof dialog>>;
    let original: ReturnType<typeof response>;
    fixture = await dialog("vpcs", (method, path, body, key) => {
      if (path === "/nodes") return { items: [node], next_cursor: null };
      if (method === "POST") {
        original = response("vpcs", key, body as Record<string, unknown>);
        throw new fixture.ApiError("unknown");
      }
      return original!;
    });
    await fill(fixture.wrapper, "vpcs");
    await fixture.wrapper.get("form").trigger("submit");
    await vi.waitFor(() => expect(fixture.calls).toHaveLength(1));
    await flushPromises();
    const key = fixture.calls[0]!.key;
    expect(entries()).toHaveLength(1);
    expect(fixture.wrapper.text()).toContain(key);
    await fixture.wrapper.get("form").trigger("submit");
    expect(fixture.calls).toHaveLength(1);
    await button(fixture.wrapper, "只读核对原记录").trigger("click");
    await vi.waitFor(() =>
      expect(fixture.wrapper.emitted("saved")).toHaveLength(1),
    );
    expect(fixture.reads.at(-1)).toBe(`/networks/vpcs/${key}`);
    expect(fixture.calls).toHaveLength(1);
    expect(entries()).toHaveLength(0);
  });
  it.each([200, 202])(
    "does not accept a %i as a new network creation ACK",
    async (status) => {
      const fixture = await dialog("vpcs");
      const fetcher = vi
        .fn<typeof fetch>()
        .mockImplementation(async (_url, init) => {
          const body = JSON.parse(String(init!.body));
          const key = (init!.headers as Record<string, string>)[
            "Idempotency-Key"
          ]!;
          return new Response(JSON.stringify(response("vpcs", key, body)), {
            status,
            headers: { "Content-Type": "application/json" },
          });
        });
      const real = fixture.createApiClient(fetcher);
      real.setCSRF("fixture-csrf");
      fixture.context.api.write = real.write;
      await fill(fixture.wrapper, "vpcs");
      await fixture.wrapper.get("form").trigger("submit");
      await vi.waitFor(() => expect(fetcher).toHaveBeenCalledOnce());
      await flushPromises();
      expect(fixture.wrapper.emitted("saved")).toBeUndefined();
      expect(entries()).toHaveLength(1);
      expect(fixture.wrapper.text()).toContain("结果尚未确认");
    },
  );
  it("keeps a failed read-after-ACK recovery retryable without another POST", async () => {
    let fixture: Awaited<ReturnType<typeof dialog>>;
    let original: unknown;
    let inspections = 0;
    fixture = await dialog("vpcs", (method, path, body, key) => {
      if (path === "/nodes") return { items: [node], next_cursor: null };
      if (method === "POST") {
        original = response("vpcs", key, body as Record<string, unknown>);
        throw new fixture.ApiError("unknown");
      }
      inspections++;
      if (inspections === 1) throw new fixture.ApiError("unavailable");
      return original;
    });
    await fill(fixture.wrapper, "vpcs");
    await fixture.wrapper.get("form").trigger("submit");
    await vi.waitFor(() => expect(fixture.calls).toHaveLength(1));
    await flushPromises();
    await button(fixture.wrapper, "只读核对原记录").trigger("click");
    await flushPromises();
    expect(fixture.wrapper.emitted("saved")).toBeUndefined();
    expect(entries()).toHaveLength(1);
    expect(
      button(fixture.wrapper, "只读核对原记录").attributes("disabled"),
    ).toBeUndefined();
    await button(fixture.wrapper, "只读核对原记录").trigger("click");
    await vi.waitFor(() =>
      expect(fixture.wrapper.emitted("saved")).toHaveLength(1),
    );
    expect(fixture.calls).toHaveLength(1);
    expect(inspections).toBe(2);
    expect(entries()).toHaveLength(0);
  });
  it.each(["epoch", "closed", "kind", "permission"] as const)(
    "drops a late POST ACK after %s changes",
    async (change) => {
      const pending = deferred<unknown>();
      let ack: unknown;
      const fixture = await dialog("vpcs", (method, path, body, key) => {
        if (path === "/nodes") return { items: [node], next_cursor: null };
        if (path === "/networks/vpcs" && method === "GET")
          return { items: [vpc], next_cursor: null };
        ack = response("vpcs", key, body as Record<string, unknown>);
        return pending.promise;
      });
      await fill(fixture.wrapper, "vpcs");
      await fixture.wrapper.get("form").trigger("submit");
      await vi.waitFor(() => expect(fixture.calls).toHaveLength(1));
      if (change === "epoch") fixture.context.session.epoch.value++;
      if (change === "closed") await fixture.wrapper.setProps({ open: false });
      if (change === "kind") await fixture.wrapper.setProps({ kind: "pools" });
      if (change === "permission")
        fixture.context.session.user.value = {
          ...fixture.context.session.user.value!,
          permissions: ["nodes.read"],
        };
      pending.resolve(ack);
      await flushPromises();
      expect(fixture.wrapper.emitted("saved")).toBeUndefined();
      expect(fixture.context.notify).not.toHaveBeenCalled();
      expect(entries()).toHaveLength(1);
    },
  );
  it("does not clear the original pending entry if the session changes during acknowledgement hashing", async () => {
    let fixture: Awaited<ReturnType<typeof dialog>>;
    let original: unknown;
    fixture = await dialog("vpcs", (method, path, body, key) => {
      if (path === "/nodes") return { items: [node], next_cursor: null };
      if (method === "POST") {
        original = response("vpcs", key, body as Record<string, unknown>);
        throw new fixture.ApiError("unknown");
      }
      return original;
    });
    await fill(fixture.wrapper, "vpcs");
    await fixture.wrapper.get("form").trigger("submit");
    await vi.waitFor(() => expect(fixture.calls).toHaveLength(1));
    await flushPromises();
    const delayed = deferred<ArrayBuffer>();
    const digest = vi
      .spyOn(crypto.subtle, "digest")
      .mockReturnValueOnce(delayed.promise);
    await button(fixture.wrapper, "只读核对原记录").trigger("click");
    await vi.waitFor(() => expect(digest).toHaveBeenCalledOnce());
    fixture.context.session.epoch.value++;
    const expected = String(entries()[0]!.fingerprint);
    delayed.resolve(
      Uint8Array.from(expected.match(/../g)!.map((part) => parseInt(part, 16)))
        .buffer,
    );
    await flushPromises();
    expect(entries()).toHaveLength(1);
    expect(fixture.wrapper.emitted("saved")).toBeUndefined();
    expect(fixture.calls).toHaveLength(1);
  });
});

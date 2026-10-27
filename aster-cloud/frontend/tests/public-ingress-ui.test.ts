import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DOMWrapper, flushPromises, mount } from "@vue/test-utils";
import { createMemoryHistory, createRouter } from "vue-router";
import { webcrypto } from "node:crypto";
import Dialog from "../src/components/PublicIngressDialog.vue";
import Panel from "../src/components/PublicIngressPanel.vue";
import Binding from "../src/components/BindingIngressSummary.vue";
import { consoleKey } from "../src/context";
import { ApiError } from "../src/api/client";
import { mockContext, deferred } from "./helpers";
import { instance } from "./fixtures";
import { ingressPolicy, ingressRule } from "./public-ingress-fixtures";
import type { PublicIngressRequest } from "../src/api/public-ingress";
const cleanup: Array<() => void> = [];
const body = () => new DOMWrapper(document.body);
const button = (text: string) =>
  body()
    .findAll("button")
    .find((b) => b.text() === text)!;
beforeEach(() => {
  sessionStorage.clear();
  vi.stubGlobal("crypto", webcrypto);
  Element.prototype.scrollIntoView = vi.fn();
  vi.spyOn(history, "back").mockImplementation(() => {});
  vi.spyOn(HTMLElement.prototype, "getClientRects").mockImplementation(
    () => [new DOMRect(0, 0, 100, 44)] as unknown as DOMRectList,
  );
});
afterEach(() => {
  cleanup
    .splice(0)
    .reverse()
    .forEach((f) => f());
  document.body.innerHTML = "";
  document.body.style.overflow = "";
  history.replaceState(null, "", "/");
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});
async function router() {
  const r = createRouter({
    history: createMemoryHistory(),
    routes: [{ path: "/:pathMatch(.*)*", component: { template: "<div/>" } }],
  });
  await r.push("/");
  await r.isReady();
  return r;
}
function dialog(policy = structuredClone(ingressPolicy)) {
  const f = mockContext(() => ({}));
  const w = mount(Dialog, {
    attachTo: document.body,
    props: { policy, busy: false, pending: false, error: "" },
    global: { provide: { [consoleKey as symbol]: f.context } },
  });
  cleanup.push(() => w.unmount());
  return { w, ...f };
}
async function add(source = "203.0.113.10/32", start = "443", end = "") {
  await body().get('[aria-label="允许来源 CIDR"]').setValue(source);
  await body().get('[aria-label="入站起始端口"]').setValue(start);
  await body().get('[aria-label="入站结束端口"]').setValue(end);
  await button("添加允许规则").trigger("click");
}
async function confirm() {
  await body()
    .get('[aria-label="确认入站规则实例 ID"]')
    .setValue(ingressPolicy.instance_id);
}
describe("instance public ingress UI", () => {
  it("starts with empty deny policy, never default-opens SSH, and submits exact revision zero", async () => {
    const { w } = dialog();
    await flushPromises();
    expect(body().find("select").exists()).toBe(false);
    expect(body().find('input[type="number"]').exists()).toBe(false);
    expect(body().get('[aria-label="允许来源 CIDR"]').element).toHaveProperty(
      "value",
      "",
    );
    expect(body().text()).toContain("没有允许规则");
    expect(body().text()).toContain("不替代实例防火墙或完整安全组");
    await confirm();
    await body().get("form").trigger("submit");
    expect(w.emitted("submit")?.[0]).toEqual([
      { expected_revision: 0, rules: [] },
    ]);
  });
  it("keeps unadded fields from being silently discarded and rejects noncanonical sources and invalid ports", async () => {
    const { w } = dialog();
    await flushPromises();
    await confirm();
    await body().get('[aria-label="允许来源 CIDR"]').setValue("0.0.0.0/0");
    expect(button("保存入站规则").attributes("disabled")).toBeDefined();
    for (const [source, start, end] of [
      ["203.0.113.1/24", "443", ""],
      ["0.0.0.0/0", "0", ""],
      ["0.0.0.0/0", "65536", ""],
      ["0.0.0.0/0", "100", "99"],
      ["0.0.0.0/0", "1e2", ""],
    ]) {
      await add(source, start, end);
      expect(body().find('[role="alert"]').exists()).toBe(true);
    }
    expect(w.emitted("submit")).toBeUndefined();
    await add();
    expect(body().findAll(".ingress-rules .ingress-rule")).toHaveLength(1);
    await add();
    expect(body().text()).toContain("这条允许规则已存在");
    await body().get("form").trigger("submit");
    expect(w.emitted("submit")).toBeUndefined();
  });
  it("supports TCP/UDP port ranges and ICMP echo only, then revokes by saving an empty list", async () => {
    const { w } = dialog({
      ...ingressPolicy,
      revision: 1,
      rules: [structuredClone(ingressRule)],
    });
    await flushPromises();
    await button("移除").trigger("click");
    await body()
      .get('[role="combobox"][aria-label="入站协议"]')
      .trigger("click");
    await body()
      .findAll('[role="option"]')
      .find((o) => o.text() === "ICMP 回显")!
      .trigger("pointerdown");
    await body().get('[aria-label="允许来源 CIDR"]').setValue("192.0.2.4/32");
    expect(body().find('[aria-label="入站起始端口"]').exists()).toBe(false);
    await button("添加允许规则").trigger("click");
    await confirm();
    await body().get("form").trigger("submit");
    const first = w.emitted("submit")![0]![0] as PublicIngressRequest;
    expect(first.rules[0]).toMatchObject({
      protocol: "icmp",
      source_cidr: "192.0.2.4/32",
      port_start: 0,
      port_end: 0,
    });
    await button("移除").trigger("click");
    await body().get("form").trigger("submit");
    expect(w.emitted("submit")?.[1]).toEqual([
      { expected_revision: 1, rules: [] },
    ]);
  });
  it("does not silently rebase a refreshed revision or permit unsupported/pending writes", async () => {
    const { w } = dialog();
    await flushPromises();
    await confirm();
    for (const patch of [
      { revision: 1 },
      { sha256: "d".repeat(64) },
      { instance_id: "e".repeat(32) },
      { owner_ref: "e".repeat(32) },
      { supported: false },
      { state: "pending" as const },
    ]) {
      await w.setProps({ policy: { ...ingressPolicy, ...patch } });
      await body().get("form").trigger("submit");
      expect(button("保存入站规则").attributes("disabled")).toBeDefined();
    }
    expect(w.emitted("submit")).toBeUndefined();
  });
  it("enforces 64 rules and does not replace the original intent while awaiting reconciliation", async () => {
    const { w } = dialog({
      ...ingressPolicy,
      revision: 1,
      rules: Array.from({ length: 64 }, (_, i) => ({
        ...ingressRule,
        id: (i + 1).toString(16).padStart(32, "0"),
        port_start: i + 1,
        port_end: i + 1,
      })),
    });
    await flushPromises();
    await add();
    expect(body().text()).toContain("最多保留 64 条允许规则");
    await w.setProps({ pending: true, error: "unknown" });
    await confirm();
    await body().get("form").trigger("submit");
    expect(w.emitted("submit")).toBeUndefined();
    await button("核对原规则操作").trigger("click");
    expect(w.emitted("reconcile")).toHaveLength(1);
  });
  it.each(["unsupported", "foreign owner", "foreign instance", "malformed"])(
    "does not authorize a %s binding policy",
    async (kind) => {
      const policy = {
        ...ingressPolicy,
        ...(kind === "unsupported"
          ? { supported: false, unsupported_reason: "UPGRADE_REQUIRED" }
          : kind === "foreign owner"
            ? { owner_ref: "f".repeat(32) }
            : kind === "foreign instance"
              ? { instance_id: "f".repeat(32) }
              : { rules: null }),
      };
      const f = mockContext(() => ({ policy }));
      const r = await router();
      const w = mount(Binding, {
        props: {
          instanceId: ingressPolicy.instance_id,
          ownerRef: ingressPolicy.owner_ref,
        },
        global: {
          plugins: [r],
          provide: { [consoleKey as symbol]: f.context },
        },
      });
      cleanup.push(() => w.unmount());
      await flushPromises();
      expect(w.emitted("ready")!.every((v) => v[0] === null)).toBe(true);
    },
  );
  it.each(["UPGRADE_REQUIRED", "NODE_NOT_READY"] as const)(
    "explains unsupported %s consistently without prescribing the wrong recovery",
    async (reason) => {
      const p = {
        ...ingressPolicy,
        supported: false,
        unsupported_reason: reason,
        state: "blocked" as const,
        effective_revision: null,
        bound_resource_id: "f".repeat(32),
      };
      const f = mockContext(() => ({ policy: p }));
      const r = await router();
      const global = {
        plugins: [r],
        provide: { [consoleKey as symbol]: f.context },
      };
      const binding = mount(Binding, {
        props: { instanceId: p.instance_id, ownerRef: p.owner_ref },
        global,
      });
      const panel = mount(Panel, {
        props: {
          instance: { ...instance, id: p.instance_id, owner_ref: p.owner_ref },
        },
        global,
      });
      cleanup.push(
        () => binding.unmount(),
        () => panel.unmount(),
      );
      for (const locale of ["zh-CN", "en"] as const) {
        f.context.prefs.locale.value = locale;
        await flushPromises();
        for (const w of [binding, panel]) {
          const text = w.get(".ingress-warning").text();
          if (reason === "UPGRADE_REQUIRED")
            expect(text).toContain(
              locale === "en"
                ? "Upgrade the participating nodes"
                : "请先升级相关节点",
            );
          else {
            expect(text).not.toMatch(/升级|upgrade/i);
            expect(text).toContain(
              locale === "en"
                ? "online status and heartbeats"
                : "在线和心跳状态",
            );
            expect(text).toContain(
              locale === "en"
                ? "current network configuration and approvals"
                : "当前网络配置与批准设置",
            );
          }
        }
        expect(
          panel.get(".ingress-actions button").attributes("disabled"),
        ).toBeDefined();
      }
      expect(binding.emitted("ready")!.every((v) => v[0] === null)).toBe(true);
      expect(f.calls).toHaveLength(0);
    },
  );
  it("waits for the exact policy GET before emitting a frozen ready summary", async () => {
    const d = deferred<unknown>();
    const f = mockContext(() => d.promise);
    const r = await router();
    const w = mount(Binding, {
      props: {
        instanceId: ingressPolicy.instance_id,
        ownerRef: ingressPolicy.owner_ref,
      },
      global: { plugins: [r], provide: { [consoleKey as symbol]: f.context } },
    });
    cleanup.push(() => w.unmount());
    expect(w.emitted("ready")!.at(-1)).toEqual([null]);
    d.resolve({ policy: ingressPolicy });
    await flushPromises();
    expect(w.emitted("ready")!.at(-1)).toEqual([ingressPolicy]);
    expect(w.emitted("ready")!.at(-1)![0]).not.toBe(ingressPolicy);
  });
  it("keeps a conflicted editor frozen and reloads before opening a fresh draft", async () => {
    let fresh = false;
    const updated = {
      ...ingressPolicy,
      revision: 1,
      effective_revision: 1,
      state: "active",
      operation_id: "f".repeat(32),
      updated_at: "2026-10-24T00:00:00Z",
    };
    const f = mockContext((method) => {
      if (method === "POST") {
        fresh = true;
        throw new ApiError("conflict");
      }
      return { policy: fresh ? updated : ingressPolicy };
    });
    const r = await router();
    const w = mount(Panel, {
      attachTo: document.body,
      props: {
        instance: {
          ...instance,
          id: ingressPolicy.instance_id,
          owner_ref: ingressPolicy.owner_ref,
        },
      },
      global: { plugins: [r], provide: { [consoleKey as symbol]: f.context } },
    });
    cleanup.push(() => w.unmount());
    await flushPromises();
    await button("编辑入站规则").trigger("click");
    await confirm();
    await body().get("form").trigger("submit");
    await flushPromises();
    expect(f.calls).toHaveLength(1);
    expect(button("保存入站规则").attributes("disabled")).toBeDefined();
    expect(body().text()).toContain("规则或绑定状态已变化");
    await button("取消").trigger("click");
    await button("编辑入站规则").trigger("click");
    await confirm();
    expect(button("保存入站规则").attributes("disabled")).toBeUndefined();
    expect(f.calls).toHaveLength(1);
  });
  it("shows legacy as unprotected and still lets an authorized operator upgrade its rules", async () => {
    const p = {
      ...ingressPolicy,
      legacy_unrestricted: true,
      effective_revision: null,
    };
    const f = mockContext(() => ({ policy: p }));
    const r = await router();
    const w = mount(Panel, {
      attachTo: document.body,
      props: {
        instance: { ...instance, id: p.instance_id, owner_ref: p.owner_ref },
      },
      global: { plugins: [r], provide: { [consoleKey as symbol]: f.context } },
    });
    cleanup.push(() => w.unmount());
    await flushPromises();
    expect(w.text()).toContain("旧绑定尚未应用入站规则");
    expect(button("编辑入站规则").attributes("disabled")).toBeUndefined();
    expect(w.text()).toContain("未确认");
    f.context.session.user.value = {
      ...f.context.session.user.value!,
      permissions: ["nodes.read", "instances.read"],
    };
    await flushPromises();
    expect(
      body()
        .findAll("button")
        .some((b) => b.text() === "编辑入站规则"),
    ).toBe(false);
  });
});

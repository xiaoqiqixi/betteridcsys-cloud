import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DOMWrapper, flushPromises, mount } from "@vue/test-utils";
import { createMemoryHistory, createRouter } from "vue-router";
import { webcrypto } from "node:crypto";
import Dialog from "../src/components/PublicIPResourceDialog.vue";
import Panel from "../src/components/PublicIPResourcesPanel.vue";
import Create from "../src/components/CreateInstanceDialog.vue";
import { consoleKey } from "../src/context";
import { mockContext } from "./helpers";
import {
  vmPublicOptions as options,
  vmPublicResource as resource,
} from "./public-ip-resource-fixtures";
import { publicPool } from "./public-ip-fixtures";
import { resources, operation } from "./fixtures";
import { ingressPolicy } from "./public-ingress-fixtures";
const cleanup: Array<() => void> = [];
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
const body = () => new DOMWrapper(document.body);
async function select(label: string, text: string) {
  await body().get(`[role="combobox"][aria-label="${label}"]`).trigger("click");
  const item = body()
    .findAll('[role="option"]')
    .find((o) => o.text() === text);
  expect(item).toBeDefined();
  await item!.trigger("pointerdown");
}
function button(text: string) {
  const el = body()
    .findAll("button")
    .find((b) => b.text() === text);
  expect(el).toBeDefined();
  return el!;
}
function dialog(override: Record<string, unknown> = {}) {
  const f = mockContext((_m, path) =>
    path.endsWith("/public-ingress")
      ? {
          policy: {
            ...structuredClone(ingressPolicy),
            owner_ref: resource.owner_ref,
          },
        }
      : {},
  );
  const wrapper = mount(Dialog, {
    attachTo: document.body,
    props: {
      action: "resource.allocate",
      cluster: resource.cluster_id,
      options: structuredClone(options),
      pool: structuredClone(publicPool),
      busy: false,
      pending: false,
      error: "",
      ...override,
    },
    global: {
      provide: { [consoleKey as symbol]: f.context },
      stubs: { RouterLink: true },
    },
  });
  cleanup.push(() => wrapper.unmount());
  return { wrapper, ...f };
}
describe("VM public address UI", () => {
  it("recovery detaches only and freezes both original epoch SHA and generation", async () => {
    const r = {
      ...resource,
      mode: "floating" as const,
      vpc_id: options.vpcs[0]!.id,
      binding_state: "blocked" as const,
      binding_generation: 8,
      releasable: false,
      epoch_id: "8".repeat(32),
    };
    const f = dialog({
      action: "resource.recover",
      resource: r,
      recoverySHA: "c".repeat(64),
    });
    await flushPromises();
    expect(body().text()).toContain("只恢复解绑，不恢复公网绑定");
    await body().get(".resource-confirmation input").setValue(r.address);
    await body().get("form").trigger("submit");
    expect(f.wrapper.emitted("submit")?.[0]).toEqual([
      "resource.recover",
      r.id,
      { expected_generation: 8, expected_snapshot_sha256: "c".repeat(64) },
    ]);
  });

  it("allocates a new direct owner only through root-approved node/profile and exact pool", async () => {
    const f = dialog();
    await flushPromises();
    await body().findAll("input")[0]!.setValue(resource.owner_ref);
    await select("公网网络配置", "node-a · normal-public-ipv4");
    await body().get("form").trigger("submit");
    expect(f.wrapper.emitted("submit")?.[0]).toEqual([
      "resource.allocate",
      "",
      {
        pool_id: publicPool.id,
        owner_ref: resource.owner_ref,
        mode: "direct",
        node_id: "node-a",
        profile_id: "normal-public-ipv4",
        vpc_id: "",
        address: "",
      },
    ]);
    expect(body().find("select").exists()).toBe(false);
  });
  it("binds floating only with an exact default-deny target policy and frozen generation", async () => {
    const r = {
      ...resource,
      mode: "floating" as const,
      vpc_id: options.vpcs[0]!.id,
      binding_generation: 4,
    };
    const f = dialog({ action: "resource.bind", resource: r });
    await flushPromises();
    await select("绑定目标实例", `10.25.0.2 · node-b · ${"2".repeat(32)}`);
    await flushPromises();
    await body().get(".resource-confirmation input").setValue("2".repeat(32));
    expect(button("确认绑定公网 IP").attributes("disabled")).toBeUndefined();
    expect(body().text()).toContain("绑定后默认拒绝公网新入站连接");
    expect(body().find(".floating-consent").exists()).toBe(false);
    await body().get("form").trigger("submit");
    expect(f.wrapper.emitted("submit")?.[0]).toEqual([
      "resource.bind",
      r.id,
      {
        instance_id: "2".repeat(32),
        expected_generation: 4,
        expected_ingress_revision: 0,
      },
    ]);
  });
  it("does not move direct addresses or silently advance a draft generation", async () => {
    const f = dialog({
      action: "resource.bind",
      resource: { ...resource, binding_generation: 5 },
    });
    await flushPromises();
    await select(
      "绑定目标实例",
      `${resource.address} · node-a · ${"1".repeat(32)}`,
    );
    await body().get(".resource-confirmation input").setValue("1".repeat(32));
    await f.wrapper.setProps({
      resource: { ...resource, binding_generation: 6 },
    });
    await body().get("form").trigger("submit");
    expect(f.wrapper.emitted("submit")).toBeUndefined();
    await f.wrapper.setProps({
      resource: {
        ...resource,
        binding_generation: 5,
        binding_state: "bound",
        instance_id: "1".repeat(32),
        releasable: false,
      },
    });
    expect(button("更换绑定实例").attributes("disabled")).toBeDefined();
  });
  it("treats pending resource bindings as unconfirmed and preserves task links and pagination", async () => {
    const r = {
      ...resource,
      mode: "floating" as const,
      vpc_id: options.vpcs[0]!.id,
      instance_id: "2".repeat(32),
      binding_state: "pending" as const,
      releasable: false,
      epoch_id: "9".repeat(32),
      operation_id: "8".repeat(32),
      binding_generation: 1,
    };
    const f = mockContext((_m, path) =>
      path === "/public-ips/options"
        ? options
        : path.startsWith("/public-ips/resources")
          ? { items: [r], next_cursor: "f".repeat(32) }
          : { items: [publicPool], next_cursor: null },
    );
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [{ path: "/:pathMatch(.*)*", component: { template: "<div/>" } }],
    });
    await router.push("/");
    await router.isReady();
    const w = mount(Panel, {
      attachTo: document.body,
      props: { cluster: resource.cluster_id },
      global: {
        plugins: [router],
        provide: { [consoleKey as symbol]: f.context },
      },
    });
    cleanup.push(() => w.unmount());
    await flushPromises();
    expect(w.text()).toContain("变更待执行或核实");
    expect(w.find('[data-binding-state="bound"]').exists()).toBe(false);
    expect(
      w.find('a[href="/networks/epochs/' + r.epoch_id + '"]').exists(),
    ).toBe(true);
    expect(w.findAll("button").some((b) => b.text() === "绑定实例")).toBe(
      false,
    );
    await button("下一页").trigger("click");
    expect(w.emitted("page")?.[0]).toEqual(["f".repeat(32)]);
    expect(f.calls).toHaveLength(0);
  });
  it("owner resource choices query server scope and preserve the old create body until direct is required", async () => {
    const paths: string[] = [];
    const f = mockContext((m, path, _b, key) => {
      paths.push(path);
      if (m !== "GET")
        return { operation: { ...operation, id: key, action: "create" } };
      if (path === "/presets")
        return {
          items: [
            {
              id: "public-normal",
              node_id: resource.node_id,
              resources: { ...resources, network_type: "normal" },
              direct_public_required: true,
            },
          ],
        };
      if (
        path.startsWith("/public-ips/resources?owner_ref=" + resource.owner_ref)
      )
        return { items: [resource], next_cursor: null };
      return {};
    });
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [{ path: "/:pathMatch(.*)*", component: { template: "<div/>" } }],
    });
    await router.push("/");
    const w = mount(Create, {
      attachTo: document.body,
      props: { open: true },
      global: {
        plugins: [router],
        provide: { [consoleKey as symbol]: f.context },
      },
    });
    cleanup.push(() => w.unmount());
    await flushPromises();
    await select(
      "选择预设规格",
      `public-normal · ${resource.node_id} · ${resources.cpu_cores} vCPU / ${resources.memory_mib / 1024} GiB / ${resources.system_disk_gib} GiB`,
    );
    const inputs = body().findAll("input");
    await inputs[0]!.setValue("public-vm");
    await inputs[1]!.setValue(resource.owner_ref);
    await flushPromises();
    expect(button("创建任务").attributes("disabled")).toBeDefined();
    await select("选择直绑公网地址", resource.address);
    await body().get("form").trigger("submit");
    // Fingerprinting awaits native WebCrypto work; one flushPromises turn is
    // not its completion signal. Observe the exact accepted UI, never resubmit.
    await vi.waitFor(() =>
      expect(body().get('.callout[role="status"]').text()).toContain(
        "实例尚未开通",
      ),
    );
    expect(f.calls).toHaveLength(1);
    expect(f.calls[0]).toMatchObject({ method: "POST", path: "/instances" });
    expect(f.calls[0]?.body).toEqual({
      hostname: "public-vm",
      owner_ref: resource.owner_ref,
      preset_id: "public-normal",
      public_ip_resource_id: resource.id,
      public_ip_expected_generation: 0,
    });
    expect(
      paths.some((p) => p.includes("owner_ref=" + resource.owner_ref)),
    ).toBe(true);
    expect(body().text()).toContain("实例尚未开通");
  });
  it.each(["zh-CN", "en"] as const)(
    "keeps custom controls and exact target confirmation in %s with a long profile",
    async (locale) => {
      const f = dialog({
        action: "resource.bind",
        resource: {
          ...resource,
          mode: "floating",
          vpc_id: options.vpcs[0]!.id,
          profile_id: "w".repeat(64),
        },
      });
      f.context.prefs.locale.value = locale;
      f.context.prefs.appearance.value = "dark";
      await flushPromises();
      expect(body().find("select").exists()).toBe(false);
      expect(body().find('[role="dialog"]').exists()).toBe(true);
      expect(body().get("form").attributes("novalidate")).toBeDefined();
    },
  );
});

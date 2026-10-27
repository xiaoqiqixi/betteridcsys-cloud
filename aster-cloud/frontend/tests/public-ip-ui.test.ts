import { beforeEach, afterEach, describe, it, expect, vi } from "vitest";
import { DOMWrapper, mount, flushPromises } from "@vue/test-utils";
import { createMemoryHistory, createRouter } from "vue-router";
import { webcrypto } from "node:crypto";
import { consoleKey } from "../src/context";
import { ApiError } from "../src/api/client";
import Page from "../src/pages/PublicIPsPage.vue";
import Dialog from "../src/components/PublicIPDialog.vue";
import NATEditor from "../src/components/OverlayNATEditor.vue";
import { mockContext } from "./helpers";
import { publicPool, publicLease, publicOptions } from "./public-ip-fixtures";
import { overlayNAT, overlayOption, overlayVPC } from "./overlay-fixtures";
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
function button(label: string) {
  const b = body()
    .findAll("button")
    .find((b) => b.text() === label);
  expect(b, `button ${label}`).toBeDefined();
  return b!;
}
async function setup(
  path = "/networks/public-ips",
  resolver?: Parameters<typeof mockContext>[0],
) {
  const f = mockContext((method, path, payload, key) => {
    if (resolver) {
      const r = resolver(method, path, payload, key);
      if (r !== undefined) return r;
    }
    if (path === "/public-ips/options") return structuredClone(publicOptions);
    return {
      items: path.includes("/leases")
        ? [structuredClone(publicLease)]
        : [structuredClone(publicPool)],
      next_cursor: null,
    };
  });
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: "/networks/public-ips", component: Page },
      {
        path: "/networks/overlays",
        component: { template: "<div>networks</div>" },
      },
      { path: "/:pathMatch(.*)*", component: { template: "<div/>" } },
    ],
  });
  await router.push(path);
  await router.isReady();
  const wrapper = mount(Page, {
    attachTo: document.body,
    global: {
      plugins: [router],
      provide: { [consoleKey as symbol]: f.context },
    },
  });
  cleanup.push(() => wrapper.unmount());
  await flushPromises();
  return { ...f, wrapper, router };
}
describe("public IP management UI", () => {
  it("adds addresses to the selected pool rather than creating overlapping inventory", async () => {
    const f = mockContext(() => ({}));
    const wrapper = mount(Dialog, {
      attachTo: document.body,
      props: {
        action: "pool.extend",
        cluster: publicPool.cluster_id,
        options: publicOptions,
        pool: { ...publicPool, addresses: [publicPool.addresses[0]!] },
        busy: false,
        pending: false,
        error: "",
      },
      global: { provide: { [consoleKey as symbol]: f.context } },
    });
    cleanup.push(() => wrapper.unmount());
    const fields = body().findAll("input");
    expect(fields).toHaveLength(2);
    await fields[0]!.setValue(publicPool.addresses[1]);
    await fields[1]!.setValue(publicPool.addresses[1]);
    await body().find("form").trigger("submit");
    expect(wrapper.emitted("submit")?.[0]).toEqual([
      "pool.extend",
      publicPool.id,
      { addresses: [publicPool.addresses[1]] },
    ]);
  });
  it("uses unified controls and a real pool context, no native select", async () => {
    await setup();
    expect(body().text()).toContain(publicPool.name);
    expect(body().findAll("select")).toHaveLength(0);
    await button("分配地址").trigger("click");
    expect(body().text()).toContain("分配公网 IP");
    expect(body().find('[role="dialog"]').exists()).toBe(true);
    expect(body().text()).toContain("分配本身不会更改正在使用的出口");
  });
  it("back navigation switches list context and disables unsafe writes without both grants", async () => {
    const f = await setup();
    f.context.session.user.value = {
      ...f.context.session.user.value!,
      permissions: ["nodes.read", "nodes.manage"],
    };
    await flushPromises();
    expect(body().text()).not.toContain("新建地址池");
    expect(
      body()
        .findAll("button")
        .some((b) => b.text() === "分配地址"),
    ).toBe(false);
    await button("分配记录").trigger("click");
    await flushPromises();
    expect(f.router.currentRoute.value.query.view).toBe("leases");
    expect(body().text()).toContain(publicLease.address);
    expect(body().text()).not.toContain("回收地址");
  });
  it.each(["bound", "pending", "release_blocked"])(
    "server %s allocation cannot be reclaimed",
    async (binding_state) => {
      await setup("/networks/public-ips?view=leases", (_m, path) =>
        path.includes("/leases")
          ? {
              items: [{ ...publicLease, binding_state, releasable: false }],
              next_cursor: null,
            }
          : undefined,
      );
      expect(button("回收地址").attributes("disabled")).toBeDefined();
      expect(body().text()).toContain("先解除 NAT 绑定");
    },
  );
  it("lost write ACK locks new writes and retains original operation after closing", async () => {
    const f = await setup(undefined, (m) => {
      if (m === "POST") throw new ApiError("unknown");
    });
    await button("停用分配").trigger("click");
    await button("停用地址分配").trigger("click");
    await flushPromises();
    expect(f.calls).toHaveLength(1);
    expect(body().text()).toContain("核对原操作");
    await body()
      .find('[role="dialog"]')
      .findAll("button")
      .find((b) => b.text() === "取消")!
      .trigger("click");
    await flushPromises();
    expect(button("新建地址池").attributes("disabled")).toBeDefined();
    expect(body().text()).toContain("有一项操作等待核实");
    expect(f.calls).toHaveLength(1);
  });
  it("pool create cancel uses dirty close guard rather than discarding silently", async () => {
    await setup();
    await button("新建地址池").trigger("click");
    await body().find('[role="dialog"] input').setValue("changed");
    await button("取消").trigger("click");
    expect(body().text()).toContain("继续编辑");
    await button("继续编辑").trigger("click");
    expect(body().find('[role="dialog"] input').element).toHaveProperty(
      "value",
      "changed",
    );
  });
  it("release requires exact address confirmation and preserves history wording", async () => {
    const f = mockContext(() => ({}));
    const wrapper = mount(Dialog, {
      attachTo: document.body,
      props: {
        action: "lease.release",
        cluster: publicPool.cluster_id,
        options: publicOptions,
        lease: publicLease,
        busy: false,
        pending: false,
        error: "",
      },
      global: { provide: { [consoleKey as symbol]: f.context } },
    });
    cleanup.push(() => wrapper.unmount());
    await button("回收公网 IP").trigger("click");
    expect(wrapper.emitted("submit")).toBeUndefined();
    await body().find("input").setValue(publicLease.address);
    await body().find("form").trigger("submit");
    expect(wrapper.emitted("submit")?.[0]).toEqual([
      "lease.release",
      publicLease.id,
      {},
    ]);
    expect(body().text()).toContain("原分配记录仍会保留");
  });
  it("NAT address selector only accepts exact VPC/node/profile leases", async () => {
    const f = mockContext(() => ({}));
    const profile = {
      ...overlayOption.nat_profiles[0]!,
      public_ipv4: "8.8.4.2",
      public_ipv4s: [publicLease.address],
    };
    const wrapper = mount(NATEditor, {
      attachTo: document.body,
      props: {
        modelValue: [overlayNAT],
        profiles: [profile],
        members: overlayOption.latest_epoch!.snapshot.members,
        instances: overlayOption.instances,
        gateways: overlayOption.gateways,
        vpcs: [overlayVPC],
        leases: [
          publicLease,
          {
            ...publicLease,
            id: "e".repeat(32),
            vpc_id: "d".repeat(32),
            address: "8.8.4.4",
          },
        ],
      },
      global: { provide: { [consoleKey as symbol]: f.context } },
    });
    cleanup.push(() => wrapper.unmount());
    await body()
      .find('[role="combobox"][aria-label="公网地址绑定"]')
      .trigger("click");
    const choices = body().findAll('[role="option"]');
    expect(choices.some((x) => x.text() === "8.8.4.4")).toBe(false);
    await choices
      .find((x) => x.text() === publicLease.address)!
      .trigger("pointerdown");
    expect(wrapper.emitted("update:modelValue")?.[0]?.[0]).toEqual([
      { ...overlayNAT, public_ipv4: publicLease.address },
    ]);
  });
});

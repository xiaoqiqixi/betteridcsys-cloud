import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DOMWrapper, flushPromises, mount } from "@vue/test-utils";
import { createMemoryHistory, createRouter } from "vue-router";
import type { DefineComponent } from "vue";
import { webcrypto } from "node:crypto";
import { deferred } from "./helpers";
import {
  overlayEpoch,
  overlayNAT,
  overlayOption,
  overlayTasks,
  overlayVPC,
} from "./overlay-fixtures";
import type {
  OverlayEpoch,
  OverlayOptions,
  OverlaySelection,
} from "../src/api/overlay";
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
    .forEach((f) => f());
  document.body.innerHTML = "";
  document.body.style.overflow = "";
  history.replaceState(null, "", "/");
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});
function body() {
  return new DOMWrapper(document.body);
}
function button(text: string) {
  const found = body()
    .findAll("button")
    .find((b) => b.text() === text);
  expect(found, `button ${text}`).toBeDefined();
  return found!;
}
const stored = () =>
  JSON.parse(sessionStorage.getItem("aster.cloud.overlay-intents.v1") || "[]");
async function setup(
  kind: "overview" | "detail" | "plan" | "recover" | "vpc",
  resolver?: (
    method: string,
    path: string,
    payload: unknown,
    key: string,
  ) => unknown | Promise<unknown>,
  overrides?: { options?: OverlayOptions; recover?: OverlayEpoch },
) {
  const [
    { consoleKey },
    { mockContext },
    { default: Overview },
    { default: Detail },
    { default: Dialog },
    { default: VPC },
  ] = await Promise.all([
    import("../src/context"),
    import("./helpers"),
    import("../src/pages/OverlayNetworksPage.vue"),
    import("../src/pages/OverlayEpochPage.vue"),
    import("../src/components/OverlayEpochDialog.vue"),
    import("../src/components/OverlayVPCDialog.vue"),
  ]);
  const reads: string[] = [];
  const { context, calls } = mockContext((method, path, payload, key) => {
    if (method === "GET") reads.push(path);
    if (resolver) {
      const value = resolver(method, path, payload, key);
      if (value !== undefined) return value;
    }
    if (path === "/overlays/clusters")
      return {
        items: [{ id: overlayVPC.cluster_id, node_ids: ["node-east"] }],
      };
    if (path.startsWith("/overlays/options?"))
      return structuredClone(overlayOption);
    if (path.startsWith("/overlays/vpcs?"))
      return { items: [structuredClone(overlayVPC)] };
    if (path.startsWith("/overlays/epochs?"))
      return {
        items: [structuredClone(overlayEpoch)],
        next_before_epoch: null,
      };
    if (path === `/overlays/epochs/${overlayEpoch.id}`)
      return { epoch: structuredClone(overlayEpoch), tasks: overlayTasks() };
    return {};
  });
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: "/", component: { template: "<div/>" } },
      { path: "/networks/overlays", component: Overview },
      { path: "/networks/epochs/:id", component: Detail },
      { path: "/elsewhere", component: { template: "<div>Elsewhere</div>" } },
      { path: "/instances/:id", component: { template: "<div/>" } },
    ],
  });
  await router.push(
    kind === "detail"
      ? `/networks/epochs/${overlayEpoch.id}`
      : `/networks/overlays?cluster_id=${overlayVPC.cluster_id}`,
  );
  await router.isReady();
  const component =
    kind === "overview" || kind === "detail"
      ? { template: "<RouterView/>" }
      : kind === "vpc"
        ? VPC
        : Dialog;
  const props =
    kind === "vpc"
      ? { cluster: overlayVPC.cluster_id, approvedIds: ["0".repeat(32)] }
      : kind === "plan" || kind === "recover"
        ? {
            cluster: overlayVPC.cluster_id,
            options: structuredClone(overrides?.options || overlayOption),
            vpcs: [structuredClone(overlayVPC)],
            ...(kind === "recover"
              ? { recover: structuredClone(overrides?.recover || overlayEpoch) }
              : {}),
          }
        : {};
  const wrapper = mount(
    component as unknown as DefineComponent<Record<string, unknown>>,
    {
      props: props as Record<string, unknown>,
      attachTo: document.body,
      global: {
        plugins: [router],
        provide: { [consoleKey as symbol]: context },
      },
    },
  );
  cleanups.push(() => wrapper.unmount());
  await flushPromises();
  return { wrapper, router, context, calls, reads };
}
describe("overlay localized timestamps", () => {
  it.each([
    ["overview", "zh-CN"],
    ["overview", "en"],
    ["detail", "zh-CN"],
    ["detail", "en"],
  ] as const)(
    "localizes %s timestamps in %s without changing RFC3339 microseconds in the API",
    async (kind, locale) => {
      const created = "2026-10-23T15:23:21.977618Z";
      const updated = "2026-10-24T11:07:03.123456Z";
      const record = {
        ...structuredClone(overlayEpoch),
        created_at: created,
        updated_at: updated,
      };
      const tasks = overlayTasks().map((task) => ({
        ...task,
        updated_at: updated,
      }));
      const { context, wrapper } = await setup(kind, (method, path) => {
        if (method !== "GET") return;
        if (path.startsWith("/overlays/epochs?"))
          return { items: [record], next_before_epoch: null };
        if (path === `/overlays/epochs/${record.id}`)
          return { epoch: record, tasks };
      });
      context.prefs.locale.value = locale;
      await flushPromises();
      const format = new Intl.DateTimeFormat(
        locale === "en" ? "en-GB" : "zh-CN",
        { dateStyle: "medium", timeStyle: "short" },
      );
      expect(wrapper.text()).toContain(format.format(new Date(created)));
      expect(wrapper.text()).not.toContain(created);
      if (kind === "detail") {
        expect(wrapper.text()).toContain(format.format(new Date(updated)));
        expect(wrapper.text()).not.toContain(updated);
      }
      expect(record.created_at).toBe(created);
      expect(record.updated_at).toBe(updated);
      expect(tasks.every((task) => task.updated_at === updated)).toBe(true);
    },
  );
});
function planned(key: string, payload: unknown, recover = false): OverlayEpoch {
  const input = payload as {
    members?: OverlaySelection["members"];
    gateways?: OverlaySelection["gateways"];
    nat_policies?: OverlaySelection["nat_policies"];
    replacement?: OverlaySelection;
  };
  const selection = recover ? input.replacement : input;
  return {
    ...structuredClone(overlayEpoch),
    id: key,
    epoch: 2,
    phase: "prepare",
    state: "pending",
    snapshot: {
      ...structuredClone(overlayEpoch.snapshot),
      epoch: 2,
      previous_sha256: overlayEpoch.snapshot_sha256,
      ...(selection?.members
        ? {
            members: overlayEpoch.snapshot.members.map((m) => ({
              ...m,
              ...selection.members!.find(
                (s) => s.instance_id === m.instance_id,
              ),
            })),
          }
        : {}),
      ...(selection?.gateways ? { gateways: selection.gateways } : {}),
      ...(selection?.nat_policies
        ? { nat_policies: selection.nat_policies }
        : {}),
    },
    ...(recover
      ? {
          recovery: {
            epoch: 1,
            snapshot_sha256: overlayEpoch.snapshot_sha256,
            heads: [
              {
                node_id: "node-east",
                cluster_id: overlayEpoch.cluster_id,
                epoch: 1,
                snapshot_sha256: overlayEpoch.snapshot_sha256,
              },
            ],
          },
        }
      : {}),
  };
}
async function confirmChange(value = overlayVPC.cluster_id) {
  await body().get(".confirmation input").setValue(value);
  await body().get("#overlay-change-form").trigger("submit");
  await flushPromises();
}
describe("network management UI", () => {
  it("loads real cluster, VPC, route and NAT views without a demonstration source", async () => {
    const f = await setup("overview");
    expect(f.reads).toContain("/overlays/clusters");
    expect(f.reads).toContain(
      `/overlays/options?cluster_id=${overlayVPC.cluster_id}`,
    );
    expect(f.wrapper.text()).toContain("生产私有网络");
    expect(f.wrapper.text()).toContain("198.18.0.0/16");
    expect(f.wrapper.text()).toContain("TCP 8443 → 443");
    expect(f.calls).toHaveLength(0);
    expect(f.wrapper.find("select").exists()).toBe(false);
  });
  it("has complete readable English labels and no raw JSON editor", async () => {
    const f = await setup("plan");
    f.context.prefs.locale.value = "en";
    await flushPromises();
    expect(body().text()).toContain("Instance members");
    expect(body().text()).toContain("NAT & port forwarding");
    expect(body().text()).toContain("Allowed source prefix");
    expect(body().find("select").exists()).toBe(false);
    expect(body().find("textarea").element.value).toBe("198.18.0.0/16");
  });
  it("shows native-phase task records and recovery entry instead of assuming connectivity", async () => {
    const f = await setup("detail");
    expect(f.wrapper.text()).toContain("节点执行记录");
    expect(f.wrapper.findAll(".node-phase")).toHaveLength(3);
    expect(f.wrapper.text()).toContain("不代替实际网络连通性验收");
    await button("恢复网络").trigger("click");
    await flushPromises();
    expect(body().text()).toContain("恢复方式");
  });
  it("hides planning and recovery for read-only staff, and checks permission again before a write", async () => {
    const f = await setup("plan");
    f.context.session.user.value = {
      ...f.context.session.user.value!,
      permissions: ["nodes.read"],
    };
    await confirmChange();
    expect(f.calls).toHaveLength(0);
    expect(button("应用网络配置").attributes("disabled")).toBeDefined();
  });
  it("requires both network and instance management for changes", async () => {
    const f = await setup("overview");
    f.context.session.user.value = {
      ...f.context.session.user.value!,
      permissions: ["nodes.read", "nodes.manage"],
    };
    await flushPromises();
    expect(
      f.wrapper.findAll("button").some((b) => b.text() === "配置网络"),
    ).toBe(false);
    expect(
      f.wrapper.findAll("button").some((b) => b.text() === "新建 VPC"),
    ).toBe(true);
  });
  it("preserves all financial-independent identities and sends the full selected NAT/route set once", async () => {
    const f = await setup("plan", (method, _path, payload, key) =>
      method === "POST" ? { epoch: planned(key, payload) } : undefined,
    );
    await confirmChange();
    expect(f.calls).toHaveLength(1);
    expect(f.calls[0]!.key).toMatch(/^[a-f0-9]{32}$/);
    expect(f.calls[0]!.path).toBe("/overlays/epochs");
    expect(f.calls[0]!.body).toMatchObject({
      cluster_id: overlayVPC.cluster_id,
      expected_epoch: 1,
      gateways: overlayEpoch.snapshot.gateways,
      nat_policies: overlayEpoch.snapshot.nat_policies,
    });
    expect(JSON.stringify(f.calls[0]!.body)).not.toMatch(
      /amount|currency|payment|price/,
    );
    expect(stored()).toHaveLength(0);
    expect(f.context.notify).toHaveBeenCalledWith(
      expect.stringContaining("已受理"),
    );
  });
  it("blocks unsafe route broadening before any POST", async () => {
    const f = await setup("plan");
    await body().get("textarea").setValue("0.0.0.0/0");
    await confirmChange();
    expect(f.calls).toHaveLength(0);
    expect(body().find("[role=alert]").exists()).toBe(true);
  });
  it("blocks disabling a NAT destination until forwarding references are corrected", async () => {
    const f = await setup("plan");
    await body()
      .get('button[aria-label="停用 web-production-01"]')
      .trigger("click");
    await confirmChange();
    expect(f.calls).toHaveLength(0);
    expect(body().find("[role=alert]").exists()).toBe(true);
  });
  it("removing a gateway cannot silently remove its existing NAT policy", async () => {
    const f = await setup("plan");
    await button("移除网关").trigger("click");
    await confirmChange();
    expect(f.calls).toHaveLength(0);
    await button("移除 NAT").trigger("click");
    await confirmChange();
    expect(f.calls).toHaveLength(1);
    expect(f.calls[0]!.body).toMatchObject({ gateways: [], nat_policies: [] });
  });
  it("recovery binds original SHA and a fresh operation key, not a replay of the original task", async () => {
    const f = await setup("recover", (m, _p, b, k) =>
      m === "POST" ? { epoch: planned(k, b, true) } : undefined,
    );
    await confirmChange(overlayEpoch.id);
    expect(f.calls).toHaveLength(1);
    expect(f.calls[0]!.path).toBe(
      `/overlays/epochs/${overlayEpoch.id}/recover`,
    );
    expect(f.calls[0]!.key).not.toBe(overlayEpoch.id);
    expect(f.calls[0]!.body).toEqual({
      expected_snapshot_sha256: overlayEpoch.snapshot_sha256,
    });
  });
  it("uses root-approved VPC identity for creation rather than an unusable random network", async () => {
    const f = await setup("vpc", (m, _p, b, k) =>
      m === "POST"
        ? { vpc: { ...overlayVPC, ...(b as object), id: k }, replay: false }
        : undefined,
    );
    const inputs = body().findAll("input");
    await inputs[0]!.setValue("备用网络");
    await inputs[1]!.setValue(overlayVPC.owner_ref);
    await inputs[2]!.setValue("10.30.0.0/24");
    await inputs[3]!.setValue("121");
    await body().get("#overlay-vpc-form").trigger("submit");
    await flushPromises();
    expect(f.calls).toHaveLength(1);
    expect(f.calls[0]!.key).toBe("0".repeat(32));
    expect(f.wrapper.emitted("saved")).toHaveLength(1);
  });
  it("retains an unknown full intent and uses only GET to confirm it", async () => {
    let accepted: OverlayEpoch | undefined;
    const f = await setup("plan", (m, p, b, k) => {
      if (m === "POST") {
        accepted = planned(k, b);
        throw new Error("lost acknowledgement");
      }
      if (accepted && p === `/overlays/epochs/${accepted.id}`)
        return { epoch: accepted, tasks: [] };
      return undefined;
    });
    await confirmChange();
    expect(f.calls).toHaveLength(1);
    expect(stored()).toHaveLength(1);
    expect(button("应用网络配置").attributes("disabled")).toBeDefined();
    await button("只读核对原变更").trigger("click");
    await flushPromises();
    expect(f.calls).toHaveLength(1);
    expect(f.reads).toContain(`/overlays/epochs/${accepted!.id}`);
    expect(stored()).toHaveLength(0);
    expect(f.wrapper.emitted("saved")).toHaveLength(1);
  });
  it("a changed or foreign GET record cannot clear an unknown intent", async () => {
    let accepted: OverlayEpoch | undefined;
    const f = await setup("plan", (m, p, b, k) => {
      if (m === "POST") {
        accepted = planned(k, b);
        throw new Error("lost");
      }
      if (accepted && p.includes(accepted.id))
        return {
          epoch: {
            ...accepted,
            snapshot: { ...accepted.snapshot, nat_policies: [] },
          },
          tasks: [],
        };
      return undefined;
    });
    await confirmChange();
    await button("只读核对原变更").trigger("click");
    await flushPromises();
    expect(f.calls).toHaveLength(1);
    expect(stored()).toHaveLength(1);
    expect(f.wrapper.emitted("saved")).toBeUndefined();
  });
  it("close and reopen restores the frozen unknown payload and never submits it twice", async () => {
    const f = await setup("plan", (m) => {
      if (m === "POST") throw new Error("lost");
      return undefined;
    });
    await confirmChange();
    const key = stored()[0].key;
    f.wrapper.unmount();
    const next = await setup("plan");
    expect(body().text()).toContain(key);
    expect(button("应用网络配置").attributes("disabled")).toBeDefined();
    expect(body().get("textarea").attributes("disabled")).toBeDefined();
    await confirmChange();
    expect(next.calls).toHaveLength(0);
    expect(stored()).toHaveLength(1);
  });
  it.each(["route", "session"] as const)(
    "ignores late success after %s changes but retains unresolved intent",
    async (mode) => {
      const pending = deferred<unknown>();
      let key = "",
        payload: unknown;
      const f = await setup("plan", (m, _p, b, k) => {
        if (m === "POST") {
          key = k;
          payload = b;
          return pending.promise;
        }
        return undefined;
      });
      await confirmChange();
      if (mode === "route") await f.router.push("/elsewhere");
      else f.context.session.invalidate();
      pending.resolve({ epoch: planned(key, payload) });
      await flushPromises();
      expect(f.context.notify).not.toHaveBeenCalled();
      expect(f.wrapper.emitted("saved")).toBeUndefined();
      expect(stored()).toHaveLength(1);
    },
  );
  it("fails closed when intent storage cannot persist before POST", async () => {
    const f = await setup("plan");
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("storage disabled");
    });
    await confirmChange();
    expect(f.calls).toHaveLength(0);
    expect(body().find("[role=alert]").exists()).toBe(true);
  });
  it("read-only staff sees network history while writes stay hidden", async () => {
    const f = await setup("detail");
    f.context.session.user.value = {
      ...f.context.session.user.value!,
      permissions: ["nodes.read"],
    };
    await flushPromises();
    expect(f.wrapper.text()).toContain("节点执行记录");
    expect(
      f.wrapper.findAll("button").some((b) => b.text() === "恢复网络"),
    ).toBe(false);
    expect(f.calls).toHaveLength(0);
  });
  it("loading is distinct from empty and failed network state", async () => {
    const waiting = deferred<unknown>();
    const f = await setup("overview", (_m, p) =>
      p === "/overlays/clusters" ? waiting.promise : undefined,
    );
    expect(f.wrapper.find("[role=status]").exists()).toBe(true);
    expect(f.wrapper.text()).not.toContain("尚未配置网络集群");
    waiting.resolve({ items: [] });
    await flushPromises();
    expect(f.wrapper.text()).toContain("尚未配置网络集群");
    expect(f.calls).toHaveLength(0);
  });
});
function publicOptions() {
  const options = structuredClone(overlayOption);
  options.nat_profiles[0]!.allow_internet_egress = true;
  options.nat_profiles[0]!.public_ipv4 = "8.8.4.4";
  return options;
}
async function choose(label: string, option: string) {
  await body()
    .get(`button[role=combobox][aria-label="${label}"]`)
    .trigger("click");
  const target = body()
    .findAll("[role=option]")
    .find((item) => item.text() === option);
  expect(target, `option ${option}`).toBeDefined();
  await target!.trigger("pointerdown");
  await flushPromises();
}
describe("public NAT egress management", () => {
  it("keeps a changed public selection behind the existing discard guard when cancelling", async () => {
    const f = await setup("plan", undefined, { options: publicOptions() });
    await choose("出口范围", "公网 IPv4");
    await button("取消").trigger("click");
    await flushPromises();
    expect(f.wrapper.emitted("close")).toBeUndefined();
    expect(body().get(".discard-box").text()).toContain("放弃更改");
    await button("继续编辑").trigger("click");
    expect(body().get('button[aria-label="出口范围"]').text()).toContain(
      "公网 IPv4",
    );
    expect(f.calls).toHaveLength(0);
  });
  it("selects an approved public egress but requires explicit scope confirmation before POST", async () => {
    const f = await setup(
      "plan",
      (m, _p, b, k) => (m === "POST" ? { epoch: planned(k, b) } : undefined),
      { options: publicOptions() },
    );
    await choose("出口范围", "公网 IPv4");
    expect(body().text()).toContain("8.8.4.4");
    expect(body().text()).toContain("这里只保存本次选择");
    expect(body().text()).toContain("私有网段与管理地址不会因此开放");
    await confirmChange();
    expect(f.calls).toHaveLength(0);
    expect(button("应用网络配置").attributes("disabled")).toBeDefined();
    await body().get(".public-consent input").setValue(true);
    await confirmChange();
    expect(f.calls).toHaveLength(1);
    expect(f.calls[0]!.body).toMatchObject({
      nat_policies: [
        {
          ...overlayNAT,
          internet_egress_enabled: true,
        },
      ],
    });
    expect(f.wrapper.emitted("saved")).toHaveLength(1);
    expect(stored()).toHaveLength(0);
  });
  it.each(["snat", "scope"] as const)(
    "turning off public access via %s omits the flag while retaining independent port mappings",
    async (mode) => {
      const f = await setup(
        "plan",
        (m, _p, b, k) => (m === "POST" ? { epoch: planned(k, b) } : undefined),
        { options: publicOptions() },
      );
      await choose("出口范围", "公网 IPv4");
      if (mode === "snat") await choose("出站地址转换", "关闭");
      else await choose("出口范围", "仅指定网段");
      expect(body().find(".public-consent").exists()).toBe(false);
      expect(body().get('button[aria-label="出口范围"]').text()).toContain(
        "仅指定网段",
      );
      await confirmChange();
      expect(f.calls).toHaveLength(1);
      const policy = (f.calls[0]!.body as OverlaySelection).nat_policies![0]!;
      expect(policy).not.toHaveProperty("internet_egress_enabled");
      expect(policy.snat_enabled).toBe(mode !== "snat");
      expect(policy.forwardings).toEqual(overlayNAT.forwardings);
    },
  );
  it("supports Internet-only egress with an explicitly empty route list and no DNAT", async () => {
    const f = await setup(
      "plan",
      (m, _p, b, k) => (m === "POST" ? { epoch: planned(k, b) } : undefined),
      { options: publicOptions() },
    );
    // Icon-only actions use an accessible name rather than visible copy.
    await body().get('button[aria-label="删除端口映射 1"]').trigger("click");
    await body().get("textarea").setValue("");
    expect(body().get("textarea").element.value).toBe("");
    await choose("出口范围", "公网 IPv4");
    await body().get(".public-consent input").setValue(true);
    await confirmChange();
    expect(f.calls).toHaveLength(1);
    const selection = f.calls[0]!.body as OverlaySelection;
    expect(selection.gateways[0]!.allowed_prefixes).toEqual([]);
    expect(selection.nat_policies![0]).toMatchObject({
      snat_enabled: true,
      internet_egress_enabled: true,
      forwardings: [],
    });
  });
  it.each([undefined, false])(
    "does not offer unapproved public egress (%s)",
    async (approved) => {
      const options = publicOptions();
      options.nat_profiles[0]!.allow_internet_egress = approved;
      const f = await setup("plan", undefined, { options });
      expect(body().text()).toContain("节点尚未开放此出口的公网访问");
      await choose("出口范围", "公网 IPv4");
      expect(body().get("[role=option][aria-disabled=true]").text()).toContain(
        "公网 IPv4",
      );
      expect(body().get('button[aria-label="出口范围"]').text()).toContain(
        "仅指定网段",
      );
      expect(body().find(".public-consent").exists()).toBe(false);
      expect(f.calls).toHaveLength(0);
    },
  );
  it("keeps the public option unavailable while SNAT is off and supports keyboard selection after enabling it", async () => {
    await setup("plan", undefined, { options: publicOptions() });
    await choose("出站地址转换", "关闭");
    expect(body().text()).toContain("先开启出站地址转换");
    const scope = body().get('button[aria-label="出口范围"]');
    await scope.trigger("keydown", { key: "Enter" });
    await scope.trigger("keydown", { key: "End" });
    await scope.trigger("keydown", { key: "Enter" });
    expect(scope.text()).toContain("仅指定网段");
    await choose("出站地址转换", "开启");
    await scope.trigger("keydown", { key: "Enter" });
    await scope.trigger("keydown", { key: "End" });
    await scope.trigger("keydown", { key: "Enter" });
    expect(scope.text()).toContain("公网 IPv4");
    expect(body().find(".public-consent").exists()).toBe(true);
  });
  it("shows invalid node egress addresses without allowing them to be selected", async () => {
    const options = publicOptions();
    options.nat_profiles[0]!.public_ipv4 = "10.0.0.5";
    await setup("plan", undefined, { options });
    expect(body().text()).toContain("没有可用的公网 IPv4 地址");
    await choose("出口范围", "公网 IPv4");
    expect(body().find(".public-consent").exists()).toBe(false);
  });
  it("locks public controls and confirmation when management permission is lost", async () => {
    const f = await setup("plan", undefined, { options: publicOptions() });
    await choose("出口范围", "公网 IPv4");
    f.context.session.user.value = {
      ...f.context.session.user.value!,
      permissions: ["nodes.read"],
    };
    await flushPromises();
    expect(
      body().get('button[aria-label="出口范围"]').attributes("disabled"),
    ).toBeDefined();
    expect(
      body().get(".public-consent input").attributes("disabled"),
    ).toBeDefined();
    await confirmChange();
    expect(f.calls).toHaveLength(0);
  });
  it("does not acknowledge a lost POST when the GET has the other public egress mode", async () => {
    let accepted: OverlayEpoch | undefined;
    const f = await setup(
      "plan",
      (m, p, b, k) => {
        if (m === "POST") {
          accepted = planned(k, b);
          throw new Error("lost acknowledgement");
        }
        if (accepted && p === `/overlays/epochs/${accepted.id}`) {
          const wrong = structuredClone(accepted);
          delete wrong.snapshot.nat_policies![0]!.internet_egress_enabled;
          return { epoch: wrong, tasks: [] };
        }
        return undefined;
      },
      { options: publicOptions() },
    );
    await choose("出口范围", "公网 IPv4");
    await body().get(".public-consent input").setValue(true);
    await confirmChange();
    expect(f.calls).toHaveLength(1);
    expect(stored()[0].body.nat_policies[0].internet_egress_enabled).toBe(true);
    await button("只读核对原变更").trigger("click");
    await flushPromises();
    expect(stored()).toHaveLength(1);
    expect(f.calls).toHaveLength(1);
    expect(f.wrapper.emitted("saved")).toBeUndefined();
    expect(body().find("[role=alert]").exists()).toBe(true);
  });
  it.each(["overview", "detail"] as const)(
    "shows public scope and the pinned output address in %s",
    async (kind) => {
      const options = publicOptions();
      const record = structuredClone(overlayEpoch);
      record.snapshot.nat_policies![0]!.internet_egress_enabled = true;
      const f = await setup(kind, (m, p) => {
        if (m !== "GET") return;
        if (p.startsWith("/overlays/options?"))
          return { ...options, latest_epoch: record };
        if (p === `/overlays/epochs/${record.id}`)
          return { epoch: record, tasks: overlayTasks(record) };
      });
      expect(f.wrapper.text()).toContain("公网 IPv4 出口已选择");
      expect(f.wrapper.text()).toContain("8.8.4.4");
      f.context.prefs.locale.value = "en";
      await flushPromises();
      expect(f.wrapper.text()).toContain(
        "Public IPv4 Internet egress selected",
      );
      expect(f.calls).toHaveLength(0);
    },
  );
  it("shows and confirms the retained public mode when recovering the original selection", async () => {
    const options = publicOptions();
    const record = structuredClone(overlayEpoch);
    record.snapshot.nat_policies![0]!.internet_egress_enabled = true;
    options.latest_epoch = record;
    const f = await setup(
      "recover",
      (m, _p, b, k) => {
        if (m !== "POST") return;
        const result = planned(k, b, true);
        result.snapshot.nat_policies![0]!.internet_egress_enabled = true;
        return { epoch: result };
      },
      { options, recover: record },
    );
    expect(body().get(".recovery-summary").text()).toContain("公网 IPv4");
    await confirmChange(record.id);
    expect(f.calls).toHaveLength(0);
    await body().get(".public-consent input").setValue(true);
    await confirmChange(record.id);
    expect(f.calls).toHaveLength(1);
    expect(f.calls[0]!.body).toEqual({
      expected_snapshot_sha256: record.snapshot_sha256,
    });
    expect(f.wrapper.emitted("saved")).toHaveLength(1);
  });
  it("keeps a maximum-length unbroken profile identity readable in the retained recovery summary", async () => {
    const options = publicOptions();
    const record = structuredClone(overlayEpoch);
    const profile = "w".repeat(64);
    record.snapshot.nat_policies![0]!.profile_id = profile;
    record.snapshot.nat_policies![0]!.internet_egress_enabled = true;
    options.nat_profiles[0]!.profile_id = profile;
    options.latest_epoch = record;
    const f = await setup("recover", undefined, { options, recover: record });
    const policy = body().get(".recovery-policy");
    expect(policy.get("dt").text()).toContain(profile);
    expect(policy.get("dd").text()).toBe("公网 IPv4");
    expect(
      body().findAll(".recovery-summary > div:not(.recovery-policy)"),
    ).toHaveLength(3);
    f.context.prefs.locale.value = "en";
    await flushPromises();
    expect(policy.get("dt").text()).toContain(profile);
    expect(policy.get("dd").text()).toBe("Public IPv4 Internet");
    expect(f.calls).toHaveLength(0);
  });
});
describe("unmapped VPC creation", () => {
  it("also creates a new network ID without a prior node mapping and explains its inactive scope", async () => {
    const f = await setup("vpc", (m, _p, b, k) =>
      m === "POST"
        ? { vpc: { ...overlayVPC, ...(b as object), id: k }, replay: false }
        : undefined,
    );
    await body().get("button[role=combobox]").trigger("click");
    await body()
      .findAll("[role=option]")
      .find((o) => o.text() === "创建新网络标识")!
      .trigger("pointerdown");
    expect(body().text()).toContain("创建后尚未映射节点");
    const inputs = body().findAll("input");
    await inputs[0]!.setValue("待配置网络");
    await inputs[1]!.setValue(overlayVPC.owner_ref);
    await inputs[2]!.setValue("10.40.0.0/24");
    await inputs[3]!.setValue("122");
    await body().get("#overlay-vpc-form").trigger("submit");
    await flushPromises();
    expect(f.calls).toHaveLength(1);
    expect(f.calls[0]!.key).toMatch(/^[a-f0-9]{32}$/);
    expect(f.calls[0]!.key).not.toBe("0".repeat(32));
    expect(f.wrapper.emitted("saved")).toHaveLength(1);
  });
  it("cannot silently downgrade a profile change into a normal plan", async () => {
    const options = structuredClone(overlayOption);
    options.profiles = [
      { ...options.profiles[0]!, profile_sha256: "f".repeat(64) },
    ];
    const f = await setup("overview", (_m, p) =>
      p.startsWith("/overlays/options?") ? options : undefined,
    );
    expect(f.wrapper.text()).toContain("节点配置已更新");
    expect(
      f.wrapper.findAll("button").some((b) => b.text() === "配置网络"),
    ).toBe(false);
    expect(f.wrapper.text()).toContain("查看变更与恢复");
  });
});
describe("network lifetime and accessibility edge cases", () => {
  it("does not allow a malformed persisted intent to be replaced with a new write", async () => {
    sessionStorage.setItem(
      "aster.cloud.overlay-intents.v1",
      '[{"owner":"' +
        "c".repeat(32) +
        '","scope":"epoch:cluster-east:1","path":"/overlays/epochs","key":"' +
        "d".repeat(32) +
        '","body":{"members":"broken"}}]',
    );
    const original = sessionStorage.getItem("aster.cloud.overlay-intents.v1");
    const f = await setup("plan");
    await confirmChange();
    expect(f.calls).toHaveLength(0);
    expect(sessionStorage.getItem("aster.cloud.overlay-intents.v1")).toBe(
      original,
    );
    expect(body().find("[role=alert]").exists()).toBe(true);
  });
  it.each([0x11, 0xee])(
    "adds stable forwarding identities when the new random ID sorts on either side of the old ID (%i)",
    async (byte) => {
      const f = await setup("plan", (m, _p, b, k) =>
        m === "POST" ? { epoch: planned(k, b) } : undefined,
      );
      vi.stubGlobal("crypto", {
        getRandomValues: (buffer: Uint8Array) => buffer.fill(byte),
      });
      await button("添加端口映射").trigger("click");
      vi.stubGlobal("crypto", webcrypto);
      await confirmChange();
      expect(f.calls).toHaveLength(1);
      const policies = (f.calls[0]!.body as OverlaySelection).nat_policies!;
      expect(policies[0]!.forwardings).toHaveLength(2);
      const oldID = overlayNAT.forwardings[0]!.id;
      expect(
        policies[0]!.forwardings.find((rule) => rule.id === oldID),
      ).toEqual(overlayNAT.forwardings[0]);
      const added = policies[0]!.forwardings.find((rule) => rule.id !== oldID);
      // The canonical payload sorts by stable ID, not creation order. Assert the
      // new rule's whole contract by identity for both lexical positions.
      expect(added).toEqual({
        id: byte.toString(16).repeat(16),
        protocol: "tcp",
        public_port: 8000,
        target_instance_id: overlayNAT.forwardings[0]!.target_instance_id,
        target_port: 8000,
        source_cidr: "198.18.0.0/16",
      });
      expect(body().findAll("select")).toHaveLength(0);
    },
  );
  it("keeps a trailing newline editable in the route field while submitting canonical prefixes", async () => {
    const f = await setup("plan", (m, _p, b, k) =>
      m === "POST" ? { epoch: planned(k, b) } : undefined,
    );
    await body().get("textarea").setValue("198.18.0.0/16\n");
    expect(body().get("textarea").element.value).toBe("198.18.0.0/16\n");
    await confirmChange();
    expect(f.calls).toHaveLength(1);
    expect(
      (f.calls[0]!.body as OverlaySelection).gateways[0]!.allowed_prefixes,
    ).toEqual(["198.18.0.0/16"]);
  });
  it("hides profile migration recovery until it is explicitly approved", async () => {
    const options = structuredClone(overlayOption);
    options.profile_migration_required = true;
    options.profile_migration_approved = false;
    const f = await setup("detail", (_m, p) =>
      p.startsWith("/overlays/options?") ? options : undefined,
    );
    expect(f.wrapper.text()).toContain("尚未批准此版本的迁移恢复");
    expect(
      f.wrapper.findAll("button").some((b) => b.text() === "恢复网络"),
    ).toBe(false);
    expect(f.calls).toHaveLength(0);
  });
  it("supports the keyboard in custom egress and protocol controls", async () => {
    await setup("plan");
    const combobox = body().find(
      'button[role=combobox][aria-label="出站地址转换"]',
    );
    await combobox.trigger("keydown", { key: "Enter" });
    expect(body().find("[role=listbox]").exists()).toBe(true);
    await combobox.trigger("keydown", { key: "Home" });
    await combobox.trigger("keydown", { key: "Enter" });
    expect(body().find("[role=listbox]").exists()).toBe(false);
    expect(combobox.text()).toContain("关闭");
  });
  it("failed reads do not turn the overview into an empty network", async () => {
    const f = await setup("overview", (_m, p) => {
      if (p.startsWith("/overlays/options?")) throw new Error("network down");
      return undefined;
    });
    expect(f.wrapper.find("[role=alert]").exists()).toBe(true);
    expect(f.wrapper.find(".vpc-card").exists()).toBe(false);
    expect(f.wrapper.text()).not.toContain("还没有 VPC");
    expect(f.calls).toHaveLength(0);
  });
});

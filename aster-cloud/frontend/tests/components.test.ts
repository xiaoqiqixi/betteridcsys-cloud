import { beforeEach, afterEach, describe, it, expect, vi } from "vitest";
import { mount, flushPromises } from "@vue/test-utils";
import { webcrypto } from "node:crypto";
import { createMemoryHistory, createRouter } from "vue-router";
import { consoleKey } from "../src/context";
import { ApiError } from "../src/api/client";
import UiButton from "../src/components/UiButton.vue";
import UiSelect from "../src/components/UiSelect.vue";
import UiOverlay from "../src/components/UiOverlay.vue";
import StateBlock from "../src/components/StateBlock.vue";
import StatusBadge from "../src/components/StatusBadge.vue";
import ActionDialog from "../src/components/ActionDialog.vue";
import CreateInstanceDialog from "../src/components/CreateInstanceDialog.vue";
import MigrationWizard from "../src/components/MigrationWizard.vue";
import NavLinks from "../src/components/NavLinks.vue";
import { instance, node, operation, resources } from "./fixtures";
import { mockContext } from "./helpers";
import { identityFixtureResponse } from "./identity-fixtures";
vi.stubGlobal("crypto", webcrypto);
const wrappers: Array<{ unmount: () => void }> = [];
const options = (context: ReturnType<typeof mockContext>["context"]) => ({
  attachTo: document.body,
  global: {
    provide: { [consoleKey as symbol]: context },
    plugins: [
      createRouter({
        history: createMemoryHistory(),
        routes: [
          { path: "/", component: { template: "<div />" } },
          { path: "/operations/:id", component: { template: "<div />" } },
        ],
      }),
    ],
    stubs: { teleport: true },
  },
});
beforeEach(() => {
  sessionStorage.clear();
  vi.spyOn(history, "back").mockImplementation(() => {});
  Element.prototype.scrollIntoView = vi.fn();
  vi.spyOn(HTMLElement.prototype, "getClientRects").mockImplementation(
    () => [new DOMRect(0, 0, 100, 44)] as unknown as DOMRectList,
  );
});
afterEach(() => {
  wrappers.splice(0).forEach((w) => w.unmount());
  document.body.innerHTML = "";
  vi.restoreAllMocks();
  history.replaceState(null, "");
});
describe("custom controls", () => {
  it("gives surface navigation an explicit tone without changing permissions, routes or events", async () => {
    const { context } = mockContext(() => ({}));
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [
        "instances",
        "nodes",
        "operations",
        "audit",
        "users",
        "networks/overlays",
      ].map((name) => ({
        path: `/${name}`,
        component: { template: "<div />" },
      })),
    });
    await router.push("/instances");
    await router.isReady();
    const wrapper = mount(NavLinks, {
      ...options(context),
      props: { tone: "surface" },
      global: { ...options(context).global, plugins: [router] },
    });
    wrappers.push(wrapper);
    expect(wrapper.get("nav").classes()).toContain("tone-surface");
    expect(wrapper.findAll("a")).toHaveLength(6);
    expect(wrapper.get('a[href="/networks/overlays"]').text()).toBe(
      "网络与 IP",
    );
    expect(wrapper.get("a.is-current").text()).toBe("实例");
    await wrapper.get('a[href="/nodes"]').trigger("click");
    await flushPromises();
    expect(router.currentRoute.value.path).toBe("/nodes");
    expect(wrapper.emitted("navigate")).toHaveLength(1);
    await wrapper.setProps({ tone: "sidebar" });
    expect(wrapper.get("nav").classes()).toContain("tone-sidebar");
    context.session.user.value = {
      ...context.session.user.value!,
      role: "custom",
      permissions: ["instances.read"],
    };
    context.prefs.locale.value = "en";
    await flushPromises();
    expect(wrapper.findAll("a").map((link) => link.text())).toEqual([
      "Instances",
      "Tasks",
    ]);
  });
  it("button exposes busy state and cannot be activated while busy", () => {
    const wrapper = mount(UiButton, {
      props: { busy: true },
      slots: { default: "保存" },
    });
    wrappers.push(wrapper);
    expect(wrapper.attributes("aria-busy")).toBe("true");
    expect(wrapper.attributes("disabled")).toBeDefined();
    expect(wrapper.find(".spinner").exists()).toBe(true);
  });
  it("Select supports keyboard, disabled option, Home/End and Escape without a native select", async () => {
    const wrapper = mount(UiSelect, {
      props: {
        modelValue: "a",
        label: "地区",
        options: [
          { value: "a", label: "甲" },
          { value: "b", label: "停用", disabled: true },
          { value: "c", label: "丙" },
        ],
      },
    });
    wrappers.push(wrapper);
    const trigger = wrapper.get("[role=combobox]");
    await trigger.trigger("keydown", { key: "ArrowDown" });
    expect(wrapper.findAll("[role=option]")).toHaveLength(3);
    await trigger.trigger("keydown", { key: "ArrowDown" });
    await trigger.trigger("keydown", { key: "Enter" });
    expect(wrapper.emitted("update:modelValue")?.[0]).toEqual(["c"]);
    await trigger.trigger("keydown", { key: "ArrowDown" });
    await trigger.trigger("keydown", { key: "End" });
    expect(trigger.attributes("aria-activedescendant")).toMatch(/-2$/);
    await trigger.trigger("keydown", { key: "Home" });
    expect(trigger.attributes("aria-activedescendant")).toMatch(/-0$/);
    await trigger.trigger("keydown", { key: "Escape" });
    expect(wrapper.find("[role=listbox]").exists()).toBe(false);
    expect(wrapper.find("select").exists()).toBe(false);
  });
  it("keeps unknown statuses case-sensitive and does not paint them successful", () => {
    const { context } = mockContext(() => ({}));
    const wrapper = mount(StatusBadge, {
      ...options(context),
      props: { state: "Succeeded" },
    });
    wrappers.push(wrapper);
    expect(wrapper.text()).toBe("Succeeded");
    expect(wrapper.classes()).not.toContain("tone-good");
  });
  it("distinguishes loading, empty and error rather than rendering empty success", async () => {
    const { context } = mockContext(() => ({}));
    const wrapper = mount(StateBlock, {
      ...options(context),
      props: { loading: true, empty: true, error: "network" },
    });
    wrappers.push(wrapper);
    expect(wrapper.find("[role=status]").exists()).toBe(true);
    expect(wrapper.find("[role=alert]").exists()).toBe(false);
    await wrapper.setProps({ loading: false });
    expect(wrapper.find("[role=alert]").exists()).toBe(true);
    expect(wrapper.text()).not.toContain("暂无记录");
    await wrapper.setProps({ error: "" });
    expect(wrapper.text()).toContain("暂无记录");
  });
  it("overlay has a unique token per opening, busy/dirty close guards and focus restoration", async () => {
    const trigger = document.createElement("button");
    trigger.textContent = "open";
    document.body.append(trigger);
    trigger.focus();
    history.replaceState({ asterOverlay: "stale-document-token" }, "");
    const wrapper = mount(UiOverlay, {
      attachTo: document.body,
      global: { stubs: { teleport: true } },
      props: { open: true, title: "设置", busy: true },
      slots: { default: '<input aria-label="name">' },
    });
    wrappers.push(wrapper);
    await flushPromises();
    const first = history.state.asterOverlay;
    document.dispatchEvent(
      new KeyboardEvent("keydown", { key: "Escape", bubbles: true }),
    );
    expect(wrapper.emitted("close")).toBeUndefined();
    await wrapper.setProps({ busy: false, dirty: true });
    document.dispatchEvent(
      new KeyboardEvent("keydown", { key: "Escape", bubbles: true }),
    );
    await flushPromises();
    expect(wrapper.get(".discard-box").text()).toContain("放弃更改");
    expect(wrapper.emitted("close")).toBeUndefined();
    await wrapper.setProps({ open: false });
    await flushPromises();
    expect(document.activeElement).toBe(trigger);
    await wrapper.setProps({ open: true, dirty: false });
    await flushPromises();
    expect(history.state.asterOverlay).not.toBe(first);
    await wrapper.get(".overlay-header button").trigger("click");
    expect(wrapper.emitted("close")).toHaveLength(1);
  });
  it("releases a closed drawer before a new dialog acquires background and focus guards", async () => {
    const app = document.createElement("div");
    app.id = "app";
    const trigger = document.createElement("button");
    app.append(trigger);
    document.body.append(app);
    trigger.focus();
    const drawer = mount(UiOverlay, {
      attachTo: document.body,
      global: { stubs: { teleport: true } },
      props: { open: true, drawer: true, title: "导航" },
      slots: {
        default: "<button>实例</button>",
        footer: "<button>退出</button>",
      },
    });
    const dialog = mount(UiOverlay, {
      attachTo: document.body,
      global: { stubs: { teleport: true } },
      props: { open: false, title: "语言与外观" },
      slots: { default: "<button>简体中文</button>" },
    });
    wrappers.push(drawer, dialog);
    await flushPromises();
    expect(app.inert).toBe(true);
    await drawer.setProps({ open: false });
    expect(app.inert).toBe(false);
    expect(document.activeElement).toBe(trigger);
    await dialog.setProps({ open: true });
    await flushPromises();
    expect(app.inert).toBe(true);
    expect(document.body.style.overflow).toBe("hidden");
    const panel = dialog.get("[role=dialog]").element;
    expect(panel.contains(document.activeElement)).toBe(true);
    drawer.unmount();
    expect(app.inert).toBe(true);
    await dialog.setProps({ open: false });
    expect(app.inert).toBe(false);
    expect(document.body.style.overflow).toBe("");
    expect(document.activeElement).toBe(trigger);
  });
});
describe("real-operation boundaries", () => {
  it("requires the exact instance ID (not the hostname), accepts only the bound task and never auto-dispatches", async () => {
    const { context, calls } = mockContext((_m, _p, _b, key) => ({
      operation: { ...operation, id: key, action: "reboot" },
    }));
    const wrapper = mount(ActionDialog, {
      ...options(context),
      props: { open: true, instance, action: "reboot" },
    });
    wrappers.push(wrapper);
    await flushPromises();
    const input = wrapper.get("input");
    const submit = () =>
      wrapper.findAll("button").find((b) => b.text() === "创建任务")!;
    await input.setValue(instance.hostname);
    expect(submit().attributes("disabled")).toBeDefined();
    await input.setValue(instance.id);
    await submit().trigger("click");
    await vi.waitFor(() => expect(calls).toHaveLength(1));
    await flushPromises();
    expect(calls[0]).toMatchObject({
      method: "POST",
      path: `/instances/${instance.id}/operations`,
      body: { action: "reboot", confirmation: instance.id },
    });
    expect(wrapper.text()).toContain("操作已受理");
    expect(calls.some((c) => /dispatch/.test(c.path))).toBe(false);
  });
  it("creation has an empty approved-preset state, not fabricated product options", async () => {
    const { context, calls } = mockContext(() => ({ items: [] }));
    const wrapper = mount(CreateInstanceDialog, {
      ...options(context),
      props: { open: true },
    });
    wrappers.push(wrapper);
    await flushPromises();
    expect(wrapper.text()).toContain("暂无可用规格");
    expect(wrapper.find("[role=combobox]").exists()).toBe(false);
    expect(calls).toHaveLength(0);
  });
  it("creates only an approved preset intent and stops at acceptance", async () => {
    const { context, calls } = mockContext((method, _path, _body, key) =>
      method === "GET"
        ? { items: [{ id: "approved", node_id: "node-b", resources }] }
        : { operation: { ...operation, id: key, action: "create" } },
    );
    const wrapper = mount(CreateInstanceDialog, {
      ...options(context),
      props: { open: true },
    });
    wrappers.push(wrapper);
    await flushPromises();
    const combobox = wrapper.get("[role=combobox]");
    await combobox.trigger("keydown", { key: "ArrowDown" });
    await combobox.trigger("keydown", { key: "Enter" });
    const inputs = wrapper.findAll("input");
    await inputs[0]!.setValue("cloud-server");
    await inputs[1]!.setValue("e".repeat(32));
    await wrapper.get("form").trigger("submit");
    await vi.waitFor(() => expect(calls).toHaveLength(1));
    await flushPromises();
    expect(calls[0]?.body).toEqual({
      hostname: "cloud-server",
      owner_ref: "e".repeat(32),
      preset_id: "approved",
    });
    expect(wrapper.text()).toContain("创建任务已受理");
    expect(calls[0]?.path).toBe("/instances");
  });
  it("transferred migration references the immutable migration artifact and never auto-activates", async () => {
    const migration = {
      id: "f".repeat(32),
      instance_id: instance.id,
      source_node_id: "node-a",
      target_node_id: "node-b",
      phase: "transferred",
      created_at: instance.created_at,
      updated_at: instance.updated_at,
    };
    const { context, calls } = mockContext((method, _path, _body, key) =>
      method === "GET"
        ? { items: [node], next_cursor: null }
        : {
            operation: {
              ...operation,
              id: key,
              action: "migrate_import",
              artifact_id: migration.id,
            },
          },
    );
    const wrapper = mount(MigrationWizard, {
      ...options(context),
      props: { open: false, instance, migrations: [migration] },
    });
    wrappers.push(wrapper);
    await wrapper.setProps({ open: true });
    await flushPromises();
    await wrapper.get("input").setValue(instance.id);
    await wrapper
      .findAll("button")
      .find((b) => b.text() === "创建本阶段任务")!
      .trigger("click");
    await vi.waitFor(() => expect(calls).toHaveLength(1));
    await flushPromises();
    expect(calls[0]?.body).toEqual({
      action: "migrate_import",
      confirmation: instance.id,
      artifact_id: migration.id,
    });
    expect(wrapper.text()).toContain("本阶段任务已受理");
    expect(
      calls.some(
        (c) => (c.body as { action?: string }).action === "migrate_activate",
      ),
    ).toBe(false);
  });
});

describe("user role editor boundaries", () => {
  it("sends fixed roles without a permissions field and never persists the entered password", async () => {
    const { default: UserEditor } =
      await import("../src/components/UserEditor.vue");
    const { context, calls } = mockContext((_m, _p, body, key) =>
      identityFixtureResponse("identity.user_created", key, body),
    );
    const wrapper = mount(UserEditor, {
      ...options(context),
      props: {
        open: true,
        user: null,
        roles: [
          { id: "viewer", name: "Viewer", permissions: ["instances.read"] },
          { id: "custom", name: "Custom", permissions: [] },
        ],
      },
    });
    wrappers.push(wrapper);
    await flushPromises();
    await wrapper.get("input[type=text]").setValue("New member");
    await wrapper.get("input[type=email]").setValue("new@example.invalid");
    await wrapper.get("input[type=password]").setValue("NeverPersist123!");
    await wrapper.get("textarea").setValue("Provision limited member access");
    await wrapper.get("form").trigger("submit");
    await vi.waitFor(() => expect(calls).toHaveLength(1));
    expect(calls[0]?.body).toEqual({
      name: "New member",
      email: "new@example.invalid",
      role: "viewer",
      password: "NeverPersist123!",
      reason: "Provision limited member access",
    });
    expect(
      sessionStorage.getItem("aster.cloud.identity.pending.v1"),
    ).not.toContain("NeverPersist");
    expect(calls[0]?.method).toBe("POST");
  });
  it("requires custom permissions explicitly, including empty grants, and dirty cancel does not silently discard", async () => {
    const { default: UserEditor } =
      await import("../src/components/UserEditor.vue");
    const { context, calls } = mockContext((_m, _p, body, key) =>
      identityFixtureResponse("identity.user_created", key, body),
    );
    const wrapper = mount(UserEditor, {
      ...options(context),
      props: {
        open: true,
        user: null,
        roles: [
          { id: "viewer", name: "Viewer", permissions: ["instances.read"] },
          { id: "custom", name: "Custom", permissions: [] },
        ],
      },
    });
    wrappers.push(wrapper);
    await flushPromises();
    await wrapper.get("input[type=text]").setValue("Restricted");
    await wrapper.get("input[type=email]").setValue("limited@example.invalid");
    await wrapper.get("input[type=password]").setValue("NeverPersist456!");
    await wrapper
      .get("textarea")
      .setValue("Create explicitly empty custom access");
    const select = wrapper.get("[role=combobox]");
    await select.trigger("keydown", { key: "ArrowDown" });
    await select.trigger("keydown", { key: "End" });
    await select.trigger("keydown", { key: "Enter" });
    await wrapper
      .findAll("button")
      .find((b) => b.text() === "取消")!
      .trigger("click");
    expect(wrapper.emitted("close")).toBeUndefined();
    expect(wrapper.text()).toContain("放弃未保存的更改");
    await wrapper.get("form").trigger("submit");
    await vi.waitFor(() => expect(calls).toHaveLength(1));
    expect(calls[0]?.body).toMatchObject({ role: "custom", permissions: [] });
  });
});

describe("live node observations", () => {
  const observation = {
    protocol: "aster.node.instance/1",
    node_id: instance.node_id,
    instance_id: instance.id,
    owner_ref: instance.owner_ref,
    hostname: instance.hostname,
    state: "shutoff",
    ipv4: "192.0.2.25",
    mac: "02:00:00:00:00:25",
    observed_at: "2026-10-22T01:00:00Z",
    source_fenced: true,
    target_pending: true,
  };
  it("makes no automatic request, then reads only on explicit click with addresses, time and fencing", async () => {
    const { default: Panel } =
      await import("../src/components/InstanceObservationPanel.vue");
    const resolver = vi.fn(() => ({ observation }));
    const { context, calls } = mockContext(resolver);
    const wrapper = mount(Panel, { ...options(context), props: { instance } });
    wrappers.push(wrapper);
    expect(resolver).not.toHaveBeenCalled();
    expect(wrapper.text()).toContain("未确认");
    await wrapper.get("button").trigger("click");
    await flushPromises();
    expect(resolver).toHaveBeenCalledOnce();
    expect(resolver.mock.calls[0]).toEqual([
      "GET",
      `/instances/${instance.id}/observation`,
      undefined,
      "",
    ]);
    expect(wrapper.text()).toContain("192.0.2.25");
    expect(wrapper.text()).toContain("02:00:00:00:00:25");
    expect(wrapper.text()).toContain("采样时间");
    expect(wrapper.text()).toContain("源实例已隔离");
    expect(wrapper.text()).toContain("目标实例尚未激活");
    expect(wrapper.text()).not.toContain("SSH");
    expect(calls).toHaveLength(0);
  });
  it("a failed second read clears the previous observation; cached state is not substituted", async () => {
    const { default: Panel } =
      await import("../src/components/InstanceObservationPanel.vue");
    let first = true;
    const { context } = mockContext(() => {
      if (first) {
        first = false;
        return { observation };
      }
      throw new ApiError("conflict");
    });
    const wrapper = mount(Panel, { ...options(context), props: { instance } });
    wrappers.push(wrapper);
    await wrapper.get("button").trigger("click");
    await flushPromises();
    expect(wrapper.text()).toContain("192.0.2.25");
    await wrapper.get("button").trigger("click");
    await flushPromises();
    expect(wrapper.text()).toContain("未确认");
    expect(wrapper.text()).not.toContain("192.0.2.25");
    expect(wrapper.findComponent(StatusBadge).exists()).toBe(false);
    expect(wrapper.find("[role=alert]").exists()).toBe(true);
  });
  it.each(["protocol", "instance_id", "node_id", "owner_ref", "hostname"])(
    "rejects an observation bound to the wrong %s",
    async (field) => {
      const { default: Panel } =
        await import("../src/components/InstanceObservationPanel.vue");
      const { context } = mockContext(() => ({
        observation: { ...observation, [field]: "wrong" },
      }));
      const wrapper = mount(Panel, {
        ...options(context),
        props: { instance },
      });
      wrappers.push(wrapper);
      await wrapper.get("button").trigger("click");
      await flushPromises();
      expect(wrapper.text()).toContain("未确认");
      expect(wrapper.text()).not.toContain("192.0.2.25");
      expect(wrapper.findComponent(StatusBadge).exists()).toBe(false);
    },
  );
  it("drops a late observation after the account is invalidated", async () => {
    const { deferred } = await import("./helpers");
    const request = deferred<unknown>();
    const { default: Panel } =
      await import("../src/components/InstanceObservationPanel.vue");
    const { context } = mockContext(() => request.promise);
    const wrapper = mount(Panel, { ...options(context), props: { instance } });
    wrappers.push(wrapper);
    await wrapper.get("button").trigger("click");
    context.session.invalidate();
    request.resolve({ observation });
    await flushPromises();
    expect(wrapper.text()).toContain("未确认");
    expect(wrapper.text()).not.toContain("192.0.2.25");
  });
});

describe("four-phase migration", () => {
  it.each([
    ["prepared", "migrate_transfer"],
    ["transferred", "migrate_import"],
    ["imported", "migrate_activate"],
  ] as const)(
    "%s only creates %s and never runs the next phase automatically",
    async (phase, action) => {
      const migration = {
        id: "9".repeat(32),
        instance_id: instance.id,
        source_node_id: "node-a",
        target_node_id: "node-b",
        phase,
        created_at: instance.created_at,
        updated_at: instance.updated_at,
      };
      const { context, calls } = mockContext((method, _path, _body, key) =>
        method === "GET"
          ? { items: [node], next_cursor: null }
          : {
              operation: {
                ...operation,
                id: key,
                action,
                artifact_id: migration.id,
              },
            },
      );
      const wrapper = mount(MigrationWizard, {
        ...options(context),
        props: { open: false, instance, migrations: [migration] },
      });
      wrappers.push(wrapper);
      await wrapper.setProps({ open: true });
      await flushPromises();
      expect(wrapper.findAll(".wizard-steps li")).toHaveLength(4);
      await wrapper.get("input").setValue(instance.id);
      await wrapper
        .findAll("button")
        .find((b) => b.text() === "创建本阶段任务")!
        .trigger("click");
      await vi.waitFor(() => expect(calls).toHaveLength(1));
      await flushPromises();
      expect(calls[0]?.body).toEqual({
        action,
        confirmation: instance.id,
        artifact_id: migration.id,
      });
      expect(calls.some((c) => /dispatch|reconcile/.test(c.path))).toBe(false);
    },
  );
});

describe("task progress controls", () => {
  it("supports explicit reconcile in sending, dispatched and uncertain, without dispatching them again", async () => {
    const { default: OperationsPage } =
      await import("../src/pages/OperationsPage.vue");
    const { createRouter, createMemoryHistory } = await import("vue-router");
    const ops = ["sending", "dispatched", "uncertain", "accepted"].map(
      (state, index) => ({
        ...operation,
        id: String(index + 1).repeat(32),
        state,
      }),
    );
    const reads: string[] = [];
    const { context, calls } = mockContext((method, path, _body, key) => {
      if (method === "GET") {
        reads.push(path);
        return path === "/operations"
          ? { items: ops, next_cursor: null }
          : { operation: ops[0] };
      }
      return { operation: { ...ops[0], id: key, state: "dispatched" } };
    });
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [{ path: "/", component: { template: "<div/>" } }],
    });
    await router.push("/");
    await router.isReady();
    const config = options(context);
    const wrapper = mount(OperationsPage, {
      ...config,
      global: { ...config.global, plugins: [router] },
    });
    wrappers.push(wrapper);
    await flushPromises();
    expect(
      wrapper.findAll("button").filter((b) => b.text() === "核对进度"),
    ).toHaveLength(2);
    expect(
      wrapper.findAll("button").filter((b) => b.text() === "核对结果"),
    ).toHaveLength(1);
    expect(
      wrapper.findAll("button").filter((b) => b.text() === "派发任务"),
    ).toHaveLength(1);
    await wrapper
      .findAll("button")
      .find((b) => b.text() === "读取状态")!
      .trigger("click");
    await flushPromises();
    expect(reads).toContain(`/operations/${ops[0]!.id}`);
    expect(calls).toHaveLength(0);
    await wrapper
      .findAll("button")
      .find((b) => b.text() === "核对进度")!
      .trigger("click");
    await flushPromises();
    const dialog = wrapper.get("[role=dialog]");
    await dialog.get("input").setValue(ops[0]!.id);
    await dialog
      .findAll("button")
      .find((b) => b.text() === "核对进度")!
      .trigger("click");
    await vi.waitFor(() => expect(calls).toHaveLength(1));
    expect(calls[0]).toMatchObject({
      path: `/operations/${ops[0]!.id}/reconcile`,
      body: {},
      key: ops[0]!.id,
    });
    expect(calls.some((c) => c.path.endsWith("/dispatch"))).toBe(false);
  });
});

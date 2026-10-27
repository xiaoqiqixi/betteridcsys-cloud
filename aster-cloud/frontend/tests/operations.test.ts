import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mount, flushPromises, DOMWrapper } from "@vue/test-utils";
import {
  createRouter,
  createMemoryHistory,
  createWebHashHistory,
  RouterLink,
} from "vue-router";
import { webcrypto } from "node:crypto";
import OperationsPage from "../src/pages/OperationsPage.vue";
import InstanceDetailPage from "../src/pages/InstanceDetailPage.vue";
import OperationDetailPage from "../src/pages/OperationDetailPage.vue";
import OperationActions from "../src/components/OperationActions.vue";
import ActionDialog from "../src/components/ActionDialog.vue";
import CreateInstanceDialog from "../src/components/CreateInstanceDialog.vue";
import MigrationWizard from "../src/components/MigrationWizard.vue";
import { ApiError } from "../src/api/client";
import type { Operation } from "../src/api/types";
import { consoleKey } from "../src/context";
import { instance, operation, node, resources } from "./fixtures";
import { mockContext, deferred } from "./helpers";

const cleanups: Array<() => void> = [];
beforeEach(() => {
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
async function routing(path = "/operations") {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: "/operations", component: { template: "<div />" } },
      { path: "/operations/:id", component: { template: "<div />" } },
      { path: "/instances/:id", component: { template: "<div />" } },
    ],
  });
  await router.push(path);
  await router.isReady();
  return router;
}
function provided(context: ReturnType<typeof mockContext>["context"]) {
  return {
    attachTo: document.body,
    global: {
      provide: { [consoleKey as symbol]: context },
      stubs: { teleport: true },
    },
  };
}
async function detailFixture(
  resolver: Parameters<typeof mockContext>[0],
  path = `/operations/${operation.id}`,
) {
  const reads: string[] = [];
  const result = mockContext((method, target, body, key) => {
    if (method === "GET") reads.push(target);
    return resolver(method, target, body, key);
  });
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: "/operations", component: OperationsPage },
      { path: "/operations/:id", component: OperationDetailPage },
      { path: "/instances/:id", component: { template: "<div />" } },
      { path: "/audit", component: { template: "<div />" } },
    ],
  });
  await router.push(path);
  await router.isReady();
  const config = provided(result.context);
  const wrapper = mount(
    { template: "<RouterView />" },
    { ...config, global: { ...config.global, plugins: [router] } },
  );
  cleanups.push(() => wrapper.unmount());
  await flushPromises();
  return { ...result, router, wrapper, reads };
}
function byText(
  wrapper: { findAll(selector: string): DOMWrapper<Element>[] },
  text: string,
) {
  const button = wrapper
    .findAll("button")
    .find((value) => value.text() === text);
  expect(button, `button ${text}`).toBeDefined();
  return button!;
}

describe("precise operation navigation", () => {
  it("finds a task by exact lowercase ID without treating it as a new mutation", async () => {
    const reads: string[] = [];
    const { context, calls } = mockContext((method, path) => {
      if (method === "GET") reads.push(path);
      return { items: [operation], next_cursor: null };
    });
    const router = await routing();
    const config = provided(context);
    const wrapper = mount(OperationsPage, {
      ...config,
      global: { ...config.global, plugins: [router] },
    });
    cleanups.push(() => wrapper.unmount());
    await flushPromises();
    const input = wrapper.get('input[aria-label="任务 ID"]');
    await input.setValue(operation.id.toUpperCase());
    await wrapper.get("form").trigger("submit");
    expect(wrapper.get('[role="alert"]').text()).toContain("32");
    expect(router.currentRoute.value.path).toBe("/operations");
    expect(reads).toEqual(["/operations"]);
    await input.setValue(operation.id);
    await wrapper.get("form").trigger("submit");
    await flushPromises();
    expect(router.currentRoute.value.path).toBe(`/operations/${operation.id}`);
    expect(calls).toHaveLength(0);
    expect(wrapper.get(".operation-reference").attributes("href")).toBe(
      `/operations/${operation.id}`,
    );
  });
  it("preserves the operation ID when leaving an instance task tab", async () => {
    const { context, calls } = mockContext((_method, path) =>
      path === "/nodes"
        ? { items: [], next_cursor: null }
        : { instance, operations: [operation], artifacts: [], migrations: [] },
    );
    const router = await routing(`/instances/${instance.id}`);
    const config = provided(context);
    const wrapper = mount(InstanceDetailPage, {
      ...config,
      global: { ...config.global, plugins: [router] },
    });
    cleanups.push(() => wrapper.unmount());
    await flushPromises();
    await wrapper
      .findAll('[role="tab"]')
      .find((tab) => tab.text() === "任务")!
      .trigger("click");
    expect(wrapper.get(".compact-row").attributes("href")).toBe(
      `/operations/${operation.id}`,
    );
    expect(calls).toHaveLength(0);
  });
});

describe("bound operation details", () => {
  it.each(["bad", "D".repeat(32), "a".repeat(31), "a".repeat(33)])(
    "does not make a request for invalid route ID %s",
    async (id) => {
      const { wrapper, reads, calls } = await detailFixture(() => {
        throw new Error("invalid IDs must never reach transport");
      }, `/operations/${id}`);
      expect(wrapper.get('[role="alert"]').text()).toContain("任务编号无效");
      expect(reads).toHaveLength(0);
      expect(calls).toHaveLength(0);
    },
  );
  it("reads only the exact task and displays public identifiers and creator, never guest readiness", async () => {
    const { wrapper, reads, calls } = await detailFixture(() => ({
      operation,
    }));
    expect(reads).toEqual([`/operations/${operation.id}`]);
    expect(calls).toHaveLength(0);
    expect(wrapper.text()).toContain("任务详情");
    expect(wrapper.text()).toContain(operation.id);
    expect(wrapper.text()).toContain(operation.actor_id);
    expect(wrapper.text()).toContain("创建者不一定是实际派发");
    expect(wrapper.text()).toContain("等待明确派发");
    expect(wrapper.get(`a[href="/audit?target=${operation.id}"]`).text()).toBe(
      "查看相关审计",
    );
    expect(wrapper.text()).not.toMatch(
      /SSH.*就绪|request_json|profile_sha|fence_token/,
    );
    await byText(wrapper, "读取状态").trigger("click");
    await flushPromises();
    expect(reads).toEqual([
      `/operations/${operation.id}`,
      `/operations/${operation.id}`,
    ]);
    expect(calls).toHaveLength(0);
  });
  it("hides related audit from members without audit.read and preserves the exact target in English", async () => {
    const { wrapper, context, calls } = await detailFixture(() => ({
      operation,
    }));
    context.prefs.locale.value = "en";
    await flushPromises();
    expect(wrapper.get(`a[href="/audit?target=${operation.id}"]`).text()).toBe(
      "View related audit",
    );
    context.session.user.value = {
      ...context.session.user.value!,
      role: "viewer",
      permissions: ["instances.read"],
    };
    await flushPromises();
    expect(wrapper.find('a[href^="/audit"]').exists()).toBe(false);
    expect(calls).toHaveLength(0);
  });
  it("rejects a valid DTO for the wrong task ID without rendering its content", async () => {
    const wrong = {
      ...operation,
      id: "f".repeat(32),
      node_id: "wrong-private-target",
    };
    const { wrapper, calls } = await detailFixture(() => ({
      operation: wrong,
    }));
    expect(wrapper.find('[role="alert"]').exists()).toBe(true);
    expect(wrapper.text()).not.toContain(wrong.node_id);
    expect(wrapper.text()).toContain("不代表节点未执行");
    expect(wrapper.findComponent(OperationActions).exists()).toBe(false);
    expect(calls).toHaveLength(0);
  });
  it.each([
    new ApiError("invalid", "NOT_FOUND", 404),
    new ApiError("forbidden", "FORBIDDEN", 403),
    new ApiError("unavailable", "DEPENDENCY_UNAVAILABLE", 503),
    new ApiError("network"),
  ])(
    "keeps an unreadable task unknown rather than offering a replacement ($kind/$status)",
    async (error) => {
      const { wrapper, reads, calls } = await detailFixture(() => {
        throw error;
      });
      expect(wrapper.find('[role="alert"]').exists()).toBe(true);
      expect(wrapper.text()).toContain("不要重复派发");
      expect(wrapper.findComponent(OperationActions).exists()).toBe(false);
      expect(reads).toHaveLength(1);
      expect(calls).toHaveLength(0);
    },
  );
  it("cannot commit a late response from the previous task route", async () => {
    const old = deferred<{ operation: Operation }>();
    const next = { ...operation, id: "e".repeat(32), node_id: "new-node" };
    const { wrapper, router, calls } = await detailFixture((_method, path) =>
      path === `/operations/${operation.id}`
        ? old.promise
        : { operation: next },
    );
    expect(wrapper.get('[role="status"]').text()).toContain("正在加载");
    await router.push(`/operations/${next.id}`);
    await flushPromises();
    expect(wrapper.text()).toContain("new-node");
    old.resolve({
      operation: { ...operation, node_id: "old-node-must-not-return" },
    });
    await flushPromises();
    expect(wrapper.text()).not.toContain("old-node-must-not-return");
    expect(wrapper.get(".task-reference").text()).toBe(next.id);
    expect(calls).toHaveLength(0);
  });
  it("drops a late task response after identity invalidation", async () => {
    const slow = deferred<{ operation: Operation }>();
    const { wrapper, context, calls } = await detailFixture(() => slow.promise);
    context.session.invalidate();
    await flushPromises();
    slow.resolve({
      operation: { ...operation, node_id: "previous-account-node" },
    });
    await flushPromises();
    expect(wrapper.text()).not.toContain("previous-account-node");
    expect(wrapper.findComponent(OperationActions).exists()).toBe(false);
    expect(calls).toHaveLength(0);
  });
  it("revokes an open write confirmation when live action grants change", async () => {
    const { wrapper, context, calls } = await detailFixture(() => ({
      operation,
    }));
    await byText(wrapper, "派发任务").trigger("click");
    expect(wrapper.find('[role="dialog"]').exists()).toBe(true);
    context.session.user.value = {
      ...context.session.user.value!,
      role: "custom",
      permissions: ["instances.read"],
    };
    context.session.epoch.value++;
    await flushPromises();
    expect(wrapper.find('[role="dialog"]').exists()).toBe(false);
    expect(
      wrapper.findAll("button").some((value) => value.text() === "派发任务"),
    ).toBe(false);
    expect(calls).toHaveLength(0);
  });
});

describe("one shared operation action contract", () => {
  it.each(["sending", "dispatched", "uncertain"])(
    "allows only explicit reconcile for %s",
    async (state) => {
      const op = { ...operation, state };
      const { wrapper, calls } = await detailFixture(() => ({ operation: op }));
      expect(
        wrapper.findAll("button").some((value) => value.text() === "派发任务"),
      ).toBe(false);
      const label = state === "uncertain" ? "核对结果" : "核对进度";
      expect(byText(wrapper, label).exists()).toBe(true);
      expect(calls).toHaveLength(0);
    },
  );
  it.each(["succeeded", "rejected", "Succeeded", "new-unconfirmed-state"])(
    "does not offer a write for %s",
    async (state) => {
      const { wrapper, calls } = await detailFixture(() => ({
        operation: { ...operation, state },
      }));
      expect(
        wrapper.findAll("button").map((value) => value.text()),
      ).not.toContain("派发任务");
      expect(
        wrapper.findAll("button").map((value) => value.text()),
      ).not.toContain("核对进度");
      expect(
        wrapper.findAll("button").map((value) => value.text()),
      ).not.toContain("核对结果");
      if (state === "Succeeded")
        expect(wrapper.get(".status-badge").classes()).not.toContain(
          "tone-good",
        );
      expect(calls).toHaveLength(0);
    },
  );
  it("requires the task ID, uses its immutable key and stops at the acknowledged state", async () => {
    const { wrapper, calls, context } = await detailFixture((method) => ({
      operation:
        method === "GET" ? operation : { ...operation, state: "dispatched" },
    }));
    const write = vi.spyOn(context.api, "write");
    await byText(wrapper, "派发任务").trigger("click");
    const dialog = wrapper.get('[role="dialog"]');
    await dialog.get("input").setValue(instance.id);
    expect(byText(dialog, "确认派发").attributes("disabled")).toBeDefined();
    await dialog.get("input").setValue(operation.id);
    await byText(dialog, "确认派发").trigger("click");
    await vi.waitFor(() => expect(calls).toHaveLength(1));
    await flushPromises();
    expect(calls[0]).toMatchObject({
      method: "POST",
      path: `/operations/${operation.id}/dispatch`,
      body: {},
      key: operation.id,
    });
    expect(write.mock.calls[0]?.[5]).toBe(202);
    expect(wrapper.find('[role="dialog"]').exists()).toBe(false);
    expect(wrapper.get(".status-badge").text()).toBe("已派发");
    expect(context.notify).not.toHaveBeenCalledWith("任务已完成。");
  });
  it("does not repeat an unknown dispatch across close/reopen and links the original task", async () => {
    const op = { ...operation, id: "1".repeat(32) };
    const { wrapper, calls } = await detailFixture((method) => {
      if (method !== "GET") throw new ApiError("unknown");
      return { operation: op };
    }, `/operations/${op.id}`);
    async function dispatch() {
      await byText(wrapper, "派发任务").trigger("click");
      const dialog = wrapper.get('[role="dialog"]');
      await dialog.get("input").setValue(op.id);
      await byText(dialog, "确认派发").trigger("click");
      await vi.waitFor(() =>
        expect(
          wrapper.get('[role="dialog"]').find('[role="alert"]').exists(),
        ).toBe(true),
      );
      return wrapper.get('[role="dialog"]');
    }
    let dialog = await dispatch();
    expect(calls).toHaveLength(1);
    expect(byText(dialog, "读取原任务").element.tagName).toBe("BUTTON");
    expect(dialog.get('[role="alert"]').text()).toContain(op.id);
    await byText(dialog, "取消").trigger("click");
    await byText(wrapper, "读取状态").trigger("click");
    await flushPromises();
    dialog = await dispatch();
    expect(calls).toHaveLength(1);
    expect(dialog.text()).toContain(op.id);
  });
  it.each([
    "id",
    "instance_id",
    "node_id",
    "action",
    "artifact_id",
    "target_node_id",
    "actor_id",
  ] as const)("keeps a mismatched %s ACK unknown", async (field) => {
    const index = [
      "id",
      "instance_id",
      "node_id",
      "action",
      "artifact_id",
      "target_node_id",
      "actor_id",
    ].indexOf(field);
    const op = { ...operation, id: (index + 8).toString(16).repeat(32) };
    const { wrapper, calls, context } = await detailFixture(
      (method) => ({
        operation:
          method === "GET"
            ? op
            : {
                ...op,
                [field]: field === "action" ? "delete" : "f".repeat(32),
                state: "succeeded",
              },
      }),
      `/operations/${op.id}`,
    );
    await byText(wrapper, "派发任务").trigger("click");
    const dialog = wrapper.get('[role="dialog"]');
    await dialog.get("input").setValue(op.id);
    await byText(dialog, "确认派发").trigger("click");
    await vi.waitFor(() => expect(calls).toHaveLength(1));
    await flushPromises();
    expect(
      wrapper.get('[role="dialog"]').get('[role="alert"]').text(),
    ).toContain("结果尚未确认");
    expect(wrapper.get(".status-badge").text()).toBe("已受理");
    expect(context.notify).not.toHaveBeenCalled();
  });
  it("rechecks the latest task state before an open confirmation can dispatch", async () => {
    const { context, calls } = mockContext(() => ({ operation }));
    const router = await routing();
    const config = provided(context);
    const wrapper = mount(OperationActions, {
      ...config,
      props: { operation },
      global: { ...config.global, plugins: [router] },
    });
    cleanups.push(() => wrapper.unmount());
    await byText(wrapper, "派发任务").trigger("click");
    await wrapper.setProps({
      operation: { ...operation, state: "dispatched" },
    });
    await flushPromises();
    expect(wrapper.find('[role="dialog"]').exists()).toBe(false);
    expect(
      wrapper.findAll("button").map((button) => button.text()),
    ).not.toContain("派发任务");
    expect(calls).toHaveLength(0);
    await byText(wrapper, "核对进度").trigger("click");
    expect(wrapper.get('[role="dialog"]').get("input").element.value).toBe("");
    expect(calls).toHaveLength(0);
  });
  it("allows another explicit unknown-result reconcile only with the same original ID", async () => {
    const op = { ...operation, id: "3".repeat(32), state: "uncertain" };
    let attempts = 0;
    const { wrapper, calls } = await detailFixture((method) => {
      if (method === "GET") return { operation: op };
      if (++attempts === 1) throw new ApiError("unknown");
      return { operation: op };
    }, `/operations/${op.id}`);
    await byText(wrapper, "核对结果").trigger("click");
    await wrapper.get('[role="dialog"]').get("input").setValue(op.id);
    await byText(wrapper.get('[role="dialog"]'), "核对进度").trigger("click");
    await vi.waitFor(() =>
      expect(
        wrapper.get('[role="dialog"]').find('[role="alert"]').exists(),
      ).toBe(true),
    );
    expect(calls).toHaveLength(1);
    await byText(wrapper.get('[role="dialog"]'), "核对进度").trigger("click");
    await vi.waitFor(() =>
      expect(wrapper.find('[role="dialog"]').exists()).toBe(false),
    );
    expect(calls).toHaveLength(2);
    for (const call of calls)
      expect(call).toMatchObject({
        path: `/operations/${op.id}/reconcile`,
        body: {},
        key: op.id,
      });
    expect(calls.some((call) => call.path.endsWith("/dispatch"))).toBe(false);
  });
});

describe("original-task links from admission acknowledgements", () => {
  it.each([
    ["action", "accepted"],
    ["action", "unknown"],
    ["creation", "accepted"],
    ["creation", "unknown"],
    ["migration", "accepted"],
    ["migration", "unknown"],
  ] as const)(
    "links the exact %s %s task without dispatching",
    async (kind, outcome) => {
      const migrationID = "4".repeat(32);
      const action =
        kind === "action"
          ? "start"
          : kind === "creation"
            ? "create"
            : "migrate_transfer";
      const { context, calls } = mockContext((method, path, _body, key) => {
        if (method === "GET")
          return path === "/presets"
            ? { items: [{ id: "approved-main", node_id: node.id, resources }] }
            : { items: [node], next_cursor: null };
        if (outcome === "unknown") throw new ApiError("unknown");
        return {
          operation: {
            ...operation,
            id: key,
            instance_id: kind === "creation" ? key : instance.id,
            action,
            artifact_id: kind === "migration" ? migrationID : "",
          },
        };
      });
      const router = await routing();
      const config = provided(context);
      const global = { ...config.global, plugins: [router] };
      const wrapper =
        kind === "action"
          ? mount(ActionDialog, {
              ...config,
              global,
              props: { open: false, instance, action: "start" },
            })
          : kind === "creation"
            ? mount(CreateInstanceDialog, {
                ...config,
                global,
                props: { open: false },
              })
            : mount(MigrationWizard, {
                ...config,
                global,
                props: {
                  open: false,
                  instance,
                  migrations: [
                    {
                      id: migrationID,
                      instance_id: instance.id,
                      source_node_id: instance.node_id,
                      target_node_id: node.id,
                      phase: "prepared",
                      created_at: operation.created_at,
                      updated_at: operation.updated_at,
                    },
                  ],
                },
              });
      cleanups.push(() => wrapper.unmount());
      await wrapper.setProps({ open: true });
      await flushPromises();
      if (kind === "creation") {
        await wrapper.get('[role="combobox"]').trigger("click");
        await wrapper.get('[role="option"]').trigger("pointerdown");
        const inputs = wrapper.findAll("input");
        await inputs[0]!.setValue("new-server");
        await inputs[1]!.setValue(instance.owner_ref);
        await wrapper.get("form").trigger("submit");
      } else {
        await wrapper.get("input").setValue(instance.id);
        await byText(
          wrapper,
          kind === "action" ? "创建任务" : "创建本阶段任务",
        ).trigger("click");
      }
      await vi.waitFor(() =>
        expect(wrapper.find("a.task-link").exists()).toBe(true),
      );
      expect(calls).toHaveLength(1);
      expect(
        wrapper
          .findAllComponents(RouterLink)
          .find((link) => link.classes().includes("task-link"))
          ?.props("replace"),
      ).toBe(true);
      expect(wrapper.get("a.task-link").attributes("href")).toBe(
        `/operations/${calls[0]!.key}`,
      );
      expect(
        calls.some((call) => /\/dispatch$|\/reconcile$/.test(call.path)),
      ).toBe(false);
      if (outcome === "unknown")
        expect(wrapper.get('[role="alert"]').text()).toContain("结果尚未确认");
    },
  );
});

// This is jsdom's real hash history, not a mock of history.back. It reproduces
// the overlay-owned entry that task links must replace before route unmount.
describe("original-task overlay history", () => {
  it.each(["accepted", "unknown"] as const)(
    "replaces the %s overlay entry and needs exactly one Back per earlier page",
    async (outcome) => {
      vi.mocked(history.back).mockRestore();
      history.replaceState(null, "", "/#/nodes");
      const routeHistory = createWebHashHistory();
      cleanups.push(() => routeHistory.destroy());
      const router = createRouter({
        history: routeHistory,
        routes: [
          { path: "/nodes", component: { template: "<h1>Nodes</h1>" } },
          { path: "/instances/:id", component: InstanceDetailPage },
          { path: "/instances", component: { template: "<div />" } },
          { path: "/operations/:id", component: OperationDetailPage },
          { path: "/operations", component: OperationsPage },
          { path: "/audit", component: { template: "<div />" } },
        ],
      });
      let task: Operation | undefined;
      const { context, calls } = mockContext((method, path, _body, key) => {
        if (method === "POST") {
          task = { ...operation, id: key };
          if (outcome === "unknown") throw new ApiError("unknown");
          return { operation: task };
        }
        if (path.startsWith("/operations/")) return { operation: task };
        if (path === "/nodes") return { items: [], next_cursor: null };
        return { instance, operations: [], artifacts: [], migrations: [] };
      });
      context.session.user.value = {
        ...context.session.user.value!,
        id: (outcome === "accepted" ? "7" : "8").repeat(32),
      };
      await router.push("/nodes");
      await router.isReady();
      const host = document.createElement("div");
      host.id = "app";
      document.body.append(host);
      const wrapper = mount(
        { template: "<RouterView />" },
        {
          attachTo: host,
          global: {
            provide: { [consoleKey as symbol]: context },
            plugins: [router],
          },
        },
      );
      cleanups.push(() => wrapper.unmount());
      await router.push(`/instances/${instance.id}`);
      await flushPromises();
      const beforeOverlay = history.length;
      await byText(wrapper, "启动").trigger("click");
      await flushPromises();
      expect(history.length).toBe(beforeOverlay + 1);
      const dialog = () => mountlessDialog();
      function mountlessDialog() {
        const element = document.querySelector('[role="dialog"]');
        expect(element).not.toBeNull();
        return new DOMWrapper(element!);
      }
      await dialog().get("input").setValue(instance.id);
      await byText(dialog(), "创建任务").trigger("click");
      await vi.waitFor(() =>
        expect(document.querySelector("a.task-link")).not.toBeNull(),
      );
      expect(calls).toHaveLength(1);
      const originalID = calls[0]!.key;
      await dialog().get("a.task-link").trigger("click");
      await flushPromises();
      expect(router.currentRoute.value.path).toBe(`/operations/${originalID}`);
      expect(location.hash).toBe(`#/operations/${originalID}`);
      expect(history.length).toBe(beforeOverlay + 1);
      expect(history.state.asterOverlay).toBeUndefined();
      expect(history.state.current).toBe(`/operations/${originalID}`);
      expect(host.inert).toBe(false);
      expect(document.querySelector('[role="dialog"]')).toBeNull();
      expect(calls).toHaveLength(1);
      async function backOnce() {
        await new Promise<void>((resolve, reject) => {
          const pop = () => {
            clearTimeout(timer);
            window.removeEventListener("popstate", pop);
            resolve();
          };
          const timer = setTimeout(() => {
            window.removeEventListener("popstate", pop);
            reject(new Error("Expected actual popstate from one history.back"));
          }, 1000);
          window.addEventListener("popstate", pop);
          history.back();
        });
        await flushPromises();
      }
      await backOnce();
      expect(router.currentRoute.value.path).toBe(`/instances/${instance.id}`);
      expect(location.hash).toBe(`#/instances/${instance.id}`);
      await backOnce();
      expect(router.currentRoute.value.path).toBe("/nodes");
      expect(location.hash).toBe("#/nodes");
      expect(calls).toHaveLength(1);
    },
  );
});

describe("cross-creator task recovery in the actual shared controls", () => {
  it("an operator reads away their lost dispatch ACK and explicitly reconciles the admin-created task", async () => {
    const op = { ...operation, id: "7".repeat(32) };
    let state = "accepted";
    const { wrapper, context, calls } = await detailFixture((method, path) => {
      if (method === "GET") return { operation: { ...op, state } };
      if (path.endsWith("/dispatch")) {
        state = "uncertain";
        throw new ApiError("unknown");
      }
      return { operation: { ...op, state: "dispatched" } };
    }, `/operations/${op.id}`);
    const requester = "9".repeat(32);
    context.session.user.value = {
      ...context.session.user.value!,
      id: requester,
      role: "operator",
    };
    context.session.epoch.value++;
    await flushPromises();
    const pendingEntries = () =>
      (
        JSON.parse(
          sessionStorage.getItem("aster.cloud.pending.v1") || "[]",
        ) as Array<{
          owner: string;
          key: string;
          binding: { actor_id: string };
        }>
      ).filter((entry) => entry.owner === requester && entry.key === op.id);
    await byText(wrapper, "派发任务").trigger("click");
    await wrapper.get('[role="dialog"]').get("input").setValue(op.id);
    await byText(wrapper.get('[role="dialog"]'), "确认派发").trigger("click");
    await vi.waitFor(() =>
      expect(
        wrapper.get('[role="dialog"]').find('[role="alert"]').exists(),
      ).toBe(true),
    );
    expect(calls).toHaveLength(1);
    expect(pendingEntries()).toHaveLength(1);
    expect(pendingEntries()[0]?.binding.actor_id).toBe(op.actor_id);
    expect(op.actor_id).not.toBe(requester);
    await byText(wrapper.get('[role="dialog"]'), "取消").trigger("click");
    await byText(wrapper, "读取状态").trigger("click");
    await flushPromises();
    expect(calls).toHaveLength(1);
    expect(pendingEntries()).toEqual([]);
    expect(wrapper.get(".status-badge").text()).toBe("待核实");
    await byText(wrapper, "核对结果").trigger("click");
    await wrapper.get('[role="dialog"]').get("input").setValue(op.id);
    await byText(wrapper.get('[role="dialog"]'), "核对进度").trigger("click");
    await vi.waitFor(() =>
      expect(wrapper.find('[role="dialog"]').exists()).toBe(false),
    );
    expect(calls.map((call) => [call.path, call.key])).toEqual([
      [`/operations/${op.id}/dispatch`, op.id],
      [`/operations/${op.id}/reconcile`, op.id],
    ]);
    expect(wrapper.get(".status-badge").text()).toBe("已派发");
    expect(pendingEntries()).toEqual([]);
  });
  it("keeps a transfer's legitimate accepted ACK pending until an explicit original-task read proves progress", async () => {
    const op = {
      ...operation,
      id: "81".repeat(16),
      action: "migrate_transfer",
      artifact_id: "6".repeat(32),
      target_node_id: "node-b",
    };
    let state = "accepted";
    const { wrapper, calls } = await detailFixture(
      () => ({ operation: { ...op, state } }),
      `/operations/${op.id}`,
    );
    await byText(wrapper, "派发任务").trigger("click");
    await wrapper.get('[role="dialog"]').get("input").setValue(op.id);
    await byText(wrapper.get('[role="dialog"]'), "确认派发").trigger("click");
    await vi.waitFor(() =>
      expect(
        wrapper.get('[role="dialog"]').find('[role="alert"]').exists(),
      ).toBe(true),
    );
    const dialog = wrapper.get('[role="dialog"]');
    expect(dialog.get('[role="alert"]').text()).toContain("结果尚未确认");
    expect(dialog.get('[role="alert"]').text()).not.toContain("连接失败");
    expect(byText(dialog, "读取原任务").element.tagName).toBe("BUTTON");
    expect(dialog.get('[role="alert"]').text()).toContain(op.id);
    expect(byText(dialog, "确认派发").attributes("disabled")).toBeDefined();
    expect(calls).toHaveLength(1);
    await byText(dialog, "取消").trigger("click");
    await byText(wrapper, "读取状态").trigger("click");
    await flushPromises();
    await byText(wrapper, "派发任务").trigger("click");
    await wrapper.get('[role="dialog"]').get("input").setValue(op.id);
    // Native WebCrypto does not settle with Vue's/JS promises. Hold the second
    // intent hash to reproduce the CI busy state, then await the actual UI
    // outcome instead of assuming flushPromises completed the digest.
    const computeDigest = crypto.subtle.digest.bind(crypto.subtle),
      heldDigest = deferred<ArrayBuffer>(),
      digest = vi
        .spyOn(crypto.subtle, "digest")
        .mockReturnValueOnce(heldDigest.promise);
    await byText(wrapper.get('[role="dialog"]'), "确认派发").trigger("click");
    await flushPromises();
    expect(digest).toHaveBeenCalledOnce();
    const hashingDialog = wrapper.get('[role="dialog"]');
    expect(byText(hashingDialog, "确认派发").attributes("aria-busy")).toBe(
      "true",
    );
    expect(hashingDialog.get("input").attributes("disabled")).toBeDefined();
    expect(hashingDialog.find('[role="alert"]').exists()).toBe(false);
    expect(calls).toHaveLength(1);
    const [algorithm, bytes] = digest.mock.calls[0]!;
    heldDigest.resolve(await computeDigest(algorithm, bytes));
    await vi.waitFor(() => {
      const repeatedDialog = wrapper.get('[role="dialog"]');
      expect(repeatedDialog.get('[role="alert"]').text()).toContain(
        "结果尚未确认",
      );
      expect(
        byText(repeatedDialog, "确认派发").attributes("aria-busy"),
      ).toBeUndefined();
    });
    digest.mockRestore();
    expect(calls).toHaveLength(1);
    expect(
      wrapper.get('[role="dialog"]').get('[role="alert"]').text(),
    ).toContain("结果尚未确认");
    await byText(wrapper.get('[role="dialog"]'), "取消").trigger("click");
    state = "sending";
    await byText(wrapper, "读取状态").trigger("click");
    await flushPromises();
    expect(calls).toHaveLength(1);
    expect(byText(wrapper, "核对进度").exists()).toBe(true);
    expect(
      wrapper.findAll("button").some((button) => button.text() === "派发任务"),
    ).toBe(false);
  });
});

async function nextActualPopstate() {
  return new Promise<void>((resolve, reject) => {
    const pop = () => {
      clearTimeout(timer);
      window.removeEventListener("popstate", pop);
      resolve();
    };
    const timer = setTimeout(() => {
      window.removeEventListener("popstate", pop);
      reject(new Error("Expected one actual history traversal"));
    }, 1000);
    window.addEventListener("popstate", pop);
  });
}
async function pendingSelfAction(
  readResult: ReturnType<typeof deferred<unknown>>,
  id: string,
  path = `/operations/${id}`,
) {
  let reads = 0;
  const op = { ...operation, id };
  const { context, calls } = mockContext((method) => {
    if (method !== "GET") throw new ApiError("unknown");
    reads++;
    return readResult.promise;
  });
  const router = await routing(path);
  const config = provided(context);
  const wrapper = mount(OperationActions, {
    ...config,
    props: { operation: op },
    global: { ...config.global, plugins: [router] },
  });
  cleanups.push(() => {
    if (wrapper.exists()) wrapper.unmount();
  });
  await byText(wrapper, "派发任务").trigger("click");
  await wrapper.get('[role="dialog"]').get("input").setValue(id);
  await byText(wrapper.get('[role="dialog"]'), "确认派发").trigger("click");
  await vi.waitFor(() =>
    expect(wrapper.get('[role="dialog"]').find('[role="alert"]').exists()).toBe(
      true,
    ),
  );
  return { wrapper, context, calls, op, router, reads: () => reads };
}
describe("same-task unknown acknowledgement readback", () => {
  it.each(["accepted-ack", "lost-ack"] as const)(
    "reads the %s original task before closing, consumes only its own hash entry and never POSTs twice",
    async (outcome) => {
      vi.mocked(history.back).mockRestore();
      const back = vi.spyOn(history, "back");
      history.replaceState(null, "", "/#/nodes");
      const routeHistory = createWebHashHistory();
      cleanups.push(() => routeHistory.destroy());
      const router = createRouter({
        history: routeHistory,
        routes: [
          { path: "/nodes", component: { template: "<h1>Nodes</h1>" } },
          { path: "/operations", component: OperationsPage },
          { path: "/operations/:id", component: OperationDetailPage },
          { path: "/instances/:id", component: { template: "<div />" } },
          { path: "/audit", component: { template: "<div />" } },
        ],
      });
      const op = {
        ...operation,
        id: (outcome === "accepted-ack" ? "a2" : "b2").repeat(16),
        action: outcome === "accepted-ack" ? "migrate_transfer" : "start",
      };
      const result = deferred<unknown>();
      let gets = 0;
      const { context, calls } = mockContext((method) => {
        if (method === "GET") {
          gets++;
          return gets === 1 ? { operation: op } : result.promise;
        }
        if (outcome === "accepted-ack") return { operation: op };
        throw new ApiError("unknown");
      });
      await router.push("/nodes");
      await router.isReady();
      const host = document.createElement("div");
      host.id = "app";
      document.body.append(host);
      const wrapper = mount(
        { template: "<RouterView />" },
        {
          attachTo: host,
          global: {
            provide: { [consoleKey as symbol]: context },
            plugins: [router],
          },
        },
      );
      cleanups.push(() => wrapper.unmount());
      await router.push(`/operations/${op.id}`);
      await flushPromises();
      await byText(wrapper, "派发任务").trigger("click");
      await flushPromises();
      const dialog = () =>
        new DOMWrapper(document.querySelector('[role="dialog"]')!);
      await dialog().get("input").setValue(op.id);
      await byText(dialog(), "确认派发").trigger("click");
      await vi.waitFor(() =>
        expect(dialog().find('[role="alert"]').exists()).toBe(true),
      );
      expect(calls).toHaveLength(1);
      expect(dialog().find("a.pending-task-link").exists()).toBe(false);
      await byText(dialog(), "读取原任务").trigger("click");
      await flushPromises();
      expect(gets).toBe(2);
      expect(document.querySelector('[role="dialog"]')).not.toBeNull();
      expect(back).not.toHaveBeenCalled();
      const popped = nextActualPopstate();
      const state = outcome === "accepted-ack" ? "accepted" : "uncertain";
      result.resolve({ operation: { ...op, state } });
      await popped;
      await flushPromises();
      expect(document.querySelector('[role="dialog"]')).toBeNull();
      expect(router.currentRoute.value.path).toBe(`/operations/${op.id}`);
      expect(location.hash).toBe(`#/operations/${op.id}`);
      expect(history.state.asterOverlay).toBeUndefined();
      expect(host.inert).toBe(false);
      expect(back).toHaveBeenCalledTimes(1);
      expect(calls).toHaveLength(1);
      const previous = nextActualPopstate();
      history.back();
      await previous;
      await flushPromises();
      expect(router.currentRoute.value.path).toBe("/nodes");
      expect(location.hash).toBe("#/nodes");
      expect(back).toHaveBeenCalledTimes(2);
      expect(calls).toHaveLength(1);
    },
  );
  it("keeps a failed original-task read and its pending ID inside the modal", async () => {
    const read = deferred<unknown>();
    const { wrapper, calls, op, reads } = await pendingSelfAction(
      read,
      "c2".repeat(16),
    );
    await byText(wrapper.get('[role="dialog"]'), "读取原任务").trigger("click");
    read.reject(new ApiError("network"));
    await flushPromises();
    const dialog = wrapper.get('[role="dialog"]');
    expect(dialog.get('[role="alert"]').text()).toContain("连接失败");
    expect(dialog.get('[role="alert"]').text()).toContain(op.id);
    expect(byText(dialog, "确认派发").attributes("disabled")).toBeDefined();
    expect(reads()).toBe(1);
    expect(calls).toHaveLength(1);
    expect(history.back).not.toHaveBeenCalled();
  });
  it.each(["unmount", "identity"] as const)(
    "does not commit an original-task read after %s",
    async (change) => {
      const read = deferred<unknown>();
      const { wrapper, context, calls, op, reads } = await pendingSelfAction(
        read,
        (change === "unmount" ? "d2" : "e2").repeat(16),
      );
      await byText(wrapper.get('[role="dialog"]'), "读取原任务").trigger(
        "click",
      );
      expect(reads()).toBe(1);
      if (change === "unmount") wrapper.unmount();
      else context.session.invalidate();
      read.resolve({ operation: { ...op, state: "succeeded" } });
      await flushPromises();
      expect(wrapper.emitted("updated")).toBeUndefined();
      expect(context.notify).not.toHaveBeenCalled();
      expect(calls).toHaveLength(1);
    },
  );
});

describe("original-task readback binding and list navigation", () => {
  it.each(["id", "node_id", "actor_id"] as const)(
    "keeps a mismatched %s read inside the original modal without updating the task",
    async (field) => {
      const result = deferred<unknown>();
      const id = { id: "12", node_id: "22", actor_id: "32" }[field].repeat(16);
      const { wrapper, calls, op } = await pendingSelfAction(result, id);
      await byText(wrapper.get('[role="dialog"]'), "读取原任务").trigger(
        "click",
      );
      result.resolve({
        operation: { ...op, [field]: "f".repeat(32), state: "succeeded" },
      });
      await flushPromises();
      const dialog = wrapper.get('[role="dialog"]');
      expect(dialog.get('[role="alert"]').text()).toContain("无法处理请求");
      expect(dialog.get('[role="alert"]').text()).toContain(op.id);
      expect(byText(dialog, "确认派发").attributes("disabled")).toBeDefined();
      expect(wrapper.emitted("updated")).toBeUndefined();
      expect(calls).toHaveLength(1);
    },
  );
  it("retains replace navigation from the list and does not close before the new route commits", async () => {
    vi.mocked(history.back).mockRestore();
    const back = vi.spyOn(history, "back");
    history.replaceState(null, "", "/#/nodes");
    const routeHistory = createWebHashHistory();
    cleanups.push(() => routeHistory.destroy());
    const router = createRouter({
      history: routeHistory,
      routes: [
        { path: "/nodes", component: { template: "<h1>Nodes</h1>" } },
        { path: "/operations", component: OperationsPage },
        { path: "/operations/:id", component: OperationDetailPage },
        { path: "/instances/:id", component: { template: "<div />" } },
        { path: "/audit", component: { template: "<div />" } },
      ],
    });
    const op = { ...operation, id: "42".repeat(16) };
    const reads: string[] = [];
    const { context, calls } = mockContext((method, path) => {
      if (method === "GET") {
        reads.push(path);
        return path === "/operations"
          ? { items: [op], next_cursor: null }
          : { operation: { ...op, state: "uncertain" } };
      }
      throw new ApiError("unknown");
    });
    await router.push("/nodes");
    await router.isReady();
    const host = document.createElement("div");
    host.id = "app";
    document.body.append(host);
    const wrapper = mount(
      { template: "<RouterView />" },
      {
        attachTo: host,
        global: {
          provide: { [consoleKey as symbol]: context },
          plugins: [router],
        },
      },
    );
    cleanups.push(() => wrapper.unmount());
    await router.push("/operations");
    await flushPromises();
    const beforeOverlay = history.length;
    await byText(wrapper, "派发任务").trigger("click");
    await flushPromises();
    const dialog = () =>
      new DOMWrapper(document.querySelector('[role="dialog"]')!);
    await dialog().get("input").setValue(op.id);
    await byText(dialog(), "确认派发").trigger("click");
    await vi.waitFor(() =>
      expect(dialog().find('[role="alert"]').exists()).toBe(true),
    );
    expect(dialog().get("a.pending-task-link").attributes("href")).toBe(
      `#/operations/${op.id}`,
    );
    expect(
      dialog()
        .findAll("button")
        .some((button) => button.text() === "读取原任务"),
    ).toBe(false);
    const guard = deferred<boolean>();
    const remove = router.beforeEach((to) =>
      to.path === `/operations/${op.id}` ? guard.promise : true,
    );
    cleanups.push(remove);
    await dialog().get("a.pending-task-link").trigger("click");
    await flushPromises();
    expect(document.querySelector('[role="dialog"]')).not.toBeNull();
    expect(router.currentRoute.value.path).toBe("/operations");
    expect(back).not.toHaveBeenCalled();
    guard.resolve(true);
    await flushPromises();
    expect(document.querySelector('[role="dialog"]')).toBeNull();
    expect(router.currentRoute.value.path).toBe(`/operations/${op.id}`);
    expect(history.length).toBe(beforeOverlay + 1);
    expect(history.state.asterOverlay).toBeUndefined();
    expect(back).not.toHaveBeenCalled();
    expect(reads).toEqual(["/operations", `/operations/${op.id}`]);
    expect(calls).toHaveLength(1);
    const backToList = nextActualPopstate();
    history.back();
    await backToList;
    await flushPromises();
    expect(router.currentRoute.value.path).toBe("/operations");
    const backToNodes = nextActualPopstate();
    history.back();
    await backToNodes;
    await flushPromises();
    expect(router.currentRoute.value.path).toBe("/nodes");
    expect(calls).toHaveLength(1);
  });
});

describe("decoded task-route equivalence", () => {
  it.each(["trailing-slash", "encoded-id"] as const)(
    "uses a real same-task read for %s rather than duplicate navigation",
    async (variant) => {
      const id = (variant === "trailing-slash" ? "52" : "62").repeat(16);
      const path =
        variant === "trailing-slash"
          ? `/operations/${id}/`
          : `/operations/%${id.charCodeAt(0).toString(16)}${id.slice(1)}`;
      const result = deferred<unknown>();
      const { wrapper, calls, op, router, reads } = await pendingSelfAction(
        result,
        id,
        path,
      );
      expect(router.currentRoute.value.params.id).toBe(id);
      expect(router.currentRoute.value.path).not.toBe(`/operations/${id}`);
      const dialog = wrapper.get('[role="dialog"]');
      expect(dialog.find("a.pending-task-link").exists()).toBe(false);
      await byText(dialog, "读取原任务").trigger("click");
      expect(reads()).toBe(1);
      expect(wrapper.find('[role="dialog"]').exists()).toBe(true);
      result.resolve({ operation: { ...op, state: "uncertain" } });
      await flushPromises();
      expect(wrapper.find('[role="dialog"]').exists()).toBe(false);
      expect(wrapper.emitted("updated")).toEqual([
        [{ ...op, state: "uncertain" }],
      ]);
      expect(calls).toHaveLength(1);
    },
  );
  it("does not treat an instance route with the same decoded ID as a task detail", async () => {
    const id = "72".repeat(16);
    const result = deferred<unknown>();
    const { wrapper, calls, router, reads } = await pendingSelfAction(
      result,
      id,
      `/instances/${id}`,
    );
    expect(router.currentRoute.value.params.id).toBe(id);
    const dialog = wrapper.get('[role="dialog"]');
    expect(dialog.get("a.pending-task-link").attributes("href")).toBe(
      `/operations/${id}`,
    );
    expect(
      dialog.findAll("button").some((button) => button.text() === "读取原任务"),
    ).toBe(false);
    expect(reads()).toBe(0);
    expect(calls).toHaveLength(1);
  });
});

describe("public binding task permissions", () => {
  it.each(["public_adopt", "public_detach"])(
    "%s requires the same three permissions for dispatch and read-only reconciliation",
    async (action) => {
      const { context, calls } = mockContext(() => ({ operation }));
      const router = await routing();
      const config = provided(context);
      const task = { ...operation, action, state: "accepted" };
      const wrapper = mount(OperationActions, {
        ...config,
        props: { operation: task },
        global: { ...config.global, plugins: [router] },
      });
      cleanups.push(() => wrapper.unmount());
      const required = ["nodes.read", "nodes.manage", "instances.manage"];
      const hasButton = (name: string) =>
        wrapper.findAll("button").some((button) => button.text() === name);
      for (const state of ["accepted", "uncertain"]) {
        await wrapper.setProps({ operation: { ...task, state } });
        const label = state === "accepted" ? "派发任务" : "核对结果";
        for (const missing of required) {
          context.session.user.value = {
            ...context.session.user.value!,
            role: "custom",
            permissions: [
              "instances.read",
              ...required.filter((p) => p !== missing),
            ],
          };
          await flushPromises();
          expect(
            hasButton(label),
            `must not expose ${state} without ${missing}`,
          ).toBe(false);
        }
        context.session.user.value = {
          ...context.session.user.value!,
          role: "custom",
          permissions: ["instances.read", ...required],
        };
        await flushPromises();
        expect(hasButton(label)).toBe(true);
      }
      expect(calls).toHaveLength(0);
    },
  );
});

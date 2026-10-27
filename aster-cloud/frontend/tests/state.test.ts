import { defineComponent, h, shallowRef, nextTick } from "vue";
import { mount, flushPromises } from "@vue/test-utils";
import { afterEach, describe, expect, it, vi } from "vitest";
import { webcrypto } from "node:crypto";
import {
  ApiError,
  createApiClient,
  operationResponse,
  validPage,
  validInstance,
} from "../src/api/client";
import { useMutation, fingerprint } from "../src/composables/mutation";
import { useQuery } from "../src/composables/query";
import { consoleKey } from "../src/context";
import { useSession } from "../src/composables/session";
import { readPreferences } from "../src/composables/preferences";
import { actionAllowed, actionPermission } from "../src/permissions";
import type { Instance, Page, Operation } from "../src/api/types";
import { admin, instance, operation } from "./fixtures";
import { deferred, mockContext } from "./helpers";
vi.stubGlobal("crypto", webcrypto);
afterEach(() => {
  document.body.innerHTML = "";
  vi.restoreAllMocks();
});
describe("identity and request lifetime", () => {
  it("does not restore a logged-out identity from a late me response", async () => {
    const response = deferred<unknown>();
    const { context } = mockContext(() => response.promise);
    const session = useSession(context.api);
    const pending = session.refresh();
    session.invalidate();
    response.resolve({ user: admin, csrf_token: "private" });
    await pending;
    expect(session.user.value).toBeNull();
    expect(context.api.setCSRF).not.toHaveBeenLastCalledWith("private");
  });
  it("does not commit a late resource response after grants change", async () => {
    const response = deferred<unknown>();
    const { context } = mockContext(() => response.promise);
    let query!: ReturnType<typeof useQuery<Page<Instance>>>;
    const wrapper = mount(
      defineComponent({
        setup() {
          query = useQuery(
            () => "/instances",
            (v): v is Page<Instance> => validPage(v, validInstance),
          );
          return () => h("div");
        },
      }),
      { global: { provide: { [consoleKey as symbol]: context } } },
    );
    context.session.invalidate();
    response.resolve({ items: [instance], next_cursor: null });
    await flushPromises();
    expect(query.data.value).toBeNull();
    wrapper.unmount();
  });
  it("a stale query cannot replace a newer path response", async () => {
    const first = deferred<unknown>();
    const path = shallowRef("/instances");
    const { context } = mockContext((_m, p) =>
      p === "/instances" ? first.promise : { items: [], next_cursor: null },
    );
    let query!: ReturnType<typeof useQuery<Page<Instance>>>;
    const wrapper = mount(
      defineComponent({
        setup() {
          query = useQuery(
            () => path.value,
            (v): v is Page<Instance> => validPage(v, validInstance),
          );
          return () => h("div");
        },
      }),
      { global: { provide: { [consoleKey as symbol]: context } } },
    );
    path.value = "/instances?cursor=abc";
    await nextTick();
    await flushPromises();
    first.resolve({ items: [instance], next_cursor: null });
    await flushPromises();
    expect(query.data.value?.items).toEqual([]);
    wrapper.unmount();
  });
});
describe("stable mutation intent", () => {
  it("keeps unknown key across close/reopen and never sends twice", async () => {
    const { context, calls } = mockContext(() => {
      throw new ApiError("unknown");
    });
    let mutation!: ReturnType<typeof useMutation>;
    const wrapper = mount(
      defineComponent({
        setup() {
          mutation = useMutation();
          return () => h("div");
        },
      }),
      { global: { provide: { [consoleKey as symbol]: context } } },
    );
    const path = `/instances/${instance.id}/operations`;
    await mutation.execute(
      "POST",
      path,
      { action: "shutdown", confirmation: instance.id },
      operationResponse,
    );
    const key = mutation.pendingKey.value;
    expect(key).toMatch(/^[a-f0-9]{32}$/);
    mutation.clearMessage();
    await mutation.execute(
      "POST",
      path,
      { action: "shutdown", confirmation: instance.id },
      operationResponse,
    );
    expect(calls).toHaveLength(1);
    expect(mutation.pendingKey.value).toBe(key);
    expect(mutation.error.value).toBe("unknown");
    wrapper.unmount();
  });
  it("does not send after identity changes during intent hashing", async () => {
    const { context, calls } = mockContext(() => ({ operation }));
    let mutation!: ReturnType<typeof useMutation>;
    const wrapper = mount(
      defineComponent({
        setup() {
          mutation = useMutation();
          return () => h("div");
        },
      }),
      { global: { provide: { [consoleKey as symbol]: context } } },
    );
    const pending = mutation.execute(
      "POST",
      "/instances",
      { hostname: "new" },
      operationResponse,
    );
    context.session.invalidate();
    await pending;
    expect(calls).toHaveLength(0);
    wrapper.unmount();
  });
  it("validates operation ID/action/instance before accepting an ACK", async () => {
    const { context, calls } = mockContext(() => ({ operation }));
    let mutation!: ReturnType<typeof useMutation>;
    const wrapper = mount(
      defineComponent({
        setup() {
          mutation = useMutation();
          return () => h("div");
        },
      }),
      { global: { provide: { [consoleKey as symbol]: context } } },
    );
    const result = await mutation.execute(
      "POST",
      "/instances/other/operations",
      { action: "start" },
      operationResponse,
      { bindOperation: { action: "start", instanceId: "other" } },
    );
    expect(result).toBeNull();
    expect(mutation.error.value).toBe("unknown");
    expect(calls).toHaveLength(1);
    expect(mutation.pendingKey.value).toBe(calls[0]?.key);
    wrapper.unmount();
  });
  it("uses existing operation ID for explicit reconcile; never rotates its key", async () => {
    const { context, calls } = mockContext((_m, _p, _b, key) => ({
      operation: { ...operation, id: key, state: "uncertain" },
    }));
    let mutation!: ReturnType<typeof useMutation>;
    const wrapper = mount(
      defineComponent({
        setup() {
          mutation = useMutation();
          return () => h("div");
        },
      }),
      { global: { provide: { [consoleKey as symbol]: context } } },
    );
    await mutation.execute(
      "POST",
      `/operations/${operation.id}/reconcile`,
      {},
      operationResponse,
      {
        ...boundOptions(operation),
        allowUncertainReconcile: true,
      },
    );
    expect(calls[0]?.key).toBe(operation.id);
    wrapper.unmount();
  });
  it("does not persist credentials or credential-derived hashes", async () => {
    expect(
      await fingerprint("/users", { email: "x", password: "OneSecret123!" }),
    ).toBe(
      await fingerprint("/users", { email: "x", password: "OtherSecret456!" }),
    );
    expect(
      await fingerprint("/users", { email: "y", password: "OneSecret123!" }),
    ).not.toBe(
      await fingerprint("/users", { email: "x", password: "OneSecret123!" }),
    );
  });
});
describe("preferences and permission gates", () => {
  it.each([null, "{broken", '{"locale":"bad","appearance":"bad"}'])(
    "fails closed for stored preferences %s",
    (raw) =>
      expect(readPreferences({ getItem: () => raw })).toEqual({
        locale: "zh-CN",
        appearance: "system",
      }),
  );
  it("keeps only legal saved values", () =>
    expect(
      readPreferences({
        getItem: () => '{"locale":"en","appearance":"dark","token":"ignored"}',
      }),
    ).toEqual({ locale: "en", appearance: "dark" }));
  it("maps action grants explicitly without assuming admin from a role string", () => {
    expect(actionPermission("delete")).toBe("instances.dangerous");
    expect(actionPermission("backup_restore")).toBe("storage.restore");
    expect(actionPermission("migrate_activate")).toBe("migration.manage");
    expect(actionPermission("unknown")).toBe("");
    expect(actionAllowed("delete", "running", ["instances.manage"])).toBe(
      false,
    );
  });
  it.each([
    "snapshot_create",
    "snapshot_restore",
    "snapshot_delete",
    "backup_create",
    "backup_verify",
    "backup_restore",
    "backup_delete",
  ] as const)("blocks %s before confirmed shutoff", (action) => {
    expect(actionAllowed(action, "running", admin.permissions)).toBe(false);
    expect(actionAllowed(action, "shutoff", admin.permissions)).toBe(true);
    expect(actionAllowed(action, "ShutOff", admin.permissions)).toBe(false);
  });
});

describe("uncertain authentication", () => {
  it("confirms an empty 204 logout and clears identity without pending uncertainty", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValue(new Response(null, { status: 204 }));
    const api = createApiClient(fetcher);
    api.setCSRF("logout-csrf");
    const session = useSession(api);
    session.user.value = admin;
    await session.logout();
    expect(session.user.value).toBeNull();
    expect(session.pendingAuth.value).toBeNull();
    expect(session.error.value).toBe("");
    expect(session.busy.value).toBe(false);
    expect(session.epoch.value).toBe(1);
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it("keeps a mismatched logout ACK unknown and blocks another authentication write", async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(
      new Response("{}", {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    const api = createApiClient(fetcher);
    api.setCSRF("logout-csrf");
    const session = useSession(api);
    session.user.value = admin;
    await session.logout();
    expect(session.user.value).toBeNull();
    expect(session.pendingAuth.value).toBe("logout");
    expect(session.error.value).toBe("unknown");
    await session.logout();
    await session.login("admin@example.invalid", "NeverPersist123!");
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it("does not issue another login until a safe session read resolves the outcome", async () => {
    let uncertain = true;
    const { context, calls } = mockContext((method, path) =>
      method === "GET"
        ? path === "/auth/csrf"
          ? { csrf_token: "csrf" }
          : uncertain
            ? Promise.reject(new ApiError("unauthorized"))
            : { user: admin, csrf_token: "csrf" }
        : Promise.reject(new ApiError("unknown")),
    );
    const session = useSession(context.api);
    await session.login("admin@example.invalid", "NeverPersist123!");
    expect(session.pendingAuth.value).toBe("login");
    await session.login("admin@example.invalid", "NeverPersist123!");
    expect(calls).toHaveLength(1);
    uncertain = false;
    await session.refresh();
    expect(session.pendingAuth.value).toBeNull();
    expect(session.user.value?.id).toBe(admin.id);
  });
  it("uncertain logout hides sensitive resources without claiming confirmed sign-out", async () => {
    const { context, calls } = mockContext(() =>
      Promise.reject(new ApiError("unknown")),
    );
    const session = useSession(context.api);
    session.user.value = admin;
    await session.logout();
    expect(session.user.value).toBeNull();
    expect(session.pendingAuth.value).toBe("logout");
    expect(session.error.value).toBe("unknown");
    await session.logout();
    expect(calls).toHaveLength(1);
  });
});

describe("read-confirmed recovery", () => {
  it("clears a lost creation acknowledgement only when a bound persisted task is read", async () => {
    const { acknowledgeOperations } =
      await import("../src/composables/mutation");
    let attempt = 0;
    const { context, calls } = mockContext((_m, _p, _b, key) => {
      if (attempt++ === 0) throw new ApiError("unknown");
      return { operation: { ...operation, id: key, action: "reboot" } };
    });
    let mutation!: ReturnType<typeof useMutation>;
    const wrapper = mount(
      defineComponent({
        setup() {
          mutation = useMutation();
          return () => h("div");
        },
      }),
      { global: { provide: { [consoleKey as symbol]: context } } },
    );
    const path = `/instances/${instance.id}/operations`,
      body = { action: "reboot", confirmation: instance.id };
    await mutation.execute("POST", path, body, operationResponse);
    const key = mutation.pendingKey.value;
    acknowledgeOperations(admin.id, [
      { ...operation, id: key, action: "reboot", actor_id: "other" },
    ]);
    mutation.clearMessage();
    await mutation.execute("POST", path, body, operationResponse);
    expect(calls).toHaveLength(1);
    acknowledgeOperations(admin.id, [
      { ...operation, id: key, action: "reboot" },
    ]);
    expect(calls).toHaveLength(1);
    mutation.clearMessage();
    await mutation.execute("POST", path, body, operationResponse, {
      bindOperation: { action: "reboot", instanceId: instance.id },
    });
    expect(calls).toHaveLength(2);
    wrapper.unmount();
  });
  it("a still-accepted task cannot authorize replay of an uncertain dispatch", async () => {
    const { acknowledgeOperations } =
      await import("../src/composables/mutation");
    const { context, calls } = mockContext(() => {
      throw new ApiError("unknown");
    });
    let mutation!: ReturnType<typeof useMutation>;
    const wrapper = mount(
      defineComponent({
        setup() {
          mutation = useMutation();
          return () => h("div");
        },
      }),
      { global: { provide: { [consoleKey as symbol]: context } } },
    );
    const path = `/operations/${operation.id}/dispatch`;
    await mutation.execute(
      "POST",
      path,
      {},
      operationResponse,
      boundOptions(operation),
    );
    acknowledgeOperations(admin.id, [operation]);
    mutation.clearMessage();
    await mutation.execute("POST", path, {}, operationResponse, {
      ...boundOptions(operation),
      allowUncertainReconcile: true,
    });
    expect(calls).toHaveLength(1);
    expect(mutation.pendingKey.value).toBe(operation.id);
    wrapper.unmount();
  });
});

const pendingStorage = "aster.cloud.pending.v1";
const operatorID = "e".repeat(32);
const operationBinding = (value: Operation) => ({
  id: value.id,
  action: value.action,
  instance_id: value.instance_id,
  node_id: value.node_id,
  artifact_id: value.artifact_id,
  target_node_id: value.target_node_id,
  actor_id: value.actor_id,
});
const boundOptions = (value: Operation) => ({
  key: value.id,
  bindOperation: {
    action: value.action,
    instanceId: value.instance_id,
    nodeId: value.node_id,
    artifactId: value.artifact_id,
    targetNodeId: value.target_node_id,
    actorId: value.actor_id,
  },
});
async function pendingFixture(
  resolver: Parameters<typeof mockContext>[0],
  stored: unknown[] = [],
  beforeLoad?: () => void,
) {
  vi.resetModules();
  sessionStorage.setItem(pendingStorage, JSON.stringify(stored));
  beforeLoad?.();
  const module = await import("../src/composables/mutation");
  const freshContext = await import("../src/context");
  const { context, calls } = mockContext(resolver);
  context.session.user.value = { ...admin, id: operatorID, role: "operator" };
  let mutation!: ReturnType<typeof module.useMutation>;
  const wrapper = mount(
    defineComponent({
      setup() {
        mutation = module.useMutation();
        return () => h("div");
      },
    }),
    { global: { provide: { [freshContext.consoleKey as symbol]: context } } },
  );
  return {
    ...module,
    mutation,
    wrapper,
    context,
    calls,
    entries: () =>
      JSON.parse(sessionStorage.getItem(pendingStorage) || "[]") as Array<
        Record<string, unknown>
      >,
  };
}
describe("immutable task recovery belongs to the current operator, not its creator", () => {
  it.each(
    ["dispatch", "reconcile"].flatMap((purpose) =>
      ["sending", "dispatched", "uncertain", "succeeded", "rejected"].map(
        (state) => [purpose, state] as const,
      ),
    ),
  )(
    "clears a lost %s ACK from a bound %s GET without redispatching",
    async (purpose, state) => {
      const fixture = await pendingFixture(() => {
        throw new ApiError("unknown");
      });
      try {
        await fixture.mutation.execute(
          "POST",
          `/operations/${operation.id}/${purpose}`,
          {},
          operationResponse,
          boundOptions(operation),
        );
        expect(fixture.calls).toHaveLength(1);
        expect(fixture.entries()[0]).toMatchObject({
          owner: operatorID,
          key: operation.id,
          purpose,
          binding: operationBinding(operation),
        });
        fixture.acknowledgeOperations(operatorID, [{ ...operation, state }]);
        expect(fixture.entries()).toEqual([]);
        expect(fixture.calls).toHaveLength(1);
      } finally {
        fixture.wrapper.unmount();
      }
    },
  );
  it("a successful bound reconcile also resolves the same operator's older uncertain dispatch slot", async () => {
    const fixture = await pendingFixture((_m, path) => {
      if (path.endsWith("/dispatch")) throw new ApiError("unknown");
      return { operation: { ...operation, state: "dispatched" } };
    });
    try {
      await fixture.mutation.execute(
        "POST",
        `/operations/${operation.id}/dispatch`,
        {},
        operationResponse,
        boundOptions(operation),
      );
      fixture.mutation.clearMessage();
      const result = await fixture.mutation.execute(
        "POST",
        `/operations/${operation.id}/reconcile`,
        {},
        operationResponse,
        { ...boundOptions(operation), allowUncertainReconcile: true },
      );
      expect(result?.operation.state).toBe("dispatched");
      expect(fixture.calls.map((call) => [call.path, call.key])).toEqual([
        [`/operations/${operation.id}/dispatch`, operation.id],
        [`/operations/${operation.id}/reconcile`, operation.id],
      ]);
      expect(fixture.entries()).toEqual([]);
    } finally {
      fixture.wrapper.unmount();
    }
  });
  it.each([
    "id",
    "action",
    "instance_id",
    "node_id",
    "artifact_id",
    "target_node_id",
    "actor_id",
  ] as const)("never clears a read with mismatched %s", async (field) => {
    const fixture = await pendingFixture(() => {
      throw new ApiError("unknown");
    });
    try {
      await fixture.mutation.execute(
        "POST",
        `/operations/${operation.id}/dispatch`,
        {},
        operationResponse,
        boundOptions(operation),
      );
      const pending = fixture.entries();
      fixture.acknowledgeOperations(operatorID, [
        {
          ...operation,
          [field]: field === "action" ? "delete" : "f".repeat(32),
          state: "succeeded",
        },
      ]);
      expect(fixture.entries()).toEqual(pending);
      expect(fixture.calls).toHaveLength(1);
    } finally {
      fixture.wrapper.unmount();
    }
  });
  it.each([
    "id",
    "action",
    "instance_id",
    "node_id",
    "artifact_id",
    "target_node_id",
    "actor_id",
  ] as const)(
    "validates %s inside execute before clearing an ACK",
    async (field) => {
      const fixture = await pendingFixture(() => ({
        operation: {
          ...operation,
          [field]: field === "action" ? "delete" : "f".repeat(32),
          state: "dispatched",
        },
      }));
      try {
        const result = await fixture.mutation.execute(
          "POST",
          `/operations/${operation.id}/dispatch`,
          {},
          operationResponse,
          boundOptions(operation),
        );
        expect(result).toBeNull();
        expect(fixture.mutation.error.value).toBe("unknown");
        expect(fixture.entries()).toHaveLength(1);
        expect(fixture.mutation.pendingKey.value).toBe(operation.id);
        expect(fixture.calls).toHaveLength(1);
      } finally {
        fixture.wrapper.unmount();
      }
    },
  );
  it("does not regard accepted as proof of progress, even in a successful HTTP ACK", async () => {
    const fixture = await pendingFixture(() => ({ operation }));
    try {
      const result = await fixture.mutation.execute(
        "POST",
        `/operations/${operation.id}/dispatch`,
        {},
        operationResponse,
        boundOptions(operation),
      );
      expect(result).toBeNull();
      expect(fixture.mutation.error.value).toBe("unknown");
      const pending = fixture.entries();
      fixture.acknowledgeOperations(operatorID, [operation]);
      expect(fixture.entries()).toEqual(pending);
      fixture.mutation.clearMessage();
      await fixture.mutation.execute(
        "POST",
        `/operations/${operation.id}/dispatch`,
        {},
        operationResponse,
        boundOptions(operation),
      );
      expect(fixture.calls).toHaveLength(1);
    } finally {
      fixture.wrapper.unmount();
    }
  });
  it.each(["dispatch", "reconcile"])(
    "keeps legacy %s entries without upgrading their missing binding",
    async (purpose) => {
      const path = `/operations/${operation.id}/${purpose}`;
      const stored = [
        {
          owner: operatorID,
          fingerprint: await fingerprint(path, {}),
          key: operation.id,
          purpose,
        },
      ];
      const fixture = await pendingFixture(
        () => ({ operation: { ...operation, state: "succeeded" } }),
        stored,
      );
      try {
        fixture.acknowledgeOperations(operatorID, [
          { ...operation, state: "succeeded" },
        ]);
        await fixture.mutation.execute("POST", path, {}, operationResponse, {
          ...boundOptions(operation),
          allowUncertainReconcile: true,
        });
        expect(fixture.calls).toHaveLength(0);
        expect(fixture.entries()).toEqual(stored);
        expect(fixture.mutation.pendingKey.value).toBe(operation.id);
        expect(fixture.mutation.error.value).toBe("unknown");
      } finally {
        fixture.wrapper.unmount();
      }
    },
  );
  it.each(["node_id", "actor_id", "id"] as const)(
    "fails closed on an incomplete or corrupt stored %s binding without rewriting it",
    async (field) => {
      const path = `/operations/${operation.id}/reconcile`;
      const binding: Record<string, unknown> = operationBinding(operation);
      if (field === "id") binding.id = "f".repeat(32);
      else delete binding[field];
      const stored = [
        {
          owner: operatorID,
          fingerprint: await fingerprint(path, {}),
          key: operation.id,
          purpose: "reconcile",
          binding,
        },
      ];
      const fixture = await pendingFixture(
        () => ({ operation: { ...operation, state: "succeeded" } }),
        stored,
      );
      try {
        fixture.acknowledgeOperations(operatorID, [
          { ...operation, state: "succeeded" },
        ]);
        await fixture.mutation.execute("POST", path, {}, operationResponse, {
          ...boundOptions(operation),
          allowUncertainReconcile: true,
        });
        expect(fixture.calls).toHaveLength(0);
        expect(fixture.entries()).toEqual(stored);
        expect(fixture.mutation.error.value).toBe("unavailable");
      } finally {
        fixture.wrapper.unmount();
      }
    },
  );
  it("requires a complete binding before issuing either operation write", async () => {
    const fixture = await pendingFixture(() => ({ operation }));
    try {
      for (const action of ["dispatch", "reconcile"])
        await fixture.mutation.execute(
          "POST",
          `/operations/${operation.id}/${action}`,
          {},
          operationResponse,
          {
            key: operation.id,
            bindOperation: {
              action: operation.action,
              instanceId: operation.instance_id,
            },
            allowUncertainReconcile: true,
          },
        );
      expect(fixture.calls).toHaveLength(0);
      expect(fixture.entries()).toEqual([]);
      expect(fixture.mutation.error.value).toBe("invalid");
    } finally {
      fixture.wrapper.unmount();
    }
  });
  it("does not cross-clear another operator's entries for the same immutable task", async () => {
    const fixture = await pendingFixture(() => {
      throw new ApiError("unknown");
    });
    try {
      const path = `/operations/${operation.id}/dispatch`;
      await fixture.mutation.execute(
        "POST",
        path,
        {},
        operationResponse,
        boundOptions(operation),
      );
      fixture.acknowledgeOperations(admin.id, [
        { ...operation, state: "dispatched" },
      ]);
      expect(fixture.entries()).toHaveLength(1);
      fixture.context.session.user.value = admin;
      fixture.context.session.epoch.value++;
      await fixture.mutation.execute(
        "POST",
        path,
        {},
        operationResponse,
        boundOptions(operation),
      );
      expect(fixture.calls).toHaveLength(2);
      expect(fixture.entries()).toHaveLength(2);
      fixture.acknowledgeOperations(admin.id, [
        { ...operation, state: "dispatched" },
      ]);
      expect(fixture.entries().map((entry) => entry.owner)).toEqual([
        operatorID,
      ]);
    } finally {
      fixture.wrapper.unmount();
    }
  });
  it("a late ACK after an identity switch cannot clear the original owner's uncertainty", async () => {
    const reply = deferred<unknown>();
    const fixture = await pendingFixture(() => reply.promise);
    try {
      const pending = fixture.mutation.execute(
        "POST",
        `/operations/${operation.id}/dispatch`,
        {},
        operationResponse,
        boundOptions(operation),
      );
      await vi.waitFor(() => expect(fixture.calls).toHaveLength(1));
      fixture.context.session.invalidate();
      fixture.context.session.user.value = admin;
      reply.resolve({ operation: { ...operation, state: "dispatched" } });
      expect(await pending).toBeNull();
      expect(fixture.entries()).toHaveLength(1);
      expect(fixture.entries()[0]?.owner).toBe(operatorID);
    } finally {
      fixture.wrapper.unmount();
    }
  });
  it("permits a 65th unresolved write without evicting earlier intents", async () => {
    const stored = Array.from({ length: 64 }, (_, index) => ({
      owner: operatorID,
      fingerprint: index.toString(16).padStart(64, "0"),
      key: index.toString(16).padStart(32, "0"),
      purpose: "dispatch",
    }));
    const fixture = await pendingFixture(() => {
      throw new ApiError("unknown");
    }, stored);
    try {
      await fixture.mutation.execute(
        "POST",
        `/operations/${operation.id}/dispatch`,
        {},
        operationResponse,
        boundOptions(operation),
      );
      expect(fixture.calls).toHaveLength(1);
      expect(fixture.entries()).toHaveLength(65);
      expect(fixture.entries().slice(0, 64)).toEqual(stored);
      expect(fixture.entries()[64]?.key).toBe(operation.id);
      expect(fixture.mutation.error.value).toBe("unknown");
    } finally {
      fixture.wrapper.unmount();
    }
  });
});

describe("durable recovery validates prior bindings and identity", () => {
  it("rehydrates a complete binding without persisting unrelated properties", async () => {
    const path = `/operations/${operation.id}/dispatch`;
    const stored = [
      {
        owner: operatorID,
        fingerprint: await fingerprint(path, {}),
        key: operation.id,
        purpose: "dispatch",
        binding: { ...operationBinding(operation), ignored: "not-binding" },
      },
    ];
    const fixture = await pendingFixture(() => {
      throw new ApiError("unknown");
    }, stored);
    try {
      fixture.acknowledgeOperations(operatorID, [
        { ...operation, state: "dispatched" },
      ]);
      expect(fixture.entries()).toEqual([]);
      expect(fixture.calls).toHaveLength(0);
    } finally {
      fixture.wrapper.unmount();
    }
  });
  it("successful reconcile cannot clear a legacy dispatch entry or another task", async () => {
    const path = `/operations/${operation.id}/dispatch`;
    const other = { ...operation, id: "6".repeat(32) };
    const stored = [
      {
        owner: operatorID,
        fingerprint: await fingerprint(path, {}),
        key: operation.id,
        purpose: "dispatch",
      },
      {
        owner: operatorID,
        fingerprint: await fingerprint(`/operations/${other.id}/dispatch`, {}),
        key: other.id,
        purpose: "dispatch",
        binding: operationBinding(other),
      },
    ];
    const fixture = await pendingFixture(
      () => ({ operation: { ...operation, state: "succeeded" } }),
      stored,
    );
    try {
      await fixture.mutation.execute(
        "POST",
        `/operations/${operation.id}/reconcile`,
        {},
        operationResponse,
        { ...boundOptions(operation), allowUncertainReconcile: true },
      );
      expect(fixture.calls).toHaveLength(1);
      expect(fixture.entries()).toEqual(stored);
    } finally {
      fixture.wrapper.unmount();
    }
  });
  it.each(["node_id", "actor_id", "artifact_id", "target_node_id"] as const)(
    "never upgrades a prior reconcile with a different %s",
    async (field) => {
      const path = `/operations/${operation.id}/reconcile`;
      const prior = { ...operation, [field]: "different-binding" };
      const stored = [
        {
          owner: operatorID,
          fingerprint: await fingerprint(path, {}),
          key: operation.id,
          purpose: "reconcile",
          binding: operationBinding(prior),
        },
      ];
      const fixture = await pendingFixture(
        () => ({ operation: { ...operation, state: "dispatched" } }),
        stored,
      );
      try {
        await fixture.mutation.execute("POST", path, {}, operationResponse, {
          ...boundOptions(operation),
          allowUncertainReconcile: true,
        });
        expect(fixture.calls).toHaveLength(0);
        expect(fixture.entries()).toEqual(stored);
        expect(fixture.mutation.error.value).toBe("unknown");
      } finally {
        fixture.wrapper.unmount();
      }
    },
  );
  it("captures the immutable binding and request key before asynchronous hashing", async () => {
    const fixture = await pendingFixture(() => ({
      operation: { ...operation, state: "dispatched" },
    }));
    try {
      const options = boundOptions(operation);
      const pending = fixture.mutation.execute(
        "POST",
        `/operations/${operation.id}/dispatch`,
        {},
        operationResponse,
        options,
      );
      options.key = "f".repeat(32);
      options.bindOperation.nodeId = "different-node";
      options.bindOperation.actorId = operatorID;
      expect((await pending)?.operation.id).toBe(operation.id);
      expect(fixture.calls[0]?.key).toBe(operation.id);
      expect(fixture.entries()).toEqual([]);
    } finally {
      fixture.wrapper.unmount();
    }
  });
  it("a late explicit error after an identity switch does not delete the original owner's entry", async () => {
    const reply = deferred<unknown>();
    const fixture = await pendingFixture(() => reply.promise);
    try {
      const pending = fixture.mutation.execute(
        "POST",
        `/operations/${operation.id}/dispatch`,
        {},
        operationResponse,
        boundOptions(operation),
      );
      await vi.waitFor(() => expect(fixture.calls).toHaveLength(1));
      fixture.context.session.invalidate();
      fixture.context.session.user.value = admin;
      reply.reject(new ApiError("conflict", "STATE_CONFLICT", 409));
      expect(await pending).toBeNull();
      expect(fixture.entries()).toHaveLength(1);
      expect(fixture.entries()[0]?.owner).toBe(operatorID);
    } finally {
      fixture.wrapper.unmount();
    }
  });
});

describe("pending intent persistence must succeed before a write", () => {
  it.each(["QuotaExceededError", "SecurityError"])(
    "%s prevents every new POST and permits the first send only after storage recovers",
    async (name) => {
      const fixture = await pendingFixture((_method, _path, _body, key) => ({
        operation: {
          ...operation,
          id: key,
          action: "create",
          actor_id: operatorID,
        },
      }));
      const setter = vi
        .spyOn(Storage.prototype, "setItem")
        .mockImplementation(() => {
          throw new DOMException("private storage fault", name);
        });
      const body = { hostname: "storage-test", owner_ref: instance.owner_ref };
      try {
        for (let attempt = 0; attempt < 2; attempt++) {
          expect(
            await fixture.mutation.execute(
              "POST",
              "/instances",
              body,
              operationResponse,
              { bindOperation: { action: "create" } },
            ),
          ).toBeNull();
          expect(fixture.calls).toHaveLength(0);
          expect(fixture.mutation.error.value).toBe("unavailable");
          expect(fixture.mutation.pendingKey.value).toBe("");
        }
        setter.mockRestore();
        expect(fixture.entries()).toEqual([]);
        const result = await fixture.mutation.execute(
          "POST",
          "/instances",
          body,
          operationResponse,
          { bindOperation: { action: "create" } },
        );
        expect(result?.operation.actor_id).toBe(operatorID);
        expect(fixture.calls).toHaveLength(1);
        expect(fixture.entries()).toEqual([]);
      } finally {
        setter.mockRestore();
        fixture.wrapper.unmount();
      }
    },
  );
  it.each(["sessionStorage getter", "getItem"])(
    "%s failure cannot overwrite unread unknown entries, and recovery rereads them before sending",
    async (fault) => {
      const stored = [
        {
          owner: operatorID,
          fingerprint: await fingerprint("/legacy-operation", {}),
          key: "3".repeat(32),
          purpose: "dispatch",
        },
      ];
      let restore = () => {};
      const fixture = await pendingFixture(
        () => {
          throw new ApiError("unknown");
        },
        stored,
        () => {
          if (fault === "getItem") {
            const read = vi
              .spyOn(Storage.prototype, "getItem")
              .mockImplementation(() => {
                throw new DOMException("blocked", "SecurityError");
              });
            restore = () => read.mockRestore();
          } else {
            const read = vi
              .spyOn(window, "sessionStorage", "get")
              .mockImplementation(() => {
                throw new DOMException("blocked", "SecurityError");
              });
            restore = () => read.mockRestore();
          }
        },
      );
      try {
        await fixture.mutation.execute(
          "POST",
          "/instances",
          { hostname: "unread-storage" },
          operationResponse,
        );
        expect(fixture.calls).toHaveLength(0);
        expect(fixture.mutation.error.value).toBe("unavailable");
        restore();
        expect(fixture.entries()).toEqual(stored);
        await fixture.mutation.execute(
          "POST",
          "/instances",
          { hostname: "unread-storage" },
          operationResponse,
        );
        expect(fixture.calls).toHaveLength(1);
        expect(fixture.entries()).toHaveLength(2);
        expect(fixture.entries()[0]).toEqual(stored[0]);
        expect(fixture.entries()[1]?.key).toBe(fixture.calls[0]?.key);
      } finally {
        restore();
        fixture.wrapper.unmount();
      }
    },
  );
  it("a failed save never replaces a prior unknown reconcile key or legacy entry", async () => {
    const path = `/operations/${operation.id}/reconcile`;
    const stored = [
      {
        owner: operatorID,
        fingerprint: await fingerprint("/legacy-operation", {}),
        key: "4".repeat(32),
        purpose: "dispatch",
      },
      {
        owner: operatorID,
        fingerprint: await fingerprint(path, {}),
        key: operation.id,
        purpose: "reconcile",
        binding: operationBinding(operation),
      },
    ];
    const fixture = await pendingFixture(
      () => ({ operation: { ...operation, state: "dispatched" } }),
      stored,
    );
    const setter = vi
      .spyOn(Storage.prototype, "setItem")
      .mockImplementation(() => {
        throw new DOMException("full", "QuotaExceededError");
      });
    try {
      const options = {
        ...boundOptions(operation),
        allowUncertainReconcile: true,
      };
      expect(
        await fixture.mutation.execute(
          "POST",
          path,
          {},
          operationResponse,
          options,
        ),
      ).toBeNull();
      expect(fixture.calls).toHaveLength(0);
      expect(fixture.mutation.pendingKey.value).toBe(operation.id);
      expect(fixture.mutation.error.value).toBe("unavailable");
      setter.mockRestore();
      expect(fixture.entries()).toEqual(stored);
      await fixture.mutation.execute(
        "POST",
        path,
        {},
        operationResponse,
        options,
      );
      expect(fixture.calls).toHaveLength(1);
      expect(fixture.calls[0]?.key).toBe(operation.id);
      expect(fixture.entries()).toEqual([stored[0]]);
    } finally {
      setter.mockRestore();
      fixture.wrapper.unmount();
    }
  });
  it.each(["ACK", "GET", "explicit failure"])(
    "%s cleanup failure retains the original uncertainty instead of permitting another POST",
    async (outcome) => {
      let setter: ReturnType<typeof vi.spyOn> | undefined;
      let explicitFailure: Error;
      const fixture = await pendingFixture(() => {
        if (outcome === "GET") throw new ApiError("unknown");
        setter = vi
          .spyOn(Storage.prototype, "setItem")
          .mockImplementation(() => {
            throw new DOMException("full", "QuotaExceededError");
          });
        if (outcome === "explicit failure") throw explicitFailure;
        return { operation: { ...operation, state: "dispatched" } };
      });
      const { ApiError: FreshApiError } = await import("../src/api/client");
      explicitFailure = new FreshApiError("conflict", "STATE_CONFLICT", 409);
      try {
        const path = `/operations/${operation.id}/dispatch`;
        const result = await fixture.mutation.execute(
          "POST",
          path,
          {},
          operationResponse,
          boundOptions(operation),
        );
        expect(result?.operation.state).toBe(
          outcome === "ACK" ? "dispatched" : undefined,
        );
        if (outcome === "GET") {
          setter = vi
            .spyOn(Storage.prototype, "setItem")
            .mockImplementation(() => {
              throw new DOMException("full", "QuotaExceededError");
            });
          fixture.acknowledgeOperations(operatorID, [
            { ...operation, state: "dispatched" },
          ]);
        }
        expect(fixture.calls).toHaveLength(1);
        setter?.mockRestore();
        expect(fixture.entries()).toHaveLength(1);
        const saved = fixture.entries()[0];
        fixture.mutation.clearMessage();
        await fixture.mutation.execute(
          "POST",
          path,
          {},
          operationResponse,
          boundOptions(operation),
        );
        expect(fixture.calls).toHaveLength(1);
        expect(fixture.mutation.error.value).toBe("unknown");
        expect(fixture.mutation.pendingKey.value).toBe(operation.id);
        expect(fixture.entries()).toEqual([saved]);
      } finally {
        setter?.mockRestore();
        fixture.wrapper.unmount();
      }
    },
  );
  it("a resource ACK whose cleanup cannot persist stays guarded after a simulated reload", async () => {
    let setter: ReturnType<typeof vi.spyOn> | undefined;
    const fixture = await pendingFixture((_method, _path, _body, key) => {
      setter = vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
        throw new DOMException("full", "QuotaExceededError");
      });
      return {
        operation: {
          ...operation,
          id: key,
          action: "create",
          actor_id: operatorID,
        },
      };
    });
    const body = { hostname: "ack-storage-test" };
    try {
      const result = await fixture.mutation.execute(
        "POST",
        "/instances",
        body,
        operationResponse,
        { bindOperation: { action: "create" } },
      );
      const key = result?.operation.id;
      expect(key).toBe(fixture.calls[0]?.key);
      expect(fixture.calls).toHaveLength(1);
      setter?.mockRestore();
      const saved = fixture.entries();
      expect(saved).toHaveLength(1);
      expect(saved[0]?.key).toBe(key);
      fixture.mutation.clearMessage();
      await fixture.mutation.execute(
        "POST",
        "/instances",
        body,
        operationResponse,
      );
      expect(fixture.calls).toHaveLength(1);
      expect(fixture.mutation.pendingKey.value).toBe(key);
      const reloaded = await pendingFixture(() => {
        throw new Error("a reloaded unknown intent must not be resent");
      }, saved);
      try {
        await reloaded.mutation.execute(
          "POST",
          "/instances",
          body,
          operationResponse,
        );
        expect(reloaded.calls).toHaveLength(0);
        expect(reloaded.mutation.error.value).toBe("unknown");
        expect(reloaded.mutation.pendingKey.value).toBe(key);
        expect(reloaded.entries()).toEqual(saved);
      } finally {
        reloaded.wrapper.unmount();
      }
    } finally {
      setter?.mockRestore();
      fixture.wrapper.unmount();
    }
  });
});

describe("pending recovery retains the whole durable ledger", () => {
  it("recovers a bound intent beyond entry 64 without reissuing or truncating its neighbors", async () => {
    const path = `/operations/${operation.id}/dispatch`;
    const neighbors = Array.from({ length: 95 }, (_, index) => ({
      owner: operatorID,
      fingerprint: index.toString(16).padStart(64, "0"),
      key: index.toString(16).padStart(32, "0"),
      purpose: "dispatch",
    }));
    const tail = {
      owner: operatorID,
      fingerprint: await fingerprint(path, {}),
      key: operation.id,
      purpose: "dispatch",
      binding: operationBinding(operation),
    };
    const fixture = await pendingFixture(
      () => ({ operation }),
      [...neighbors, tail],
    );
    try {
      await fixture.mutation.execute(
        "POST",
        path,
        {},
        operationResponse,
        boundOptions(operation),
      );
      expect(fixture.calls).toHaveLength(0);
      expect(fixture.mutation.error.value).toBe("unknown");
      expect(fixture.mutation.pendingKey.value).toBe(operation.id);
      expect(fixture.entries()).toEqual([...neighbors, tail]);
      fixture.acknowledgeOperations(operatorID, [
        { ...operation, state: "dispatched" },
      ]);
      expect(fixture.entries()).toEqual(neighbors);
    } finally {
      fixture.wrapper.unmount();
    }
  });
});

describe("pending ledger is bounded and restored atomically", () => {
  const entry = {
    owner: operatorID,
    fingerprint: "0".repeat(64),
    key: "0".repeat(32),
    purpose: "other",
  };
  it.each([
    ["empty string", ""],
    ["non-array object", "{}"],
    ["null", "null"],
    ["broken JSON", "["],
    ["invalid tail", JSON.stringify([entry, null])],
    ["unknown purpose", JSON.stringify([{ ...entry, purpose: "future" }])],
    ["invalid key", JSON.stringify([{ ...entry, key: "bad" }])],
    ["missing owner", JSON.stringify([{ ...entry, owner: "" }])],
    [
      "duplicate slot",
      JSON.stringify([entry, { ...entry, key: "1".repeat(32) }]),
    ],
    ["oversized raw JSON", " ".repeat(1024 * 1024) + "[]"],
    [
      "UTF-8 exceeds byte budget",
      JSON.stringify([{ ...entry, owner: "界".repeat(400000) }]),
    ],
  ])(
    "refuses %s before HTTP and leaves all original bytes intact",
    async (_name, raw) => {
      const fixture = await pendingFixture(
        () => ({ operation }),
        [],
        () => {
          sessionStorage.setItem(pendingStorage, raw);
        },
      );
      try {
        await fixture.mutation.execute(
          "POST",
          `/operations/${operation.id}/dispatch`,
          {},
          operationResponse,
          boundOptions(operation),
        );
        fixture.acknowledgeOperations(operatorID, [
          { ...operation, state: "succeeded" },
        ]);
        expect(fixture.calls).toHaveLength(0);
        expect(fixture.mutation.error.value).toBe("unavailable");
        expect(sessionStorage.getItem(pendingStorage)).toBe(raw);
        // Repairing storage later must reload atomically, not use a partial map.
        sessionStorage.setItem(pendingStorage, "[]");
        await fixture.mutation.execute(
          "POST",
          `/operations/${operation.id}/dispatch`,
          {},
          operationResponse,
          boundOptions(operation),
        );
        expect(fixture.calls).toHaveLength(1);
      } finally {
        fixture.wrapper.unmount();
      }
    },
  );
  it("does not commit a valid prefix when a later entry fails validation", async () => {
    const path = `/operations/${operation.id}/dispatch`;
    const valid = {
      ...entry,
      fingerprint: await fingerprint(path, {}),
      key: operation.id,
      purpose: "dispatch",
      binding: operationBinding(operation),
    };
    const fixture = await pendingFixture(() => ({ operation }), [valid, null]);
    try {
      await fixture.mutation.execute(
        "POST",
        path,
        {},
        operationResponse,
        boundOptions(operation),
      );
      expect(fixture.calls).toHaveLength(0);
      sessionStorage.setItem(pendingStorage, "[]");
      await fixture.mutation.execute(
        "POST",
        path,
        {},
        operationResponse,
        boundOptions(operation),
      );
      expect(fixture.calls).toHaveLength(1);
    } finally {
      fixture.wrapper.unmount();
    }
  });
  it("refuses a write over the serialized budget instead of evicting unresolved entries", async () => {
    const stored = [{ ...entry, owner: "x" }];
    // A near-budget legacy record checks serialized bytes independently of count.
    stored[0]!.owner += "x".repeat(
      1024 * 1024 - JSON.stringify(stored).length - 8,
    );
    const raw = JSON.stringify(stored);
    const fixture = await pendingFixture(() => ({ operation }), stored);
    try {
      await fixture.mutation.execute(
        "POST",
        `/operations/${operation.id}/dispatch`,
        {},
        operationResponse,
        boundOptions(operation),
      );
      expect(fixture.calls).toHaveLength(0);
      expect(fixture.mutation.error.value).toBe("unavailable");
      expect(sessionStorage.getItem(pendingStorage)).toBe(raw);
    } finally {
      fixture.wrapper.unmount();
    }
  });
  it("allows an exact read acknowledgement to free capacity without sending a mutation", async () => {
    const removable = {
      ...entry,
      owner: "x",
      key: operation.id,
      purpose: "creation",
    };
    removable.owner += "x".repeat(
      1024 * 1024 - JSON.stringify([removable]).length - 8,
    );
    const fixture = await pendingFixture(() => ({ operation }), [removable]);
    try {
      fixture.acknowledgeOperations(removable.owner, [
        { ...operation, actor_id: removable.owner, state: "succeeded" },
      ]);
      expect(fixture.entries()).toEqual([]);
      expect(fixture.calls).toHaveLength(0);
      await fixture.mutation.execute(
        "POST",
        `/operations/${operation.id}/dispatch`,
        {},
        operationResponse,
        boundOptions(operation),
      );
      expect(fixture.calls).toHaveLength(1);
    } finally {
      fixture.wrapper.unmount();
    }
  });
});

describe("caller-provided idempotency keys cannot poison recovery", () => {
  it.each(["", "short", "g".repeat(32), "A".repeat(32), "a".repeat(33)])(
    "rejects explicit invalid key %j before persistence or HTTP",
    async (key) => {
      const stored = [
        {
          owner: operatorID,
          fingerprint: "1".repeat(64),
          key: "1".repeat(32),
          purpose: "other",
        },
      ];
      const fixture = await pendingFixture(() => ({ operation }), stored);
      try {
        await fixture.mutation.execute(
          "POST",
          "/instances",
          { hostname: "synthetic" },
          operationResponse,
          { key },
        );
        expect(fixture.calls).toHaveLength(0);
        expect(fixture.entries()).toEqual(stored);
        expect(fixture.mutation.error.value).toBe("invalid");
        expect(fixture.mutation.pendingKey.value).toBe("");
      } finally {
        fixture.wrapper.unmount();
      }
    },
  );
});

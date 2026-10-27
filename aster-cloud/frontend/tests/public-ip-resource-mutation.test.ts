import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { defineComponent } from "vue";
import { mount } from "@vue/test-utils";
import { webcrypto } from "node:crypto";
import { ApiError } from "../src/api/client";
import { consoleKey } from "../src/context";
import { usePublicIPResourceMutation } from "../src/composables/public-ip-resource-mutation";
import {
  vmPublicInput as input,
  vmPublicOperation as operation,
} from "./public-ip-resource-fixtures";
import { deferred, mockContext } from "./helpers";
const storage = "aster.cloud.public-ip-resource-intents.v1";
const cleanup: Array<() => void> = [];
beforeEach(() => {
  sessionStorage.clear();
  vi.stubGlobal("crypto", webcrypto);
});
afterEach(() => {
  cleanup.splice(0).forEach((f) => f());
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});
function setup(resolver: Parameters<typeof mockContext>[0]) {
  const f = mockContext(resolver);
  let mutation!: ReturnType<typeof usePublicIPResourceMutation>;
  const wrapper = mount(
    defineComponent({
      setup() {
        mutation = usePublicIPResourceMutation();
        return () => null;
      },
    }),
    { global: { provide: { [consoleKey as symbol]: f.context } } },
  );
  cleanup.push(() => wrapper.unmount());
  return { ...f, mutation, wrapper };
}
function answer(key: string, actor: string) {
  const op = {
    ...structuredClone(operation),
    id: key,
    actor_id: actor,
    resource_id: key,
    result: { resource: { ...operation.result.resource, id: key } },
  };
  return { resource: op.result.resource, operation: op, replay: false };
}
describe("VM public IP durable intent safety", () => {
  it("persists the complete request before one exact POST without the legacy NAT ledger", async () => {
    const f = setup((method, path, body, key) => {
      expect(method).toBe("POST");
      expect(path).toBe("/public-ips/resources");
      expect(JSON.parse(sessionStorage.getItem(storage)!)[0]).toMatchObject({
        owner: f.context.session.user.value!.id,
        key,
        body,
      });
      return answer(key, f.context.session.user.value!.id);
    });
    expect(
      await f.mutation.execute("resource.allocate", "", input),
    ).not.toBeNull();
    expect(f.calls).toHaveLength(1);
    expect(f.mutation.pending.value).toBeNull();
    expect(
      sessionStorage.getItem("aster.cloud.public-ip-intents.v1"),
    ).toBeNull();
  });
  it("unknown ACK survives close/remount and changed draft; only original GET can unlock", async () => {
    let key = "";
    const f = setup((_m, _p, _b, k) => {
      key = k;
      throw new ApiError("unknown");
    });
    const actor = f.context.session.user.value!.id;
    expect(await f.mutation.execute("resource.allocate", "", input)).toBeNull();
    expect(
      await f.mutation.execute("resource.allocate", "", {
        ...input,
        owner_ref: "f".repeat(32),
      }),
    ).toBeNull();
    expect(f.calls).toHaveLength(1);
    f.wrapper.unmount();
    const g = setup((method, path) => {
      expect(method).toBe("GET");
      expect(path).toBe(`/public-ips/resource-operations/${key}`);
      return { operation: answer(key, actor).operation };
    });
    expect(g.mutation.pending.value?.key).toBe(key);
    expect(await g.mutation.reconcile()).not.toBeNull();
    expect(g.calls).toHaveLength(0);
    expect(g.mutation.pending.value).toBeNull();
  });
  it.each(["actor", "request", "result", "target", "key"])(
    "foreign %s cannot resolve an unknown resource operation",
    async (kind) => {
      let key = "";
      const f = setup((m, _p, _b, k) => {
        if (m === "POST") {
          key = k;
          throw new ApiError("unknown");
        }
        const v = answer(key, f.context.session.user.value!.id).operation;
        if (kind === "actor") v.actor_id = "f".repeat(32);
        if (kind === "request") v.request.mode = "floating";
        if (kind === "result") v.result.resource.mode = "floating";
        if (kind === "target") v.target_resource_id = "f".repeat(32);
        if (kind === "key") v.id = "f".repeat(32);
        return { operation: v };
      });
      await f.mutation.execute("resource.allocate", "", input);
      expect(await f.mutation.reconcile()).toBeNull();
      expect(f.mutation.pending.value?.key).toBe(key);
      expect(f.calls).toHaveLength(1);
    },
  );
  it("corrupt storage and failed persistence block all sending", async () => {
    sessionStorage.setItem(storage, '{"corrupt":true}');
    const f = setup(() => ({}));
    expect(await f.mutation.execute("resource.allocate", "", input)).toBeNull();
    expect(f.calls).toHaveLength(0);
    sessionStorage.clear();
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw Error("blocked");
    });
    expect(await f.mutation.execute("resource.allocate", "", input)).toBeNull();
    expect(f.calls).toHaveLength(0);
  });
  it.each(["logout", "unmount", "role"])(
    "late acknowledgement after %s cannot clear original intent",
    async (kind) => {
      const gate = deferred<unknown>();
      let key = "";
      const f = setup((_m, _p, _b, k) => {
        key = k;
        return gate.promise;
      });
      const owner = f.context.session.user.value!.id;
      const promise = f.mutation.execute("resource.allocate", "", input);
      if (kind === "logout") f.context.session.invalidate();
      if (kind === "unmount") f.wrapper.unmount();
      if (kind === "role")
        f.context.session.user.value = {
          ...f.context.session.user.value!,
          permissions: ["nodes.read"],
        };
      gate.resolve(answer(key, owner));
      expect(await promise).toBeNull();
      expect(JSON.parse(sessionStorage.getItem(storage)!)).toHaveLength(1);
    },
  );
  it("known rejection is not success; both management grants are required", async () => {
    const f = setup(() => {
      throw new ApiError("forbidden");
    });
    expect(await f.mutation.execute("resource.allocate", "", input)).toBeNull();
    expect(f.mutation.pending.value).toBeNull();
    expect(f.mutation.error.value).toBe("forbidden");
    f.context.session.user.value = {
      ...f.context.session.user.value!,
      permissions: ["nodes.read", "nodes.manage"],
    };
    expect(await f.mutation.execute("resource.allocate", "", input)).toBeNull();
    expect(f.calls).toHaveLength(1);
  });
});

import { beforeEach, afterEach, describe, it, expect, vi } from "vitest";
import { defineComponent } from "vue";
import { mount } from "@vue/test-utils";
import { webcrypto } from "node:crypto";
import { consoleKey } from "../src/context";
import { ApiError } from "../src/api/client";
import { usePublicIPMutation } from "../src/composables/public-ip-mutation";
import { mockContext, deferred } from "./helpers";
import { publicOperation, publicPoolInput } from "./public-ip-fixtures";
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
  const { context, calls } = mockContext(resolver);
  let mutation!: ReturnType<typeof usePublicIPMutation>;
  const wrapper = mount(
    defineComponent({
      setup() {
        mutation = usePublicIPMutation();
        return () => null;
      },
    }),
    { global: { provide: { [consoleKey as symbol]: context } } },
  );
  cleanup.push(() => wrapper.unmount());
  return { context, calls, mutation };
}
const storage = "aster.cloud.public-ip-intents.v1";
describe("public IP persisted mutation safety", () => {
  it("persists full actor-bound intent before POST and confirms exact response", async () => {
    const f = setup((_method, _path, body, key) => {
      expect(JSON.parse(sessionStorage.getItem(storage)!)[0]).toMatchObject({
        key,
        body,
      });
      return {
        replay: false,
        operation: {
          ...publicOperation,
          id: key,
          resource_id: key,
          actor_id: f.context.session.user.value!.id,
          result: { pool: { ...publicOperation.result.pool, id: key } },
        },
      };
    });
    expect(
      await f.mutation.execute("pool.create", "", publicPoolInput),
    ).not.toBeNull();
    expect(f.calls).toHaveLength(1);
    expect(JSON.parse(sessionStorage.getItem(storage)!)).toEqual([]);
  });
  it("lost ACK survives remount and edited form, GET verifies only original operation", async () => {
    let key = "",
      owner = "";
    const f = setup((method, _path, _body, actual) => {
      if (method === "POST") {
        key = actual;
        throw new ApiError("unknown");
      }
      return {
        operation: {
          ...publicOperation,
          id: key,
          resource_id: key,
          actor_id: owner,
          result: { pool: { ...publicOperation.result.pool, id: key } },
        },
      };
    });
    owner = f.context.session.user.value!.id;
    expect(
      await f.mutation.execute("pool.create", "", publicPoolInput),
    ).toBeNull();
    expect(f.mutation.pending.value?.key).toBe(key);
    expect(
      await f.mutation.execute("pool.create", "", {
        ...publicPoolInput,
        name: "edited",
      }),
    ).toBeNull();
    expect(f.calls).toHaveLength(1);
    const g = setup(async (method, path, _body, _actual) => {
      expect(method).toBe("GET");
      expect(path).toBe(`/public-ips/operations/${key}`);
      return {
        operation: {
          ...publicOperation,
          id: key,
          resource_id: key,
          actor_id: owner,
          result: { pool: { ...publicOperation.result.pool, id: key } },
        },
      };
    });
    expect(g.mutation.pending.value?.key).toBe(key);
    expect(await g.mutation.reconcile()).not.toBeNull();
    expect(g.calls).toHaveLength(0);
    expect(g.mutation.pending.value).toBeNull();
  });
  it.each(["actor", "body", "key", "target", "result"])(
    "foreign %s never clears an unknown intent",
    async (caseName) => {
      let key = "";
      const f = setup((method, _path, _body, k) => {
        if (method === "POST") {
          key = k;
          throw new ApiError("unknown");
        }
        const op = {
          ...structuredClone(publicOperation),
          id: key,
          resource_id: key,
          actor_id: f.context.session.user.value!.id,
          result: { pool: { ...publicOperation.result.pool, id: key } },
        };
        if (caseName === "actor") op.actor_id = "f".repeat(32);
        if (caseName === "body") op.request.name = "foreign";
        if (caseName === "key") op.id = "f".repeat(32);
        if (caseName === "target") op.target_resource_id = "f".repeat(32);
        if (caseName === "result") op.result.pool.name = "foreign";
        return { operation: op };
      });
      await f.mutation.execute("pool.create", "", publicPoolInput);
      expect(await f.mutation.reconcile()).toBeNull();
      expect(f.mutation.pending.value?.key).toBe(key);
      expect(f.calls).toHaveLength(1);
    },
  );
  it("storage corruption blocks sending and is not silently erased", async () => {
    sessionStorage.setItem(storage, '{"broken":true}');
    const f = setup(() => ({}));
    expect(
      await f.mutation.execute("pool.create", "", publicPoolInput),
    ).toBeNull();
    expect(f.calls).toHaveLength(0);
    expect(sessionStorage.getItem(storage)).toBe('{"broken":true}');
  });
  it("storage failure blocks sending", async () => {
    const f = setup(() => ({}));
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw Error("denied");
    });
    expect(
      await f.mutation.execute("pool.create", "", publicPoolInput),
    ).toBeNull();
    expect(f.calls).toHaveLength(0);
  });
  it("known forbidden response is not success and does not retain an ambiguous POST", async () => {
    const f = setup(() => {
      throw new ApiError("forbidden");
    });
    expect(
      await f.mutation.execute("pool.create", "", publicPoolInput),
    ).toBeNull();
    expect(f.mutation.error.value).toBe("forbidden");
    expect(f.mutation.pending.value).toBeNull();
  });
  it("late response after logout cannot acknowledge another identity", async () => {
    const gate = deferred<unknown>();
    let key = "";
    const f = setup((_method, _path, _body, k) => {
      key = k;
      return gate.promise;
    });
    const owner = f.context.session.user.value!.id;
    const promise = f.mutation.execute("pool.create", "", publicPoolInput);
    f.context.session.invalidate();
    gate.resolve({
      replay: false,
      operation: {
        ...publicOperation,
        id: key,
        resource_id: key,
        actor_id: owner,
        result: { pool: { ...publicOperation.result.pool, id: key } },
      },
    });
    expect(await promise).toBeNull();
    expect(JSON.parse(sessionStorage.getItem(storage)!)).toHaveLength(1);
  });
  it("requires both management permissions", async () => {
    const f = setup(() => ({}));
    f.context.session.user.value!.permissions = ["nodes.read", "nodes.manage"];
    expect(
      await f.mutation.execute("pool.create", "", publicPoolInput),
    ).toBeNull();
    expect(f.calls).toHaveLength(0);
  });
});

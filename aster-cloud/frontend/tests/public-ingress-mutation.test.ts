import { afterEach, beforeEach, describe, it, expect, vi } from "vitest";
import { defineComponent } from "vue";
import { mount } from "@vue/test-utils";
import { webcrypto } from "node:crypto";
import { ApiError } from "../src/api/client";
import { consoleKey } from "../src/context";
import { usePublicIngressMutation } from "../src/composables/public-ingress-mutation";
import {
  ingressPolicy,
  ingressRequest,
  ingressOperation,
} from "./public-ingress-fixtures";
import { mockContext } from "./helpers";
const storage = "aster.cloud.public-ingress-intents.v1";
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
  let mutation!: ReturnType<typeof usePublicIngressMutation>;
  const wrapper = mount(
    defineComponent({
      setup() {
        mutation = usePublicIngressMutation();
        return () => null;
      },
    }),
    { global: { provide: { [consoleKey as symbol]: f.context } } },
  );
  cleanup.push(() => wrapper.unmount());
  return { ...f, mutation, wrapper };
}
describe("durable public ingress intent", () => {
  it("persists exact target/version/rules before one POST and accepts only fixed ACK", async () => {
    const f = setup((method, path, body, key) => {
      expect(method).toBe("POST");
      expect(path).toBe(
        `/instances/${ingressPolicy.instance_id}/public-ingress`,
      );
      expect(JSON.parse(sessionStorage.getItem(storage)!)[0]).toMatchObject({
        owner: f.context.session.user.value!.id,
        key,
        target: ingressPolicy.instance_id,
        action: "public_ingress.update",
        body,
      });
      const op = ingressOperation(key, f.context.session.user.value!.id);
      return { policy: op.result.policy, operation: op, replay: false };
    });
    expect(
      await f.mutation.execute(ingressPolicy.instance_id, ingressRequest),
    ).not.toBeNull();
    expect(f.calls).toHaveLength(1);
    expect(f.mutation.pending.value).toBeNull();
  });
  it("lost ACK survives remount; a different target/rule never causes a new key or POST", async () => {
    let key = "";
    const f = setup((_m, _p, _b, k) => {
      key = k;
      throw new ApiError("unknown");
    });
    const actor = f.context.session.user.value!.id;
    expect(
      await f.mutation.execute(ingressPolicy.instance_id, ingressRequest),
    ).toBeNull();
    expect(
      await f.mutation.execute("f".repeat(32), {
        expected_revision: 0,
        rules: [],
      }),
    ).toBeNull();
    expect(f.calls).toHaveLength(1);
    f.wrapper.unmount();
    const g = setup((method, path) => {
      expect(method).toBe("GET");
      expect(path).toBe(`/public-ingress-operations/${key}`);
      return { operation: ingressOperation(key, actor) };
    });
    expect(g.mutation.pending.value?.key).toBe(key);
    expect(await g.mutation.reconcile()).not.toBeNull();
    expect(g.calls).toHaveLength(0);
    expect(g.mutation.pending.value).toBeNull();
  });
  it.each(["actor", "target", "rules", "revision", "result"])(
    "foreign %s does not unlock unknown intent",
    async (kind) => {
      let key = "";
      const f = setup((m, _p, _b, k) => {
        if (m === "POST") {
          key = k;
          throw new ApiError("unknown");
        }
        const op = ingressOperation(key, f.context.session.user.value!.id);
        if (kind === "actor") op.actor_id = "f".repeat(32);
        if (kind === "target") op.target_instance_id = "f".repeat(32);
        if (kind === "rules") op.request.rules = [];
        if (kind === "revision") op.request.expected_revision = 1;
        if (kind === "result") op.result.policy.rules = [];
        return { operation: op };
      });
      await f.mutation.execute(ingressPolicy.instance_id, ingressRequest);
      expect(await f.mutation.reconcile()).toBeNull();
      expect(f.mutation.pending.value?.key).toBe(key);
      expect(f.calls).toHaveLength(1);
    },
  );
  it("corrupt or unavailable storage blocks sending", async () => {
    sessionStorage.setItem(storage, "{}");
    const f = setup(() => ({}));
    expect(
      await f.mutation.execute(ingressPolicy.instance_id, ingressRequest),
    ).toBeNull();
    expect(f.calls).toHaveLength(0);
    sessionStorage.clear();
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw Error("quota");
    });
    expect(
      await f.mutation.execute(ingressPolicy.instance_id, ingressRequest),
    ).toBeNull();
    expect(f.calls).toHaveLength(0);
  });
});

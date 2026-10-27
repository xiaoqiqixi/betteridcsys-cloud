import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { defineComponent, h } from "vue";
import { mount } from "@vue/test-utils";
import { webcrypto } from "node:crypto";
import { deferred } from "./helpers";
const pendingStorage = "aster.cloud.pending.v1";
const key = "e".repeat(32);
const vpcBody = {
  owner_ref: "2".repeat(32),
  node_id: "node-a",
  name: "网络甲",
  cidr: "10.20.0.0/24",
  vlan_id: 42,
};
const vpc = {
  ...vpcBody,
  id: key,
  state: "planned",
  created_at: "2026-10-23T00:00:00Z",
};
const poolBody = {
  node_id: "node-a",
  vpc_id: "1".repeat(32),
  name: "地址池甲",
  cidr: "10.20.0.0/24",
  gateway: "10.20.0.1",
  addresses: ["10.20.0.3", "10.20.0.2"],
  enabled: true,
};
const cleanups: Array<() => void> = [];
beforeEach(() => {
  vi.resetModules();
  sessionStorage.clear();
  vi.stubGlobal("crypto", webcrypto);
});
afterEach(() => {
  cleanups.splice(0).forEach((fn) => fn());
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

async function fixture() {
  const [module, { consoleKey }, { mockContext }, client, network] =
    await Promise.all([
      import("../src/composables/mutation"),
      import("../src/context"),
      import("./helpers"),
      import("../src/api/client"),
      import("../src/api/network"),
    ]);
  const { context, calls } = mockContext(() => {
    throw new client.ApiError("unknown");
  });
  let mutation!: ReturnType<typeof module.useMutation>;
  const wrapper = mount(
    defineComponent({
      setup() {
        mutation = module.useMutation();
        return () => h("div");
      },
    }),
    { global: { provide: { [consoleKey as symbol]: context } } },
  );
  cleanups.push(() => wrapper.unmount());
  const entries = () =>
    JSON.parse(sessionStorage.getItem(pendingStorage) || "[]") as Array<
      Record<string, unknown>
    >;
  async function send(kind = "vpcs", body: unknown = vpcBody, id = key) {
    return mutation.execute(
      "POST",
      `/networks/${kind}`,
      body,
      (v): v is Record<string, unknown> => client.record(v),
      { key: id },
    );
  }
  return { ...module, ...network, context, calls, mutation, entries, send };
}

describe("network pending recovery never trusts an ID alone", () => {
  it.each(["owner", "key", "payload", "returned-field", "kind"])(
    "does not clear pending when %s changes",
    async (change) => {
      const f = await fixture();
      await f.send();
      const owner = f.context.session.user.value!.id;
      const body =
        change === "payload" ? { ...vpcBody, name: "changed" } : vpcBody;
      const value =
        change === "payload"
          ? { ...vpc, name: "changed" }
          : change === "returned-field"
            ? { ...vpc, owner_ref: "f".repeat(32) }
            : change === "key"
              ? { ...vpc, id: "d".repeat(32) }
              : vpc;
      const got = await f.acknowledgeNetwork(
        change === "owner" ? "9".repeat(32) : owner,
        change === "kind" ? "pools" : "vpcs",
        body,
        change === "key" ? "d".repeat(32) : key,
        value,
        () => true,
      );
      expect(got).toBe(false);
      expect(f.entries()).toHaveLength(1);
      await f.send();
      expect(f.calls).toHaveLength(1);
      expect(f.mutation.pendingKey.value).toBe(key);
    },
  );
  it("clears only the exact same owner/key/full payload after a read", async () => {
    const f = await fixture();
    await f.send();
    expect(
      await f.acknowledgeNetwork(
        f.context.session.user.value!.id,
        "vpcs",
        vpcBody,
        key,
        vpc,
        () => true,
      ),
    ).toBe(true);
    expect(f.entries()).toHaveLength(0);
    expect(f.calls).toHaveLength(1);
  });
  it("retains the old entry when acknowledgement storage persistence fails", async () => {
    const f = await fixture();
    await f.send();
    const stored = sessionStorage.getItem(pendingStorage);
    const setter = vi
      .spyOn(Storage.prototype, "setItem")
      .mockImplementation(() => {
        throw new DOMException("unwritable", "QuotaExceededError");
      });
    expect(
      await f.acknowledgeNetwork(
        f.context.session.user.value!.id,
        "vpcs",
        vpcBody,
        key,
        vpc,
        () => true,
      ),
    ).toBe(false);
    expect(sessionStorage.getItem(pendingStorage)).toBe(stored);
    setter.mockRestore();
    await f.send();
    expect(f.calls).toHaveLength(1);
    expect(f.mutation.pendingKey.value).toBe(key);
  });
  it("rechecks current identity after asynchronous hashing before clearing", async () => {
    const f = await fixture();
    await f.send();
    const original = String(f.entries()[0]!.fingerprint);
    const wait = deferred<ArrayBuffer>();
    const digest = vi
      .spyOn(crypto.subtle, "digest")
      .mockReturnValueOnce(wait.promise);
    let current = true;
    const pending = f.acknowledgeNetwork(
      f.context.session.user.value!.id,
      "vpcs",
      vpcBody,
      key,
      vpc,
      () => current,
    );
    expect(digest).toHaveBeenCalledOnce();
    current = false;
    wait.resolve(
      Uint8Array.from(original.match(/../g)!.map((part) => parseInt(part, 16)))
        .buffer,
    );
    expect(await pending).toBe(false);
    expect(f.entries()).toHaveLength(1);
  });
  it("does not generate a new POST for a reordered set of the same pool addresses", async () => {
    const f = await fixture();
    await f.send("pools", poolBody);
    await f.send(
      "pools",
      { ...poolBody, addresses: [...poolBody.addresses].reverse() },
      "f".repeat(32),
    );
    expect(f.calls).toHaveLength(1);
    expect(f.mutation.pendingKey.value).toBe(key);
    expect(f.entries()).toHaveLength(1);
  });
});

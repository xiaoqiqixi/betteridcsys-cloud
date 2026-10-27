import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mount } from "@vue/test-utils";
import { defineComponent } from "vue";
import { ApiError, record } from "../src/api/client";
import { consoleKey } from "../src/context";
import { useOverlayMutation } from "../src/composables/overlay-mutation";
import { admin } from "./fixtures";
import { deferred, mockContext } from "./helpers";
import { overlayNAT, overlayVPC } from "./overlay-fixtures";

const storageKey = "aster.cloud.overlay-intents.v1";
const budget = 1024 * 1024;
const key = "d".repeat(32);
const cleanups: Array<() => void> = [];
const epochBody = (cluster = "cluster-east") => ({
  cluster_id: cluster,
  expected_epoch: 0,
  members: [],
  gateways: [],
});
const existing = () => ({
  owner: admin.id,
  scope: "epoch:other:0",
  path: "/overlays/epochs",
  key: "e".repeat(32),
  body: epochBody("other"),
});
const accepted = (value: unknown, expected: string): value is { id: string } =>
  record(value) && value.id === expected;
function setup(
  scope = "epoch:cluster-east:0",
  resolver: Parameters<typeof mockContext>[0] = (
    _method,
    _path,
    _body,
    id,
  ) => ({
    id,
  }),
) {
  const { context, calls } = mockContext(resolver);
  let mutation!: ReturnType<typeof useOverlayMutation>;
  const wrapper = mount(
    defineComponent({
      setup() {
        mutation = useOverlayMutation(() => scope);
        return () => null;
      },
    }),
    { global: { provide: { [consoleKey as symbol]: context } } },
  );
  cleanups.push(() => wrapper.unmount());
  return { mutation, context, calls };
}
beforeEach(() => sessionStorage.clear());
afterEach(() => {
  cleanups
    .splice(0)
    .reverse()
    .forEach((dispose) => dispose());
  vi.restoreAllMocks();
});

describe("overlay durable intent validation", () => {
  it.each([
    ["non-object body", "/overlays/epochs", "epoch:cluster-east:0", null, key],
    [
      "invalid selection",
      "/overlays/epochs",
      "epoch:cluster-east:0",
      { ...epochBody(), members: "bad" },
      key,
    ],
    ["wrong scope", "/overlays/epochs", "epoch:different:0", epochBody(), key],
    [
      "wrong path",
      "/overlays/unsupported",
      "epoch:cluster-east:0",
      epochBody(),
      key,
    ],
    [
      "invalid NAT",
      "/overlays/epochs",
      "epoch:cluster-east:0",
      {
        ...epochBody(),
        nat_policies: [{ ...overlayNAT, snat_enabled: "yes" }],
      },
      key,
    ],
    [
      "invalid VPC",
      "/overlays/vpcs",
      "vpc:cluster-east",
      { ...overlayVPC, cidr: "0.0.0.0/0" },
      key,
    ],
    [
      "invalid recovery hash",
      `/overlays/epochs/${key}/recover`,
      "epoch:cluster-east:1",
      { expected_snapshot_sha256: "bad" },
      key,
    ],
    [
      "invalid recovery selection",
      `/overlays/epochs/${key}/recover`,
      "epoch:cluster-east:1",
      {
        expected_snapshot_sha256: "f".repeat(64),
        replacement: { members: [], gateways: "bad" },
      },
      key,
    ],
    [
      "nonempty advance body",
      `/overlays/epochs/${key}/advance`,
      `advance:${key}`,
      { changed: true },
      key,
    ],
    [
      "mismatched reconcile key",
      `/overlays/epochs/${key}/reconcile`,
      `reconcile:${key}`,
      {},
      "f".repeat(32),
    ],
    [
      "invalid key",
      "/overlays/epochs",
      "epoch:cluster-east:0",
      epochBody(),
      "invalid",
    ],
  ] as const)(
    "rejects %s before storage or POST",
    async (_name, path, scope, payload, requestKey) => {
      const original = JSON.stringify([existing()]);
      sessionStorage.setItem(storageKey, original);
      const { mutation, calls } = setup(scope);
      const writes = vi.spyOn(Storage.prototype, "setItem");
      expect(
        await mutation.execute(path, payload, accepted, () => true, {
          key: requestKey,
        }),
      ).toBeNull();
      expect(calls).toHaveLength(0);
      expect(writes).not.toHaveBeenCalled();
      expect(sessionStorage.getItem(storageKey)).toBe(original);
      expect(mutation.pending.value).toBeNull();
      expect(mutation.error.value).toBe("invalid");
      expect(mutation.busy.value).toBe(false);
    },
  );

  it("does not accept an empty string as an absent ledger", async () => {
    sessionStorage.setItem(storageKey, "");
    const { mutation, calls } = setup();
    expect(mutation.error.value).toBe("unavailable");
    expect(
      await mutation.execute(
        "/overlays/epochs",
        epochBody(),
        accepted,
        () => true,
        { key },
      ),
    ).toBeNull();
    expect(calls).toHaveLength(0);
    expect(sessionStorage.getItem(storageKey)).toBe("");
    expect(mutation.error.value).toBe("unavailable");
  });

  it("persists a valid full intent before one POST and removes only its confirmed entry", async () => {
    const prior = existing();
    sessionStorage.setItem(storageKey, JSON.stringify([prior]));
    const response = deferred<{ id: string }>();
    const { mutation, calls } = setup(
      undefined,
      (_method, path, payload, id) => {
        expect(JSON.parse(sessionStorage.getItem(storageKey)!)).toEqual([
          prior,
          {
            owner: admin.id,
            scope: "epoch:cluster-east:0",
            path,
            key: id,
            body: payload,
          },
        ]);
        return response.promise;
      },
    );
    const request = mutation.execute(
      "/overlays/epochs",
      epochBody(),
      accepted,
      () => true,
      { key },
    );
    expect(calls).toHaveLength(1);
    expect(mutation.pendingKey.value).toBe(key);
    expect(mutation.busy.value).toBe(true);
    response.resolve({ id: key });
    expect(await request).toEqual({ id: key });
    expect(JSON.parse(sessionStorage.getItem(storageKey)!)).toEqual([prior]);
    expect(mutation.pending.value).toBeNull();
    expect(mutation.error.value).toBe("");
  });

  it.each(["/advance", "/reconcile"])(
    "accepts a valid %s intent with the original key",
    async (action) => {
      const { mutation, calls } = setup(`${action.slice(1)}:${key}`);
      expect(
        await mutation.execute(
          `/overlays/epochs/${key}${action}`,
          {},
          accepted,
          () => true,
          { key },
        ),
      ).toEqual({ id: key });
      expect(calls).toHaveLength(1);
      expect(calls[0]!.key).toBe(key);
    },
  );

  it("keeps an uncertain valid intent across reload and blocks a replacement POST", async () => {
    const f = setup(undefined, () => {
      throw new ApiError("unknown");
    });
    expect(
      await f.mutation.execute(
        "/overlays/epochs",
        epochBody(),
        accepted,
        () => true,
        { key },
      ),
    ).toBeNull();
    const original = sessionStorage.getItem(storageKey);
    const resumed = setup();
    expect(resumed.mutation.pendingKey.value).toBe(key);
    expect(
      await resumed.mutation.execute(
        "/overlays/epochs",
        epochBody(),
        accepted,
        () => true,
        { key: "f".repeat(32) },
      ),
    ).toBeNull();
    expect(resumed.calls).toHaveLength(0);
    expect(sessionStorage.getItem(storageKey)).toBe(original);
    expect(resumed.mutation.error.value).toBe("unknown");
  });

  it("does not POST or expose an unpersisted intent when browser storage is full", async () => {
    const original = JSON.stringify([existing()]);
    sessionStorage.setItem(storageKey, original);
    const { mutation, calls } = setup();
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new DOMException("full", "QuotaExceededError");
    });
    expect(
      await mutation.execute(
        "/overlays/epochs",
        epochBody(),
        accepted,
        () => true,
        { key },
      ),
    ).toBeNull();
    expect(calls).toHaveLength(0);
    expect(sessionStorage.getItem(storageKey)).toBe(original);
    expect(mutation.pending.value).toBeNull();
    expect(mutation.error.value).toBe("unavailable");
  });

  it("does not report confirmation if its persisted intent cannot be removed", async () => {
    let original = "";
    const { mutation, calls } = setup(
      undefined,
      (_method, _path, _body, id) => {
        original = sessionStorage.getItem(storageKey)!;
        vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
          throw new DOMException("full", "QuotaExceededError");
        });
        return { id };
      },
    );
    expect(
      await mutation.execute(
        "/overlays/epochs",
        epochBody(),
        accepted,
        () => true,
        { key },
      ),
    ).toBeNull();
    expect(calls).toHaveLength(1);
    expect(sessionStorage.getItem(storageKey)).toBe(original);
    expect(mutation.pendingKey.value).toBe(key);
    expect(mutation.error.value).toBe("unknown");
  });
});

describe("overlay raw storage budget", () => {
  it.each([
    ["ASCII", "[]" + " ".repeat(budget - 1)],
    ["UTF-8", JSON.stringify(["界".repeat(Math.floor(budget / 3))])],
  ])(
    "rejects over-budget %s before JSON parsing without erasing storage",
    async (_name, raw) => {
      expect(new TextEncoder().encode(raw!).byteLength).toBeGreaterThan(budget);
      sessionStorage.setItem(storageKey, raw!);
      const parse = vi.spyOn(JSON, "parse");
      const { mutation, calls } = setup();
      expect(mutation.error.value).toBe("unavailable");
      expect(
        await mutation.execute(
          "/overlays/epochs",
          epochBody(),
          accepted,
          () => true,
          { key },
        ),
      ).toBeNull();
      expect(calls).toHaveLength(0);
      expect(parse.mock.calls.some(([value]) => value === raw)).toBe(false);
      expect(sessionStorage.getItem(storageKey)).toBe(raw);
    },
  );

  it("accepts an exactly 1 MiB valid raw ledger", async () => {
    const raw = "[]" + " ".repeat(budget - 2);
    sessionStorage.setItem(storageKey, raw);
    const { mutation, calls } = setup();
    expect(mutation.error.value).toBe("");
    expect(
      await mutation.execute(
        "/overlays/epochs",
        epochBody(),
        accepted,
        () => true,
        { key },
      ),
    ).toEqual({ id: key });
    expect(calls).toHaveLength(1);
  });

  it("refuses a valid append over the byte budget without losing prior intent", async () => {
    const large = {
      ...epochBody("other"),
      nat_policies: Array.from({ length: 32 }, (_, policy) => ({
        ...overlayNAT,
        id: policy.toString(16).padStart(32, "0"),
        forwardings: Array.from({ length: 128 }, (_, rule) => ({
          ...overlayNAT.forwardings[0]!,
          id: rule.toString(16).padStart(32, "0"),
        })),
      })),
    };
    const prior = { ...existing(), body: large };
    const original = JSON.stringify([prior]);
    expect(new TextEncoder().encode(original).byteLength).toBeLessThan(budget);
    expect(
      new TextEncoder().encode(JSON.stringify([prior, prior])).byteLength,
    ).toBeGreaterThan(budget);
    sessionStorage.setItem(storageKey, original);
    const { mutation, calls } = setup();
    const writes = vi.spyOn(Storage.prototype, "setItem");
    expect(
      await mutation.execute(
        "/overlays/epochs",
        { ...large, cluster_id: "cluster-east" },
        accepted,
        () => true,
        { key },
      ),
    ).toBeNull();
    expect(calls).toHaveLength(0);
    expect(writes).not.toHaveBeenCalled();
    expect(sessionStorage.getItem(storageKey)).toBe(original);
    expect(mutation.pending.value).toBeNull();
    expect(mutation.error.value).toBe("unavailable");
  });
});

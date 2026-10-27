import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { defineComponent } from "vue";
import { mount } from "@vue/test-utils";
import { webcrypto } from "node:crypto";
import { ApiError } from "../src/api/client";
import { consoleKey } from "../src/context";
import { usePublicIPMutation } from "../src/composables/public-ip-mutation";
import { usePublicIPResourceMutation } from "../src/composables/public-ip-resource-mutation";
import { usePublicIngressMutation } from "../src/composables/public-ingress-mutation";
import type { PublicIngressRequest } from "../src/api/public-ingress";
import { publicPoolInput } from "./public-ip-fixtures";
import { vmPublicInput } from "./public-ip-resource-fixtures";
import {
  ingressPolicy,
  ingressRequest,
  ingressRule,
} from "./public-ingress-fixtures";
import { mockContext } from "./helpers";

const budget = 1024 * 1024;
const byteLength = (raw: string) => new TextEncoder().encode(raw).byteLength;
const cleanup: Array<() => void> = [];
const variants = [
  {
    name: "public IP inventory",
    storage: "aster.cloud.public-ip-intents.v1",
    action: "pool.create",
    target: "",
    body: publicPoolInput,
    create() {
      const mutation = usePublicIPMutation();
      return {
        ...mutation,
        run: () => mutation.execute("pool.create", "", publicPoolInput),
      };
    },
  },
  {
    name: "public IP resource",
    storage: "aster.cloud.public-ip-resource-intents.v1",
    action: "resource.allocate",
    target: "",
    body: vmPublicInput,
    create() {
      const mutation = usePublicIPResourceMutation();
      return {
        ...mutation,
        run: () => mutation.execute("resource.allocate", "", vmPublicInput),
      };
    },
  },
  {
    name: "public ingress",
    storage: "aster.cloud.public-ingress-intents.v1",
    action: "public_ingress.update",
    target: ingressPolicy.instance_id,
    body: ingressRequest,
    create(body: PublicIngressRequest = ingressRequest) {
      const mutation = usePublicIngressMutation();
      return {
        ...mutation,
        run: () => mutation.execute(ingressPolicy.instance_id, body),
      };
    },
  },
] as const;
type Variant = (typeof variants)[number];
function setup(variant: Variant, largeIngress?: PublicIngressRequest) {
  const f = mockContext(() => {
    throw new ApiError("unknown");
  });
  let mutation!: ReturnType<Variant["create"]>;
  const wrapper = mount(
    defineComponent({
      setup() {
        mutation = variant.create(largeIngress);
        return () => null;
      },
    }),
    { global: { provide: { [consoleKey as symbol]: f.context } } },
  );
  cleanup.push(() => wrapper.unmount());
  return { ...f, mutation };
}
function intent(variant: Variant, index = 0) {
  return {
    owner: index.toString(16).padStart(32, "0"),
    key: "d".repeat(32),
    action: variant.action,
    target: variant.target,
    body: structuredClone(variant.body),
  };
}
beforeEach(() => {
  sessionStorage.clear();
  vi.stubGlobal("crypto", webcrypto);
});
afterEach(() => {
  cleanup
    .splice(0)
    .reverse()
    .forEach((f) => f());
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe.each(variants)("$name persistent storage boundary", (variant) => {
  it("rejects empty storage without replacing it or POSTing", async () => {
    sessionStorage.setItem(variant.storage, "");
    const { mutation, calls } = setup(variant);
    const writes = vi.spyOn(Storage.prototype, "setItem");
    expect(mutation.error.value).toBe("unavailable");
    expect(await mutation.run()).toBeNull();
    expect(calls).toHaveLength(0);
    expect(writes).not.toHaveBeenCalled();
    expect(sessionStorage.getItem(variant.storage)).toBe("");
  });

  it.each([
    ["ASCII", "[]" + " ".repeat(budget - 1)],
    ["UTF-8", JSON.stringify(["界".repeat(Math.floor(budget / 3))])],
  ])(
    "rejects oversized %s before parsing and preserves every byte",
    async (_name, raw) => {
      expect(byteLength(raw!)).toBeGreaterThan(budget);
      sessionStorage.setItem(variant.storage, raw!);
      const parse = vi.spyOn(JSON, "parse");
      const { mutation, calls } = setup(variant);
      const writes = vi.spyOn(Storage.prototype, "setItem");
      expect(mutation.error.value).toBe("unavailable");
      expect(await mutation.run()).toBeNull();
      expect(calls).toHaveLength(0);
      expect(writes).not.toHaveBeenCalled();
      expect(parse.mock.calls.some(([value]) => value === raw)).toBe(false);
      expect(sessionStorage.getItem(variant.storage)).toBe(raw);
    },
  );

  it.each([null, "[]" + " ".repeat(budget - 2)])(
    "accepts absent or exactly budget-sized valid storage (%#)",
    async (raw) => {
      if (raw !== null) sessionStorage.setItem(variant.storage, raw);
      const { mutation, calls } = setup(variant);
      expect(mutation.error.value).toBe("");
      expect(await mutation.run()).toBeNull();
      expect(calls).toHaveLength(1);
      expect(mutation.error.value).toBe("unknown");
      expect(mutation.pending.value?.key).toBe(calls[0]!.key);
      const original = sessionStorage.getItem(variant.storage);
      const resumed = setup(variant);
      expect(resumed.mutation.pending.value?.key).toBe(calls[0]!.key);
      expect(await resumed.mutation.run()).toBeNull();
      expect(resumed.calls).toHaveLength(0);
      expect(sessionStorage.getItem(variant.storage)).toBe(original);
    },
  );

  it("preserves existing intents and does not POST when browser quota rejects a write", async () => {
    const original = JSON.stringify([intent(variant)]);
    sessionStorage.setItem(variant.storage, original);
    const { mutation, calls } = setup(variant);
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new DOMException("full", "QuotaExceededError");
    });
    expect(await mutation.run()).toBeNull();
    expect(calls).toHaveLength(0);
    expect(mutation.pending.value).toBeNull();
    expect(mutation.error.value).toBe("unavailable");
    expect(sessionStorage.getItem(variant.storage)).toBe(original);
  });

  it("retains the original 128-owner limit without evicting a record", async () => {
    const original = JSON.stringify(
      Array.from({ length: 128 }, (_, i) => intent(variant, i)),
    );
    sessionStorage.setItem(variant.storage, original);
    const { mutation, calls } = setup(variant);
    expect(mutation.error.value).toBe("");
    expect(await mutation.run()).toBeNull();
    expect(calls).toHaveLength(0);
    expect(sessionStorage.getItem(variant.storage)).toBe(original);
  });

  it("rejects a compact append beyond the byte budget before writing or sending", async () => {
    let original: string;
    let largeIngress: PublicIngressRequest | undefined;
    if (variant.action === "public_ingress.update") {
      largeIngress = {
        expected_revision: Number.MAX_SAFE_INTEGER - 1,
        rules: Array.from({ length: 64 }, (_, i) => ({
          ...ingressRule,
          id: i.toString(16).padStart(32, "0"),
          source_cidr: "223.255.255.255/32",
          port_start: 65000 + i,
          port_end: 65000 + i,
        })),
      };
      const entries = [];
      for (let i = 0; ; i++) {
        const next = { ...intent(variant, i), body: largeIngress };
        if (byteLength(JSON.stringify([...entries, next])) > budget) break;
        entries.push(next);
      }
      expect(entries.length).toBeLessThan(128);
      original = JSON.stringify(entries);
    } else {
      // These two legacy readers accept unrecognized top-level metadata.
      // Preserve it: do not tighten their existing intent schema in this fix.
      const prior = { ...intent(variant), legacy_metadata: "" };
      prior.legacy_metadata = "x".repeat(
        budget - byteLength(JSON.stringify([prior])),
      );
      original = JSON.stringify([prior]);
    }
    expect(byteLength(original)).toBeLessThanOrEqual(budget);
    sessionStorage.setItem(variant.storage, original);
    const { mutation, calls } = setup(variant, largeIngress);
    expect(mutation.error.value).toBe("");
    const writes = vi.spyOn(Storage.prototype, "setItem");
    expect(await mutation.run()).toBeNull();
    expect(calls).toHaveLength(0);
    expect(writes).not.toHaveBeenCalled();
    expect(mutation.pending.value).toBeNull();
    expect(mutation.error.value).toBe("unavailable");
    expect(sessionStorage.getItem(variant.storage)).toBe(original);
  });
});

import { beforeEach, afterEach, describe, it, expect, vi } from "vitest";
import { defineComponent } from "vue";
import { mount } from "@vue/test-utils";
import { webcrypto } from "node:crypto";
import { ApiError } from "../src/api/client";
import {
  identityWriteResponse,
  publicIdentityIntent,
  validIdentityOperation,
  type IdentityOperation,
} from "../src/api/identity";
import {
  IdentityLedger,
  identityStorageKey,
  type PendingIdentity,
} from "../src/composables/identity-ledger";
import { useIdentityMutation } from "../src/composables/identity-mutation";
import { consoleKey } from "../src/context";
import { admin } from "./fixtures";
import { deferred, mockContext } from "./helpers";

const target = {
  ...admin,
  id: "a".repeat(32),
  email: "target@example.invalid",
  role: "viewer",
  permissions: ["instances.read"],
};
const body = {
  revision: 1,
  name: "Edited member",
  reason: "Routine account correction",
};
const entry = (i = 0): PendingIdentity => ({
  owner: admin.id,
  key: (i + 1).toString(16).padStart(32, "0"),
  action: "identity.user_updated",
  target: (i + 100).toString(16).padStart(32, "0"),
  target_email: `target${i}@example.invalid`,
  intent: publicIdentityIntent(body)!,
});
function receipt(p: PendingIdentity): IdentityOperation {
  return {
    id: p.key,
    actor_id: p.owner,
    target_id: p.action === "identity.user_created" ? target.id : p.target,
    action: p.action,
    base_revision: p.intent.revision,
    result_revision: p.intent.revision + 1,
    intent: structuredClone(p.intent),
    request_sha256: "d".repeat(64),
    reason: p.intent.reason,
    audit_id: "9007199254740993",
    completed_at: "2026-10-26T10:00:00.123456Z",
  };
}
function success(key: string, input: unknown) {
  const p = {
    ...entry(),
    key,
    target: target.id,
    intent: publicIdentityIntent(input)!,
  };
  return {
    user: { ...target, name: (input as typeof body).name, revision: 2 },
    operation: receipt(p),
  };
}
const cleanups: (() => void)[] = [];
beforeEach(() => {
  sessionStorage.clear();
  vi.stubGlobal("crypto", webcrypto);
});
afterEach(() => {
  cleanups.splice(0).forEach((f) => f());
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});
function setup(resolver: Parameters<typeof mockContext>[0]) {
  const fake = mockContext(resolver);
  let mutation!: ReturnType<typeof useIdentityMutation>;
  const w = mount(
    defineComponent({
      setup() {
        mutation = useIdentityMutation();
        return () => null;
      },
    }),
    { global: { provide: { [consoleKey as symbol]: fake.context } } },
  );
  cleanups.push(() => w.unmount());
  return { ...fake, mutation };
}
describe("identity receipt protocol", () => {
  it("checks every public field and never stores password contents or a credential digest", () => {
    const input = { ...body, password: "Private-only-secret-123!" };
    const p = { ...entry(), intent: publicIdentityIntent(input)! };
    const op = receipt(p);
    expect(validIdentityOperation(op)).toBe(true);
    expect(JSON.stringify(p)).not.toContain(input.password);
    expect(p.intent.password_changed).toBe(true);
    expect(
      publicIdentityIntent({ ...input, reason: input.password }),
    ).toBeNull();
    expect(publicIdentityIntent({ ...body, token: "secret" })).toBeNull();
    for (const bad of [
      { ...op, audit_id: 9007199254740993 },
      { ...op, result_revision: 3 },
      { ...op, intent: { ...op.intent, password: input.password } },
      { ...op, reason: "different" },
      { ...op, extra: "value" },
      { ...op, intent: { ...op.intent, revision: 1.5 } },
    ])
      expect(validIdentityOperation(bad)).toBe(false);
    expect(identityWriteResponse({ user: target, operation: op })).toBe(false);
  });
});
describe("complete durable identity ledger", () => {
  it("restores more than64 intents without truncating and removes only full matching receipts", () => {
    const ledger = new IdentityLedger();
    const all = Array.from({ length: 180 }, (_, i) => entry(i));
    sessionStorage.setItem(identityStorageKey, JSON.stringify(all));
    expect(ledger.read()).toHaveLength(180);
    const p = all[179]!,
      op = receipt(p);
    expect(
      ledger.acknowledge(p, {
        ...op,
        intent: { ...op.intent, reason: "Different input" },
        reason: "Different input",
      }),
    ).toBe(false);
    expect(ledger.acknowledge(p, op)).toBe(true);
    expect(ledger.read()).toEqual(all.slice(0, -1));
  });
  it("locks actor+target across changed drafts and revocation, not just body fingerprint", () => {
    const ledger = new IdentityLedger(),
      p = entry();
    expect(ledger.add(p)).toBeNull();
    expect(
      ledger.add({
        ...p,
        key: "f".repeat(32),
        intent: { ...p.intent, reason: "Changed reason" },
      }),
    ).toEqual(p);
    expect(
      ledger.add({
        ...p,
        key: "e".repeat(32),
        action: "identity.sessions_revoked",
        intent: {
          revision: 1,
          reason: "End all sessions",
          password_changed: false,
        },
      }),
    ).toEqual(p);
    expect(ledger.read()).toEqual([p]);
    const other = { ...entry(3), owner: "b".repeat(32), target: p.target };
    expect(ledger.add(other)).toBeNull();
  });
  it("does not bypass an unknown creation by editing its newly visible account", () => {
    const p: PendingIdentity = {
      ...entry(),
      action: "identity.user_created",
      target: target.email,
      target_email: target.email,
      intent: {
        revision: 0,
        reason: "Create account",
        name: target.name,
        email: target.email,
        role: "viewer",
        password_changed: true,
      },
    };
    const ledger = new IdentityLedger();
    expect(ledger.add(p)).toBeNull();
    expect(
      ledger.add({
        ...entry(1),
        target: target.id,
        target_email: target.email,
      }),
    ).toEqual(p);
  });
  it.each([
    "{",
    JSON.stringify([entry(), entry()]),
    JSON.stringify([{ ...entry(), password: "do not repair" }]),
    JSON.stringify([
      { ...entry(), intent: { ...entry().intent, revision: 0 } },
    ]),
    " ".repeat(1024 * 1024 + 1),
  ])("preserves malformed bytes %s", (raw) => {
    const ledger = new IdentityLedger();
    sessionStorage.setItem(identityStorageKey, raw);
    expect(() => ledger.read()).toThrow();
    expect(() => ledger.add(entry(5))).toThrow();
    expect(sessionStorage.getItem(identityStorageKey)).toBe(raw);
  });
  it("fails closed on insertion and removal quota errors without losing prior uncertainty", () => {
    const p = entry(),
      ledger = new IdentityLedger();
    ledger.add(p);
    const raw = sessionStorage.getItem(identityStorageKey);
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new DOMException("quota", "QuotaExceededError");
    });
    expect(() => ledger.add(entry(1))).toThrow();
    expect(() => ledger.acknowledge(p, receipt(p))).toThrow();
    expect(sessionStorage.getItem(identityStorageKey)).toBe(raw);
    expect(ledger.read()).toEqual([p]);
  });
});
describe("identity writes and read-only reconciliation", () => {
  it("persists before the only HTTP request and acknowledges exact response", async () => {
    const { mutation, calls } = setup((_m, _p, input, key) => {
      const all = new IdentityLedger().read();
      expect(all).toHaveLength(1);
      expect(all[0]?.key).toBe(key);
      return success(key, input);
    });
    expect(
      await mutation.execute("identity.user_updated", target, body),
    ).not.toBeNull();
    expect(calls).toHaveLength(1);
    expect(new IdentityLedger().read()).toEqual([]);
  });
  it("retains unknown results across remount and404; only exact original GET receipt unlocks", async () => {
    const gate = deferred<unknown>();
    const first = setup(() => gate.promise);
    const request = first.mutation.execute(
      "identity.user_updated",
      target,
      body,
    );
    expect(first.calls).toHaveLength(1);
    gate.reject(new ApiError("unknown"));
    await request;
    const stored = new IdentityLedger().read()[0]!;
    let ready = false;
    const second = setup((method, path) => {
      expect(method).toBe("GET");
      expect(path).toBe(`/identity-operations/${stored.key}`);
      if (!ready) throw new ApiError("invalid", "NOT_FOUND", 404);
      return { operation: receipt(stored) };
    });
    expect(
      await second.mutation.execute("identity.user_updated", target, {
        ...body,
        reason: "New draft",
      }),
    ).toBeNull();
    expect(second.calls).toHaveLength(0);
    expect(await second.mutation.inspect(stored)).toBe(false);
    expect(new IdentityLedger().read()).toHaveLength(1);
    ready = true;
    expect(await second.mutation.inspect(stored)).toBe(true);
    expect(new IdentityLedger().read()).toEqual([]);
  });
  it.each([
    new ApiError("unknown", "IDENTITY_UNAVAILABLE", 503),
    new ApiError("conflict", "OPERATION_USED", 409),
    new ApiError("invalid", "", 400),
    new ApiError("invalid"),
  ])(
    "does not treat generic transport/errors as non-commit proof",
    async (cause) => {
      const { mutation, calls } = setup(() => {
        throw cause;
      });
      await mutation.execute("identity.user_updated", target, body);
      expect(calls).toHaveLength(1);
      expect(new IdentityLedger().read()).toHaveLength(1);
      expect(mutation.error.value).toBe("unknown");
    },
  );
  it("retains the draft but clears only its fresh intent on an explicit revision conflict", async () => {
    const { mutation } = setup(() => {
      throw new ApiError("conflict", "REVISION_CONFLICT", 409);
    });
    await mutation.execute("identity.user_updated", target, body);
    expect(mutation.error.value).toBe("revision");
    expect(new IdentityLedger().read()).toEqual([]);
    expect(body.name).toBe("Edited member");
  });
  it("blocks both clicks before await and never mutates the input captured by the request", async () => {
    const gate = deferred<unknown>();
    const { mutation, calls } = setup(() => gate.promise);
    const draft = { ...body };
    const first = mutation.execute("identity.user_updated", target, draft);
    draft.reason = "Changed outside";
    expect(
      await mutation.execute("identity.user_updated", target, draft),
    ).toBeNull();
    expect(calls).toHaveLength(1);
    expect((calls[0]!.body as typeof body).reason).toBe(body.reason);
    gate.resolve(success(calls[0]!.key, body));
    await first;
  });
  it("a late exact receipt may clear its own record but never populate another identity", async () => {
    const gate = deferred<unknown>();
    const { mutation, calls, context } = setup(() => gate.promise);
    const run = mutation.execute("identity.user_updated", target, body);
    context.session.user.value = { ...admin, id: "f".repeat(32) };
    context.session.epoch.value++;
    gate.resolve(success(calls[0]!.key, body));
    expect(await run).toBeNull();
    expect(new IdentityLedger().read()).toEqual([]);
    expect(mutation.pending.value).toEqual([]);
  });
  it("clears auth immediately after starting self revocation and keeps lost receipts for fresh login", async () => {
    const gate = deferred<unknown>();
    const { mutation, context, calls } = setup(() => gate.promise);
    const run = mutation.execute("identity.sessions_revoked", admin, {
      revision: 1,
      reason: "Sign out every device",
    });
    expect(calls).toHaveLength(1);
    expect(context.session.user.value).toBeNull();
    gate.reject(new ApiError("unknown"));
    await run;
    expect(new IdentityLedger().read()).toHaveLength(1);
    expect(mutation.pending.value).toEqual([]);
    context.session.user.value = admin;
    context.session.epoch.value++;
    expect(mutation.pending.value).toHaveLength(1);
  });
  it.each([
    "bad",
    JSON.stringify([
      {
        owner: admin.id,
        fingerprint: "d".repeat(64),
        key: "f".repeat(32),
        purpose: "other",
      },
    ]),
  ])("does not bypass corrupted or legacy generic uncertainty", async (raw) => {
    sessionStorage.setItem("aster.cloud.pending.v1", raw);
    const { mutation, calls } = setup(() => {
      throw new Error("No write allowed");
    });
    expect(mutation.blocked.value).not.toBe("");
    await mutation.execute("identity.user_updated", target, body);
    expect(calls).toHaveLength(0);
    expect(sessionStorage.getItem("aster.cloud.pending.v1")).toBe(raw);
  });
});

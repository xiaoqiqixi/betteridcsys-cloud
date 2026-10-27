import { beforeEach, afterEach, describe, it, expect, vi } from "vitest";
import { DOMWrapper, flushPromises, mount } from "@vue/test-utils";
import { webcrypto } from "node:crypto";
import Panel from "../src/components/SourceRetirementPanel.vue";
import { consoleKey } from "../src/context";
import { mockContext } from "./helpers";
import { instance, operation } from "./fixtures";
import { validDetail } from "../src/api/client";
import { actionPermission } from "../src/permissions";
const cleanup: Array<() => void> = [];
beforeEach(() => {
  sessionStorage.clear();
  vi.stubGlobal("crypto", webcrypto);
  Element.prototype.scrollIntoView = vi.fn();
});
afterEach(() => {
  cleanup.splice(0).forEach((f) => f());
  document.body.innerHTML = "";
  document.body.style.overflow = "";
  vi.unstubAllGlobals();
});
const migration = {
  id: "9".repeat(32),
  instance_id: instance.id,
  source_node_id: "node-old",
  target_node_id: instance.node_id,
  phase: "active",
  source_retirement_state: "required" as const,
  created_at: instance.created_at,
  updated_at: instance.updated_at,
};
const body = () => new DOMWrapper(document.body);
describe("explicit source retirement is not automatic activation or deletion", () => {
  it("requires both exact IDs and permanent-source consent, only accepts a separate immutable task", async () => {
    const f = mockContext((_m, _p, _b, key) => ({
      operation: {
        ...operation,
        id: key,
        action: "migrate_retire_source",
        artifact_id: migration.id,
      },
    }));
    const w = mount(Panel, {
      attachTo: document.body,
      props: { instance, migration },
      global: {
        stubs: { RouterLink: true },
        provide: { [consoleKey as symbol]: f.context },
      },
    });
    cleanup.push(() => w.unmount());
    await w.get("button").trigger("click");
    await flushPromises();
    const fields = body().findAll('input:not([type="checkbox"])');
    await fields[0]!.setValue(instance.id);
    await fields[1]!.setValue(migration.id);
    await body().get("form").trigger("submit");
    expect(f.calls).toHaveLength(0);
    await body().get('input[type="checkbox"]').setValue(true);
    await body().get("form").trigger("submit");
    // WebCrypto's native digest runs outside the microtask queue. Await the
    // single observable POST rather than assuming flushPromises settles it.
    await vi.waitFor(() => expect(f.calls).toHaveLength(1));
    await flushPromises();
    expect(f.calls[0]?.body).toEqual({
      action: "migrate_retire_source",
      confirmation: instance.id,
      artifact_id: migration.id,
    });
    expect(f.calls[0]?.path).toBe(`/instances/${instance.id}/operations`);
    expect(f.calls.some((c) => /dispatch/.test(c.path))).toBe(false);
    expect(w.text()).toContain("待执行或核实");
    expect(w.get("button").attributes("disabled")).toBeDefined();
    await w.setProps({
      migration: {
        ...migration,
        source_retirement_operation_id: f.calls[0]!.key,
      },
    });
    expect(w.get("button").attributes("disabled")).toBeUndefined();
    expect(f.calls).toHaveLength(1);
  });
  it("allows a new explicit confirmation only after a known rejection, while retaining its exact old task link", async () => {
    const f = mockContext(() => ({}));
    const old = "7".repeat(32);
    const w = mount(Panel, {
      attachTo: document.body,
      props: {
        instance,
        migration: { ...migration, source_retirement_operation_id: old },
      },
      global: {
        stubs: { RouterLink: true },
        provide: { [consoleKey as symbol]: f.context },
      },
    });
    cleanup.push(() => w.unmount());
    expect(w.get("button").attributes("disabled")).toBeUndefined();
    expect(w.get("router-link-stub").attributes("to")).toBe(
      `/operations/${old}`,
    );
    await w.get("button").trigger("click");
    await flushPromises();
    expect(body().find("[role=dialog]").exists()).toBe(true);
    expect(f.calls).toHaveLength(0);
  });
  it.each(["pending", "blocked", "succeeded"] as const)(
    "refresh of %s links the precise old operation without a new retirement request",
    async (state) => {
      const f = mockContext(() => ({}));
      const id = "8".repeat(32);
      const w = mount(Panel, {
        props: {
          instance,
          migration: {
            ...migration,
            source_retirement_state: state,
            source_retirement_operation_id: id,
          },
        },
        global: {
          stubs: { RouterLink: true },
          provide: { [consoleKey as symbol]: f.context },
        },
      });
      cleanup.push(() => w.unmount());
      expect(w.get("button").attributes("disabled")).toBeDefined();
      expect(w.get("router-link-stub").attributes("to")).toBe(
        `/operations/${id}`,
      );
      await w.get("button").trigger("click");
      expect(f.calls).toHaveLength(0);
      if (state === "succeeded") expect(w.text()).toContain("源实例已退役");
    },
  );
  it("validates optional server projection without weakening old storage1 DTOs", () => {
    const detail = {
      instance,
      operations: [],
      artifacts: [],
      migrations: [migration],
    };
    expect(validDetail(detail)).toBe(true);
    expect(
      validDetail({
        ...detail,
        migrations: [{ ...migration, source_retirement_state: "probably" }],
      }),
    ).toBe(false);
    expect(
      validDetail({
        ...detail,
        migrations: [{ ...migration, source_retirement_operation_id: "wrong" }],
      }),
    ).toBe(false);
    expect(actionPermission("migrate_retire_source")).toBe("migration.manage");
  });
});

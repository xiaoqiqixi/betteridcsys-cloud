import { beforeEach, afterEach, describe, it, expect, vi } from "vitest";
import { mount, flushPromises } from "@vue/test-utils";
import { webcrypto } from "node:crypto";
import { validMigrationTargets } from "../src/api/migration-targets";
import Wizard from "../src/components/MigrationWizard.vue";
import { consoleKey } from "../src/context";
import { mockContext } from "./helpers";
import { instance, operation } from "./fixtures";
const cleanup: Array<() => void> = [];
beforeEach(() => {
  sessionStorage.clear();
  vi.stubGlobal("crypto", webcrypto);
  Element.prototype.scrollIntoView = vi.fn();
});
afterEach(() => {
  cleanup.splice(0).forEach((f) => f());
  vi.unstubAllGlobals();
});
describe("complete server-verified migration compatibility", () => {
  it("requires complete, unique, bounded target metadata", () => {
    expect(
      validMigrationTargets({
        complete: true,
        items: [{ node_id: "node-b", eligible: true, reason: "" }],
      }),
    ).toBe(true);
    for (const v of [
      { items: [] },
      { complete: false, items: [] },
      {
        complete: true,
        items: [{ node_id: "node-b", eligible: "yes", reason: "" }],
      },
      {
        complete: true,
        items: [
          { node_id: "node-b", eligible: true, reason: "" },
          { node_id: "node-b", eligible: false, reason: "ROOT_DENIED" },
        ],
      },
    ])
      expect(validMigrationTargets(v)).toBe(false);
  });
  it("does not offer online nodes without exact public migration eligibility or send a forced invalid selection", async () => {
    const paths: string[] = [];
    const f = mockContext((m, path, _b, key) => {
      paths.push(path);
      return m === "GET"
        ? {
            complete: true,
            items: [
              {
                node_id: "node-b",
                eligible: false,
                reason: "DIRECT_PUBLIC_NOT_APPROVED",
              },
              { node_id: "node-c", eligible: true, reason: "" },
            ],
          }
        : {
            operation: {
              ...operation,
              id: key,
              action: "migrate_prepare",
              target_node_id: "node-c",
            },
          };
    });
    const w = mount(Wizard, {
      props: { open: false, instance, migrations: [] },
      global: {
        stubs: { Teleport: true, RouterLink: true },
        provide: { [consoleKey as symbol]: f.context },
      },
    });
    cleanup.push(() => w.unmount());
    await w.setProps({ open: true });
    await flushPromises();
    await w.get('[role="combobox"]').trigger("click");
    expect(w.get('[role="option"][aria-disabled="true"]').text()).toContain(
      "node-b",
    );
    expect(paths).toEqual([`/instances/${instance.id}/migration-targets`]);
    await w.get('[role="option"][aria-disabled="true"]').trigger("pointerdown");
    await w.get("input").setValue(instance.id);
    const submit = w
      .findAll("button")
      .find((b) => b.text() === "创建本阶段任务")!;
    await submit.trigger("click");
    expect(f.calls).toHaveLength(0);
    await w
      .get('[role="option"]:not([aria-disabled="true"])')
      .trigger("pointerdown");
    await submit.trigger("click");
    // WebCrypto completes outside Vue's microtask queue. Wait for the single
    // write boundary, not a second click/retry that could mask duplicate sends.
    await vi.waitFor(() => {
      expect(f.calls).toHaveLength(1);
      expect(f.calls[0]?.body).toMatchObject({
        action: "migrate_prepare",
        target_node_id: "node-c",
      });
    });
  });
});

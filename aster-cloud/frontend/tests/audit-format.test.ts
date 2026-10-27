import { describe, expect, it } from "vitest";
import { auditNames } from "../src/format";

const productionActions: [string, string, string][] = [
  ["instance.create_requested", "请求创建实例", "Instance creation requested"],
  ["node.registered", "节点已登记", "Node registered"],
  ["node.heartbeat", "记录节点心跳", "Node heartbeat recorded"],
  [
    "node.dispatch_claimed",
    "已锁定任务，准备派发",
    "Task claimed for node dispatch",
  ],
  [
    "node.result_dispatched",
    "节点已受理开通任务",
    "Node accepted provisioning task",
  ],
  [
    "node.result_succeeded",
    "节点开通任务已完成",
    "Node provisioning task completed",
  ],
  [
    "node.result_rejected",
    "节点已拒绝开通任务",
    "Node rejected provisioning task",
  ],
  [
    "node.result_uncertain",
    "节点开通结果待核实",
    "Node provisioning result uncertain",
  ],
];

describe("production node audit labels", () => {
  it.each(productionActions)(
    "translates %s in Chinese and English",
    (code, zh, en) => {
      expect(auditNames[code]).toEqual([zh, en]);
    },
  );

  it.each([
    "instance.create_requested",
    "node.dispatch_claimed",
    "node.result_dispatched",
  ])("%s does not claim that a VM was successfully created", (code) => {
    const labels = auditNames[code];
    expect(labels).toBeDefined();
    expect(labels?.[0]).not.toMatch(/成功|完成|已创建|已启动/);
    expect(labels?.[1]).not.toMatch(
      /succeeded|completed|created|running|started/i,
    );
  });

  it("keeps accepted, completed, rejected and uncertain results distinct", () => {
    const statuses = ["dispatched", "succeeded", "rejected", "uncertain"];
    for (const localeIndex of [0, 1]) {
      expect(
        new Set(
          statuses.map(
            (status) => auditNames[`node.result_${status}`]?.[localeIndex],
          ),
        ).size,
      ).toBe(statuses.length);
    }
    expect(auditNames["node.result_uncertain"]?.[0]).toContain("待核实");
    expect(auditNames["node.result_uncertain"]?.[1]).toContain("uncertain");
  });

  it("does not promote a synthetic fixture event to a production audit label", () => {
    expect(Object.hasOwn(auditNames, "fixture.synthetic_cache_seeded")).toBe(
      false,
    );
  });
});

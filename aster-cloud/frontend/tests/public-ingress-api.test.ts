import { describe, it, expect } from "vitest";
import {
  ingressSource,
  validPublicIngressRule,
  validPublicIngressPolicy,
  validPublicIngressRequest,
  validPublicIngressOperation,
  matchesPublicIngressOperation,
  matchesPublicIngressResponse,
  sameIngressRules,
} from "../src/api/public-ingress";
import {
  ingressPolicy,
  ingressRule,
  ingressRequest,
  ingressOperation,
} from "./public-ingress-fixtures";
describe("instance public ingress contract", () => {
  it("default empty rules are explicit deny, not implicit legacy all", () => {
    expect(validPublicIngressPolicy(ingressPolicy)).toBe(true);
    expect(
      validPublicIngressPolicy({
        ...ingressPolicy,
        supported: false,
        unsupported_reason: "NODE_NOT_READY",
        state: "blocked",
        effective_revision: null,
      }),
    ).toBe(true);
    expect(
      validPublicIngressPolicy({
        ...ingressPolicy,
        legacy_unrestricted: true,
        effective_revision: null,
      }),
    ).toBe(true);
    expect(
      validPublicIngressPolicy({ ...ingressPolicy, rules: [ingressRule] }),
    ).toBe(false);
  });
  it.each([
    "1.2.3.4/24",
    "01.2.3.0/24",
    "::/0",
    "0.0.0.0/00",
    "0.0.0.0/33",
    "0.0.0.0",
    "0.0.0.0/0 ",
  ])("rejects noncanonical source %s", (source) =>
    expect(ingressSource(source)).toBe(false),
  );
  it.each(["0.0.0.0/0", "1.2.3.4/32", "8.8.8.0/24"])(
    "supports exact IPv4 source %s",
    (source) => expect(ingressSource(source)).toBe(true),
  );
  it("validates protocol-specific bounds and rule identities without native validation", () => {
    expect(validPublicIngressRule(ingressRule)).toBe(true);
    expect(
      validPublicIngressRule({
        ...ingressRule,
        protocol: "icmp",
        port_start: 0,
        port_end: 0,
      }),
    ).toBe(true);
    for (const edit of [
      { protocol: "all" },
      { port_start: 0 },
      { port_end: 65536 },
      { port_start: 444 },
      { source_cidr: "1.2.3.4/24" },
      { id: "BAD" },
      { protocol: "icmp" },
      { path: "/host" },
    ])
      expect(validPublicIngressRule({ ...ingressRule, ...edit })).toBe(false);
    expect(
      validPublicIngressRequest({
        ...ingressRequest,
        rules: [ingressRule, ingressRule],
      }),
    ).toBe(false);
    expect(
      validPublicIngressRequest({ ...ingressRequest, expected_revision: -1 }),
    ).toBe(false);
    expect(
      validPublicIngressRequest({
        ...ingressRequest,
        expected_revision: Number.MAX_SAFE_INTEGER,
      }),
    ).toBe(false);
    expect(
      validPublicIngressRequest({
        ...ingressRequest,
        instance_id: ingressPolicy.instance_id,
      }),
    ).toBe(false);
    expect(validPublicIngressRequest({ ...ingressRequest, rules: null })).toBe(
      false,
    );
  });
  it("binds actor/action/target/revision/rules and fixed result to the original operation", () => {
    const op = ingressOperation();
    expect(validPublicIngressOperation(op)).toBe(true);
    const match = (v: unknown) =>
      matchesPublicIngressOperation(
        v,
        op.id,
        op.actor_id,
        op.target_instance_id,
        ingressRequest,
      );
    expect(match(op)).toBe(true);
    for (const edit of [
      { actor_id: "f".repeat(32) },
      { id: "f".repeat(32) },
      { target_instance_id: "f".repeat(32) },
      { action: "resource.bind" },
      { request: { ...ingressRequest, expected_revision: 1 } },
      { result: { policy: { ...op.result.policy, revision: 2 } } },
      { result: { policy: { ...op.result.policy, rules: [] } } },
    ])
      expect(match({ ...op, ...edit })).toBe(false);
    expect(
      matchesPublicIngressResponse(
        { policy: op.result.policy, operation: op, replay: false },
        op.id,
        op.actor_id,
        op.target_instance_id,
        ingressRequest,
      ),
    ).toBe(true);
    expect(
      matchesPublicIngressResponse(
        {
          policy: { ...op.result.policy, state: "pending" },
          operation: op,
          replay: false,
        },
        op.id,
        op.actor_id,
        op.target_instance_id,
        ingressRequest,
      ),
    ).toBe(false);
  });
  it("keeps pending policy admission distinct from active rules and requires the exact frozen result time", () => {
    const op = ingressOperation();
    const pending = {
      ...op,
      result: {
        policy: {
          ...op.result.policy,
          state: "pending",
          effective_revision: null,
          epoch_id: "f".repeat(32),
          bound_resource_id: "e".repeat(32),
        },
      },
    };
    expect(validPublicIngressOperation(pending)).toBe(true);
    for (const patch of [
      { effective_revision: 1 },
      { epoch_id: "" },
      { bound_resource_id: "" },
      { state: "active" },
      { updated_at: "2026-10-23T23:59:59Z" },
    ])
      expect(
        validPublicIngressOperation({
          ...pending,
          result: { policy: { ...pending.result.policy, ...patch } },
        }),
      ).toBe(false);
  });
  it("rejects semantically duplicate allow rules even when IDs differ", () => {
    expect(
      validPublicIngressRequest({
        ...ingressRequest,
        rules: [ingressRule, { ...ingressRule, id: "f".repeat(32) }],
      }),
    ).toBe(false);
  });
  it("rules are order-independent but no fields may silently change", () => {
    const second = {
      ...ingressRule,
      id: "f".repeat(32),
      protocol: "udp" as const,
    };
    expect(sameIngressRules([ingressRule, second], [second, ingressRule])).toBe(
      true,
    );
    expect(
      sameIngressRules([ingressRule], [{ ...ingressRule, port_end: 444 }]),
    ).toBe(false);
  });
});

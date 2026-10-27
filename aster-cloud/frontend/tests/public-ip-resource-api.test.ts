import { describe, it, expect } from "vitest";
import {
  validPublicIPResource,
  validPublicIPResourceOptions,
  validPublicIPResourceRequest,
  validPublicIPResourceOperation,
  matchesPublicIPResourceResponse,
  matchesPublicIPResourceOperation,
  publicIPResourcePage,
  publicIPResourcePath,
  targetsForPublicIP,
} from "../src/api/public-ip-resource";
import {
  vmPublicResource as resource,
  vmPublicOptions as options,
  vmPublicInput as input,
  vmPublicOperation as operation,
} from "./public-ip-resource-fixtures";
describe("VM public IP contracts stay separate from NAT leases", () => {
  it("recovery freezes the exact original snapshot and generation and cannot masquerade as a direct operation", () => {
    const request = {
      expected_generation: 7,
      expected_snapshot_sha256: "c".repeat(64),
    };
    const result = {
      ...resource,
      mode: "floating" as const,
      vpc_id: options.vpcs[0]!.id,
      binding_generation: 8,
      binding_state: "pending" as const,
      releasable: false,
      operation_id: operation.id,
      epoch_id: "8".repeat(32),
    };
    const op = {
      ...operation,
      action: "resource.recover" as const,
      target_resource_id: resource.id,
      request,
      result: { resource: result },
    };
    expect(publicIPResourcePath("resource.recover", resource.id)).toBe(
      `/public-ips/resources/${resource.id}/recover`,
    );
    expect(validPublicIPResourceOperation(op)).toBe(true);
    expect(
      validPublicIPResourceRequest("resource.recover", resource.id, {
        expected_generation: 7,
      }),
    ).toBe(false);
    expect(
      validPublicIPResourceRequest("resource.recover", resource.id, {
        ...request,
        expected_snapshot_sha256: "changed",
      }),
    ).toBe(false);
    expect(
      matchesPublicIPResourceOperation(
        op,
        op.id,
        op.actor_id,
        "resource.recover",
        resource.id,
        { ...request, expected_snapshot_sha256: "d".repeat(64) },
      ),
    ).toBe(false);
    expect(
      validPublicIPResourceOperation({
        ...op,
        result: { resource: { ...result, mode: "direct", vpc_id: "" } },
      }),
    ).toBe(false);
  });
  it("validates complete direct/floating approval and exact target projection", () => {
    expect(validPublicIPResource(resource)).toBe(true);
    expect(validPublicIPResourceOptions(options)).toBe(true);
    expect(validPublicIPResourceRequest("resource.allocate", "", input)).toBe(
      true,
    );
    expect(validPublicIPResourceOperation(operation)).toBe(true);
    expect(
      matchesPublicIPResourceResponse(
        { resource, operation, replay: false },
        operation.id,
        operation.actor_id,
        operation.action,
        "",
        input,
      ),
    ).toBe(true);
  });
  it.each([
    "complete",
    "targets",
    "mode",
    "null",
    "public",
    "gateway",
    "approval-alias",
  ])("rejects unsafe options: %s", (kind) => {
    const v = structuredClone(options) as unknown as Record<string, unknown>;
    if (kind === "complete") v.complete = false;
    if (kind === "targets") delete v.resource_targets;
    if (kind === "mode")
      (v.resource_targets as Record<string, unknown>[])[0]!.mode = "normal";
    if (kind === "null") v.direct_approvals = null;
    if (kind === "public")
      (v.direct_approvals as Record<string, unknown>[])[0]!.public_ipv4s = [
        "10.0.0.1",
      ];
    if (kind === "gateway")
      (v.direct_approvals as Record<string, unknown>[])[0]!.gateway_ipv4 =
        "9.9.9.9";
    if (kind === "approval-alias")
      (v.direct_approvals as unknown[]).push(
        (v.direct_approvals as unknown[])[0],
      );
    expect(validPublicIPResourceOptions(v)).toBe(false);
  });
  it.each([
    "owner",
    "mode",
    "vpc",
    "instance",
    "state",
    "release",
    "time",
    "operation",
  ])("rejects inconsistent resource: %s", (kind) => {
    const v = { ...resource } as unknown as Record<string, unknown>;
    if (kind === "owner") v.owner_ref = "foreign";
    if (kind === "mode") v.mode = "nat";
    if (kind === "vpc") v.vpc_id = "1".repeat(32);
    if (kind === "instance") v.instance_id = "foreign";
    if (kind === "state") v.binding_state = "success";
    if (kind === "release") v.state = "released";
    if (kind === "time") v.updated_at = "2025-01-01T00:00:00Z";
    if (kind === "operation") delete v.operation_id;
    expect(validPublicIPResource(v)).toBe(false);
  });
  it("matches immutable intent, actor and every frozen result field", () => {
    for (const field of ["actor_id", "id", "target_resource_id"] as const) {
      const v = { ...operation, [field]: "f".repeat(32) };
      expect(
        matchesPublicIPResourceOperation(
          v,
          operation.id,
          operation.actor_id,
          operation.action,
          "",
          input,
        ),
      ).toBe(false);
    }
    expect(
      matchesPublicIPResourceResponse(
        {
          resource: { ...resource, address: "8.8.4.4" },
          operation,
          replay: false,
        },
        operation.id,
        operation.actor_id,
        operation.action,
        "",
        input,
      ),
    ).toBe(false);
    expect(
      validPublicIPResourceOperation({
        ...operation,
        result: { lease: resource },
      }),
    ).toBe(false);
    expect(
      validPublicIPResourceOperation({
        ...operation,
        request: { ...input, confirmation: "guess" },
      }),
    ).toBe(false);
  });
  it("binding acknowledgements remain pending, and require the exact node operation", () => {
    const op = {
      ...operation,
      id: "4".repeat(32),
      action: "resource.bind",
      target_resource_id: resource.id,
      request: { instance_id: "1".repeat(32), expected_generation: 0 },
      result: {
        resource: {
          ...resource,
          instance_id: "1".repeat(32),
          binding_state: "pending",
          operation_id: "4".repeat(32),
          binding_generation: 1,
          releasable: false,
        },
      },
    };
    expect(validPublicIPResourceOperation(op)).toBe(true);
    expect(
      validPublicIPResourceOperation({
        ...op,
        result: { resource: { ...op.result.resource, binding_state: "bound" } },
      }),
    ).toBe(false);
    expect(
      validPublicIPResourceOperation({
        ...op,
        result: {
          resource: { ...op.result.resource, operation_id: "5".repeat(32) },
        },
      }),
    ).toBe(false);
    expect(publicIPResourcePath("resource.bind", resource.id)).toBe(
      `/public-ips/resources/${resource.id}/binding`,
    );
    expect(
      validPublicIPResourceRequest("resource.unbind", resource.id, {
        expected_generation: 1,
      }),
    ).toBe(true);
    expect(
      validPublicIPResourceRequest("resource.unbind", resource.id, {}),
    ).toBe(false);
    expect(
      validPublicIPResourceOperation({
        ...op,
        result: { resource: { ...op.result.resource, binding_generation: 2 } },
      }),
    ).toBe(false);
    expect(
      validPublicIPResourceRequest("resource.bind", resource.id, {
        instance_id: "1".repeat(32),
        owner_ref: resource.owner_ref,
      }),
    ).toBe(false);
  });
  it("never merges cross-owner/mode/VPC candidates or guesses a direct guest IP", () => {
    expect(
      targetsForPublicIP(resource, options).map((t) => t.instance_id),
    ).toEqual(["1".repeat(32)]);
    expect(
      targetsForPublicIP({ ...resource, address: "8.8.4.4" }, options),
    ).toEqual([]);
    const floating = {
      ...resource,
      mode: "floating" as const,
      vpc_id: options.vpcs[0]!.id,
    };
    expect(
      targetsForPublicIP(floating, options).map((t) => t.instance_id),
    ).toEqual(["2".repeat(32)]);
  });
  it("fails closed for duplicate or malformed resource pages", () => {
    expect(publicIPResourcePage({ items: [resource], next_cursor: null })).toBe(
      true,
    );
    expect(
      publicIPResourcePage({ items: [resource, resource], next_cursor: null }),
    ).toBe(false);
    expect(
      publicIPResourcePage({ items: [resource], next_cursor: "not-a-cursor" }),
    ).toBe(false);
  });
});

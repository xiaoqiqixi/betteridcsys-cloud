import { describe, it, expect } from "vitest";
import {
  validPublicIPResourceRequest,
  matchesPublicIPResourceOperation,
} from "../src/api/public-ip-resource";
import {
  vmPublicResource as resource,
  vmPublicOperation as base,
} from "./public-ip-resource-fixtures";
const actor = base.actor_id,
  key = "f".repeat(32),
  instance = "2".repeat(32);
const body = {
  instance_id: instance,
  expected_generation: 3,
  expected_ingress_revision: 0,
};
const op = {
  ...base,
  id: key,
  actor_id: actor,
  action: "resource.bind",
  target_resource_id: resource.id,
  resource_id: resource.id,
  request: body,
  result: {
    resource: {
      ...resource,
      mode: "floating",
      vpc_id: "e".repeat(32),
      binding_state: "pending",
      binding_generation: 4,
      instance_id: instance,
      operation_id: key,
      epoch_id: "d".repeat(32),
      releasable: false,
    },
  },
};
describe("frozen ingress revision on public IP binding", () => {
  it("preserves historical two-field operation reads and accepts exact explicit revision zero", () => {
    expect(
      validPublicIPResourceRequest("resource.bind", resource.id, body),
    ).toBe(true);
    expect(
      matchesPublicIPResourceOperation(
        op,
        key,
        actor,
        "resource.bind",
        resource.id,
        body,
      ),
    ).toBe(true);
    const old = { instance_id: instance, expected_generation: 3 };
    expect(
      matchesPublicIPResourceOperation(
        { ...op, request: old },
        key,
        actor,
        "resource.bind",
        resource.id,
        old,
      ),
    ).toBe(true);
    expect(
      matchesPublicIPResourceOperation(
        { ...op, request: old },
        key,
        actor,
        "resource.bind",
        resource.id,
        body,
      ),
    ).toBe(false);
  });
  it.each([null, -1, 1.5, "0", Number.MAX_SAFE_INTEGER + 1])(
    "rejects nonnumeric invalid frozen revision %j",
    (value) => {
      expect(
        validPublicIPResourceRequest("resource.bind", resource.id, {
          ...body,
          expected_ingress_revision: value,
        }),
      ).toBe(false);
    },
  );
  it("cannot unlock the original intent with another policy version or added field", () => {
    expect(
      matchesPublicIPResourceOperation(
        { ...op, request: { ...body, expected_ingress_revision: 1 } },
        key,
        actor,
        "resource.bind",
        resource.id,
        body,
      ),
    ).toBe(false);
    expect(
      validPublicIPResourceRequest("resource.bind", resource.id, {
        ...body,
        all_ports: true,
      }),
    ).toBe(false);
  });
});

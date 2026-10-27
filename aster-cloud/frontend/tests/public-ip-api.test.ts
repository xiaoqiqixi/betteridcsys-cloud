import { describe, it, expect } from "vitest";
import {
  expandPublicIPRange,
  matchesPublicIPOperation,
  samePublicIPRequest,
  validPublicIPOperation,
  validPublicIPOptions,
  validPublicIPRequest,
} from "../src/api/public-ip";
import {
  canonicalSelection,
  sameSelection,
  validNATPolicy,
  validSelection,
  overlayOptions,
} from "../src/api/overlay";
import { overlayNAT, overlayOption } from "./overlay-fixtures";
import {
  publicPool,
  publicLease,
  publicOptions,
  publicOperation,
  publicPoolInput as input,
} from "./public-ip-fixtures";
describe("public IP strict API contracts", () => {
  it("append-only pool completion binds the target and every added address", () => {
    const request = { addresses: ["8.8.4.5"] };
    const op = {
      ...publicOperation,
      id: "f".repeat(32),
      action: "pool.extend",
      target_resource_id: publicPool.id,
      request,
      result: {
        pool: {
          ...publicPool,
          addresses: [...publicPool.addresses, ...request.addresses],
        },
      },
    };
    expect(validPublicIPRequest("pool.extend", publicPool.id, request)).toBe(
      true,
    );
    expect(validPublicIPOperation(op)).toBe(true);
    expect(
      validPublicIPOperation({ ...op, result: { pool: publicPool } }),
    ).toBe(false);
    expect(validPublicIPRequest("pool.extend", "", request)).toBe(false);
    expect(
      validPublicIPRequest("pool.extend", publicPool.id, {
        addresses: [...request.addresses, ...request.addresses],
      }),
    ).toBe(false);
  });
  it("an automatic allocation response retains the empty request and exact actual address binding", () => {
    const request = {
      pool_id: publicPool.id,
      owner_ref: publicLease.owner_ref,
      vpc_id: publicLease.vpc_id,
      node_id: publicLease.node_id,
      profile_id: publicLease.profile_id,
      address: "",
    };
    const op = {
      ...publicOperation,
      id: publicLease.id,
      resource_id: publicLease.id,
      action: "lease.allocate",
      request,
      result: { lease: publicLease },
    };
    expect(validPublicIPOperation(op)).toBe(true);
    expect(
      validPublicIPOperation({
        ...op,
        result: { lease: { ...publicLease, owner_ref: "e".repeat(32) } },
      }),
    ).toBe(false);
    expect(
      validPublicIPOperation({
        ...op,
        result: { lease: { ...publicLease, state: "released" } },
      }),
    ).toBe(false);
  });
  it("requires complete root projection and retains address ownership", () => {
    expect(validPublicIPOptions(publicOptions)).toBe(true);
    expect(validPublicIPOptions({ ...publicOptions, complete: false })).toBe(
      false,
    );
    expect(
      validPublicIPOptions({
        ...publicOptions,
        approvals: [{ ...publicOptions.approvals[0], owner_ref: "" }],
      }),
    ).toBe(false);
  });
  it.each([
    "10.0.0.2",
    "100.64.0.1",
    "169.254.169.254",
    "192.0.2.1",
    "203.0.113.3",
    "127.0.0.1",
    "8.08.4.1",
    "224.0.0.2",
  ])("rejects non-public inventory %s", (address) => {
    expect(
      validPublicIPRequest("pool.create", "", {
        ...input,
        addresses: [address],
      }),
    ).toBe(false);
  });
  it("range input rejects inversion, huge ranges and any special-use gap", () => {
    expect(expandPublicIPRange("8.8.4.3", "8.8.4.4")).toEqual(
      publicPool.addresses,
    );
    for (const [a, b] of [
      ["8.8.4.4", "8.8.4.3"],
      ["8.8.0.0", "8.9.0.0"],
      ["192.0.1.255", "192.0.3.1"],
    ])
      expect(expandPublicIPRange(a!, b!)).toEqual([]);
  });
  it("binds acknowledgement to actor, action, original key, full request and target", () => {
    expect(validPublicIPOperation(publicOperation)).toBe(true);
    expect(
      matchesPublicIPOperation(
        publicOperation,
        publicPool.id,
        publicOperation.actor_id,
        "pool.create",
        "",
        input,
      ),
    ).toBe(true);
    for (const patch of [
      { actor_id: "b".repeat(32) },
      { id: "c".repeat(32) },
      { action: "pool.state" },
      { target_resource_id: publicPool.id },
      { request: { ...input, name: "other" } },
    ])
      expect(
        matchesPublicIPOperation(
          { ...publicOperation, ...patch },
          publicPool.id,
          publicOperation.actor_id,
          "pool.create",
          "",
          input,
        ),
      ).toBe(false);
  });
  it("result must represent the confirmed full request, not a different resource value", () => {
    expect(
      validPublicIPOperation({
        ...publicOperation,
        result: { pool: { ...publicPool, name: "wrong" } },
      }),
    ).toBe(false);
    expect(
      validPublicIPOperation({
        ...publicOperation,
        result: { pool: { ...publicPool, addresses: ["8.8.4.7"] } },
      }),
    ).toBe(false);
  });
  it("canonical address order is set-like but cannot lose an address", () => {
    expect(
      samePublicIPRequest(input, {
        ...input,
        addresses: [...input.addresses].reverse(),
      }),
    ).toBe(true);
    expect(
      samePublicIPRequest(input, { ...input, addresses: [input.addresses[0]] }),
    ).toBe(false);
  });
  it("old NAT intent is unchanged; explicit address is distinct frozen intent", () => {
    const old = { members: [], gateways: [], nat_policies: [overlayNAT] };
    expect(canonicalSelection(old).nat_policies?.[0]).not.toHaveProperty(
      "public_ipv4",
    );
    expect(
      sameSelection(old, {
        ...old,
        nat_policies: [{ ...overlayNAT, public_ipv4: publicLease.address }],
      }),
    ).toBe(false);
    expect(validNATPolicy({ ...overlayNAT, public_ipv4: "10.0.0.2" })).toBe(
      false,
    );
  });
  it("explicit NAT selection requires exact reserved lease and current root profile", () => {
    const options = structuredClone(overlayOption);
    options.nat_profiles[0]!.public_ipv4s = [publicLease.address];
    options.public_ip_leases = [publicLease];
    const selection = {
      members: options.latest_epoch!.snapshot.members,
      gateways: options.gateways,
      nat_policies: [{ ...overlayNAT, public_ipv4: publicLease.address }],
    };
    expect(overlayOptions(options)).toBe(true);
    expect(validSelection(selection, options)).toBe(true);
    for (const patch of [
      { vpc_id: "d".repeat(32) },
      { node_id: "foreign-node" },
      { profile_id: "foreign-profile" },
      { state: "released" as const },
    ]) {
      options.public_ip_leases = [{ ...publicLease, ...patch }];
      expect(validSelection(selection, options)).toBe(false);
    }
    options.public_ip_leases = [];
    expect(validSelection(selection, options)).toBe(false);
  });
});

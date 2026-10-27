import { describe, expect, it } from "vitest";
import {
  validSnapshot,
  validFloatingIP,
  type FloatingIP,
} from "../src/api/overlay";
import {
  overlayEpoch,
  overlayGateway,
  overlayMember,
} from "./overlay-fixtures";
import { ingressRule } from "./public-ingress-fixtures";
const floating: FloatingIP = {
  resource_id: "9".repeat(32),
  node_id: overlayGateway.node_id,
  vpc_id: overlayMember.vpc_id,
  owner_ref: overlayMember.owner_ref,
  profile_id: "internet",
  profile_sha256: "f".repeat(64),
  gateway_instance_id: overlayGateway.instance_id,
  instance_id: overlayMember.instance_id,
  target_ipv4: overlayMember.ipv4,
  public_ipv4: "8.8.4.4",
  ingress: {
    schema: 1,
    instance_id: overlayMember.instance_id,
    owner_ref: overlayMember.owner_ref,
    revision: 0,
    sha256: "a".repeat(64),
    rules: [],
  },
};
describe("typed floating ingress immutable snapshot", () => {
  it("keeps absence as legacy without manufacturing policy, but accepts explicit default deny", () => {
    expect(validSnapshot(overlayEpoch.snapshot)).toBe(true);
    const legacy = { ...floating };
    delete legacy.ingress;
    expect(validFloatingIP(legacy)).toBe(true);
    expect(validFloatingIP(floating)).toBe(true);
    expect(
      validSnapshot({ ...overlayEpoch.snapshot, floating_ips: [floating] }),
    ).toBe(true);
  });
  it.each([
    null,
    {},
    { ...floating.ingress, instance_id: "1".repeat(32) },
    { ...floating.ingress, owner_ref: "1".repeat(32) },
    { ...floating.ingress, rules: null },
    { ...floating.ingress, rules: [ingressRule] },
    { ...floating.ingress, extra: true },
    { ...floating.ingress, sha256: "bad" },
    { ...floating.ingress, revision: -1 },
  ])("rejects invalid or cross-identity ingress %j", (ingress) => {
    expect(validFloatingIP({ ...floating, ingress })).toBe(false);
    expect(
      validSnapshot({
        ...overlayEpoch.snapshot,
        floating_ips: [{ ...floating, ingress }],
      }),
    ).toBe(false);
  });
  it("rejects duplicates, missing member, wrong gateway, owner, target and NAT overlap", () => {
    for (const patch of [
      { node_id: "other" },
      { owner_ref: "1".repeat(32) },
      { target_ipv4: "10.20.0.99" },
      { instance_id: "1".repeat(32) },
      { gateway_instance_id: "1".repeat(32) },
      { vpc_id: "1".repeat(32) },
    ])
      expect(
        validSnapshot({
          ...overlayEpoch.snapshot,
          floating_ips: [{ ...floating, ...patch }],
        }),
      ).toBe(false);
    expect(
      validSnapshot({
        ...overlayEpoch.snapshot,
        floating_ips: [floating, floating],
      }),
    ).toBe(false);
    expect(
      validSnapshot({
        ...overlayEpoch.snapshot,
        nat_policies: [
          {
            ...overlayEpoch.snapshot.nat_policies![0]!,
            public_ipv4: floating.public_ipv4,
            internet_egress_enabled: true,
          },
        ],
        floating_ips: [floating],
      }),
    ).toBe(false);
  });
});

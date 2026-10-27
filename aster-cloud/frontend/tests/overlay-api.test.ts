import { describe, expect, it } from "vitest";
import {
  canonicalSelection,
  clusterList,
  containsPrefix,
  epochDetail,
  epochList,
  matchesEpoch,
  matchesRecovery,
  matchesVPC,
  overlayOptions,
  publicIPv4,
  prefix,
  sameSelection,
  validEpoch,
  validNATPolicy,
  validNATProfile,
  validOverlayVPCInput,
  validSelection,
} from "../src/api/overlay";
import {
  overlayEpoch as epoch,
  overlayGateway as gateway,
  overlayMember as member,
  overlayNAT as nat,
  overlayOption as options,
  overlayTasks,
  overlayVPC as vpc,
} from "./overlay-fixtures";
describe("overlay network contracts", () => {
  it("accepts complete real DTO shapes including NAT, strict snapshots and full node phase records", () => {
    expect(validEpoch(epoch)).toBe(true);
    expect(epochDetail({ epoch, tasks: overlayTasks() })).toBe(true);
    expect(overlayOptions(options)).toBe(true);
    expect(epochList({ items: [epoch], next_before_epoch: null })).toBe(true);
    expect(validSelection(epoch.snapshot, options)).toBe(true);
  });
  it("accepts 64 approved NAT port ranges but rejects 65 without reducing forwarding capacity", () => {
    const approved = structuredClone(options.nat_profiles[0]!);
    approved.allowed_ports = Array.from({ length: 64 }, (_, index) => ({
      protocol: "tcp" as const,
      start: 10000 + index,
      end: 10000 + index,
    }));
    expect(validNATProfile(approved)).toBe(true);
    approved.allowed_ports.push({ protocol: "udp", start: 20000, end: 20000 });
    expect(validNATProfile(approved)).toBe(false);
    const policy = structuredClone(nat);
    policy.forwardings = Array.from({ length: 128 }, (_, index) => ({
      ...nat.forwardings[0]!,
      id: (index + 1).toString(16).padStart(32, "0"),
      public_port: 10000 + index,
    }));
    expect(validNATPolicy(policy)).toBe(true);
  });
  it.each([
    null,
    {},
    [],
    { items: null },
    { items: [{ id: "x", node_ids: null }] },
    { items: [{ id: "x", node_ids: ["n", "n"] }] },
  ])("rejects malformed cluster lists %j", (v) =>
    expect(clusterList(v)).toBe(false),
  );
  it.each([
    "10.20.0.1/24",
    "10.20.0.0/024",
    "10.020.0.0/24",
    "256.20.0.0/24",
    "::/0",
    "10.20.0.0/-1",
    "10.20.0.0/33",
    "10.20.0.0/24/1",
  ])("rejects noncanonical prefix %s", (v) => expect(prefix(v)).toBe(false));
  it("compares canonical subnet containment without string-prefix mistakes", () => {
    expect(containsPrefix("198.18.0.0/16", "198.18.128.0/17")).toBe(true);
    expect(containsPrefix("198.18.0.0/16", "198.19.0.0/16")).toBe(false);
    expect(containsPrefix("198.18.0.0/16", "0.0.0.0/0")).toBe(false);
  });
  it.each(["cluster_id", "owner_ref", "name", "cidr", "vni"] as const)(
    "requires complete VPC intent match for %s",
    (field) => {
      expect(matchesVPC(vpc, vpc.id, vpc)).toBe(true);
      const wrong = { ...vpc, [field]: field === "vni" ? 999 : "wrong" };
      expect(matchesVPC(wrong, vpc.id, vpc)).toBe(false);
    },
  );
  it("rejects malformed VPC inputs and control names", () => {
    expect(validOverlayVPCInput({ ...vpc, name: "\u202eweb" })).toBe(false);
    expect(validOverlayVPCInput({ ...vpc, vni: 16777216 })).toBe(false);
  });
  it("does not accept a response from another cluster, version, member or NAT target", () => {
    const input = {
      cluster_id: epoch.cluster_id,
      expected_epoch: 0,
      ...canonicalSelection(epoch.snapshot),
    };
    expect(matchesEpoch(epoch, epoch.id, input)).toBe(true);
    for (const changed of [
      { ...epoch, cluster_id: "foreign" },
      { ...epoch, epoch: 2 },
      {
        ...epoch,
        snapshot: {
          ...epoch.snapshot,
          members: [{ ...member, enabled: false }],
        },
      },
      {
        ...epoch,
        snapshot: {
          ...epoch.snapshot,
          nat_policies: [{ ...nat, snat_enabled: false }],
        },
      },
    ])
      expect(matchesEpoch(changed, epoch.id, input)).toBe(false);
  });
  it("treats empty omitted NAT consistently while retaining all policy identities", () => {
    expect(
      sameSelection(
        { members: [], gateways: [] },
        { members: [], gateways: [], nat_policies: [] },
      ),
    ).toBe(true);
    expect(
      sameSelection(epoch.snapshot, { ...epoch.snapshot, nat_policies: [] }),
    ).toBe(false);
  });
  it.each([
    [
      "missing profile",
      (x: typeof options): void => {
        x.nat_profiles = [];
      },
    ],
    [
      "unapproved source",
      (x: typeof options): void => {
        x.nat_profiles[0]!.allowed_source_cidrs = ["192.0.2.0/24"];
      },
    ],
    [
      "unapproved port",
      (x: typeof options): void => {
        x.nat_profiles[0]!.allowed_ports[0]!.end = 8100;
      },
    ],
    [
      "SNAT denied",
      (x: typeof options): void => {
        x.nat_profiles[0]!.allow_snat = false;
      },
    ],
  ] as const)("rejects NAT %s", (_, change) => {
    const next = structuredClone(options);
    change(next);
    expect(validSelection(epoch.snapshot, next)).toBe(false);
  });
  it("rejects NAT if the target is disabled, gateway removed or duplicate VPC policy", () => {
    expect(
      validSelection(
        { ...epoch.snapshot, members: [{ ...member, enabled: false }] },
        options,
      ),
    ).toBe(false);
    expect(validSelection({ ...epoch.snapshot, gateways: [] }, options)).toBe(
      false,
    );
    expect(
      validSelection(
        {
          ...epoch.snapshot,
          nat_policies: [nat, { ...nat, id: "9".repeat(32) }],
        },
        options,
      ),
    ).toBe(false);
  });
  it("never permits broadening approved route prefixes or switching gateway identity", () => {
    expect(
      validSelection(
        {
          ...epoch.snapshot,
          gateways: [{ ...gateway, allowed_prefixes: ["0.0.0.0/0"] }],
        },
        options,
      ),
    ).toBe(false);
    expect(
      validSelection(
        {
          ...epoch.snapshot,
          gateways: [{ ...gateway, mac: "02:00:00:00:00:99" }],
        },
        options,
      ),
    ).toBe(false);
  });
  it("keeps existing members present and permits unavailable candidates only unchanged", () => {
    expect(validSelection({ ...epoch.snapshot, members: [] }, options)).toBe(
      false,
    );
    const blocked = structuredClone(options);
    blocked.instances[0]!.eligible = false;
    blocked.instances[0]!.reason = "INSTANCE_OPERATION_PENDING";
    expect(validSelection(epoch.snapshot, blocked)).toBe(false);
    expect(validSelection(epoch.snapshot, blocked, true)).toBe(true);
    expect(
      validSelection(
        { ...epoch.snapshot, members: [{ ...member, enabled: false }] },
        blocked,
      ),
    ).toBe(false);
  });
  it("validates snapshot and task identity, state and numeric boundaries", () => {
    expect(
      validEpoch({ ...epoch, snapshot: { ...epoch.snapshot, epoch: 2 } }),
    ).toBe(false);
    expect(validEpoch({ ...epoch, state: "success" })).toBe(false);
    expect(
      epochDetail({
        epoch,
        tasks: [{ ...overlayTasks()[0], epoch_id: "f".repeat(32) }],
      }),
    ).toBe(false);
    expect(epochList({ items: [epoch], next_before_epoch: 0 })).toBe(false);
    expect(
      validNATPolicy({
        ...nat,
        forwardings: [{ ...nat.forwardings[0], public_port: 65536 }],
      }),
    ).toBe(false);
  });
  it("accepts unassigned ineligible options without making them selectable", () => {
    const x = structuredClone(options);
    x.instances[0]!.vpc_id = "";
    x.instances[0]!.eligible = false;
    x.instances[0]!.reason = "ROOT_MAPPING_REQUIRED";
    expect(overlayOptions(x)).toBe(true);
    expect(validSelection(epoch.snapshot, x)).toBe(false);
  });
  it("requires a new recovery version bound to original SHA and full replacement", () => {
    const recovered = {
      ...epoch,
      id: "f".repeat(32),
      epoch: 2,
      snapshot: {
        ...epoch.snapshot,
        epoch: 2,
        previous_sha256: epoch.snapshot_sha256,
      },
      recovery: {
        epoch: 1,
        snapshot_sha256: epoch.snapshot_sha256,
        heads: [
          {
            node_id: "node-east",
            cluster_id: epoch.cluster_id,
            epoch: 1,
            snapshot_sha256: epoch.snapshot_sha256,
          },
        ],
      },
    };
    expect(
      matchesRecovery(recovered, recovered.id, epoch, epoch.snapshot),
    ).toBe(true);
    expect(
      matchesRecovery(
        {
          ...recovered,
          recovery: { ...recovered.recovery, snapshot_sha256: "0".repeat(64) },
        },
        recovered.id,
        epoch,
        epoch.snapshot,
      ),
    ).toBe(false);
  });
});
describe("public IPv4 egress contracts", () => {
  function publicSelection() {
    const selection = structuredClone(epoch.snapshot);
    selection.gateways[0]!.allowed_prefixes = [];
    selection.nat_policies![0] = {
      ...selection.nat_policies![0]!,
      internet_egress_enabled: true,
      forwardings: [],
    };
    const approved = structuredClone(options);
    approved.nat_profiles[0]!.public_ipv4 = "8.8.4.4";
    approved.nat_profiles[0]!.allow_internet_egress = true;
    return { selection, approved };
  }
  it("allows an explicitly selected empty route list for Internet-only SNAT", () => {
    const { selection, approved } = publicSelection();
    expect(validSelection(selection, approved)).toBe(true);
    expect(validEpoch({ ...epoch, snapshot: selection })).toBe(true);
    expect(overlayOptions(approved)).toBe(true);
  });
  it("keeps legacy absent/false modes equivalent, serializes only true and never loses public intent", () => {
    const { selection } = publicSelection();
    expect(canonicalSelection(selection).nat_policies![0]).toHaveProperty(
      "internet_egress_enabled",
      true,
    );
    const legacy = structuredClone(selection);
    legacy.nat_policies![0]!.internet_egress_enabled = false;
    const omitted = structuredClone(legacy);
    delete omitted.nat_policies![0]!.internet_egress_enabled;
    expect(canonicalSelection(legacy).nat_policies![0]).not.toHaveProperty(
      "internet_egress_enabled",
    );
    expect(sameSelection(legacy, omitted)).toBe(true);
    expect(sameSelection(selection, legacy)).toBe(false);
    const input = {
      ...canonicalSelection(selection),
      cluster_id: epoch.cluster_id,
      expected_epoch: 0,
    };
    expect(matchesEpoch({ ...epoch, snapshot: legacy }, epoch.id, input)).toBe(
      false,
    );
  });
  it("rejects unapproved public egress, nonpublic addresses and Internet mode without SNAT", () => {
    const { selection, approved } = publicSelection();
    const denied = structuredClone(approved);
    delete denied.nat_profiles[0]!.allow_internet_egress;
    expect(validSelection(selection, denied)).toBe(false);
    denied.nat_profiles[0]!.allow_internet_egress = false;
    expect(validSelection(selection, denied)).toBe(false);
    const noSnat = structuredClone(selection);
    noSnat.nat_policies![0]!.snat_enabled = false;
    expect(validNATPolicy(noSnat.nat_policies![0])).toBe(false);
    expect(validSelection(noSnat, approved)).toBe(false);
    const privateProfile = {
      ...approved.nat_profiles[0]!,
      public_ipv4: "10.1.2.3",
    };
    expect(validNATProfile(privateProfile)).toBe(false);
    expect(
      validSelection(selection, {
        ...approved,
        nat_profiles: [privateProfile],
      }),
    ).toBe(false);
    // Legacy approved-prefix NAT keeps accepting its pre-existing private or
    // benchmark egress profile; the new public guard is opt-in only.
    expect(validNATProfile(options.nat_profiles[0])).toBe(true);
  });
  it.each([null, "true", 1, {}, []])(
    "rejects malformed public capability or intent %j",
    (value) => {
      expect(validNATPolicy({ ...nat, internet_egress_enabled: value })).toBe(
        false,
      );
      expect(
        validNATProfile({
          ...options.nat_profiles[0],
          allow_internet_egress: value,
        }),
      ).toBe(false);
    },
  );
  it.each([
    "0.0.0.0",
    "10.0.0.1",
    "100.64.0.1",
    "127.0.0.1",
    "169.254.169.254",
    "172.16.0.1",
    "192.168.1.1",
    "192.0.2.1",
    "198.18.1.1",
    "198.51.100.1",
    "203.0.113.1",
    "224.0.0.1",
    "240.0.0.1",
    "255.255.255.255",
    "8.8.8.8/32",
    "8.008.8.8",
  ])("does not label special-use address %s as an Internet egress", (value) => {
    expect(publicIPv4(value)).toBe(false);
  });
  it.each(["1.1.1.1", "8.8.4.4", "9.9.9.9"])(
    "accepts public unicast address %s",
    (value) => expect(publicIPv4(value)).toBe(true),
  );
  it("does not let public mode broaden DNAT sources or replace route approval", () => {
    const { selection, approved } = publicSelection();
    selection.nat_policies![0]!.forwardings = nat.forwardings;
    expect(validSelection(selection, approved)).toBe(false);
    selection.gateways[0]!.allowed_prefixes = gateway.allowed_prefixes;
    expect(validSelection(selection, approved)).toBe(true);
    selection.gateways[0]!.allowed_prefixes = ["0.0.0.0/0"];
    expect(validSelection(selection, approved)).toBe(false);
  });
  it("will not acknowledge a recovery GET with the wrong public mode", () => {
    const { selection } = publicSelection();
    const recovered = {
      ...epoch,
      id: "f".repeat(32),
      epoch: 2,
      snapshot: {
        ...selection,
        epoch: 2,
        previous_sha256: epoch.snapshot_sha256,
      },
      recovery: {
        epoch: 1,
        snapshot_sha256: epoch.snapshot_sha256,
        heads: [
          {
            node_id: "node-east",
            cluster_id: epoch.cluster_id,
            epoch: 1,
            snapshot_sha256: epoch.snapshot_sha256,
          },
        ],
      },
    };
    expect(matchesRecovery(recovered, recovered.id, epoch, selection)).toBe(
      true,
    );
    const wrong = structuredClone(recovered);
    delete wrong.snapshot.nat_policies![0]!.internet_egress_enabled;
    expect(matchesRecovery(wrong, wrong.id, epoch, selection)).toBe(false);
  });
});
describe("recovery candidate boundaries", () => {
  it("lets recovery correct retained uncertain members without permitting new pending members", () => {
    const o = structuredClone(options);
    o.instances[0]!.eligible = false;
    o.instances[0]!.reason = "INSTANCE_OPERATION_PENDING";
    const selection = {
      ...epoch.snapshot,
      members: [{ ...member, enabled: false }],
      nat_policies: [],
    };
    expect(validSelection(selection, o, false)).toBe(false);
    expect(validSelection(selection, o, true)).toBe(true);
    o.latest_epoch = { ...epoch, snapshot: { ...epoch.snapshot, members: [] } };
    expect(validSelection(selection, o, true)).toBe(false);
  });
  it("requires an explicit deletion state before removing a retained member", () => {
    const o = structuredClone(options);
    o.instances[0]!.state = "deleted";
    o.instances[0]!.eligible = false;
    o.instances[0]!.reason = "INSTANCE_DELETED";
    const selection = { members: [], gateways: [], nat_policies: [] };
    expect(validSelection(selection, o)).toBe(true);
    o.instances = [];
    expect(validSelection(selection, o)).toBe(false);
  });
  it("rejects a NAT source outside the newly narrowed route even if root originally approved it", () => {
    expect(
      validSelection(
        {
          ...epoch.snapshot,
          gateways: [{ ...gateway, allowed_prefixes: ["198.18.2.0/24"] }],
        },
        options,
      ),
    ).toBe(false);
  });
  it("only normalizes cosmetic whitespace and order, never identity or permissions", () => {
    expect(
      sameSelection(
        {
          ...epoch.snapshot,
          gateways: [{ ...gateway, allowed_prefixes: [" 198.18.0.0/16 ", ""] }],
        },
        epoch.snapshot,
      ),
    ).toBe(true);
    expect(
      sameSelection(
        { ...epoch.snapshot, members: [{ ...member, reserved: true }] },
        epoch.snapshot,
      ),
    ).toBe(false);
  });
  it("requires explicit migration-approval metadata in the options response", () => {
    const o = { ...options } as Record<string, unknown>;
    delete o.profile_migration_approved;
    expect(overlayOptions(o)).toBe(false);
  });
});

import type {
  OverlayEpoch,
  OverlayGateway,
  OverlayMember,
  OverlayOptions,
  OverlayVPC,
  NATPolicy,
} from "../src/api/overlay";
export const overlayVPC: OverlayVPC = {
  id: "a".repeat(32),
  cluster_id: "cluster-east",
  owner_ref: "b".repeat(32),
  name: "生产私有网络",
  cidr: "10.20.0.0/24",
  vni: 120,
  created_at: "2026-10-24T00:00:00Z",
};
export const overlayMember: OverlayMember = {
  instance_id: "c".repeat(32),
  vpc_id: overlayVPC.id,
  enabled: true,
  reserved: false,
  node_id: "node-east",
  interface_id: "12345678-1234-8234-8234-123456789abc",
  owner_ref: overlayVPC.owner_ref,
  local_vpc_id: "d".repeat(32),
  lease_id: "e".repeat(32),
  pool_id: "f".repeat(32),
  network_sha256: "1".repeat(64),
  ipv4: "10.20.0.2",
  mac: "02:00:00:00:00:02",
  inbound_mbps: 100,
  outbound_mbps: 100,
};
export const overlayGateway: OverlayGateway = {
  node_id: "node-east",
  instance_id: "2".repeat(32),
  interface_id: "22345678-1234-8234-8234-123456789abc",
  owner_ref: overlayVPC.owner_ref,
  vpc_id: overlayVPC.id,
  ipv4: "10.20.0.1",
  mac: "02:00:00:00:00:01",
  allowed_prefixes: ["198.18.0.0/16"],
};
export const overlayNAT: NATPolicy = {
  id: "3".repeat(32),
  node_id: "node-east",
  vpc_id: overlayVPC.id,
  gateway_instance_id: overlayGateway.instance_id,
  profile_id: "edge-a",
  profile_sha256: "4".repeat(64),
  snat_enabled: true,
  forwardings: [
    {
      id: "5".repeat(32),
      protocol: "tcp",
      public_port: 8443,
      target_instance_id: overlayMember.instance_id,
      target_port: 443,
      source_cidr: "198.18.1.0/24",
    },
  ],
};
export const overlayEpoch: OverlayEpoch = {
  id: "6".repeat(32),
  cluster_id: overlayVPC.cluster_id,
  epoch: 1,
  snapshot_sha256: "7".repeat(64),
  snapshot: {
    protocol: "aster.overlay/1",
    cluster_id: overlayVPC.cluster_id,
    epoch: 1,
    previous_sha256: "",
    profiles: [
      {
        node_id: "node-east",
        profile_id: "private",
        profile_sha256: "8".repeat(64),
      },
    ],
    vpcs: [
      {
        id: overlayVPC.id,
        owner_ref: overlayVPC.owner_ref,
        cidr: overlayVPC.cidr,
        vni: overlayVPC.vni,
      },
    ],
    members: [overlayMember],
    gateways: [overlayGateway],
    nat_policies: [overlayNAT],
  },
  phase: "release",
  state: "succeeded",
  created_at: overlayVPC.created_at,
  updated_at: overlayVPC.created_at,
  superseded_by: "",
};
export const overlayOption: OverlayOptions = {
  profile_migration_required: false,
  profile_migration_approved: false,
  cluster_id: overlayVPC.cluster_id,
  profiles: overlayEpoch.snapshot.profiles,
  mappings: [
    {
      node_id: overlayMember.node_id,
      local_vpc_id: overlayMember.local_vpc_id,
      vpc_id: overlayVPC.id,
    },
    {
      node_id: "node-east",
      local_vpc_id: "9".repeat(32),
      vpc_id: "0".repeat(32),
    },
  ],
  instances: [
    {
      instance_id: overlayMember.instance_id,
      node_id: overlayMember.node_id,
      owner_ref: overlayMember.owner_ref,
      hostname: "web-production-01",
      state: "running",
      vpc_id: overlayVPC.id,
      local_vpc_id: overlayMember.local_vpc_id,
      ipv4: overlayMember.ipv4,
      enabled: true,
      reserved: false,
      eligible: true,
      reason: "",
    },
  ],
  gateways: [overlayGateway],
  nat_profiles: [
    {
      node_id: "node-east",
      vpc_id: overlayVPC.id,
      gateway_instance_id: overlayGateway.instance_id,
      profile_id: "edge-a",
      profile_sha256: "4".repeat(64),
      public_ipv4: "198.18.10.10",
      allow_snat: true,
      allowed_source_cidrs: ["198.18.0.0/16"],
      allowed_ports: [{ protocol: "tcp", start: 8000, end: 9000 }],
    },
  ],
  latest_epoch: overlayEpoch,
};
export const overlayTasks = (e = overlayEpoch) =>
  ["prepare", "program", "release"].map((phase, index) => ({
    operation_id: String(index + 1).repeat(32),
    epoch_id: e.id,
    node_id: "node-east",
    phase: phase as OverlayEpoch["phase"],
    state: "succeeded" as const,
    request_sha256: "9".repeat(64),
    updated_at: overlayVPC.created_at,
  }));

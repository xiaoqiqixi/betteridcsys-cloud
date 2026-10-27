import type { PublicIPPool, PublicIPLease } from "../src/api/public-ip";
import { overlayVPC, overlayNAT } from "./overlay-fixtures";
const now = "2026-10-24T00:00:00Z";
export const publicPool: PublicIPPool = {
  id: "9".repeat(32),
  cluster_id: overlayVPC.cluster_id,
  name: "公网出口池",
  cidr: "8.8.4.0/24",
  addresses: ["8.8.4.3", "8.8.4.4"],
  enabled: true,
  created_at: now,
  updated_at: now,
};
export const publicLease: PublicIPLease = {
  id: "0".repeat(32),
  pool_id: publicPool.id,
  cluster_id: overlayVPC.cluster_id,
  owner_ref: overlayVPC.owner_ref,
  vpc_id: overlayVPC.id,
  node_id: overlayNAT.node_id,
  profile_id: overlayNAT.profile_id,
  address: publicPool.addresses[0]!,
  state: "reserved",
  binding_state: "reserved",
  releasable: true,
  release_reason: "",
  created_at: now,
  updated_at: now,
};
export const publicOptions = {
  complete: true as const,
  clusters: [{ id: overlayVPC.cluster_id }],
  vpcs: [overlayVPC],
  approvals: [
    {
      cluster_id: overlayVPC.cluster_id,
      node_id: overlayNAT.node_id,
      vpc_id: overlayVPC.id,
      owner_ref: overlayVPC.owner_ref,
      profile_id: overlayNAT.profile_id,
      profile_sha256: overlayNAT.profile_sha256,
      public_ipv4s: ["8.8.4.2", ...publicPool.addresses],
      allow_internet_egress: true,
    },
  ],
};
export const publicPoolInput = {
  cluster_id: publicPool.cluster_id,
  name: publicPool.name,
  cidr: publicPool.cidr,
  addresses: publicPool.addresses,
  enabled: true,
};
export const publicOperation = {
  id: publicPool.id,
  actor_id: "a".repeat(32),
  action: "pool.create" as const,
  target_resource_id: "",
  resource_id: publicPool.id,
  request_sha256: "e".repeat(64),
  request: publicPoolInput,
  result: { pool: publicPool },
  created_at: now,
};

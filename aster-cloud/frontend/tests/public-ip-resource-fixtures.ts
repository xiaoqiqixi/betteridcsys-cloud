import type {
  PublicIPResource,
  PublicIPResourceOptions,
  PublicIPResourceOperation,
} from "../src/api/public-ip-resource";
import { publicPool, publicOptions } from "./public-ip-fixtures";
const now = "2026-10-24T00:00:00Z";
export const vmPublicResource: PublicIPResource = {
  id: "7".repeat(32),
  cluster_id: publicPool.cluster_id,
  pool_id: publicPool.id,
  owner_ref: publicOptions.vpcs[0]!.owner_ref,
  mode: "direct",
  node_id: "node-a",
  profile_id: "normal-public-ipv4",
  vpc_id: "",
  address: publicPool.addresses[0]!,
  state: "reserved",
  binding_state: "unbound",
  instance_id: "",
  epoch_id: "",
  operation_id: "",
  binding_generation: 0,
  releasable: true,
  release_reason: "",
  created_at: now,
  updated_at: now,
};
export const vmPublicInput = {
  pool_id: vmPublicResource.pool_id,
  owner_ref: vmPublicResource.owner_ref,
  mode: "direct",
  node_id: vmPublicResource.node_id,
  profile_id: vmPublicResource.profile_id,
  vpc_id: "",
  address: "",
};
export const vmPublicOptions: PublicIPResourceOptions = {
  ...structuredClone(publicOptions),
  approvals: publicOptions.approvals.map((p) => ({
    ...p,
    allow_floating_ip: true,
  })),
  direct_approvals: [
    {
      cluster_id: publicPool.cluster_id,
      node_id: "node-a",
      profile_id: "normal-public-ipv4",
      profile_sha256: "f".repeat(64),
      cidr: publicPool.cidr,
      gateway_ipv4: "8.8.4.1",
      public_ipv4s: [...publicPool.addresses],
    },
  ],
  resource_targets: [
    {
      instance_id: "1".repeat(32),
      owner_ref: vmPublicResource.owner_ref,
      node_id: "node-a",
      mode: "direct",
      vpc_id: "",
      cluster_id: publicPool.cluster_id,
      ipv4: vmPublicResource.address,
      state: "shutoff",
    },
    {
      instance_id: "2".repeat(32),
      owner_ref: vmPublicResource.owner_ref,
      node_id: "node-b",
      mode: "floating",
      vpc_id: publicOptions.vpcs[0]!.id,
      cluster_id: publicPool.cluster_id,
      ipv4: "10.25.0.2",
      state: "running",
    },
    {
      instance_id: "3".repeat(32),
      owner_ref: "d".repeat(32),
      node_id: "node-b",
      mode: "floating",
      vpc_id: publicOptions.vpcs[0]!.id,
      cluster_id: publicPool.cluster_id,
      ipv4: "10.25.0.3",
      state: "running",
    },
  ],
};
export const vmPublicOperation: PublicIPResourceOperation = {
  id: vmPublicResource.id,
  actor_id: "a".repeat(32),
  action: "resource.allocate",
  target_resource_id: "",
  resource_id: vmPublicResource.id,
  request_sha256: "e".repeat(64),
  request: { ...vmPublicInput },
  result: { resource: vmPublicResource },
  created_at: now,
};

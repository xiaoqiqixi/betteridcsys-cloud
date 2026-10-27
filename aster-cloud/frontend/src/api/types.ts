export interface User {
  id: string;
  email: string;
  name: string;
  role: string;
  enabled: boolean;
  permissions: string[];
  revision: number;
}
export interface Session {
  user: User;
  csrf_token: string;
}
export interface Role {
  id: string;
  name: string;
  permissions: string[];
}
export interface Page<T> {
  items: T[];
  next_cursor: string | null;
}
export interface Resources {
  cpu_cores: number;
  memory_mib: number;
  system_disk_gib: number;
  data_disk_gib: number;
  image_id: string;
  datacenter_id: string;
  compute_node_id: string;
  node_group_id: string;
  system_storage_id: string;
  data_storage_id: string;
  network_type: string;
  ipv4_count: number;
  ipv6_count: number;
  bandwidth_mbps: number;
  inbound_bandwidth_mbps: number;
  transfer_gib: number;
  traffic_direction: string;
}
export interface Instance {
  id: string;
  owner_ref: string;
  node_id: string;
  hostname: string;
  state: string;
  resources: Resources;
  created_at: string;
  updated_at: string;
}
export type Action =
  | "create"
  | "start"
  | "shutdown"
  | "reboot"
  | "force_off"
  | "delete"
  | "snapshot_create"
  | "snapshot_restore"
  | "snapshot_delete"
  | "backup_create"
  | "backup_verify"
  | "backup_restore"
  | "backup_delete"
  | "migrate_prepare"
  | "migrate_transfer"
  | "migrate_import"
  | "migrate_activate"
  | "migrate_retire_source";
export interface Operation {
  id: string;
  instance_id: string;
  node_id: string;
  action: string;
  state: string;
  artifact_id: string;
  target_node_id: string;
  actor_id?: string;
  created_at: string;
  updated_at: string;
}
export interface Artifact {
  id: string;
  instance_id: string;
  kind: "snapshot" | "backup";
  state: string;
  created_at: string;
}
export interface Migration {
  source_retirement_state?: "required" | "pending" | "succeeded" | "blocked";
  source_retirement_operation_id?: string;
  id: string;
  instance_id: string;
  source_node_id: string;
  target_node_id: string;
  phase: string;
  created_at: string;
  updated_at: string;
}
export interface InstanceDetail {
  instance: Instance;
  operations: Operation[];
  artifacts: Artifact[];
  migrations: Migration[];
}
export interface Node {
  id: string;
  online: boolean;
  datacenter_id: string;
  maintenance: boolean;
  heartbeat_at: string | null;
  free_cpu: number;
  free_memory_mib: number;
  free_disk_gib: number;
  reserved_cpu: number;
  reserved_memory_mib: number;
  reserved_disk_gib: number;
}
export interface Audit {
  id: number | string;
  source: "identity" | "resource";
  actor: string;
  action: string;
  target: string;
  created_at: string;
  identity_detail?: {
    operation_id: string;
    base_revision: number;
    result_revision: number;
    reason: string;
  };
}
export interface OperationInput {
  action: Action;
  confirmation: string;
  artifact_id?: string;
  target_node_id?: string;
}
export interface UsersResult {
  items: User[];
  next_cursor: string | null;
  limit: 100;
  truncated_possible: boolean;
}
export interface UserInput {
  email: string;
  name: string;
  role: string;
  enabled: boolean;
  password?: string;
}

export interface Preset {
  direct_public_required?: boolean;
  id: string;
  node_id: string;
  resources: Resources;
}
export interface InstanceObservation {
  protocol: "aster.node.instance/1";
  node_id: string;
  instance_id: string;
  owner_ref: string;
  hostname: string;
  state: string;
  ipv4: string;
  mac: string;
  observed_at: string;
  source_fenced: boolean;
  target_pending: boolean;
}
// Counters remain decimal strings through validation and rendering. A JSON
// number cannot represent all uint64 values without losing precision.
export interface InstanceMetrics {
  protocol: "aster.node.metrics/1";
  node_id: string;
  instance_id: string;
  owner_ref: string;
  hostname: string;
  state: string;
  observed_at: string;
  vcpus: number;
  cpu_time_ns: string | null;
  memory_rss_kib: string | null;
  memory_actual_kib: string | null;
  memory_unused_kib: string | null;
  block_read_bytes: string | null;
  block_write_bytes: string | null;
  network_receive_bytes: string | null;
  network_transmit_bytes: string | null;
}

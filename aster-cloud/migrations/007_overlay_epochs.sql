CREATE TABLE IF NOT EXISTS controller_overlay_vpcs (
 id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 cluster_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 owner_ref CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 name VARCHAR(80) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
 cidr VARCHAR(18) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 vni INT NOT NULL,
 request_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 actor_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 created_at DATETIME(6) NOT NULL,
 UNIQUE KEY controller_overlay_vpc_vni (cluster_id,vni),
 INDEX controller_overlay_vpc_cluster (cluster_id,id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS controller_overlay_epochs (
 id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 cluster_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 epoch BIGINT NOT NULL,
 actor_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 request_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 snapshot_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 snapshot MEDIUMBLOB NOT NULL,
 recovery MEDIUMBLOB NOT NULL,
 superseded_by CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 phase VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 state VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 created_at DATETIME(6) NOT NULL,
 updated_at DATETIME(6) NOT NULL,
 UNIQUE KEY controller_overlay_cluster_epoch (cluster_id,epoch)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS controller_overlay_tasks (
 operation_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 epoch_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 node_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 phase VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 node_profile_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 request_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 state VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 receipt MEDIUMBLOB NOT NULL,
 updated_at DATETIME(6) NOT NULL,
 UNIQUE KEY controller_overlay_task_phase (epoch_id,phase,node_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS controller_overlay_members (
 instance_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 cluster_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 vpc_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 address VARCHAR(15) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 lease_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 network_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 created_at DATETIME(6) NOT NULL,
 UNIQUE KEY controller_overlay_member_address (vpc_id,address),
 UNIQUE KEY controller_overlay_member_lease (lease_id),
 INDEX controller_overlay_member_cluster (cluster_id,instance_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

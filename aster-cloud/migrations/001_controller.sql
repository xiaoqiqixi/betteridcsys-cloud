CREATE TABLE IF NOT EXISTS controller_schema (version BIGINT NOT NULL PRIMARY KEY, sha256 CHAR(64) NOT NULL, applied_at DATETIME(6) NOT NULL) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS controller_lock (id INT NOT NULL PRIMARY KEY) ENGINE=InnoDB;
INSERT IGNORE INTO controller_lock(id) VALUES(1);
CREATE TABLE IF NOT EXISTS controller_nodes (
 id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 profile_sha256 CHAR(64) NOT NULL, datacenter_id VARCHAR(128) NOT NULL,
 maintenance BOOLEAN NOT NULL DEFAULT TRUE, heartbeat_at DATETIME(6) NULL,
 free_cpu BIGINT NOT NULL DEFAULT 0, free_memory_mib BIGINT NOT NULL DEFAULT 0, free_disk_gib BIGINT NOT NULL DEFAULT 0,
 capabilities MEDIUMBLOB NOT NULL, updated_at DATETIME(6) NOT NULL
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS controller_instances (
 id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 owner_ref CHAR(32) NOT NULL, node_id VARCHAR(64) NOT NULL, hostname VARCHAR(63) NOT NULL,
 state VARCHAR(20) NOT NULL, resources MEDIUMBLOB NOT NULL, created_at DATETIME(6) NOT NULL, updated_at DATETIME(6) NOT NULL,
 INDEX controller_instances_owner(owner_ref), INDEX controller_instances_node(node_id)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS controller_jobs (
 operation_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 order_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL UNIQUE,
 controller_id VARCHAR(64) NOT NULL, request_sha256 CHAR(64) NOT NULL, request_json MEDIUMBLOB NOT NULL,
 instance_id CHAR(32) NOT NULL, node_id VARCHAR(64) NOT NULL, node_profile_sha256 CHAR(64) NOT NULL,
 node_request_sha256 CHAR(64) NOT NULL, node_request MEDIUMBLOB NOT NULL,
 state VARCHAR(20) NOT NULL, created_at DATETIME(6) NOT NULL, updated_at DATETIME(6) NOT NULL,
 INDEX controller_jobs_state(state,created_at)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS controller_reservations (
 operation_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY, node_id VARCHAR(64) NOT NULL,
 cpu BIGINT NOT NULL, memory_mib BIGINT NOT NULL, disk_gib BIGINT NOT NULL,
 released BOOLEAN NOT NULL DEFAULT FALSE, created_at DATETIME(6) NOT NULL,
 INDEX controller_reservations_node(node_id,released)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS controller_audit (
 id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
 actor VARCHAR(80) NOT NULL, action VARCHAR(64) NOT NULL, target VARCHAR(128) NOT NULL,
 created_at DATETIME(6) NOT NULL, INDEX controller_audit_time(created_at,id)
) ENGINE=InnoDB;

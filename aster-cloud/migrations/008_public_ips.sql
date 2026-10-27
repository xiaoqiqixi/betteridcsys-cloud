CREATE TABLE IF NOT EXISTS controller_public_ip_pools (
 id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 cluster_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 name VARCHAR(80) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
 cidr VARCHAR(18) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 addresses MEDIUMBLOB NOT NULL,
 enabled TINYINT(1) NOT NULL,
 created_at DATETIME(6) NOT NULL,
 updated_at DATETIME(6) NOT NULL,
 INDEX controller_public_pool_cluster (cluster_id,id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS controller_public_ip_inventory (
 address VARCHAR(15) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 pool_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 legacy_epoch_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 INDEX controller_public_inventory_pool (pool_id,address)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS controller_public_ip_leases (
 id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 cluster_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 pool_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 owner_ref CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 vpc_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 node_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 profile_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 address VARCHAR(15) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 state VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 created_at DATETIME(6) NOT NULL,
 updated_at DATETIME(6) NOT NULL,
 INDEX controller_public_lease_cluster (cluster_id,id),
 INDEX controller_public_lease_pool (pool_id,id),
 INDEX controller_public_lease_address (address,id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS controller_public_ip_active (
 address VARCHAR(15) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 lease_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 UNIQUE KEY controller_public_active_lease (lease_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS controller_public_ip_operations (
 id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 actor_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 action VARCHAR(24) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 target_resource_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 resource_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 request_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 request MEDIUMBLOB NOT NULL,
 result MEDIUMBLOB NOT NULL,
 created_at DATETIME(6) NOT NULL,
 INDEX controller_public_operation_actor (actor_id,id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

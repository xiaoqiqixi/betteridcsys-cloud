CREATE TABLE IF NOT EXISTS controller_public_ip_resources (
 id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 cluster_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 pool_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 owner_ref CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 mode VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 node_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 profile_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 vpc_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 address VARCHAR(15) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 state VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 binding_generation BIGINT NOT NULL,
 created_at DATETIME(6) NOT NULL,
 updated_at DATETIME(6) NOT NULL,
 INDEX controller_public_resource_cluster (cluster_id,id),
 INDEX controller_public_resource_pool (pool_id,id),
 INDEX controller_public_resource_address (address,id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS controller_public_ip_resource_operations (
 id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 actor_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 action VARCHAR(24) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 target_resource_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 resource_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 request_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 request MEDIUMBLOB NOT NULL,
 result MEDIUMBLOB NOT NULL,
 created_at DATETIME(6) NOT NULL,
 INDEX controller_public_resource_operation_actor (actor_id,id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS controller_public_ip_bindings (
 id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 resource_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 revision BIGINT NOT NULL,
 binding_generation BIGINT NOT NULL,
 action VARCHAR(24) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 instance_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 previous_instance_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 epoch_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 request_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 binding MEDIUMBLOB NOT NULL,
 created_at DATETIME(6) NOT NULL,
 UNIQUE KEY controller_public_binding_revision (resource_id,revision),
 INDEX controller_public_binding_instance (instance_id,id),
 INDEX controller_public_binding_previous (previous_instance_id,id),
 INDEX controller_public_binding_epoch (epoch_id,id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

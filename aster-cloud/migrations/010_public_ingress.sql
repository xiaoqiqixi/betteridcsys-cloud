CREATE TABLE IF NOT EXISTS controller_public_ingress_versions (
 instance_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 revision BIGINT NOT NULL,
 owner_ref CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 policy MEDIUMBLOB NOT NULL,
 operation_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 epoch_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 created_at DATETIME(6) NOT NULL,
 PRIMARY KEY (instance_id,revision),
 UNIQUE KEY controller_public_ingress_version_operation (operation_id),
 INDEX controller_public_ingress_version_epoch (epoch_id,instance_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS controller_public_ingress_operations (
 id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 actor_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 action VARCHAR(24) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 target_instance_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 request_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 request MEDIUMBLOB NOT NULL,
 result MEDIUMBLOB NOT NULL,
 created_at DATETIME(6) NOT NULL,
 INDEX controller_public_ingress_operation_actor (actor_id,id),
 INDEX controller_public_ingress_operation_instance (target_instance_id,id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

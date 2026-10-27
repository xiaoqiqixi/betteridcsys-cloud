CREATE TABLE IF NOT EXISTS controller_operations (
 seq BIGINT NOT NULL AUTO_INCREMENT UNIQUE,
 id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 actor_id CHAR(32) NOT NULL, instance_id CHAR(32) NOT NULL,
 node_id VARCHAR(64) NOT NULL, profile_sha256 CHAR(64) NOT NULL,
 action VARCHAR(32) NOT NULL, artifact_id CHAR(32) NOT NULL DEFAULT '', target_node_id VARCHAR(64) NOT NULL DEFAULT '',
 intent_sha256 CHAR(64) NOT NULL, request_protocol VARCHAR(32) NOT NULL,
 request_json MEDIUMBLOB NOT NULL, request_sha256 CHAR(64) NOT NULL,
 state VARCHAR(20) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 created_at DATETIME(6) NOT NULL, updated_at DATETIME(6) NOT NULL,
 INDEX controller_operations_instance(instance_id,state), INDEX controller_operations_node(node_id,state)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS controller_artifacts (
 id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 instance_id CHAR(32) NOT NULL, node_id VARCHAR(64) NOT NULL,
 kind VARCHAR(16) NOT NULL, state VARCHAR(20) NOT NULL, manifest_sha256 CHAR(64) NOT NULL DEFAULT '',
 created_at DATETIME(6) NOT NULL, updated_at DATETIME(6) NOT NULL,
 INDEX controller_artifacts_instance(instance_id)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS controller_migrations (
 id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 instance_id CHAR(32) NOT NULL, source_node_id VARCHAR(64) NOT NULL, target_node_id VARCHAR(64) NOT NULL,
 target_profile_sha256 CHAR(64) NOT NULL, source_operation_id CHAR(32) NOT NULL, target_resources MEDIUMBLOB NOT NULL,
 manifest_sha256 CHAR(64) NOT NULL DEFAULT '', fence_token CHAR(64) NOT NULL DEFAULT '',
 phase VARCHAR(24) NOT NULL, created_at DATETIME(6) NOT NULL, updated_at DATETIME(6) NOT NULL,
 INDEX controller_migrations_instance(instance_id,phase)
) ENGINE=InnoDB;

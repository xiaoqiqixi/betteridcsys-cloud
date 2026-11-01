CREATE TABLE IF NOT EXISTS controller_service_operations (
 operation_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 instance_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 owner_ref CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 action VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 request_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 receipt_status VARCHAR(16) NOT NULL, receipt_code VARCHAR(64) NOT NULL,
 result_code VARCHAR(64) NOT NULL DEFAULT '',
 requires_secret BOOLEAN NOT NULL, snapshot_name VARCHAR(80) NOT NULL DEFAULT '',
 created_at DATETIME(6) NOT NULL,
 INDEX controller_service_operations_instance(instance_id,created_at)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS controller_service_state (
 instance_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 suspended BOOLEAN NOT NULL DEFAULT FALSE,
 rescue_active BOOLEAN NOT NULL DEFAULT FALSE
) ENGINE=InnoDB;

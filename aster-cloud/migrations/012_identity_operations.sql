ALTER TABLE controller_console_users ADD COLUMN revision BIGINT UNSIGNED NOT NULL DEFAULT 1;
CREATE TABLE controller_identity_operations (
 operation_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
 actor_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 target_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 action VARCHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 base_revision BIGINT UNSIGNED NOT NULL,
 result_revision BIGINT UNSIGNED NOT NULL,
 intent_json JSON NOT NULL,
 request_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 reason VARCHAR(500) NOT NULL,
 audit_id BIGINT NOT NULL,
 completed_at DATETIME(6) NOT NULL,
 UNIQUE KEY controller_identity_operations_audit (audit_id)
) ENGINE=InnoDB DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;

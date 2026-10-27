CREATE TABLE IF NOT EXISTS controller_identity_lock (id INT NOT NULL PRIMARY KEY) ENGINE=InnoDB;
INSERT IGNORE INTO controller_identity_lock(id) VALUES(1);
CREATE TABLE IF NOT EXISTS controller_console_users (
 id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
 email VARCHAR(254) CHARACTER SET ascii COLLATE ascii_bin NOT NULL UNIQUE,
 name VARCHAR(100) NOT NULL,
 password_hash VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 role VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 enabled BOOLEAN NOT NULL,
 permissions JSON NOT NULL,
 created_at DATETIME(6) NOT NULL,
 updated_at DATETIME(6) NOT NULL
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS controller_console_sessions (
 token_hash BINARY(32) NOT NULL PRIMARY KEY,
 user_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NULL,
 created_at DATETIME(6) NOT NULL,
 expires_at DATETIME(6) NOT NULL,
 INDEX controller_console_sessions_user(user_id),
 INDEX controller_console_sessions_expiry(expires_at),
 CONSTRAINT controller_console_sessions_user_fk FOREIGN KEY(user_id) REFERENCES controller_console_users(id) ON DELETE CASCADE
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS controller_console_login_limits (
 bucket BINARY(32) NOT NULL PRIMARY KEY,
 window_at DATETIME(6) NOT NULL,
 attempts INT UNSIGNED NOT NULL
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS controller_identity_audit (
 id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
 actor VARCHAR(80) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 action VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 target VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 created_at DATETIME(6) NOT NULL,
 INDEX controller_identity_audit_time(created_at,id)
) ENGINE=InnoDB;

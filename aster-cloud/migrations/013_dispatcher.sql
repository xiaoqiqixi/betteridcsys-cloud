CREATE TABLE IF NOT EXISTS controller_dispatch_leases (
  operation_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
  kind VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  holder CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  expires_at DATETIME(6) NOT NULL,
  INDEX dispatch_expiry (expires_at)
) ENGINE=InnoDB;

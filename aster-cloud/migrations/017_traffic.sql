CREATE TABLE IF NOT EXISTS controller_traffic_policies (
  instance_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
  policy JSON NOT NULL,
  updated_at DATETIME(6) NOT NULL
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS controller_traffic_samples (
  instance_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  node_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  stream_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  sample_day DATE NOT NULL,
  revision BIGINT UNSIGNED NOT NULL,
  rx_bytes BIGINT UNSIGNED NOT NULL,
  tx_bytes BIGINT UNSIGNED NOT NULL,
  observed_at DATETIME(6) NOT NULL,
  PRIMARY KEY(instance_id,node_id,stream_id,sample_day)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS controller_traffic (
  instance_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  period_start DATETIME(6) NOT NULL,
  period_end DATETIME(6) NOT NULL,
  rx_bytes BIGINT UNSIGNED NOT NULL,
  tx_bytes BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY(instance_id,period_start)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS controller_metrics (
  instance_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  bucket DATETIME(6) NOT NULL,
  aggregate_json JSON NOT NULL,
  PRIMARY KEY(instance_id,bucket),
  KEY metrics_retention(bucket)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS controller_metric_cursors (
  instance_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
  observed_at DATETIME(6) NOT NULL,
  sample JSON NOT NULL,
  KEY metric_cursor_retention(observed_at)
) ENGINE=InnoDB;

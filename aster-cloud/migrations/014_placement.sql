CREATE TABLE IF NOT EXISTS controller_region_placement (
  region_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
  policy VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  updated_at DATETIME(6) NOT NULL
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS controller_node_allocation (
  node_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
  allocation_disabled BOOLEAN NOT NULL,
  updated_at DATETIME(6) NOT NULL
) ENGINE=InnoDB;

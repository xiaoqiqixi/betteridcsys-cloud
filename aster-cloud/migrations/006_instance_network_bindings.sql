CREATE TABLE IF NOT EXISTS controller_instance_networks (
 instance_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 operation_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 node_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 request_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 network_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 binding MEDIUMBLOB NOT NULL,
 created_at DATETIME(6) NOT NULL,
 UNIQUE KEY controller_instance_network_operation (operation_id),
 INDEX controller_instance_network_node (node_id,instance_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

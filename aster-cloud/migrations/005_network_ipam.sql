CREATE TABLE IF NOT EXISTS controller_network_vpcs (
 id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 owner_ref CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 node_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 name VARCHAR(80) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
 cidr VARCHAR(18) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 vlan_id INT NOT NULL,
 state VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 request_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 actor_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 created_at DATETIME(6) NOT NULL,
 UNIQUE KEY controller_network_vpc_vlan (node_id,vlan_id),
 INDEX controller_network_vpc_owner (owner_ref,id),
 INDEX controller_network_vpc_node (node_id,id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS controller_network_pools (
 id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 node_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 vpc_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 name VARCHAR(80) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
 cidr VARCHAR(18) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 gateway VARCHAR(15) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 addresses MEDIUMBLOB NOT NULL,
 enabled BOOLEAN NOT NULL,
 request_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 actor_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 created_at DATETIME(6) NOT NULL,
 INDEX controller_network_pool_node (node_id,id),
 INDEX controller_network_pool_vpc (vpc_id,id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS controller_network_leases (
 id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 pool_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 vpc_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 node_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 instance_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 owner_ref CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 address VARCHAR(15) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 state VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 request_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 actor_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 created_at DATETIME(6) NOT NULL,
 UNIQUE KEY controller_network_lease_pool_address (pool_id,address),
 UNIQUE KEY controller_network_lease_node_address (node_id,address),
 INDEX controller_network_lease_instance (instance_id,id),
 INDEX controller_network_lease_owner (owner_ref,id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

package networking

import (
	"context"
	"database/sql"
	"strconv"
)

// SchemaReader is implemented by both sql.DB and the migration's locked Conn.
// Inspection is read-only. Missing tables are permitted only during preflight of
// an unrecorded migration; present tables must already have the exact shape.
type SchemaReader interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}
type columnSpec struct {
	name, kind, collation string
	length                int64
	precision             int64
}
type indexSpec struct {
	name    string
	unique  bool
	columns []string
}
type tableSpec struct {
	name    string
	columns []columnSpec
	indexes []indexSpec
}

func ascii(name, kind string, n int64) columnSpec { return columnSpec{name, kind, "ascii_bin", n, 0} }
func baseID(name string) columnSpec               { return ascii(name, "char", 32) }
func hashColumn() columnSpec                      { return ascii("request_sha256", "char", 64) }
func createdColumn() columnSpec                   { return columnSpec{"created_at", "datetime", "", 0, 6} }
func networkTables() []tableSpec {
	return []tableSpec{
		{"controller_network_vpcs", []columnSpec{baseID("id"), baseID("owner_ref"), ascii("node_id", "varchar", 64), {"name", "varchar", "utf8mb4_bin", 80, 0}, ascii("cidr", "varchar", 18), {"vlan_id", "int", "", 0, 0}, ascii("state", "varchar", 16), hashColumn(), baseID("actor_id"), createdColumn()}, []indexSpec{{"PRIMARY", true, []string{"id"}}, {"controller_network_vpc_vlan", true, []string{"node_id", "vlan_id"}}, {"controller_network_vpc_owner", false, []string{"owner_ref", "id"}}, {"controller_network_vpc_node", false, []string{"node_id", "id"}}}},
		{"controller_network_pools", []columnSpec{baseID("id"), ascii("node_id", "varchar", 64), baseID("vpc_id"), {"name", "varchar", "utf8mb4_bin", 80, 0}, ascii("cidr", "varchar", 18), ascii("gateway", "varchar", 15), {"addresses", "mediumblob", "", 0, 0}, {"enabled", "tinyint", "", 0, 0}, hashColumn(), baseID("actor_id"), createdColumn()}, []indexSpec{{"PRIMARY", true, []string{"id"}}, {"controller_network_pool_node", false, []string{"node_id", "id"}}, {"controller_network_pool_vpc", false, []string{"vpc_id", "id"}}}},
		{"controller_network_leases", []columnSpec{baseID("id"), baseID("pool_id"), baseID("vpc_id"), ascii("node_id", "varchar", 64), baseID("instance_id"), baseID("owner_ref"), ascii("address", "varchar", 15), ascii("state", "varchar", 16), hashColumn(), baseID("actor_id"), createdColumn()}, []indexSpec{{"PRIMARY", true, []string{"id"}}, {"controller_network_lease_pool_address", true, []string{"pool_id", "address"}}, {"controller_network_lease_node_address", true, []string{"node_id", "address"}}, {"controller_network_lease_instance", false, []string{"instance_id", "id"}}, {"controller_network_lease_owner", false, []string{"owner_ref", "id"}}}},
	}
}
func CheckMigration(ctx context.Context, db SchemaReader, allowMissing bool) error {
	return checkTables(ctx, db, allowMissing, networkTables())
}

func CheckTaskBindingMigration(ctx context.Context, db SchemaReader, allowMissing bool) error {
	tables := []tableSpec{{
		name:    "controller_instance_networks",
		columns: []columnSpec{baseID("instance_id"), baseID("operation_id"), ascii("node_id", "varchar", 64), hashColumn(), ascii("network_sha256", "char", 64), {"binding", "mediumblob", "", 0, 0}, createdColumn()},
		indexes: []indexSpec{{"PRIMARY", true, []string{"instance_id"}}, {"controller_instance_network_operation", true, []string{"operation_id"}}, {"controller_instance_network_node", false, []string{"node_id", "instance_id"}}},
	}}
	return checkTables(ctx, db, allowMissing, tables)
}

func checkTables(ctx context.Context, db SchemaReader, allowMissing bool, tables []tableSpec) error {
	if db == nil {
		return ErrUnavailable
	}
	for _, table := range tables {
		var engine, collation sql.NullString
		var kind string
		e := db.QueryRowContext(ctx, "SELECT ENGINE,TABLE_COLLATION,TABLE_TYPE FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name=?", table.name).Scan(&engine, &collation, &kind)
		if e == sql.ErrNoRows && allowMissing {
			continue
		}
		if e != nil {
			if e == sql.ErrNoRows {
				return ErrConflict
			}
			return ErrUnavailable
		}
		if !engine.Valid || engine.String != "InnoDB" || !collation.Valid || collation.String != "utf8mb4_bin" || kind != "BASE TABLE" {
			return ErrConflict
		}
		rows, e := db.QueryContext(ctx, "SELECT COLUMN_NAME,DATA_TYPE,COLUMN_TYPE,IS_NULLABLE,CHARACTER_MAXIMUM_LENGTH,COLLATION_NAME,DATETIME_PRECISION,EXTRA FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name=? ORDER BY ORDINAL_POSITION", table.name)
		if e != nil {
			return ErrUnavailable
		}
		count := 0
		for rows.Next() {
			var name, dataType, columnType, nullable, extra string
			var length, precision sql.NullInt64
			var collate sql.NullString
			if rows.Scan(&name, &dataType, &columnType, &nullable, &length, &collate, &precision, &extra) != nil {
				rows.Close()
				return ErrUnavailable
			}
			if count >= len(table.columns) {
				rows.Close()
				return ErrConflict
			}
			want := table.columns[count]
			wantType := want.kind
			if want.length > 0 {
				wantType += "(" + strconv.FormatInt(want.length, 10) + ")"
			}
			if want.precision > 0 {
				wantType += "(" + strconv.FormatInt(want.precision, 10) + ")"
			}
			if want.kind == "tinyint" {
				wantType = "tinyint(1)"
			}
			if name != want.name || dataType != want.kind || columnType != wantType || nullable != "NO" || extra != "" || want.length > 0 && (!length.Valid || length.Int64 != want.length) || want.collation != "" && (!collate.Valid || collate.String != want.collation) || want.collation == "" && collate.Valid || want.precision > 0 && (!precision.Valid || precision.Int64 != want.precision) {
				rows.Close()
				return ErrConflict
			}
			count++
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return ErrUnavailable
		}
		if count != len(table.columns) {
			return ErrConflict
		}
		for _, idx := range table.indexes {
			rows, e = db.QueryContext(ctx, "SELECT COLUMN_NAME,SEQ_IN_INDEX,NON_UNIQUE,SUB_PART,INDEX_TYPE,IS_VISIBLE,EXPRESSION,COLLATION FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name=? AND index_name=? ORDER BY SEQ_IN_INDEX", table.name, idx.name)
			if e != nil {
				return ErrUnavailable
			}
			n := 0
			for rows.Next() {
				var col, expression, direction sql.NullString
				var seq, nonunique int
				var partial sql.NullInt64
				var indexType, visible string
				if rows.Scan(&col, &seq, &nonunique, &partial, &indexType, &visible, &expression, &direction) != nil {
					rows.Close()
					return ErrUnavailable
				}
				wantUnique := 0
				if !idx.unique {
					wantUnique = 1
				}
				if n >= len(idx.columns) || !col.Valid || col.String != idx.columns[n] || seq != n+1 || nonunique != wantUnique || partial.Valid || indexType != "BTREE" || visible != "YES" || expression.Valid || !direction.Valid || direction.String != "A" {
					rows.Close()
					return ErrConflict
				}
				n++
			}
			e = rows.Err()
			rows.Close()
			if e != nil {
				return ErrUnavailable
			}
			if n != len(idx.columns) {
				return ErrConflict
			}
		}
	}
	return nil
}
func (s *Store) Check(ctx context.Context) error {
	if s == nil || s.DB == nil {
		return ErrUnavailable
	}
	return CheckMigration(ctx, s.DB, false)
}

func CheckOverlayMigration(ctx context.Context, db SchemaReader, allowMissing bool) error {
	tables := []tableSpec{
		{"controller_overlay_vpcs", []columnSpec{baseID("id"), ascii("cluster_id", "varchar", 64), baseID("owner_ref"), {"name", "varchar", "utf8mb4_bin", 80, 0}, ascii("cidr", "varchar", 18), {"vni", "int", "", 0, 0}, hashColumn(), baseID("actor_id"), createdColumn()}, []indexSpec{{"PRIMARY", true, []string{"id"}}, {"controller_overlay_vpc_vni", true, []string{"cluster_id", "vni"}}, {"controller_overlay_vpc_cluster", false, []string{"cluster_id", "id"}}}},
		{"controller_overlay_epochs", []columnSpec{baseID("id"), ascii("cluster_id", "varchar", 64), {"epoch", "bigint", "", 0, 0}, baseID("actor_id"), hashColumn(), ascii("snapshot_sha256", "char", 64), {"snapshot", "mediumblob", "", 0, 0}, {"recovery", "mediumblob", "", 0, 0}, baseID("superseded_by"), ascii("phase", "varchar", 16), ascii("state", "varchar", 16), createdColumn(), {"updated_at", "datetime", "", 0, 6}}, []indexSpec{{"PRIMARY", true, []string{"id"}}, {"controller_overlay_cluster_epoch", true, []string{"cluster_id", "epoch"}}}},
		{"controller_overlay_tasks", []columnSpec{baseID("operation_id"), baseID("epoch_id"), ascii("node_id", "varchar", 64), ascii("phase", "varchar", 16), ascii("node_profile_sha256", "char", 64), hashColumn(), ascii("state", "varchar", 16), {"receipt", "mediumblob", "", 0, 0}, {"updated_at", "datetime", "", 0, 6}}, []indexSpec{{"PRIMARY", true, []string{"operation_id"}}, {"controller_overlay_task_phase", true, []string{"epoch_id", "phase", "node_id"}}}},
		{"controller_overlay_members", []columnSpec{baseID("instance_id"), ascii("cluster_id", "varchar", 64), baseID("vpc_id"), ascii("address", "varchar", 15), baseID("lease_id"), ascii("network_sha256", "char", 64), createdColumn()}, []indexSpec{{"PRIMARY", true, []string{"instance_id"}}, {"controller_overlay_member_address", true, []string{"vpc_id", "address"}}, {"controller_overlay_member_lease", true, []string{"lease_id"}}, {"controller_overlay_member_cluster", false, []string{"cluster_id", "instance_id"}}}},
	}
	return checkTables(ctx, db, allowMissing, tables)
}

// CheckPublicIPMigration is independent of the original private IPAM schema.
func CheckPublicIPMigration(ctx context.Context, db SchemaReader, allowMissing bool) error {
	updated := columnSpec{"updated_at", "datetime", "", 0, 6}
	tables := []tableSpec{
		{"controller_public_ip_pools", []columnSpec{baseID("id"), ascii("cluster_id", "varchar", 64), {"name", "varchar", "utf8mb4_bin", 80, 0}, ascii("cidr", "varchar", 18), {"addresses", "mediumblob", "", 0, 0}, {"enabled", "tinyint", "", 0, 0}, createdColumn(), updated}, []indexSpec{{"PRIMARY", true, []string{"id"}}, {"controller_public_pool_cluster", false, []string{"cluster_id", "id"}}}},
		{"controller_public_ip_inventory", []columnSpec{ascii("address", "varchar", 15), baseID("pool_id"), baseID("legacy_epoch_id")}, []indexSpec{{"PRIMARY", true, []string{"address"}}, {"controller_public_inventory_pool", false, []string{"pool_id", "address"}}}},
		{"controller_public_ip_leases", []columnSpec{baseID("id"), ascii("cluster_id", "varchar", 64), baseID("pool_id"), baseID("owner_ref"), baseID("vpc_id"), ascii("node_id", "varchar", 64), ascii("profile_id", "varchar", 64), ascii("address", "varchar", 15), ascii("state", "varchar", 16), createdColumn(), updated}, []indexSpec{{"PRIMARY", true, []string{"id"}}, {"controller_public_lease_cluster", false, []string{"cluster_id", "id"}}, {"controller_public_lease_pool", false, []string{"pool_id", "id"}}, {"controller_public_lease_address", false, []string{"address", "id"}}}},
		{"controller_public_ip_active", []columnSpec{ascii("address", "varchar", 15), baseID("lease_id")}, []indexSpec{{"PRIMARY", true, []string{"address"}}, {"controller_public_active_lease", true, []string{"lease_id"}}}},
		{"controller_public_ip_operations", []columnSpec{baseID("id"), baseID("actor_id"), ascii("action", "varchar", 24), baseID("target_resource_id"), baseID("resource_id"), hashColumn(), {"request", "mediumblob", "", 0, 0}, {"result", "mediumblob", "", 0, 0}, createdColumn()}, []indexSpec{{"PRIMARY", true, []string{"id"}}, {"controller_public_operation_actor", false, []string{"actor_id", "id"}}}},
	}
	return checkTables(ctx, db, allowMissing, tables)
}

// Public VM resources add independent intent history; previous NAT rows remain immutable.
func CheckPublicIPResourceMigration(ctx context.Context, db SchemaReader, allowMissing bool) error {
	updated := columnSpec{"updated_at", "datetime", "", 0, 6}
	tables := []tableSpec{
		{"controller_public_ip_resources", []columnSpec{baseID("id"), ascii("cluster_id", "varchar", 64), baseID("pool_id"), baseID("owner_ref"), ascii("mode", "varchar", 16), ascii("node_id", "varchar", 64), ascii("profile_id", "varchar", 64), baseID("vpc_id"), ascii("address", "varchar", 15), ascii("state", "varchar", 16), {"binding_generation", "bigint", "", 0, 0}, createdColumn(), updated}, []indexSpec{{"PRIMARY", true, []string{"id"}}, {"controller_public_resource_cluster", false, []string{"cluster_id", "id"}}, {"controller_public_resource_pool", false, []string{"pool_id", "id"}}, {"controller_public_resource_address", false, []string{"address", "id"}}}},
		{"controller_public_ip_resource_operations", []columnSpec{baseID("id"), baseID("actor_id"), ascii("action", "varchar", 24), baseID("target_resource_id"), baseID("resource_id"), hashColumn(), {"request", "mediumblob", "", 0, 0}, {"result", "mediumblob", "", 0, 0}, createdColumn()}, []indexSpec{{"PRIMARY", true, []string{"id"}}, {"controller_public_resource_operation_actor", false, []string{"actor_id", "id"}}}},
		{"controller_public_ip_bindings", []columnSpec{baseID("id"), baseID("resource_id"), {"revision", "bigint", "", 0, 0}, {"binding_generation", "bigint", "", 0, 0}, ascii("action", "varchar", 24), baseID("instance_id"), baseID("previous_instance_id"), baseID("epoch_id"), hashColumn(), {"binding", "mediumblob", "", 0, 0}, createdColumn()}, []indexSpec{{"PRIMARY", true, []string{"id"}}, {"controller_public_binding_revision", true, []string{"resource_id", "revision"}}, {"controller_public_binding_instance", false, []string{"instance_id", "id"}}, {"controller_public_binding_previous", false, []string{"previous_instance_id", "id"}}, {"controller_public_binding_epoch", false, []string{"epoch_id", "id"}}}},
	}
	return checkTables(ctx, db, allowMissing, tables)
}

// Public ingress is an independent append-only policy/operation history.
func CheckPublicIngressMigration(ctx context.Context, db SchemaReader, allowMissing bool) error {
	tables := []tableSpec{
		{"controller_public_ingress_versions", []columnSpec{baseID("instance_id"), {"revision", "bigint", "", 0, 0}, baseID("owner_ref"), {"policy", "mediumblob", "", 0, 0}, baseID("operation_id"), baseID("epoch_id"), createdColumn()}, []indexSpec{{"PRIMARY", true, []string{"instance_id", "revision"}}, {"controller_public_ingress_version_operation", true, []string{"operation_id"}}, {"controller_public_ingress_version_epoch", false, []string{"epoch_id", "instance_id"}}}},
		{"controller_public_ingress_operations", []columnSpec{baseID("id"), baseID("actor_id"), ascii("action", "varchar", 24), baseID("target_instance_id"), hashColumn(), {"request", "mediumblob", "", 0, 0}, {"result", "mediumblob", "", 0, 0}, createdColumn()}, []indexSpec{{"PRIMARY", true, []string{"id"}}, {"controller_public_ingress_operation_actor", false, []string{"actor_id", "id"}}, {"controller_public_ingress_operation_instance", false, []string{"target_instance_id", "id"}}}},
	}
	return checkTables(ctx, db, allowMissing, tables)
}

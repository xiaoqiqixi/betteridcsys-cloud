package identity

import (
	"context"
	"database/sql"
	"strings"
)

type SchemaReader interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

const revisionDDL = "ALTER TABLE controller_console_users ADD COLUMN revision BIGINT UNSIGNED NOT NULL DEFAULT 1"
const operationsDDL = "CREATE TABLE controller_identity_operations (\n operation_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,\n actor_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,\n target_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,\n action VARCHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,\n base_revision BIGINT UNSIGNED NOT NULL,\n result_revision BIGINT UNSIGNED NOT NULL,\n intent_json JSON NOT NULL,\n request_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,\n reason VARCHAR(500) NOT NULL,\n audit_id BIGINT NOT NULL,\n completed_at DATETIME(6) NOT NULL,\n UNIQUE KEY controller_identity_operations_audit (audit_id)\n) ENGINE=InnoDB DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_bin"

func revisionColumn(ctx context.Context, db SchemaReader) (bool, error) {
	rows, err := db.QueryContext(ctx, "SELECT COLUMN_NAME,COLUMN_TYPE,IS_NULLABLE,COLUMN_DEFAULT,EXTRA,COLLATION_NAME,GENERATION_EXPRESSION,ORDINAL_POSITION FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='controller_console_users' AND column_name='revision'")
	if err != nil {
		return false, err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var name, typ, nullable, extra, expr string
		var def, coll sql.NullString
		var pos int
		if err = rows.Scan(&name, &typ, &nullable, &def, &extra, &coll, &expr, &pos); err != nil {
			return false, err
		}
		if count != 0 || name != "revision" || typ != "bigint unsigned" || nullable != "NO" || !def.Valid || def.String != "1" || extra != "" || coll.Valid || expr != "" || pos != 10 {
			return false, ErrConflict
		}
		count++
	}
	return count == 1, rows.Err()
}
func operationsTable(ctx context.Context, db SchemaReader) (bool, error) {
	var n int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='controller_identity_operations'").Scan(&n); err != nil {
		return false, err
	}
	if n == 0 {
		return false, nil
	}
	var name, engine, kind, collation string
	if err := db.QueryRowContext(ctx, "SELECT TABLE_NAME,ENGINE,TABLE_TYPE,TABLE_COLLATION FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='controller_identity_operations'").Scan(&name, &engine, &kind, &collation); err != nil {
		return false, err
	}
	if n != 1 || name != "controller_identity_operations" || engine != "InnoDB" || kind != "BASE TABLE" || collation != "utf8mb4_bin" {
		return false, ErrConflict
	}
	want := [][3]string{{"operation_id", "char(32)", "ascii_bin"}, {"actor_id", "char(32)", "ascii_bin"}, {"target_id", "char(32)", "ascii_bin"}, {"action", "varchar(40)", "ascii_bin"}, {"base_revision", "bigint unsigned", ""}, {"result_revision", "bigint unsigned", ""}, {"intent_json", "json", ""}, {"request_sha256", "char(64)", "ascii_bin"}, {"reason", "varchar(500)", "utf8mb4_bin"}, {"audit_id", "bigint", ""}, {"completed_at", "datetime(6)", ""}}
	rows, err := db.QueryContext(ctx, "SELECT COLUMN_NAME,COLUMN_TYPE,IS_NULLABLE,COLUMN_DEFAULT,EXTRA,COLLATION_NAME,GENERATION_EXPRESSION,ORDINAL_POSITION FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='controller_identity_operations' ORDER BY ORDINAL_POSITION")
	if err != nil {
		return false, err
	}
	count := 0
	for rows.Next() {
		var name, typ, nullable, extra, expr string
		var def, coll sql.NullString
		var pos int
		if err = rows.Scan(&name, &typ, &nullable, &def, &extra, &coll, &expr, &pos); err != nil {
			rows.Close()
			return false, err
		}
		if count >= len(want) || name != want[count][0] || typ != want[count][1] || coll.String != want[count][2] || nullable != "NO" || def.Valid || extra != "" || expr != "" || pos != count+1 {
			rows.Close()
			return false, ErrConflict
		}
		count++
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return false, err
	}
	if count != len(want) {
		return false, ErrConflict
	}
	rows, err = db.QueryContext(ctx, "SELECT INDEX_NAME,SEQ_IN_INDEX,COLUMN_NAME,NON_UNIQUE,SUB_PART,INDEX_TYPE,IS_VISIBLE,EXPRESSION,COLLATION FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='controller_identity_operations' ORDER BY INDEX_NAME,SEQ_IN_INDEX")
	if err != nil {
		return false, err
	}
	defer rows.Close()
	count = 0
	for rows.Next() {
		var name, kind, visible string
		var seq, nonunique int
		var column, expr, direction sql.NullString
		var prefix sql.NullInt64
		if err = rows.Scan(&name, &seq, &column, &nonunique, &prefix, &kind, &visible, &expr, &direction); err != nil {
			return false, err
		}
		if count >= 2 || seq != 1 || nonunique != 0 || prefix.Valid || kind != "BTREE" || visible != "YES" || expr.Valid || !direction.Valid || direction.String != "A" {
			return false, ErrConflict
		}
		if !((name == "PRIMARY" && column.String == "operation_id") || (name == "controller_identity_operations_audit" && column.String == "audit_id")) {
			return false, ErrConflict
		}
		count++
	}
	if err = rows.Err(); err != nil {
		return false, err
	}
	if count != 2 {
		return false, ErrConflict
	}
	if err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.table_constraints WHERE constraint_schema=DATABASE() AND table_name='controller_identity_operations'").Scan(&n); err != nil {
		return false, err
	}
	if n != 2 {
		return false, ErrConflict
	}
	return true, nil
}

// Only exact completed objects can be skipped after DDL committed but the
// numbered migration receipt did not. Never silently replace a drifted object.
func IdentityMigrationPlan(ctx context.Context, db SchemaReader, raw string) (map[string]bool, error) {
	parts := []string{}
	for _, q := range strings.Split(raw, ";") {
		if s := strings.TrimSpace(q); s != "" {
			parts = append(parts, s)
		}
	}
	if len(parts) != 2 || parts[0] != revisionDDL || parts[1] != operationsDDL {
		return nil, ErrConflict
	}
	col, err := revisionColumn(ctx, db)
	if err != nil {
		return nil, err
	}
	table, err := operationsTable(ctx, db)
	if err != nil {
		return nil, err
	}
	return map[string]bool{revisionDDL: col, operationsDDL: table}, nil
}
func CheckOperationsSchema(ctx context.Context, db SchemaReader) error {
	col, err := revisionColumn(ctx, db)
	if err != nil {
		return err
	}
	table, err := operationsTable(ctx, db)
	if err != nil {
		return err
	}
	if !col || !table {
		return ErrConflict
	}
	return nil
}

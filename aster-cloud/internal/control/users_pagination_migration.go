package control

import (
	"context"
	"database/sql"
	"strings"
)

const usersPaginationIndexStatement = "CREATE INDEX controller_console_users_created_id ON controller_console_users (created_at,id)"

// This exact, visible ascending index is the read path for complete member
// pagination. Existing operator indexes are not changed or treated as substitutes.
func inspectUsersPaginationIndex(ctx context.Context, db auditIndexReader) (bool, error) {
	rows, err := db.QueryContext(ctx, "SELECT TABLE_NAME,INDEX_NAME,SEQ_IN_INDEX,COLUMN_NAME,NON_UNIQUE,SUB_PART,INDEX_TYPE,IS_VISIBLE,EXPRESSION,COLLATION FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name=? AND index_name=? ORDER BY SEQ_IN_INDEX", "controller_console_users", "controller_console_users_created_id")
	if err != nil {
		return false, err
	}
	defer rows.Close()
	fields := []string{"created_at", "id"}
	count := 0
	for rows.Next() {
		var seq, nonunique int
		var column, expression, direction sql.NullString
		var prefix sql.NullInt64
		var table, name, kind, visible string
		if err = rows.Scan(&table, &name, &seq, &column, &nonunique, &prefix, &kind, &visible, &expression, &direction); err != nil {
			return false, err
		}
		if table != "controller_console_users" || name != "controller_console_users_created_id" || count >= len(fields) || seq != count+1 || !column.Valid || column.String != fields[count] || nonunique != 1 || prefix.Valid || kind != "BTREE" || visible != "YES" || expression.Valid || !direction.Valid || direction.String != "A" {
			return false, ErrConflict
		}
		count++
	}
	if err = rows.Err(); err != nil {
		return false, err
	}
	if count != 0 && count != len(fields) {
		return false, ErrConflict
	}
	return count == len(fields), nil
}

// InnoDB DDL commits before the migration receipt. Reentry may skip only the
// exact unrecorded index; never drop, replace or silently bless a conflicting one.
func usersPaginationMigrationPlan(ctx context.Context, db auditIndexReader, raw string) (map[string]bool, error) {
	statements := []string{}
	for _, statement := range strings.Split(raw, ";") {
		if q := strings.TrimSpace(statement); q != "" {
			statements = append(statements, q)
		}
	}
	if len(statements) != 1 || statements[0] != usersPaginationIndexStatement {
		return nil, ErrConflict
	}
	present, err := inspectUsersPaginationIndex(ctx, db)
	if err != nil {
		return nil, err
	}
	return map[string]bool{usersPaginationIndexStatement: present}, nil
}

func checkUsersPaginationIndex(ctx context.Context, db auditIndexReader) error {
	present, err := inspectUsersPaginationIndex(ctx, db)
	if err != nil {
		return err
	}
	if !present {
		return ErrConflict
	}
	return nil
}

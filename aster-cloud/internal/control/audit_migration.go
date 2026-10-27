package control

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

type auditQueryIndex struct {
	Table, Name, Field string
}

var auditQueryIndexes = []auditQueryIndex{
	{"controller_audit", "controller_audit_action_time", "action"},
	{"controller_audit", "controller_audit_actor_time", "actor"},
	{"controller_audit", "controller_audit_target_time", "target"},
	{"controller_identity_audit", "controller_identity_audit_action_time", "action"},
	{"controller_identity_audit", "controller_identity_audit_actor_time", "actor"},
	{"controller_identity_audit", "controller_identity_audit_target_time", "target"},
}

func (i auditQueryIndex) statement() string {
	return fmt.Sprintf("CREATE INDEX %s ON %s (%s,created_at,id)", i.Name, i.Table, i.Field)
}

type auditIndexReader interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func inspectAuditIndex(ctx context.Context, db auditIndexReader, expected auditQueryIndex) (bool, error) {
	rows, e := db.QueryContext(ctx, "SELECT TABLE_NAME,INDEX_NAME,SEQ_IN_INDEX,COLUMN_NAME,NON_UNIQUE,SUB_PART,INDEX_TYPE,IS_VISIBLE,EXPRESSION,COLLATION FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name=? AND index_name=? ORDER BY SEQ_IN_INDEX", expected.Table, expected.Name)
	if e != nil {
		return false, e
	}
	defer rows.Close()
	fields := []string{expected.Field, "created_at", "id"}
	count := 0
	for rows.Next() {
		var seq, nonunique int
		var column, expression, direction sql.NullString
		var prefix sql.NullInt64
		var table, name, kind, visible string
		if e = rows.Scan(&table, &name, &seq, &column, &nonunique, &prefix, &kind, &visible, &expression, &direction); e != nil {
			return false, e
		}
		if table != expected.Table || name != expected.Name || count >= len(fields) || seq != count+1 || !column.Valid || column.String != fields[count] || nonunique != 1 || prefix.Valid || kind != "BTREE" || visible != "YES" || expression.Valid || !direction.Valid || direction.String != "A" {
			return false, ErrConflict
		}
		count++
	}
	if e = rows.Err(); e != nil {
		return false, e
	}
	if count != 0 && count != len(fields) {
		return false, ErrConflict
	}
	return count == len(fields), nil
}

// Validate all six reserved names before any new DDL. This repairs only a
// partially applied *unrecorded* version four, never drops/rewrites an index or
// silently accepts a conflicting definition. Other operator indexes are left.
func auditIndexMigrationPlan(ctx context.Context, db auditIndexReader, raw string) (map[string]bool, error) {
	statements := []string{}
	for _, statement := range strings.Split(raw, ";") {
		if s := strings.TrimSpace(statement); s != "" {
			statements = append(statements, s)
		}
	}
	if len(statements) != len(auditQueryIndexes) {
		return nil, ErrConflict
	}
	plan := map[string]bool{}
	for j, index := range auditQueryIndexes {
		if statements[j] != index.statement() {
			return nil, ErrConflict
		}
		present, e := inspectAuditIndex(ctx, db, index)
		if e != nil {
			return nil, e
		}
		plan[index.statement()] = present
	}
	return plan, nil
}

func checkAuditQueryIndexes(ctx context.Context, db auditIndexReader) error {
	for _, index := range auditQueryIndexes {
		present, e := inspectAuditIndex(ctx, db, index)
		if e != nil {
			return e
		}
		if !present {
			return ErrConflict
		}
	}
	return nil
}

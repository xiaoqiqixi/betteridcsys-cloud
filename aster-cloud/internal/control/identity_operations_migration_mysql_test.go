package control

import (
	"aster/cloud/internal/identity"
	"aster/cloud/migrations"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func identityOperationMigration(t *testing.T) string {
	t.Helper()
	for _, m := range migrations.All() {
		if m.Version == 12 {
			return m.SQL
		}
	}
	t.Fatal("identity operations migration missing")
	return ""
}

func TestIdentityOperationsMigrationRejectsChangedStatementsBeforeSQL(t *testing.T) {
	raw := identityOperationMigration(t)
	for _, s := range []string{"", raw + "; DROP TABLE controller_console_users", strings.Replace(raw, "DEFAULT 1", "DEFAULT 0", 1), strings.Replace(raw, "base_revision", "old_revision", 1)} {
		if _, e := identity.IdentityMigrationPlan(context.Background(), nil, s); !errors.Is(e, identity.ErrConflict) {
			t.Fatal("changed migration reached database", e)
		}
	}
}

func resetIdentityOperationsMigration(t *testing.T, s *SQLStore) {
	t.Helper()
	for _, q := range []string{"DELETE FROM controller_schema WHERE version=12", "DROP TABLE IF EXISTS controller_identity_operations", "ALTER TABLE controller_console_users DROP COLUMN revision"} {
		if _, e := s.DB.Exec(q); e != nil {
			t.Fatal(e)
		}
	}
}

// Exact old-column snapshots, including password hashes and binary session
// tokens; adding a new column may not rewrite any pre-existing value.
func identityOldData(t *testing.T, s *SQLStore) []string {
	t.Helper()
	out := []string{}
	for _, q := range []string{
		"SELECT CAST(JSON_ARRAY(id,email,name,password_hash,role,enabled,permissions,created_at,updated_at) AS CHAR) FROM controller_console_users ORDER BY id",
		"SELECT CAST(JSON_ARRAY(HEX(token_hash),user_id,created_at,expires_at) AS CHAR) FROM controller_console_sessions ORDER BY token_hash",
		"SELECT CAST(JSON_ARRAY(id,actor,action,target,created_at) AS CHAR) FROM controller_identity_audit ORDER BY id",
		"SELECT CAST(JSON_ARRAY(version,sha256,applied_at) AS CHAR) FROM controller_schema WHERE version<=11 ORDER BY version",
	} {
		rows, e := s.DB.Query(q)
		if e != nil {
			t.Fatal(e)
		}
		for rows.Next() {
			var v string
			if e = rows.Scan(&v); e != nil {
				rows.Close()
				t.Fatal(e)
			}
			out = append(out, v)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			t.Fatal(e)
		}
	}
	return out
}

func TestMySQLIdentityOperationsUpgradeAndPartialDDL(t *testing.T) {
	for _, mode := range []string{"schema_eleven", "column_only", "table_only", "both_unrecorded", "database_default_unicode_ci"} {
		t.Run(mode, func(t *testing.T) {
			s := consoleHTTPStore(t)
			now := time.Date(2024, 6, 2, 1, 2, 3, 4000, time.UTC)
			u := strings.Repeat("f", 32)
			for _, statement := range []struct {
				q    string
				args []any
			}{
				{"INSERT INTO controller_console_users(id,email,name,password_hash,role,enabled,permissions,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)", []any{u, "old-identity@example.invalid", "旧账户", "old hash bytes remain untouched", "viewer", true, `["instances.read","nodes.read","storage.read"]`, now, now}},
				{"INSERT INTO controller_console_sessions(token_hash,user_id,created_at,expires_at) VALUES(?,?,?,?)", []any{make([]byte, 32), u, now, now.Add(time.Hour)}},
				{"INSERT INTO controller_identity_audit(actor,action,target,created_at) VALUES(?,?,?,?)", []any{u, "old.identity.event", u, now}},
			} {
				if _, e := s.DB.Exec(statement.q, statement.args...); e != nil {
					t.Fatal(e)
				}
			}
			resetIdentityOperationsMigration(t, s)
			if mode == "database_default_unicode_ci" {
				if _, e := s.DB.Exec("ALTER DATABASE CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"); e != nil {
					t.Fatal(e)
				}
			}
			before := identityOldData(t, s)
			raw := identityOperationMigration(t)
			parts := strings.Split(raw, ";")
			if mode == "column_only" || mode == "both_unrecorded" {
				if _, e := s.DB.Exec(strings.TrimSpace(parts[0])); e != nil {
					t.Fatal(e)
				}
			}
			if mode == "table_only" || mode == "both_unrecorded" {
				if _, e := s.DB.Exec(strings.TrimSpace(parts[1])); e != nil {
					t.Fatal(e)
				}
			}
			if e := s.Check(context.Background()); !errors.Is(e, ErrConflict) {
				t.Fatal("unrecorded 012 accepted by runtime", e)
			}
			for range 2 {
				if e := s.Migrate(context.Background()); e != nil {
					t.Fatal("exact 012 reentry failed", e)
				}
			}
			if e := s.Check(context.Background()); e != nil {
				t.Fatal(e)
			}
			var revision uint64
			if e := s.DB.QueryRow("SELECT revision FROM controller_console_users WHERE id=?", u).Scan(&revision); e != nil || revision != 1 {
				t.Fatal("old account revision not initialized", e)
			}
			var got string
			if e := s.DB.QueryRow("SELECT sha256 FROM controller_schema WHERE version=12").Scan(&got); e != nil {
				t.Fatal(e)
			}
			h := sha256.Sum256([]byte(raw))
			if got != hex.EncodeToString(h[:]) {
				t.Fatal("incorrect 012 receipt")
			}
			if !reflect.DeepEqual(before, identityOldData(t, s)) {
				t.Fatal("012 changed historical data or old migration receipts")
			}
		})
	}
}

func TestMySQLIdentityOperationsDriftIsNeverSilentlyRepaired(t *testing.T) {
	cases := map[string]string{
		"revision_signed":     "ALTER TABLE controller_console_users MODIFY COLUMN revision BIGINT NOT NULL DEFAULT 1",
		"revision_default":    "ALTER TABLE controller_console_users MODIFY COLUMN revision BIGINT UNSIGNED NOT NULL DEFAULT 0",
		"revision_nullable":   "ALTER TABLE controller_console_users MODIFY COLUMN revision BIGINT UNSIGNED NULL DEFAULT 1",
		"revision_order":      "ALTER TABLE controller_console_users MODIFY COLUMN revision BIGINT UNSIGNED NOT NULL DEFAULT 1 FIRST",
		"operation_collation": "ALTER TABLE controller_identity_operations MODIFY COLUMN operation_id CHAR(32) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL",
		"reason_nullable":     "ALTER TABLE controller_identity_operations MODIFY COLUMN reason VARCHAR(500) NULL",
		"reason_length":       "ALTER TABLE controller_identity_operations MODIFY COLUMN reason VARCHAR(499) NOT NULL",
		"extra_column":        "ALTER TABLE controller_identity_operations ADD COLUMN extra INT",
		"extra_index":         "CREATE INDEX unexpected_identity_index ON controller_identity_operations(actor_id)",
		"nonunique_audit":     "ALTER TABLE controller_identity_operations DROP INDEX controller_identity_operations_audit, ADD INDEX controller_identity_operations_audit(audit_id)",
		"invisible_audit":     "ALTER TABLE controller_identity_operations ALTER INDEX controller_identity_operations_audit INVISIBLE",
		"descending_audit":    "ALTER TABLE controller_identity_operations DROP INDEX controller_identity_operations_audit, ADD UNIQUE INDEX controller_identity_operations_audit(audit_id DESC)",
		"missing_table":       "DROP TABLE controller_identity_operations",
	}
	for name, q := range cases {
		t.Run(name, func(t *testing.T) {
			s := consoleHTTPStore(t)
			if _, e := s.DB.Exec(q); e != nil {
				t.Fatal("invalid drift fixture", e)
			}
			for _, recorded := range []bool{true, false} {
				if !recorded {
					if _, e := s.DB.Exec("DELETE FROM controller_schema WHERE version=12"); e != nil {
						t.Fatal(e)
					}
				}
				if e := s.Check(context.Background()); !errors.Is(e, ErrConflict) {
					t.Fatal("runtime accepted drift", e)
				}
				// A genuinely missing table with no receipt is a legitimate partial
				// DDL state. Recorded absence, unlike unrecorded absence, is drift.
				if name == "missing_table" && !recorded {
					continue
				}
				if e := s.Migrate(context.Background()); !errors.Is(e, ErrConflict) {
					t.Fatal("migration repaired drift", e)
				}
				var n int
				if e := s.DB.QueryRow("SELECT COUNT(*) FROM controller_schema WHERE version=12").Scan(&n); e != nil || n != map[bool]int{true: 1, false: 0}[recorded] {
					t.Fatal("drift changed receipt", e)
				}
			}
		})
	}
}

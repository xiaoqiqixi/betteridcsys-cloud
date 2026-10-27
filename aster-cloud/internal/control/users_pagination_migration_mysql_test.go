package control

import (
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

const usersPageIndexDDL = "CREATE INDEX controller_console_users_created_id ON controller_console_users (created_at,id)"

func TestUsersPaginationMigrationContract(t *testing.T) {
	for _, migration := range migrations.All() {
		if migration.Version == 11 {
			if migration.SQL != usersPageIndexDDL+";\n" {
				t.Fatal("users pagination migration must add only its exact read index")
			}
			return
		}
	}
	t.Fatal("users pagination migration 011 missing")
}

func TestUsersPaginationMigrationRejectsChangedStatements(t *testing.T) {
	for _, raw := range []string{"", usersPageIndexDDL + "; DROP TABLE controller_console_users", strings.Replace(usersPageIndexDDL, "(created_at,id)", "(id,created_at)", 1), usersPageIndexDDL + ";" + usersPageIndexDDL} {
		if _, err := usersPaginationMigrationPlan(context.Background(), nil, raw); !errors.Is(err, ErrConflict) {
			t.Fatal("changed migration statement reached database", err)
		}
	}
}

func resetUsersPageVersionElevenFixture(t *testing.T, s *SQLStore) {
	t.Helper()
	var count int
	if err := s.DB.QueryRow("SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='controller_console_users' AND index_name='controller_console_users_created_id'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count > 0 {
		if _, err := s.DB.Exec("DROP INDEX controller_console_users_created_id ON controller_console_users"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.DB.Exec("DELETE FROM controller_schema WHERE version=11"); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLUsersPaginationMigrationReentryAndConflict(t *testing.T) {
	s := consoleHTTPStore(t)
	ctx := context.Background()
	now := time.Date(2025, 1, 2, 3, 4, 5, 6000, time.UTC)
	userID := strings.Repeat("a", 32)
	if _, err := s.DB.Exec("INSERT INTO controller_console_users(id,email,name,password_hash,role,enabled,permissions,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)", userID, "history@example.invalid", "Historical member", "unchanged fixture hash", "viewer", true, `["instances.read","nodes.read","storage.read"]`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec("INSERT INTO controller_console_sessions(token_hash,user_id,created_at,expires_at) VALUES(?,?,?,?)", make([]byte, 32), userID, now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec("INSERT INTO controller_identity_audit(actor,action,target,created_at) VALUES(?,?,?,?)", userID, "historical.event", userID, now); err != nil {
		t.Fatal(err)
	}
	historyTables := map[string]string{"controller_console_users": "id", "controller_console_sessions": "token_hash", "controller_identity_audit": "id"}
	history := auditDataDigest(t, s, historyTables)
	oldHashes := map[int]string{}
	for version := 1; version <= 10; version++ {
		var hash string
		if err := s.DB.QueryRow("SELECT sha256 FROM controller_schema WHERE version=?", version).Scan(&hash); err != nil {
			t.Fatal(err)
		}
		oldHashes[version] = hash
	}

	t.Run("schema_ten_upgrade_and_repeated_migrate", func(t *testing.T) {
		resetUsersPageVersionElevenFixture(t, s)
		if err := s.Check(ctx); !errors.Is(err, ErrConflict) {
			t.Fatal("schema ten accepted before users pagination migration", err)
		}
		if err := s.Migrate(ctx); err != nil {
			t.Fatal("schema ten upgrade failed", err)
		}
		if err := s.Migrate(ctx); err != nil {
			t.Fatal("completed migration is not idempotent", err)
		}
	})
	t.Run("correct_unrecorded_index_reenters_without_rewriting", func(t *testing.T) {
		resetUsersPageVersionElevenFixture(t, s)
		if _, err := s.DB.Exec(usersPageIndexDDL); err != nil {
			t.Fatal(err)
		}
		if _, err := s.DB.Exec("CREATE INDEX operator_extra_users_index ON controller_console_users (created_at)"); err != nil {
			t.Fatal(err)
		}
		if err := s.Migrate(ctx); err != nil {
			t.Fatal("unrecorded users index could not resume", err)
		}
		var got string
		if err := s.DB.QueryRow("SELECT sha256 FROM controller_schema WHERE version=11").Scan(&got); err != nil {
			t.Fatal(err)
		}
		want := sha256.Sum256([]byte(usersPageIndexDDL + ";\n"))
		if got != hex.EncodeToString(want[:]) {
			t.Fatal("wrong migration receipt after reentry")
		}
		var extra int
		if err := s.DB.QueryRow("SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='controller_console_users' AND index_name='operator_extra_users_index'").Scan(&extra); err != nil || extra != 1 {
			t.Fatal("unrelated operator index changed", err)
		}
	})
	for name, definition := range map[string]string{
		"wrong_columns":     "CREATE INDEX %s ON controller_console_users (updated_at,id)",
		"wrong_order":       "CREATE INDEX %s ON controller_console_users (id,created_at)",
		"unique":            "CREATE UNIQUE INDEX %s ON controller_console_users (created_at,id)",
		"prefix":            "CREATE INDEX %s ON controller_console_users (created_at,id(8))",
		"invisible":         "CREATE INDEX %s ON controller_console_users (created_at,id) INVISIBLE",
		"descending":        "CREATE INDEX %s ON controller_console_users (created_at DESC,id)",
		"functional_column": "CREATE INDEX %s ON controller_console_users ((lower(id)),created_at)",
		"extra_column":      "CREATE INDEX %s ON controller_console_users (created_at,id,role)",
		"missing_column":    "CREATE INDEX %s ON controller_console_users (created_at)",
		"reserved_case":     "CREATE INDEX %s ON controller_console_users (created_at,id)",
	} {
		t.Run(name, func(t *testing.T) {
			resetUsersPageVersionElevenFixture(t, s)
			index := "controller_console_users_created_id"
			if name == "reserved_case" {
				index = strings.ToUpper(index)
			}
			if _, err := s.DB.Exec(strings.Replace(definition, "%s", index, 1)); err != nil {
				t.Fatal("conflicting index fixture invalid", err)
			}
			if err := s.Migrate(ctx); !errors.Is(err, ErrConflict) {
				t.Fatal("conflicting users index was accepted", err)
			}
			var recorded int
			if err := s.DB.QueryRow("SELECT COUNT(*) FROM controller_schema WHERE version=11").Scan(&recorded); err != nil || recorded != 0 {
				t.Fatal("conflicting migration recorded a receipt", err)
			}
		})
	}
	t.Run("recorded_receipt_does_not_hide_missing_or_changed_index", func(t *testing.T) {
		resetUsersPageVersionElevenFixture(t, s)
		if err := s.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := s.DB.Exec("DROP INDEX controller_console_users_created_id ON controller_console_users"); err != nil {
			t.Fatal(err)
		}
		for _, changed := range []bool{false, true} {
			if changed {
				if _, err := s.DB.Exec("CREATE INDEX controller_console_users_created_id ON controller_console_users (updated_at,id)"); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.Check(ctx); !errors.Is(err, ErrConflict) {
				t.Fatal("runtime accepted missing or changed users index", err)
			}
			if err := s.Migrate(ctx); !errors.Is(err, ErrConflict) {
				t.Fatal("recorded schema silently repaired users index drift", err)
			}
		}
	})
	for version, want := range oldHashes {
		var got string
		if err := s.DB.QueryRow("SELECT sha256 FROM controller_schema WHERE version=?", version).Scan(&got); err != nil || got != want {
			t.Fatal("old immutable migration receipt changed", version)
		}
	}
	if !reflect.DeepEqual(history, auditDataDigest(t, s, historyTables)) {
		t.Fatal("users pagination migration changed accounts, sessions or audit history")
	}
}

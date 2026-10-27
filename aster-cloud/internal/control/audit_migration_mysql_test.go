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

func resetAuditVersionFourFixture(t *testing.T, s *SQLStore) {
	t.Helper()
	for _, index := range auditQueryIndexes {
		var count int
		if e := s.DB.QueryRow("SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name=? AND index_name=?", index.Table, index.Name).Scan(&count); e != nil {
			t.Fatal(e)
		}
		if count > 0 {
			if _, e := s.DB.Exec("DROP INDEX " + index.Name + " ON " + index.Table); e != nil {
				t.Fatal(e)
			}
		}
	}
	if _, e := s.DB.Exec("DELETE FROM controller_schema WHERE version=4"); e != nil {
		t.Fatal(e)
	}
}

func TestMySQLAuditIndexMigrationReentryAndConflict(t *testing.T) {
	s := consoleHTTPStore(t)
	ctx := context.Background()
	for _, table := range []string{"controller_audit", "controller_identity_audit"} {
		if _, e := s.DB.Exec("INSERT INTO "+table+"(actor,action,target,created_at) VALUES(?,?,?,?)", "historical-actor", "historical.event", "historical-target", time.Date(2025, 1, 2, 3, 4, 5, 6000, time.UTC)); e != nil {
			t.Fatal(e)
		}
	}
	historyTables := map[string]string{"controller_audit": "id", "controller_identity_audit": "id"}
	history := auditDataDigest(t, s, historyTables)
	oldHashes := map[int]string{}
	for version := 1; version <= 3; version++ {
		var h string
		if e := s.DB.QueryRow("SELECT sha256 FROM controller_schema WHERE version=?", version).Scan(&h); e != nil {
			t.Fatal(e)
		}
		oldHashes[version] = h
	}
	t.Run("partially_applied_unrecorded_DDL_reenters_and_records_SHA_only_after_all_indexes", func(t *testing.T) {
		resetAuditVersionFourFixture(t, s)
		for _, index := range auditQueryIndexes[:2] {
			if _, e := s.DB.Exec(index.statement()); e != nil {
				t.Fatal(e)
			}
		}
		var recorded int
		if e := s.DB.QueryRow("SELECT COUNT(*) FROM controller_schema WHERE version=4").Scan(&recorded); e != nil || recorded != 0 {
			t.Fatal("partial DDL pretended to be applied")
		}
		// Extra operator-defined indexes are neither replaced nor deleted.
		if _, e := s.DB.Exec("CREATE INDEX operator_extra_audit_index ON controller_audit (created_at)"); e != nil {
			t.Fatal(e)
		}
		if e := s.Migrate(ctx); e != nil {
			t.Fatal("correct partial audit migration did not reenter", e)
		}
		if e := s.Migrate(ctx); e != nil {
			t.Fatal("completed audit migration was not idempotent", e)
		}
		var got string
		if e := s.DB.QueryRow("SELECT sha256 FROM controller_schema WHERE version=4").Scan(&got); e != nil {
			t.Fatal(e)
		}
		all := migrations.All()
		want := sha256.Sum256([]byte(all[3].SQL))
		if got != hex.EncodeToString(want[:]) || checkAuditQueryIndexes(ctx, s.DB) != nil {
			t.Fatal("migration SHA recorded without complete exact indexes")
		}
		var extra int
		if e := s.DB.QueryRow("SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='controller_audit' AND index_name='operator_extra_audit_index'").Scan(&extra); e != nil || extra != 1 {
			t.Fatal("migration changed an unrelated operator index")
		}
	})
	for name, definition := range map[string]string{
		"wrong_columns":      "CREATE INDEX %s ON controller_audit (target,created_at,id)",
		"wrong_order":        "CREATE INDEX %s ON controller_audit (created_at,action,id)",
		"unique":             "CREATE UNIQUE INDEX %s ON controller_audit (action,created_at,id)",
		"prefix":             "CREATE INDEX %s ON controller_audit (action(5),created_at,id)",
		"invisible":          "CREATE INDEX %s ON controller_audit (action,created_at,id) INVISIBLE",
		"descending":         "CREATE INDEX %s ON controller_audit (action DESC,created_at,id)",
		"functional_column":  "CREATE INDEX %s ON controller_audit ((lower(action)),created_at,id)",
		"reserved_name_case": "CREATE INDEX %s ON controller_audit (action,created_at,id)",
	} {
		t.Run(name, func(t *testing.T) {
			resetAuditVersionFourFixture(t, s)
			indexName := auditQueryIndexes[0].Name
			if name == "reserved_name_case" {
				indexName = strings.ToUpper(indexName)
			}
			ddl := strings.Replace(definition, "%s", indexName, 1)
			if _, e := s.DB.Exec(ddl); e != nil {
				t.Fatal("cannot prepare independent conflicting index fixture", e)
			}
			if e := s.Migrate(ctx); !errors.Is(e, ErrConflict) {
				t.Fatal("conflicting reserved index accepted", e)
			}
			var recorded, other int
			if e := s.DB.QueryRow("SELECT COUNT(*) FROM controller_schema WHERE version=4").Scan(&recorded); e != nil || recorded != 0 {
				t.Fatal("failed index migration recorded an applied SHA")
			}
			if e := s.DB.QueryRow("SELECT COUNT(DISTINCT index_name) FROM information_schema.statistics WHERE table_schema=DATABASE() AND index_name IN (?,?,?,?,?)", auditQueryIndexes[1].Name, auditQueryIndexes[2].Name, auditQueryIndexes[3].Name, auditQueryIndexes[4].Name, auditQueryIndexes[5].Name).Scan(&other); e != nil || other != 0 {
				t.Fatal("conflict preflight changed other indexes")
			}
		})
	}
	t.Run("recorded_migration_with_missing_index_fails_runtime_check", func(t *testing.T) {
		resetAuditVersionFourFixture(t, s)
		if e := s.Migrate(ctx); e != nil {
			t.Fatal(e)
		}
		index := auditQueryIndexes[4]
		if _, e := s.DB.Exec("DROP INDEX " + index.Name + " ON " + index.Table); e != nil {
			t.Fatal(e)
		}
		if e := s.Check(ctx); !errors.Is(e, ErrConflict) {
			t.Fatal("runtime check ignored missing recorded audit index", e)
		}
		if e := s.Migrate(ctx); !errors.Is(e, ErrConflict) {
			t.Fatal("recorded schema silently repaired/widened", e)
		}
		if _, e := s.DB.Exec("CREATE INDEX " + index.Name + " ON " + index.Table + " (target,created_at,id)"); e != nil {
			t.Fatal(e)
		}
		if e := s.Check(ctx); !errors.Is(e, ErrConflict) {
			t.Fatal("runtime check ignored a changed recorded index", e)
		}
		if e := s.Migrate(ctx); !errors.Is(e, ErrConflict) {
			t.Fatal("recorded schema silently accepted a changed index", e)
		}
	})
	for version, want := range oldHashes {
		var got string
		if e := s.DB.QueryRow("SELECT sha256 FROM controller_schema WHERE version=?", version).Scan(&got); e != nil || got != want {
			t.Fatal("old immutable migration receipt changed", version)
		}
	}
	if !reflect.DeepEqual(history, auditDataDigest(t, s, historyTables)) {
		t.Fatal("index migration changed historical audit events")
	}
}

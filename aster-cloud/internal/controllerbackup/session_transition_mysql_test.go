package controllerbackup_test

import (
	"aster/cloud/internal/controllerbackup"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Agreed authenticated-archive / real-MySQL seam. The enclosing fixture owns
// this database and its exact source records. This is NOT host activation or
// browser-cookie acceptance; those remain independent coordinator tests.
func exerciseSessionTransition(t *testing.T, ctx context.Context, a *controllerbackup.Archive, db *sql.DB, owner []byte, dsn string, proof []byte) {
	t.Helper()
	binding := controllerbackup.SessionTransitionBinding{
		TargetPlanSHA256: strings.Repeat("a", 64), MaterialManifestSHA256: strings.Repeat("b", 64),
		CreatedAt: time.Date(2026, 10, 28, 9, 8, 7, 123456000, time.UTC),
	}
	intent, e := a.PlanSessionRevocation(ctx, db, owner, dsn, proof, binding)
	if e != nil || len(intent) == 0 {
		t.Fatal("exact restored database must produce a read-only session plan", e)
	}
	if _, e := a.VerifyRestoredDatabase(ctx, db, owner, dsn, proof); e != nil {
		t.Fatal("planning changed source sessions or audit", e)
	}
	verify := func() (controllerbackup.SessionRevocationReport, error) {
		return a.VerifyRevokedSessions(ctx, db, owner, dsn, proof, binding, intent)
	}
	if _, e := verify(); e != controllerbackup.ErrInvalid {
		t.Fatal("unchanged preimage must not count as revoked", e)
	}
	var untrusted map[string]any
	if json.Unmarshal(intent, &untrusted) != nil {
		t.Fatal("intent must be JSON")
	}
	for key, bad := range map[string]any{"source_sessions": 1, "audit_id": "43", "operation_id": strings.Repeat("0", 32), "source_manifest_sha256": strings.Repeat("0", 64)} {
		// Keep canonical field order/format so the negative case exercises the
		// changed binding, not merely rejection of alphabetically sorted JSON.
		original, _ := json.Marshal(untrusted[key])
		replacement, _ := json.Marshal(bad)
		needle := append([]byte(`"`+key+`":`), original...)
		if bytes.Count(intent, needle) != 1 {
			t.Fatal("fault must replace exactly one field")
		}
		changed := bytes.Replace(intent, needle, append([]byte(`"`+key+`":`), replacement...), 1)
		if _, e := a.ApplySessionRevocation(ctx, db, owner, dsn, proof, binding, changed); e != controllerbackup.ErrInvalid {
			t.Fatal("changed durable intent accepted", key, e)
		}
	}
	if _, e := a.VerifyRestoredDatabase(ctx, db, owner, dsn, proof); e != nil {
		t.Fatal("intent refusals changed the preimage", e)
	}
	for _, bad := range []controllerbackup.SessionTransitionBinding{
		{TargetPlanSHA256: strings.Repeat("c", 64), MaterialManifestSHA256: binding.MaterialManifestSHA256, CreatedAt: binding.CreatedAt},
		{TargetPlanSHA256: binding.TargetPlanSHA256, MaterialManifestSHA256: strings.Repeat("c", 64), CreatedAt: binding.CreatedAt},
		{TargetPlanSHA256: binding.TargetPlanSHA256, MaterialManifestSHA256: binding.MaterialManifestSHA256, CreatedAt: binding.CreatedAt.Add(time.Second)},
	} {
		if _, e := a.ApplySessionRevocation(ctx, db, owner, dsn, proof, bad, intent); e != controllerbackup.ErrInvalid {
			t.Fatal("operation binding changed without rejecting persisted intent", e)
		}
	}
	// A consumed AUTO_INCREMENT without a committed row is a real MySQL
	// rollback state, not a new intent or a reason to drop/change the table.
	tx, e := db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO controller_identity_audit(id,actor,action,target,created_at) VALUES(42,'fault','fault','fault','2026-10-28')"); e != nil {
		t.Fatal(e)
	}
	if e = tx.Rollback(); e != nil {
		t.Fatal(e)
	}
	if _, e := a.ApplySessionRevocation(ctx, db, owner, dsn, proof, binding, intent); e != controllerbackup.ErrInvalid {
		t.Fatal("ordinary apply must not silently repair an interrupted counter", e)
	}
	if _, e := verify(); e != controllerbackup.ErrInvalid {
		t.Fatal("rolled-back audit must not count as successful revocation", e)
	}
	report, e := a.ResumeSessionRevocation(ctx, db, owner, dsn, proof, binding, intent)
	if e != nil || !report.SessionsRevoked || report.RevokedSessions != 2 || !report.ExactDatabaseVerified || !report.AuditAppended || report.ReadOnlyVerification || report.MigrationReady || report.TargetActivationApproved {
		t.Fatal("explicit same-intent resume must remove both authenticated and anonymous sessions", report, e)
	}
	for i := 0; i < 2; i++ {
		report, e := verify()
		if e != nil || !report.ReadOnlyVerification || !report.SessionsRevoked {
			t.Fatal("read-only unknown-commit confirmation failed", e, report)
		}
	}
	for _, apply := range []func() (controllerbackup.SessionRevocationReport, error){
		func() (controllerbackup.SessionRevocationReport, error) {
			return a.ApplySessionRevocation(ctx, db, owner, dsn, proof, binding, intent)
		},
		func() (controllerbackup.SessionRevocationReport, error) {
			return a.ResumeSessionRevocation(ctx, db, owner, dsn, proof, binding, intent)
		},
	} {
		if _, e := apply(); e != controllerbackup.ErrInvalid {
			t.Fatal("already committed transition must use status, not replay", e)
		}
	}
	var sessions, events int
	var actor, action, target, stamp string
	if db.QueryRowContext(ctx, "SELECT COUNT(*) FROM controller_console_sessions").Scan(&sessions) != nil || sessions != 0 ||
		db.QueryRowContext(ctx, "SELECT COUNT(*) FROM controller_identity_audit").Scan(&events) != nil || events != 2 ||
		db.QueryRowContext(ctx, "SELECT actor,action,target,CAST(created_at AS CHAR) FROM controller_identity_audit WHERE id=42").Scan(&actor, &action, &target, &stamp) != nil ||
		actor != "controller-migration" || action != "migration.sessions_revoked" || target != report.OperationID || stamp != "2026-10-28 09:08:07.123456" {
		t.Fatal("single event, original audit and predetermined high-water mark not retained")
	}
	conn, e := db.Conn(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	if _, e := conn.ExecContext(ctx, "SET SESSION information_schema_stats_expiry=0"); e != nil {
		t.Fatal(e)
	}
	var high string
	if conn.QueryRowContext(ctx, "SELECT CAST(AUTO_INCREMENT AS CHAR) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='controller_identity_audit'").Scan(&high) != nil || high != "43" {
		t.Fatal("counter must be checked uncached on the same SQL session")
	}
	// Each negative case is bracketed by successful full postimage checks, so a
	// SQL/protocol failure cannot accidentally make every rejection test pass.
	for _, fault := range []struct {
		change, repair string
		args           []any
	}{
		{"INSERT INTO controller_console_sessions VALUES(?,NULL,'2026-10-28','2027-01-01')", "DELETE FROM controller_console_sessions WHERE token_hash=?", []any{bytes.Repeat([]byte{66}, 32)}},
		{"UPDATE controller_identity_audit SET actor='changed' WHERE id=42", "UPDATE controller_identity_audit SET actor='controller-migration' WHERE id=42", nil},
		{"UPDATE controller_identity_audit SET target='changed' WHERE id=7", "UPDATE controller_identity_audit SET target='retained' WHERE id=7", nil},
		{"UPDATE controller_nodes SET datacenter_id='changed' WHERE id='node-a'", "UPDATE controller_nodes SET datacenter_id='香港' WHERE id='node-a'", nil},
		{"INSERT INTO controller_identity_audit(id,actor,action,target,created_at) VALUES(40,'controller-migration','migration.sessions_revoked','extra','2026-10-28')", "DELETE FROM controller_identity_audit WHERE id=40", nil},
		{"UPDATE controller_console_users SET password_hash='changed'", "UPDATE controller_console_users SET password_hash='unusable-fixture-hash'", nil},
		{"ALTER TABLE controller_console_sessions DROP FOREIGN KEY controller_console_sessions_user_fk", "ALTER TABLE controller_console_sessions ADD CONSTRAINT controller_console_sessions_user_fk FOREIGN KEY(user_id) REFERENCES controller_console_users(id) ON DELETE CASCADE", nil},
	} {
		if _, e := db.ExecContext(ctx, fault.change, fault.args...); e != nil {
			t.Fatal(e)
		}
		if _, e := verify(); e != controllerbackup.ErrInvalid {
			t.Fatal("postimage drift accepted", e)
		}
		if _, e := db.ExecContext(ctx, fault.repair, fault.args...); e != nil {
			t.Fatal(e)
		}
		if _, e := verify(); e != nil {
			t.Fatal("fixture-only repair did not restore exact postimage", e)
		}
	}
}

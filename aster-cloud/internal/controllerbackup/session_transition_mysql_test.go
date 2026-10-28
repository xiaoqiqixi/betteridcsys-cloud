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
	// The bounded schema wait must not turn duplicate operation attempts into
	// queued retries. A second connection already owns this exact operation.
	blocker, e := db.Conn(ctx)
	if e != nil {
		t.Fatal(e)
	}
	operationLock := "aster_restore_" + untrusted["operation_id"].(string)
	func() {
		defer blocker.Close()
		var owned int
		if e := blocker.QueryRowContext(ctx, "SELECT GET_LOCK(?,5)", operationLock).Scan(&owned); e != nil || owned != 1 {
			t.Fatal("fixture operation lock unavailable", e)
		}
		defer blocker.ExecContext(context.Background(), "DO RELEASE_LOCK(?)", operationLock)
		short, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		if _, e := a.ResumeSessionRevocation(short, db, owner, dsn, proof, binding, intent); e != controllerbackup.ErrInvalid || short.Err() != nil {
			t.Fatal("duplicate operation was queued instead of refused", e, short.Err())
		}
	}()
	if _, e := a.VerifyRestoredDatabase(ctx, db, owner, dsn, proof); e != nil {
		t.Fatal("duplicate attempt changed the preimage", e)
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
	report, e := resumeAfterSchemaLock(t, ctx, db, untrusted["operation_id"].(string), func(call context.Context) (controllerbackup.SessionRevocationReport, error) {
		return a.ResumeSessionRevocation(call, db, owner, dsn, proof, binding, intent)
	})
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

// A schema migration elsewhere on the same MySQL server uses the same named
// lock. Observe the actual blocked SQL request, not a guessed sleep or mocked
// query. Releasing that lock must let this one explicit resume proceed without
// replaying the operation. This is also a deterministic reproduction of the
// parallel-package Ubuntu22 failure at the public recovery boundary.
func resumeAfterSchemaLock(t *testing.T, ctx context.Context, db *sql.DB, operation string, resume func(context.Context) (controllerbackup.SessionRevocationReport, error)) (controllerbackup.SessionRevocationReport, error) {
	t.Helper()
	blocker, e := db.Conn(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer blocker.Close()
	var locked int
	if e = blocker.QueryRowContext(ctx, "SELECT GET_LOCK('aster_controller_schema_v1',5)").Scan(&locked); e != nil || locked != 1 {
		t.Fatal("fixture must actually hold the schema lock", e)
	}
	released := false
	release := func() {
		if released {
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		var unlocked int
		if e := blocker.QueryRowContext(cleanup, "SELECT RELEASE_LOCK('aster_controller_schema_v1')").Scan(&unlocked); e != nil || unlocked != 1 {
			t.Error("fixture schema lock release failed", e)
		}
		released = true
	}
	defer release()
	type outcome struct {
		report controllerbackup.SessionRevocationReport
		err    error
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	unchanged := func() {
		t.Helper()
		var sessions, audit int
		if blocker.QueryRowContext(ctx, "SELECT COUNT(*) FROM controller_console_sessions").Scan(&sessions) != nil || sessions != 2 ||
			blocker.QueryRowContext(ctx, "SELECT COUNT(*) FROM controller_identity_audit").Scan(&audit) != nil || audit != 1 {
			t.Fatal("waiting recovery changed the restored preimage")
		}
	}
	for _, cancelWaiting := range []bool{true, false} {
		call, cancel := context.WithTimeout(ctx, 8*time.Second)
		done := make(chan outcome, 1)
		settled := false
		go func() { r, e := resume(call); done <- outcome{r, e} }()
		defer func() {
			cancel()
			if !settled {
				release()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Error("owned recovery goroutine did not settle")
				}
			}
		}()
		waiting := false
		for !waiting {
			select {
			case r := <-done:
				settled = true
				t.Fatalf("explicit recovery returned before a temporary schema lock was released: %v", r.err)
			case <-call.Done():
				t.Fatal("actual schema wait was not observed", call.Err())
			case <-ticker.C:
				var count int
				q := "SELECT COUNT(*) FROM performance_schema.metadata_locks m JOIN performance_schema.threads t ON t.THREAD_ID=m.OWNER_THREAD_ID WHERE m.OBJECT_TYPE='USER LEVEL LOCK' AND m.OBJECT_NAME='aster_controller_schema_v1' AND m.LOCK_STATUS='PENDING' AND t.PROCESSLIST_ID=IS_USED_LOCK(?)"
				if e := blocker.QueryRowContext(call, q, "aster_restore_"+operation).Scan(&count); e != nil {
					t.Fatal("real metadata-lock observation unavailable", e)
				}
				waiting = count == 1
			}
		}
		unchanged()
		if cancelWaiting {
			cancel()
		} else {
			release()
		}
		select {
		case r := <-done:
			settled = true
			if !cancelWaiting {
				return r.report, r.err
			}
			if r.err != controllerbackup.ErrInvalid || call.Err() != context.Canceled || r.report.SessionsRevoked {
				t.Fatal("cancelled schema wait was accepted", r.err, r.report)
			}
			unchanged()
			// MySQL may notice the closed socket only when its bounded GET_LOCK
			// wait returns. Client cancellation must not be mistaken for instant
			// server-side release, nor followed by an automatic operation retry.
			// Release the fixture blocker now so unrelated packages sharing this
			// isolated server are not held for an entire five-second deadline.
			release()
			cleanup, stop := context.WithTimeout(ctx, 8*time.Second)
			for {
				var free int
				if e := blocker.QueryRowContext(cleanup, "SELECT IS_FREE_LOCK(?)", "aster_restore_"+operation).Scan(&free); e != nil {
					stop()
					t.Fatal("cancelled wait did not release its operation lock within the bound", e)
				}
				if free == 1 {
					break
				}
				select {
				case <-cleanup.Done():
					stop()
					t.Fatal("cancelled wait retained the operation lock beyond the server wait budget")
				case <-ticker.C:
				}
			}
			stop()
			unchanged()
			if e := blocker.QueryRowContext(ctx, "SELECT GET_LOCK('aster_controller_schema_v1',5)").Scan(&locked); e != nil || locked != 1 {
				t.Fatal("fixture failed to restore schema contention for the successful call", e)
			}
			released = false
		case <-time.After(3 * time.Second):
			t.Fatal("recovery did not settle after schema release or cancellation")
		}
	}
	panic("unreachable")
}

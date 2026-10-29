package controllerbackup_test

import (
	"aster/cloud/internal/controllerbackup"
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

// Same authenticated archive/real SQL seam as restore and session transition.
// SQL fixtures describe permitted data shapes, NOT browser/host activation.
func exerciseVerificationDataPhase(t *testing.T, ctx context.Context, a *controllerbackup.Archive, db *sql.DB, owner []byte, dsn string, proof []byte, sessions controllerbackup.SessionTransitionBinding, sessionIntent []byte) {
	t.Helper()
	binding := controllerbackup.VerificationDataBinding{
		VerificationPlanSHA256: strings.Repeat("c", 64), AccountReceiptSHA256: strings.Repeat("d", 64),
		StartedAt: sessions.CreatedAt.Add(time.Minute), ExpiresAt: sessions.CreatedAt.Add(time.Hour + time.Minute),
	}
	intent, e := a.PlanVerificationDataPhase(ctx, db, owner, dsn, proof, sessions, sessionIntent, binding)
	if e != nil || len(intent) == 0 {
		t.Fatal("exact revoked image must produce a bound verification phase", e)
	}
	if _, e := a.VerifyRevokedSessions(ctx, db, owner, dsn, proof, sessions, sessionIntent); e != nil {
		t.Fatal("planning modified restored state", e)
	}
	verify := func() (controllerbackup.VerificationDataReport, error) {
		return a.VerifyVerificationDataPhase(ctx, db, owner, dsn, proof, sessions, sessionIntent, binding, intent)
	}
	report, e := verify()
	if e != nil || !report.BusinessDataUnchanged || !report.HistoricalAuditPreserved || !report.AuthenticationDataValidated || !report.ReadOnlyVerification || report.MigrationReady || report.TargetActivationApproved || report.AppendedAuditRows != 0 {
		t.Fatal("empty verification stage not accurately reported", e, report)
	}
	changed := bytes.Replace(intent, []byte(strings.Repeat("c", 64)), []byte(strings.Repeat("e", 64)), 1)
	if _, e := a.VerifyVerificationDataPhase(ctx, db, owner, dsn, proof, sessions, sessionIntent, binding, changed); e != controllerbackup.ErrInvalid {
		t.Fatal("changed phase binding accepted", e)
	}
	for _, bad := range []controllerbackup.VerificationDataBinding{
		{VerificationPlanSHA256: binding.VerificationPlanSHA256, AccountReceiptSHA256: strings.Repeat("e", 64), StartedAt: binding.StartedAt, ExpiresAt: binding.ExpiresAt},
		{VerificationPlanSHA256: binding.VerificationPlanSHA256, AccountReceiptSHA256: binding.AccountReceiptSHA256, StartedAt: binding.StartedAt.Add(time.Second), ExpiresAt: binding.ExpiresAt},
	} {
		if _, e := a.VerifyVerificationDataPhase(ctx, db, owner, dsn, proof, sessions, sessionIntent, bad, intent); e != controllerbackup.ErrInvalid {
			t.Fatal("a different approved phase accepted original intent", e)
		}
	}
	for _, mutate := range []func(*controllerbackup.VerificationDataBinding){
		func(b *controllerbackup.VerificationDataBinding) { b.VerificationPlanSHA256 = "" },
		func(b *controllerbackup.VerificationDataBinding) { b.AccountReceiptSHA256 = strings.Repeat("D", 64) },
		func(b *controllerbackup.VerificationDataBinding) {
			b.StartedAt = sessions.CreatedAt.Add(-time.Microsecond)
		},
		func(b *controllerbackup.VerificationDataBinding) { b.StartedAt = b.StartedAt.Add(time.Nanosecond) },
		func(b *controllerbackup.VerificationDataBinding) { b.ExpiresAt = b.ExpiresAt.Add(time.Nanosecond) },
		func(b *controllerbackup.VerificationDataBinding) { b.ExpiresAt = b.StartedAt },
		func(b *controllerbackup.VerificationDataBinding) {
			b.ExpiresAt = b.StartedAt.Add(time.Hour + time.Microsecond)
		},
		func(b *controllerbackup.VerificationDataBinding) {
			b.StartedAt = b.StartedAt.In(time.FixedZone("not UTC", 3600))
		},
	} {
		bad := binding
		mutate(&bad)
		if _, e := a.PlanVerificationDataPhase(ctx, db, owner, dsn, proof, sessions, sessionIntent, bad); e != controllerbackup.ErrInvalid {
			t.Fatal("invalid approval interval or binding accepted", e)
		}
	}
	if _, e := db.ExecContext(ctx, "UPDATE controller_console_login_limits SET attempts=2 WHERE bucket=?", bytes.Repeat([]byte{88}, 32)); e != nil {
		t.Fatal(e)
	}
	if report, e := verify(); e != nil || report.CurrentLoginBuckets != 3 {
		t.Fatal("a still-live source window must accept normal bounded increments without resetting its timestamp", e, report)
	}
	// Synthetic authentication records with the same exact shapes as identity;
	// source cookies must never reappear, even with a new creation timestamp.
	at := binding.StartedAt.Add(time.Second).Format("2006-01-02 15:04:05.000000")
	until := binding.StartedAt.Add(8*time.Hour + time.Second).Format("2006-01-02 15:04:05.000000")
	uid := strings.Repeat("a", 32)
	token := bytes.Repeat([]byte{77}, 32)
	if _, e := db.ExecContext(ctx, "INSERT INTO controller_console_sessions VALUES(?,?,?,?)", token, uid, at, until); e != nil {
		t.Fatal(e)
	}
	if _, e := db.ExecContext(ctx, "INSERT INTO controller_console_login_limits VALUES(?,?,1)", bytes.Repeat([]byte{91}, 32), at); e != nil {
		t.Fatal(e)
	}
	if _, e := db.ExecContext(ctx, "INSERT INTO controller_identity_audit(actor,action,target,created_at) VALUES(?,'identity.login',?,?)", uid, uid, at); e != nil {
		t.Fatal(e)
	}
	report, e = verify()
	if e != nil || report.AppendedAuditRows != 1 || report.CurrentSessions != 1 || report.CurrentLoginBuckets != 4 {
		t.Fatal("valid authentication delta refused", e, report)
	}
	for _, fault := range []struct {
		name, change, repair   string
		changeArgs, repairArgs []any
	}{
		{"live bucket cannot disappear", "DELETE FROM controller_console_login_limits WHERE bucket=?", "INSERT INTO controller_console_login_limits VALUES(?,'2026-10-28 09:07:07.123456',2)", []any{bytes.Repeat([]byte{88}, 32)}, []any{bytes.Repeat([]byte{88}, 32)}},
		{"expired window is not yet cleanup eligible", "DELETE FROM controller_console_login_limits WHERE bucket=?", "INSERT INTO controller_console_login_limits VALUES(?,'2026-10-28 08:00:00.000000',5)", []any{bytes.Repeat([]byte{89}, 32)}, []any{bytes.Repeat([]byte{89}, 32)}},
		{"source attempts cannot decrease", "UPDATE controller_console_login_limits SET attempts=0 WHERE bucket=?", "UPDATE controller_console_login_limits SET attempts=2 WHERE bucket=?", []any{bytes.Repeat([]byte{88}, 32)}, []any{bytes.Repeat([]byte{88}, 32)}},
		{"live window cannot reset early", "UPDATE controller_console_login_limits SET window_at=? WHERE bucket=?", "UPDATE controller_console_login_limits SET window_at='2026-10-28 09:07:07.123456' WHERE bucket=?", []any{at, bytes.Repeat([]byte{88}, 32)}, []any{bytes.Repeat([]byte{88}, 32)}},
		{"expired window cannot keep incrementing", "UPDATE controller_console_login_limits SET attempts=6 WHERE bucket=?", "UPDATE controller_console_login_limits SET attempts=5 WHERE bucket=?", []any{bytes.Repeat([]byte{89}, 32)}, []any{bytes.Repeat([]byte{89}, 32)}},
		{"new bucket needs a committed attempt", "UPDATE controller_console_login_limits SET attempts=0 WHERE bucket=?", "UPDATE controller_console_login_limits SET attempts=1 WHERE bucket=?", []any{bytes.Repeat([]byte{91}, 32)}, []any{bytes.Repeat([]byte{91}, 32)}},
		{"new bucket cannot exceed authentication ceiling", "UPDATE controller_console_login_limits SET attempts=4097 WHERE bucket=?", "UPDATE controller_console_login_limits SET attempts=1 WHERE bucket=?", []any{bytes.Repeat([]byte{91}, 32)}, []any{bytes.Repeat([]byte{91}, 32)}},
		{"new bucket must belong to approved interval", "UPDATE controller_console_login_limits SET window_at=? WHERE bucket=?", "UPDATE controller_console_login_limits SET window_at=? WHERE bucket=?", []any{binding.ExpiresAt.Format("2006-01-02 15:04:05.000000"), bytes.Repeat([]byte{91}, 32)}, []any{at, bytes.Repeat([]byte{91}, 32)}},
	} {
		t.Run(fault.name, func(t *testing.T) {
			if _, e := db.ExecContext(ctx, fault.change, fault.changeArgs...); e != nil {
				t.Fatal(e)
			}
			if _, e := verify(); e != controllerbackup.ErrInvalid {
				t.Error("invalid limiter change accepted", e)
			}
			if _, e := db.ExecContext(ctx, fault.repair, fault.repairArgs...); e != nil {
				t.Fatal(e)
			}
			if _, e := verify(); e != nil {
				t.Fatal("fixture-only undo did not restore valid verification state", e)
			}
		})
	}
	// Existing authentication legitimately resets an expired window and prunes
	// buckets at least 24 hours old; neither operation may be broadly forbidden.
	if _, e := db.ExecContext(ctx, "UPDATE controller_console_login_limits SET window_at=?,attempts=1 WHERE bucket=?", at, bytes.Repeat([]byte{89}, 32)); e != nil {
		t.Fatal(e)
	}
	if _, e := db.ExecContext(ctx, "DELETE FROM controller_console_login_limits WHERE bucket=?", bytes.Repeat([]byte{90}, 32)); e != nil {
		t.Fatal(e)
	}
	if report, e := verify(); e != nil || report.CurrentLoginBuckets != 3 {
		t.Fatal("valid expiry/reset and cleanup refused", e, report)
	}
	anonymousToken := bytes.Repeat([]byte{66}, 32)
	anonymousUntil := binding.StartedAt.Add(time.Second + 10*time.Minute).Format("2006-01-02 15:04:05.000000")
	if _, e := db.ExecContext(ctx, "INSERT INTO controller_console_sessions VALUES(?,NULL,?,?)", anonymousToken, at, anonymousUntil); e != nil {
		t.Fatal(e)
	}
	if report, e := verify(); e != nil || report.CurrentSessions != 2 {
		t.Fatal("valid authenticated and anonymous sessions must remain distinct", e, report)
	}
	oldToken := make([]byte, 32)
	for i := range oldToken {
		oldToken[i] = byte(i)
	}
	for _, fault := range []struct {
		name, change, repair   string
		changeArgs, repairArgs []any
	}{
		{"old authenticated cookie cannot revive", "UPDATE controller_console_sessions SET token_hash=? WHERE token_hash=?", "UPDATE controller_console_sessions SET token_hash=? WHERE token_hash=?", []any{oldToken, token}, []any{token, oldToken}},
		{"old anonymous cookie cannot revive", "UPDATE controller_console_sessions SET token_hash=? WHERE token_hash=?", "UPDATE controller_console_sessions SET token_hash=? WHERE token_hash=?", []any{bytes.Repeat([]byte{255}, 32), anonymousToken}, []any{anonymousToken, bytes.Repeat([]byte{255}, 32)}},
		{"disabled source account cannot get a session", "UPDATE controller_console_sessions SET user_id=? WHERE token_hash=?", "UPDATE controller_console_sessions SET user_id=? WHERE token_hash=?", []any{strings.Repeat("b", 32), token}, []any{uid, token}},
		{"session cannot predate approved interval", "UPDATE controller_console_sessions SET created_at=? WHERE token_hash=?", "UPDATE controller_console_sessions SET created_at=? WHERE token_hash=?", []any{binding.StartedAt.Add(-time.Microsecond).Format("2006-01-02 15:04:05.000000"), token}, []any{at, token}},
		{"session cannot begin at expiry", "UPDATE controller_console_sessions SET created_at=? WHERE token_hash=?", "UPDATE controller_console_sessions SET created_at=? WHERE token_hash=?", []any{binding.ExpiresAt.Format("2006-01-02 15:04:05.000000"), token}, []any{at, token}},
		{"authenticated session must respect minimum identity lifetime", "UPDATE controller_console_sessions SET expires_at=? WHERE token_hash=?", "UPDATE controller_console_sessions SET expires_at=? WHERE token_hash=?", []any{binding.StartedAt.Add(time.Second + time.Minute).Format("2006-01-02 15:04:05.000000"), token}, []any{until, token}},
		{"authenticated session cannot outlive maximum identity lifetime", "UPDATE controller_console_sessions SET expires_at=? WHERE token_hash=?", "UPDATE controller_console_sessions SET expires_at=? WHERE token_hash=?", []any{binding.StartedAt.Add(time.Second + 24*time.Hour + time.Microsecond).Format("2006-01-02 15:04:05.000000"), token}, []any{until, token}},
		{"anonymous session lifetime must match identity protocol", "UPDATE controller_console_sessions SET expires_at=? WHERE token_hash=?", "UPDATE controller_console_sessions SET expires_at=? WHERE token_hash=?", []any{binding.StartedAt.Add(time.Second + 5*time.Minute).Format("2006-01-02 15:04:05.000000"), anonymousToken}, []any{anonymousUntil, anonymousToken}},
		{"anonymous session cannot borrow authenticated lifetime", "UPDATE controller_console_sessions SET expires_at=? WHERE token_hash=?", "UPDATE controller_console_sessions SET expires_at=? WHERE token_hash=?", []any{until, anonymousToken}, []any{anonymousUntil, anonymousToken}},
	} {
		t.Run(fault.name, func(t *testing.T) {
			if _, e := db.ExecContext(ctx, fault.change, fault.changeArgs...); e != nil {
				t.Fatal(e)
			}
			if _, e := verify(); e != controllerbackup.ErrInvalid {
				t.Error("invalid session change accepted", e)
			}
			if _, e := db.ExecContext(ctx, fault.repair, fault.repairArgs...); e != nil {
				t.Fatal(e)
			}
			if _, e := verify(); e != nil {
				t.Fatal("fixture-only undo did not restore valid session state", e)
			}
		})
	}
	for _, fault := range []struct {
		name, change, repair string
	}{
		{"historical audit bytes cannot change", "UPDATE controller_identity_audit SET target='changed' WHERE id=-9223372036854775808", "UPDATE controller_identity_audit SET target='retained' WHERE id=-9223372036854775808"},
		{"historical audit cannot disappear", "DELETE FROM controller_identity_audit WHERE id=-9223372036854775808", "INSERT INTO controller_identity_audit VALUES(-9223372036854775808,'historical','historical','retained','2026-10-27 01:00:00.000001')"},
		{"original revocation event cannot change", "UPDATE controller_identity_audit SET actor='changed' WHERE id=42", "UPDATE controller_identity_audit SET actor='controller-migration' WHERE id=42"},
		{"new audit cannot impersonate a business write", "UPDATE controller_identity_audit SET action='user.updated' WHERE id=43", "UPDATE controller_identity_audit SET action='identity.login' WHERE id=43"},
		{"new login audit needs the same actor and target", "UPDATE controller_identity_audit SET target=REPEAT('b',32) WHERE id=43", "UPDATE controller_identity_audit SET target=REPEAT('a',32) WHERE id=43"},
		{"new audit cannot predate approval", "UPDATE controller_identity_audit SET created_at='2026-10-28 09:09:07.123455' WHERE id=43", "UPDATE controller_identity_audit SET created_at='2026-10-28 09:09:08.123456' WHERE id=43"},
		{"new audit cannot begin at expiry", "UPDATE controller_identity_audit SET created_at='2026-10-28 10:09:07.123456' WHERE id=43", "UPDATE controller_identity_audit SET created_at='2026-10-28 09:09:08.123456' WHERE id=43"},
		{"business rows stay exact", "UPDATE controller_nodes SET datacenter_id='changed' WHERE id='node-a'", "UPDATE controller_nodes SET datacenter_id='香港' WHERE id='node-a'"},
		{"passwords stay exact", "UPDATE controller_console_users SET password_hash='changed'", "UPDATE controller_console_users SET password_hash='unusable-fixture-hash'"},
		{"permissions stay exact", "UPDATE controller_console_users SET permissions=JSON_ARRAY('changed')", "UPDATE controller_console_users SET permissions=JSON_ARRAY()"},
		{"authentication foreign key stays exact", "ALTER TABLE controller_console_sessions DROP FOREIGN KEY controller_console_sessions_user_fk", "ALTER TABLE controller_console_sessions ADD CONSTRAINT controller_console_sessions_user_fk FOREIGN KEY(user_id) REFERENCES controller_console_users(id) ON DELETE CASCADE"},
		{"unrelated table cannot be hidden", "CREATE TABLE forbidden_verification_table(id INT PRIMARY KEY) ENGINE=InnoDB", "DROP TABLE forbidden_verification_table"},
		{"trigger cannot be hidden", "CREATE TRIGGER forbidden_verification_trigger BEFORE INSERT ON controller_console_sessions FOR EACH ROW SET NEW.created_at=NEW.created_at", "DROP TRIGGER forbidden_verification_trigger"},
	} {
		t.Run(fault.name, func(t *testing.T) {
			if _, e := db.ExecContext(ctx, fault.change); e != nil {
				t.Fatal(e)
			}
			if _, e := verify(); e != controllerbackup.ErrInvalid {
				t.Error("business, schema or audit drift accepted", e)
			}
			if _, e := db.ExecContext(ctx, fault.repair); e != nil {
				t.Fatal(e)
			}
			if _, e := verify(); e != nil {
				t.Fatal("fixture-only undo did not restore valid data proof", e)
			}
		})
	}
	if _, e := db.ExecContext(ctx, "INSERT INTO controller_identity_audit(actor,action,target,created_at) VALUES(?,'identity.logout',?,?),('anonymous','identity.login_failed',?,?)", uid, uid, at, strings.Repeat("f", 64), at); e != nil {
		t.Fatal(e)
	}
	// A rolled-back insertion consumes an ID on real MySQL. Rejecting every
	// gap would prevent a valid verification stop after a canceled request.
	tx, e := db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := tx.ExecContext(ctx, "INSERT INTO controller_identity_audit(actor,action,target,created_at) VALUES(?,'identity.logout',?,?)", uid, uid, at); e != nil {
		tx.Rollback()
		t.Fatal(e)
	}
	if e := tx.Rollback(); e != nil {
		t.Fatal(e)
	}
	if report, e := verify(); e != nil || report.AppendedAuditRows != 3 {
		t.Fatal("allowed audit actions and rolled-back high-water gap refused", e, report)
	}
	// Read access is not authority to replace the protected migration identity.
	// Keep the original CURRENT_USER binding, even for an otherwise legitimate
	// local account. Its write probe must return a real permission error.
	t.Run("read access cannot replace bound migration identity", func(t *testing.T) {
		limited := verificationDataReadOnlyFixture(t, ctx, db, dsn)
		if report, e := a.VerifyVerificationDataPhase(ctx, limited, owner, dsn, proof, sessions, sessionIntent, binding, intent); e != controllerbackup.ErrInvalid || report != (controllerbackup.VerificationDataReport{}) {
			t.Fatal("foreign SQL identity replaced original migration identity", e, report)
		}
	})
	if report, e := verify(); e != nil || report.AppendedAuditRows != 3 {
		t.Fatal("foreign identity refusal changed the approved image", e, report)
	}
	if _, e := a.PlanVerificationDataPhase(ctx, db, owner, dsn, proof, sessions, sessionIntent, binding); e != controllerbackup.ErrInvalid {
		t.Fatal("changed image silently adopted as a new baseline", e)
	}
	if _, e := a.VerifyRevokedSessions(ctx, db, owner, dsn, proof, sessions, sessionIntent); e != controllerbackup.ErrInvalid {
		t.Fatal("ordinary exact-postimage check was weakened", e)
	}
}

func verificationDataReadOnlyFixture(t *testing.T, ctx context.Context, admin *sql.DB, dsn string) *sql.DB {
	t.Helper()
	cfg, e := mysql.ParseDSN(dsn)
	if e != nil {
		t.Fatal("owned fixture DSN invalid")
	}
	secret := make([]byte, 32)
	if _, e := rand.Read(secret); e != nil {
		t.Fatal("fixture randomness unavailable")
	}
	user := "aster_v_" + hex.EncodeToString(secret[:12])
	password := hex.EncodeToString(secret)
	account := "`" + user + "`@`localhost`"
	if _, e := admin.ExecContext(ctx, "CREATE USER "+account+" IDENTIFIED BY '"+password+"'"); e != nil {
		t.Fatal("owned read-only account creation failed")
	}
	var db *sql.DB
	t.Cleanup(func() {
		if db != nil {
			db.Close()
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, e := admin.ExecContext(cleanup, "DROP USER "+account); e != nil {
			t.Error("owned read-only account cleanup failed")
		}
	})
	schema := "`" + strings.ReplaceAll(cfg.DBName, "_", `\_`) + "`.*"
	if _, e := admin.ExecContext(ctx, "GRANT SELECT ON "+schema+" TO "+account); e != nil {
		t.Fatal("read-only fixture grant failed")
	}
	cfg.User, cfg.Passwd = user, password
	db, e = sql.Open("mysql", cfg.FormatDSN())
	if e != nil || db.PingContext(ctx) != nil {
		t.Fatal("read-only fixture login failed")
	}
	_, e = db.ExecContext(ctx, "UPDATE controller_console_users SET name='forbidden' WHERE 1=0")
	var denial *mysql.MySQLError
	if !errors.As(e, &denial) || denial.Number != 1142 {
		t.Fatalf("read-only fixture must receive explicit MySQL 1142, got %T", e)
	}
	return db
}

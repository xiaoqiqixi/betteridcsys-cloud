package identity

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestMySQLAnonymousFloodPreservesAdminAdmission(t *testing.T) {
	s, db := mysqlIdentity(t)
	admin := bootstrap(t, s)
	authenticated := loginUser(t, s, admin)
	// A fixed microsecond clock also exercises the deterministic token-hash
	// tiebreaker for simultaneous creation. No anonymous creation bucket may
	// refuse a new prefix, even after more than 4096 requests in this window.
	now := s.now().Truncate(time.Microsecond)
	s.nowFn = func() time.Time { return now }
	oldest, err := s.anonymousSession(context.Background(), "198.51.100.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	for i := range 4100 {
		peer := fmt.Sprintf("[2001:db8:%x::1]:1234", i)
		if _, err := s.anonymousSession(context.Background(), peer); err != nil {
			t.Fatalf("distributed request %d refused: %v", i, err)
		}
	}
	if _, err = s.lookupSession(context.Background(), oldest); !errors.Is(err, ErrAuthentication) {
		t.Fatal("oldest anonymous session survived eviction", err)
	}
	if got, err := s.authenticate(context.Background(), authenticated); err != nil || got.ID != admin.ID {
		t.Fatal("anonymous flood evicted authenticated session", err)
	}
	now = now.Add(time.Second)
	peer := "203.0.113.123:443"
	challenge, err := s.anonymousSession(context.Background(), peer)
	if err != nil {
		t.Fatal("new administrator prefix refused", err)
	}
	var count int
	if err = db.QueryRow("SELECT COUNT(*) FROM controller_console_sessions WHERE user_id IS NULL AND expires_at>?", now).Scan(&count); err != nil || count != 4096 {
		t.Fatal("anonymous storage ceiling lost", count, err)
	}
	if got, _, err := s.login(context.Background(), admin.Email, testPassword, challenge, peer); err != nil || got.ID != admin.ID {
		t.Fatal("administrator could not log in after distributed flood", err)
	}
}

func TestMySQLLoginFailuresCannotLockAccount(t *testing.T) {
	s, db := mysqlIdentity(t)
	admin := bootstrap(t, s)
	now := s.now().Truncate(time.Microsecond)
	s.nowFn = func() time.Time { return now }
	attacker := "[2001:db8:bad:1::1]:1234"
	challenge, err := s.anonymousSession(context.Background(), attacker)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 40 {
		if _, _, err = s.login(context.Background(), admin.Email, "incorrect password", challenge, attacker); !errors.Is(err, ErrAuthentication) {
			t.Fatal("failed login did not reach authentication", i, err)
		}
	}
	var count int
	if err = db.QueryRow("SELECT COUNT(*) FROM controller_console_login_limits").Scan(&count); err != nil || count != 2 {
		t.Fatal("login wrote non-prefix rate limits", count, err)
	}
	if err = db.QueryRow("SELECT COUNT(*) FROM controller_identity_audit WHERE action='identity.login_failed'").Scan(&count); err != nil || count != 40 {
		t.Fatal("failure auditing lost", count, err)
	}
	reopened, _ := New(db, Config{Origin: s.origin})
	reopened.nowFn = s.nowFn
	if err = reopened.reserveLogin(context.Background(), "[2001:db8:bad:1::ffff]:9999"); !errors.Is(err, ErrRateLimited) {
		t.Fatal("IPv6 host rotation or restart bypassed prefix limit", err)
	}
	if _, _, err = reopened.login(context.Background(), "another@example.invalid", testPassword, challenge, attacker); !errors.Is(err, ErrRateLimited) {
		t.Fatal("email rotation bypassed prefix limit", err)
	}
	peer := "203.0.113.89:443"
	// Old account counters may survive an upgrade. They must neither deny nor
	// delay a new prefix, and successful login must not rewrite those buckets.
	legacy := [][32]byte{
		tokenHash("email:" + admin.Email),
		tokenHash("login:email-backoff:" + admin.Email),
		tokenHash("login:email-ip:" + admin.Email + "\x00" + loginIP(peer)),
	}
	for _, bucket := range legacy {
		if _, err = db.Exec("INSERT INTO controller_console_login_limits(bucket,window_at,attempts) VALUES(?,?,100)", bucket[:], now); err != nil {
			t.Fatal(err)
		}
	}
	challenge, err = reopened.anonymousSession(context.Background(), peer)
	if err != nil {
		t.Fatal(err)
	}
	if got, _, err := reopened.login(context.Background(), admin.Email, testPassword, challenge, peer); err != nil || got.ID != admin.ID {
		t.Fatal("attacker locked out administrator on new prefix", err)
	}
	for _, bucket := range legacy {
		var at time.Time
		var attempts int
		if err = db.QueryRow("SELECT window_at,attempts FROM controller_console_login_limits WHERE bucket=?", bucket[:]).Scan(&at, &attempts); err != nil || attempts != 100 || !at.Equal(now) {
			t.Fatal("login still uses legacy account counters", attempts, at, err)
		}
	}
	if err = reopened.reserveLogin(context.Background(), attacker); !errors.Is(err, ErrRateLimited) {
		t.Fatal("successful login cleared another peer's attempt budget", err)
	}
}

func TestMySQLAnonymousIPv6PrefixLimit(t *testing.T) {
	s, _ := mysqlIdentity(t)
	for i := range 41 {
		_, err := s.anonymousSession(context.Background(), fmt.Sprintf("[2001:db8:abcd:1::%x]:1234", i))
		if i < 40 && err != nil || i == 40 && !errors.Is(err, ErrRateLimited) {
			t.Fatal("anonymous IPv6 /64 limit not enforced", i, err)
		}
	}
	if _, err := s.anonymousSession(context.Background(), "[2001:db8:abcd:2::1]:1234"); err != nil {
		t.Fatal("independent /64 inherited limit", err)
	}
}

func TestMySQLSuccessfulLoginConsumesPeerBudget(t *testing.T) {
	s, db := mysqlIdentity(t)
	admin := bootstrap(t, s)
	for range 12 {
		loginUser(t, s, admin)
	}
	bucket := tokenHash("ip:192.0.2.11")
	var attempts int
	if err := db.QueryRow("SELECT attempts FROM controller_console_login_limits WHERE bucket=?", bucket[:]).Scan(&attempts); err != nil || attempts != 12 {
		t.Fatal("successful login reset its prefix budget", attempts, err)
	}
	for range 28 {
		if err := s.reserveLogin(context.Background(), "192.0.2.11:1234"); err != nil {
			t.Fatal(err)
		}
	}
	challenge, err := s.anonymousSession(context.Background(), "192.0.2.11:4321")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.login(context.Background(), admin.Email, testPassword, challenge, "192.0.2.11:4321"); !errors.Is(err, ErrRateLimited) {
		t.Fatal("valid credentials bypassed an exhausted prefix budget", err)
	}
}

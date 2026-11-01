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

func TestMySQLLoginFailureIsolationAndBackoff(t *testing.T) {
	s, db := mysqlIdentity(t)
	admin := bootstrap(t, s)
	now := s.now().Truncate(time.Microsecond)
	s.nowFn = func() time.Time { return now }
	attacker := "[2001:db8:bad:1::1]:1234"
	challenge, err := s.anonymousSession(context.Background(), attacker)
	if err != nil {
		t.Fatal(err)
	}
	account := tokenHash("login:email-backoff:" + admin.Email)
	for i := range 10 {
		// Advance only the fixture clock, keeping the pair in its 15m window.
		now = now.Add(3 * time.Second)
		if _, _, err = s.login(context.Background(), admin.Email, "incorrect password", challenge, attacker); !errors.Is(err, ErrAuthentication) {
			t.Fatal("failed login did not reach authentication", i, err)
		}
		var failures int
		var at time.Time
		if err = db.QueryRow("SELECT window_at,attempts FROM controller_console_login_limits WHERE bucket=?", account[:]).Scan(&at, &failures); err != nil || failures != min(i+1, 6) || !at.Equal(now) {
			t.Fatal("account backoff not persisted/capped", failures, at, err)
		}
	}
	reopened, _ := New(db, Config{Origin: s.origin})
	reopened.nowFn = s.nowFn
	if err = reopened.reserveLogin(context.Background(), admin.Email, "[2001:db8:bad:1::ffff]:9999"); !errors.Is(err, ErrRateLimited) {
		t.Fatal("IPv6 host rotation or restart bypassed pair limit", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = s.waitLoginBackoff(ctx, admin.Email); !errors.Is(err, context.Canceled) {
		t.Fatal("backoff ignored cancellation", err)
	}
	peer := "203.0.113.89:443"
	challenge, err = reopened.anonymousSession(context.Background(), peer)
	if err != nil {
		t.Fatal(err)
	}
	// The account is at maximum backoff right now: a new prefix must wait a
	// bounded delay and authenticate, rather than inheriting a hard lockout.
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if got, _, err := reopened.login(ctx, admin.Email, testPassword, challenge, peer); err != nil || got.ID != admin.ID {
		t.Fatal("attacker locked out administrator on new prefix", err)
	}
	var count int
	if err = db.QueryRow("SELECT COUNT(*) FROM controller_console_login_limits WHERE bucket=?", account[:]).Scan(&count); err != nil || count != 0 {
		t.Fatal("successful login did not clear account backoff", err)
	}
	if err = reopened.reserveLogin(context.Background(), admin.Email, attacker); !errors.Is(err, ErrRateLimited) {
		t.Fatal("successful login cleared another peer's failure budget", err)
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

func TestMySQLSuccessfulLoginClearsOwnFailureReservation(t *testing.T) {
	s, _ := mysqlIdentity(t)
	admin := bootstrap(t, s)
	for range 12 {
		loginUser(t, s, admin)
	}
}

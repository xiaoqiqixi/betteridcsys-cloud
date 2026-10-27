package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The first read occurs in decode, after the real Require/CSRF middleware.
// No production hook or scheduling sleep is needed to hold that boundary.
type identityBodyGate struct {
	body    io.Reader
	ctx     context.Context
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (g *identityBodyGate) Read(p []byte) (int, error) {
	g.once.Do(func() { close(g.entered) })
	select {
	case <-g.release:
		return g.body.Read(p)
	case <-g.ctx.Done():
		return 0, g.ctx.Err()
	}
}

func identityCSRFHTTP(t *testing.T, s *Service, token string) string {
	t.Helper()
	r := httptest.NewRequest("GET", s.origin+"/console/v1/auth/csrf", nil)
	r.AddCookie(&http.Cookie{Name: CookieName, Value: token})
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	var body struct {
		Token string `json:"csrf_token"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Token == "" {
		t.Fatal("real authenticated CSRF exchange failed")
	}
	return body.Token
}

func identityHTTPMutation(t *testing.T, s *Service, token, method, path string, value any) *httptest.ResponseRecorder {
	t.Helper()
	value = identityFixtureInput(t, s, method, path, value)
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(method, s.origin+path, bytes.NewReader(b))
	r.AddCookie(&http.Cookie{Name: CookieName, Value: token})
	r.Header.Set("Origin", s.origin)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", identityCSRFHTTP(t, s, token))
	k, _ := randomToken()
	r.Header.Set("Idempotency-Key", k[:32])
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func queuedIdentityMutation(t *testing.T, s *Service, token, method, path string, value any) (func(), func() *httptest.ResponseRecorder) {
	t.Helper()
	value = identityFixtureInput(t, s, method, path, value)
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	gate := &identityBodyGate{body: bytes.NewReader(b), ctx: ctx, entered: make(chan struct{}), release: make(chan struct{})}
	r := httptest.NewRequest(method, s.origin+path, gate).WithContext(ctx)
	r.AddCookie(&http.Cookie{Name: CookieName, Value: token})
	r.Header.Set("Origin", s.origin)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", identityCSRFHTTP(t, s, token))
	k, _ := randomToken()
	r.Header.Set("Idempotency-Key", k[:32])
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { defer close(done); s.Handler().ServeHTTP(w, r) }()
	var once sync.Once
	release := func() { once.Do(func() { close(gate.release) }) }
	t.Cleanup(func() {
		release()
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("owned queued identity request failed to stop")
		}
	})
	select {
	case <-gate.entered:
	case <-done:
		t.Fatalf("request failed before the authenticated body boundary: HTTP %d", w.Code)
	case <-ctx.Done():
		t.Fatal("authenticated identity request did not reach its body boundary")
	}
	return release, func() *httptest.ResponseRecorder {
		t.Helper()
		select {
		case <-done:
			return w
		case <-ctx.Done():
			t.Fatal("queued identity request did not finish")
			return nil
		}
	}
}

func requireIdentity401(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if response.Code != 401 || json.Unmarshal(response.Body.Bytes(), &body) != nil || body.Error.Code != "AUTH_REQUIRED" || !strings.HasPrefix(response.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("revoked queued write must return complete HTTP 401 AUTH_REQUIRED, got %d", response.Code)
	}
}

// B1 keeps its HTTP/session-race seam but uses the current strict identity wire
// contract. B's malformed-input tests use a separate raw helper without defaults.
func identityFixtureInput(t *testing.T, s *Service, method, path string, value any) any {
	t.Helper()
	if !strings.HasPrefix(path, "/console/v1/users") || method == "GET" {
		return value
	}
	b, e := json.Marshal(value)
	if e != nil {
		t.Fatal(e)
	}
	var v map[string]any
	if json.Unmarshal(b, &v) != nil {
		t.Fatal("fixture input is not an object")
	}
	if _, ok := v["reason"]; !ok {
		v["reason"] = "Isolated HTTP session fixture"
	}
	if method == "PATCH" {
		if _, ok := v["revision"]; !ok {
			var rev uint64
			if e = s.db.QueryRow("SELECT revision FROM controller_console_users WHERE id=?", strings.TrimPrefix(path, "/console/v1/users/")).Scan(&rev); e != nil {
				t.Fatal(e)
			}
			v["revision"] = rev
		}
	}
	return v
}

func TestMySQLQueuedIdentityWritesRecheckSession(t *testing.T) {
	for _, method := range []string{"POST", "PATCH"} {
		for _, revoke := range []string{"logout", "password", "expiry"} {
			t.Run(method+"_"+revoke, func(t *testing.T) {
				s, db := mysqlIdentity(t)
				var clock atomic.Int64
				clock.Store(time.Now().UTC().UnixMicro())
				s.nowFn = func() time.Time { return time.UnixMicro(clock.Load()) }
				admin := bootstrap(t, s)
				other := create(t, s, admin, "other-admin@example.invalid", "admin", nil)
				target := create(t, s, admin, "target@example.invalid", "viewer", nil)
				token := loginUsersPageHTTP(t, s, admin)
				otherToken := loginUsersPageHTTP(t, s, other)
				var otherDevice string
				if revoke == "logout" {
					otherDevice = loginUsersPageHTTP(t, s, admin)
				}
				path := "/console/v1/users"
				var payload any = map[string]any{"email": "queued-new@example.invalid", "name": "Must not exist", "role": "viewer", "password": testPassword}
				if method == "PATCH" {
					path += "/" + target.ID
					payload = map[string]any{"name": "Must not change"}
				}
				var before int
				if err := db.QueryRow("SELECT COUNT(*) FROM controller_identity_audit WHERE action IN ('identity.user_created','identity.user_updated')").Scan(&before); err != nil {
					t.Fatal(err)
				}
				release, wait := queuedIdentityMutation(t, s, token, method, path, payload)
				switch revoke {
				case "logout":
					if response := identityHTTPMutation(t, s, token, "POST", "/console/v1/auth/logout", map[string]any{}); response.Code != 204 {
						t.Fatalf("real logout did not commit: HTTP %d", response.Code)
					}
				case "password":
					if response := identityHTTPMutation(t, s, otherToken, "PATCH", "/console/v1/users/"+admin.ID, map[string]any{"password": "a separate private reset password 456"}); response.Code != 200 {
						t.Fatalf("real password reset did not commit: HTTP %d", response.Code)
					}
					before++ // Only the other administrator's explicit update is allowed.
				case "expiry":
					clock.Add(int64(s.ttl / time.Microsecond)) // Exactly at the expiry boundary.
				}
				release()
				requireIdentity401(t, wait())
				var count, audits int
				var name string
				if err := db.QueryRow("SELECT COUNT(*) FROM controller_console_users WHERE email='queued-new@example.invalid'").Scan(&count); err != nil {
					t.Fatal(err)
				}
				if err := db.QueryRow("SELECT name FROM controller_console_users WHERE id=?", target.ID).Scan(&name); err != nil {
					t.Fatal(err)
				}
				if err := db.QueryRow("SELECT COUNT(*) FROM controller_identity_audit WHERE action IN ('identity.user_created','identity.user_updated')").Scan(&audits); err != nil {
					t.Fatal(err)
				}
				if count != 0 || name != target.Name || audits != before {
					t.Fatal("revoked queued identity write changed an account or identity-write audit")
				}
				if revoke == "logout" {
					// Another device's already issued session remains valid.
					if response := identityHTTPMutation(t, s, otherDevice, "PATCH", "/console/v1/users/"+target.ID, map[string]any{"name": "Other active session"}); response.Code != 200 {
						t.Fatalf("logout revoked an unrelated device: HTTP %d", response.Code)
					}
					// A fresh credential exchange also works; no permanent account lock.
					fresh := loginUsersPageHTTP(t, s, admin)
					if response := identityHTTPMutation(t, s, fresh, "PATCH", "/console/v1/users/"+target.ID, map[string]any{"name": "Valid fresh session"}); response.Code != 200 {
						t.Fatalf("fresh real login cannot update the target: HTTP %d", response.Code)
					}
				}
			})
		}
	}
}

func TestMySQLQueuedIdentityWriteBindsPersistedSessionOwner(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		t.Run(map[bool]string{false: "different_owner", true: "anonymous_owner"}[anonymous], func(t *testing.T) {
			s, db := mysqlIdentity(t)
			admin := bootstrap(t, s)
			target := create(t, s, admin, "owner-target@example.invalid", "viewer", nil)
			token := loginUsersPageHTTP(t, s, admin)
			release, wait := queuedIdentityMutation(t, s, token, "PATCH", "/console/v1/users/"+target.ID, map[string]any{"name": "Must not change"})
			var owner any = target.ID
			if anonymous {
				owner = nil
			}
			hash := tokenHash(token)
			// Corrupt/replace only the disposable session after authentication.
			// The handler must not trust an earlier owner projection.
			if _, err := db.Exec("UPDATE controller_console_sessions SET user_id=? WHERE token_hash=?", owner, hash[:]); err != nil {
				t.Fatal(err)
			}
			release()
			requireIdentity401(t, wait())
			var name string
			if err := db.QueryRow("SELECT name FROM controller_console_users WHERE id=?", target.ID).Scan(&name); err != nil || name != target.Name {
				t.Fatal("changed session owner authorized a stale actor", err)
			}
		})
	}
}

func TestMySQLQueuedIdentityWriteRechecksExpiryAfterLockWait(t *testing.T) {
	s, db := mysqlIdentity(t)
	var clock atomic.Int64
	clock.Store(time.Now().UTC().UnixMicro())
	s.nowFn = func() time.Time { return time.UnixMicro(clock.Load()) }
	admin := bootstrap(t, s)
	target := create(t, s, admin, "wait-target@example.invalid", "viewer", nil)
	token := loginUsersPageHTTP(t, s, admin)
	lock, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback()
	if err = identityLock(context.Background(), lock); err != nil {
		t.Fatal(err)
	}
	release, wait := queuedIdentityMutation(t, s, token, "PATCH", "/console/v1/users/"+target.ID, map[string]any{"name": "Must not change"})
	release()
	// This fixture has no background DB activity. One connection is our lock;
	// the second belongs to the waiting write transaction, not authentication.
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for db.Stats().InUse < 2 {
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("identity write never acquired its waiting transaction")
		}
	}
	clock.Add(int64((9 * time.Hour) / time.Microsecond))
	if err = lock.Commit(); err != nil {
		t.Fatal(err)
	}
	requireIdentity401(t, wait())
	var name string
	if err = db.QueryRow("SELECT name FROM controller_console_users WHERE id=?", target.ID).Scan(&name); err != nil || name != target.Name {
		t.Fatal("lock-wait expiry allowed an identity update", err)
	}
}

func TestMySQLQueuedIdentityWriteDatabaseErrorIsNotAuthentication(t *testing.T) {
	s, db := mysqlIdentity(t)
	admin := bootstrap(t, s)
	token := loginUsersPageHTTP(t, s, admin)
	release, wait := queuedIdentityMutation(t, s, token, "POST", "/console/v1/users", map[string]any{"email": "error-new@example.invalid", "name": "Must not exist", "role": "viewer", "password": testPassword})
	if _, err := db.Exec("DROP TABLE controller_console_sessions"); err != nil {
		t.Fatal(err)
	}
	release()
	response := wait()
	var body struct {
		Error struct{ Code string } `json:"error"`
	}
	if response.Code != 503 || json.Unmarshal(response.Body.Bytes(), &body) != nil || body.Error.Code != "IDENTITY_UNAVAILABLE" {
		t.Fatalf("session-store error must fail closed as unavailable, got HTTP %d", response.Code)
	}
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM controller_console_users WHERE email='error-new@example.invalid'").Scan(&count); err != nil || count != 0 {
		t.Fatal("session-store error created an identity", err)
	}
}

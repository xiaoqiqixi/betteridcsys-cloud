package identity

import (
	"aster/cloud/migrations"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

const testPassword = "a private synthetic test password 123"

func mysqlIdentity(t *testing.T) (*Service, *sql.DB) {
	t.Helper()
	raw := os.Getenv("ASTER_CLOUD_TEST_DSN")
	fallback := false
	if raw == "" {
		raw = os.Getenv("ASTER_MYSQL_TEST_DSN")
		fallback = true
	}
	if raw == "" {
		t.Skip("identity real MySQL fixture unset; no database acceptance performed")
	}
	c, err := mysql.ParseDSN(raw)
	if err != nil || (fallback && c.DBName != "aster_ci_test") || (!fallback && !strings.Contains(c.DBName, "_test")) {
		t.Fatal("refuse non-isolated identity test DSN")
	}
	if c.Net != "unix" && !(c.Net == "tcp" && (strings.HasPrefix(c.Addr, "127.0.0.1:") || strings.HasPrefix(c.Addr, "[::1]:"))) {
		t.Fatal("identity test requires local private MySQL")
	}
	c.MultiStatements = false
	c.ParseTime = true
	c.Loc = time.UTC
	c.Timeout = 5 * time.Second
	c.ReadTimeout = 10 * time.Second
	c.WriteTimeout = 10 * time.Second
	admin, err := sql.Open("mysql", c.FormatDSN())
	if err != nil {
		t.Fatal("identity fixture connection invalid")
	}
	token, err := randomToken()
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	name := "aster_cloud_test_identity_" + token[:16]
	if _, err = admin.Exec("CREATE DATABASE `" + name + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin"); err != nil {
		admin.Close()
		t.Fatal("cannot create independent identity test database")
	}
	t.Cleanup(func() {
		if _, err := admin.Exec("DROP DATABASE `" + name + "`"); err != nil {
			t.Error("cannot drop independent identity fixture")
		}
		admin.Close()
	})
	c.DBName = name
	db, err := sql.Open("mysql", c.FormatDSN())
	if err != nil {
		t.Fatal("cannot open independent identity fixture")
	}
	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(8)
	t.Cleanup(func() { db.Close() })
	var b []byte
	for _, migration := range migrations.All() {
		if migration.Version == 2 || migration.Version == 11 || migration.Version == 12 {
			b = append(b, []byte(migration.SQL)...)
		}
	}
	if len(b) == 0 {
		t.Fatal("embedded identity migration missing")
	}
	for _, q := range strings.Split(string(b), ";") {
		if strings.TrimSpace(q) != "" {
			if _, err = db.Exec(q); err != nil {
				t.Fatal("identity migration failed", err)
			}
		}
	}
	s, err := New(db, Config{Origin: "https://console.example.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	return s, db
}
func bootstrap(t *testing.T, s *Service) User {
	t.Helper()
	u, err := s.Bootstrap(context.Background(), "root@example.invalid", "Root", []byte(testPassword))
	if err != nil {
		t.Fatal(err)
	}
	return u
}
func create(t *testing.T, s *Service, a User, email, role string, p []string) User {
	t.Helper()
	u, err := createAs(t, s, a.ID, CreateUser{Email: email, Name: "Synthetic User", Password: testPassword, Role: role, Permissions: p})
	if err != nil {
		t.Fatal(err)
	}
	return u
}
func loginUser(t *testing.T, s *Service, u User) string {
	t.Helper()
	raw, err := s.anonymousSession(context.Background(), "192.0.2.11:55555")
	if err != nil {
		t.Fatal(err)
	}
	got, token, err := s.login(context.Background(), u.Email, testPassword, raw, "192.0.2.11:55555")
	if err != nil || got.ID != u.ID {
		t.Fatal("login", err)
	}
	if _, err = s.lookupSession(context.Background(), raw); !errors.Is(err, ErrAuthentication) {
		t.Fatal("prelogin session not rotated")
	}
	return token
}

func TestMySQLConsoleIdentity(t *testing.T) {
	t.Run("bootstrap_serialized_and_no_default_account", func(t *testing.T) {
		s, db := mysqlIdentity(t)
		var success atomic.Int32
		var conflictCount atomic.Int32
		var wg sync.WaitGroup
		for range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := s.Bootstrap(context.Background(), "root@example.invalid", "Root", []byte(testPassword))
				if err == nil {
					success.Add(1)
				} else if errors.Is(err, ErrConflict) {
					conflictCount.Add(1)
				} else {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		var users, audits int
		db.QueryRow("SELECT COUNT(*) FROM controller_console_users").Scan(&users)
		db.QueryRow("SELECT COUNT(*) FROM controller_identity_audit WHERE action='identity.bootstrap'").Scan(&audits)
		if success.Load() != 1 || conflictCount.Load() != 1 || users != 1 || audits != 1 {
			t.Fatal("bootstrap not exclusive", success.Load(), conflictCount.Load(), users, audits)
		}
	})
	t.Run("persistent_hashed_sessions_expiry_logout_and_password_revocation", func(t *testing.T) {
		s, db := mysqlIdentity(t)
		a := bootstrap(t, s)
		raw := loginUser(t, s, a)
		h := tokenHash(raw)
		var stored []byte
		if err := db.QueryRow("SELECT token_hash FROM controller_console_sessions WHERE user_id=?", a.ID).Scan(&stored); err != nil || !bytes.Equal(stored, h[:]) || bytes.Contains(stored, []byte(raw)) {
			t.Fatal("session token not hash-only")
		}
		reopened, err := New(db, Config{Origin: s.origin})
		if err != nil {
			t.Fatal(err)
		}
		if u, err := reopened.authenticate(context.Background(), raw); err != nil || u.ID != a.ID {
			t.Fatal("session not durable")
		}
		later := *reopened
		later.nowFn = func() time.Time { return time.Now().Add(25 * time.Hour) }
		if _, err := later.authenticate(context.Background(), raw); !errors.Is(err, ErrAuthentication) {
			t.Fatal("expired session accepted")
		}
		if err := s.logout(context.Background(), raw); err != nil {
			t.Fatal(err)
		}
		if _, err := s.authenticate(context.Background(), raw); !errors.Is(err, ErrAuthentication) {
			t.Fatal("logout did not revoke")
		}
		raw = loginUser(t, s, a)
		next := "another strong independent password"
		if _, err := updateAs(t, s, a.ID, a.ID, UpdateUser{Password: &next}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.authenticate(context.Background(), raw); !errors.Is(err, ErrAuthentication) {
			t.Fatal("password change left session active")
		}
		var hash string
		db.QueryRow("SELECT password_hash FROM controller_console_users WHERE id=?", a.ID).Scan(&hash)
		if !verifyPassword(hash, []byte(next)) || verifyPassword(hash, []byte(testPassword)) {
			t.Fatal("credential update binding")
		}
	})
	t.Run("disabled_and_role_changed_sessions_revoke_immediately", func(t *testing.T) {
		s, _ := mysqlIdentity(t)
		a := bootstrap(t, s)
		v := create(t, s, a, "viewer@example.invalid", "viewer", nil)
		raw := loginUser(t, s, v)
		enabled := false
		if _, err := updateAs(t, s, a.ID, v.ID, UpdateUser{Enabled: &enabled}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.authenticate(context.Background(), raw); !errors.Is(err, ErrAuthentication) {
			t.Fatal("disabled session survived")
		}
		anon, _ := s.anonymousSession(context.Background(), "192.0.2.11:55555")
		if _, _, err := s.login(context.Background(), v.Email, testPassword, anon, "192.0.2.11:5555"); !errors.Is(err, ErrAuthentication) {
			t.Fatal("disabled credentials accepted")
		}
		enabled = true
		if _, err := updateAs(t, s, a.ID, v.ID, UpdateUser{Enabled: &enabled}); err != nil {
			t.Fatal(err)
		}
		raw = loginUser(t, s, v)
		role := "operator"
		if _, err := updateAs(t, s, a.ID, v.ID, UpdateUser{Role: &role}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.authenticate(context.Background(), raw); !errors.Is(err, ErrAuthentication) {
			t.Fatal("role change left session active")
		}
	})
	t.Run("concurrent_admin_demotion_preserves_last_and_self_protection", func(t *testing.T) {
		s, db := mysqlIdentity(t)
		a := bootstrap(t, s)
		b := create(t, s, a, "second@example.invalid", "admin", nil)
		role := "operator"
		disabled := false
		if _, err := updateAs(t, s, a.ID, a.ID, UpdateUser{Role: &role}); !errors.Is(err, ErrForbidden) {
			t.Fatal("self-demotion allowed")
		}
		if _, err := updateAs(t, s, a.ID, a.ID, UpdateUser{Enabled: &disabled}); !errors.Is(err, ErrForbidden) {
			t.Fatal("self-disable allowed")
		}
		// Both real sessions pass authentication before either write starts.
		// The winner revokes the loser's session; the queued loser must return
		// an exact authentication denial, not continue under its earlier grants.
		tokenA := loginUsersPageHTTP(t, s, a)
		tokenB := loginUsersPageHTTP(t, s, b)
		releaseA, waitA := queuedIdentityMutation(t, s, tokenA, "PATCH", "/console/v1/users/"+b.ID, map[string]any{"role": role})
		releaseB, waitB := queuedIdentityMutation(t, s, tokenB, "PATCH", "/console/v1/users/"+a.ID, map[string]any{"role": role})
		releaseA()
		releaseB()
		success, denied := 0, 0
		for _, response := range []*httptest.ResponseRecorder{waitA(), waitB()} {
			if response.Code == 200 {
				success++
			} else {
				requireIdentity401(t, response)
				denied++
			}
		}
		var admins int
		db.QueryRow("SELECT COUNT(*) FROM controller_console_users WHERE enabled=TRUE AND role='admin'").Scan(&admins)
		if success != 1 || denied != 1 || admins != 1 {
			t.Fatal("last-admin invariant", success, denied, admins)
		}
		last, err := scanUser(db.QueryRow("SELECT " + userColumns + " FROM controller_console_users WHERE role='admin'"))
		if err != nil {
			t.Fatal(err)
		}
		manager := create(t, s, last, "manager@example.invalid", "custom", []string{"users.manage"})
		if _, err = updateAs(t, s, manager.ID, last.ID, UpdateUser{Role: &role}); !errors.Is(err, ErrForbidden) {
			t.Fatal("custom manager removed last administrator")
		}
		p := []string{}
		if _, err = updateAs(t, s, manager.ID, manager.ID, UpdateUser{Permissions: &p}); !errors.Is(err, ErrForbidden) {
			t.Fatal("custom self grant change allowed")
		}
	})
	t.Run("login_rotation_claim_and_generic_failure", func(t *testing.T) {
		s, _ := mysqlIdentity(t)
		a := bootstrap(t, s)
		anon, err := s.anonymousSession(context.Background(), "192.0.2.11:55555")
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		var success atomic.Int32
		var denied atomic.Int32
		for range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _, err := s.login(context.Background(), a.Email, testPassword, anon, "192.0.2.10:5555")
				if err == nil {
					success.Add(1)
				} else if errors.Is(err, ErrAuthentication) {
					denied.Add(1)
				} else {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		if success.Load() != 1 || denied.Load() != 1 {
			t.Fatal("one anonymous challenge yielded two sessions")
		}
		for _, email := range []string{a.Email, "unknown@example.invalid"} {
			challenge, _ := s.anonymousSession(context.Background(), "192.0.2.11:55555")
			if _, _, err := s.login(context.Background(), email, "wrong password", challenge, "192.0.2.10:5555"); !errors.Is(err, ErrAuthentication) {
				t.Fatal("account enumeration error", err)
			}
		}
	})
	t.Run("nonadmin_account_management_is_bounded_by_both_grant_sets", func(t *testing.T) {
		s, db := mysqlIdentity(t)
		a := bootstrap(t, s)
		manager := create(t, s, a, "bounded-manager@example.invalid", "custom", []string{"instances.read", "users.manage"})
		limited := create(t, s, a, "bounded-target@example.invalid", "custom", []string{"instances.read"})
		higher := create(t, s, a, "higher-target@example.invalid", "custom", []string{"instances.dangerous", "instances.read"})
		var before int
		db.QueryRow("SELECT COUNT(*) FROM controller_identity_audit").Scan(&before)
		if _, err := createAs(t, s, manager.ID, CreateUser{Email: "escalate@example.invalid", Name: "Escalation", Password: testPassword, Role: "admin"}); !errors.Is(err, ErrForbidden) {
			t.Fatal("bounded manager created admin", err)
		}
		reset := "not the original administrator password"
		if _, err := updateAs(t, s, manager.ID, a.ID, UpdateUser{Password: &reset}); !errors.Is(err, ErrForbidden) {
			t.Fatal("bounded manager reset admin", err)
		}
		danger := []string{"instances.dangerous", "instances.read"}
		if _, err := updateAs(t, s, manager.ID, limited.ID, UpdateUser{Permissions: &danger}); !errors.Is(err, ErrForbidden) {
			t.Fatal("bounded manager granted absent dangerous permission", err)
		}
		low := []string{"instances.read"}
		if _, err := updateAs(t, s, manager.ID, higher.ID, UpdateUser{Permissions: &low, Password: &reset}); !errors.Is(err, ErrForbidden) {
			t.Fatal("bounded manager controlled superior existing account", err)
		}
		if _, err := createAs(t, s, manager.ID, CreateUser{Email: "escalate-custom@example.invalid", Name: "Escalation", Password: testPassword, Role: "custom", Permissions: danger}); !errors.Is(err, ErrForbidden) {
			t.Fatal("bounded manager created superior custom account", err)
		}
		var after int
		db.QueryRow("SELECT COUNT(*) FROM controller_identity_audit").Scan(&after)
		if after != before {
			t.Fatal("forbidden delegation committed state/audit")
		}
		created, err := createAs(t, s, manager.ID, CreateUser{Email: "scoped-new@example.invalid", Name: "Scoped", Password: testPassword, Role: "custom", Permissions: low})
		if err != nil {
			t.Fatal("scoped creation rejected", err)
		}
		if _, err = updateAs(t, s, manager.ID, created.ID, UpdateUser{Password: &reset}); err != nil {
			t.Fatal("scoped credential management rejected", err)
		}
		all := create(t, s, a, "custom-all@example.invalid", "custom", append([]string{}, allPermissions...))
		if _, err = updateAs(t, s, all.ID, a.ID, UpdateUser{Password: &reset}); !errors.Is(err, ErrForbidden) {
			t.Fatal("all-grants custom manager edited administrator", err)
		}
		var hash string
		db.QueryRow("SELECT password_hash FROM controller_console_users WHERE id=?", a.ID).Scan(&hash)
		if !verifyPassword(hash, []byte(testPassword)) {
			t.Fatal("administrator credentials changed despite denial")
		}
	})
	t.Run("persistent_parallel_account_and_peer_rate_limits", func(t *testing.T) {
		s, db := mysqlIdentity(t)
		var good, limited atomic.Int32
		var wg sync.WaitGroup
		for range 20 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := s.reserveLogin(context.Background(), "limited@example.invalid", "192.0.2.20:2222")
				if err == nil {
					good.Add(1)
				} else if errors.Is(err, ErrRateLimited) {
					limited.Add(1)
				} else {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		if good.Load() != 10 || limited.Load() != 10 {
			t.Fatal("parallel account limit not atomic", good.Load(), limited.Load())
		}
		reopened, _ := New(db, Config{Origin: s.origin})
		if err := reopened.reserveLogin(context.Background(), "limited@example.invalid", "192.0.2.21:2222"); !errors.Is(err, ErrRateLimited) {
			t.Fatal("rate counter lost on restart")
		}
		for i := range 41 {
			err := s.reserveLogin(context.Background(), strings.Repeat("x", i+1)+"@example.invalid", "192.0.2.30:1234")
			if i < 40 && err != nil {
				t.Fatal(err)
			}
			if i == 40 && !errors.Is(err, ErrRateLimited) {
				t.Fatal("peer limit missing")
			}
		}
		later := *s
		later.nowFn = func() time.Time { return time.Now().Add(16 * time.Minute) }
		if err := later.reserveLogin(context.Background(), "limited@example.invalid", "192.0.2.20:2222"); err != nil {
			t.Fatal("expired rate window not reset", err)
		}
	})
	t.Run("anonymous_sessions_are_bounded_and_cleanup_never_revokes_live_sessions", func(t *testing.T) {
		s, db := mysqlIdentity(t)
		a := bootstrap(t, s)
		now := s.now()
		// Seed more expired rows than the per-request cleanup budget to prove it
		// is bounded, plus both live anonymous and authenticated sessions.
		var sessionValues []string
		var sessionArgs []any
		for range 150 {
			raw, _ := randomToken()
			h := tokenHash(raw)
			sessionValues = append(sessionValues, "(?,?,?,?)")
			sessionArgs = append(sessionArgs, h[:], nil, now.Add(-2*time.Hour), now.Add(-time.Hour))
		}
		liveAnon, _ := randomToken()
		liveAuth, _ := randomToken()
		for _, v := range []struct {
			raw string
			uid any
		}{{liveAnon, nil}, {liveAuth, a.ID}} {
			h := tokenHash(v.raw)
			sessionValues = append(sessionValues, "(?,?,?,?)")
			sessionArgs = append(sessionArgs, h[:], v.uid, now, now.Add(time.Hour))
		}
		if _, err := db.Exec("INSERT INTO controller_console_sessions(token_hash,user_id,created_at,expires_at) VALUES "+strings.Join(sessionValues, ","), sessionArgs...); err != nil {
			t.Fatal(err)
		}
		var bucketValues []string
		var bucketArgs []any
		for i := range 150 {
			h := tokenHash("expired-bucket:" + strings.Repeat("x", i))
			bucketValues = append(bucketValues, "(?,?,?)")
			bucketArgs = append(bucketArgs, h[:], now.Add(-25*time.Hour), 40)
		}
		if _, err := db.Exec("INSERT INTO controller_console_login_limits(bucket,window_at,attempts) VALUES "+strings.Join(bucketValues, ","), bucketArgs...); err != nil {
			t.Fatal(err)
		}
		if _, err := s.anonymousSession(context.Background(), "192.0.2.50:1234"); err != nil {
			t.Fatal(err)
		}
		var expiredSessions, expiredBuckets int
		db.QueryRow("SELECT COUNT(*) FROM controller_console_sessions WHERE expires_at<=?", now).Scan(&expiredSessions)
		db.QueryRow("SELECT COUNT(*) FROM controller_console_login_limits WHERE window_at<=?", now.Add(-24*time.Hour)).Scan(&expiredBuckets)
		if expiredSessions != 50 || expiredBuckets != 50 {
			t.Fatal("cleanup is missing or unbounded", expiredSessions, expiredBuckets)
		}
		if _, err := s.lookupSession(context.Background(), liveAnon); err != nil {
			t.Fatal("cleanup revoked live anonymous session", err)
		}
		if u, err := s.authenticate(context.Background(), liveAuth); err != nil || u.ID != a.ID {
			t.Fatal("cleanup revoked live authenticated session", err)
		}
		var good, limited atomic.Int32
		var wg sync.WaitGroup
		for range 50 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := s.anonymousSession(context.Background(), "[::ffff:192.0.2.50]:5678")
				if err == nil {
					good.Add(1)
				} else if errors.Is(err, ErrRateLimited) {
					limited.Add(1)
				} else {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		if good.Load() != 39 || limited.Load() != 11 {
			t.Fatal("fresh-cookie per-peer rate ceiling not atomic/canonical", good.Load(), limited.Load())
		}
		reopened, _ := New(db, Config{Origin: s.origin})
		if _, err := reopened.anonymousSession(context.Background(), "192.0.2.50:9999"); !errors.Is(err, ErrRateLimited) {
			t.Fatal("anonymous ceiling lost on restart")
		}
		global := tokenHash("anonymous:global")
		if _, err := db.Exec("UPDATE controller_console_login_limits SET attempts=4096 WHERE bucket=?", global[:]); err != nil {
			t.Fatal(err)
		}
		var before, after int
		db.QueryRow("SELECT COUNT(*) FROM controller_console_sessions").Scan(&before)
		if _, err := s.anonymousSession(context.Background(), "198.51.100.88:1234"); !errors.Is(err, ErrRateLimited) {
			t.Fatal("global anonymous creation ceiling missing", err)
		}
		db.QueryRow("SELECT COUNT(*) FROM controller_console_sessions").Scan(&after)
		if before != after {
			t.Fatal("throttled anonymous request inserted a session")
		}
		later := *s
		later.nowFn = func() time.Time { return now.Add(16 * time.Minute) }
		if _, err := later.anonymousSession(context.Background(), "192.0.2.50:1234"); err != nil {
			t.Fatal("anonymous expired budget not reset", err)
		}
		if _, err := s.authenticate(context.Background(), liveAuth); err != nil {
			t.Fatal("budget reset cleanup removed still-live auth session", err)
		}
	})
	t.Run("audit_is_transactional_and_contains_no_credentials", func(t *testing.T) {
		s, db := mysqlIdentity(t)
		a := bootstrap(t, s)
		raw := loginUser(t, s, a)
		v := create(t, s, a, "audit@example.invalid", "viewer", nil)
		disabled := false
		if _, err := updateAs(t, s, a.ID, v.ID, UpdateUser{Enabled: &disabled}); err != nil {
			t.Fatal(err)
		}
		if err := s.logout(context.Background(), raw); err != nil {
			t.Fatal(err)
		}
		rows, err := db.Query("SELECT actor,action,target FROM controller_identity_audit ORDER BY id")
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		count := 0
		for rows.Next() {
			var actor, action, target string
			if err := rows.Scan(&actor, &action, &target); err != nil {
				t.Fatal(err)
			}
			count++
			if actor == "" || action == "" || target == "" || strings.Contains(actor+action+target, testPassword) || strings.Contains(actor+action+target, raw) || strings.Contains(actor+action+target, csrfToken(raw)) {
				t.Fatal("audit lacks binding or leaks secrets")
			}
		}
		if rows.Err() != nil || count != 5 {
			t.Fatal("missing identity audit", count)
		}
		var before int
		db.QueryRow("SELECT COUNT(*) FROM controller_identity_audit").Scan(&before)
		role := "viewer"
		if _, err := updateAs(t, s, a.ID, a.ID, UpdateUser{Role: &role}); !errors.Is(err, ErrForbidden) {
			t.Fatal("forbidden update allowed")
		}
		var after int
		db.QueryRow("SELECT COUNT(*) FROM controller_identity_audit").Scan(&after)
		if before != after {
			t.Fatal("rejected mutation committed audit/state")
		}
	})
	t.Run("real_TLS_login_CSRF_RBAC_and_account_HTTP_contract", func(t *testing.T) {
		s, _ := mysqlIdentity(t)
		a := bootstrap(t, s)
		viewer := create(t, s, a, "http-viewer@example.invalid", "viewer", nil)
		server := httptest.NewTLSServer(s.Handler())
		defer server.Close()
		client := server.Client()
		var cookie *http.Cookie
		request := func(method, path string, body any, csrf, origin string) (int, map[string]json.RawMessage) {
			t.Helper()
			var b []byte
			if body != nil {
				b, _ = json.Marshal(body)
			}
			req, err := http.NewRequest(method, server.URL+path, bytes.NewReader(b))
			if err != nil {
				t.Fatal(err)
			}
			req.Host = "console.example.invalid"
			if body != nil {
				req.Header.Set("Content-Type", "application/json")
				op, _ := randomToken()
				req.Header.Set("Idempotency-Key", op[:32])
			}
			if csrf != "" {
				req.Header.Set("X-CSRF-Token", csrf)
			}
			if origin != "" {
				req.Header.Set("Origin", origin)
			}
			if cookie != nil {
				req.AddCookie(cookie)
			}
			res, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			data, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatal(err)
			}
			if res.TLS == nil {
				t.Fatal("test did not use actual TLS")
			}
			for _, c := range res.Cookies() {
				if c.Name == CookieName {
					cookie = c
				}
			}
			obj := map[string]json.RawMessage{}
			if len(data) > 0 && json.Unmarshal(data, &obj) != nil {
				t.Fatal("non-JSON response", string(data))
			}
			return res.StatusCode, obj
		}
		getCSRF := func() string {
			t.Helper()
			status, obj := request("GET", "/console/v1/auth/csrf", nil, "", "")
			var csrf string
			json.Unmarshal(obj["csrf_token"], &csrf)
			if status != 200 || len(csrf) != 64 || cookie == nil || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
				t.Fatal("anonymous CSRF contract", status)
			}
			return csrf
		}
		csrf := getCSRF()
		oldCookie := cookie.Value
		if status, _ := request("POST", "/console/v1/auth/login", map[string]string{"email": a.Email, "password": testPassword}, csrf, ""); status != 403 {
			t.Fatal("missing origin accepted", status)
		}
		if status, _ := request("POST", "/console/v1/auth/login", map[string]string{"email": a.Email, "password": testPassword}, "wrong", s.origin); status != 403 {
			t.Fatal("bad csrf accepted", status)
		}
		status, obj := request("POST", "/console/v1/auth/login", map[string]string{"email": a.Email, "password": testPassword}, csrf, s.origin)
		if status != 200 || oldCookie == cookie.Value {
			t.Fatal("login did not rotate cookie", status)
		}
		json.Unmarshal(obj["csrf_token"], &csrf)
		var got User
		json.Unmarshal(obj["user"], &got)
		if got.ID != a.ID || !got.Can("users.manage") {
			t.Fatal("login shape")
		}
		if status, _ := request("GET", "/console/v1/auth/me", nil, "", ""); status != 200 {
			t.Fatal("me failed", status)
		}
		if status, _ := request("GET", "/console/v1/roles", nil, "", ""); status != 200 {
			t.Fatal("roles failed", status)
		}
		if status, _ := request("POST", "/console/v1/users", CreateUser{Email: "created@example.invalid", Name: "Created", Password: testPassword, Role: "operator", Reason: "Isolated HTTP creation"}, csrf, s.origin); status != 201 {
			t.Fatal("create contract", status)
		}
		if status, _ := request("GET", "/console/v1/users", nil, "", ""); status != 200 {
			t.Fatal("users read", status)
		}
		if status, _ := request("POST", "/console/v1/auth/logout", map[string]string{}, csrf, s.origin); status != 204 || cookie.MaxAge != -1 {
			t.Fatal("logout contract", status)
		}
		csrf = getCSRF()
		status, obj = request("POST", "/console/v1/auth/login", map[string]string{"email": viewer.Email, "password": testPassword}, csrf, s.origin)
		if status != 200 {
			t.Fatal("viewer login", status)
		}
		json.Unmarshal(obj["csrf_token"], &csrf)
		if status, _ := request("GET", "/console/v1/users", nil, "", ""); status != 403 {
			t.Fatal("viewer users access allowed", status)
		}
		if status, _ := request("POST", "/console/v1/users", CreateUser{Email: "bad@example.invalid", Name: "Bad", Password: testPassword, Role: "admin"}, csrf, s.origin); status != 403 {
			t.Fatal("viewer account mutation allowed", status)
		}
		// The same authentication middleware must not discard resource pagination.
		resourceServer := httptest.NewTLSServer(s.Require("instances.read", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			actor, ok := Actor(r.Context())
			if !ok || actor.ID != viewer.ID || r.URL.Query().Get("cursor") != "abc" {
				t.Error("resource query/actor lost")
			}
			w.WriteHeader(204)
		})))
		defer resourceServer.Close()
		req, _ := http.NewRequest("GET", resourceServer.URL+"/console/v1/instances?cursor=abc", nil)
		req.Host = "console.example.invalid"
		req.AddCookie(cookie)
		res, err := resourceServer.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.TLS == nil || res.StatusCode != 204 {
			t.Fatal("authenticated resource pagination rejected", res.StatusCode)
		}
	})
}

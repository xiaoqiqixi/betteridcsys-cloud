package control

import (
	"aster/cloud/internal/identity"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

// Real SQL is the capability boundary: denial must be a MySQL privilege error,
// not a disconnected client, invalid statement, absent table or HTTP-only gate.
func TestMySQLVerificationSQLDeniesNonAuthenticationWrites(t *testing.T) {
	admin := consoleHTTPStore(t)
	op := id()
	limited := verificationSQLStore(t, admin, op)
	if _, err := identity.CheckVerificationSQLIdentity(context.Background(), limited.DB, op); err != nil {
		t.Fatal(err)
	}
	before := verificationDatabaseImage(t, admin)
	for name, query := range map[string]string{
		"users":           "UPDATE controller_console_users SET name='changed' WHERE 1=0",
		"identity_lock":   "UPDATE controller_identity_lock SET id=id WHERE id=1",
		"nodes":           "DELETE FROM controller_nodes WHERE 1=0",
		"operations":      "DELETE FROM controller_operations WHERE 1=0",
		"audit_delete":    "DELETE FROM controller_identity_audit WHERE 1=0",
		"audit_update":    "UPDATE controller_identity_audit SET actor='changed' WHERE 1=0",
		"audit_id":        "INSERT INTO controller_identity_audit(id,actor,action,target,created_at) VALUES(999,'fixture','identity.login','fixture',UTC_TIMESTAMP(6))",
		"sessions_update": "UPDATE controller_console_sessions SET expires_at=UTC_TIMESTAMP(6) WHERE 1=0",
		"ddl":             "CREATE TABLE forbidden_verification_write(id INT)",
		"other_database":  "SELECT * FROM mysql.user",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := limited.DB.Exec(query)
			var denied *mysql.MySQLError
			if !errors.As(err, &denied) || (denied.Number != 1142 && denied.Number != 1143 && denied.Number != 1044) {
				t.Fatalf("expected explicit SQL privilege refusal, got %T", err)
			}
		})
	}
	if !reflect.DeepEqual(before, verificationDatabaseImage(t, admin)) {
		t.Fatal("denied SQL changed restored database")
	}
}

func TestMySQLVerificationSQLRejectsGrantDriftWithoutRepair(t *testing.T) {
	admin := consoleHTTPStore(t)
	op := id()
	limited := verificationSQLStore(t, admin, op)
	ctx := context.Background()
	policy, err := identity.CheckVerificationSQLIdentity(ctx, limited.DB, op)
	if err != nil {
		t.Fatal(err)
	}
	account := "`" + policy.User + "`@`localhost`"
	schema := "`" + strings.ReplaceAll(policy.Database, "_", `\_`) + "`.*"
	table := "`" + policy.Database + "`."
	changes := []struct{ name, grant, revoke string }{
		{"global", "GRANT SELECT ON *.* TO " + account, "REVOKE SELECT ON *.* FROM " + account},
		{"business_schema", "GRANT UPDATE ON " + schema + " TO " + account, "REVOKE UPDATE ON " + schema + " FROM " + account},
		{"users_table", "GRANT UPDATE ON " + table + "controller_console_users TO " + account, "REVOKE UPDATE ON " + table + "controller_console_users FROM " + account},
		{"audit_id_column", "GRANT INSERT(id) ON " + table + "controller_identity_audit TO " + account, "REVOKE INSERT(id) ON " + table + "controller_identity_audit FROM " + account},
		{"audit_whole_insert", "GRANT INSERT ON " + table + "controller_identity_audit TO " + account, "REVOKE INSERT ON " + table + "controller_identity_audit FROM " + account},
		{"grant_option", "GRANT SELECT ON " + schema + " TO " + account + " WITH GRANT OPTION", "REVOKE GRANT OPTION ON " + schema + " FROM " + account},
		{"missing_session_delete", "REVOKE DELETE ON " + table + "controller_console_sessions FROM " + account, "GRANT DELETE ON " + table + "controller_console_sessions TO " + account},
	}
	grants := func() []string {
		rows, e := admin.DB.Query("SHOW GRANTS FOR " + account)
		if e != nil {
			t.Fatal("fixture grants unavailable")
		}
		defer rows.Close()
		out := []string{}
		for rows.Next() {
			var line string
			if rows.Scan(&line) != nil {
				t.Fatal("grant scan")
			}
			out = append(out, line)
		}
		if rows.Err() != nil {
			t.Fatal("grant read")
		}
		return out
	}
	for _, tc := range changes {
		t.Run(tc.name, func(t *testing.T) {
			if _, e := admin.DB.Exec(tc.grant); e != nil {
				t.Fatal("fixture drift failed")
			}
			defer func() {
				if _, e := admin.DB.Exec(tc.revoke); e != nil {
					t.Error("fixture restoration failed")
				}
				if tc.name == "audit_whole_insert" {
					// MySQL REVOKE of table INSERT also removes column INSERT.
					if _, e := admin.DB.Exec("GRANT INSERT(actor,action,target,created_at) ON " + table + "controller_identity_audit TO " + account); e != nil {
						t.Error("fixture column grant restoration failed")
					}
				}
			}()
			before := grants()
			if _, e := identity.CheckVerificationSQLIdentity(ctx, limited.DB, op); e == nil {
				t.Fatal("broadened or missing grants accepted")
			}
			if !reflect.DeepEqual(before, grants()) {
				t.Fatal("policy check repaired unknown grants")
			}
		})
		if _, e := identity.CheckVerificationSQLIdentity(ctx, limited.DB, op); e != nil {
			t.Fatal("restored exact policy rejected", tc.name)
		}
	}
	// An inactive role must be refused too, not only CURRENT_ROLE(). It could be
	// activated by a later query on the same database identity.
	role := "`aster_role_" + id()[:16] + "`@`localhost`"
	if _, err = admin.DB.Exec("CREATE ROLE " + role); err != nil {
		t.Fatal("fixture role creation")
	}
	defer admin.DB.Exec("DROP ROLE " + role)
	if _, err = admin.DB.Exec("GRANT " + role + " TO " + account); err != nil {
		t.Fatal("fixture role assignment")
	}
	if _, err = identity.CheckVerificationSQLIdentity(ctx, limited.DB, op); err == nil {
		t.Fatal("inactive role accepted")
	}
}

func TestMySQLVerificationLoginWaitsForOrdinaryRevocation(t *testing.T) {
	store := consoleHTTPStore(t)
	server := httptest.NewUnstartedServer(nil)
	cfg := identity.Config{Origin: "https://" + server.Listener.Addr().String()}
	ordinary, err := identity.New(store.DB, cfg)
	if err != nil {
		t.Fatal(err)
	}
	user, err := ordinary.Bootstrap(context.Background(), "revocation@example.invalid", "Revocation fixture", []byte(consoleHTTPPassword))
	if err != nil {
		t.Fatal(err)
	}
	op := id()
	handler, err := NewVerificationConsole(context.Background(), verificationSQLStore(t, store, op), testConfig(testProfile()), cfg, op)
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = handler
	server.StartTLS()
	defer server.Close()
	browser := newConsoleHTTPBrowser(t, server)
	status, raw := browser.request(t, "GET", "/console/v1/auth/csrf", "", consoleHTTPOptions{})
	var challenge struct {
		CSRF string `json:"csrf_token"`
	}
	if status != 200 || json.Unmarshal(raw, &challenge) != nil {
		t.Fatal("csrf failed")
	}
	browser.csrf = challenge.CSRF
	tx, err := store.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var sentinel int
	if tx.QueryRow("SELECT id FROM controller_identity_lock WHERE id=1 FOR UPDATE").Scan(&sentinel) != nil {
		t.Fatal("fixture writer lock")
	}
	done := make(chan struct{})
	var loginStatus int
	var response []byte
	go func() {
		defer close(done)
		loginStatus, response = browser.request(t, "POST", "/console/v1/auth/login", consoleHTTPJSON(t, map[string]string{"email": user.Email, "password": consoleHTTPPassword}), consoleHTTPOptions{})
	}()
	defer func() {
		tx.Rollback()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Error("login did not drain")
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var waits int
		err = store.DB.QueryRow("SELECT COUNT(*) FROM performance_schema.data_lock_waits w JOIN performance_schema.data_locks l ON w.REQUESTING_ENGINE_LOCK_ID=l.ENGINE_LOCK_ID AND w.ENGINE=l.ENGINE WHERE l.OBJECT_SCHEMA=DATABASE() AND l.OBJECT_NAME='controller_identity_lock'").Scan(&waits)
		if err != nil {
			t.Fatal("cannot observe real pending lock")
		}
		if waits > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("login did not reach writer fence")
		}
		select {
		case <-done:
			t.Fatal("login bypassed writer fence")
		case <-time.After(5 * time.Millisecond):
		}
	}
	// Exact ordinary revision fence, held by the same exclusive sentinel as the
	// separately tested public revocation API. No credential implementation mock.
	if _, err = tx.Exec("UPDATE controller_console_users SET revision=revision+1 WHERE id=?", user.ID); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	<-done
	if loginStatus != 401 || consoleHTTPError(t, response) != "LOGIN_FAILED" {
		t.Fatalf("stale credential snapshot admitted: %d %s", loginStatus, response)
	}
	browser.login(t, user.Email)
}

func TestMySQLVerificationAnonymousCapacityAcrossIndependentServices(t *testing.T) {
	admin := consoleHTTPStore(t)
	// Seed the last available slot directly at the agreed real SQL boundary.
	tx, err := admin.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	stmt, err := tx.Prepare("INSERT INTO controller_console_sessions(token_hash,user_id,created_at,expires_at) VALUES(?,NULL,?,?)")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4095; i++ {
		token := []byte(fmt.Sprintf("%032x", i))
		if _, err = stmt.Exec(token, now, now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	stmt.Close()
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	servers := []*httptest.Server{httptest.NewUnstartedServer(nil), httptest.NewUnstartedServer(nil)}
	browsers := make([]*consoleHTTPBrowser, 2)
	for i, s := range servers {
		op := id()
		h, e := NewVerificationConsole(context.Background(), verificationSQLStore(t, admin, op), testConfig(testProfile()), identity.Config{Origin: "https://" + s.Listener.Addr().String()}, op)
		if e != nil {
			t.Fatal(e)
		}
		s.Config.Handler = h
		s.StartTLS()
		defer s.Close()
		browsers[i] = newConsoleHTTPBrowser(t, s)
	}
	start := make(chan struct{})
	done := make(chan int, 2)
	for _, b := range browsers {
		go func(b *consoleHTTPBrowser) {
			status := 0
			defer func() { done <- status }()
			<-start
			var raw []byte
			status, raw = b.request(t, "GET", "/console/v1/auth/csrf", "", consoleHTTPOptions{})
			if status != 200 && (status != 429 || consoleHTTPError(t, raw) != "RATE_LIMITED") {
				t.Errorf("unexpected capacity response %d", status)
			}
		}(b)
	}
	close(start)
	a, b := <-done, <-done
	if !((a == 200 && b == 429) || (b == 200 && a == 429)) {
		t.Fatalf("last slot not exclusive: %d %d", a, b)
	}
	var count int
	if admin.DB.QueryRow("SELECT COUNT(*) FROM controller_console_sessions WHERE user_id IS NULL").Scan(&count) != nil || count != 4096 {
		t.Fatal("anonymous capacity changed", count)
	}
}

// Cancellation must release both SQL locks; a stopped request cannot keep
// verification authentication blocked or silently consume a session slot.
func TestMySQLVerificationCancelledAuthenticationReleasesLocks(t *testing.T) {
	store := consoleHTTPStore(t)
	server := httptest.NewUnstartedServer(nil)
	op := id()
	limited := verificationSQLStore(t, store, op)
	policy, err := identity.CheckVerificationSQLIdentity(context.Background(), limited.DB, op)
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewVerificationConsole(context.Background(), limited, testConfig(testProfile()), identity.Config{Origin: "https://" + server.Listener.Addr().String()}, op)
	if err != nil {
		t.Fatal(err)
	}
	drained := make(chan struct{}, 2)
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { drained <- struct{}{} }()
		h.ServeHTTP(w, r)
	})
	server.StartTLS()
	defer server.Close()
	tx, err := store.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var n int
	if tx.QueryRow("SELECT id FROM controller_identity_lock WHERE id=1 FOR UPDATE").Scan(&n) != nil {
		t.Fatal("writer lock")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, "GET", server.URL+"/console/v1/auth/csrf", nil)
	if err != nil {
		t.Fatal(err)
	}
	clientDone := make(chan error, 1)
	go func() {
		res, e := server.Client().Do(request)
		if res != nil {
			res.Body.Close()
		}
		clientDone <- e
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		err = store.DB.QueryRow("SELECT COUNT(*) FROM performance_schema.data_lock_waits w JOIN performance_schema.data_locks l ON w.REQUESTING_ENGINE_LOCK_ID=l.ENGINE_LOCK_ID AND w.ENGINE=l.ENGINE WHERE l.OBJECT_SCHEMA=DATABASE() AND l.OBJECT_NAME='controller_identity_lock'").Scan(&n)
		if err != nil {
			t.Fatal("lock observation")
		}
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("authentication did not block on writer")
		}
		select {
		case <-drained:
			t.Fatal("request bypassed writer")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	select {
	case err = <-clientDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("request did not report cancellation")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("client failed to cancel")
	}
	select {
	case <-drained:
	case <-time.After(10 * time.Second):
		t.Fatal("cancelled handler did not drain")
	}
	// Client close and server disconnect observation are asynchronous. Observe
	// real SQL release with a bound; never count request cancellation as proof.
	deadline = time.Now().Add(6 * time.Second)
	for {
		if err = store.DB.QueryRow("SELECT COUNT(*) FROM performance_schema.metadata_locks l JOIN performance_schema.threads t ON t.THREAD_ID=l.OWNER_THREAD_ID WHERE l.OBJECT_TYPE='USER LEVEL LOCK' AND t.PROCESSLIST_USER=?", policy.User).Scan(&n); err != nil {
			t.Fatal("lock release observation failed")
		}
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("cancelled request retained named lock beyond bounded drain", n)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if store.DB.QueryRow("SELECT COUNT(*) FROM controller_console_sessions").Scan(&n) != nil || n != 0 {
		t.Fatal("cancelled request issued a session")
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	browser := newConsoleHTTPBrowser(t, server)
	status, _ := browser.request(t, "GET", "/console/v1/auth/csrf", "", consoleHTTPOptions{})
	if status != 200 {
		t.Fatal("authentication did not recover", status)
	}
}

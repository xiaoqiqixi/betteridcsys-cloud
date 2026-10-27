package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMySQLIdentityDetailHasCurrentRevision(t *testing.T) {
	s, _ := mysqlIdentity(t)
	admin := bootstrap(t, s)
	token := loginUsersPageHTTP(t, s, admin)
	r := httptest.NewRequest("GET", s.origin+"/console/v1/users/"+admin.ID, nil)
	r.AddCookie(&http.Cookie{Name: CookieName, Value: token})
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	var body struct {
		User struct {
			ID       string `json:"id"`
			Revision int64  `json:"revision"`
		} `json:"user"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.User.ID != admin.ID || body.User.Revision != 1 {
		t.Fatalf("current identity detail must return initial revision1, HTTP %d", w.Code)
	}
}

func identityOperationHTTP(t *testing.T, s *Service, token, method, path string, input any, keys ...string) *httptest.ResponseRecorder {
	t.Helper()
	var body []byte
	var err error
	if input != nil {
		body, err = json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(method, s.origin+path, bytes.NewReader(body))
	if token != "" {
		r.AddCookie(&http.Cookie{Name: CookieName, Value: token})
	}
	if method != "GET" {
		r.Header.Set("Origin", s.origin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", identityCSRFHTTP(t, s, token))
	}
	for _, k := range keys {
		r.Header.Add("Idempotency-Key", k)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}
func operationKey(t *testing.T) string {
	t.Helper()
	k, e := randomToken()
	if e != nil {
		t.Fatal(e)
	}
	return k[:32]
}
func identityErrorCode(t *testing.T, w *httptest.ResponseRecorder, want int, code string) {
	t.Helper()
	var v struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if w.Code != want || json.Unmarshal(w.Body.Bytes(), &v) != nil || v.Error.Code != code {
		t.Fatalf("want HTTP %d %s, got %d", want, code, w.Code)
	}
}
func operationResult(t *testing.T, w *httptest.ResponseRecorder, status int) (User, IdentityOperation) {
	t.Helper()
	var v struct {
		User      User              `json:"user"`
		Operation IdentityOperation `json:"operation"`
	}
	if w.Code != status || json.Unmarshal(w.Body.Bytes(), &v) != nil || v.User.Revision < 1 || v.User.ID != v.Operation.TargetID || v.User.Revision != v.Operation.ResultRevision {
		t.Fatalf("invalid confirmed identity result, HTTP %d", w.Code)
	}
	return v.User, v.Operation
}
func readIdentityUser(t *testing.T, s *Service, token, id string) User {
	t.Helper()
	w := identityOperationHTTP(t, s, token, "GET", "/console/v1/users/"+id, nil)
	var v struct {
		User User `json:"user"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &v) != nil {
		t.Fatalf("user detail HTTP %d", w.Code)
	}
	return v.User
}

func TestMySQLIdentityRevisionConflictIsNotAnOverride(t *testing.T) {
	s, db := mysqlIdentity(t)
	a := bootstrap(t, s)
	b := create(t, s, a, "second-op-admin@example.invalid", "admin", nil)
	target := create(t, s, a, "op-target@example.invalid", "viewer", nil)
	ta, tb := loginUsersPageHTTP(t, s, a), loginUsersPageHTTP(t, s, b)
	releaseA, waitA := queuedIdentityMutation(t, s, ta, "PATCH", "/console/v1/users/"+target.ID, map[string]any{"name": "First draft", "revision": target.Revision, "reason": "First operator change"})
	releaseB, waitB := queuedIdentityMutation(t, s, tb, "PATCH", "/console/v1/users/"+target.ID, map[string]any{"name": "Second draft", "revision": target.Revision, "reason": "Second operator change"})
	releaseA()
	releaseB()
	ok, conflicts := 0, 0
	for _, w := range []*httptest.ResponseRecorder{waitA(), waitB()} {
		if w.Code == 200 {
			_, op := operationResult(t, w, 200)
			if op.BaseRevision != 1 || op.ResultRevision != 2 {
				t.Fatal("revision did not advance exactly once")
			}
			ok++
		} else {
			identityErrorCode(t, w, 409, "REVISION_CONFLICT")
			conflicts++
		}
	}
	got := readIdentityUser(t, s, ta, target.ID)
	if ok != 1 || conflicts != 1 || got.Revision != 2 || (got.Name != "First draft" && got.Name != "Second draft") {
		t.Fatal("stale edit overwrote current account")
	}
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM controller_identity_operations WHERE target_id=? AND action='identity.user_updated'", target.ID).Scan(&n); err != nil || n != 1 {
		t.Fatal("conflicting edit left a receipt", err)
	}
}

func TestMySQLIdentityOperationKeyIsSingleUseAndPrivate(t *testing.T) {
	s, db := mysqlIdentity(t)
	a := bootstrap(t, s)
	b := create(t, s, a, "foreign-op-admin@example.invalid", "admin", nil)
	target := create(t, s, a, "single-op-target@example.invalid", "viewer", nil)
	ta, tb := loginUsersPageHTTP(t, s, a), loginUsersPageHTTP(t, s, b)
	key := operationKey(t)
	input := map[string]any{"revision": target.Revision, "reason": "Correct target name", "name": "Committed once"}
	_, op := operationResult(t, identityOperationHTTP(t, s, ta, "PATCH", "/console/v1/users/"+target.ID, input, key), 200)
	for _, body := range []map[string]any{input, {"revision": 2, "reason": "Changed secret must not replay", "password": "a different never persisted secret 567"}} {
		identityErrorCode(t, identityOperationHTTP(t, s, ta, "PATCH", "/console/v1/users/"+target.ID, body, key), 409, "OPERATION_USED")
	}
	identityErrorCode(t, identityOperationHTTP(t, s, ta, "PATCH", "/console/v1/users/"+b.ID, map[string]any{"revision": 1, "reason": "Different target", "name": "Must not change"}, key), 409, "OPERATION_USED")
	w := identityOperationHTTP(t, s, ta, "GET", "/console/v1/identity-operations/"+key, nil)
	var saved struct {
		Operation IdentityOperation `json:"operation"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &saved) != nil || saved.Operation.ID != op.ID || saved.Operation.ActorID != a.ID || saved.Operation.RequestSHA256 != op.RequestSHA256 {
		t.Fatal("cannot read original immutable operation")
	}
	identityErrorCode(t, identityOperationHTTP(t, s, tb, "GET", "/console/v1/identity-operations/"+key, nil), 404, "NOT_FOUND")
	identityErrorCode(t, identityOperationHTTP(t, s, ta, "GET", "/console/v1/identity-operations/"+operationKey(t), nil), 404, "NOT_FOUND")
	var raw string
	if err := db.QueryRow("SELECT CAST(intent_json AS CHAR) FROM controller_identity_operations WHERE operation_id=?", key).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, "\"password\"") || strings.Contains(raw, "password_hash") || strings.Contains(raw, testPassword) || strings.Contains(raw, ta) || strings.Contains(raw, csrfToken(ta)) {
		t.Fatal("operation intent persisted a secret")
	}
	if got := readIdentityUser(t, s, ta, target.ID); got.Revision != 2 || got.Name != "Committed once" {
		t.Fatal("reused key mutated account")
	}
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM controller_identity_operations WHERE operation_id=?", key).Scan(&n); err != nil || n != 1 {
		t.Fatal("operation was not exactly once", err)
	}
}

func TestMySQLIdentityWritesRejectMissingOrAmbiguousContract(t *testing.T) {
	s, _ := mysqlIdentity(t)
	a := bootstrap(t, s)
	target := create(t, s, a, "contract-target@example.invalid", "viewer", nil)
	token := loginUsersPageHTTP(t, s, a)
	valid := map[string]any{"revision": 1, "reason": "Routine controlled change", "name": "New name"}
	for _, keys := range [][]string{nil, {""}, {"ABCDEF"}, {operationKey(t), operationKey(t)}} {
		identityErrorCode(t, identityOperationHTTP(t, s, token, "PATCH", "/console/v1/users/"+target.ID, valid, keys...), 400, "INVALID_INPUT")
	}
	for _, v := range []map[string]any{{"name": "No revision", "reason": "No missing version allowed"}, {"revision": 0, "name": "Zero version", "reason": "Reject zero"}, {"revision": 1, "name": "No reason"}, {"revision": 1, "name": "Bad reason", "reason": "line\nbreak"}, {"revision": 1.5, "name": "Float version", "reason": "Reject float"}, {"revision": maxIdentityRevision + 1, "name": "Unsafe version", "reason": "Reject unsafe integer"}, {"revision": 1, "name": "Unknown field", "reason": "Reject unknown", "extra": true}} {
		identityErrorCode(t, identityOperationHTTP(t, s, token, "PATCH", "/console/v1/users/"+target.ID, v, operationKey(t)), 400, "INVALID_INPUT")
	}
	if got := readIdentityUser(t, s, token, target.ID); got.Revision != 1 || got.Name != target.Name {
		t.Fatal("invalid contract changed target")
	}
}

func TestMySQLIdentityRevokeAllSessionsAndSelfReceipt(t *testing.T) {
	s, _ := mysqlIdentity(t)
	a := bootstrap(t, s)
	b := create(t, s, a, "revoke-admin@example.invalid", "admin", nil)
	ta := loginUsersPageHTTP(t, s, a)
	tb1, tb2 := loginUsersPageHTTP(t, s, b), loginUsersPageHTTP(t, s, b)
	for rev := uint64(1); rev <= 2; rev++ {
		u, op := operationResult(t, identityOperationHTTP(t, s, ta, "POST", "/console/v1/users/"+b.ID+"/revoke-sessions", map[string]any{"revision": rev, "reason": "Require a fresh operator login"}, operationKey(t)), 200)
		if u.Revision != rev+1 || op.Action != "identity.sessions_revoked" || op.Intent.PasswordChanged {
			t.Fatal("revocation did not commit exact version")
		}
	}
	for _, token := range []string{tb1, tb2} {
		identityErrorCode(t, identityOperationHTTP(t, s, token, "GET", "/console/v1/auth/me", nil), 401, "AUTH_REQUIRED")
	}
	if w := identityOperationHTTP(t, s, ta, "GET", "/console/v1/auth/me", nil); w.Code != 200 {
		t.Fatal("revocation logged out unrelated operator")
	}
	fresh := loginUsersPageHTTP(t, s, b)
	key := operationKey(t)
	w := identityOperationHTTP(t, s, fresh, "POST", "/console/v1/users/"+b.ID+"/revoke-sessions", map[string]any{"revision": 3, "reason": "End every session including this device"}, key)
	operationResult(t, w, 200)
	cleared := false
	for _, c := range w.Result().Cookies() {
		if c.Name == CookieName && c.MaxAge < 0 && c.Secure && c.HttpOnly {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("self revocation did not clear host cookie")
	}
	identityErrorCode(t, identityOperationHTTP(t, s, fresh, "GET", "/console/v1/auth/me", nil), 401, "AUTH_REQUIRED")
	fresh = loginUsersPageHTTP(t, s, b)
	if w = identityOperationHTTP(t, s, fresh, "GET", "/console/v1/identity-operations/"+key, nil); w.Code != 200 {
		t.Fatal("new login cannot reconcile its own self-revocation")
	}
}

func TestMySQLIdentityReceiptFailureRollsBackAccountSessionsAndAudit(t *testing.T) {
	s, db := mysqlIdentity(t)
	a := bootstrap(t, s)
	target := create(t, s, a, "rollback-op-target@example.invalid", "viewer", nil)
	ta, tt := loginUsersPageHTTP(t, s, a), loginUsersPageHTTP(t, s, target)
	var before int
	if err := db.QueryRow("SELECT COUNT(*) FROM controller_identity_audit").Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TRIGGER fixture_reject_identity_receipt BEFORE INSERT ON controller_identity_operations FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='isolated receipt failure'"); err != nil {
		t.Fatal(err)
	}
	key := operationKey(t)
	identityErrorCode(t, identityOperationHTTP(t, s, ta, "PATCH", "/console/v1/users/"+target.ID, map[string]any{"revision": 1, "reason": "Test atomic rollback", "password": "never retained updated password 789"}, key), 503, "IDENTITY_UNAVAILABLE")
	if u := readIdentityUser(t, s, ta, target.ID); u.Revision != 1 {
		t.Fatal("receipt failure committed revision")
	}
	if w := identityOperationHTTP(t, s, tt, "GET", "/console/v1/auth/me", nil); w.Code != 200 {
		t.Fatal("receipt failure revoked a session")
	}
	var after, n int
	if err := db.QueryRow("SELECT COUNT(*) FROM controller_identity_audit").Scan(&after); err != nil || after != before {
		t.Fatal("receipt failure committed audit", err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM controller_identity_operations WHERE operation_id=?", key).Scan(&n); err != nil || n != 0 {
		t.Fatal("receipt failure retained partial proof", err)
	}
}

func TestMySQLIdentityRevisionLimitIsFailClosed(t *testing.T) {
	s, db := mysqlIdentity(t)
	a := bootstrap(t, s)
	target := create(t, s, a, "limit-op-target@example.invalid", "viewer", nil)
	ta := loginUsersPageHTTP(t, s, a)
	if _, err := db.Exec("UPDATE controller_console_users SET revision=? WHERE id=?", maxIdentityRevision, target.ID); err != nil {
		t.Fatal(err)
	}
	identityErrorCode(t, identityOperationHTTP(t, s, ta, "PATCH", "/console/v1/users/"+target.ID, map[string]any{"revision": maxIdentityRevision, "reason": "Do not wrap a version", "name": "Not applied"}, operationKey(t)), 409, "REVISION_LIMIT")
	if _, err := db.Exec("UPDATE controller_console_users SET revision=? WHERE id=?", maxIdentityRevision+1, target.ID); err != nil {
		t.Fatal(err)
	}
	identityErrorCode(t, identityOperationHTTP(t, s, ta, "GET", "/console/v1/users/"+target.ID, nil), 503, "IDENTITY_UNAVAILABLE")
}

func TestMySQLIdentityOperationDelegationAndSecretBoundaries(t *testing.T) {
	s, db := mysqlIdentity(t)
	a := bootstrap(t, s)
	manager := create(t, s, a, "bounded-op-manager@example.invalid", "custom", []string{"instances.read", "nodes.read", "storage.read", "users.manage"})
	viewer := create(t, s, a, "bounded-op-viewer@example.invalid", "viewer", nil)
	operator := create(t, s, a, "bounded-op-operator@example.invalid", "operator", nil)
	ma, ad, vw := loginUsersPageHTTP(t, s, manager), loginUsersPageHTTP(t, s, a), loginUsersPageHTTP(t, s, viewer)
	for _, target := range []User{a, operator} {
		identityErrorCode(t, identityOperationHTTP(t, s, ma, "POST", "/console/v1/users/"+target.ID+"/revoke-sessions", map[string]any{"revision": target.Revision, "reason": "Must not cross delegation boundary"}, operationKey(t)), 403, "FORBIDDEN")
	}
	k := operationKey(t)
	_, op := operationResult(t, identityOperationHTTP(t, s, ma, "POST", "/console/v1/users/"+viewer.ID+"/revoke-sessions", map[string]any{"revision": 1, "reason": "Bounded manager session revocation"}, k), 200)
	if op.ActorID != manager.ID || op.TargetID != viewer.ID {
		t.Fatal("receipt authority mismatch")
	}
	if w := identityOperationHTTP(t, s, ma, "GET", "/console/v1/identity-operations/"+k, nil); w.Code != 200 {
		t.Fatal("bounded actor cannot read own allowed operation")
	}
	identityErrorCode(t, identityOperationHTTP(t, s, "", "GET", "/console/v1/identity-operations/"+k, nil), 401, "AUTH_REQUIRED")
	vw = loginUsersPageHTTP(t, s, viewer)
	identityErrorCode(t, identityOperationHTTP(t, s, vw, "GET", "/console/v1/identity-operations/"+k, nil), 403, "FORBIDDEN")
	identityErrorCode(t, identityOperationHTTP(t, s, ad, "GET", "/console/v1/identity-operations/"+k, nil), 404, "NOT_FOUND")
	operationResult(t, identityOperationHTTP(t, s, ad, "PATCH", "/console/v1/users/"+viewer.ID, map[string]any{"role": "operator", "revision": 2, "reason": "Change account scope for receipt authorization test"}, operationKey(t)), 200)
	identityErrorCode(t, identityOperationHTTP(t, s, ma, "GET", "/console/v1/identity-operations/"+k, nil), 403, "FORBIDDEN")
	secret := "never copy this password 12345"
	for _, field := range []string{"name", "reason"} {
		input := map[string]any{"revision": 3, "reason": "Reject secret in public field", "password": secret}
		input[field] = secret
		identityErrorCode(t, identityOperationHTTP(t, s, ad, "PATCH", "/console/v1/users/"+viewer.ID, input, operationKey(t)), 400, "INVALID_INPUT")
	}
	key := operationKey(t)
	_, op = operationResult(t, identityOperationHTTP(t, s, ad, "PATCH", "/console/v1/users/"+viewer.ID, map[string]any{"revision": 3, "reason": "Rotate a fixture credential without retaining it", "password": secret}, key), 200)
	if !op.Intent.PasswordChanged || op.Intent.Revision != 3 {
		t.Fatal("credential change projection invalid")
	}
	var raw string
	if e := db.QueryRow("SELECT CAST(intent_json AS CHAR) FROM controller_identity_operations WHERE operation_id=?", key).Scan(&raw); e != nil || strings.Contains(raw, secret) || strings.Contains(raw, "password_hash") || strings.Contains(raw, "\"password\"") {
		t.Fatal("password retained in identity operation", e)
	}
}

func TestMySQLIdentityAuditFailureRollsBackExplicitRevocation(t *testing.T) {
	s, db := mysqlIdentity(t)
	a := bootstrap(t, s)
	target := create(t, s, a, "audit-rollback-revoke@example.invalid", "viewer", nil)
	ad, tt := loginUsersPageHTTP(t, s, a), loginUsersPageHTTP(t, s, target)
	if _, e := db.Exec("CREATE TRIGGER fixture_reject_identity_audit BEFORE INSERT ON controller_identity_audit FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='owned audit failure'"); e != nil {
		t.Fatal(e)
	}
	key := operationKey(t)
	identityErrorCode(t, identityOperationHTTP(t, s, ad, "POST", "/console/v1/users/"+target.ID+"/revoke-sessions", map[string]any{"revision": 1, "reason": "Test explicit revocation audit rollback"}, key), 503, "IDENTITY_UNAVAILABLE")
	if u := readIdentityUser(t, s, ad, target.ID); u.Revision != 1 {
		t.Fatal("audit error advanced revision")
	}
	if w := identityOperationHTTP(t, s, tt, "GET", "/console/v1/auth/me", nil); w.Code != 200 {
		t.Fatal("audit error revoked target session")
	}
	var n int
	if e := db.QueryRow("SELECT COUNT(*) FROM controller_identity_operations WHERE operation_id=?", key).Scan(&n); e != nil || n != 0 {
		t.Fatal("audit error retained receipt", e)
	}
}

func TestMySQLIdentityRevocationFencesAlreadyStartedLogin(t *testing.T) {
	s, db := mysqlIdentity(t)
	a := bootstrap(t, s)
	anon, err := s.anonymousSession(context.Background(), "192.0.2.90:1234")
	if err != nil {
		t.Fatal(err)
	}
	lock, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback()
	if err = identityLock(context.Background(), lock); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var w *httptest.ResponseRecorder
	t.Cleanup(func() {
		lock.Rollback()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Error("owned in-flight login did not stop")
		}
	})
	go func() {
		defer close(done)
		r := httptest.NewRequest("POST", s.origin+"/console/v1/auth/login", strings.NewReader(`{"email":"root@example.invalid","password":"`+testPassword+`"}`))
		r.Header.Set("Origin", s.origin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrfToken(anon))
		r.AddCookie(&http.Cookie{Name: CookieName, Value: anon})
		w = httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var waits int
		err = db.QueryRow("SELECT COUNT(*) FROM performance_schema.data_lock_waits w JOIN performance_schema.data_locks l ON w.REQUESTING_ENGINE_LOCK_ID=l.ENGINE_LOCK_ID AND w.ENGINE=l.ENGINE WHERE l.OBJECT_SCHEMA=DATABASE() AND l.OBJECT_NAME='controller_identity_lock'").Scan(&waits)
		if err != nil {
			t.Fatal("cannot observe real login lock wait", err)
		}
		if waits > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("login never reached serialized issuance")
		}
		select {
		case <-done:
			t.Fatal("login bypassed held identity lock")
		case <-time.After(5 * time.Millisecond):
		}
	}
	// Model the concurrent revoker while holding the exact production identity
	// lock. The all-session HTTP operation is independently tested above.
	if _, err = lock.Exec("UPDATE controller_console_users SET revision=revision+1 WHERE id=?", a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = lock.Exec("DELETE FROM controller_console_sessions WHERE user_id=?", a.ID); err != nil {
		t.Fatal(err)
	}
	if err = lock.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("login did not finish after revocation")
	}
	identityErrorCode(t, w, 401, "LOGIN_FAILED")
	if fresh := loginUsersPageHTTP(t, s, a); fresh == "" {
		t.Fatal("fresh post-revocation login must remain possible")
	}
}

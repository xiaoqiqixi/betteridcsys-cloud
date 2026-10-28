package control

import (
	"aster/cloud/internal/identity"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// Observe the actual isolated database boundary, including unknown future
// tables, rather than only checking an HTTP success/error label. No SQL/identity
// implementation is mocked. These hashes never contain plaintext credentials.
func verificationDatabaseImage(t *testing.T, store *SQLStore) map[string]string {
	t.Helper()
	rows, err := store.DB.Query("SHOW TABLES")
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if rows.Scan(&name) != nil || !regexp.MustCompile(`^[a-z][a-z0-9_]+$`).MatchString(name) {
			t.Fatal("unsafe fixture table")
		}
		tables = append(tables, name)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, table := range tables {
		rows, err = store.DB.Query("SELECT * FROM `" + table + "`")
		if err != nil {
			t.Fatal(err)
		}
		cols, err := rows.Columns()
		if err != nil {
			rows.Close()
			t.Fatal(err)
		}
		var encoded []string
		for rows.Next() {
			values := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range values {
				ptrs[i] = &values[i]
			}
			if rows.Scan(ptrs...) != nil {
				rows.Close()
				t.Fatal("snapshot failed")
			}
			raw, e := json.Marshal(values)
			if e != nil {
				rows.Close()
				t.Fatal(e)
			}
			encoded = append(encoded, string(raw))
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			t.Fatal(err)
		}
		sort.Strings(encoded)
		var name, ddl string
		if store.DB.QueryRow("SHOW CREATE TABLE `"+table+"`").Scan(&name, &ddl) != nil || name != table {
			t.Fatal("snapshot structure failed")
		}
		raw, err := json.Marshal([]any{cols, encoded, ddl})
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(raw)
		out[table] = hex.EncodeToString(hash[:])
	}
	return out
}

func TestMySQLVerificationConsoleRejectsBusinessAndIdentityWrites(t *testing.T) {
	store := consoleHTTPStore(t)
	server := httptest.NewUnstartedServer(nil)
	auth, err := identity.New(store.DB, identity.Config{Origin: "https://" + server.Listener.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	admin, err := auth.Bootstrap(context.Background(), "verification-admin@example.invalid", "Verification admin", []byte(consoleHTTPPassword))
	if err != nil {
		t.Fatal(err)
	}
	operation := strings.Repeat("a", 32)
	handler, err := NewVerificationConsole(store, testConfig(testProfile()), auth, operation)
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = handler
	server.StartTLS()
	defer server.Close()
	browser := newConsoleHTTPBrowser(t, server)
	browser.login(t, admin.Email)
	before := verificationDatabaseImage(t, store)
	path := "/console/v1/users"
	body := consoleHTTPJSON(t, map[string]any{"email": "must-not-exist@example.invalid", "name": "Must not exist", "role": "admin", "password": consoleHTTPPassword, "reason": "Blocked during migration verification"})
	status, raw := browser.request(t, http.MethodPost, path, body, consoleHTTPOptions{idempotency: id()})
	if status != http.StatusForbidden || consoleHTTPError(t, raw) != "MIGRATION_VERIFICATION_READ_ONLY" {
		t.Fatalf("verification issued user mutation: status=%d", status)
	}

	object := strings.Repeat("d", 32)
	for _, path := range []string{
		"/console/v1/users", "/console/v1/users/" + admin.ID, "/console/v1/users/" + admin.ID + "/revoke-sessions",
		"/console/v1/instances", "/console/v1/instances/" + object + "/operations",
		"/console/v1/instances/" + object + "/public-ingress", "/console/v1/nodes/node-a/maintenance",
		"/console/v1/operations/" + object + "/dispatch", "/console/v1/operations/" + object + "/reconcile",
		"/console/v1/networks/vpcs", "/console/v1/networks/pools", "/console/v1/networks/leases",
		"/console/v1/overlays/vpcs", "/console/v1/overlays/epochs", "/console/v1/overlays/epochs/" + object + "/dispatch",
		"/console/v1/public-ips/resources", "/console/v1/public-ips/resources/" + object + "/binding",
		"/console/v1/public-ips/resources/" + object + "/recover", "/console/v1/public-ips/resources/" + object + "/release",
		"/console/v1/public-ips/pools", "/console/v1/public-ips/leases", "/v1/jobs",
		"/console/v1/migration-verification",
	} {
		for _, method := range []string{"POST", "PATCH", "PUT", "DELETE", "HEAD", "OPTIONS"} {
			status, raw := browser.request(t, method, path, `{}`, consoleHTTPOptions{idempotency: id()})
			if status != 403 || method != "HEAD" && consoleHTTPError(t, raw) != "MIGRATION_VERIFICATION_READ_ONLY" {
				t.Fatalf("write or method escaped verification: %s %s status=%d", method, path, status)
			}
		}
	}
	for _, path := range []string{
		"/console/v1/instances/" + object + "/metrics", "/console/v1/instances/" + object + "/observation",
		"/console/v1/instances/" + object + "/migration-targets", "/console/v1/future-resource",
		"/console/v1/auth/future", "/console/v1/nodes/node-a", "/console/v1/instances/../users",
		"/console//v1/users", "/console/v1/users/", "/console/v1/%75sers", "/console%2fv1/users",
		"/console/v1/users?", "/console/v1/migration-verification?", "/console/v1/public-ips/options/" + object,
	} {
		status, raw := browser.request(t, "GET", path, "", consoleHTTPOptions{})
		if status != 403 || consoleHTTPError(t, raw) != "MIGRATION_VERIFICATION_READ_ONLY" {
			t.Fatalf("unapproved read or alias escaped verification: %s status=%d", path, status)
		}
	}
	if !reflect.DeepEqual(before, verificationDatabaseImage(t, store)) {
		t.Fatal("refused requests changed database")
	}

}

func TestMySQLVerificationConsoleReadsRestoredStateWithoutClaimingNodeConnection(t *testing.T) {
	store := consoleHTTPStore(t)
	profile, now := mysqlNode(t, store)
	config := testConfig(profile)
	config.HeartbeatTTLSeconds = 300
	request := testRequest(profile)
	job, _, err := store.Admit(context.Background(), request, config.Candidates(request), now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(nil)
	auth, err := identity.New(store.DB, identity.Config{Origin: "https://" + server.Listener.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	admin, err := auth.Bootstrap(context.Background(), "read-verification@example.invalid", "Verification admin", []byte(consoleHTTPPassword))
	if err != nil {
		t.Fatal(err)
	}
	operation := strings.Repeat("b", 32)
	handler, err := NewVerificationConsole(store, config, auth, operation)
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = handler
	server.StartTLS()
	defer server.Close()
	browser := newConsoleHTTPBrowser(t, server)
	browser.login(t, admin.Email)
	before := verificationDatabaseImage(t, store)
	status, raw := browser.request(t, "GET", "/console/v1/migration-verification", "", consoleHTTPOptions{})
	var mode struct {
		Operation      string `json:"operation_id"`
		Phase          string `json:"phase"`
		BusinessWrites *bool  `json:"business_writes"`
		NodeContacts   *bool  `json:"node_contacts"`
	}
	if status != 200 || json.Unmarshal(raw, &mode) != nil || mode.Operation != operation || mode.Phase != "verification" || mode.BusinessWrites == nil || *mode.BusinessWrites || mode.NodeContacts == nil || *mode.NodeContacts {
		t.Fatalf("missing authenticated verification status: %d", status)
	}
	consoleHTTPPrivateCheck(t, raw, browser, config)
	status, raw = browser.request(t, "GET", "/console/v1/nodes", "", consoleHTTPOptions{})
	var nodes struct {
		Items []NodeView `json:"items"`
	}
	if status != 200 || json.Unmarshal(raw, &nodes) != nil || len(nodes.Items) != 1 || nodes.Items[0].ID != profile.ID || nodes.Items[0].Online || nodes.Items[0].HeartbeatAt == nil || !nodes.Items[0].HeartbeatAt.Equal(now) {
		t.Fatalf("verification must preserve heartbeat evidence without claiming live node contact: %d", status)
	}
	for _, tc := range []struct {
		path   string
		status int
	}{
		{"/console/v1/users", 200}, {"/console/v1/users/" + admin.ID, 200}, {"/console/v1/roles", 200},
		{"/console/v1/presets", 200}, {"/console/v1/instances", 200}, {"/console/v1/instances/" + job.InstanceID, 200},
		{"/console/v1/operations", 200}, {"/console/v1/audit", 200},
		{"/console/v1/networks/vpcs", 200}, {"/console/v1/networks/pools", 200}, {"/console/v1/networks/leases", 200},
		{"/console/v1/overlays/clusters", 200}, {"/console/v1/overlays/epochs?cluster_id=cluster-a", 200},
		{"/console/v1/public-ips/options", 200}, {"/console/v1/public-ips/pools", 200}, {"/console/v1/public-ips/leases", 200},
		{"/console/v1/public-ips/operations", 200}, {"/console/v1/public-ips/resources", 200}, {"/console/v1/public-ips/resource-operations", 200},
		{"/console/v1/overlays/options?cluster_id=unknown", 400}, {"/console/v1/overlays/vpcs?cluster_id=unknown", 400},
		{"/console/v1/users?cursor=invalid", 400}, {"/console/v1/instances?cursor=bad", 400}, {"/console/v1/nodes?extra=1", 400},
		{"/console/v1/migration-verification?extra=1", 400},
	} {
		t.Run(tc.path, func(t *testing.T) {
			status, raw := browser.request(t, "GET", tc.path, "", consoleHTTPOptions{})
			if status != tc.status {
				t.Fatalf("local read status=%d, want %d", status, tc.status)
			}
			consoleHTTPPrivateCheck(t, raw, browser, config)
		})
	}
	// Missing objects retain their ordinary not-found result; allowing only lists
	// would make the restored database impossible to inspect through the UI.
	for _, prefix := range []string{"users", "identity-operations", "instances", "operations", "public-ingress-operations", "networks/vpcs", "networks/pools", "networks/leases", "overlays/vpcs", "overlays/epochs", "public-ips/pools", "public-ips/leases", "public-ips/operations", "public-ips/resources", "public-ips/resource-operations"} {
		status, _ := browser.request(t, "GET", "/console/v1/"+prefix+"/"+strings.Repeat("c", 32), "", consoleHTTPOptions{})
		if status != 404 {
			t.Errorf("missing %s: status=%d", prefix, status)
		}
	}
	if !reflect.DeepEqual(before, verificationDatabaseImage(t, store)) {
		t.Fatal("read-only verification changed database content or schema")
	}
}

// Login/logout may change only the three identity-runtime tables. Keep exact
// old audit rows too: allowing an audit-table digest to change is not permission
// to rewrite the historical prefix.
func verificationAuthenticationImage(t *testing.T, store *SQLStore) func() {
	t.Helper()
	before := verificationDatabaseImage(t, store)
	type event struct {
		ID                    int64
		Actor, Action, Target string
		At                    time.Time
	}
	events := func() []event {
		rows, err := store.DB.Query("SELECT id,actor,action,target,created_at FROM controller_identity_audit ORDER BY id")
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := []event{}
		for rows.Next() {
			var e event
			if err = rows.Scan(&e.ID, &e.Actor, &e.Action, &e.Target, &e.At); err != nil {
				t.Fatal(err)
			}
			out = append(out, e)
		}
		if err = rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	oldEvents := events()
	return func() {
		t.Helper()
		after := verificationDatabaseImage(t, store)
		if len(before) != len(after) {
			t.Fatal("authentication changed table inventory")
		}
		for table, digest := range before {
			if table != "controller_console_sessions" && table != "controller_console_login_limits" && table != "controller_identity_audit" && after[table] != digest {
				t.Fatalf("authentication changed %s", table)
			}
		}
		all := events()
		if len(all) < len(oldEvents) || !reflect.DeepEqual(oldEvents, all[:len(oldEvents)]) {
			t.Fatal("authentication rewrote historical audit prefix")
		}
		for _, e := range all[len(oldEvents):] {
			if e.Action != "identity.login" && e.Action != "identity.login_failed" && e.Action != "identity.logout" {
				t.Fatalf("unapproved verification audit action %s", e.Action)
			}
		}
	}
}

func TestMySQLVerificationConsoleUsesRealIdentityWithoutGrantExpansion(t *testing.T) {
	store := consoleHTTPStore(t)
	config := testConfig(testProfile())
	// A separate ordinary TLS console only provisions fixture accounts and later
	// revokes one of them through the existing administrator API. It is never a
	// verification-mode escape hatch and does not share a browser cookie jar.
	ordinary := httptest.NewUnstartedServer(nil)
	provisioner, err := identity.New(store.DB, identity.Config{Origin: "https://" + ordinary.Listener.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	admin, err := provisioner.Bootstrap(context.Background(), "verify-root@example.invalid", "Fixture admin", []byte(consoleHTTPPassword))
	if err != nil {
		t.Fatal(err)
	}
	ordinary.Config.Handler = (Console{Store: store, Config: config, Identity: provisioner}).Handler()
	ordinary.StartTLS()
	defer ordinary.Close()
	root := newConsoleHTTPBrowser(t, ordinary)
	root.login(t, admin.Email)
	limited := root.createUser(t, "verify-limited@example.invalid", "custom", []string{"instances.read"})
	server := httptest.NewUnstartedServer(nil)
	auth, err := identity.New(store.DB, identity.Config{Origin: "https://" + server.Listener.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewVerificationConsole(store, config, auth, strings.Repeat("e", 32))
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = handler
	server.StartTLS()
	defer server.Close()
	browser := newConsoleHTTPBrowser(t, server)
	for _, path := range []string{"/console/v1/migration-verification", "/console/v1/instances", "/console/v1/nodes", "/console/v1/auth/me", "/console/v1/users"} {
		status, raw := browser.request(t, "GET", path, "", consoleHTTPOptions{})
		if status != 401 || consoleHTTPError(t, raw) != "AUTH_REQUIRED" {
			t.Fatalf("anonymous read admitted: %s %d", path, status)
		}
	}
	checkAuth := verificationAuthenticationImage(t, store)
	browser.login(t, limited.Email)
	checkAuth()
	for _, tc := range []struct {
		path   string
		status int
	}{
		{"/console/v1/migration-verification", 200}, {"/console/v1/instances", 200}, {"/console/v1/auth/me", 200}, {"/console/v1/roles", 200},
		{"/console/v1/nodes", 403}, {"/console/v1/audit", 403}, {"/console/v1/users", 403}, {"/console/v1/users/" + admin.ID, 403},
		{"/console/v1/networks/vpcs", 403}, {"/console/v1/public-ips/resources", 403},
	} {
		status, raw := browser.request(t, "GET", tc.path, "", consoleHTTPOptions{})
		if status != tc.status || status == 403 && consoleHTTPError(t, raw) != "FORBIDDEN" {
			t.Fatalf("current grants changed: %s %d", tc.path, status)
		}
	}
	before := verificationDatabaseImage(t, store)
	for _, tc := range []struct {
		method, path string
		opts         consoleHTTPOptions
		code         string
	}{
		{"GET", "/console/v1/migration-verification", consoleHTTPOptions{origin: ptr("https://foreign.invalid")}, "ORIGIN_INVALID"},
		{"GET", "/console/v1/instances", consoleHTTPOptions{host: "foreign.invalid"}, "ORIGIN_INVALID"},
		{"POST", "/console/v1/auth/logout", consoleHTTPOptions{csrf: ptr("")}, "CSRF_INVALID"},
		{"POST", "/console/v1/auth/logout", consoleHTTPOptions{origin: ptr("")}, "ORIGIN_INVALID"},
		{"POST", "/console/v1/auth/login", consoleHTTPOptions{csrf: ptr("wrong")}, "CSRF_INVALID"},
	} {
		status, raw := browser.request(t, tc.method, tc.path, `{}`, tc.opts)
		if status != 403 || consoleHTTPError(t, raw) != tc.code {
			t.Fatalf("identity safety guard lost: %s %d", tc.path, status)
		}
	}
	plain := httptest.NewServer(handler)
	plainBrowser := newConsoleHTTPBrowser(t, plain)
	status, raw := plainBrowser.request(t, "GET", "/console/v1/migration-verification", "", consoleHTTPOptions{})
	plain.Close()
	if status != 426 || consoleHTTPError(t, raw) != "TLS_REQUIRED" {
		t.Fatal("plaintext verification admitted", status)
	}
	if !reflect.DeepEqual(before, verificationDatabaseImage(t, store)) {
		t.Fatal("identity refusals changed database")
	}

	// A legitimately logged-out cookie must not regain access when copied back.
	u, _ := url.Parse(server.URL)
	oldCookies := browser.client.Jar.Cookies(u)
	checkAuth = verificationAuthenticationImage(t, store)
	status, _ = browser.request(t, "POST", "/console/v1/auth/logout", "", consoleHTTPOptions{})
	if status != 204 {
		t.Fatal("logout failed", status)
	}
	checkAuth()
	browser.client.Jar.SetCookies(u, oldCookies)
	status, raw = browser.request(t, "GET", "/console/v1/migration-verification", "", consoleHTTPOptions{})
	if status != 401 || consoleHTTPError(t, raw) != "AUTH_REQUIRED" {
		t.Fatal("logged-out cookie accepted", status)
	}
	browser.login(t, limited.Email)
	// Account changes are fixture setup performed by the ordinary control plane,
	// not by this restricted service. Revocation must be observed immediately.
	status, _ = root.request(t, "POST", "/console/v1/users/"+limited.ID+"/revoke-sessions", consoleHTTPJSON(t, identity.RevokeSessions{Revision: limited.Revision, Reason: "Verify live session revocation"}), consoleHTTPOptions{idempotency: id()})
	if status != 200 {
		t.Fatal("fixture session revocation failed", status)
	}
	before = verificationDatabaseImage(t, store)
	status, raw = browser.request(t, "GET", "/console/v1/instances", "", consoleHTTPOptions{})
	if status != 401 || consoleHTTPError(t, raw) != "AUTH_REQUIRED" {
		t.Fatal("revoked session still read restored state", status)
	}
	if !reflect.DeepEqual(before, verificationDatabaseImage(t, store)) {
		t.Fatal("revoked session read changed database")
	}
	checkAuth = verificationAuthenticationImage(t, store)
	browser.login(t, limited.Email)
	checkAuth()
	status, raw = browser.request(t, "GET", "/console/v1/nodes", "", consoleHTTPOptions{})
	if status != 403 || consoleHTTPError(t, raw) != "FORBIDDEN" {
		t.Fatal("new login elevated limited user", status)
	}
}

package control

import (
	"aster/cloud/internal/identity"
	"aster/cloud/internal/nodeproto"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

// These tests use a real isolated MySQL fixture and real TLS, but node commands
// deliberately use the existing deterministic consoleRPC fake. They do not
// claim actual libvirt/KVM, guest networking or production deployment acceptance.
const consoleHTTPPassword = "synthetic console integration password 123"

var ownedControllerDBPrefix = regexp.MustCompile(`^aster_cloud_test_[0-9a-f]{12,24}_$`)

func controllerFixtureDatabasePrefix(raw string) (string, error) {
	if raw == "" {
		return "aster_cloud_test_console_http_", nil
	}
	if !ownedControllerDBPrefix.MatchString(raw) {
		return "", ErrInput
	}
	return raw, nil
}

// Bootstrap requires an empty identity table. Even an explicitly supplied
// private test DSN may already contain another suite's accounts: borrow only its
// isolated server privileges and create/drop our own random database. Never
// truncate or delete existing users to make this integration test pass.
func consoleHTTPStore(t *testing.T) *SQLStore {
	t.Helper()
	raw := os.Getenv("ASTER_CLOUD_TEST_DSN")
	fallback := false
	if raw == "" {
		raw = os.Getenv("ASTER_MYSQL_TEST_DSN")
		fallback = true
	}
	if raw == "" {
		t.Skip("isolated MySQL fixture unset: console HTTP database acceptance not run")
	}
	c, err := mysql.ParseDSN(raw)
	if err != nil || (fallback && c.DBName != "aster_ci_test") || (!fallback && !strings.Contains(c.DBName, "_test")) {
		t.Fatal("refuse non-test console HTTP fixture")
	}
	if c.Net != "unix" && !(c.Net == "tcp" && (strings.HasPrefix(c.Addr, "127.0.0.1:") || strings.HasPrefix(c.Addr, "[::1]:"))) {
		t.Fatal("console fixture requires a private local MySQL server")
	}
	c.MultiStatements = false
	c.ParseTime = true
	c.Loc = time.UTC
	c.Timeout = 5 * time.Second
	c.ReadTimeout = 10 * time.Second
	c.WriteTimeout = 10 * time.Second
	admin, err := sql.Open("mysql", c.FormatDSN())
	if err != nil {
		t.Fatal("invalid console HTTP fixture")
	}
	prefix, err := controllerFixtureDatabasePrefix(os.Getenv("ASTER_CLOUD_TEST_DB_PREFIX"))
	if err != nil {
		admin.Close()
		t.Fatal("refuse non-random controller fixture database prefix")
	}
	name := prefix + id()[:16]
	if _, err = admin.Exec("CREATE DATABASE `" + name + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin"); err != nil {
		admin.Close()
		t.Fatal("cannot create independent console HTTP fixture")
	}
	t.Cleanup(func() {
		if _, err := admin.Exec("DROP DATABASE `" + name + "`"); err != nil {
			t.Error("cannot drop independent console HTTP fixture")
		}
		admin.Close()
	})
	c.DBName = name
	s, err := OpenDSN(c.FormatDSN())
	if err != nil {
		t.Fatal("cannot open independent console HTTP fixture")
	}
	t.Cleanup(func() { s.DB.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err = s.Migrate(ctx); err != nil {
		t.Fatal("console HTTP fixture migration failed", err)
	}
	return s
}

type consoleHTTPBrowser struct {
	client *http.Client
	origin string
	csrf   string
	user   identity.User
}
type consoleHTTPOptions struct {
	origin, csrf *string // nil = normal browser value; pointer-to-empty = omit.
	idempotency  string
	host         string
}

func newConsoleHTTPBrowser(t *testing.T, server *httptest.Server) *consoleHTTPBrowser {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := *server.Client() // Server.Client returns a shared pointer; copy it.
	client.Jar = jar
	client.Timeout = 15 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &consoleHTTPBrowser{client: &client, origin: server.URL}
}
func (b *consoleHTTPBrowser) request(t *testing.T, method, path, body string, opts consoleHTTPOptions) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, b.origin+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	origin, csrf := b.origin, b.csrf
	if opts.origin != nil {
		origin = *opts.origin
	}
	if opts.csrf != nil {
		csrf = *opts.csrf
	}
	if method != "GET" && method != "HEAD" && origin != "" {
		req.Header.Set("Origin", origin)
	}
	if method != "GET" && method != "HEAD" && csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	if opts.origin != nil && origin != "" {
		req.Header.Set("Origin", origin)
	}
	if opts.idempotency != "" {
		req.Header.Set("Idempotency-Key", opts.idempotency)
	}
	if opts.host != "" {
		req.Host = opts.host
	}
	res, err := b.client.Do(req)
	if err != nil {
		t.Fatal("console HTTP request failed", err)
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(b.origin, "https:") && res.TLS == nil {
		t.Fatal("regression did not perform a real TLS handshake")
	}
	if res.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("console response is cacheable")
	}
	for _, c := range res.Cookies() {
		if c.Name == identity.CookieName && (!c.Secure || !c.HttpOnly || c.Path != "/" || c.Domain != "" || c.SameSite != http.SameSiteLaxMode) {
			t.Fatal("unsafe console cookie")
		}
	}
	return res.StatusCode, data
}
func consoleHTTPJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
func consoleHTTPError(t *testing.T, raw []byte) string {
	t.Helper()
	var v struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &v) != nil || v.Error.Code == "" {
		t.Fatal("missing structured console error")
	}
	return v.Error.Code
}
func (b *consoleHTTPBrowser) login(t *testing.T, email string) {
	t.Helper()
	status, raw := b.request(t, "GET", "/console/v1/auth/csrf", "", consoleHTTPOptions{})
	var challenge struct {
		CSRF string `json:"csrf_token"`
	}
	if status != 200 || json.Unmarshal(raw, &challenge) != nil || len(challenge.CSRF) != 64 {
		t.Fatal("pre-login CSRF contract", status)
	}
	b.csrf = challenge.CSRF
	u, _ := url.Parse(b.origin)
	before := b.client.Jar.Cookies(u)
	if len(before) != 1 || before[0].Name != identity.CookieName {
		t.Fatal("pre-login cookie missing")
	}
	status, raw = b.request(t, "POST", "/console/v1/auth/login", consoleHTTPJSON(t, map[string]string{"email": email, "password": consoleHTTPPassword}), consoleHTTPOptions{})
	var response struct {
		User identity.User `json:"user"`
		CSRF string        `json:"csrf_token"`
	}
	if status != 200 || json.Unmarshal(raw, &response) != nil || !response.User.Enabled || len(response.CSRF) != 64 {
		t.Fatal("console login contract", status)
	}
	after := b.client.Jar.Cookies(u)
	if len(after) != 1 || after[0].Value == before[0].Value || response.CSRF == b.csrf {
		t.Fatal("login did not rotate session/CSRF")
	}
	b.csrf, b.user = response.CSRF, response.User
}
func (b *consoleHTTPBrowser) createUser(t *testing.T, email, role string, permissions []string) identity.User {
	t.Helper()
	input := map[string]any{"email": email, "name": "Synthetic " + role, "password": consoleHTTPPassword, "role": role, "reason": "Isolated console fixture account creation"}
	if permissions != nil {
		input["permissions"] = permissions
	}
	status, raw := b.request(t, "POST", "/console/v1/users", consoleHTTPJSON(t, input), consoleHTTPOptions{idempotency: id()})
	var response struct {
		User identity.User `json:"user"`
	}
	if status != 201 || json.Unmarshal(raw, &response) != nil || response.User.ID == "" || response.User.Role != role {
		t.Fatal("console user creation contract", status)
	}
	return response.User
}
func consoleHTTPPrivateCheck(t *testing.T, raw []byte, b *consoleHTTPBrowser, c Config) {
	t.Helper()
	for _, marker := range []string{`"request_json"`, `"request_sha256"`, `"node_request"`, `"profile_sha256"`, `"intent_sha256"`, `"request_protocol"`, `"password_hash"`, `"password"`, `"csrf_token"`, `"server_certificate_sha256"`, `"client_key_file"`, `"client_cert_file"`, `"ca_file"`, `"dsn_file"`, `"billing_token_file"`, consoleHTTPPassword, b.csrf, c.TLSKeyFile, c.DSNFile, c.BillingTokenFile, c.AdminReadTokenFile, c.AdminWriteTokenFile} {
		if marker != "" && strings.Contains(string(raw), marker) {
			t.Fatal("resource DTO leaks private material")
		}
	}
	for _, p := range c.Nodes {
		for _, value := range []string{p.Endpoint, p.CAFile, p.ClientKeyFile, p.ClientCertFile, p.ServerCertificateSHA256} {
			if value != "" && strings.Contains(string(raw), value) {
				t.Fatal("resource DTO exposes approved private node profile")
			}
		}
	}
	u, _ := url.Parse(b.origin)
	for _, cookie := range b.client.Jar.Cookies(u) {
		if cookie.Value != "" && strings.Contains(string(raw), cookie.Value) {
			t.Fatal("resource DTO exposes a session token")
		}
	}
}

func TestMySQLConsoleHTTPSessionsRBACAndExplicitDispatch(t *testing.T) {
	s := consoleHTTPStore(t)
	c, p, instance, now := readyConsoleInstance(t, s)
	c.HeartbeatTTLSeconds = 300 // Keep KDF/race instrumentation from aging a synthetic heartbeat.
	c.Presets = []Preset{{ID: "approved-console", NodeID: p.ID, Resources: testResources(p)}}
	ctx := context.Background()
	// A real listener determines the fixed Origin, then the concurrency-safe mux
	// is populated before any client request. No Request.TLS or Actor is forged.
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	defer server.Close()
	ident, err := identity.New(s.DB, identity.Config{Origin: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	root, err := ident.Bootstrap(ctx, "console-root@example.invalid", "Console Root", []byte(consoleHTTPPassword))
	if err != nil {
		t.Fatal("console fixture requires an empty identity user table", err)
	}
	rpc := &consoleRPC{}
	worker := &OperationWorker{Store: s, Config: c, RPC: func(context.Context, NodeProfile) (NodeRPC, error) { return rpc, nil }, Now: func() time.Time { return now }}
	console := Console{Store: s, Config: c, Identity: ident, Worker: worker}
	mux.Handle("/", console.Handler())
	admin := newConsoleHTTPBrowser(t, server)
	admin.login(t, root.Email)
	if admin.user.ID != root.ID || !admin.user.Can("users.manage") || !admin.user.Can("instances.dangerous") {
		t.Fatal("admin grants were not obtained through real login")
	}
	viewerUser := admin.createUser(t, "console-viewer@example.invalid", "viewer", nil)
	operatorUser := admin.createUser(t, "console-operator@example.invalid", "operator", nil)
	limitedUser := admin.createUser(t, "console-limited@example.invalid", "custom", []string{"instances.read"})
	viewer := newConsoleHTTPBrowser(t, server)
	viewer.login(t, viewerUser.Email)
	operator := newConsoleHTTPBrowser(t, server)
	operator.login(t, operatorUser.Email)
	limited := newConsoleHTTPBrowser(t, server)
	limited.login(t, limitedUser.Email)
	if viewer.user.Can("instances.manage") || operator.user.Can("instances.dangerous") || limited.user.Can("storage.read") {
		t.Fatal("login returned an expanded role")
	}

	if !t.Run("viewer_keyset_pagination_and_server_side_write_rejection", func(t *testing.T) {
		// Read-only synthetic rows exercise a real two-page result, not merely a
		// tolerated empty cursor. They are not node allocations or financial orders.
		var values []string
		var args []any
		for range 101 {
			values = append(values, "(?,?,?,?,?,?,?,?)")
			args = append(args, id(), instance.OwnerRef, p.ID, "page-fixture", "shutoff", mustJSON(instance.Resources), now, now)
		}
		if _, err := s.DB.Exec("INSERT INTO controller_instances(id,owner_ref,node_id,hostname,state,resources,created_at,updated_at) VALUES "+strings.Join(values, ","), args...); err != nil {
			t.Fatal(err)
		}
		status, raw := viewer.request(t, "GET", "/console/v1/instances", "", consoleHTTPOptions{})
		var first struct {
			Items []Instance `json:"items"`
			Next  string     `json:"next_cursor"`
		}
		if status != 200 || json.Unmarshal(raw, &first) != nil || len(first.Items) != 100 || !nodeproto.ValidID(first.Next) {
			t.Fatal("first instance page", status, len(first.Items))
		}
		consoleHTTPPrivateCheck(t, raw, viewer, c)
		status, raw = viewer.request(t, "GET", "/console/v1/instances?cursor="+url.QueryEscape(first.Next), "", consoleHTTPOptions{})
		var second struct {
			Items []Instance `json:"items"`
			Next  any        `json:"next_cursor"`
		}
		if status != 200 || json.Unmarshal(raw, &second) != nil || len(second.Items) != 2 || second.Next != nil {
			t.Fatal("second instance page", status, len(second.Items))
		}
		seen := map[string]bool{}
		for _, v := range first.Items {
			seen[v.ID] = true
		}
		for _, v := range second.Items {
			if seen[v.ID] {
				t.Fatal("cursor repeated an instance")
			}
		}
		for _, path := range []string{"/console/v1/operations?cursor=999999999&instance_id=" + instance.ID, "/console/v1/nodes", "/console/v1/presets"} {
			status, raw = viewer.request(t, "GET", path, "", consoleHTTPOptions{})
			if status != 200 {
				t.Fatal("viewer read/pagination denied", path, status)
			}
			consoleHTTPPrivateCheck(t, raw, viewer, c)
		}
		status, raw = viewer.request(t, "POST", "/console/v1/instances/"+instance.ID+"/operations", `{"action":"start","confirmation":""}`, consoleHTTPOptions{idempotency: id()})
		if status != 403 || consoleHTTPError(t, raw) != "FORBIDDEN" {
			t.Fatal("viewer instance mutation allowed", status)
		}
		status, _ = viewer.request(t, "POST", "/console/v1/instances", consoleHTTPJSON(t, CreateInstanceInput{Hostname: "denied", OwnerRef: id(), PresetID: "approved-console"}), consoleHTTPOptions{idempotency: id()})
		if status != 403 {
			t.Fatal("viewer creation allowed", status)
		}
		status, _ = viewer.request(t, "GET", "/console/v1/users", "", consoleHTTPOptions{})
		if status != 403 {
			t.Fatal("viewer account access allowed", status)
		}
		status, _ = viewer.request(t, "GET", "/console/v1/audit", "", consoleHTTPOptions{})
		if status != 403 {
			t.Fatal("viewer audit access allowed", status)
		}
		status, raw = viewer.request(t, "GET", "/console/v1/roles", "", consoleHTTPOptions{})
		var roles struct {
			Items []identity.Role `json:"items"`
		}
		if status != 200 || json.Unmarshal(raw, &roles) != nil || len(roles.Items) != 4 {
			t.Fatal("role metadata not available through session API")
		}
	}) {
		return
	}

	if !t.Run("CSRF_origin_host_TLS_and_operator_danger_fail_closed", func(t *testing.T) {
		op := id()
		body := `{"action":"shutdown","confirmation":""}`
		status, raw := admin.request(t, "POST", "/console/v1/instances/"+instance.ID+"/operations", body, consoleHTTPOptions{csrf: ptr(""), idempotency: op})
		if status != 403 || consoleHTTPError(t, raw) != "CSRF_INVALID" {
			t.Fatal("missing CSRF not denied", status)
		}
		status, raw = admin.request(t, "POST", "/console/v1/instances/"+instance.ID+"/operations", body, consoleHTTPOptions{origin: ptr("https://attacker.invalid"), idempotency: op})
		if status != 403 || consoleHTTPError(t, raw) != "ORIGIN_INVALID" {
			t.Fatal("forged Origin accepted", status)
		}
		status, _ = admin.request(t, "GET", "/console/v1/instances", "", consoleHTTPOptions{host: "attacker.invalid"})
		if status != 403 {
			t.Fatal("wrong Host accepted", status)
		}
		status, _ = operator.request(t, "POST", "/console/v1/instances/"+instance.ID+"/operations", consoleHTTPJSON(t, OperationInput{Action: "delete", Confirmation: instance.ID}), consoleHTTPOptions{idempotency: id()})
		if status != 403 {
			t.Fatal("operator gained dangerous action", status)
		}
		anonymous := newConsoleHTTPBrowser(t, server)
		status, raw = anonymous.request(t, "GET", "/console/v1/instances", "", consoleHTTPOptions{})
		if status != 401 || consoleHTTPError(t, raw) != "AUTH_REQUIRED" {
			t.Fatal("credential-free console read allowed", status)
		}
		plain := httptest.NewServer(console.Handler())
		defer plain.Close()
		insecure := &consoleHTTPBrowser{client: plain.Client(), origin: plain.URL}
		status, raw = insecure.request(t, "GET", "/console/v1/instances", "", consoleHTTPOptions{})
		if status != 426 || consoleHTTPError(t, raw) != "TLS_REQUIRED" {
			t.Fatal("actual plaintext connection not rejected", status)
		}
		var count int
		if err := s.DB.QueryRow("SELECT COUNT(*) FROM controller_operations WHERE id=?", op).Scan(&count); err != nil || count != 0 || rpc.posts.Load() != 0 {
			t.Fatal("denied request changed state or dispatched", count)
		}
	}) {
		return
	}

	if !t.Run("maintenance_and_operation_required_exact_JSON_never_mutate_on_rejection", func(t *testing.T) {
		var before int
		s.DB.QueryRow("SELECT COUNT(*) FROM controller_operations").Scan(&before)
		for _, body := range []string{`{}`, `null`, `{"enabled":null}`, `{"Enabled":false}`, `{"enabled":false,"Enabled":true}`, `{"enabled":false,"enabled":true}`} {
			status, _ := admin.request(t, "POST", "/console/v1/nodes/"+p.ID+"/maintenance", body, consoleHTTPOptions{})
			if status != 400 {
				t.Fatal("ambiguous maintenance request accepted", body, status)
			}
		}
		for _, body := range []string{`{}`, `null`, `{"Action":"start","confirmation":""}`, `{"action":"start","confirmation":null}`, `{"action":"start"}`, `{"action":"start","Action":"delete","confirmation":""}`} {
			status, _ := admin.request(t, "POST", "/console/v1/instances/"+instance.ID+"/operations", body, consoleHTTPOptions{idempotency: id()})
			if status != 400 {
				t.Fatal("ambiguous operation accepted", body, status)
			}
		}
		var after int
		s.DB.QueryRow("SELECT COUNT(*) FROM controller_operations").Scan(&after)
		var maintenance bool
		s.DB.QueryRow("SELECT maintenance FROM controller_nodes WHERE id=?", p.ID).Scan(&maintenance)
		if before != after || maintenance || rpc.posts.Load() != 0 {
			t.Fatal("rejected JSON changed state")
		}
	}) {
		return
	}

	if !t.Run("admin_operation_is_durable_before_single_explicit_dispatch_then_GET_reconcile", func(t *testing.T) {
		op := id()
		path := "/console/v1/instances/" + instance.ID + "/operations"
		input := OperationInput{Action: "shutdown", Confirmation: ""}
		status, raw := admin.request(t, "POST", path, consoleHTTPJSON(t, input), consoleHTTPOptions{idempotency: op})
		var response struct {
			Operation Operation `json:"operation"`
		}
		if status != 202 || json.Unmarshal(raw, &response) != nil || response.Operation.ID != op || response.Operation.State != "accepted" || rpc.posts.Load() != 0 {
			t.Fatal("intent did not persist before network", status)
		}
		consoleHTTPPrivateCheck(t, raw, admin, c)
		status, _ = admin.request(t, "POST", path, consoleHTTPJSON(t, input), consoleHTTPOptions{idempotency: op})
		if status != 202 || rpc.posts.Load() != 0 {
			t.Fatal("admission replay dispatched")
		}
		var requestAudits int
		status, _ = viewer.request(t, "POST", "/console/v1/operations/"+op+"/dispatch", `{}`, consoleHTTPOptions{idempotency: op})
		if status != 403 {
			t.Fatal("viewer dispatched another staff intent", status)
		}
		if err := s.DB.QueryRow("SELECT COUNT(*) FROM controller_audit WHERE target=? AND action IN ('operation.dispatch_requested','operation.reconcile_requested','operation.dispatch_committed')", op).Scan(&requestAudits); err != nil || requestAudits != 0 {
			t.Fatal("unauthorized dispatch wrote request/commit audit", err, requestAudits)
		}
		status, raw = operator.request(t, "POST", "/console/v1/operations/"+op+"/dispatch", `{}`, consoleHTTPOptions{idempotency: op})
		if status != 202 || json.Unmarshal(raw, &response) != nil || response.Operation.State != "dispatched" || response.Operation.ActorID != admin.user.ID || rpc.posts.Load() != 1 {
			t.Fatal("explicit dispatch contract", status, response.Operation.State)
		}
		consoleHTTPPrivateCheck(t, raw, operator, c)
		status, _ = operator.request(t, "POST", "/console/v1/operations/"+op+"/dispatch", `{}`, consoleHTTPOptions{idempotency: op})
		if status != 409 || rpc.posts.Load() != 1 {
			t.Fatal("second dispatch resent", status)
		}
		status, raw = admin.request(t, "GET", "/console/v1/operations/"+op, "", consoleHTTPOptions{})
		if status != 200 || json.Unmarshal(raw, &response) != nil || response.Operation.State != "dispatched" {
			t.Fatal("persisted operation lookup", status)
		}
		consoleHTTPPrivateCheck(t, raw, admin, c)
		status, raw = operator.request(t, "POST", "/console/v1/operations/"+op+"/reconcile", `{}`, consoleHTTPOptions{idempotency: op})
		if status != 202 || json.Unmarshal(raw, &response) != nil || response.Operation.State != "succeeded" || response.Operation.ActorID != admin.user.ID || rpc.posts.Load() != 1 || rpc.gets.Load() != 1 {
			t.Fatal("reconcile not GET-only", status)
		}
		var dispatchRequested, reconcileRequested, wrongActor, committed, wrongCommitted int
		if err := s.DB.QueryRow("SELECT COUNT(*) FROM controller_audit WHERE target=? AND action='operation.dispatch_requested' AND actor=?", op, "user:"+operator.user.ID).Scan(&dispatchRequested); err != nil {
			t.Fatal(err)
		}
		if err := s.DB.QueryRow("SELECT COUNT(*) FROM controller_audit WHERE target=? AND action='operation.reconcile_requested' AND actor=?", op, "user:"+operator.user.ID).Scan(&reconcileRequested); err != nil {
			t.Fatal(err)
		}
		if err := s.DB.QueryRow("SELECT COUNT(*) FROM controller_audit WHERE target=? AND action IN ('operation.dispatch_requested','operation.reconcile_requested') AND actor<>?", op, "user:"+operator.user.ID).Scan(&wrongActor); err != nil {
			t.Fatal(err)
		}
		if err := s.DB.QueryRow("SELECT COUNT(*) FROM controller_audit WHERE target=? AND action='operation.dispatch_committed' AND actor='controller'", op).Scan(&committed); err != nil {
			t.Fatal(err)
		}
		if err := s.DB.QueryRow("SELECT COUNT(*) FROM controller_audit WHERE target=? AND action='operation.dispatch_committed' AND actor<>'controller'", op).Scan(&wrongCommitted); err != nil {
			t.Fatal(err)
		}
		if dispatchRequested != 2 || reconcileRequested != 1 || wrongActor != 0 || committed != 1 || wrongCommitted != 0 {
			t.Fatal("actual requester/immutable creator/controller commit audit attribution", dispatchRequested, reconcileRequested, wrongActor, committed, wrongCommitted)
		}
		status, raw = admin.request(t, "GET", "/console/v1/instances/"+instance.ID, "", consoleHTTPOptions{})
		var detail struct {
			Instance Instance `json:"instance"`
		}
		if status != 200 || json.Unmarshal(raw, &detail) != nil || detail.Instance.State != "shutoff" {
			t.Fatal("API instance state not confirmed", status)
		}
		consoleHTTPPrivateCheck(t, raw, admin, c)
	}) {
		return
	}

	if !t.Run("admin_instance_create_never_fabricates_financial_order_or_automatically_dispatches", func(t *testing.T) {
		op := id()
		in := CreateInstanceInput{Hostname: "console-created", OwnerRef: id(), PresetID: "approved-console"}
		basePosts := rpc.posts.Load()
		status, raw := admin.request(t, "POST", "/console/v1/instances", consoleHTTPJSON(t, in), consoleHTTPOptions{idempotency: op})
		var response struct {
			Operation Operation `json:"operation"`
		}
		if status != 202 || json.Unmarshal(raw, &response) != nil || response.Operation.InstanceID != op || response.Operation.State != "accepted" || rpc.posts.Load() != basePosts {
			t.Fatal("resource create admission", status)
		}
		consoleHTTPPrivateCheck(t, raw, admin, c)
		var financialJobs int
		s.DB.QueryRow("SELECT COUNT(*) FROM controller_jobs WHERE operation_id=? OR order_id=?", op, op).Scan(&financialJobs)
		if financialJobs != 0 {
			t.Fatal("console invented a financial job")
		}
		status, _ = admin.request(t, "POST", "/console/v1/instances", consoleHTTPJSON(t, in), consoleHTTPOptions{idempotency: op})
		if status != 202 {
			t.Fatal("resource replay rejected", status)
		}
		in.Hostname = "changed-intent"
		status, _ = admin.request(t, "POST", "/console/v1/instances", consoleHTTPJSON(t, in), consoleHTTPOptions{idempotency: op})
		if status != 409 {
			t.Fatal("changed create intent accepted", status)
		}
		for _, action := range []string{"dispatch", "reconcile"} {
			status, raw = admin.request(t, "POST", "/console/v1/operations/"+op+"/"+action, `{}`, consoleHTTPOptions{idempotency: op})
			if status != 202 {
				t.Fatal("resource explicit worker action", action, status)
			}
		}
		if rpc.posts.Load() != basePosts+1 {
			t.Fatal("resource create sent more than once")
		}
		status, raw = admin.request(t, "GET", "/console/v1/instances/"+op, "", consoleHTTPOptions{})
		var detail struct {
			Instance Instance `json:"instance"`
		}
		if status != 200 || json.Unmarshal(raw, &detail) != nil || detail.Instance.State != "running" {
			t.Fatal("created resource not confirmed running", status)
		}
		consoleHTTPPrivateCheck(t, raw, admin, c)
	}) {
		return
	}

	if !t.Run("detail_metadata_respects_storage_and_migration_permissions_and_hides_private_bindings", func(t *testing.T) {
		artifact, migration := id(), id()
		if _, err := s.DB.Exec("INSERT INTO controller_artifacts(id,instance_id,node_id,kind,state,manifest_sha256,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)", artifact, instance.ID, p.ID, "snapshot", "ready", strings.Repeat("b", 64), now, now); err != nil {
			t.Fatal(err)
		}
		if _, err := s.DB.Exec("INSERT INTO controller_migrations("+migrationColumns+") VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", migration, instance.ID, p.ID, "history-target", strings.Repeat("c", 64), id(), mustJSON(instance.Resources), strings.Repeat("d", 64), strings.Repeat("e", 64), "active", now, now); err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			browser               *consoleHTTPBrowser
			artifacts, migrations int
		}{{limited, 0, 0}, {viewer, 1, 0}, {admin, 1, 1}} {
			status, raw := tc.browser.request(t, "GET", "/console/v1/instances/"+instance.ID, "", consoleHTTPOptions{})
			var detail struct {
				Artifacts  []Artifact  `json:"artifacts"`
				Migrations []Migration `json:"migrations"`
			}
			if status != 200 || json.Unmarshal(raw, &detail) != nil || len(detail.Artifacts) != tc.artifacts || len(detail.Migrations) != tc.migrations {
				t.Fatal("metadata permission boundary", status, len(detail.Artifacts), len(detail.Migrations))
			}
			for _, historical := range detail.Migrations {
				if historical.SourceRetirementState != "" || historical.SourceRetirementOperationID != "" {
					t.Fatal("historical storage/1 metadata invented a retirement receipt")
				}
			}
			consoleHTTPPrivateCheck(t, raw, tc.browser, c)
			for _, private := range []string{strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64), strings.Repeat("e", 64), `"fence_token"`, `"manifest_sha256"`, `"target_profile_sha256"`} {
				if strings.Contains(string(raw), private) {
					t.Fatal("artifact/migration DTO leaks private evidence binding")
				}
			}
		}
		status, raw := admin.request(t, "GET", "/console/v1/audit", "", consoleHTTPOptions{})
		if status != 200 {
			t.Fatal("audits unavailable", status)
		}
		consoleHTTPPrivateCheck(t, raw, admin, c)
		status, raw = admin.request(t, "GET", "/console/v1/users", "", consoleHTTPOptions{})
		if status != 200 {
			t.Fatal("admin accounts unavailable", status)
		}
		consoleHTTPPrivateCheck(t, raw, admin, c)
	}) {
		return
	}

	t.Run("disabling_user_through_account_API_revokes_existing_browser_immediately", func(t *testing.T) {
		status, _ := admin.request(t, "PATCH", "/console/v1/users/"+viewer.user.ID, consoleHTTPJSON(t, map[string]any{"enabled": false, "revision": viewer.user.Revision, "reason": "隔离验收：停用现有成员并撤销会话"}), consoleHTTPOptions{idempotency: id()})
		if status != 200 {
			t.Fatal("admin could not disable staff account", status)
		}
		for _, path := range []string{"/console/v1/auth/me", "/console/v1/instances"} {
			status, raw := viewer.request(t, "GET", path, "", consoleHTTPOptions{})
			if status != 401 || consoleHTTPError(t, raw) != "AUTH_REQUIRED" {
				t.Fatal("disabled browser session remained active", path, status)
			}
		}
	})
}

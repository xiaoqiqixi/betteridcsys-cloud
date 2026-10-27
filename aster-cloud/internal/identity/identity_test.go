package identity

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPasswordHashAndVerification(t *testing.T) {
	password := []byte("an independent long test password")
	a, err := hashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	b, err := hashPassword(password)
	if err != nil || a == b {
		t.Fatal("random salt missing")
	}
	if strings.Contains(a, string(password)) || !verifyPassword(a, password) || verifyPassword(a, []byte("different password")) {
		t.Fatal("password hash binding")
	}
	for _, bad := range []string{"", strings.Replace(a, "600000", "1", 1), strings.Replace(a, "pbkdf2-sha256", "md5", 1), a + "$", dummyPasswordHash} {
		if verifyPassword(bad, password) {
			t.Fatal("invalid hash accepted")
		}
	}
	for _, bad := range [][]byte{nil, []byte("short"), bytes.Repeat([]byte("a"), 1025)} {
		if _, err := hashPassword(bad); err == nil {
			t.Fatal("weak/oversized password accepted")
		}
	}
}
func TestPermissionsAreExplicitAndImmutableCopies(t *testing.T) {
	for _, role := range []string{"admin", "operator", "viewer", "custom"} {
		var custom []string
		if role == "custom" {
			custom = []string{"storage.restore", "instances.read"}
		}
		p, err := permissions(role, custom)
		if err != nil {
			t.Fatal(err)
		}
		u := User{Enabled: true, Permissions: p}
		if !u.Can("instances.read") || u.Can("not.real") {
			t.Fatal(role, "permissions")
		}
		if role != "admin" && role != "custom" && u.Can("storage.restore") {
			t.Fatal("restore implicitly granted")
		}
		if role == "operator" && (u.Can("instances.dangerous") || u.Can("users.manage") || u.Can("migration.manage")) {
			t.Fatal("operator privilege expansion")
		}
		u.Enabled = false
		if u.Can("instances.read") {
			t.Fatal("disabled actor allowed")
		}
		p[0] = "not.real"
	}
	for _, v := range []struct {
		role string
		p    []string
	}{{"root", nil}, {"admin", []string{}}, {"custom", nil}, {"custom", []string{"users.*"}}, {"custom", []string{"nodes.read", "nodes.read"}}} {
		if _, err := permissions(v.role, v.p); err == nil {
			t.Fatal("invalid grants accepted")
		}
	}
	r := Roles()
	r[0].Permissions[0] = "changed"
	if Roles()[0].Permissions[0] == "changed" {
		t.Fatal("role grants alias mutable global")
	}
}

func TestUserManagementDelegationCannotEscalate(t *testing.T) {
	adminP, _ := permissions("admin", nil)
	admin := User{Role: "admin", Enabled: true, Permissions: adminP}
	manager := User{Role: "custom", Enabled: true, Permissions: []string{"instances.read", "users.manage"}}
	low := User{Role: "custom", Enabled: true, Permissions: []string{"instances.read"}}
	high := User{Role: "custom", Enabled: true, Permissions: []string{"instances.dangerous", "instances.read"}}
	if mayManage(manager, nil, admin) || mayManage(manager, &admin, low) || mayManage(manager, nil, high) || mayManage(manager, &high, low) {
		t.Fatal("bounded manager escalated or controlled a superior account")
	}
	if !mayManage(manager, nil, low) || !mayManage(manager, &low, low) || !mayManage(admin, &high, admin) {
		t.Fatal("legitimate scoped/admin management rejected")
	}
	customAll := admin
	customAll.Role = "custom"
	if mayManage(customAll, &admin, admin) {
		t.Fatal("custom all-grants manager acquired administrator control")
	}
	manager.Enabled = false
	if mayManage(manager, nil, low) {
		t.Fatal("disabled manager allowed")
	}
}
func TestEmailNameAndJSONValidation(t *testing.T) {
	if got, err := normalizeEmail(" Admin@Example.invalid "); err != nil || got != "admin@example.invalid" {
		t.Fatal("normalization", got, err)
	}
	for _, bad := range []string{"a", "User <a@example.invalid>", "a\n@example.invalid", "用户@example.invalid", "a b@example.invalid"} {
		if _, err := normalizeEmail(bad); err == nil {
			t.Fatal("bad email accepted")
		}
	}
	for _, bad := range []string{"", " trimmed ", "line\nname", strings.Repeat("a", 101)} {
		if validName(bad) {
			t.Fatal("bad name accepted")
		}
	}
	for _, body := range []string{`null`, `[]`, `{"email":"a","email":"b"}`, `{"email":"a","unknown":true}`, `{"Email":"a"}`, `{"email":"a","Email":"b"}`, `{"email":null}`, `{"email":"a"} {}`, strings.Repeat(" ", 16385)} {
		r := httptest.NewRequest("POST", "https://console.example.invalid", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		var in struct {
			Email string `json:"email"`
		}
		if decode(r, &in) == nil {
			t.Fatal("ambiguous/invalid JSON accepted", body[:min(len(body), 80)])
		}
	}
	for _, body := range []string{`{"Role":"admin"}`, `{"role":null}`, `{"enabled":null}`, `{"permissions":null}`, `{"password":null}`} {
		r := httptest.NewRequest("PATCH", "https://console.example.invalid", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		var in UpdateUser
		if decode(r, &in) == nil {
			t.Fatal("case alias/null patch accepted", body)
		}
	}
}

func TestInvalidPeerCannotCreateAnonymousOrAttemptLogin(t *testing.T) {
	db, err := sql.Open("mysql", "unused:unused@unix(/nonexistent)/aster_cloud_test")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s, _ := New(db, Config{Origin: "https://console.example.invalid"})
	for _, peer := range []string{"", "garbage", "example.invalid:1234", "192.0.2.1, 198.51.100.1", "[broken]:123"} {
		if _, err = s.anonymousSession(context.Background(), peer); err != ErrRateLimited {
			t.Fatal("invalid peer reached database/session creation", peer, err)
		}
		if err = s.reserveLogin(context.Background(), "test@example.invalid", peer); err != ErrRateLimited {
			t.Fatal("invalid login peer", peer, err)
		}
	}
	if loginIP("192.0.2.1:1234") != "192.0.2.1" || loginIP("[::ffff:192.0.2.1]:1234") != "192.0.2.1" {
		t.Fatal("equivalent peer forms bypass bucket")
	}
}
func TestSessionTokenAndCSRFBinding(t *testing.T) {
	a, err := randomToken()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := randomToken()
	if !validToken(a) || a == b || csrfToken(a) == csrfToken(b) || csrfToken(a) == a || tokenHash(a) == tokenHash(b) {
		t.Fatal("session binding")
	}
	for _, bad := range []string{"", a[:63], strings.ToUpper(a), strings.Repeat("g", 64)} {
		if validToken(bad) {
			t.Fatal("invalid token")
		}
	}
	r := httptest.NewRequest("GET", "https://console.example.invalid", nil)
	r.Header.Set("Cookie", CookieName+"="+a+"; "+CookieName+"="+b)
	if _, err := sessionCookie(r); err == nil {
		t.Fatal("duplicate cookie accepted")
	}
	u, ok := Actor(context.Background())
	if ok || u.ID != "" {
		t.Fatal("anonymous actor invented")
	}
}
func TestTLSOriginAndCSRFRejectBeforeDatabase(t *testing.T) {
	db, err := sql.Open("mysql", "unused:unused@unix(/nonexistent)/aster_cloud_test")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s, err := New(db, Config{Origin: "https://console.example.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	for _, origin := range []string{"http://console.example.invalid", "https://", "https://u:p@console.example.invalid", "https://console.example.invalid/path", "https://console.example.invalid?x=1"} {
		if _, err := New(db, Config{Origin: origin}); err == nil {
			t.Fatal("unsafe origin accepted")
		}
	}
	for _, ttl := range []time.Duration{time.Second, 25 * time.Hour} {
		if _, err := New(db, Config{Origin: s.origin, SessionTTL: ttl}); err == nil {
			t.Fatal("unsafe TTL")
		}
	}
	for _, tc := range []struct {
		name, url, origin, site, method string
		want                            int
	}{{"no_tls", "http://console.example.invalid/console/v1/auth/csrf", "", "", "GET", 426}, {"wrong_host", "https://evil.example.invalid/console/v1/auth/csrf", "", "", "GET", 403}, {"cross_origin", "https://console.example.invalid/console/v1/auth/csrf", "https://evil.example.invalid", "", "GET", 403}, {"cross_site", "https://console.example.invalid/console/v1/auth/csrf", "", "cross-site", "GET", 403}, {"query", "https://console.example.invalid/console/v1/auth/csrf?token=x", "", "", "GET", 400}, {"missing_cookie", "https://console.example.invalid/console/v1/auth/me", "", "", "GET", 401}, {"unknown", "https://console.example.invalid/unknown", "", "", "GET", 404}} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.url, nil)
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			if tc.site != "" {
				r.Header.Set("Sec-Fetch-Site", tc.site)
			}
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatal(w.Code, w.Body.String())
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("sensitive response cacheable")
			}
		})
	}
	raw, _ := randomToken()
	for _, tc := range []struct {
		origin, csrf string
		want         int
	}{{"", csrfToken(raw), 403}, {"https://evil.invalid", csrfToken(raw), 403}, {s.origin, "", 403}, {s.origin, csrfToken(raw + "other"), 403}} {
		r := httptest.NewRequest("POST", s.origin+"/console/v1/auth/login", nil)
		r.Header.Set("Origin", tc.origin)
		r.Header.Set("X-CSRF-Token", tc.csrf)
		w := httptest.NewRecorder()
		if s.checkCSRF(w, r, raw) || w.Code != tc.want {
			t.Fatal("csrf accepted")
		}
	}
	w := httptest.NewRecorder()
	s.setCookie(w, raw, time.Hour)
	c := w.Result().Cookies()[0]
	if c.Name != CookieName || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Domain != "" || c.Path != "/" {
		t.Fatal("unsafe cookie", c)
	}
	b, _ := json.Marshal(User{})
	if strings.Contains(string(b), "password") || strings.Contains(string(b), "session") {
		t.Fatal("user leaks credentials")
	}
}

// This is a real network/TLS handshake test, unlike the request-recorder unit
// cases above. Database-backed login over real TLS is additionally exercised by
// TestMySQLConsoleIdentity when the isolated MySQL fixture is available.
func TestRealTLSConsoleSecurityBoundary(t *testing.T) {
	db, err := sql.Open("mysql", "unused:unused@unix(/nonexistent)/aster_cloud_test")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s, err := New(db, Config{Origin: "https://console.example.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(s.Handler())
	defer server.Close()
	for _, tc := range []struct {
		host, origin string
		want         int
	}{{"console.example.invalid", "", 404}, {"evil.example.invalid", "", 403}, {"console.example.invalid", "https://evil.example.invalid", 403}} {
		req, _ := http.NewRequest("GET", server.URL+"/unknown", nil)
		req.Host = tc.host
		if tc.origin != "" {
			req.Header.Set("Origin", tc.origin)
		}
		res, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.TLS == nil || res.StatusCode != tc.want {
			t.Fatal("TLS/origin enforcement", res.StatusCode)
		}
	}
}

func TestResourceRequireAllowsGETQueryButIdentityAndWritesRejectIt(t *testing.T) {
	db, err := sql.Open("mysql", "unused:unused@unix(/nonexistent)/aster_cloud_test")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s, err := New(db, Config{Origin: "https://console.example.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("anonymous resource handler reached") })
	for _, tc := range []struct {
		method, path string
		h            http.Handler
		want         int
	}{{"GET", "/console/v1/instances?cursor=abc", s.Require("instances.read", next), 401}, {"GET", "/console/v1/auth/me?anything=1", s.Handler(), 400}, {"POST", "/console/v1/instances?anything=1", s.Require("instances.manage", next), 400}} {
		r := httptest.NewRequest(tc.method, s.origin+tc.path, nil)
		w := httptest.NewRecorder()
		tc.h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatal("query routing regression", tc.path, w.Code, w.Body.String())
		}
	}
}

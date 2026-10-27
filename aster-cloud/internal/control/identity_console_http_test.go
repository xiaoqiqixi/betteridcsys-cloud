package control

import (
	"aster/cloud/internal/identity"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMySQLConsoleRoutesIdentityReceiptsThroughCurrentManager(t *testing.T) {
	s := consoleHTTPStore(t)
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	defer server.Close()
	auth, e := identity.New(s.DB, identity.Config{Origin: server.URL})
	if e != nil {
		t.Fatal(e)
	}
	a, e := auth.Bootstrap(context.Background(), "receipt-route-admin@example.invalid", "Receipt route admin", []byte(consoleHTTPPassword))
	if e != nil {
		t.Fatal(e)
	}
	c := Console{Store: s, Config: testConfig(testProfile()), Identity: auth}
	mux.Handle("/", c.Handler())
	b := newConsoleHTTPBrowser(t, server)
	b.login(t, a.Email)
	key := id()
	status, raw := b.request(t, "POST", "/console/v1/users", consoleHTTPJSON(t, map[string]any{"email": "receipt-route-viewer@example.invalid", "name": "Receipt route viewer", "role": "viewer", "password": consoleHTTPPassword, "reason": "Isolated route acceptance"}), consoleHTTPOptions{idempotency: key})
	var result struct {
		User      identity.User              `json:"user"`
		Operation identity.IdentityOperation `json:"operation"`
	}
	if status != 201 || json.Unmarshal(raw, &result) != nil || result.Operation.ID != key {
		t.Fatal("console create did not confirm identity receipt", status)
	}
	status, raw = b.request(t, "GET", "/console/v1/identity-operations/"+key, "", consoleHTTPOptions{})
	var saved struct {
		Operation identity.IdentityOperation `json:"operation"`
	}
	if status != 200 || json.Unmarshal(raw, &saved) != nil || saved.Operation.ActorID != a.ID || saved.Operation.TargetID != result.User.ID {
		t.Fatal("production Console.Handler failed to route identity receipt", status)
	}
	viewer := newConsoleHTTPBrowser(t, server)
	viewer.login(t, result.User.Email)
	status, raw = viewer.request(t, "GET", "/console/v1/identity-operations/"+key, "", consoleHTTPOptions{})
	if status != 403 || consoleHTTPError(t, raw) != "FORBIDDEN" {
		t.Fatal("receipt route bypassed current users.manage", status)
	}
}

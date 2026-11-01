package control

import (
	"aster/cloud/internal/identity"
	"aster/cloud/internal/nodeproto"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMySQLTrafficConsolePermissionsAndExactByteLimits(t *testing.T) {
	s := consoleHTTPStore(t)
	cfg, p, i, now := readyConsoleInstance(t, s)
	caps := testCapabilities(p, now)
	caps.NetworkProfiles = append(caps.NetworkProfiles, nodeproto.TrafficCapability, nodeproto.TrafficThrottleCapability)
	if _, e := s.DB.Exec("UPDATE controller_nodes SET capabilities=? WHERE id=?", mustJSON(caps), p.ID); e != nil {
		t.Fatal(e)
	}
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	defer server.Close()
	auth, e := identity.New(s.DB, identity.Config{Origin: server.URL})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = auth.Bootstrap(context.Background(), "traffic-admin@example.invalid", "Traffic admin", []byte(consoleHTTPPassword)); e != nil {
		t.Fatal(e)
	}
	mux.Handle("/", (Console{Store: s, Config: cfg, Identity: auth}).Handler())
	admin := newConsoleHTTPBrowser(t, server)
	admin.login(t, "traffic-admin@example.invalid")
	admin.createUser(t, "traffic-viewer@example.invalid", "viewer", nil)
	viewer := newConsoleHTTPBrowser(t, server)
	viewer.login(t, "traffic-viewer@example.invalid")
	path := "/console/v1/instances/" + i.ID + "/traffic"
	body := `{"reset_day":1,"direction":"both","limit_bytes":"9007199254740993","overage_policy":"throttle:8"}`
	if status, _ := viewer.request(t, "POST", path, body, consoleHTTPOptions{}); status != 403 {
		t.Fatal("viewer changed traffic policy", status)
	}
	status, raw := admin.request(t, "POST", path, body, consoleHTTPOptions{})
	if status != 200 {
		t.Fatal(status, string(raw))
	}
	var result struct {
		Policy consoleTrafficPolicy `json:"policy"`
	}
	if json.Unmarshal(raw, &result) != nil || result.Policy.LimitBytes == nil || *result.Policy.LimitBytes != "9007199254740993" {
		t.Fatal("byte precision lost", string(raw))
	}
	var before, after int
	s.DB.QueryRow("SELECT COUNT(*) FROM controller_audit").Scan(&before)
	if status, _ := viewer.request(t, "GET", path, "", consoleHTTPOptions{}); status != 200 {
		t.Fatal(status)
	}
	s.DB.QueryRow("SELECT COUNT(*) FROM controller_audit").Scan(&after)
	if before != after {
		t.Fatal("read appended audit")
	}
	var operations int
	if e = s.DB.QueryRow("SELECT COUNT(*) FROM controller_operations WHERE action=?", nodeproto.TrafficControlAction).Scan(&operations); e != nil || operations != 0 {
		t.Fatal("HTTP read/write dispatched an enforcement", operations, e)
	}
	if status, _ := admin.request(t, "POST", path, `{"reset_day":1,"direction":"both","limit_bytes":"18446744073709551616","overage_policy":"none"}`, consoleHTTPOptions{}); status != 400 {
		t.Fatal("overflow accepted", status)
	}
}

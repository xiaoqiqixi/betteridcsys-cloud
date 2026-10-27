package control

import (
	"aster/cloud/internal/identity"
	"aster/cloud/internal/networking"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMySQLNetworkConsoleWiringRequiresReadAndManageWithoutNodeWrites(t *testing.T) {
	s := consoleHTTPStore(t)
	cfg, node, instance, _ := readyConsoleInstance(t, s)
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	ident, err := identity.New(s.DB, identity.Config{Origin: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ident.Bootstrap(context.Background(), "network-admin@example.invalid", "Network fixture", []byte(consoleHTTPPassword)); err != nil {
		t.Fatal(err)
	}
	rpc := &consoleRPC{}
	worker := &OperationWorker{Store: s, Config: cfg, RPC: func(context.Context, NodeProfile) (NodeRPC, error) { return rpc, nil }}
	mux.Handle("/", (Console{Store: s, Config: cfg, Identity: ident, Worker: worker}).Handler())
	admin := newConsoleHTTPBrowser(t, server)
	admin.login(t, "network-admin@example.invalid")
	admin.createUser(t, "network-read@example.invalid", "custom", []string{"nodes.read"})
	admin.createUser(t, "network-manage@example.invalid", "custom", []string{"nodes.manage"})
	admin.createUser(t, "network-both@example.invalid", "custom", []string{"nodes.read", "nodes.manage"})
	read, manage, both := newConsoleHTTPBrowser(t, server), newConsoleHTTPBrowser(t, server), newConsoleHTTPBrowser(t, server)
	read.login(t, "network-read@example.invalid")
	manage.login(t, "network-manage@example.invalid")
	both.login(t, "network-both@example.invalid")
	path := "/console/v1/networks/vpcs"
	input := networking.CreateVPCInput{OwnerRef: instance.OwnerRef, NodeID: node.ID, Name: "隔离验收网络", CIDR: "10.25.0.0/24", VLANID: 11}
	body := consoleHTTPJSON(t, input)
	key := id()
	for _, b := range []*consoleHTTPBrowser{read, manage} {
		if status, _ := b.request(t, "POST", path, body, consoleHTTPOptions{idempotency: key}); status != 403 {
			t.Fatal("network write did not require both explicit grants", status)
		}
	}
	if status, _ := manage.request(t, "GET", path, "", consoleHTTPOptions{}); status != 403 {
		t.Fatal("manage implicitly acquired read", status)
	}
	if status, _ := read.request(t, "GET", path, "", consoleHTTPOptions{}); status != 200 {
		t.Fatal("read-only network list denied", status)
	}
	status, raw := both.request(t, "POST", path, body, consoleHTTPOptions{idempotency: key})
	var saved struct {
		VPC    networking.VPC `json:"vpc"`
		Replay bool           `json:"replay"`
	}
	if status != 201 || json.Unmarshal(raw, &saved) != nil || saved.VPC.ID != key || saved.VPC.State != "planned" || saved.Replay {
		t.Fatal("network intent not persisted as planned", status)
	}
	status, raw = both.request(t, "POST", path, body, consoleHTTPOptions{idempotency: key})
	if status != 200 || json.Unmarshal(raw, &saved) != nil || !saved.Replay {
		t.Fatal("canonical network replay changed intent", status)
	}
	if status, _ = admin.request(t, "POST", path, body, consoleHTTPOptions{idempotency: key}); status != 409 {
		t.Fatal("another actor adopted original network intent", status)
	}
	for _, suffix := range []string{"", "/" + key} {
		if status, _ = read.request(t, "GET", path+suffix, "", consoleHTTPOptions{}); status != 200 {
			t.Fatal("confirmed intent cannot be read without resending", status)
		}
	}
	if status, _ = both.request(t, "POST", path, body, consoleHTTPOptions{}); status != 400 {
		t.Fatal("network creation lacked stable intent ID", status)
	}
	if status, _ = both.request(t, "POST", path, body, consoleHTTPOptions{idempotency: id(), csrf: ptr("")}); status != 403 {
		t.Fatal("network route bypassed real session CSRF", status)
	}
	var count int
	if err = s.DB.QueryRow("SELECT COUNT(*) FROM controller_network_vpcs").Scan(&count); err != nil || count != 1 {
		t.Fatal("replay/unauthorized requests created duplicate networks", err, count)
	}
	if rpc.posts.Load() != 0 || rpc.gets.Load() != 0 {
		t.Fatal("network metadata write executed a node/VM operation")
	}
}

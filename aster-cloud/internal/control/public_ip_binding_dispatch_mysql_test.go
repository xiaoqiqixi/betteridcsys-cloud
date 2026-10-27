package control

import (
	"aster/cloud/internal/identity"
	"aster/cloud/internal/nodeproto"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

type publicBindingDispatchRPC struct {
	inner *publicVMRPC
	gets  atomic.Int32
}

func (r *publicBindingDispatchRPC) Send(ctx context.Context, raw []byte, sha string) (nodeproto.NodeResult, error) {
	return r.inner.Send(ctx, raw, sha)
}
func (r *publicBindingDispatchRPC) Lookup(ctx context.Context, op, sha string) (nodeproto.NodeResult, error) {
	r.gets.Add(1)
	return r.inner.Lookup(ctx, op, sha)
}
func (r *publicBindingDispatchRPC) Capabilities(ctx context.Context) (Capability, error) {
	return r.inner.Capabilities(ctx)
}

// The network mutation has already been frozen by the resource CAS transaction.
// Dispatch/reconciliation must use the same grants as planning, before audit/RPC.
func TestMySQLPublicVMBindingDispatchRequiresCompleteGrantsAndExactOriginalReconcile(t *testing.T) {
	f := mysqlPublicVMFixture(t)
	ctx := context.Background()
	// Adopt a genuinely existing controller instance; do not create a synthetic
	// binding task by inserting around resource ownership or version checks.
	legacy := f.config
	legacy.DirectPublicProfiles = nil
	created, _, e := f.store.CreateInstance(ctx, legacy, f.actor, id(), CreateInstanceInput{Hostname: "legacy-binding-console", OwnerRef: f.owner, PresetID: "direct-preset"}, f.now)
	if e != nil {
		t.Fatal(e)
	}
	oldWorker := f.worker()
	oldWorker.Config = legacy
	if _, e = oldWorker.Dispatch(ctx, created.ID); e != nil {
		t.Fatal(e)
	}
	stop, _, e := f.store.CreateOperation(ctx, legacy, f.actor, created.InstanceID, id(), OperationInput{Action: "shutdown"}, f.now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = oldWorker.Dispatch(ctx, stop.ID); e != nil {
		t.Fatal(e)
	}
	rpc := &publicBindingDispatchRPC{inner: f.rpc}
	worker := f.worker()
	worker.RPC = func(context.Context, NodeProfile) (NodeRPC, error) { return rpc, nil }
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	ident, e := identity.New(f.store.DB, identity.Config{Origin: server.URL})
	if e != nil {
		t.Fatal(e)
	}
	const adminMail = "binding-dispatch-admin@example.invalid"
	if _, e = ident.Bootstrap(ctx, adminMail, "binding dispatch", []byte(consoleHTTPPassword)); e != nil {
		t.Fatal(e)
	}
	mux.Handle("/", (Console{Store: f.store, Config: f.config, Identity: ident, Worker: &worker}).Handler())
	admin := newConsoleHTTPBrowser(t, server)
	admin.login(t, adminMail)
	type permissionCase struct {
		name        string
		permissions []string
		browser     *consoleHTTPBrowser
	}
	cases := []permissionCase{
		{name: "instances_only", permissions: []string{"instances.read", "instances.manage"}},
		{name: "no_node_read", permissions: []string{"instances.read", "instances.manage", "nodes.manage"}},
		{name: "no_node_manage", permissions: []string{"instances.read", "instances.manage", "nodes.read"}},
		{name: "no_instance_manage", permissions: []string{"instances.read", "nodes.read", "nodes.manage"}},
		{name: "complete", permissions: []string{"instances.read", "instances.manage", "nodes.read", "nodes.manage"}},
	}
	for i := range cases {
		email := "binding-" + cases[i].name + "@example.invalid"
		admin.createUser(t, email, "custom", cases[i].permissions)
		cases[i].browser = newConsoleHTTPBrowser(t, server)
		cases[i].browser.login(t, email)
	}
	complete := cases[len(cases)-1].browser
	auditCount := func(target string) int {
		t.Helper()
		var n int
		if e := f.store.DB.QueryRow("SELECT COUNT(*) FROM controller_audit WHERE target=?", target).Scan(&n); e != nil {
			t.Fatal(e)
		}
		return n
	}
	postCount := func(op string) int { f.rpc.mu.Lock(); defer f.rpc.mu.Unlock(); return f.rpc.posts[op] }
	getOperation := func(op string) Operation {
		t.Helper()
		status, raw := admin.request(t, "GET", "/console/v1/operations/"+op, "", consoleHTTPOptions{})
		var result struct {
			Operation Operation `json:"operation"`
		}
		if status != 200 || json.Unmarshal(raw, &result) != nil || result.Operation.ID != op {
			t.Fatal("read original binding operation", status)
		}
		return result.Operation
	}
	// Recognizing an action for execution does not turn the generic operation API
	// into a second, unversioned binding planner, even for a complete administrator.
	for _, action := range []string{"public_adopt", "public_detach"} {
		key := id()
		input := OperationInput{Action: action, Confirmation: created.InstanceID}
		status, _ := admin.request(t, "POST", "/console/v1/instances/"+created.InstanceID+"/operations", consoleHTTPJSON(t, input), consoleHTTPOptions{idempotency: key})
		if status != 400 {
			t.Fatal("generic action bypassed resource CAS", action, status)
		}
		for _, q := range []string{"SELECT COUNT(*) FROM controller_operations WHERE id=?", "SELECT COUNT(*) FROM controller_public_ip_bindings WHERE id=?"} {
			var n int
			if e := f.store.DB.QueryRow(q, key).Scan(&n); e != nil || n != 0 {
				t.Fatal("raw action left an intent", action, n, e)
			}
		}
		if auditCount(key) != 0 || postCount(key) != 0 {
			t.Fatal("raw action caused side effects", action)
		}
	}
	for _, action := range []string{"public_adopt", "public_detach"} {
		unbind := action == "public_detach"
		instance := ""
		generation := uint64(1)
		if !unbind {
			instance = created.InstanceID
			generation = 0
		}
		resource, op, _, e := f.store.BindPublicIPResource(ctx, f.config, f.actor, id(), f.resource.ID, instance, unbind, generation, f.now)
		if e != nil || resource.BindingState != "pending" {
			t.Fatal("resource CAS did not plan binding", action, e)
		}
		original := mustOperation(t, f.store, op.ID)
		if original.Action != action || original.Protocol != nodeproto.DirectPublicProtocol {
			t.Fatal("wrong frozen task", original)
		}
		baseline := auditCount(op.ID)
		for _, tc := range cases[:len(cases)-1] {
			for _, step := range []string{"dispatch", "reconcile"} {
				status, _ := tc.browser.request(t, "POST", "/console/v1/operations/"+op.ID+"/"+step, `{}`, consoleHTTPOptions{idempotency: op.ID})
				if status != 403 {
					t.Fatal("incomplete grants reached binding executor", action, tc.name, step, status)
				}
			}
		}
		if auditCount(op.ID) != baseline || postCount(op.ID) != 0 || getOperation(op.ID).State != "accepted" {
			t.Fatal("forbidden action changed audit/state/node", action)
		}
		executor := admin
		f.rpc.mu.Lock()
		f.rpc.drop = action == "public_adopt"
		f.rpc.mu.Unlock()
		if action == "public_adopt" {
			executor = complete
		}
		status, raw := executor.request(t, "POST", "/console/v1/operations/"+op.ID+"/dispatch", `{}`, consoleHTTPOptions{idempotency: op.ID})
		var response struct {
			Operation Operation `json:"operation"`
		}
		if status != 202 || json.Unmarshal(raw, &response) != nil || response.Operation.ID != op.ID || postCount(op.ID) != 1 {
			t.Fatal("complete grants cannot explicitly dispatch original binding task", action, status, string(raw))
		}
		if action == "public_adopt" {
			if response.Operation.State != "uncertain" {
				t.Fatal("lost ACK became success", response.Operation.State)
			}
			beforeGets := rpc.gets.Load()
			status, raw = complete.request(t, "POST", "/console/v1/operations/"+op.ID+"/reconcile", `{}`, consoleHTTPOptions{idempotency: op.ID})
			if status != 202 || json.Unmarshal(raw, &response) != nil || response.Operation.State != "succeeded" || rpc.gets.Load() != beforeGets+1 || postCount(op.ID) != 1 {
				t.Fatal("original lookup resent node action or failed exact proof", status, string(raw))
			}
		} else if response.Operation.State != "succeeded" {
			t.Fatal("admin detach not confirmed", response.Operation.State)
		}
		saved := getOperation(op.ID)
		if saved.State != "succeeded" || saved.ActorID != original.ActorID || saved.ID != original.ID || postCount(op.ID) != 1 {
			t.Fatal("binding completion changed immutable creator/identity", saved)
		}
		if status, _ = executor.request(t, "POST", "/console/v1/operations/"+op.ID+"/dispatch", `{}`, consoleHTTPOptions{idempotency: op.ID}); status != 409 || postCount(op.ID) != 1 {
			t.Fatal("completed binding dispatch sent twice", status)
		}
		current, e := f.store.PublicIPResource(ctx, f.config, f.resource.ID)
		if e != nil {
			t.Fatal(e)
		}
		if unbind {
			if current.BindingState != "unbound" || !current.Releasable {
				t.Fatal("exact detach not reflected", current)
			}
		} else if current.BindingState != "bound" || current.Releasable {
			t.Fatal("exact adopt not reflected", current)
		}
	}
}

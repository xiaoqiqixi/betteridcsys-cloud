package control

import (
	"aster/cloud/internal/identity"
	"aster/cloud/internal/nodeproto"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
)

type metricsReaderFunc func(context.Context, string) (nodeproto.InstanceMetrics, error)

func (f metricsReaderFunc) Metrics(ctx context.Context, id string) (nodeproto.InstanceMetrics, error) {
	return f(ctx, id)
}

// This uses real HTTPS login/Secure cookies, isolated MySQL and pinned mutual TLS
// to a synthetic node. It proves permission/binding/read-only boundaries, not
// virsh counter accuracy or real KVM execution.
func TestMySQLMetricsRealSessionsReadOnlyAndBoundNode(t *testing.T) {
	s := consoleHTTPStore(t)
	cfg, profile, instance, _ := readyConsoleInstance(t, s)
	f := newObservationFixture(t, "/metrics")
	f.value.NodeID, f.value.InstanceID = profile.ID, instance.ID
	f.value.OwnerRef, f.value.Hostname = instance.OwnerRef, instance.Hostname
	approved := f.client.profile
	approved.ID, approved.DatacenterID, approved.GroupID = profile.ID, profile.DatacenterID, profile.GroupID
	f.client.profile = approved
	cfg.Nodes = []NodeProfile{approved}
	value := metricFixtureValue(f)
	value.VCPUs = instance.Resources.CPUCores
	raw, _ := json.Marshal(value)
	f.reply(200, raw)

	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	auth, err := identity.New(s.DB, identity.Config{Origin: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = auth.Bootstrap(context.Background(), "metrics-admin@example.invalid", "Metrics test admin", []byte(consoleHTTPPassword)); err != nil {
		t.Fatal(err)
	}
	var rpcFactories atomic.Int32
	var changeBinding atomic.Bool
	console := Console{Store: s, Config: cfg, Identity: auth, MetricsRPC: func(_ context.Context, p NodeProfile) (MetricsReader, error) {
		rpcFactories.Add(1)
		if !reflect.DeepEqual(p, approved) {
			t.Fatal("metrics factory received an unapproved destination")
		}
		return metricsReaderFunc(func(ctx context.Context, id string) (nodeproto.InstanceMetrics, error) {
			v, e := f.client.Metrics(ctx, id)
			if e == nil && changeBinding.Load() {
				_, e = s.DB.ExecContext(ctx, "UPDATE controller_instances SET node_id='changed-test-node' WHERE id=?", instance.ID)
			}
			return v, e
		}), nil
	}}
	mux.Handle("/", console.Handler())
	admin := newConsoleHTTPBrowser(t, server)
	admin.login(t, "metrics-admin@example.invalid")
	admin.createUser(t, "metrics-viewer@example.invalid", "viewer", nil)
	limitedUser := admin.createUser(t, "metrics-limited@example.invalid", "custom", []string{"nodes.read"})
	viewer, limited := newConsoleHTTPBrowser(t, server), newConsoleHTTPBrowser(t, server)
	viewer.login(t, "metrics-viewer@example.invalid")
	limited.login(t, limitedUser.Email)
	path := "/console/v1/instances/" + instance.ID + "/metrics"

	tables := map[string]string{"controller_schema": "version", "controller_lock": "id", "controller_identity_lock": "id", "controller_nodes": "id", "controller_instances": "id", "controller_jobs": "operation_id", "controller_reservations": "operation_id", "controller_operations": "id", "controller_artifacts": "id", "controller_migrations": "id", "controller_audit": "id", "controller_identity_audit": "id", "controller_console_users": "id", "controller_console_sessions": "token_hash", "controller_console_login_limits": "bucket"}
	before := auditDataDigest(t, s, tables)
	for _, b := range []*consoleHTTPBrowser{admin, viewer} {
		status, body := b.request(t, "GET", path, "", consoleHTTPOptions{})
		var result struct {
			Metrics nodeproto.InstanceMetrics `json:"metrics"`
		}
		if status != 200 || !strict(body, &result) || !reflect.DeepEqual(result.Metrics, value) {
			t.Fatal("real session metrics read rejected or changed data", status)
		}
		consoleHTTPPrivateCheck(t, body, b, cfg)
	}
	if f.verifiedPeers.Load() != 2 || f.requests.Load() != 2 {
		t.Fatal("metrics did not use two independent authenticated node GETs")
	}
	for _, tc := range []struct {
		browser            *consoleHTTPBrowser
		method, path, body string
		status             int
	}{
		{newConsoleHTTPBrowser(t, server), "GET", path, "", 401},
		{limited, "GET", path, "", 403},
		{viewer, "GET", path + "?ignored=true", "", 400},
		{viewer, "GET", path + "?cursor=a&cursor=b", "", 400},
		{viewer, "GET", "/console/v1/instances/invalid/metrics", "", 404},
		{viewer, "GET", "/console/v1/instances/" + id() + "/metrics", "", 404},
		{viewer, "POST", path, "{}", 404},
		{viewer, "DELETE", path, "", 405},
	} {
		calls := rpcFactories.Load()
		status, _ := tc.browser.request(t, tc.method, tc.path, tc.body, consoleHTTPOptions{})
		if status != tc.status || rpcFactories.Load() != calls {
			t.Fatal("invalid/unauthorized request sampled a node", tc.method, tc.path, status)
		}
	}
	for _, mutate := range []func(*nodeproto.InstanceMetrics){
		func(v *nodeproto.InstanceMetrics) { v.OwnerRef = id() },
		func(v *nodeproto.InstanceMetrics) { v.Hostname = "another-instance" },
		func(v *nodeproto.InstanceMetrics) { v.VCPUs++ },
	} {
		bad := value
		mutate(&bad)
		body, _ := json.Marshal(bad)
		f.reply(200, body)
		status, response := viewer.request(t, "GET", path, "", consoleHTTPOptions{})
		if status != 503 || consoleHTTPError(t, response) != "DEPENDENCY_UNAVAILABLE" {
			t.Fatal("valid-shaped sample crossed owner/host/vCPU binding", status)
		}
	}
	f.reply(409, []byte(`{"error":{"code":"LIVE_INSTANCE_METRICS_UNCONFIRMED"}}`))
	status, body := viewer.request(t, "GET", path, "", consoleHTTPOptions{})
	if status != 409 || consoleHTTPError(t, body) != "STATE_CONFLICT" {
		t.Fatal("busy node response disguised as sample", status)
	}
	if after := auditDataDigest(t, s, tables); !reflect.DeepEqual(before, after) {
		t.Fatal("monitoring changed identity/resource/task/audit tables")
	}

	f.reply(200, raw)
	changeBinding.Store(true)
	status, body = viewer.request(t, "GET", path, "", consoleHTTPOptions{})
	if status != 409 || consoleHTTPError(t, body) != "STATE_CONFLICT" {
		t.Fatal("in-flight node change returned a sample from old placement", status)
	}
	changeBinding.Store(false)
	if _, err = s.DB.Exec("UPDATE controller_instances SET node_id=? WHERE id=?", instance.NodeID, instance.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec("UPDATE controller_console_users SET enabled=FALSE WHERE id=?", viewer.user.ID); err != nil {
		t.Fatal(err)
	}
	calls := rpcFactories.Load()
	status, _ = viewer.request(t, "GET", path, "", consoleHTTPOptions{})
	if status != 401 || rpcFactories.Load() != calls {
		t.Fatal("revoked session still sampled node", status)
	}
}

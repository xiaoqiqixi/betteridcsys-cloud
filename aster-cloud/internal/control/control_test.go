package control

import (
	"aster/billing/controllerapi"
	"aster/cloud/internal/nodeproto"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testProfile() NodeProfile {
	return NodeProfile{ID: "node-a", DatacenterID: "dc-a", GroupID: "", Endpoint: "https://node.invalid:9444", AllowedCIDRs: []string{"192.0.2.0/24"}, CAFile: "/etc/aster/node-ca.crt", ClientCertFile: "/etc/aster/client.crt", ClientKeyFile: "/etc/aster/client.key", ServerCertificateSHA256: strings.Repeat("a", 64)}
}
func testResources(p NodeProfile) controllerapi.Resources {
	return controllerapi.Resources{DatacenterID: p.DatacenterID, ComputeNodeID: p.ID, NodeGroupID: p.GroupID, ImageID: "ubuntu22", CPUCores: 2, MemoryMiB: 512, SystemDiskGiB: 5, SystemStorageID: "fast", NetworkType: "normal", TrafficDirection: "all", IPv4Count: 1}
}
func testRequest(p NodeProfile) controllerapi.Request {
	spec := controllerapi.ProductSpec{Mode: "custom", ControllerID: "main", Resources: ptr(testResources(p))}
	h, _ := spec.Digest()
	return controllerapi.Request{Protocol: controllerapi.Protocol, OperationID: id(), OrderID: id(), OwnerRef: id(), Hostname: "test-vm", ConfigurationRevision: 1, ConfigurationSHA256: h, Product: spec}
}
func ptr[T any](v T) *T { return &v }
func testConfig(p NodeProfile) Config {
	return Config{Schema: 1, ControllerID: "main", Listen: "127.0.0.1:9443", TLSCertFile: "/etc/aster/server.crt", TLSKeyFile: "/etc/aster/server.key", DSNFile: "/etc/aster/mysql-dsn", BillingTokenFile: "/etc/aster/billing.token", AdminReadTokenFile: "/etc/aster/read.token", AdminWriteTokenFile: "/etc/aster/write.token", HeartbeatTTLSeconds: 60, Nodes: []NodeProfile{p}, Presets: []Preset{}}
}
func testCapabilities(p NodeProfile, now time.Time) Capability {
	return Capability(nodeproto.Capabilities{Protocol: nodeproto.Protocol, NodeID: p.ID, Hypervisor: "libvirt-kvm", ObservedAt: now.Format(time.RFC3339Nano), Actions: []string{"create", "start", "shutdown", "reboot", "force_off", "delete"}, ImageIDs: []string{"ubuntu22"}, StorageIDs: []string{"fast"}, NetworkProfiles: []string{"normal-static-ipv4-dedicated-bridge"}, IPv4Counts: []int{1}, IPv6Counts: []int{0}, BandwidthMbps: []int{0}, TransferGiB: []int{0}, Limitations: []string{}, Capacity: nodeproto.Capacity{CPUCoresTotal: 8, MemoryTotalMiB: 8192, MemoryAvailableMiB: 8192, StorageTotalGiB: 100, StorageAvailableGiB: 100}})
}
func TestStrictWireRequest(t *testing.T) {
	r := testRequest(testProfile())
	raw, _, _ := r.BytesAndDigest()
	var out controllerapi.Request
	if !strict(raw, &out) || !out.Valid() {
		t.Fatal("valid request rejected")
	}
	tests := map[string]string{
		"unknown":           strings.Replace(string(raw), `"protocol":`, `"extra":1,"protocol":`, 1),
		"duplicate":         strings.Replace(string(raw), `"protocol":`, `"protocol":"aster.controller/1","protocol":`, 1),
		"wrong_case":        strings.Replace(string(raw), `"operation_id":`, `"Operation_ID":`, 1),
		"null":              strings.Replace(string(raw), `"hostname":"test-vm"`, `"hostname":null`, 1),
		"missing":           strings.Replace(string(raw), `"hostname":"test-vm",`, ``, 1),
		"trailing":          string(raw) + ` {}`,
		"nested_unknown":    strings.Replace(string(raw), `"cpu_cores":`, `"unapproved":1,"cpu_cores":`, 1),
		"nested_wrong_case": strings.Replace(string(raw), `"cpu_cores":`, `"CPU_CORES":`, 1),
	}
	for name, v := range tests {
		t.Run(name, func(t *testing.T) {
			var x controllerapi.Request
			if strict([]byte(v), &x) {
				t.Fatal("ambiguous wire accepted")
			}
		})
	}
}
func TestCapabilitiesRejectEveryUnsupportedResource(t *testing.T) {
	p := testProfile()
	c := testCapabilities(p, time.Now())
	r := testResources(p)
	if !c.Supports(r, p) {
		t.Fatal("baseline unsupported")
	}
	tests := map[string]func(*controllerapi.Resources){"cpu_zero": func(r *controllerapi.Resources) { r.CPUCores = 0 }, "image": func(r *controllerapi.Resources) { r.ImageID = "other" }, "storage": func(r *controllerapi.Resources) { r.SystemStorageID = "other" }, "node": func(r *controllerapi.Resources) { r.ComputeNodeID = "node-b" }, "datacenter": func(r *controllerapi.Resources) { r.DatacenterID = "dc-b" }, "group": func(r *controllerapi.Resources) { r.NodeGroupID = "group-b" }, "data_disk": func(r *controllerapi.Resources) { r.DataDiskGiB = 1 }, "data_storage": func(r *controllerapi.Resources) { r.DataStorageID = "fast" }, "vpc": func(r *controllerapi.Resources) { r.NetworkType = "vpc" }, "bandwidth": func(r *controllerapi.Resources) { r.BandwidthMbps = 1 }, "inbound": func(r *controllerapi.Resources) { r.InboundBandwidthMbps = 1 }, "transfer": func(r *controllerapi.Resources) { r.TransferGiB = 1 }, "direction": func(r *controllerapi.Resources) { r.TrafficDirection = "in" }, "ipv4": func(r *controllerapi.Resources) { r.IPv4Count = 2 }, "ipv6": func(r *controllerapi.Resources) { r.IPv6Count = 1 }}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			v := r
			change(&v)
			if c.Supports(v, p) {
				t.Fatal("silently ignored resource")
			}
		})
	}
	c.Maintenance = true
	if c.Supports(r, p) {
		t.Fatal("maintenance ignored")
	}
}
func TestConfigBoundaries(t *testing.T) {
	base := testConfig(testProfile())
	if !base.Valid() {
		t.Fatal("baseline invalid")
	}
	for _, endpoint := range []string{"http://node.invalid", "https://user@node.invalid", "https://node.invalid/", "https://node.invalid/path", "https://node.invalid?x=1", "https://NODE.invalid", "https://node.invalid#x"} {
		t.Run(endpoint, func(t *testing.T) {
			c := base
			c.Nodes = append([]NodeProfile{}, base.Nodes...)
			c.Nodes[0].Endpoint = endpoint
			if c.Valid() {
				t.Fatal("unsafe endpoint accepted")
			}
		})
	}
	for _, cidr := range []string{"0.0.0.0/0", "192.0.2.1/24", "::/0", "::ffff:192.0.2.0/120"} {
		p := testProfile()
		p.AllowedCIDRs = []string{cidr}
		if p.Valid() {
			t.Fatal("unsafe CIDR accepted", cidr)
		}
	}
	r := testRequest(base.Nodes[0])
	if len(base.Candidates(r)) != 1 {
		t.Fatal("custom rejected")
	}
	r.Product.Resources.ComputeNodeID = ""
	if len(base.Candidates(r)) != 0 {
		t.Fatal("implicit custom node mapping")
	}
}
func TestProtectedFileNoLinksOrSharedSecrets(t *testing.T) {
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(dir, "token")
	os.WriteFile(file, []byte("synthetic-private-data"), 0600)
	owner := uint32(os.Geteuid())
	if _, e := readProtected(file, true, 100, owner); e != nil {
		t.Fatal(e)
	}
	os.Chmod(file, 0644)
	if _, e := readProtected(file, true, 100, owner); e == nil {
		t.Fatal("shared secret read")
	}
	os.Chmod(file, 0600)
	link := filepath.Join(dir, "link")
	os.Symlink(file, link)
	if _, e := readProtected(link, true, 100, owner); e == nil {
		t.Fatal("symlink read")
	}
	hard := filepath.Join(dir, "hard")
	os.Link(file, hard)
	if _, e := readProtected(file, true, 100, owner); e == nil {
		t.Fatal("hardlink read")
	}
}

type fakeStore struct {
	mu             sync.Mutex
	job            Job
	admissions     int
	claims         int
	completionFail bool
	node           NodeView
}

func (s *fakeStore) Ping(context.Context) error { return nil }
func (s *fakeStore) Admit(_ context.Context, r controllerapi.Request, _ []Candidate, now time.Time, _ time.Duration) (Job, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, h, _ := r.BytesAndDigest()
	if s.job.OperationID != "" {
		if s.job.OperationID != r.OperationID || s.job.RequestSHA != h {
			return Job{}, false, ErrConflict
		}
		return s.job, true, nil
	}
	s.admissions++
	s.job = Job{OperationID: r.OperationID, OrderID: r.OrderID, ControllerID: r.Product.ControllerID, RequestJSON: raw, RequestSHA: h, State: "accepted", CreatedAt: now}
	return s.job, false, nil
}
func (s *fakeStore) Lookup(_ context.Context, op string) (Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if op != s.job.OperationID {
		return Job{}, ErrNotFound
	}
	return s.job, nil
}
func (s *fakeStore) Claim(_ context.Context, op, profile string, _ time.Time, _ time.Duration) (Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if op != s.job.OperationID || profile != s.job.NodeProfileSHA || s.job.State != "accepted" {
		return Job{}, ErrState
	}
	s.job.State = "sending"
	s.claims++
	return s.job, nil
}
func (s *fakeStore) Complete(_ context.Context, op, status string, _ time.Time) (Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.completionFail {
		return Job{}, ErrUnavailable
	}
	s.job.State = status
	if status == "accepted" {
		s.job.State = "dispatched"
	}
	return s.job, nil
}
func (s *fakeStore) Nodes(context.Context) ([]NodeView, error)     { return []NodeView{s.node}, nil }
func (s *fakeStore) Instances(context.Context) ([]Instance, error) { return []Instance{}, nil }
func (s *fakeStore) Jobs(context.Context) ([]Job, error)           { return []Job{s.job}, nil }
func (s *fakeStore) Audits(context.Context) ([]Audit, error)       { return []Audit{}, nil }
func requestHTTP(app App, method, path, token string, raw []byte, headers map[string]string, tlsOn bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://controller.invalid"+path, bytes.NewReader(raw))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	if tlsOn {
		r.TLS = &tls.ConnectionState{}
	} else {
		r.TLS = nil
	}
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, r)
	return w
}
func TestHTTPAuthAndExactResultBinding(t *testing.T) {
	p := testProfile()
	s := &fakeStore{}
	secrets := Secrets{strings.Repeat("b", 64), strings.Repeat("r", 64), strings.Repeat("w", 64)}
	app := App{Store: s, Config: testConfig(p), Secrets: secrets}
	r := testRequest(p)
	raw, h, _ := r.BytesAndDigest()
	headers := map[string]string{"Idempotency-Key": r.OperationID, "X-Aster-Request-SHA256": h}
	for _, test := range []struct {
		name, token, path, method string
		tls                       bool
		want                      int
	}{
		{"no_tls", secrets.Billing, "/v1/provisioning", "POST", false, 426}, {"missing_token", "", "/v1/provisioning", "POST", true, 401}, {"read_cannot_submit", secrets.AdminRead, "/v1/provisioning", "POST", true, 403}, {"write_not_billing", secrets.AdminWrite, "/v1/provisioning", "POST", true, 403}, {"billing_not_admin", secrets.Billing, "/v1/nodes", "GET", true, 403}, {"admin_read", secrets.AdminRead, "/v1/nodes", "GET", true, 200}, {"admin_write_read", secrets.AdminWrite, "/v1/tasks", "GET", true, 200}, {"admin_read_not_write", secrets.AdminRead, "/v1/nodes", "POST", true, 405},
	} {
		t.Run(test.name, func(t *testing.T) {
			w := requestHTTP(app, test.method, test.path, test.token, raw, headers, test.tls)
			if w.Code != test.want {
				t.Fatalf("got %d want %d", w.Code, test.want)
			}
		})
	}
	if s.admissions != 0 {
		t.Fatal("unauthorized admission")
	}
	for i, want := range []int{202, 409} {
		w := requestHTTP(app, "POST", "/v1/provisioning", secrets.Billing, raw, headers, true)
		if w.Code != want {
			t.Fatalf("attempt %d status %d", i, w.Code)
		}
		var fields map[string]any
		json.Unmarshal(w.Body.Bytes(), &fields)
		if len(fields) != 6 {
			t.Fatal("result envelope/keys changed")
		}
		var result controllerapi.Result
		json.Unmarshal(w.Body.Bytes(), &result)
		if !result.Matches(r) {
			t.Fatal("unbound result")
		}
	}
	if s.admissions != 1 {
		t.Fatal("replayed admission duplicated")
	}
	w := requestHTTP(app, "GET", "/v1/provisioning/"+r.OperationID, secrets.Billing, nil, headers, true)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	bad := map[string]string{"Idempotency-Key": r.OperationID, "X-Aster-Request-SHA256": strings.Repeat("0", 64)}
	if requestHTTP(app, "GET", "/v1/provisioning/"+r.OperationID, secrets.Billing, nil, bad, true).Code != 409 {
		t.Fatal("lookup binding bypass")
	}
	if requestHTTP(app, "POST", "/v1/provisioning", secrets.Billing, raw, nil, true).Code != 400 {
		t.Fatal("missing header accepted")
	}
	headers["Origin"] = "https://untrusted.invalid"
	if requestHTTP(app, "POST", "/v1/provisioning", secrets.Billing, raw, headers, true).Code != 403 {
		t.Fatal("browser mutation accepted")
	}
}

type fakeRPC struct {
	mu          sync.Mutex
	sends, gets int
	lost        bool
	result      nodeproto.NodeResult
}

func (f *fakeRPC) Send(_ context.Context, raw []byte, sha string) (nodeproto.NodeResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sends++
	task, e := nodeproto.DecodeTask(raw)
	if e != nil || nodeproto.Digest(raw) != sha {
		return nodeproto.NodeResult{}, ErrInput
	}
	f.result = nodeproto.NodeResult{Protocol: nodeproto.Protocol, OperationID: task.OperationID, RequestSHA256: sha, Status: "succeeded", InstanceID: task.InstanceID}
	if f.lost {
		return nodeproto.NodeResult{}, errors.New("synthetic lost response")
	}
	return f.result, nil
}
func (f *fakeRPC) Lookup(_ context.Context, op, sha string) (nodeproto.NodeResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets++
	if op != f.result.OperationID || sha != f.result.RequestSHA256 {
		return nodeproto.NodeResult{}, ErrNotFound
	}
	return f.result, nil
}
func (f *fakeRPC) Capabilities(context.Context) (Capability, error) {
	return Capability{}, ErrUnavailable
}
func workerFixture() (*fakeStore, *fakeRPC, Worker) {
	p := testProfile()
	r := testRequest(p)
	raw, digest, _ := r.BytesAndDigest()
	task := nodeproto.NodeTask{Protocol: nodeproto.Protocol, OperationID: r.OperationID, NodeID: p.ID, Action: "create", InstanceID: id(), OwnerRef: r.OwnerRef, Hostname: r.Hostname, Resources: *r.Product.Resources}
	nraw, ndigest, _ := task.BytesAndDigest()
	s := &fakeStore{job: Job{OperationID: r.OperationID, OrderID: r.OrderID, ControllerID: "main", RequestSHA: digest, RequestJSON: raw, InstanceID: task.InstanceID, NodeID: p.ID, NodeProfileSHA: p.Digest(), NodeRequest: nraw, NodeRequestSHA: ndigest, State: "accepted"}}
	rpc := &fakeRPC{}
	return s, rpc, Worker{Store: s, Config: testConfig(p), RPC: func(context.Context, NodeProfile) (NodeRPC, error) { return rpc, nil }}
}
func TestWorkerLossNeverRepeatsPOST(t *testing.T) {
	s, rpc, w := workerFixture()
	rpc.lost = true
	op := s.job.OperationID
	j, e := w.Dispatch(context.Background(), op)
	if e == nil || j.State != "uncertain" {
		t.Fatal("loss not preserved")
	}
	if _, e = w.Dispatch(context.Background(), op); !errors.Is(e, ErrState) {
		t.Fatal("uncertain was dispatchable")
	}
	j, e = w.Reconcile(context.Background(), op)
	if e != nil || j.State != "succeeded" || rpc.sends != 1 || rpc.gets != 1 {
		t.Fatal("GET reconcile failed", j.State, rpc.sends, rpc.gets, e)
	}
}
func TestWorkerConcurrentClaimsAndCompletionFailure(t *testing.T) {
	s, rpc, w := workerFixture()
	op := s.job.OperationID
	s.completionFail = true
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = w.Dispatch(context.Background(), op) }()
	}
	wg.Wait()
	if rpc.sends != 1 || s.claims != 1 || s.job.State != "sending" {
		t.Fatal("duplicate POST or lost claim", rpc.sends, s.claims, s.job.State)
	}
	s.completionFail = false
	if _, e := w.Reconcile(context.Background(), op); e != nil {
		t.Fatal(e)
	}
	if rpc.sends != 1 || rpc.gets != 1 {
		t.Fatal("completion failure resent mutation")
	}
}
func TestWorkerRejectsStoredByteTampering(t *testing.T) {
	s, rpc, w := workerFixture()
	s.job.NodeRequest = append(s.job.NodeRequest, ' ')
	if _, e := w.Dispatch(context.Background(), s.job.OperationID); !errors.Is(e, ErrState) {
		t.Fatal("corrupt bytes dispatched")
	}
	if rpc.sends != 0 || s.claims != 0 {
		t.Fatal("mutation before validation")
	}
}

func TestNodeClientCapabilitiesAndNoSilentPOSTRetry(t *testing.T) {
	p := testProfile()
	var posts int
	var mu sync.Mutex
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/capabilities":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(testCapabilities(p, time.Now().UTC()))
		case "/v1/tasks":
			mu.Lock()
			posts++
			mu.Unlock()
			conn, _, e := w.(http.Hijacker).Hijack()
			if e == nil {
				conn.Close()
			}
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	u, _ := url.Parse(server.URL)
	p.Endpoint = server.URL
	client := &NodeClient{profile: p, address: u.Host, tls: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}
	caps, e := client.Capabilities(context.Background())
	if e != nil || !caps.Supports(testResources(p), p) {
		t.Fatal("actual node wire capability shape rejected", e)
	}
	task := nodeproto.NodeTask{Protocol: nodeproto.Protocol, OperationID: id(), NodeID: p.ID, Action: "create", InstanceID: id(), OwnerRef: id(), Hostname: "vm-demo", Resources: testResources(p)}
	raw, digest, _ := task.BytesAndDigest()
	if _, e = client.Send(context.Background(), raw, digest); e == nil {
		t.Fatal("lost response accepted")
	}
	if posts != 1 {
		t.Fatal("silent POST replay", posts)
	}
	caps.NetworkProfiles = []string{"normal-isolated-no-nic"}
	if caps.Supports(testResources(p), p) {
		t.Fatal("isolated NIC treated as paid static IPv4")
	}
}

// Verbatim synthetic fixture supplied by the node-protocol implementation. It is
// a protocol agreement, NOT a real heartbeat or a claim of KVM availability.
//
//go:embed testdata/capabilities-approved-static-ipv4.json
var approvedNodeCapabilities []byte

func TestSharedNodeCapabilitiesFixtureSupportsApprovedNetwork(t *testing.T) {
	var caps Capability
	if !strict(approvedNodeCapabilities, &caps) {
		t.Fatal("node capability fixture has incompatible shape")
	}
	p := testProfile()
	p.GroupID = "group-a"
	r := testResources(p)
	r.SystemStorageID = "local"
	if !caps.Supports(r, p) {
		t.Fatal("approved node profile cannot satisfy exact paid resource shape")
	}
	r.NetworkType = "vpc"
	if caps.Supports(r, p) {
		t.Fatal("VPC implicitly substituted")
	}
}

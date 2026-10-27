package control

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func controllerNetworkTask(p NodeProfile) nodeproto.NodeTask {
	task := nodeproto.NodeTask{Protocol: nodeproto.NetworkProtocol, OperationID: id(), NodeID: p.ID, Action: "create", InstanceID: id(), OwnerRef: id(), Hostname: "private-vm", Resources: vpcTestResources(p)}
	task.Network = nodeproto.NetworkBinding{Schema: 1, ProfileID: "vpc-a-v1", ProfileSHA256: strings.Repeat("b", 64), LeaseID: id(), PoolID: id(), VPCID: id(), NodeID: p.ID, OwnerRef: task.OwnerRef, InstanceID: task.InstanceID, CIDR: "10.25.0.0/24", IPv4: "10.25.0.10", MAC: nodeproto.NetworkMAC(p.ID, task.InstanceID), InterfaceID: nodeproto.NetworkInterfaceID(task.InstanceID), VLANID: 25, InboundMbps: task.Resources.InboundBandwidthMbps, OutboundMbps: task.Resources.BandwidthMbps}
	return task
}

type networkWorkerRPC struct {
	mu            sync.Mutex
	task          nodeproto.NodeTask
	sends, gets   int
	wrongProtocol bool
}

func (c *networkWorkerRPC) Send(_ context.Context, raw []byte, sha string) (nodeproto.NodeResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sends++
	task, e := nodeproto.DecodeTask(raw)
	if e != nil || nodeproto.Digest(raw) != sha || task != c.task {
		return nodeproto.NodeResult{}, ErrInput
	}
	return nodeproto.NodeResult{}, ErrUnavailable
}
func (c *networkWorkerRPC) Lookup(_ context.Context, op, sha string) (nodeproto.NodeResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gets++
	_, want, _ := c.task.BytesAndDigest()
	if op != c.task.OperationID || sha != want {
		return nodeproto.NodeResult{}, ErrInput
	}
	protocol := c.task.Protocol
	if c.wrongProtocol {
		protocol = nodeproto.Protocol
	}
	return nodeproto.NodeResult{Protocol: protocol, OperationID: op, RequestSHA256: sha, InstanceID: c.task.InstanceID, Status: "succeeded"}, nil
}
func (c *networkWorkerRPC) Capabilities(context.Context) (Capability, error) {
	return Capability{}, ErrUnavailable
}
func TestNetworkWorkerKeepsLostPOSTUncertainAndOnlyReconcilesExactNewProtocol(t *testing.T) {
	p := testProfile()
	task := controllerNetworkTask(p)
	raw, sha, e := task.BytesAndDigest()
	if e != nil {
		t.Fatal(e)
	}
	financial := testRequest(p)
	financial.OperationID = task.OperationID
	financial.OwnerRef = task.OwnerRef
	*financial.Product.Resources = task.Resources
	financial.ConfigurationSHA256, _ = financial.Product.Digest()
	financialRaw, financialSHA, _ := financial.BytesAndDigest()
	store := &fakeStore{job: Job{OperationID: task.OperationID, OrderID: financial.OrderID, ControllerID: financial.Product.ControllerID, RequestSHA: financialSHA, RequestJSON: financialRaw, InstanceID: task.InstanceID, NodeID: p.ID, NodeProfileSHA: p.Digest(), NodeRequestSHA: sha, NodeRequest: raw, State: "accepted"}}
	rpc := &networkWorkerRPC{task: task}
	config := vpcTestConfig(p, task.Network.PoolID)
	config.NetworkProfiles[0].OwnerRef = task.OwnerRef
	worker := Worker{Store: store, Config: config, RPC: func(context.Context, NodeProfile) (NodeRPC, error) { return rpc, nil }}
	j, e := worker.Dispatch(context.Background(), task.OperationID)
	if !errors.Is(e, ErrUnavailable) || j.State != "uncertain" || rpc.sends != 1 {
		t.Fatal("lost POST falsely confirmed/replayed", j.State, e, rpc.sends)
	}
	worker.Config.NetworkProfiles = nil // Revocation blocks new writes, never the bound GET.
	if _, e = worker.Dispatch(context.Background(), task.OperationID); !errors.Is(e, ErrState) || rpc.sends != 1 {
		t.Fatal("uncertain POST resent", e, rpc.sends)
	}
	rpc.wrongProtocol = true
	if _, e = worker.Reconcile(context.Background(), task.OperationID); !errors.Is(e, ErrUnavailable) {
		t.Fatal("legacy result confirmed new request", e)
	}
	rpc.wrongProtocol = false
	j, e = worker.Reconcile(context.Background(), task.OperationID)
	if e != nil || j.State != "succeeded" || rpc.sends != 1 || rpc.gets != 2 || !j.Result().Matches(financial) || j.Result().Protocol != financial.Protocol {
		t.Fatal("exact new result changed financial result contract", j, e)
	}
}
func TestNodeClientSendsExactNetworkTaskOnExistingPinnedEndpoint(t *testing.T) {
	p := testProfile()
	task := controllerNetworkTask(p)
	raw, sha, e := task.BytesAndDigest()
	if e != nil {
		t.Fatal(e)
	}
	var posts atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/capabilities" {
			json.NewEncoder(w).Encode(vpcTestCapabilities(p, time.Now().UTC()))
			return
		}
		if r.Method != "POST" || r.URL.Path != "/v1/tasks" {
			w.WriteHeader(404)
			return
		}
		posts.Add(1)
		got, e := io.ReadAll(r.Body)
		if e != nil || string(got) != string(raw) || r.Header.Get("X-Request-SHA256") != sha {
			t.Error("client changed immutable network task")
		}
		json.NewEncoder(w).Encode(nodeproto.NodeResult{Protocol: nodeproto.NetworkProtocol, OperationID: task.OperationID, InstanceID: task.InstanceID, RequestSHA256: sha, Status: "accepted"})
	}))
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	u, _ := url.Parse(server.URL)
	p.Endpoint = server.URL
	client := &NodeClient{profile: p, address: u.Host, tls: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}
	caps, e := client.Capabilities(context.Background())
	if e != nil || !caps.SupportsNetwork(task.Resources, p, task.Network.ProfileID) {
		t.Fatal("new capabilities rejected", e)
	}
	result, e := client.Send(context.Background(), raw, sha)
	if e != nil || !result.Matches(task, sha) || posts.Load() != 1 {
		t.Fatal("new task endpoint/protocol mismatch", result, e, posts.Load())
	}
}

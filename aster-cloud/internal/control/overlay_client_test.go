package control

import (
	"aster/cloud/internal/overlayproto"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestOverlayNodeClientUsesIndependentWireAndDoesNotRetryPOST(t *testing.T) {
	p := testProfile()
	s := overlayproto.Snapshot{Protocol: overlayproto.Protocol, ClusterID: "wire-cluster", Epoch: 1, Profiles: []overlayproto.ProfilePin{{NodeID: p.ID, ProfileID: "private", ProfileSHA256: strings.Repeat("1", 64)}}, VPCs: []overlayproto.VPC{{ID: id(), OwnerRef: id(), CIDR: "10.24.0.0/24", VNI: 10}}, Members: []overlayproto.Member{}, Gateways: []overlayproto.Gateway{}}
	s, sha, e := overlayproto.CanonicalSnapshot(s)
	if e != nil {
		t.Fatal(e)
	}
	task := overlayproto.Task{Protocol: overlayproto.Protocol, OperationID: id(), NodeID: p.ID, Phase: "prepare", Snapshot: s, SnapshotSHA256: sha}
	_, requestSHA, _ := task.BytesAndDigest()
	receipt := overlayproto.Receipt{Protocol: overlayproto.Protocol, OperationID: task.OperationID, NodeID: p.ID, ClusterID: s.ClusterID, Epoch: 1, Phase: "prepare", SnapshotSHA256: sha, RequestSHA256: requestSHA, Status: "succeeded", Code: "PREPARED"}
	var posts, gets atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "POST" && r.URL.Path == "/v1/overlay/tasks":
			posts.Add(1)
			raw, _ := io.ReadAll(r.Body)
			decoded, e := overlayproto.DecodeTask(raw)
			if e != nil || decoded.NodeID != p.ID || overlayproto.Digest(raw) != r.Header.Get("X-Request-SHA256") {
				t.Error("invalid forwarded overlay wire")
			}
			conn, _, e := w.(http.Hijacker).Hijack()
			if e == nil {
				conn.Close()
			}
		case r.Method == "GET" && r.URL.Path == "/v1/overlay/tasks/"+task.OperationID:
			gets.Add(1)
			if r.Header.Get("X-Request-SHA256") != requestSHA {
				t.Error("lookup omitted exact request binding")
			}
			json.NewEncoder(w).Encode(receipt)
		case r.Method == "GET" && r.URL.Path == "/v1/overlay/head":
			if r.URL.Query().Get("profile_id") != "private" {
				t.Error("wrong profile")
			}
			json.NewEncoder(w).Encode(overlayproto.Head{NodeID: p.ID})
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
	if _, e = client.SendOverlay(context.Background(), task); e == nil || posts.Load() != 1 {
		t.Fatal("lost response retried or called success", posts.Load(), e)
	}
	r, e := client.LookupOverlay(context.Background(), task)
	if e != nil || !r.Matches(task, requestSHA) || gets.Load() != 1 || posts.Load() != 1 {
		t.Fatal("read-only receipt reconciliation failed", e)
	}
	h, e := client.OverlayHead(context.Background(), "private")
	if e != nil || h.Epoch != 0 || h.NodeID != p.ID {
		t.Fatal("empty durable head not read", e)
	}
}

package control

import (
	"aster/cloud/internal/nodeproto"
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type transferFixture struct {
	mu                                     sync.Mutex
	relay                                  transferRelay
	manifest                               nodeproto.StorageManifest
	raw, disk                              []byte
	manifestPresent, diskPresent, approved bool
	mode                                   atomic.Value
	puts, posts, sourceGets, targetGets    atomic.Int32
	events                                 []string
	blocked                                chan struct{}
	blockedOnce                            sync.Once
	diskPutStarted                         chan struct{}
	diskPutFinished                        chan struct{}
	diskPutStartedOnce                     sync.Once
	diskPutFinishedOnce                    sync.Once
	mutationDone                           []<-chan struct{}
}

func newTransferFixture(t *testing.T, mutate func(*nodeproto.StorageManifest)) *transferFixture {
	t.Helper()
	f := &transferFixture{blocked: make(chan struct{}), diskPutStarted: make(chan struct{}), diskPutFinished: make(chan struct{})}
	f.mode.Store("")
	ca, key, caPEM := authority(t)
	sourceIdentity, targetIdentity, clientIdentity := issue(t, ca, key, false), issue(t, ca, key, false), issue(t, ca, key, true)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	clientPin := nodeproto.Digest(clientIdentity.der)
	configure := func(server *httptest.Server, identity testIdentity) {
		server.Config.ErrorLog = log.New(io.Discard, "", 0)
		server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{identity.cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) != 1 || nodeproto.Digest(state.PeerCertificates[0].Raw) != clientPin {
				return ErrUnavailable
			}
			return nil
		}}
		server.StartTLS()
		t.Cleanup(server.Close)
	}
	sourceServer := httptest.NewUnstartedServer(http.HandlerFunc(f.serveSource))
	configure(sourceServer, sourceIdentity)
	targetServer := httptest.NewUnstartedServer(http.HandlerFunc(f.serveTarget))
	configure(targetServer, targetIdentity)
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	write := func(name string, raw []byte, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, raw, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	caPath, clientPath, keyPath := write("ca.pem", caPEM, 0644), write("client.crt", clientIdentity.certPEM, 0644), write("client.key", clientIdentity.keyPEM, 0600)
	profile := func(id, endpoint string, identity testIdentity) NodeProfile {
		return NodeProfile{ID: id, DatacenterID: "dc-" + id, GroupID: "group-" + id, Endpoint: endpoint, AllowedCIDRs: []string{"127.0.0.1/32"}, CAFile: caPath, ClientCertFile: clientPath, ClientKeyFile: keyPath, ServerCertificateSHA256: nodeproto.Digest(identity.der)}
	}
	sourceProfile, targetProfile := profile("source", sourceServer.URL, sourceIdentity), profile("target", targetServer.URL, targetIdentity)
	source, err := newNodeClientOwned(context.Background(), sourceProfile, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	target, err := newNodeClientOwned(context.Background(), targetProfile, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	v := Instance{ID: id(), OwnerRef: id(), NodeID: sourceProfile.ID, Hostname: "transfer-fixture", State: "shutoff", Resources: testResources(sourceProfile)}
	artifact, sourceOperation, transfer := id(), id(), id()
	f.disk = bytes.Repeat([]byte("synthetic-flat-disk-not-a-real-VM\n"), 1<<15)
	m := nodeproto.StorageManifest{Protocol: nodeproto.StorageProtocol, ArtifactID: artifact, Kind: "migration", NodeID: sourceProfile.ID, InstanceID: v.ID, OwnerRef: v.OwnerRef, Hostname: v.Hostname, Resources: v.Resources, SourceDomain: "aster-" + v.ID, ImageID: v.Resources.ImageID, ImageSHA256: strings.Repeat("a", 64), DiskSHA256: nodeproto.Digest(f.disk), DiskBytes: int64(len(f.disk)), VirtualBytes: uint64(v.Resources.SystemDiskGiB) << 30, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), ExportOperationID: sourceOperation, TargetNodeID: targetProfile.ID, FenceToken: strings.Repeat("f", 64)}
	if mutate != nil {
		mutate(&m)
	}
	inner, _ := json.Marshal(m)
	message := append([]byte(transferSigningDomain), inner...)
	hash := sha256.Sum256(message)
	signer := sourceIdentity.cert.PrivateKey.(crypto.Signer)
	sig, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	signed := nodeproto.SignedStorageManifest{Manifest: m, CertificateDER: base64.StdEncoding.EncodeToString(sourceIdentity.der), Signature: base64.StdEncoding.EncodeToString(sig)}
	f.raw, _ = json.Marshal(signed)
	f.manifest = m
	a := nodeproto.StorageInboxApprovalTask{Protocol: nodeproto.StorageProtocol, TransferID: transfer, ArtifactID: artifact, NodeID: targetProfile.ID, InstanceID: v.ID, OwnerRef: v.OwnerRef, SourceNodeID: sourceProfile.ID, SourceOperationID: sourceOperation, TargetNodeID: targetProfile.ID, ManifestSHA256: nodeproto.Digest(inner), FenceToken: strings.Repeat("f", 64)}
	f.relay = transferRelay{source: source, target: target, intent: TransferIntent{Protocol: TransferProtocol, SourceProfileSHA: sourceProfile.Digest(), Approval: a}, instance: v}
	return f
}
func (f *transferFixture) event(event string) {
	f.mu.Lock()
	f.events = append(f.events, event)
	f.mu.Unlock()
}
func transferJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func transferMissing(w http.ResponseWriter, code string) {
	transferJSON(w, 404, map[string]any{"error": map[string]string{"code": code}})
}
func (f *transferFixture) serveSource(w http.ResponseWriter, r *http.Request) {
	f.sourceGets.Add(1)
	f.event("source:" + r.Method + ":" + r.URL.Path)
	if r.Method != "GET" || r.TLS == nil {
		w.WriteHeader(405)
		return
	}
	mode := f.mode.Load().(string)
	if mode == "source_unavailable" {
		w.WriteHeader(503)
		return
	}
	if mode == "source_redirect" {
		http.Redirect(w, r, "https://127.0.0.1:1/forbidden", 307)
		return
	}
	f.mu.Lock()
	raw, disk, m := f.raw, f.disk, f.manifest
	f.mu.Unlock()
	file := strings.TrimPrefix(r.URL.Path, "/v1/storage-artifacts/"+f.relay.intent.Approval.ArtifactID+"/")
	body := raw
	if file == "disk" {
		body = disk
		w.Header().Set("Content-Type", "application/octet-stream")
	} else if file == "manifest" {
		w.Header().Set("Content-Type", "application/json")
	} else {
		w.WriteHeader(404)
		return
	}
	if mode == "large_manifest" && file == "manifest" {
		body = bytes.Repeat([]byte("x"), 65537)
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("X-Content-SHA256", nodeproto.Digest(body))
	w.Header().Set("X-Manifest-SHA256", f.relay.intent.Approval.ManifestSHA256)
	if file == "disk" {
		w.Header().Set("X-Content-SHA256", m.DiskSHA256)
	}
	if mode == "wrong_disk_header" && file == "disk" {
		w.Header().Set("X-Content-SHA256", strings.Repeat("0", 64))
	}
	if mode == "disk_hash" && file == "disk" {
		body = append([]byte{}, body...)
		body[0] ^= 0xff
	}
	if file == "disk" {
		// For every disk variant, make the first target PUT handler observable
		// before upstream EOF/hash/cancellation can fail the client. A loopback
		// TCP write may otherwise be buffered while the old handler is scheduled
		// only during a later GET-only reconciliation (especially on a busy VM).
		w.Write(body[:64<<10])
		w.(http.Flusher).Flush()
		select {
		case <-f.diskPutStarted:
		case <-r.Context().Done():
			return
		}
		if mode == "source_short" {
			w.Write(body[64<<10 : len(body)/2])
			return
		}
		if mode == "source_block" {
			f.blockedOnce.Do(func() { close(f.blocked) })
			<-r.Context().Done()
			return
		}
		w.Write(body[64<<10:])
		return
	}
	w.Write(body)
}
func (f *transferFixture) receipt(file string) nodeproto.StorageFileReceipt {
	a := f.relay.intent.Approval
	sha, n, status := nodeproto.Digest(f.raw), int64(len(f.raw)), "available"
	if file != "manifest" {
		sha, n = f.manifest.DiskSHA256, f.manifest.DiskBytes
	}
	if file == "approval" {
		status = "approved"
	}
	r := nodeproto.StorageFileReceipt{Protocol: nodeproto.StorageProtocol, NodeID: a.NodeID, TransferID: a.TransferID, ArtifactID: a.ArtifactID, File: file, SHA256: sha, Bytes: n, Status: status, ManifestSHA256: a.ManifestSHA256, SourceNodeID: a.SourceNodeID, SourceOperationID: a.SourceOperationID, InstanceID: a.InstanceID, OwnerRef: a.OwnerRef, FenceToken: a.FenceToken, TargetNodeID: a.TargetNodeID}
	switch f.mode.Load().(string) {
	case "wrong_receipt_hash":
		r.SHA256 = strings.Repeat("0", 64)
	case "wrong_receipt_transfer":
		r.TransferID = id()
	case "wrong_receipt_file":
		r.File = "disk"
	case "wrong_receipt_owner":
		r.OwnerRef = id()
	case "uncertain_receipt":
		r.Status = "uncertain"
	}
	return r
}
func (f *transferFixture) serveTarget(w http.ResponseWriter, r *http.Request) {
	f.event("target:" + r.Method + ":" + r.URL.Path)
	a := f.relay.intent.Approval
	if r.TLS == nil || r.Header.Get("X-Transfer-ID") != a.TransferID {
		w.WriteHeader(403)
		return
	}
	file := strings.TrimPrefix(r.URL.Path, "/v1/storage-inbox/"+a.ArtifactID+"/")
	if r.Method == "PUT" || r.Method == "POST" {
		done := make(chan struct{})
		f.mu.Lock()
		f.mutationDone = append(f.mutationDone, done)
		f.mu.Unlock()
		defer close(done)
	}
	mode := f.mode.Load().(string)
	if r.Method == "GET" {
		f.targetGets.Add(1)
		f.mu.Lock()
		present := file == "manifest" && f.manifestPresent || file == "disk" && f.diskPresent || file == "approval" && f.approved
		receipt := f.receipt(file)
		f.mu.Unlock()
		if !present {
			code := "FILE_NOT_RECEIVED"
			if file == "approval" {
				code = "APPROVAL_NOT_REQUESTED"
			}
			transferMissing(w, code)
			return
		}
		transferJSON(w, 200, receipt)
		return
	}
	if r.Method == "PUT" {
		f.puts.Add(1)
		if file == "disk" {
			f.diskPutStartedOnce.Do(func() { close(f.diskPutStarted) })
			defer f.diskPutFinishedOnce.Do(func() { close(f.diskPutFinished) })
		}
		if mode == "target_redirect" {
			http.Redirect(w, r, "https://127.0.0.1:1/forbidden", 307)
			return
		}
		if r.ContentLength < 1 || len(r.TransferEncoding) != 0 {
			w.WriteHeader(400)
			return
		}
		h := sha256.New()
		n, err := io.Copy(h, io.LimitReader(r.Body, r.ContentLength+1))
		if err != nil || n != r.ContentLength || strings.ToLower(r.Header.Get("X-Content-SHA256")) != hex.EncodeToString(h.Sum(nil)) {
			transferJSON(w, 409, map[string]any{"error": map[string]string{"code": "DIGEST_MISMATCH"}})
			return
		}
		f.mu.Lock()
		if file == "manifest" {
			f.manifestPresent = true
		} else if file == "disk" {
			f.diskPresent = true
		} else {
			f.mu.Unlock()
			w.WriteHeader(404)
			return
		}
		receipt := f.receipt(file)
		f.mu.Unlock()
		if mode == "target_drop_disk" && file == "disk" {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				conn.Close()
			}
			return
		}
		transferJSON(w, 201, receipt)
		return
	}
	if r.Method == "POST" && file == "approve" {
		f.posts.Add(1)
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 65537))
		var got nodeproto.StorageInboxApprovalTask
		if !strict(raw, &got) || got != a {
			w.WriteHeader(400)
			return
		}
		if mode == "approval_denied" {
			transferJSON(w, 403, map[string]any{"error": map[string]string{"code": "ROOT_CONTROLLER_INBOX_APPROVAL_NOT_ENABLED"}})
			return
		}
		f.mu.Lock()
		ready := f.manifestPresent && f.diskPresent
		if ready {
			f.approved = true
		}
		receipt := f.receipt("approval")
		f.mu.Unlock()
		if !ready {
			w.WriteHeader(409)
			return
		}
		if mode == "drop_approval" {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				conn.Close()
			}
			return
		}
		transferJSON(w, 200, receipt)
		return
	}
	w.WriteHeader(404)
}
func TestTransferIntentCanonicalAndBound(t *testing.T) {
	f := newTransferFixture(t, nil)
	raw, sha, err := f.relay.intent.BytesAndDigest()
	if err != nil || nodeproto.Digest(raw) != sha {
		t.Fatal(err)
	}
	got, err := DecodeTransferIntent(raw)
	if err != nil || got != f.relay.intent {
		t.Fatal("canonical intent", err)
	}
	for _, bad := range []string{string(raw) + "\n", strings.Replace(string(raw), `"protocol":`, `"Protocol":`, 1), strings.Replace(string(raw), `"approval":`, `"approval":null,"approval":`, 1), strings.Replace(string(raw), `"source_profile_sha256":`, `"extra":1,"source_profile_sha256":`, 1)} {
		if _, err := DecodeTransferIntent([]byte(bad)); err == nil {
			t.Fatal("ambiguous transfer intent accepted")
		}
	}
	for _, mutate := range []func(*transferRelay){func(r *transferRelay) { r.intent.SourceProfileSHA = strings.Repeat("0", 64) }, func(r *transferRelay) { r.intent.Approval.TargetNodeID = "other-node" }, func(r *transferRelay) { r.instance.OwnerRef = id() }, func(r *transferRelay) { r.instance.ID = id() }} {
		r := f.relay
		mutate(&r)
		if r.dispatch(context.Background()) == nil || f.sourceGets.Load() != 0 || f.puts.Load() != 0 {
			t.Fatal("unbound intent reached transport")
		}
	}
}

func (f *transferFixture) waitMutationHandlers(t *testing.T) {
	t.Helper()
	f.mu.Lock()
	done := append([]<-chan struct{}{}, f.mutationDone...)
	f.mu.Unlock()
	for _, ch := range done {
		select {
		case <-ch:
		case <-time.After(3 * time.Second):
			t.Fatal("initial mutation handler has not completed; cannot establish GET-only counter baseline")
		}
	}
}

func TestMigrationTransferCancellationJoinsStreamingWorker(t *testing.T) {
	f := newTransferFixture(t, nil)
	f.mode.Store("source_block")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- f.relay.dispatch(ctx) }()
	select {
	case <-f.blocked:
	case <-time.After(3 * time.Second):
		t.Fatal("source stream did not enter blocking gate")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled stream reported success")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled streaming goroutine was not joined")
	}
	if f.posts.Load() != 0 || f.puts.Load() > 2 {
		t.Fatal("cancellation approved or replayed")
	}
}
func TestMigrationTransferRealMTLSStreamAndGETOnlyReconcile(t *testing.T) {
	f := newTransferFixture(t, nil)
	if err := f.relay.dispatch(context.Background()); err != nil {
		t.Fatal("stream dispatch", err)
	}
	if f.puts.Load() != 2 || f.posts.Load() != 1 {
		t.Fatal("unexpected write count", f.puts.Load(), f.posts.Load())
	}
	f.mu.Lock()
	events := append([]string{}, f.events...)
	f.mu.Unlock()
	for _, file := range []string{"manifest", "disk"} {
		get, put := -1, -1
		for i, event := range events {
			if strings.Contains(event, "target:GET:") && strings.HasSuffix(event, "/"+file) {
				get = i
			}
			if strings.Contains(event, "target:PUT:") && strings.HasSuffix(event, "/"+file) {
				put = i
			}
		}
		if get < 0 || put < get {
			t.Fatal("PUT lacked prior GET receipt")
		}
	}
	if err := f.relay.reconcile(context.Background()); err != nil {
		t.Fatal("GET reconcile", err)
	}
	if f.puts.Load() != 2 || f.posts.Load() != 1 {
		t.Fatal("reconcile rewrote files or re-approved")
	}
	// Existing complete receipts can also satisfy a never-sent accepted intent
	// without rewriting bytes. Controller SQL prevents dispatching unknown jobs.
	if err := f.relay.dispatch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.puts.Load() != 2 || f.posts.Load() != 1 {
		t.Fatal("complete receipt replay wrote")
	}
}
func TestMigrationTransferRejectsManifestIdentityAndSignature(t *testing.T) {
	for name, mutate := range map[string]func(*nodeproto.StorageManifest){"owner": func(m *nodeproto.StorageManifest) { m.OwnerRef = id() }, "instance": func(m *nodeproto.StorageManifest) { m.InstanceID = id() }, "target": func(m *nodeproto.StorageManifest) { m.TargetNodeID = "other-target" }, "fence": func(m *nodeproto.StorageManifest) { m.FenceToken = strings.Repeat("b", 64) }, "resources": func(m *nodeproto.StorageManifest) { m.Resources.CPUCores++ }, "hostname": func(m *nodeproto.StorageManifest) { m.Hostname = "other-host" }, "disk_bounds": func(m *nodeproto.StorageManifest) { m.DiskBytes = 1 << 60 }} {
		t.Run(name, func(t *testing.T) {
			f := newTransferFixture(t, mutate)
			if err := f.relay.dispatch(context.Background()); err == nil {
				t.Fatal("foreign manifest accepted")
			}
			if f.puts.Load() != 0 || f.posts.Load() != 0 {
				t.Fatal("invalid proof caused target mutation")
			}
		})
	}
	t.Run("bad_signature", func(t *testing.T) {
		f := newTransferFixture(t, nil)
		f.mu.Lock()
		var signed nodeproto.SignedStorageManifest
		json.Unmarshal(f.raw, &signed)
		signed.Signature = base64.StdEncoding.EncodeToString(make([]byte, 64))
		f.raw, _ = json.Marshal(signed)
		f.mu.Unlock()
		if err := f.relay.dispatch(context.Background()); err == nil || f.puts.Load() != 0 {
			t.Fatal("bad signature forwarded")
		}
	})
	t.Run("wrong_signer_pin", func(t *testing.T) {
		f := newTransferFixture(t, nil)
		f.mu.Lock()
		var signed nodeproto.SignedStorageManifest
		json.Unmarshal(f.raw, &signed)
		signed.CertificateDER = base64.StdEncoding.EncodeToString([]byte("unapproved signer"))
		f.raw, _ = json.Marshal(signed)
		f.mu.Unlock()
		if err := f.relay.dispatch(context.Background()); err == nil || f.puts.Load() != 0 {
			t.Fatal("unapproved signer forwarded")
		}
	})
}
func TestMigrationTransferFaultsNeverApproveOrSilentlyReplay(t *testing.T) {
	for _, mode := range []string{"source_short", "disk_hash", "wrong_disk_header", "large_manifest", "source_redirect", "target_redirect", "wrong_receipt_hash", "wrong_receipt_transfer", "wrong_receipt_file", "wrong_receipt_owner", "uncertain_receipt", "approval_denied"} {
		t.Run(mode, func(t *testing.T) {
			f := newTransferFixture(t, nil)
			f.mode.Store(mode)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := f.relay.dispatch(ctx); err == nil {
				t.Fatal("fault accepted", mode)
			}
			f.waitMutationHandlers(t)
			puts, posts := f.puts.Load(), f.posts.Load()
			if err := f.relay.reconcile(ctx); err == nil {
				t.Fatal("incomplete handoff reconciled", mode)
			}
			if f.puts.Load() != puts || f.posts.Load() != posts {
				t.Fatal("reconcile wrote after unknown outcome")
			}
			if posts > 1 {
				t.Fatal("approval silently repeated")
			}
		})
	}
}
func TestMigrationTransferLostResponseRequiresOnlyReceiptReads(t *testing.T) {
	for _, mode := range []string{"target_drop_disk", "drop_approval"} {
		t.Run(mode, func(t *testing.T) {
			f := newTransferFixture(t, nil)
			f.mode.Store(mode)
			if err := f.relay.dispatch(context.Background()); err == nil {
				t.Fatal("lost response became success")
			}
			f.waitMutationHandlers(t)
			puts, posts := f.puts.Load(), f.posts.Load()
			if mode == "target_drop_disk" {
				if err := f.relay.reconcile(context.Background()); err == nil {
					t.Fatal("files without approval became success")
				}
				f.mu.Lock()
				f.approved = true
				f.mu.Unlock()
			}
			if err := f.relay.reconcile(context.Background()); err != nil {
				t.Fatal("complete bound receipts did not resolve unknown", err)
			}
			if f.puts.Load() != puts || f.posts.Load() != posts {
				t.Fatal("recovery repeated mutation")
			}
		})
	}
}
func TestMigrationTransferPinsCIDRProxyAndOfflineSourceFailClosed(t *testing.T) {
	f := newTransferFixture(t, nil)
	var proxyHits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { proxyHits.Add(1) }))
	defer proxy.Close()
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("HTTP_PROXY", proxy.URL)
	if err := f.relay.dispatch(context.Background()); err != nil || proxyHits.Load() != 0 {
		t.Fatal("proxy used or pinned relay failed", err)
	}
	f.mode.Store("source_unavailable")
	puts, posts := f.puts.Load(), f.posts.Load()
	if err := f.relay.reconcile(context.Background()); err == nil {
		t.Fatal("offline source assembled success from target receipts")
	}
	if puts != f.puts.Load() || posts != f.posts.Load() {
		t.Fatal("offline-source reconcile mutated")
	}
	f.mode.Store("")
	bad := f.relay.source.profile
	bad.ServerCertificateSHA256 = strings.Repeat("0", 64)
	client, err := newNodeClientOwned(context.Background(), bad, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	relay := f.relay
	relay.source = client
	if _, err := relay.readManifest(context.Background()); err == nil {
		t.Fatal("stream bypassed server leaf pin")
	}
	bad.AllowedCIDRs = []string{"192.0.2.0/24"}
	if _, err := newNodeClientOwned(context.Background(), bad, uint32(os.Geteuid())); err == nil {
		t.Fatal("stream accepted unapproved destination")
	}
}

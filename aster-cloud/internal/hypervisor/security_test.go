package hypervisor

import (
	"aster/cloud/internal/nodeproto"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFilesystemRejectsSymlinkHardlinkAndWritableAncestor(t *testing.T) {
	root := privateDir(t)
	good := filepath.Join(root, "secret")
	if e := os.WriteFile(good, []byte("private"), 0600); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(root, "alias")
	if e := os.Symlink(good, link); e != nil {
		t.Fatal(e)
	}
	if _, e := readApproved(link, true, 64); e == nil {
		t.Fatal("symlink read")
	}
	if e := os.Remove(link); e != nil {
		t.Fatal(e)
	}
	if e := os.Link(good, link); e != nil {
		t.Fatal(e)
	}
	if _, e := readApproved(good, true, 64); e == nil {
		t.Fatal("hardlinked secret read")
	}
	_ = os.Remove(link)
	if _, e := readApproved(good, true, 2); e == nil {
		t.Fatal("unbounded secret read")
	}
	writable := filepath.Join(root, "writable")
	_ = os.Mkdir(writable, 0700)
	_ = os.Chmod(writable, 0777)
	if e := NoSymlinkPath(filepath.Join(writable, "absent")); e == nil {
		t.Fatal("renameable ancestor accepted")
	}
	_ = os.Chmod(writable, 0700)
	if e := NoSymlinkPath(filepath.Join(writable, "absent")); e != nil {
		t.Fatal(e)
	}
	if e := NoSymlinkPath("relative/path"); e == nil {
		t.Fatal("relative path")
	}
}
func TestPrivateJournalPermissionsAndExclusiveProcessLock(t *testing.T) {
	m, _, _ := newFixture(t)
	if _, e := OpenLedger(m.Config.StateDirectory, m.Config.NodeID); e == nil {
		t.Fatal("second process lock acquired")
	}
	if e := os.Chmod(m.Config.StateDirectory, 0755); e != nil {
		t.Fatal(e)
	}
	if e := ownedPath(m.Config.StateDirectory, true, true); e == nil {
		t.Fatal("public state directory")
	}
	_ = os.Chmod(m.Config.StateDirectory, 0700)
	if e := os.Link(filepath.Join(m.Config.StateDirectory, "journal.json"), filepath.Join(m.Config.StateDirectory, "journal-hardlink")); e != nil {
		t.Fatal(e)
	}
	_ = m.Ledger.Close()
	if _, e := OpenLedger(m.Config.StateDirectory, m.Config.NodeID); e == nil {
		t.Fatal("hardlinked journal accepted")
	}
}
func TestJournalSizeLimitAppliesBeforePublishingSave(t *testing.T) {
	m, _, task := newFixture(t)
	_, sha, _ := task.BytesAndDigest()
	if _, _, e := m.Ledger.Claim(task, sha); e != nil {
		t.Fatal(e)
	}
	before, e := os.ReadFile(filepath.Join(m.Config.StateDirectory, "journal.json"))
	if e != nil {
		t.Fatal(e)
	}
	m.Ledger.mu.Lock()
	op := m.Ledger.state.Operations[task.OperationID]
	op.ErrorCode = strings.Repeat("x", maxJournalBytes)
	m.Ledger.state.Operations[task.OperationID] = op
	e = m.Ledger.save()
	m.Ledger.mu.Unlock()
	if e == nil {
		t.Fatal("oversize journal published")
	}
	after, e := os.ReadFile(filepath.Join(m.Config.StateDirectory, "journal.json"))
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("last restartable journal overwritten", e)
	}
}
func TestJournalWriteFailureCannotReportSuccess(t *testing.T) {
	m, _, task := newFixture(t)
	_, sha, _ := task.BytesAndDigest()
	_, _, _ = m.Ledger.Claim(task, sha)
	m.Ledger.mu.Lock()
	m.Ledger.poisoned = true
	m.Ledger.mu.Unlock()
	result, e := m.Ledger.Finish(task.OperationID, "succeeded", "", nil)
	if e == nil || result.Status != "uncertain" {
		t.Fatal(result, e)
	}
	if op, _ := m.Ledger.Query(task.OperationID); op.Result.Status == "succeeded" {
		t.Fatal("volatile success leaked")
	}
}
func TestFilterSelfContainedDefaultDenyAndStructuralValidation(t *testing.T) {
	raw := ApprovedFilterXML("aster-static-ipv4")
	if e := validateFilter(raw, "aster-static-ipv4"); e != nil {
		t.Fatal(e)
	}
	withUUID := bytes.Replace(raw, []byte(`chain="root">`), []byte(`chain="root"><uuid>1234</uuid>`), 1)
	if e := validateFilter(withUUID, "aster-static-ipv4"); e != nil {
		t.Fatal(e)
	}
	for _, raw := range [][]byte{bytes.Replace(raw, []byte("drop"), []byte("accept"), 1), bytes.Replace(raw, []byte("0x8100"), []byte("0x8101"), 1), bytes.Replace(raw, []byte("</filter>"), []byte(`<filterref filter="clean-traffic"/></filter>`), 1)} {
		if e := validateFilter(raw, "aster-static-ipv4"); e == nil {
			t.Fatal("weakened/unpinned policy accepted")
		}
	}
}
func TestNetworkConfigValidationRejectsDangerousValues(t *testing.T) {
	cases := map[string]func(*Network){"bridgepath": func(n *Network) { n.Bridge = "../../sys" }, "missing_ack": func(n *Network) { n.DedicatedBridgeAcknowledged = false }, "ipv6": func(n *Network) { n.CIDR = "2001:db8::/64" }, "network": func(n *Network) { n.Addresses = []string{"192.0.2.0"} }, "broadcast": func(n *Network) { n.Addresses = []string{"192.0.2.255"} }, "gateway": func(n *Network) { n.Addresses = []string{n.Gateway} }, "duplicate": func(n *Network) { n.Addresses = []string{"192.0.2.10", "192.0.2.10"} }, "key_injection": func(n *Network) { n.SSHAuthorizedKeys = []string{"ssh-ed25519 nope\nroot: x"} }, "password_key": func(n *Network) { n.SSHAuthorizedKeys = []string{"password secret"} }, "filtername": func(n *Network) { n.Filter = "clean-traffic" }}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m, _, _ := newFixture(t)
			mutate(&m.Config.Network)
			if e := m.Config.Network.Validate(); e == nil {
				t.Fatal("unsafe network config")
			}
		})
	}
}
func TestListenerNeedsExplicitApproval(t *testing.T) {
	m, _, _ := newFixture(t)
	m.Config.Listen = "0.0.0.0:9443"
	if e := m.Config.Validate(); e == nil {
		t.Fatal("implicit public listener")
	}
	m.Config.AllowPublicListen = true
	if e := m.Config.Validate(); e != nil {
		t.Fatal(e)
	}
	m.Config.Listen = "example.org:9443"
	if e := m.Config.Validate(); e == nil {
		t.Fatal("DNS bind accepted")
	}
}

type certSet struct {
	ca                    []byte
	server, good, bad     tls.Certificate
	serverCert, serverKey []byte
	goodLeaf              *x509.Certificate
}

func certificates(t *testing.T) certSet {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	caT := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, e := x509.CreateCertificate(rand.Reader, caT, caT, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	ca, _ := x509.ParseCertificate(caDER)
	out := certSet{ca: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})}
	makeCert := func(serial int64, client bool) (tls.Certificate, []byte, []byte, *x509.Certificate) {
		k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "fixture"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		if client {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		} else {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		der, e := x509.CreateCertificate(rand.Reader, tmpl, ca, &k.PublicKey, key)
		if e != nil {
			t.Fatal(e)
		}
		b, e := x509.MarshalECPrivateKey(k)
		if e != nil {
			t.Fatal(e)
		}
		certPEM, keyPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
		pair, e := tls.X509KeyPair(certPEM, keyPEM)
		if e != nil {
			t.Fatal(e)
		}
		leaf, _ := x509.ParseCertificate(der)
		return pair, certPEM, keyPEM, leaf
	}
	out.server, out.serverCert, out.serverKey, _ = makeCert(2, false)
	out.good, _, _, out.goodLeaf = makeCert(3, true)
	out.bad, _, _, _ = makeCert(4, true)
	return out
}
func authorizedRequest(m *Manager, method, path string, raw []byte, leaf *x509.Certificate) *http.Request {
	r := httptest.NewRequest(method, path, bytes.NewReader(raw))
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf}}}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Request-SHA256", nodeproto.Digest(raw))
	return r
}
func TestMTLSPinsExactControllerNotAnySameCA(t *testing.T) {
	m, _, _ := newFixture(t)
	certs := certificates(t)
	for path, raw := range map[string][]byte{m.Config.Certificate: certs.serverCert, m.Config.PrivateKey: certs.serverKey, m.Config.ControllerCA: certs.ca} {
		if e := os.WriteFile(path, raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	m.Config.ExpectedControllerCertificateSHA256 = nodeproto.Digest(certs.goodLeaf.Raw)
	cfg, e := ServerTLS(m.Config)
	if e != nil {
		t.Fatal(e)
	}
	if cfg.MinVersion != tls.VersionTLS12 || cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatal("TLS weakened")
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certs.ca)
	for name, pair := range map[string]*tls.Certificate{"approved": &certs.good, "same_ca_wrong_leaf": &certs.bad, "no_client": nil} {
		t.Run(name, func(t *testing.T) {
			cc := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "127.0.0.1"}
			if pair != nil {
				cc.Certificates = []tls.Certificate{*pair}
			}
			// Real TLS handshakes over an in-memory full-duplex transport: no listening
			// socket, no sandbox network exemption, no mocked verification callback.
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			_ = left.SetDeadline(time.Now().Add(time.Second))
			_ = right.SetDeadline(time.Now().Add(time.Second))
			server := tls.Server(left, cfg)
			client := tls.Client(right, cc)
			done := make(chan error, 1)
			go func() {
				e := server.Handshake()
				if e != nil {
					left.Close()
				}
				done <- e
			}()
			clientErr := client.Handshake()
			serverErr := <-done
			if name == "approved" {
				if clientErr != nil || serverErr != nil {
					t.Fatal(clientErr, serverErr)
				}
			} else if serverErr == nil {
				t.Fatal("unapproved client passed TLS", clientErr)
			}
		})
	}

}
func TestHandlerRejectsPlaintextDigestAndLargeBody(t *testing.T) {
	m, _, task := newFixture(t)
	certs := certificates(t)
	m.Config.ExpectedControllerCertificateSHA256 = nodeproto.Digest(certs.goodLeaf.Raw)
	h := m.Handler()
	r := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
	raw, _, _ := task.BytesAndDigest()
	for name, mutate := range map[string]func(*http.Request){"digest": func(r *http.Request) { r.Header.Set("X-Request-SHA256", strings.Repeat("0", 64)) }, "wrong_ca": func(r *http.Request) { r.TLS.VerifiedChains = nil }, "content_type": func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }} {
		t.Run(name, func(t *testing.T) {
			r := authorizedRequest(m, "POST", "/v1/tasks", raw, certs.goodLeaf)
			mutate(r)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code < 400 {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
	r = authorizedRequest(m, "POST", "/v1/tasks", append(raw, bytes.Repeat([]byte(" "), 65536)...), certs.goodLeaf)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
	if len(m.Ledger.Instances()) != 0 {
		t.Fatal("invalid request reserved resources")
	}
}
func TestHandlerAcceptedThenQueryAndConflict(t *testing.T) {
	m, f, task := newFixture(t)
	certs := certificates(t)
	m.Config.ExpectedControllerCertificateSHA256 = nodeproto.Digest(certs.goodLeaf.Raw)
	gate := make(chan struct{})
	f.block = gate
	raw, sha, _ := task.BytesAndDigest()
	h := m.Handler()
	r := authorizedRequest(m, "POST", "/v1/tasks", raw, certs.goodLeaf)
	ctx, cancel := context.WithCancel(r.Context())
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	cancel()
	if w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	var result nodeproto.NodeResult
	if json.Unmarshal(w.Body.Bytes(), &result) != nil || !result.Matches(task, sha) || result.Status != "accepted" {
		t.Fatal(w.Body.String())
	}
	r = authorizedRequest(m, "GET", "/v1/tasks/"+task.OperationID, nil, certs.goodLeaf)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"accepted"`) {
		t.Fatal(w.Code, w.Body.String())
	}
	changed := append(raw, ' ')
	r = authorizedRequest(m, "POST", "/v1/tasks", changed, certs.goodLeaf)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 409 || !strings.Contains(w.Body.String(), "OPERATION_CONFLICT") {
		t.Fatal(w.Code, w.Body.String())
	}
	close(gate)
	if result = submit(t, m, task); result.Status != "succeeded" {
		t.Fatal(result)
	}
}
func TestCapabilitiesNeverNullAndDoctorDoesNotMutate(t *testing.T) {
	m, f, _ := newFixture(t)
	f.fail = "list" // Deterministic readiness failure on Linux and macOS alike.
	c := m.Capabilities(context.Background())
	raw, e := json.Marshal(c)
	if e != nil || bytes.Contains(raw, []byte(":null")) {
		t.Fatal(string(raw), e)
	}
	if c.ObservedAt == "" || !c.Maintenance || len(c.Actions) != 0 {
		t.Fatal("failed inventory must not advertise real KVM", c)
	}
	for _, needle := range []string{" define ", " start ", " create ", " nwfilter-define ", " destroy "} {
		if f.count(needle) != 0 {
			t.Fatal("doctor mutated", f.commands)
		}
	}
}
func TestReadonlyReconcileRequiresOwnedTargetAndNeverProvesReboot(t *testing.T) {
	m, f, task := newFixture(t)
	f.fail = "start"
	_ = submit(t, m, task)
	f.fail = ""
	f.states["aster-"+task.InstanceID] = "shut off"
	if _, e := m.Reconcile(context.Background(), task.OperationID); e == nil {
		t.Fatal("off create proved succeeded")
	}
	f.states["aster-"+task.InstanceID] = "running"
	f.domains["aster-"+task.InstanceID] = []byte(`<domain type="kvm"><name>foreign</name></domain>`)
	if _, e := m.Reconcile(context.Background(), task.OperationID); !errors.Is(e, ErrOwnership) {
		t.Fatal(e)
	}
	op, _ := m.Ledger.Query(task.OperationID)
	if op.Result.Status != "uncertain" {
		t.Fatal(op)
	}
}

func TestTerminalPublicationWaitsForWorkerReleaseAcrossGETAndReplay(t *testing.T) {
	m, _, task := newFixture(t)
	certs := certificates(t)
	m.Config.ExpectedControllerCertificateSHA256 = nodeproto.Digest(certs.goodLeaf.Raw)
	persisted, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	m.beforeRelease = func() { once.Do(func() { close(persisted); <-release }) }
	// Release on any assertion failure before fixture cleanup waits on the worker.
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	raw, _, _ := task.BytesAndDigest()
	h := m.Handler()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, authorizedRequest(m, "POST", "/v1/tasks", raw, certs.goodLeaf))
	if w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	select {
	case <-persisted:
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not reach terminal-persisted gate")
	}
	durable, ok := m.Ledger.Query(task.OperationID)
	if !ok || durable.Result.Status != "succeeded" {
		t.Fatal("test gate did not expose intended durable terminal window", durable)
	}
	// Neither direct public Lookup, HTTP GET, nor same-operation POST replay may
	// reveal succeeded while a subsequent operation would still hit NODE_BUSY.
	if result, ok := m.Lookup(task.OperationID); !ok || result.Status != "accepted" {
		t.Fatal(result, ok)
	}
	if result, e := m.Accept(task, raw); e != nil || result.Status != "accepted" {
		t.Fatal(result, e)
	}
	for _, method := range []string{"GET", "POST"} {
		path := "/v1/tasks"
		body := raw
		if method == "GET" {
			path += "/" + task.OperationID
			body = nil
		}
		w = httptest.NewRecorder()
		h.ServeHTTP(w, authorizedRequest(m, method, path, body, certs.goodLeaf))
		var result nodeproto.NodeResult
		if json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Status != "accepted" {
			t.Fatal(method, w.Code, w.Body.String())
		}
		if method == "POST" && w.Code != 202 {
			t.Fatal(w.Code)
		}
	}
	stillDurable, _ := m.Ledger.Query(task.OperationID)
	if stillDurable.Result.Status != "succeeded" {
		t.Fatal("visibility fix rewrote durable outcome")
	}
	close(release)
	if result := submit(t, m, task); result.Status != "succeeded" {
		t.Fatal(result)
	}
	// Once terminal is externally visible, the next genuine operation must enter
	// immediately without retries/sleeps and cannot be permanently BUSY-rejected.
	off := next(task, "4", "force_off")
	offRaw, _, _ := off.BytesAndDigest()
	w = httptest.NewRecorder()
	h.ServeHTTP(w, authorizedRequest(m, "POST", "/v1/tasks", offRaw, certs.goodLeaf))
	if w.Code != 202 {
		t.Fatal("terminal visible but next admission unavailable", w.Code, w.Body.String())
	}
	if result := submit(t, m, off); result.Status != "succeeded" {
		t.Fatal(result)
	}
}

package control

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type testIdentity struct {
	cert            tls.Certificate
	certPEM, keyPEM []byte
	der             []byte
}

func issue(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, client bool) testIdentity {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "synthetic-test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}}
	if client {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		template.IPAddresses = nil
	}
	der, e := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	keyDER, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	pair, e := tls.X509KeyPair(certPEM, keyPEM)
	if e != nil {
		t.Fatal(e)
	}
	return testIdentity{pair, certPEM, keyPEM, der}
}
func authority(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-test-ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	cert, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	return cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
func TestNodeClientRealMutualTLSPinsRedirectAndBinding(t *testing.T) {
	ca, caKey, caPEM := authority(t)
	serverID := issue(t, ca, caKey, false)
	clientID := issue(t, ca, caKey, true)
	unapprovedClient := issue(t, ca, caKey, true)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	clientPin := sha256.Sum256(clientID.der)
	serverPin := sha256.Sum256(serverID.der)
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	os.Chmod(dir, 0700)
	write := func(name string, raw []byte, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if e := os.WriteFile(p, raw, mode); e != nil {
			t.Fatal(e)
		}
		return p
	}
	p := testProfile()
	p.CAFile = write("ca.pem", caPEM, 0644)
	p.ClientCertFile = write("client.crt", clientID.certPEM, 0644)
	p.ClientKeyFile = write("client.key", clientID.keyPEM, 0600)
	p.ServerCertificateSHA256 = hex.EncodeToString(serverPin[:])
	p.AllowedCIDRs = []string{"127.0.0.1/32"}
	var posts atomic.Int32
	var redirectHits atomic.Int32
	var mode atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirectHits.Add(1) }))
	defer target.Close()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if mode.Load() == 1 {
			http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
			return
		}
		if r.URL.Path == "/v1/capabilities" {
			json.NewEncoder(w).Encode(testCapabilities(p, time.Now().UTC()))
			return
		}
		if r.Method == "POST" {
			posts.Add(1)
			raw, _ := io.ReadAll(r.Body)
			task, e := nodeproto.DecodeTask(raw)
			if e != nil || r.Header.Get("X-Request-SHA256") != nodeproto.Digest(raw) {
				w.WriteHeader(400)
				return
			}
			result := nodeproto.NodeResult{Protocol: nodeproto.Protocol, OperationID: task.OperationID, RequestSHA256: nodeproto.Digest(raw), Status: "accepted", InstanceID: task.InstanceID}
			if mode.Load() == 2 {
				result.InstanceID = id()
			}
			w.WriteHeader(202)
			json.NewEncoder(w).Encode(result)
			return
		}
		w.WriteHeader(404)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverID.cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, VerifyConnection: func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return ErrUnavailable
		}
		h := sha256.Sum256(state.PeerCertificates[0].Raw)
		if h != clientPin {
			return ErrUnavailable
		}
		return nil
	}}
	server.StartTLS()
	defer server.Close()
	p.Endpoint = server.URL
	owner := uint32(os.Geteuid())
	client, e := newNodeClientOwned(context.Background(), p, owner)
	if e != nil {
		t.Fatal(e)
	}
	caps, e := client.Capabilities(context.Background())
	if e != nil || !caps.Supports(testResources(p), p) {
		t.Fatal("real mTLS capability failed", e)
	}
	task := nodeproto.NodeTask{Protocol: nodeproto.Protocol, OperationID: id(), NodeID: p.ID, Action: "create", InstanceID: id(), OwnerRef: id(), Hostname: "synthetic-vm", Resources: testResources(p)}
	raw, digest, _ := task.BytesAndDigest()
	if result, e := client.Send(context.Background(), raw, digest); e != nil || !result.Matches(task, digest) {
		t.Fatal("bound accepted response failed", e)
	}
	t.Run("wrong_server_leaf_pin", func(t *testing.T) {
		bad := p
		bad.ServerCertificateSHA256 = strings.Repeat("0", 64)
		c, e := newNodeClientOwned(context.Background(), bad, owner)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = c.Capabilities(context.Background()); e == nil {
			t.Fatal("wrong server pin accepted")
		}
	})
	t.Run("wrong_CA", func(t *testing.T) {
		_, _, otherCA := authority(t)
		bad := p
		bad.CAFile = write("other-ca.pem", otherCA, 0644)
		c, e := newNodeClientOwned(context.Background(), bad, owner)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = c.Capabilities(context.Background()); e == nil {
			t.Fatal("untrusted CA accepted")
		}
	})
	t.Run("same_CA_wrong_client_leaf_pin", func(t *testing.T) {
		bad := p
		bad.ClientCertFile = write("other-client.crt", unapprovedClient.certPEM, 0644)
		bad.ClientKeyFile = write("other-client.key", unapprovedClient.keyPEM, 0600)
		c, e := newNodeClientOwned(context.Background(), bad, owner)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = c.Capabilities(context.Background()); e == nil {
			t.Fatal("same CA unauthorized controller accepted")
		}
	})
	t.Run("disallowed_destination_CIDR", func(t *testing.T) {
		bad := p
		bad.AllowedCIDRs = []string{"192.0.2.0/24"}
		if _, e := newNodeClientOwned(context.Background(), bad, owner); e == nil {
			t.Fatal("disallowed target dialed")
		}
	})
	t.Run("redirect_not_followed", func(t *testing.T) {
		mode.Store(1)
		defer mode.Store(0)
		if _, e = client.Send(context.Background(), raw, digest); e == nil {
			t.Fatal("redirect accepted")
		}
		if redirectHits.Load() != 0 {
			t.Fatal("redirect leaked authenticated mutation")
		}
	})
	t.Run("wrong_instance_result_rejected", func(t *testing.T) {
		mode.Store(2)
		defer mode.Store(0)
		if _, e = client.Send(context.Background(), raw, digest); e == nil {
			t.Fatal("unbound result accepted")
		}
	})
	if posts.Load() != 2 {
		t.Fatal("unexpected mutation replay", posts.Load())
	}
}

package billingconnector

import (
	"aster/billing/controllerapi"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
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

func newFixtureCA() ([]byte, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Untrusted connector fixture CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	return x509.CreateCertificate(rand.Reader, ca, ca, public, private)
}

// This exercises the real public transport with real verified TLS, not a
// relaxed owner/CA test client. Running unprivileged is an explicit skip.
func TestRootTLSConnectorUsesExistingProtectedTransport(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root-owned policy/credential fixtures; run this compiled test as root on isolated Linux")
	}
	request := fixtureRequest(t)
	raw, digest, _ := request.BytesAndDigest()
	good := fixtureResult(t, request)
	goodRaw, _ := json.Marshal(good)
	for _, mode := range []string{"accepted", "succeeded", "rejected", "bound409", "duplicate", "wrong_order", "wrong_digest", "unknown_status", "extra_field", "unbound409", "redirect", "html", "lost_ack", "oversize", "untrusted_ca"} {
		t.Run(mode, func(t *testing.T) {
			var requests, connections atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Header.Get("Authorization") != "Bearer fixture-private-billing-connector-token" || r.Header.Get("Idempotency-Key") != request.OperationID || r.Header.Get("X-Aster-Request-SHA256") != digest {
					t.Error("stable request authentication/binding missing")
				}
				body, _ := io.ReadAll(r.Body)
				if r.Method == "POST" {
					if r.URL.Path != "/v1/provisioning" || string(body) != string(raw) {
						t.Error("request changed")
					}
				} else if r.Method != "GET" || r.URL.Path != "/v1/provisioning/"+request.OperationID || len(body) != 0 {
					t.Error("lookup is not original operation-bound GET")
				}
				if mode == "lost_ack" {
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					_ = conn.Close()
					return
				}
				payload := string(goodRaw)
				status := 202
				w.Header().Set("Content-Type", "application/json")
				switch mode {
				case "succeeded":
					v := good
					v.Status = "succeeded"
					v.ResourceID = "vm-a"
					b, _ := json.Marshal(v)
					payload = string(b)
				case "rejected":
					v := good
					v.Status = "rejected"
					b, _ := json.Marshal(v)
					payload = string(b)
				case "bound409":
					status = 409
				case "duplicate":
					payload = strings.Replace(payload, `"status":`, `"status":"accepted","status":`, 1)
				case "wrong_order":
					payload = strings.Replace(payload, request.OrderID, strings.Repeat("f", 32), 1)
				case "wrong_digest":
					payload = strings.Replace(payload, digest, strings.Repeat("0", 64), 1)
				case "unknown_status":
					payload = strings.Replace(payload, `"accepted"`, `"unknown"`, 1)
				case "extra_field":
					payload = strings.TrimSuffix(payload, "}") + `,"paid":true}`
				case "unbound409":
					status = 409
					payload = `{}`
				case "redirect":
					status = 307
					w.Header().Set("Location", "/steal")
				case "html":
					w.Header().Set("Content-Type", "text/html")
				case "oversize":
					payload += strings.Repeat(" ", 16385)
				}
				w.WriteHeader(status)
				_, _ = io.WriteString(w, payload)
			}))
			server.Config.ErrorLog = log.New(io.Discard, "", 0)
			server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					connections.Add(1)
				}
			}
			server.StartTLS()
			t.Cleanup(server.Close)
			base := "/tmp"
			if _, err := os.Stat("/private/tmp"); err == nil {
				base = "/private/tmp"
			}
			dir, err := os.MkdirTemp(base, "aster-billing-connector-tls-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			token, ca, path := filepath.Join(dir, "token"), filepath.Join(dir, "ca.pem"), filepath.Join(dir, "policy.json")
			if err := os.WriteFile(token, []byte("fixture-private-billing-connector-token"), 0600); err != nil {
				t.Fatal(err)
			}
			certificate := server.Certificate().Raw
			if mode == "untrusted_ca" {
				// A different TLS fixture is not an authority for this endpoint.
				// Generate a distinct CA rather than replacing verification with
				// InsecureSkipVerify or adding a transport test-only override.
				otherCA, err := newFixtureCA()
				if err != nil {
					t.Fatal(err)
				}
				certificate = otherCA
			}
			if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}), 0600); err != nil {
				t.Fatal(err)
			}
			policy := controllerapi.Policy{Schema: 1, Controllers: []controllerapi.Profile{{ID: "primary", Enabled: true, Endpoint: server.URL + "/v1/provisioning", AllowedCIDRs: []string{"127.0.0.1/32"}, TokenFile: token, CAFile: ca}}}
			policyRaw, _ := json.Marshal(policy)
			if err := os.WriteFile(path, policyRaw, 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
			connector, err := Open(context.Background(), path, "primary")
			if err != nil {
				t.Fatal("real protected transport could not open fixture", err)
			}
			valid := mode == "accepted" || mode == "succeeded" || mode == "rejected" || mode == "bound409"
			result, err := connector.Send(context.Background(), request)
			if valid {
				if err != nil || !result.Matches(request) {
					t.Fatal("complete bound response rejected", err)
				}
			} else if !errors.Is(err, controllerapi.ErrUncertain) || result != (controllerapi.Result{}) {
				t.Fatal("bad/unknown outcome became success", err)
			}
			wantRequests := int32(1)
			if mode == "untrusted_ca" {
				wantRequests = 0
			}
			if requests.Load() != wantRequests || connections.Load() != 1 {
				t.Fatal("send followed a redirect, retried or redialed", requests.Load(), connections.Load())
			}
			if valid {
				result, err = connector.Lookup(context.Background(), request)
				if err != nil || !result.Matches(request) || requests.Load() != 2 || connections.Load() != 2 {
					t.Fatal("lookup changed intent or reused/retried a connection", err)
				}
			}
		})
	}
}

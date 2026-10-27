package control

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type observationFixture struct {
	client        *NodeClient
	value         nodeproto.InstanceObservation
	mu            sync.Mutex
	status        int
	raw           []byte
	requests      atomic.Int32
	verifiedPeers atomic.Int32
}

func newObservationFixture(t *testing.T, suffix ...string) *observationFixture {
	t.Helper()
	readSuffix := ""
	if len(suffix) == 1 {
		readSuffix = suffix[0]
	}
	ca, key, caPEM := authority(t)
	serverIdentity, clientIdentity := issue(t, ca, key, false), issue(t, ca, key, true)
	clientPin := sha256.Sum256(clientIdentity.der)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	p := testProfile()
	p.ID = "observed-node"
	p.AllowedCIDRs = []string{"127.0.0.1/32"}
	f := &observationFixture{status: 200, value: nodeproto.InstanceObservation{Protocol: nodeproto.InstanceProtocol, NodeID: p.ID, InstanceID: id(), OwnerRef: id(), Hostname: "observed-vm", State: "shutoff", IPv4: "192.0.2.40", MAC: "02:00:00:00:00:40", ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), SourceFenced: true, TargetPending: true}}
	f.raw, _ = json.Marshal(f.value)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		if r.Method != "GET" || r.URL.Path != "/v1/instances/"+f.value.InstanceID+readSuffix || r.URL.RawQuery != "" {
			w.WriteHeader(400)
			return
		}
		f.mu.Lock()
		status, raw := f.status, append([]byte{}, f.raw...)
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(raw)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverIdentity.cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, VerifyConnection: func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) != 1 || sha256.Sum256(state.PeerCertificates[0].Raw) != clientPin {
			return ErrUnavailable
		}
		f.verifiedPeers.Add(1)
		return nil
	}}
	server.StartTLS()
	t.Cleanup(server.Close)
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	write := func(name string, raw []byte, mode os.FileMode) string {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, raw, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	p.Endpoint = server.URL
	p.CAFile = write("ca.crt", caPEM, 0644)
	p.ClientCertFile = write("client.crt", clientIdentity.certPEM, 0644)
	p.ClientKeyFile = write("client.key", clientIdentity.keyPEM, 0600)
	pin := sha256.Sum256(serverIdentity.der)
	p.ServerCertificateSHA256 = hex.EncodeToString(pin[:])
	f.client, err = newNodeClientOwned(context.Background(), p, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *observationFixture) reply(status int, raw []byte) {
	f.mu.Lock()
	f.status = status
	f.raw = append([]byte{}, raw...)
	f.mu.Unlock()
}
func TestObservationUsesRealMutualTLSAndFreshBoundRead(t *testing.T) {
	f := newObservationFixture(t)
	got, err := f.client.Observe(context.Background(), f.value.InstanceID)
	if err != nil || got != f.value {
		t.Fatal("fresh bound read rejected", err)
	}
	if f.requests.Load() != 1 || f.verifiedPeers.Load() != 1 {
		t.Fatal("observation did not use one authenticated physical request")
	}
	f.reply(409, []byte(`{"error":{"code":"LIVE_INSTANCE_OBSERVATION_UNCONFIRMED"}}`))
	got, err = f.client.Observe(context.Background(), f.value.InstanceID)
	if !errors.Is(err, ErrState) || got.Protocol != "" || got.State != "" {
		t.Fatal("busy response reused the prior confirmed observation", err, got)
	}
	response := httptest.NewRecorder()
	consoleError(response, err)
	if response.Code != 409 || strings.Contains(response.Body.String(), f.value.IPv4) || strings.Contains(response.Body.String(), `"observation"`) {
		t.Fatal("host error projection displayed prior success")
	}
	if f.requests.Load() != 2 {
		t.Fatal("read was silently retried")
	}
}
func TestObservationRejectsFreshPayloadUnderNonObservationHTTPStatus(t *testing.T) {
	f := newObservationFixture(t)
	raw, _ := json.Marshal(f.value)
	for _, status := range []int{202, 409} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			f.reply(status, raw)
			before := f.requests.Load()
			if _, err := f.client.Observe(context.Background(), f.value.InstanceID); err == nil {
				t.Fatalf("HTTP %d confirmed an observation", status)
			}
			if f.requests.Load() != before+1 {
				t.Fatal("invalid observation triggered retry")
			}
		})
	}
}
func TestObservationNeverConfirmsStaleAmbiguousOrMismatchedNodeData(t *testing.T) {
	f := newObservationFixture(t)
	tests := map[string]func(*nodeproto.InstanceObservation){"stale": func(v *nodeproto.InstanceObservation) {
		v.ObservedAt = time.Now().Add(-6 * time.Minute).UTC().Format(time.RFC3339Nano)
	}, "future": func(v *nodeproto.InstanceObservation) {
		v.ObservedAt = time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)
	}, "invalid_time": func(v *nodeproto.InstanceObservation) { v.ObservedAt = "not-a-timestamp" }, "node_mismatch": func(v *nodeproto.InstanceObservation) { v.NodeID = "other-node" }, "instance_mismatch": func(v *nodeproto.InstanceObservation) { v.InstanceID = id() }, "protocol_mismatch": func(v *nodeproto.InstanceObservation) { v.Protocol = "other/1" }, "malformed_owner": func(v *nodeproto.InstanceObservation) { v.OwnerRef = "not-an-owner" }, "unknown_state": func(v *nodeproto.InstanceObservation) { v.State = "Succeeded" }, "ipv4_multicast": func(v *nodeproto.InstanceObservation) { v.IPv4 = "224.0.0.1" }, "ipv4_unspecified": func(v *nodeproto.InstanceObservation) { v.IPv4 = "0.0.0.0" }, "ipv6_in_ipv4": func(v *nodeproto.InstanceObservation) { v.IPv4 = "::1" }, "mac_multicast": func(v *nodeproto.InstanceObservation) { v.MAC = "01:00:00:00:00:01" }, "mac_extended": func(v *nodeproto.InstanceObservation) { v.MAC = "02:00:00:00:00:00:00:01" }}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			value := f.value
			mutate(&value)
			raw, _ := json.Marshal(value)
			f.reply(200, raw)
			before := f.requests.Load()
			_, err := f.client.Observe(context.Background(), f.value.InstanceID)
			if !errors.Is(err, ErrUnavailable) {
				t.Fatal("untrusted observation accepted", err)
			}
			response := httptest.NewRecorder()
			consoleError(response, err)
			if response.Code == 200 || strings.Contains(response.Body.String(), `"observation"`) || strings.Contains(response.Body.String(), f.value.IPv4) {
				t.Fatal("invalid read projected a cached success")
			}
			if f.requests.Load() != before+1 {
				t.Fatal("invalid read was retried")
			}
		})
	}
	raw, _ := json.Marshal(f.value)
	for name, body := range map[string][]byte{"unknown": []byte(strings.Replace(string(raw), `"protocol":`, `"secret":1,"protocol":`, 1)), "duplicate": []byte(strings.Replace(string(raw), `"state":`, `"state":"running","state":`, 1)), "null": []byte(strings.Replace(string(raw), `"source_fenced":true`, `"source_fenced":null`, 1)), "missing": []byte(strings.Replace(string(raw), `,"target_pending":true`, "", 1)), "trailing": append(append([]byte{}, raw...), []byte(` {}`)...)} {
		t.Run(name, func(t *testing.T) {
			f.reply(200, body)
			if _, err := f.client.Observe(context.Background(), f.value.InstanceID); err == nil {
				t.Fatal("ambiguous observation accepted")
			}
		})
	}
}
func TestObservationCanonicalStateConversionDoesNotChangeCase(t *testing.T) {
	f := newObservationFixture(t)
	value := f.value
	value.State = "shut off"
	raw, _ := json.Marshal(value)
	f.reply(200, raw)
	got, err := f.client.Observe(context.Background(), value.InstanceID)
	if err != nil || got.State != "shutoff" {
		t.Fatal("documented libvirt state normalization failed", err)
	}
	value.State = "Shut Off"
	raw, _ = json.Marshal(value)
	f.reply(200, raw)
	if _, err = f.client.Observe(context.Background(), value.InstanceID); err == nil {
		t.Fatal("unknown casing converted to confirmed state")
	}
	before := f.requests.Load()
	if _, err = f.client.Observe(context.Background(), "invalid"); !errors.Is(err, ErrInput) || f.requests.Load() != before {
		t.Fatal("invalid instance reached node")
	}
}

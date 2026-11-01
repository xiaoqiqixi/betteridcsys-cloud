package control

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestGuestConsoleVendoredSourceDigests(t *testing.T) {
	raw, e := guestConsoleAssets.ReadFile("guestconsole/novnc/UPSTREAM.json")
	var index struct{ Files, Patches map[string]string }
	if e != nil || json.Unmarshal(raw, &index) != nil || len(index.Files) < 50 || len(index.Patches) != 2 {
		t.Fatal("vendor manifest")
	}
	for name, want := range index.Files {
		if patched, ok := index.Patches[name]; ok {
			want = patched
		}
		content, e := guestConsoleAssets.ReadFile("guestconsole/novnc/" + name)
		got := sha256.Sum256(content)
		if e != nil || hex.EncodeToString(got[:]) != want {
			t.Fatal("vendor digest", name, e)
		}
	}
}

func guestConsoleFixture(t *testing.T) (*GuestConsole, *serviceFixture, *httptest.Server) {
	t.Helper()
	app, store, _ := serviceApp()
	store.caps.Actions = append(store.caps.Actions, "console")
	c, e := NewGuestConsole(store, app.Config, "https://localhost")
	if e != nil {
		t.Fatal(e)
	}
	s := httptest.NewTLSServer(c.Handler())
	c.Origin = s.URL
	t.Cleanup(s.Close)
	return c, store, s
}
func TestGuestConsoleTicketsExpireAndConsumeExactlyOnce(t *testing.T) {
	c, s, _ := guestConsoleFixture(t)
	now := time.Now().UTC()
	c.Now = func() time.Time { return now }
	issue := func() string {
		v, e := c.Issue(context.Background(), s.value)
		if e != nil {
			t.Fatal(e)
		}
		if v.ExpiresAt.Sub(now) != time.Minute {
			t.Fatal("TTL")
		}
		u, _ := url.Parse(v.URL)
		return u.Fragment
	}
	secret := issue()
	var success atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := c.consume(secret); ok {
				success.Add(1)
			}
		}()
	}
	wg.Wait()
	if success.Load() != 1 {
		t.Fatal("ticket was not single use")
	}
	secret = issue()
	now = now.Add(time.Minute)
	if _, ok := c.consume(secret); ok {
		t.Fatal("expired ticket accepted")
	}
}
func TestGuestConsoleStreamsBinaryAndRejectsReplayAndOrigin(t *testing.T) {
	c, s, server := guestConsoleFixture(t)
	var dials atomic.Int32
	c.Dial = func(ctx context.Context, _ NodeProfile, v Instance) (net.Conn, error) {
		if v.OwnerRef != s.value.OwnerRef {
			t.Error("owner changed")
		}
		dials.Add(1)
		a, b := net.Pipe()
		go func() { defer b.Close(); _, _ = b.Write([]byte("RFB 003.008\n")); _, _ = io.Copy(b, b) }()
		return a, nil
	}
	issued, e := c.Issue(context.Background(), s.value)
	if e != nil {
		t.Fatal(e)
	}
	u, _ := url.Parse(issued.URL)
	endpoint := "wss" + strings.TrimPrefix(server.URL, "https") + "/console/ws?ticket=" + u.Fragment
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	opts := &websocket.DialOptions{HTTPClient: server.Client(), HTTPHeader: http.Header{"Origin": []string{"https://foreign.invalid"}}, Subprotocols: []string{"binary"}}
	if _, response, e := websocket.Dial(ctx, endpoint, opts); e == nil || response.StatusCode != 403 || dials.Load() != 0 {
		t.Fatal("foreign Origin accepted", e)
	}
	opts.HTTPHeader.Set("Origin", server.URL)
	ws, _, e := websocket.Dial(ctx, endpoint, opts)
	if e != nil {
		t.Fatal(e)
	}
	defer ws.CloseNow()
	stream := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	banner := make([]byte, 12)
	if _, e = io.ReadFull(stream, banner); e != nil || string(banner) != "RFB 003.008\n" {
		t.Fatal(string(banner), e)
	}
	if _, e = stream.Write([]byte("abc")); e != nil {
		t.Fatal(e)
	}
	echo := make([]byte, 3)
	if _, e = io.ReadFull(stream, echo); e != nil || string(echo) != "abc" {
		t.Fatal(e)
	}
	if _, response, e := websocket.Dial(ctx, endpoint, opts); e == nil || response.StatusCode != 404 || dials.Load() != 1 {
		t.Fatal("replayed ticket dialled node")
	}
}
func TestGuestConsoleRevalidatesOwnerAndServesSelfOnlyAssets(t *testing.T) {
	c, s, server := guestConsoleFixture(t)
	issued, e := c.Issue(context.Background(), s.value)
	if e != nil {
		t.Fatal(e)
	}
	u, _ := url.Parse(issued.URL)
	s.value.OwnerRef = strings.Repeat("f", 32)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, response, e := websocket.Dial(ctx, "wss"+strings.TrimPrefix(server.URL, "https")+"/console/ws?ticket="+u.Fragment, &websocket.DialOptions{HTTPClient: server.Client(), HTTPHeader: http.Header{"Origin": []string{server.URL}}})
	if e == nil || response.StatusCode != 404 {
		t.Fatal("owner change admitted")
	}
	for _, path := range []string{"/console/", "/console/console.js", "/console/novnc/core/rfb.js", "/console/novnc/docs/LICENSE.MPL-2.0"} {
		r, e := server.Client().Get(server.URL + path)
		if e != nil {
			t.Fatal(e)
		}
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if r.StatusCode != 200 || len(b) == 0 || r.Header.Get("Referrer-Policy") != "no-referrer" {
			t.Fatal(path, r.StatusCode)
		}
		csp := r.Header.Get("Content-Security-Policy")
		if !strings.Contains(csp, "default-src 'self'") || strings.Contains(csp, "unsafe-") || strings.Contains(csp, "data:") || strings.Contains(csp, "blob:") {
			t.Fatal(csp)
		}
	}
}
func TestGuestConsoleNodeTransportUsesPinnedMutualTLS(t *testing.T) {
	ca, key, _ := authority(t)
	serverID, clientID := issue(t, ca, key, false), issue(t, ca, key, true)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	var requests atomic.Int32
	owner, instance := id(), id()
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if len(r.TLS.VerifiedChains) == 0 || r.Header.Get("X-Aster-Owner-Ref") != owner || r.URL.Path != "/v1/instances/"+instance+"/console" {
			t.Error("unbound tunnel")
			w.WriteHeader(403)
			return
		}
		ws, e := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"binary"}})
		if e != nil {
			return
		}
		defer ws.CloseNow()
		_ = ws.Write(r.Context(), websocket.MessageBinary, []byte("RFB 003.008\n"))
		_, _, _ = ws.Read(r.Context())
	}))
	s.TLS = &tls.Config{Certificates: []tls.Certificate{serverID.cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS12}
	s.StartTLS()
	defer s.Close()
	pin := sha256.Sum256(serverID.der)
	p := testProfile()
	p.Endpoint = s.URL
	p.ServerCertificateSHA256 = hex.EncodeToString(pin[:])
	c := &NodeClient{profile: p, address: strings.TrimPrefix(s.URL, "https://"), tls: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{clientID.cert}, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12, VerifyConnection: func(cs tls.ConnectionState) error {
		if sha256.Sum256(cs.PeerCertificates[0].Raw) != pin {
			return ErrUnavailable
		}
		return nil
	}}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, e := c.Console(ctx, instance, owner)
	if e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 12)
	_, e = io.ReadFull(stream, b)
	stream.Close()
	if e != nil || string(b) != "RFB 003.008\n" || requests.Load() != 1 {
		t.Fatal(e)
	}
	c.tls = c.tls.Clone()
	c.tls.VerifyConnection = func(tls.ConnectionState) error { return ErrUnavailable }
	if _, e = c.Console(ctx, instance, owner); e == nil || requests.Load() != 1 {
		t.Fatal("invalid pin reached node")
	}
}

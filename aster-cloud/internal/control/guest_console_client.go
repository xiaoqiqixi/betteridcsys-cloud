package control

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
)

// Console uses this client's already-resolved CIDR-checked address and verified
// pinned mTLS identity. WebSocket upgrade gets exactly one dial and no redirects.
func (c *NodeClient) Console(ctx context.Context, instance, owner string) (net.Conn, error) {
	if !nodeproto.ValidID(instance) || !nodeproto.ValidID(owner) {
		return nil, ErrInput
	}
	var dials atomic.Int32
	dialer := net.Dialer{Timeout: 3 * time.Second, KeepAlive: -1}
	t := &http.Transport{Proxy: nil, DisableKeepAlives: true, DisableCompression: true, ForceAttemptHTTP2: false, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}, TLSClientConfig: c.tls.Clone(), TLSHandshakeTimeout: 4 * time.Second, ResponseHeaderTimeout: 6 * time.Second, MaxResponseHeaderBytes: 16 << 10, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		if !dials.CompareAndSwap(0, 1) {
			return nil, ErrUnavailable
		}
		return dialer.DialContext(ctx, network, c.address)
	}}
	defer t.CloseIdleConnections()
	h := http.Header{"X-Aster-Owner-Ref": []string{owner}}
	client := &http.Client{Transport: t, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ws, _, e := websocket.Dial(dialCtx, "wss"+strings.TrimPrefix(c.profile.Endpoint, "https")+"/v1/instances/"+instance+"/console", &websocket.DialOptions{HTTPClient: client, HTTPHeader: h, Subprotocols: []string{"binary"}, CompressionMode: websocket.CompressionDisabled})
	if e != nil {
		return nil, ErrUnavailable
	}
	if ws.Subprotocol() != "binary" {
		ws.CloseNow()
		return nil, ErrUnavailable
	}
	stream := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	ws.SetReadLimit(1 << 20)
	return stream, nil
}

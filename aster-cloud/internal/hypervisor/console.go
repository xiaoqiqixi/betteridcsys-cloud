package hypervisor

import (
	"aster/cloud/internal/consolestream"
	"aster/cloud/internal/nodeproto"
	"context"
	"encoding/xml"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
)

func (m *Manager) domainType() string {
	if m.Config.AllowSoftwareEmulation || m.domainKind == "qemu" {
		return "qemu"
	}
	return "kvm"
}

// Console dials only a verified running domain's loopback graphics listener.
// The admission lock binds inspection and dial to the same local instance.
func (m *Manager) Console(ctx context.Context, id, owner string) (net.Conn, error) {
	if !nodeproto.ValidID(id) || !nodeproto.ValidID(owner) {
		return nil, ErrOwnership
	}
	m.admission.Lock()
	defer m.admission.Unlock()
	i, ok := m.Ledger.Instance(id)
	if !ok || i.OwnerRef != owner {
		return nil, ErrNotFound
	}
	if m.stopping || m.active || i.Suspended || i.GuestChange != nil || i.State == "uncertain" || i.State == "deleted" || i.PublicRetired || i.SourceFence != nil {
		return nil, ErrOwnership
	}
	if e := m.assertOwned(ctx, i); e != nil {
		return nil, e
	}
	state, e := m.state(ctx, i.Domain)
	if e != nil || state != "running" {
		return nil, ErrOwnership
	}
	raw, e := m.virsh(ctx, "dumpxml", i.Domain)
	var domain domainXML
	if e != nil || xml.Unmarshal(raw, &domain) != nil || len(domain.Devices.Graphics) != 1 || domain.Metadata.Instance.InstanceID != id || domain.Metadata.Instance.OwnerRef != owner {
		return nil, ErrOwnership
	}
	g := domain.Devices.Graphics[0]
	if g.Type != "vnc" || g.Listen != "127.0.0.1" || g.Port < 5900 || g.Port > 65535 || g.AutoPort != "yes" {
		return nil, ErrOwnership
	}
	for _, l := range g.Listeners {
		if l.Type != "address" || l.Address != "127.0.0.1" {
			return nil, ErrOwnership
		}
	}
	return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(g.Port)))
}

func (m *Manager) serveConsole(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(r.URL.Path, "/v1/instances/") || !strings.HasSuffix(r.URL.Path, "/console") {
		return false
	}
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/instances/"), "/console")
	owners := r.Header.Values("X-Aster-Owner-Ref")
	if r.Method != "GET" || !nodeproto.ValidID(id) || len(owners) != 1 || !nodeproto.ValidID(owners[0]) || r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Header.Values("Origin")) != 0 || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		respond(w, 404, errorBody("NOT_FOUND"))
		return true
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
	defer cancel()
	dialCtx, stop := context.WithTimeout(ctx, 10*time.Second)
	vnc, e := m.Console(dialCtx, id, owners[0])
	stop()
	if e != nil {
		respond(w, 409, errorBody("CONSOLE_UNAVAILABLE"))
		return true
	}
	defer vnc.Close()
	ws, e := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"binary"}, CompressionMode: websocket.CompressionDisabled})
	if e != nil {
		return true
	}
	defer ws.CloseNow()
	stream := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	ws.SetReadLimit(1 << 20)
	consolestream.Proxy(ctx, stream, vnc)
	return true
}

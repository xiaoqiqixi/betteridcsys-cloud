package control

import (
	"aster/billing/serviceapi"
	"aster/cloud/internal/consolestream"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

//go:embed guestconsole
var guestConsoleAssets embed.FS

var guestTicketPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

type consoleTicket struct {
	InstanceID, OwnerRef, NodeID string
	ExpiresAt                    time.Time
}

type GuestConsole struct {
	Store    ServiceStore
	Config   Config
	Origin   string
	Now      func() time.Time
	Dial     func(context.Context, NodeProfile, Instance) (net.Conn, error)
	mu       sync.Mutex
	tickets  map[[32]byte]consoleTicket
	sessions chan struct{}
}

func NewGuestConsole(store ServiceStore, config Config, origin string) (*GuestConsole, error) {
	u, e := url.Parse(origin)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, ErrInput
	}
	return &GuestConsole{Store: store, Config: config, Origin: origin, tickets: map[[32]byte]consoleTicket{}, sessions: make(chan struct{}, 64)}, nil
}
func (c *GuestConsole) now() time.Time {
	if c.Now != nil {
		return c.Now().UTC()
	}
	return time.Now().UTC()
}

func (c *GuestConsole) Issue(ctx context.Context, v Instance) (serviceapi.Console, error) {
	current, e := c.Store.Instance(ctx, v.ID)
	if e != nil || current.OwnerRef != v.OwnerRef || current.NodeID != v.NodeID || current.State == "deleted" || current.State == "uncertain" {
		return serviceapi.Console{}, ErrNotFound
	}
	flags, e := c.Store.ServiceFlags(ctx, v.ID)
	if e != nil || flags.Suspended {
		return serviceapi.Console{}, ErrState
	}
	now := c.now()
	caps, e := c.Store.ServiceCapability(ctx, c.Config, v.NodeID, now)
	if e != nil || !contains(caps.Actions, "console") {
		return serviceapi.Console{}, ErrState
	}
	var secret [32]byte
	if _, e = rand.Read(secret[:]); e != nil {
		return serviceapi.Console{}, ErrUnavailable
	}
	token := base64.RawURLEncoding.EncodeToString(secret[:])
	expires := now.Add(time.Minute)
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, t := range c.tickets {
		if !now.Before(t.ExpiresAt) {
			delete(c.tickets, key)
		}
	}
	if len(c.tickets) >= 4096 {
		return serviceapi.Console{}, ErrCapacity
	}
	if e := c.Store.RecordConsoleGrant(ctx, v, now); e != nil {
		return serviceapi.Console{}, e
	}
	c.tickets[sha256.Sum256([]byte(token))] = consoleTicket{v.ID, v.OwnerRef, v.NodeID, expires}
	return serviceapi.Console{URL: c.Origin + "/console/#" + token, ExpiresAt: expires}, nil
}
func (c *GuestConsole) consume(token string) (consoleTicket, bool) {
	if !guestTicketPattern.MatchString(token) {
		return consoleTicket{}, false
	}
	key := sha256.Sum256([]byte(token))
	c.mu.Lock()
	defer c.mu.Unlock()
	t, ok := c.tickets[key]
	delete(c.tickets, key)
	return t, ok && c.now().Before(t.ExpiresAt)
}

func (c *GuestConsole) Handler() http.Handler {
	assets, _ := fs.Sub(guestConsoleAssets, "guestconsole")
	files := http.FileServer(http.FS(assets))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'; form-action 'none'")
		if r.TLS == nil {
			failure(w, 426, "TLS_REQUIRED")
			return
		}
		origin, _ := url.Parse(c.Origin)
		if r.Host != origin.Host {
			failure(w, 403, "ORIGIN_REQUIRED")
			return
		}
		if r.URL.Path == "/console/ws" {
			c.websocket(w, r)
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" {
			failure(w, 405, "METHOD_NOT_ALLOWED")
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery || !strings.HasPrefix(r.URL.Path, "/console/") {
			failure(w, 404, "NOT_FOUND")
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/console/")
		if path == "" {
			path = "index.html"
		}
		if !fs.ValidPath(path) || strings.HasPrefix(path, ".") {
			failure(w, 404, "NOT_FOUND")
			return
		}
		info, e := fs.Stat(assets, path)
		if e != nil || info.IsDir() {
			failure(w, 404, "NOT_FOUND")
			return
		}
		copy := r.Clone(r.Context())
		urlCopy := *r.URL
		copy.URL = &urlCopy
		// FileServer redirects /index.html; ServeContent serves the fixed entry.
		if path == "index.html" {
			raw, _ := fs.ReadFile(assets, path)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if r.Method == "GET" {
				_, _ = w.Write(raw)
			}
			return
		}
		copy.URL.Path = "/" + path
		files.ServeHTTP(w, copy)
	})
}
func (c *GuestConsole) websocket(w http.ResponseWriter, r *http.Request) {
	origins := r.Header.Values("Origin")
	q := r.URL.Query()
	if r.Method != "GET" || len(origins) != 1 || origins[0] != c.Origin || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		failure(w, 403, "ORIGIN_REQUIRED")
		return
	}
	if len(q) != 1 || len(q["ticket"]) != 1 || r.URL.RawQuery != "ticket="+q.Get("ticket") {
		failure(w, 404, "TICKET_UNAVAILABLE")
		return
	}
	t, ok := c.consume(q.Get("ticket"))
	if !ok {
		failure(w, 404, "TICKET_UNAVAILABLE")
		return
	}
	select {
	case c.sessions <- struct{}{}:
		defer func() { <-c.sessions }()
	default:
		failure(w, 503, "CONSOLE_UNAVAILABLE")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
	defer cancel()
	v, e := c.Store.Instance(ctx, t.InstanceID)
	if e != nil || v.OwnerRef != t.OwnerRef || v.NodeID != t.NodeID || v.State == "deleted" || v.State == "uncertain" {
		failure(w, 404, "TICKET_UNAVAILABLE")
		return
	}
	p, ok := c.Config.Node(t.NodeID)
	if !ok {
		failure(w, 409, "CONSOLE_UNAVAILABLE")
		return
	}
	var node net.Conn
	if c.Dial != nil {
		node, e = c.Dial(ctx, p, v)
	} else {
		var client *NodeClient
		client, e = NewNodeClient(ctx, p)
		if e == nil {
			node, e = client.Console(ctx, v.ID, v.OwnerRef)
		}
	}
	if e != nil {
		failure(w, 409, "CONSOLE_UNAVAILABLE")
		return
	}
	defer node.Close()
	ws, e := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"binary"}, CompressionMode: websocket.CompressionDisabled})
	if e != nil {
		return
	}
	defer ws.CloseNow()
	stream := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	ws.SetReadLimit(1 << 20)
	consolestream.Proxy(ctx, stream, node)
}

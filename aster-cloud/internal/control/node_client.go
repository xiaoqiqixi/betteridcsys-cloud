package control

import (
	"aster/cloud/internal/nodeproto"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"sync/atomic"
	"time"
)

type NodeRPC interface {
	Send(context.Context, []byte, string) (nodeproto.NodeResult, error)
	Lookup(context.Context, string, string) (nodeproto.NodeResult, error)
	Capabilities(context.Context) (Capability, error)
}
type NodeClient struct {
	profile NodeProfile
	address string
	tls     *tls.Config
}

func NewNodeClient(ctx context.Context, p NodeProfile) (*NodeClient, error) {
	return newNodeClientOwned(ctx, p, 0)
}

func newNodeClientOwned(ctx context.Context, p NodeProfile, owner uint32) (*NodeClient, error) {
	if !p.Valid() {
		return nil, ErrInput
	}
	tlsConfig, e := loadNodeTLSOwned(p, owner)
	if e != nil {
		return nil, e
	}
	u, _ := url.Parse(p.Endpoint)
	port := u.Port()
	if port == "" {
		port = "443"
	}
	var addresses []netip.Addr
	if ip, e := netip.ParseAddr(u.Hostname()); e == nil {
		addresses = []netip.Addr{ip}
	} else {
		addresses, e = net.DefaultResolver.LookupNetIP(ctx, "ip", u.Hostname())
		if e != nil {
			return nil, ErrUnavailable
		}
	}
	if len(addresses) == 0 {
		return nil, ErrUnavailable
	}
	var prefixes []netip.Prefix
	for _, s := range p.AllowedCIDRs {
		v, _ := netip.ParsePrefix(s)
		prefixes = append(prefixes, v)
	}
	for _, ip := range addresses {
		allowed := false
		for _, cidr := range prefixes {
			if cidr.Contains(ip.Unmap()) {
				allowed = true
			}
		}
		if !allowed || ip.IsUnspecified() || ip.IsMulticast() || ip.Zone() != "" {
			return nil, ErrUnavailable
		}
	}
	sort.Slice(addresses, func(i, j int) bool { return addresses[i].Compare(addresses[j]) < 0 })
	return &NodeClient{p, net.JoinHostPort(addresses[0].String(), port), tlsConfig}, nil
}
func (c *NodeClient) call(ctx context.Context, method, path string, body []byte, sha string) ([]byte, error) {
	raw, _, e := c.callStatus(ctx, method, path, body, sha)
	return raw, e
}
func (c *NodeClient) callStatus(ctx context.Context, method, path string, body []byte, sha string) ([]byte, int, error) {
	return c.callStatusTimed(ctx, method, path, body, sha, 10*time.Second, 6*time.Second)
}
func (c *NodeClient) callStatusTimed(ctx context.Context, method, path string, body []byte, sha string, total, header time.Duration) ([]byte, int, error) {
	req, e := http.NewRequestWithContext(ctx, method, c.profile.Endpoint+path, bytes.NewReader(body))
	if e != nil {
		return nil, 0, ErrUnavailable
	}
	req.GetBody = nil
	req.Close = true
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if sha != "" {
		req.Header.Set("X-Request-SHA256", sha)
	}
	var dials atomic.Int32
	dialer := net.Dialer{Timeout: 3 * time.Second, KeepAlive: -1}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DisableCompression: true, ForceAttemptHTTP2: false, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}, TLSClientConfig: c.tls.Clone(), TLSHandshakeTimeout: 4 * time.Second, ResponseHeaderTimeout: header, MaxResponseHeaderBytes: 16 << 10, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		if !dials.CompareAndSwap(0, 1) {
			return nil, ErrUnavailable
		}
		return dialer.DialContext(ctx, network, c.address)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: total, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, e := client.Do(req)
	if e != nil {
		return nil, 0, ErrUnavailable
	}
	defer response.Body.Close()
	media, _, e := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if e != nil || media != "application/json" || response.Header.Get("Content-Encoding") != "" || response.StatusCode != 200 && response.StatusCode != 202 && response.StatusCode != 409 {
		return nil, 0, ErrUnavailable
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, 65537))
	if e != nil || len(raw) > 65536 {
		return nil, 0, ErrUnavailable
	}
	return raw, response.StatusCode, nil
}
func (c *NodeClient) Send(ctx context.Context, raw []byte, sha string) (nodeproto.NodeResult, error) {
	task, e := nodeproto.DecodeTask(raw)
	if e != nil || nodeproto.Digest(raw) != sha || task.NodeID != c.profile.ID {
		return nodeproto.NodeResult{}, ErrInput
	}
	out, e := c.call(ctx, http.MethodPost, "/v1/tasks", raw, sha)
	if e != nil {
		return nodeproto.NodeResult{}, e
	}
	var result nodeproto.NodeResult
	if !strict(out, &result) || !result.Matches(task, sha) {
		return nodeproto.NodeResult{}, ErrUnavailable
	}
	return result, nil
}
func (c *NodeClient) Lookup(ctx context.Context, op, sha string) (nodeproto.NodeResult, error) {
	if !nodeproto.ValidID(op) || !shaRE.MatchString(sha) {
		return nodeproto.NodeResult{}, ErrInput
	}
	raw, e := c.call(ctx, http.MethodGet, "/v1/tasks/"+op, nil, sha)
	if e != nil {
		return nodeproto.NodeResult{}, e
	}
	var result nodeproto.NodeResult
	if !strict(raw, &result) || result.OperationID != op || result.RequestSHA256 != sha {
		return nodeproto.NodeResult{}, ErrUnavailable
	}
	return result, nil
}
func (c *NodeClient) Capabilities(ctx context.Context) (Capability, error) {
	raw, e := c.call(ctx, http.MethodGet, "/v1/capabilities", nil, "")
	if e != nil {
		return Capability{}, e
	}
	var v Capability
	if !strict(raw, &v) || v.NodeID != c.profile.ID || v.Protocol != nodeproto.Protocol || v.ObservedAt == "" || !v.validNetworkCapabilities() {
		return Capability{}, ErrUnavailable
	}
	return v, nil
}

type Worker struct {
	Store  Store
	Config Config
	RPC    func(context.Context, NodeProfile) (NodeRPC, error)
	Now    func() time.Time
}

func (w Worker) now() time.Time {
	if w.Now != nil {
		return w.Now().UTC()
	}
	return time.Now().UTC()
}
func (w Worker) rpc(ctx context.Context, p NodeProfile) (NodeRPC, error) {
	if w.RPC != nil {
		return w.RPC(ctx, p)
	}
	return NewNodeClient(ctx, p)
}
func (w Worker) Dispatch(ctx context.Context, op string) (out Job, err error) {
	defer func() { logWorkerOutcome(ctx, "aster_controller_provisioning", "dispatch", op, out.State, err) }()
	j, e := w.Store.Lookup(ctx, op)
	if e != nil {
		return Job{}, e
	}
	p, ok := w.Config.Node(j.NodeID)
	if !ok || p.Digest() != j.NodeProfileSHA {
		return Job{}, ErrState
	}
	task, e := nodeproto.DecodeTask(j.NodeRequest)
	if e != nil || nodeproto.Digest(j.NodeRequest) != j.NodeRequestSHA || task.OperationID != j.OperationID || task.InstanceID != j.InstanceID || task.NodeID != j.NodeID || task.Action != "create" || !w.Config.approvesTaskNetwork(task) {
		return Job{}, ErrState
	}
	rpc, e := w.rpc(ctx, p)
	if e != nil {
		return Job{}, e
	}
	j, e = w.Store.Claim(ctx, op, p.Digest(), w.now(), time.Duration(w.Config.HeartbeatTTLSeconds)*time.Second)
	if e != nil {
		return Job{}, e
	}
	result, callErr := rpc.Send(ctx, j.NodeRequest, j.NodeRequestSHA)
	status := "uncertain"
	if callErr == nil && result.Matches(task, j.NodeRequestSHA) {
		status = result.Status
	}
	finish, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	saved, e := w.Store.Complete(finish, op, status, w.now())
	if e != nil {
		return Job{}, e
	}
	if callErr != nil {
		return saved, ErrUnavailable
	}
	return saved, nil
}
func (w Worker) Reconcile(ctx context.Context, op string) (out Job, err error) {
	defer func() { logWorkerOutcome(ctx, "aster_controller_provisioning", "reconcile", op, out.State, err) }()
	j, e := w.Store.Lookup(ctx, op)
	if e != nil {
		return Job{}, e
	}
	if j.State == "succeeded" || j.State == "rejected" {
		return j, nil
	}
	if j.State != "sending" && j.State != "uncertain" && j.State != "dispatched" {
		return Job{}, ErrState
	}
	p, ok := w.Config.Node(j.NodeID)
	if !ok || p.Digest() != j.NodeProfileSHA {
		return Job{}, ErrState
	}
	task, e := nodeproto.DecodeTask(j.NodeRequest)
	if e != nil || nodeproto.Digest(j.NodeRequest) != j.NodeRequestSHA {
		return Job{}, ErrState
	}
	rpc, e := w.rpc(ctx, p)
	if e != nil {
		return Job{}, e
	}
	result, e := rpc.Lookup(ctx, op, j.NodeRequestSHA)
	if e != nil || !result.Matches(task, j.NodeRequestSHA) {
		return j, ErrUnavailable
	}
	return w.Store.Complete(ctx, op, result.Status, w.now())
}

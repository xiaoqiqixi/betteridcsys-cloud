package control

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"net"
	"net/netip"
	"strings"
	"time"
)

func (c *NodeClient) Observe(ctx context.Context, instance string) (nodeproto.InstanceObservation, error) {
	if !nodeproto.ValidID(instance) {
		return nodeproto.InstanceObservation{}, ErrInput
	}
	raw, status, e := c.callStatus(ctx, "GET", "/v1/instances/"+instance, nil, "")
	if e != nil {
		return nodeproto.InstanceObservation{}, e
	}
	var failure struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if status == 409 && strict(raw, &failure) && failure.Error.Code == "LIVE_INSTANCE_OBSERVATION_UNCONFIRMED" {
		return nodeproto.InstanceObservation{}, ErrState
	}
	if status != 200 {
		return nodeproto.InstanceObservation{}, ErrUnavailable
	}
	var v nodeproto.InstanceObservation
	if !strict(raw, &v) || v.Protocol != nodeproto.InstanceProtocol || v.InstanceID != instance || v.NodeID != c.profile.ID || !nodeproto.ValidID(v.OwnerRef) {
		return v, ErrUnavailable
	}
	at, e := time.Parse(time.RFC3339Nano, v.ObservedAt)
	now := time.Now().UTC()
	if e != nil || at.After(now.Add(5*time.Second)) || now.Sub(at) > 5*time.Minute {
		return v, ErrUnavailable
	}
	if v.IPv4 != "" {
		ip, e := netip.ParseAddr(v.IPv4)
		if e != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() {
			return v, ErrUnavailable
		}
	}
	if v.MAC != "" {
		mac, e := net.ParseMAC(v.MAC)
		if e != nil || len(mac) != 6 || mac[0]&1 != 0 {
			return v, ErrUnavailable
		}
	}
	v.State = strings.ReplaceAll(v.State, " ", "_")
	if v.State == "shut_off" {
		v.State = "shutoff"
	}
	switch v.State {
	case "running", "shutoff", "paused", "in_shutdown", "crashed", "pmsuspended", "idle", "blocked":
	default:
		return v, ErrUnavailable
	}
	return v, nil
}

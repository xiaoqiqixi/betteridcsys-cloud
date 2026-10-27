package fabric

import (
	"aster/cloud/internal/overlayproto"
	"context"
	"encoding/json"
	"net/netip"
	"strings"
)

type natLink struct {
	Index     int      `json:"ifindex"`
	PeerIndex int      `json:"link_index"`
	Name      string   `json:"ifname"`
	MAC       string   `json:"address"`
	MTU       int      `json:"mtu"`
	Flags     []string `json:"flags"`
	Alias     string   `json:"ifalias"`
	Info      struct {
		Kind string `json:"info_kind"`
	} `json:"linkinfo"`
	Addresses []struct {
		Family string `json:"family"`
		Local  string `json:"local"`
		Prefix int    `json:"prefixlen"`
	} `json:"addr_info"`
}

func natAlias(node, profile, side string) string {
	return "aster-nat:" + node + ":" + profile + ":" + side
}
func validNATLink(v natLink, name, alias string, mtu int) bool {
	up := false
	for _, f := range v.Flags {
		if f == "UP" {
			up = true
		}
	}
	return v.Name == name && v.Index > 0 && v.PeerIndex > 0 && v.Info.Kind == "veth" && v.Alias == alias && v.MTU == mtu && up
}
func (e *Executor) probeNAT(ctx context.Context, c OverlayConfig, s overlayproto.Snapshot, p NATProfile) error {
	var g overlayproto.Gateway
	var vpc overlayproto.VPC
	for _, v := range c.Gateways {
		if v.InstanceID == p.GatewayInstanceID && v.NodeID == c.Base.NodeID {
			g = v
		}
	}
	for _, v := range s.VPCs {
		if v.ID == p.VPCID {
			vpc = v
		}
	}
	if vpc.ID == "" {
		vpc = overlayproto.VPC{ID: p.VPCID, CIDR: p.VPCCIDR}
	}
	if g.InstanceID == "" || vpc.CIDR != p.VPCCIDR {
		return ErrInvalid
	}
	raw, err := e.natRun(ctx, p, NATIP, "-j", "-d", "address", "show")
	if err != nil {
		return err
	}
	var links []natLink
	if json.Unmarshal(raw, &links) != nil || len(links) != 3 {
		return ErrUnavailable
	}
	var inside, outside natLink
	for _, l := range links {
		switch l.Name {
		case p.InsideInterface:
			inside = l
		case p.OutsideInterface:
			outside = l
		case "lo":
		default:
			return ErrUnavailable
		}
	}
	if !validNATLink(inside, p.InsideInterface, natAlias(c.Base.NodeID, p.ID, "inside"), c.GuestMTU) || !validNATLink(outside, p.OutsideInterface, natAlias(c.Base.NodeID, p.ID, "outside"), c.GuestMTU) || inside.MAC != g.MAC {
		return ErrUnavailable
	}
	prefix, _ := overlayproto.Prefix(vpc.CIDR)
	hasAddress := func(l natLink, ip string, bits int) bool {
		found := false
		for _, a := range l.Addresses {
			if a.Family == "inet" {
				if a.Local != ip || bits >= 0 && a.Prefix != bits || found {
					return false
				}
				found = true
			}
		}
		return found
	}
	if !hasAddress(inside, g.IPv4, prefix.Bits()) {
		return ErrUnavailable
	}
	selected := p.PublicIPv4
	for _, policy := range s.NATPolicies {
		if policy.NodeID == c.Base.NodeID && policy.ProfileID == p.ID && policy.GatewayInstanceID == p.GatewayInstanceID && policy.VPCID == p.VPCID {
			selected = natPolicyPublicIPv4(p, policy)
		}
	}
	if !natPublicIPv4Approved(p, selected) {
		return ErrUnavailable
	}
	// Pool approval alone is not proof that an address is usable. The root
	// default and the effective selected address must actually exist on this
	// dedicated outside veth. Other configured addresses must be in the same
	// independent root grant; an unconfigured approved reserve is permitted.
	outsideIPs, outsidePrefixes := map[string]bool{}, map[string]bool{}
	uplink, _ := netip.ParseAddr(p.UplinkGatewayIPv4)
	uplinkOnLink := false
	for _, a := range outside.Addresses {
		if a.Family != "inet" {
			continue
		}
		ip, err := netip.ParseAddr(a.Local)
		if err != nil || !ip.Is4() || ip.String() != a.Local || a.Prefix < 1 || a.Prefix > 32 || !natPublicIPv4Approved(p, a.Local) || outsideIPs[a.Local] {
			return ErrUnavailable
		}
		q := netip.PrefixFrom(ip, a.Prefix).Masked()
		outsideIPs[a.Local], outsidePrefixes[q.String()] = true, true
		if a.Local == p.PublicIPv4 && q.Contains(uplink) {
			uplinkOnLink = true
		}
	}
	for _, f := range s.FloatingIPs {
		if f.NodeID == c.Base.NodeID && f.ProfileID == p.ID && !outsideIPs[f.PublicIPv4] {
			return ErrUnavailable
		}
	}
	if !outsideIPs[p.PublicIPv4] || !outsideIPs[selected] || !uplinkOnLink {
		return ErrUnavailable
	}
	// A host-side peer is independently proven, never an arbitrary physical NIC.
	for _, pair := range []struct {
		name, side string
		peer       natLink
	}{{TAPName(g.InstanceID), "inside-peer", inside}, {p.OutsidePeer, "outside-peer", outside}} {
		raw, err = e.run(ctx, NATIP, "-j", "-d", "link", "show", "dev", pair.name)
		if err != nil {
			return err
		}
		var host []natLink
		if json.Unmarshal(raw, &host) != nil || len(host) != 1 || !validNATLink(host[0], pair.name, natAlias(c.Base.NodeID, p.ID, pair.side), c.GuestMTU) || host[0].Index != pair.peer.PeerIndex || host[0].PeerIndex != pair.peer.Index {
			return ErrUnavailable
		}
	}
	raw, err = e.natRun(ctx, p, NATIP, "-j", "-4", "route", "show", "table", "all")
	if err != nil {
		return err
	}
	var routes []struct {
		Dst     string `json:"dst"`
		Gateway string `json:"gateway"`
		Dev     string `json:"dev"`
		Table   any    `json:"table"`
		Type    string `json:"type"`
	}
	if json.Unmarshal(raw, &routes) != nil {
		return ErrUnavailable
	}
	var routeFields []map[string]json.RawMessage
	if json.Unmarshal(raw, &routeFields) != nil {
		return ErrUnavailable
	}
	for _, fields := range routeFields {
		for key, value := range fields {
			switch key {
			case "dst", "gateway", "dev", "protocol", "scope", "prefsrc", "table", "type":
			case "flags":
				var flags []any
				if json.Unmarshal(value, &flags) != nil || len(flags) != 0 {
					return ErrUnavailable
				}
			default:
				return ErrUnavailable
			}
		}
	}
	foundDefault, foundVPC, foundUplink := false, false, false
	for _, r := range routes {
		if r.Type == "local" || r.Type == "broadcast" {
			if r.Table != "local" && r.Table != float64(255) {
				return ErrUnavailable
			}
			address := strings.TrimSuffix(r.Dst, "/32")
			if r.Dev == "lo" {
				if r.Gateway != "" || address != "127.0.0.0/8" && address != "127.0.0.0" && address != "127.0.0.1" && address != "127.255.255.255" {
					return ErrUnavailable
				}
				continue
			}
			link := inside
			if r.Dev == p.OutsideInterface {
				link = outside
			} else if r.Dev != p.InsideInterface {
				return ErrUnavailable
			}
			valid := false
			for _, a := range link.Addresses {
				if a.Family != "inet" {
					continue
				}
				ip, _ := netip.ParseAddr(a.Local)
				prefix := netip.PrefixFrom(ip, a.Prefix).Masked()
				end := prefix.Addr().As4()
				for bit := a.Prefix; bit < 32; bit++ {
					end[bit/8] |= 1 << uint(7-bit%8)
				}
				broadcast := netip.AddrFrom4(end).String()
				if r.Type == "local" && address == a.Local || r.Type == "broadcast" && (address == prefix.Addr().String() || address == broadcast) {
					valid = true
				}
			}
			if !valid || r.Gateway != "" {
				return ErrUnavailable
			}
			continue
		}
		if r.Table != nil && r.Table != "main" && r.Table != float64(254) {
			return ErrUnavailable
		}
		if r.Dst == "default" {
			if foundDefault || r.Dev != p.OutsideInterface || r.Gateway != p.UplinkGatewayIPv4 {
				return ErrUnavailable
			}
			foundDefault = true
			continue
		}
		if r.Dst == vpc.CIDR && r.Dev == p.InsideInterface && r.Gateway == "" {
			foundVPC = true
			continue
		}
		q, err := netip.ParsePrefix(r.Dst)
		if err != nil || q.Masked() != q || r.Dev != p.OutsideInterface || r.Gateway != "" || !outsidePrefixes[r.Dst] || r.Type != "" && r.Type != "unicast" {
			return ErrUnavailable
		}
		if q.Contains(uplink) {
			foundUplink = true
		}
	}
	// With only the three exact kernel policy rules below, the exact on-link
	// uplink plus the one default route proves the selected configured source
	// leaves through this outside interface, not a management/other-node route.
	if !foundDefault || !foundVPC || !foundUplink {
		return ErrUnavailable
	}
	// Policy routing could bypass these exact routes. Only kernel defaults exist.
	raw, err = e.natRun(ctx, p, NATIP, "-j", "-4", "rule", "show")
	if err != nil {
		return err
	}
	var rules []struct {
		Priority int    `json:"priority"`
		Src      string `json:"src"`
		Table    string `json:"table"`
	}
	if json.Unmarshal(raw, &rules) != nil || len(rules) != 3 {
		return ErrUnavailable
	}
	var ruleFields []map[string]json.RawMessage
	if json.Unmarshal(raw, &ruleFields) != nil {
		return ErrUnavailable
	}
	for _, fields := range ruleFields {
		for key, value := range fields {
			switch key {
			case "priority", "src", "table":
			case "protocol":
				var protocol string
				if json.Unmarshal(value, &protocol) != nil || protocol != "kernel" {
					return ErrUnavailable
				}
			default:
				return ErrUnavailable
			}
		}
	}
	for i, r := range rules {
		if r.Priority != []int{0, 32766, 32767}[i] || r.Src != "all" || r.Table != []string{"local", "main", "default"}[i] {
			return ErrUnavailable
		}
	}
	if strings.Contains(p.Namespace, "/") {
		return ErrInvalid
	}
	return nil
}

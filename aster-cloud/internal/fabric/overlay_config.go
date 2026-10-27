package fabric

import (
	"aster/cloud/internal/overlayproto"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// OverlayConfig is a separate root approval. VXLAN itself does not authenticate
// peers: TrustedAck approves an independently isolated/authenticated underlay,
// and TrustReference records the operator's evidence, not an encryption claim.
type OverlayConfig struct {
	Schema                int                    `json:"schema"`
	Base                  Config                 `json:"base"`
	LocalIPv4             string                 `json:"local_ipv4"`
	UnderlayMTU           int                    `json:"underlay_mtu"`
	GuestMTU              int                    `json:"guest_mtu"`
	UnderlayTrustedAck    bool                   `json:"underlay_trusted_ack"`
	TrustReference        string                 `json:"trust_reference"`
	ProtectedCIDRs        []string               `json:"protected_cidrs"`
	Peers                 []OverlayPeer          `json:"peers"`
	Gateways              []overlayproto.Gateway `json:"gateways"`
	GuestNetworks         []OverlayGuestNetwork  `json:"guest_networks"`
	NATProfiles           []NATProfile           `json:"nat_profiles,omitempty"`
	PreviousProfileSHA256 string                 `json:"previous_profile_sha256,omitempty"`
}
type OverlayGuestNetwork struct {
	LocalVPCID          string   `json:"local_vpc_id"`
	VPCID               string   `json:"vpc_id,omitempty"`
	OwnerRef            string   `json:"owner_ref"`
	CIDR                string   `json:"cidr"`
	GatewayIPv4         string   `json:"gateway_ipv4"`
	AllowedPrefixes     []string `json:"allowed_prefixes"`
	AllowInternetEgress bool     `json:"allow_internet_egress,omitempty"`
	DNSIPv4             []string `json:"dns_ipv4,omitempty"`
}
type OverlayPeer struct {
	NodeID string `json:"node_id"`
	IPv4   string `json:"ipv4"`
}

func canonicalOverlayConfig(c OverlayConfig) (OverlayConfig, error) {
	if c.PreviousProfileSHA256 != "" && !overlayproto.ValidSHA(c.PreviousProfileSHA256) {
		return c, ErrInvalid
	}
	ip, e := netip.ParseAddr(c.LocalIPv4)
	if c.Schema != 1 || !c.Base.Validate() || e != nil || !ip.Is4() || !ip.IsGlobalUnicast() || ip.String() != c.LocalIPv4 || !c.UnderlayTrustedAck || len(c.TrustReference) < 1 || len(c.TrustReference) > 160 || strings.ContainsAny(c.TrustReference, "\x00\r\n") || c.UnderlayMTU < 1280 || c.UnderlayMTU > 9216 || c.GuestMTU < 576 || c.GuestMTU > c.UnderlayMTU-50 || c.ProtectedCIDRs == nil || len(c.ProtectedCIDRs) < 1 || len(c.ProtectedCIDRs) > 64 || c.Peers == nil || len(c.Peers) > 31 || c.Gateways == nil || len(c.Gateways) > 32 || c.GuestNetworks == nil || len(c.GuestNetworks) > 32 {
		return OverlayConfig{}, ErrInvalid
	}
	c.Peers = append([]OverlayPeer{}, c.Peers...)
	c.ProtectedCIDRs = append([]string{}, c.ProtectedCIDRs...)
	c.Gateways = append([]overlayproto.Gateway{}, c.Gateways...)
	sort.Slice(c.Peers, func(i, j int) bool { return c.Peers[i].NodeID < c.Peers[j].NodeID })
	sort.Strings(c.ProtectedCIDRs)
	sort.Slice(c.Gateways, func(i, j int) bool { return c.Gateways[i].VPCID < c.Gateways[j].VPCID })
	peers := map[string]bool{}
	ips := map[string]bool{c.LocalIPv4: true}
	for _, p := range c.Peers {
		a, e := netip.ParseAddr(p.IPv4)
		if !nodeRE.MatchString(p.NodeID) || p.NodeID == c.Base.NodeID || peers[p.NodeID] || e != nil || !a.Is4() || !a.IsGlobalUnicast() || a.String() != p.IPv4 || ips[p.IPv4] {
			return OverlayConfig{}, ErrInvalid
		}
		peers[p.NodeID] = true
		ips[p.IPv4] = true
	}
	for i, p := range c.ProtectedCIDRs {
		if _, ok := overlayproto.Prefix(p); !ok || i > 0 && c.ProtectedCIDRs[i-1] == p {
			return OverlayConfig{}, ErrInvalid
		}
	}
	for i, g := range c.Gateways {
		if !nodeRE.MatchString(g.NodeID) || !idRE.MatchString(g.InstanceID) || g.InterfaceID != InterfaceID(g.InstanceID) || !idRE.MatchString(g.OwnerRef) || !idRE.MatchString(g.VPCID) || g.AllowedPrefixes == nil || len(g.AllowedPrefixes) > 32 || i > 0 && c.Gateways[i-1].VPCID == g.VPCID {
			return OverlayConfig{}, ErrInvalid
		}
		g.AllowedPrefixes = append([]string{}, g.AllowedPrefixes...)
		sort.Strings(g.AllowedPrefixes)
		for j, r := range g.AllowedPrefixes {
			p, ok := overlayproto.Prefix(r)
			if !ok || j > 0 && g.AllowedPrefixes[j-1] == r {
				return OverlayConfig{}, ErrInvalid
			}
			for _, blocked := range append(append([]string{}, c.ProtectedCIDRs...), "0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4") {
				q, _ := netip.ParsePrefix(blocked)
				if p.Overlaps(q) {
					return OverlayConfig{}, ErrInvalid
				}
			}
			for a := range ips {
				ip, _ := netip.ParseAddr(a)
				if p.Contains(ip) {
					return OverlayConfig{}, ErrInvalid
				}
			}
		}
		c.Gateways[i] = g
	}
	c.GuestNetworks = append([]OverlayGuestNetwork{}, c.GuestNetworks...)
	sort.Slice(c.GuestNetworks, func(i, j int) bool { return c.GuestNetworks[i].LocalVPCID < c.GuestNetworks[j].LocalVPCID })
	for i, g := range c.GuestNetworks {
		p, ok := overlayproto.Prefix(g.CIDR)
		if !ok || !p.Addr().IsPrivate() || p.Bits() < 8 || p.Bits() > 30 || !idRE.MatchString(g.LocalVPCID) || !idRE.MatchString(g.OwnerRef) || !overlayproto.Usable(g.GatewayIPv4, p) || g.AllowedPrefixes == nil || len(g.AllowedPrefixes) > 32 || i > 0 && c.GuestNetworks[i-1].LocalVPCID == g.LocalVPCID || g.VPCID != "" && !idRE.MatchString(g.VPCID) || g.AllowInternetEgress && !idRE.MatchString(g.VPCID) {
			return OverlayConfig{}, ErrInvalid
		}
		g.AllowedPrefixes = append([]string{}, g.AllowedPrefixes...)
		sort.Strings(g.AllowedPrefixes)
		if len(g.DNSIPv4) > 4 {
			return OverlayConfig{}, ErrInvalid
		}
		g.DNSIPv4 = append([]string(nil), g.DNSIPv4...)
		dns := map[string]bool{}
		for _, raw := range g.DNSIPv4 {
			a, e := netip.ParseAddr(raw)
			if e != nil || !a.Is4() || a.String() != raw || !a.IsGlobalUnicast() || dns[raw] || !(g.AllowInternetEgress && overlayproto.PublicInternetIPv4(raw) || prefixSubset(raw+"/32", g.AllowedPrefixes)) {
				return OverlayConfig{}, ErrInvalid
			}
			dns[raw] = true
		}
		found := false
		for _, gw := range c.Gateways {
			a, _ := json.Marshal(g.AllowedPrefixes)
			b, _ := json.Marshal(gw.AllowedPrefixes)
			if gw.OwnerRef == g.OwnerRef && gw.IPv4 == g.GatewayIPv4 && string(a) == string(b) && (g.VPCID == "" || g.VPCID == gw.VPCID) {
				found = true
			}
		}
		if !found {
			return OverlayConfig{}, ErrInvalid
		}
		c.GuestNetworks[i] = g
	}
	if err := canonicalNATConfig(&c); err != nil {
		return c, err
	}
	return c, nil
}
func OverlayConfigSHA256(c OverlayConfig) (string, error) {
	c, e := canonicalOverlayConfig(c)
	if e != nil {
		return "", e
	}
	raw, e := json.Marshal(c)
	if e != nil {
		return "", ErrInvalid
	}
	return overlayproto.Digest(raw), nil
}
func DecodeOverlayConfig(raw []byte) (OverlayConfig, error) {
	var c OverlayConfig
	keys := []string{"schema", "base", "local_ipv4", "underlay_mtu", "guest_mtu", "underlay_trusted_ack", "trust_reference", "protected_cidrs", "peers", "gateways", "guest_networks"}
	var outer map[string]json.RawMessage
	_ = json.Unmarshal(raw, &outer)
	if _, ok := outer["nat_profiles"]; ok {
		keys = append(keys, "nat_profiles")
	}
	if _, ok := outer["previous_profile_sha256"]; ok {
		keys = append(keys, "previous_profile_sha256")
	}
	if object(raw, keys, &c) != nil {
		return c, ErrInvalid
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	if _, e := DecodeConfig(fields["base"]); e != nil {
		return c, ErrInvalid
	}
	var peers, gateways []json.RawMessage
	_ = json.Unmarshal(fields["peers"], &peers)
	_ = json.Unmarshal(fields["gateways"], &gateways)
	for _, r := range peers {
		var p OverlayPeer
		if object(r, []string{"node_id", "ipv4"}, &p) != nil {
			return c, ErrInvalid
		}
	}
	for _, r := range gateways {
		var g overlayproto.Gateway
		if object(r, []string{"node_id", "instance_id", "interface_id", "owner_ref", "vpc_id", "ipv4", "mac", "allowed_prefixes"}, &g) != nil {
			return c, ErrInvalid
		}
	}
	var networks []json.RawMessage
	_ = json.Unmarshal(fields["guest_networks"], &networks)
	for _, r := range networks {
		var g OverlayGuestNetwork
		guestKeys := []string{"local_vpc_id", "owner_ref", "cidr", "gateway_ipv4", "allowed_prefixes"}
		var guestFields map[string]json.RawMessage
		_ = json.Unmarshal(r, &guestFields)
		for _, key := range []string{"vpc_id", "allow_internet_egress", "dns_ipv4"} {
			if _, ok := guestFields[key]; ok {
				guestKeys = append(guestKeys, key)
			}
		}
		if object(r, guestKeys, &g) != nil {
			return c, ErrInvalid
		}
		if value, exists := guestFields["dns_ipv4"]; exists && string(value) == "null" {
			return c, ErrInvalid
		}
	}
	var profiles []json.RawMessage
	if r, ok := fields["nat_profiles"]; ok {
		if json.Unmarshal(r, &profiles) != nil || profiles == nil {
			return c, ErrInvalid
		}
		for _, r := range profiles {
			var p NATProfile
			natKeys := []string{"id", "namespace", "namespace_device", "namespace_inode", "dedicated_ack", "vpc_id", "vpc_cidr", "gateway_instance_id", "inside_interface", "outside_interface", "outside_peer", "public_ipv4", "uplink_gateway_ipv4", "allow_snat", "allowed_source_cidrs", "allowed_ports"}
			var natFields map[string]json.RawMessage
			_ = json.Unmarshal(r, &natFields)
			for _, key := range []string{"previous_profile_sha256", "retired_previous_namespace_ack", "allow_internet_egress", "public_ipv4s", "allow_floating_ip"} {
				if _, ok := natFields[key]; ok {
					natKeys = append(natKeys, key)
				}
			}
			if object(r, natKeys, &p) != nil {
				return c, ErrInvalid
			}
			var f map[string]json.RawMessage
			_ = json.Unmarshal(r, &f)
			var ports []json.RawMessage
			_ = json.Unmarshal(f["allowed_ports"], &ports)
			for _, rr := range ports {
				var pp NATPortRange
				if object(rr, []string{"protocol", "start", "end"}, &pp) != nil {
					return c, ErrInvalid
				}
			}
		}
	}
	return canonicalOverlayConfig(c)
}
func LoadOverlayConfig(path string) (OverlayConfig, error) {
	raw, e := readPrivate(path, 0, 65536)
	if e != nil {
		return OverlayConfig{}, e
	}
	return DecodeOverlayConfig(raw)
}

// The ownership marker is written before any overlay host mutation. Older
// single-host entrypoints may not replace flows after this irreversible opt-in.
func legacyOverlayGuard(c Config) error {
	if _, e := os.Lstat(filepath.Join(c.StateDirectory, "overlay.owner")); os.IsNotExist(e) {
		return nil
	}
	return ErrConflict
}
func overlayTunnelName(local, peer string) string {
	return "ax" + overlayproto.Digest([]byte(local + ":" + peer))[:12]
}
func overlayTunnelID(local, peer string) string {
	return namedUUID("aster.overlay.tunnel/1:", overlayproto.Digest([]byte(local + ":" + peer))[:32])
}
func validateOverlayApproval(c OverlayConfig, s overlayproto.Snapshot) (OverlayConfig, overlayproto.Snapshot, string, error) {
	c, e := canonicalOverlayConfig(c)
	if e != nil {
		return c, s, "", e
	}
	s, d, e := overlayproto.CanonicalSnapshot(s)
	if e != nil {
		return c, s, "", ErrInvalid
	}
	sha, _ := OverlayConfigSHA256(c)
	found := false
	peers := map[string]bool{}
	for _, p := range c.Peers {
		peers[p.NodeID] = true
	}
	for _, p := range s.Profiles {
		if p.NodeID == c.Base.NodeID {
			if p.ProfileSHA256 != sha {
				return c, s, "", ErrConflict
			}
			found = true
		} else if !peers[p.NodeID] {
			return c, s, "", ErrInvalid
		}
	}
	if !found {
		return c, s, "", ErrInvalid
	}
	for _, g := range s.Gateways {
		found := false
		for _, root := range c.Gateways {
			if gatewaySubset(g, root) {
				found = true
			}
		}
		if !found {
			return c, s, "", ErrConflict
		}
	}
	if validateNATApproval(c, s) != nil {
		return c, s, "", ErrConflict
	}
	if !internetGuestApproval(c, s) {
		return c, s, "", ErrConflict
	}
	names := map[string]bool{}
	for _, m := range s.Members {
		if m.NodeID == c.Base.NodeID {
			n := TAPName(m.InstanceID)
			if names[n] {
				return c, s, "", ErrInvalid
			}
			names[n] = true
		}
	}
	for _, g := range c.Gateways {
		if g.NodeID == c.Base.NodeID {
			n := TAPName(g.InstanceID)
			if names[n] {
				return c, s, "", ErrInvalid
			}
			names[n] = true
		}
	}
	for _, gn := range c.GuestNetworks {
		for _, m := range s.Members {
			if m.NodeID != c.Base.NodeID || m.LocalVPCID != gn.LocalVPCID {
				continue
			}
			found := false
			for _, v := range s.VPCs {
				if v.ID != m.VPCID {
					continue
				}
				if gn.OwnerRef != m.OwnerRef || gn.CIDR != v.CIDR || gn.VPCID != "" && gn.VPCID != m.VPCID {
					return c, s, "", ErrConflict
				}
				for _, g := range s.Gateways {
					if g.VPCID == v.ID && g.IPv4 == gn.GatewayIPv4 {
						found = true
						for _, r := range g.AllowedPrefixes {
							if !prefixSubset(r, gn.AllowedPrefixes) {
								found = false
							}
						}
					}
				}
			}
			selected := false
			for _, g := range s.Gateways {
				if g.VPCID == m.VPCID {
					selected = true
				}
			}
			if selected && !found {
				return c, s, "", ErrConflict
			}
		}
	}
	return c, s, d, nil
}

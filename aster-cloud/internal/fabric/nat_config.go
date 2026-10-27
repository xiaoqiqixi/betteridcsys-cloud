package fabric

import (
	"aster/cloud/internal/overlayproto"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// NATProfile approves an already prepared dedicated namespace. The service never
// creates its uplink or changes host routes, physical NICs, nftables or sysctls.
// Device/inode bind this approval to one namespace lifetime (reapprove on rebuild).
type NATProfile struct {
	ID                          string         `json:"id"`
	PreviousProfileSHA256       string         `json:"previous_profile_sha256,omitempty"`
	RetiredPreviousNamespaceAck bool           `json:"retired_previous_namespace_ack,omitempty"`
	Namespace                   string         `json:"namespace"`
	NamespaceDevice             uint64         `json:"namespace_device"`
	NamespaceInode              uint64         `json:"namespace_inode"`
	DedicatedAck                bool           `json:"dedicated_ack"`
	VPCID                       string         `json:"vpc_id"`
	VPCCIDR                     string         `json:"vpc_cidr"`
	GatewayInstanceID           string         `json:"gateway_instance_id"`
	InsideInterface             string         `json:"inside_interface"`
	OutsideInterface            string         `json:"outside_interface"`
	OutsidePeer                 string         `json:"outside_peer"`
	PublicIPv4                  string         `json:"public_ipv4"`
	PublicIPv4s                 []string       `json:"public_ipv4s,omitempty"`
	UplinkGatewayIPv4           string         `json:"uplink_gateway_ipv4"`
	AllowSNAT                   bool           `json:"allow_snat"`
	AllowInternetEgress         bool           `json:"allow_internet_egress,omitempty"`
	AllowFloatingIP             bool           `json:"allow_floating_ip,omitempty"`
	AllowedSourceCIDRs          []string       `json:"allowed_source_cidrs"`
	AllowedPorts                []NATPortRange `json:"allowed_ports"`
}
type NATPortRange struct {
	Protocol string `json:"protocol"`
	Start    int    `json:"start"`
	End      int    `json:"end"`
}

func canonicalNATProfile(p NATProfile) (NATProfile, error) {
	if p.AllowFloatingIP && !p.AllowInternetEgress {
		return p, ErrInvalid
	}
	if p.AllowInternetEgress && (!p.AllowSNAT || !overlayproto.PublicInternetIPv4(p.PublicIPv4)) {
		return p, ErrInvalid
	}
	if p.PreviousProfileSHA256 != "" && !overlayproto.ValidSHA(p.PreviousProfileSHA256) || p.RetiredPreviousNamespaceAck && p.PreviousProfileSHA256 == "" {
		return p, ErrInvalid
	}
	vp, vpok := overlayproto.Prefix(p.VPCCIDR)
	a, ae := netip.ParseAddr(p.PublicIPv4)
	g, ge := netip.ParseAddr(p.UplinkGatewayIPv4)
	if !vpok || !vp.Addr().IsPrivate() || vp.Bits() < 8 || vp.Bits() > 30 || !nodeRE.MatchString(p.ID) || !strings.HasPrefix(p.Namespace, "aster-") || !nodeRE.MatchString(p.Namespace) || p.NamespaceDevice == 0 || p.NamespaceInode == 0 || !p.DedicatedAck || !idRE.MatchString(p.VPCID) || !idRE.MatchString(p.GatewayInstanceID) || !nameRE.MatchString(p.InsideInterface) || !nameRE.MatchString(p.OutsideInterface) || !nameRE.MatchString(p.OutsidePeer) || p.InsideInterface == p.OutsideInterface || p.OutsidePeer == TAPName(p.GatewayInstanceID) || ae != nil || ge != nil || !a.Is4() || !g.Is4() || !a.IsGlobalUnicast() || !g.IsGlobalUnicast() || a == g || vp.Contains(a) || vp.Contains(g) || a.String() != p.PublicIPv4 || g.String() != p.UplinkGatewayIPv4 || p.AllowedSourceCIDRs == nil || len(p.AllowedSourceCIDRs) > 32 || p.AllowedPorts == nil || len(p.AllowedPorts) > 64 {
		return p, ErrInvalid
	}
	if len(p.PublicIPv4s) > 64 {
		return p, ErrInvalid
	}
	// Extra pool addresses are an independent, bounded root grant. An empty
	// grant is omitted, preserving every historical profile and owner digest.
	if len(p.PublicIPv4s) > 0 {
		addresses := append([]string{}, p.PublicIPv4s...)
		sort.Strings(addresses)
		p.PublicIPv4s = nil
		for _, ip := range addresses {
			if !overlayproto.PublicInternetIPv4(ip) || ip == p.PublicIPv4 || ip == p.UplinkGatewayIPv4 {
				return p, ErrInvalid
			}
			if len(p.PublicIPv4s) == 0 || p.PublicIPv4s[len(p.PublicIPv4s)-1] != ip {
				p.PublicIPv4s = append(p.PublicIPv4s, ip)
			}
		}
	} else {
		p.PublicIPv4s = nil
	}
	p.AllowedSourceCIDRs = append([]string{}, p.AllowedSourceCIDRs...)
	sort.Strings(p.AllowedSourceCIDRs)
	for i, r := range p.AllowedSourceCIDRs {
		q, ok := overlayproto.Prefix(r)
		if !ok || q.Bits() == 0 || q.Overlaps(vp) || i > 0 && r == p.AllowedSourceCIDRs[i-1] {
			return p, ErrInvalid
		}
	}
	p.AllowedPorts = append([]NATPortRange{}, p.AllowedPorts...)
	sort.Slice(p.AllowedPorts, func(i, j int) bool {
		if p.AllowedPorts[i].Protocol != p.AllowedPorts[j].Protocol {
			return p.AllowedPorts[i].Protocol < p.AllowedPorts[j].Protocol
		}
		return p.AllowedPorts[i].Start < p.AllowedPorts[j].Start
	})
	for i, r := range p.AllowedPorts {
		if (r.Protocol != "tcp" && r.Protocol != "udp") || r.Start < 1 || r.End > 65535 || r.Start > r.End || i > 0 && p.AllowedPorts[i-1].Protocol == r.Protocol && p.AllowedPorts[i-1].End >= r.Start {
			return p, ErrInvalid
		}
	}
	return p, nil
}

// natProfilePublicIPv4s returns a fresh list including the legacy default.
func natProfilePublicIPv4s(p NATProfile) []string {
	return append([]string{p.PublicIPv4}, p.PublicIPv4s...)
}

func natPolicyPublicIPv4(root NATProfile, policy overlayproto.NATPolicy) string {
	if policy.PublicIPv4 != "" {
		return policy.PublicIPv4
	}
	return root.PublicIPv4
}

func natPublicIPv4Approved(root NATProfile, ip string) bool {
	for _, allowed := range natProfilePublicIPv4s(root) {
		if ip == allowed {
			return true
		}
	}
	return false
}

func NATProfileSHA256(p NATProfile) (string, error) {
	p, e := canonicalNATProfile(p)
	if e != nil {
		return "", e
	}
	raw, _ := json.Marshal(p)
	return overlayproto.Digest(raw), nil
}
func prefixSubset(raw string, allowed []string) bool {
	p, ok := overlayproto.Prefix(raw)
	if !ok {
		return false
	}
	for _, r := range allowed {
		q, ok := overlayproto.Prefix(r)
		if ok && q.Bits() <= p.Bits() && q.Contains(p.Addr()) {
			return true
		}
	}
	return false
}
func gatewaySubset(want, root overlayproto.Gateway) bool {
	a, b := want, root
	a.AllowedPrefixes = nil
	b.AllowedPrefixes = nil
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	if string(x) != string(y) {
		return false
	}
	for _, r := range want.AllowedPrefixes {
		if !prefixSubset(r, root.AllowedPrefixes) {
			return false
		}
	}
	return true
}
func natGatewayProfile(c OverlayConfig, gateway string) (NATProfile, bool) {
	for _, p := range c.NATProfiles {
		if p.GatewayInstanceID == gateway {
			return p, true
		}
	}
	return NATProfile{}, false
}
func canonicalNATConfig(c *OverlayConfig) error {
	if len(c.NATProfiles) > 32 {
		return ErrInvalid
	}
	if len(c.NATProfiles) == 0 {
		c.NATProfiles = nil
		return nil
	}
	c.NATProfiles = append([]NATProfile{}, c.NATProfiles...)
	sort.Slice(c.NATProfiles, func(i, j int) bool { return c.NATProfiles[i].ID < c.NATProfiles[j].ID })
	used := map[string]bool{}
	for i, p := range c.NATProfiles {
		var e error
		p, e = canonicalNATProfile(p)
		if e != nil {
			return e
		}
		for _, public := range p.PublicIPv4s {
			for _, other := range c.NATProfiles {
				if public == other.UplinkGatewayIPv4 {
					return ErrInvalid
				}
			}
		}
		for _, key := range []string{"id:" + p.ID, "ns:" + p.Namespace, fmt.Sprintf("inode:%d:%d", p.NamespaceDevice, p.NamespaceInode), "vpc:" + p.VPCID, "gw:" + p.GatewayInstanceID, "ip:" + p.PublicIPv4, "peer:" + p.OutsidePeer} {
			if used[key] {
				return ErrInvalid
			}
			used[key] = true
		}
		found := false
		for _, g := range c.Gateways {
			if g.NodeID == c.Base.NodeID && g.InstanceID == p.GatewayInstanceID && g.VPCID == p.VPCID {
				vp, _ := overlayproto.Prefix(p.VPCCIDR)
				if !overlayproto.Usable(g.IPv4, vp) {
					return ErrInvalid
				}
				found = true
			}
		}
		if !found {
			return ErrInvalid
		}
		protected := append(append([]string{}, c.ProtectedCIDRs...), "0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4")
		ips := []string{c.LocalIPv4}
		for _, peer := range c.Peers {
			ips = append(ips, peer.IPv4)
		}
		for _, source := range p.AllowedSourceCIDRs {
			q, _ := overlayproto.Prefix(source)
			for _, b := range protected {
				r, _ := overlayproto.Prefix(b)
				if q.Overlaps(r) {
					return ErrInvalid
				}
			}
			for _, ip := range ips {
				a, _ := netip.ParseAddr(ip)
				if q.Contains(a) {
					return ErrInvalid
				}
			}
		}
		for _, public := range append(natProfilePublicIPv4s(p), p.UplinkGatewayIPv4) {
			a, _ := netip.ParseAddr(public)
			for _, b := range protected {
				r, _ := overlayproto.Prefix(b)
				if r.Contains(a) {
					return ErrInvalid
				}
			}
			for _, ip := range ips {
				if ip == public {
					return ErrInvalid
				}
			}
		}
		c.NATProfiles[i] = p
	}
	return nil
}
func validateNATApproval(c OverlayConfig, s overlayproto.Snapshot) error {
	usedPublic := map[string]bool{}
	for _, p := range s.NATPolicies {
		if p.NodeID != c.Base.NodeID {
			continue
		}
		root, ok := natGatewayProfile(c, p.GatewayInstanceID)
		sha, e := NATProfileSHA256(root)
		if !ok || e != nil || root.ID != p.ProfileID || root.VPCID != p.VPCID || sha != p.ProfileSHA256 || p.SNATEnabled && !root.AllowSNAT || p.InternetEgressEnabled && !root.AllowInternetEgress {
			return ErrConflict
		}
		public := natPolicyPublicIPv4(root, p)
		if !natPublicIPv4Approved(root, public) || usedPublic[public] {
			return ErrConflict
		}
		usedPublic[public] = true
		for _, f := range p.Forwardings {
			var gateway overlayproto.Gateway
			for _, g := range s.Gateways {
				if g.InstanceID == p.GatewayInstanceID {
					gateway = g
				}
			}
			if !prefixSubset(f.SourceCIDR, gateway.AllowedPrefixes) || !prefixSubset(f.SourceCIDR, root.AllowedSourceCIDRs) {
				return ErrConflict
			}
			allowed := false
			for _, r := range root.AllowedPorts {
				if r.Protocol == f.Protocol && f.PublicPort >= r.Start && f.PublicPort <= r.End {
					allowed = true
				}
			}
			if !allowed {
				return ErrConflict
			}
		}
	}
	for _, f := range s.FloatingIPs {
		if f.NodeID != c.Base.NodeID {
			continue
		}
		root, ok := natGatewayProfile(c, f.GatewayInstanceID)
		sha, err := NATProfileSHA256(root)
		if !ok || err != nil || !root.AllowFloatingIP || !root.AllowInternetEgress || root.ID != f.ProfileID || root.VPCID != f.VPCID || sha != f.ProfileSHA256 || !natPublicIPv4Approved(root, f.PublicIPv4) || usedPublic[f.PublicIPv4] {
			return ErrConflict
		}
		usedPublic[f.PublicIPv4] = true
	}
	for _, p := range c.NATProfiles {
		for _, v := range s.VPCs {
			q, _ := overlayproto.Prefix(v.CIDR)
			if v.ID == p.VPCID && v.CIDR != p.VPCCIDR {
				return ErrConflict
			}
			for _, ip := range append(natProfilePublicIPv4s(p), p.UplinkGatewayIPv4) {
				a, _ := netip.ParseAddr(ip)
				if q.Contains(a) {
					return ErrConflict
				}
			}
			for _, source := range p.AllowedSourceCIDRs {
				r, _ := overlayproto.Prefix(source)
				if q.Overlaps(r) {
					return ErrConflict
				}
			}
		}
	}
	return nil
}

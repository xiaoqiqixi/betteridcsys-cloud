package control

import (
	"aster/cloud/internal/nodeproto"
	"aster/cloud/internal/overlayproto"
	"net"
	"net/netip"
)

// Only safe approval metadata is exposed to console users. A controller never
// receives a namespace/device/path from an HTTP request. The pinned node's root
// config is the independent final authority for execution.
type OverlayNATProfile struct {
	NodeID              string                `json:"node_id"`
	VPCID               string                `json:"vpc_id"`
	GatewayInstanceID   string                `json:"gateway_instance_id"`
	ProfileID           string                `json:"profile_id"`
	ProfileSHA256       string                `json:"profile_sha256"`
	PublicIPv4          string                `json:"public_ipv4"`
	PublicIPv4s         []string              `json:"public_ipv4s,omitempty"`
	AllowSNAT           bool                  `json:"allow_snat"`
	AllowFloatingIP     bool                  `json:"allow_floating_ip,omitempty"`
	AllowInternetEgress bool                  `json:"allow_internet_egress,omitempty"`
	AllowedSourceCIDRs  []string              `json:"allowed_source_cidrs"`
	AllowedPorts        []OverlayNATPortRange `json:"allowed_ports"`
}
type OverlayNATPortRange struct {
	Protocol string `json:"protocol"`
	Start    int    `json:"start"`
	End      int    `json:"end"`
}

func prefixWithin(raw string, allowed []string) bool {
	p, ok := overlayproto.Prefix(raw)
	if !ok || p.Bits() == 0 {
		return false
	}
	for _, value := range allowed {
		root, valid := overlayproto.Prefix(value)
		if valid && p.Bits() >= root.Bits() && root.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

func validOverlayPolicyApproval(cluster OverlayCluster, nodes map[string]bool) bool {
	if len(cluster.Gateways) > 32 || len(cluster.NATProfiles) > 32 {
		return false
	}
	gateways, gatewayIDs, gatewayIPs, macs := map[string]overlayproto.Gateway{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, g := range cluster.Gateways {
		ip, err := netip.ParseAddr(g.IPv4)
		mac, me := net.ParseMAC(g.MAC)
		if !nodes[g.NodeID] || !nodeproto.ValidID(g.VPCID) || !nodeproto.ValidID(g.OwnerRef) || !nodeproto.ValidID(g.InstanceID) || g.InterfaceID != nodeproto.NetworkInterfaceID(g.InstanceID) || gateways[g.VPCID].InstanceID != "" || gatewayIDs[g.InstanceID] || gatewayIPs[g.VPCID+":"+g.IPv4] || macs[g.MAC] || err != nil || !ip.Is4() || !ip.IsPrivate() || ip.String() != g.IPv4 || me != nil || len(mac) != 6 || mac.String() != g.MAC || mac[0]&1 != 0 || g.MAC == "00:00:00:00:00:00" || g.AllowedPrefixes == nil || len(g.AllowedPrefixes) > 32 {
			return false
		}
		prefixes := map[string]bool{}
		for _, value := range g.AllowedPrefixes {
			p, ok := overlayproto.Prefix(value)
			if !ok || p.Bits() == 0 || prefixes[value] || p.Contains(ip) {
				return false
			}
			prefixes[value] = true
		}
		gateways[g.VPCID], gatewayIDs[g.InstanceID], gatewayIPs[g.VPCID+":"+g.IPv4], macs[g.MAC] = g, true, true, true
	}
	profiles, public, natVPCs, natGateways := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, p := range cluster.NATProfiles {
		g := gateways[p.VPCID]
		ip, err := netip.ParseAddr(p.PublicIPv4)
		key := p.NodeID + ":" + p.ProfileID
		if !nodes[p.NodeID] || !nodeproto.ValidID(p.VPCID) || !nodeproto.ValidNodeID(p.ProfileID) || !overlayproto.ValidSHA(p.ProfileSHA256) || g.NodeID != p.NodeID || g.InstanceID != p.GatewayInstanceID || profiles[key] || public[p.NodeID+":"+p.PublicIPv4] || natVPCs[p.VPCID] || natGateways[p.GatewayInstanceID] || err != nil || !ip.Is4() || !ip.IsGlobalUnicast() || ip.String() != p.PublicIPv4 || p.AllowedSourceCIDRs == nil || len(p.AllowedSourceCIDRs) > 32 || p.AllowedPorts == nil || len(p.AllowedPorts) > 64 {
			return false
		}
		if !validPublicIPApprovalAddresses(p) {
			return false
		}
		if p.AllowFloatingIP && !p.AllowInternetEgress {
			return false
		}
		if p.AllowInternetEgress && (!p.AllowSNAT || !overlayproto.PublicInternetIPv4(p.PublicIPv4)) {
			return false
		}
		prefixes := map[string]bool{}
		for _, value := range p.AllowedSourceCIDRs {
			if !prefixWithin(value, g.AllowedPrefixes) || prefixes[value] {
				return false
			}
			prefixes[value] = true
		}
		for i, port := range p.AllowedPorts {
			if port.Protocol != "tcp" && port.Protocol != "udp" || port.Start < 1 || port.End > 65535 || port.End < port.Start {
				return false
			}
			for _, old := range p.AllowedPorts[:i] {
				if old.Protocol == port.Protocol && old.Start <= port.End && port.Start <= old.End {
					return false
				}
			}
		}
		profiles[key], public[p.NodeID+":"+p.PublicIPv4] = true, true
		natVPCs[p.VPCID], natGateways[p.GatewayInstanceID] = true, true
	}
	return true
}

func overlayPoliciesApproved(cluster OverlayCluster, snapshot overlayproto.Snapshot) bool {
	for _, f := range snapshot.FloatingIPs {
		approved := false
		for _, p := range cluster.NATProfiles {
			if p.NodeID == f.NodeID && p.ProfileID == f.ProfileID && p.ProfileSHA256 == f.ProfileSHA256 && p.VPCID == f.VPCID && p.GatewayInstanceID == f.GatewayInstanceID && p.AllowFloatingIP && p.AllowInternetEgress && approvedPublicIPAddress(p, f.PublicIPv4) {
				approved = true
			}
		}
		if !approved {
			return false
		}
	}

	for _, selected := range snapshot.Gateways {
		approved := false
		for _, root := range cluster.Gateways {
			if root.NodeID != selected.NodeID || root.InstanceID != selected.InstanceID || root.InterfaceID != selected.InterfaceID || root.OwnerRef != selected.OwnerRef || root.VPCID != selected.VPCID || root.IPv4 != selected.IPv4 || root.MAC != selected.MAC {
				continue
			}
			approved = selected.AllowedPrefixes != nil && root.AllowedPrefixes != nil
			for _, prefix := range selected.AllowedPrefixes {
				approved = approved && prefixWithin(prefix, root.AllowedPrefixes)
			}
			// Explicit [] is an inactive route selection, never a default-route
			// approval. Internet forwarding is authorized separately below.
		}
		if !approved {
			return false
		}
	}
	for _, selected := range snapshot.NATPolicies {
		approved := false
		selectedPrefixes := []string{}
		gatewaySelected := false
		for _, gateway := range snapshot.Gateways {
			if gateway.NodeID == selected.NodeID && gateway.VPCID == selected.VPCID && gateway.InstanceID == selected.GatewayInstanceID {
				selectedPrefixes = gateway.AllowedPrefixes
				gatewaySelected = gateway.AllowedPrefixes != nil
			}
		}
		for _, root := range cluster.NATProfiles {
			if root.NodeID != selected.NodeID || root.VPCID != selected.VPCID || root.GatewayInstanceID != selected.GatewayInstanceID || root.ProfileID != selected.ProfileID || root.ProfileSHA256 != selected.ProfileSHA256 {
				continue
			}
			approved = gatewaySelected && (!selected.SNATEnabled || root.AllowSNAT) && (selected.PublicIPv4 == "" || approvedPublicIPAddress(root, selected.PublicIPv4))
			if selected.InternetEgressEnabled {
				approved = approved && selected.SNATEnabled && root.AllowSNAT && root.AllowInternetEgress && overlayproto.PublicInternetIPv4(effectivePublicIPAddress(root, selected.PublicIPv4))
			}
			for _, forwarding := range selected.Forwardings {
				portOK := false
				for _, port := range root.AllowedPorts {
					if forwarding.Protocol == port.Protocol && forwarding.PublicPort >= port.Start && forwarding.PublicPort <= port.End {
						portOK = true
					}
				}
				approved = approved && portOK && prefixWithin(forwarding.SourceCIDR, root.AllowedSourceCIDRs) && prefixWithin(forwarding.SourceCIDR, selectedPrefixes)
			}
		}
		if !approved {
			return false
		}
	}
	return true
}

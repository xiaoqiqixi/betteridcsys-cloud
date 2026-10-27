package fabric

import "aster/cloud/internal/overlayproto"

// Every participant independently approves public routing, even when the NAT
// namespace is on a remote node. A controller flag alone cannot expand the
// node's data plane. Explicit global VPC identity prevents overlapping tenant
// CIDRs/gateway IPs from borrowing another network's permission.
func internetGuestApproval(c OverlayConfig, s overlayproto.Snapshot) bool {
	policies := append([]overlayproto.NATPolicy{}, s.NATPolicies...)
	for _, f := range s.FloatingIPs {
		policies = append(policies, overlayproto.NATPolicy{NodeID: f.NodeID, VPCID: f.VPCID, GatewayInstanceID: f.GatewayInstanceID, InternetEgressEnabled: true})
	}
	for _, policy := range policies {
		if !policy.InternetEgressEnabled {
			continue
		}
		var v overlayproto.VPC
		var gateway overlayproto.Gateway
		for _, candidate := range s.VPCs {
			if candidate.ID == policy.VPCID {
				v = candidate
			}
		}
		for _, candidate := range s.Gateways {
			if candidate.VPCID == policy.VPCID && candidate.InstanceID == policy.GatewayInstanceID && candidate.NodeID == policy.NodeID {
				gateway = candidate
			}
		}
		approved := func(g OverlayGuestNetwork) bool {
			return g.AllowInternetEgress && g.VPCID == v.ID && g.OwnerRef == v.OwnerRef && g.CIDR == v.CIDR && g.GatewayIPv4 == gateway.IPv4
		}
		found := false
		for _, g := range c.GuestNetworks {
			if approved(g) {
				found = true
			}
		}
		if !found {
			return false
		}
		for _, member := range s.Members {
			if member.NodeID != c.Base.NodeID || member.VPCID != policy.VPCID {
				continue
			}
			found = false
			for _, g := range c.GuestNetworks {
				if g.LocalVPCID == member.LocalVPCID && approved(g) {
					found = true
				}
			}
			if !found {
				return false
			}
		}
	}
	return true
}

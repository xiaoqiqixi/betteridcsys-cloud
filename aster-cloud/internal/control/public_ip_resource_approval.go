package control

import (
	"aster/cloud/internal/nodeproto"
	"aster/cloud/internal/overlayproto"
	"context"
	"database/sql"
	"net/netip"
)

func (c Config) validDirectPublicProfiles() bool {
	if len(c.DirectPublicProfiles) > 256 {
		return false
	}
	seen := map[string]bool{}
	public := map[string]bool{}
	for _, cluster := range c.OverlayClusters {
		for _, p := range cluster.NATProfiles {
			public[p.PublicIPv4] = true
			for _, a := range p.PublicIPv4s {
				public[a] = true
			}
		}
	}
	for _, p := range c.DirectPublicProfiles {
		_, exists := c.Node(p.NodeID)
		prefix, e := netip.ParsePrefix(p.CIDR)
		gateway, ge := netip.ParseAddr(p.GatewayIPv4)
		if !exists || !nodeproto.ValidNodeID(p.ClusterID) || !nodeproto.ValidNodeID(p.ProfileID) || !shaRE.MatchString(p.ProfileSHA256) || seen[p.NodeID+":"+p.ProfileID] || e != nil || !prefix.Addr().Is4() || prefix.Masked() != prefix || prefix.String() != p.CIDR || prefix.Bits() < 1 || prefix.Bits() > 30 || p.ProfileID != "normal-public-ipv4" || ge != nil || !gateway.Is4() || !overlayproto.PublicInternetIPv4(p.GatewayIPv4) || gateway.String() != p.GatewayIPv4 || !prefix.Contains(gateway) || gateway == prefix.Addr() || !prefix.Contains(gateway.Next()) || len(p.PublicIPv4s) < 1 || len(p.PublicIPv4s) > 4096 {
			return false
		}
		used := map[string]bool{}
		for _, a := range p.PublicIPv4s {
			ip, e := netip.ParseAddr(a)
			if e != nil || !overlayproto.PublicInternetIPv4(a) || !prefix.Contains(ip) || ip == gateway || ip == prefix.Addr() || !prefix.Contains(ip.Next()) || used[a] || public[a] {
				return false
			}
			used[a] = true
		}
		seen[p.NodeID+":"+p.ProfileID] = true
	}
	return true
}
func directPublicAddressApproved(p DirectPublicProfile, address string) bool {
	for _, a := range p.PublicIPv4s {
		if a == address {
			return true
		}
	}
	return false
}
func directPublicProfile(c Config, cluster, node, profile string) (DirectPublicProfile, bool) {
	if !c.validDirectPublicProfiles() {
		return DirectPublicProfile{}, false
	}
	for _, p := range c.DirectPublicProfiles {
		if p.ClusterID == cluster && p.NodeID == node && p.ProfileID == profile {
			return p, true
		}
	}
	return DirectPublicProfile{}, false
}
func publicResourceInputValid(in PublicIPResourceInput) bool {
	return nodeproto.ValidID(in.PoolID) && nodeproto.ValidID(in.OwnerRef) && nodeproto.ValidNodeID(in.NodeID) && nodeproto.ValidNodeID(in.ProfileID) && (in.Address == "" || overlayproto.PublicInternetIPv4(in.Address)) && (in.Mode == "direct" && in.VPCID == "" || in.Mode == "floating" && nodeproto.ValidID(in.VPCID))
}
func publicResourceApprovedTx(ctx context.Context, tx *sql.Tx, c Config, r PublicIPResource, address string) bool {
	if r.Mode == "direct" {
		p, ok := directPublicProfile(c, r.ClusterID, r.NodeID, r.ProfileID)
		return ok && directPublicAddressApproved(p, address)
	}
	if r.Mode != "floating" {
		return false
	}
	lease := PublicIPLease{ClusterID: r.ClusterID, OwnerRef: r.OwnerRef, VPCID: r.VPCID, NodeID: r.NodeID, ProfileID: r.ProfileID}
	p, e := publicLeaseRootProfileTx(ctx, tx, c, lease)
	return e == nil && p.AllowFloatingIP && p.AllowInternetEgress && approvedPublicIPAddress(p, address)
}
func resourcePoolInventoryTx(ctx context.Context, tx *sql.Tx, r PublicIPResource) error {
	return publicLeaseInventoryTx(ctx, tx, PublicIPLease{PoolID: r.PoolID, ClusterID: r.ClusterID, Address: r.Address})
}

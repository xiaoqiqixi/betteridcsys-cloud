package overlayproto

import (
	"aster/cloud/internal/nodeproto"
	"sort"
	"strconv"
)

// NAT is explicit additional intent; absence preserves every pre-NAT snapshot byte.
type NATPolicy struct {
	ID                    string          `json:"id"`
	NodeID                string          `json:"node_id"`
	VPCID                 string          `json:"vpc_id"`
	GatewayInstanceID     string          `json:"gateway_instance_id"`
	ProfileID             string          `json:"profile_id"`
	ProfileSHA256         string          `json:"profile_sha256"`
	SNATEnabled           bool            `json:"snat_enabled"`
	InternetEgressEnabled bool            `json:"internet_egress_enabled,omitempty"`
	PublicIPv4            string          `json:"public_ipv4,omitempty"`
	Forwardings           []NATForwarding `json:"forwardings"`
}
type NATForwarding struct {
	ID               string `json:"id"`
	Protocol         string `json:"protocol"`
	PublicPort       int    `json:"public_port"`
	TargetInstanceID string `json:"target_instance_id"`
	TargetPort       int    `json:"target_port"`
	SourceCIDR       string `json:"source_cidr"`
}

func canonicalNAT(s *Snapshot) error {
	if len(s.NATPolicies) > 32 {
		return ErrInput
	}
	if len(s.NATPolicies) == 0 {
		s.NATPolicies = nil
		return nil
	}
	s.NATPolicies = append([]NATPolicy{}, s.NATPolicies...)
	sort.Slice(s.NATPolicies, func(i, j int) bool { return s.NATPolicies[i].ID < s.NATPolicies[j].ID })
	ids, vpcs, profiles := map[string]bool{}, map[string]bool{}, map[string]bool{}
	members := map[string]Member{}
	for _, m := range s.Members {
		members[m.InstanceID] = m
	}
	for i, p := range s.NATPolicies {
		if !nodeproto.ValidID(p.ID) || !nodeproto.ValidNodeID(p.NodeID) || !nodeproto.ValidID(p.VPCID) || !nodeproto.ValidID(p.GatewayInstanceID) || !nodeproto.ValidNodeID(p.ProfileID) || !ValidSHA(p.ProfileSHA256) || ids[p.ID] || vpcs[p.VPCID] || profiles[p.NodeID+":"+p.ProfileID] || p.Forwardings == nil || len(p.Forwardings) > 128 || p.InternetEgressEnabled && !p.SNATEnabled || p.PublicIPv4 != "" && !PublicInternetIPv4(p.PublicIPv4) {
			return ErrInput
		}
		ids[p.ID] = true
		vpcs[p.VPCID] = true
		profiles[p.NodeID+":"+p.ProfileID] = true
		found := false
		for _, g := range s.Gateways {
			if g.VPCID == p.VPCID && g.InstanceID == p.GatewayInstanceID && g.NodeID == p.NodeID {
				found = true
			}
		}
		if !found {
			return ErrInput
		}
		p.Forwardings = append([]NATForwarding{}, p.Forwardings...)
		sort.Slice(p.Forwardings, func(i, j int) bool { return p.Forwardings[i].ID < p.Forwardings[j].ID })
		fids, ports := map[string]bool{}, map[string]bool{}
		for _, f := range p.Forwardings {
			source, ok := Prefix(f.SourceCIDR)
			m, mok := members[f.TargetInstanceID]
			key := f.Protocol + ":" + strconv.Itoa(f.PublicPort)
			if !nodeproto.ValidID(f.ID) || fids[f.ID] || (f.Protocol != "tcp" && f.Protocol != "udp") || f.PublicPort < 1 || f.PublicPort > 65535 || f.TargetPort < 1 || f.TargetPort > 65535 || ports[key] || !ok || source.Bits() == 0 || !mok || m.VPCID != p.VPCID || !m.Enabled {
				return ErrInput
			}
			fids[f.ID] = true
			ports[key] = true
		}
		s.NATPolicies[i] = p
	}
	return nil
}

package overlayproto

import (
	"aster/cloud/internal/nodeproto"
	"bytes"
	"encoding/json"
	"sort"
)

// FloatingIP is an independent whole-address mapping to one exact VPC member.
// It is deliberately distinct from a guest's real directly configured public IP.
// Missing/empty arrays preserve every pre-existing canonical snapshot byte.
type FloatingIP struct {
	Ingress           *PublicIngressPolicy `json:"ingress,omitempty"`
	ResourceID        string               `json:"resource_id"`
	NodeID            string               `json:"node_id"`
	VPCID             string               `json:"vpc_id"`
	OwnerRef          string               `json:"owner_ref"`
	ProfileID         string               `json:"profile_id"`
	ProfileSHA256     string               `json:"profile_sha256"`
	GatewayInstanceID string               `json:"gateway_instance_id"`
	InstanceID        string               `json:"instance_id"`
	TargetIPv4        string               `json:"target_ipv4"`
	PublicIPv4        string               `json:"public_ipv4"`
}

func canonicalFloatingIPs(s *Snapshot) error {
	if len(s.FloatingIPs) > 128 {
		return ErrInput
	}
	if len(s.FloatingIPs) == 0 {
		s.FloatingIPs = nil
		return nil
	}
	s.FloatingIPs = append([]FloatingIP{}, s.FloatingIPs...)
	sort.Slice(s.FloatingIPs, func(i, j int) bool { return s.FloatingIPs[i].ResourceID < s.FloatingIPs[j].ResourceID })
	members := map[string]Member{}
	vpcs := map[string]VPC{}
	gateways := map[string]Gateway{}
	for _, v := range s.VPCs {
		vpcs[v.ID] = v
	}
	for _, m := range s.Members {
		members[m.InstanceID] = m
	}
	for _, g := range s.Gateways {
		gateways[g.InstanceID] = g
	}
	ids, ips, targets := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, f := range s.FloatingIPs {
		m, mok := members[f.InstanceID]
		g, gok := gateways[f.GatewayInstanceID]
		v, vok := vpcs[f.VPCID]
		if !nodeproto.ValidID(f.ResourceID) || !nodeproto.ValidNodeID(f.NodeID) || !nodeproto.ValidNodeID(f.ProfileID) || !ValidSHA(f.ProfileSHA256) || !PublicInternetIPv4(f.PublicIPv4) || !mok || !gok || !vok || !m.Enabled || m.Reserved || m.OwnerRef != f.OwnerRef || v.OwnerRef != f.OwnerRef || g.OwnerRef != f.OwnerRef || m.VPCID != f.VPCID || g.VPCID != f.VPCID || g.NodeID != f.NodeID || m.IPv4 != f.TargetIPv4 || ids[f.ResourceID] || ips[f.PublicIPv4] || targets[f.InstanceID] {
			return ErrInput
		}
		for _, n := range s.NATPolicies {
			if n.PublicIPv4 == f.PublicIPv4 {
				return ErrInput
			}
		}
		if f.Ingress != nil {
			if f.Ingress.InstanceID != f.InstanceID || f.Ingress.OwnerRef != f.OwnerRef || !ValidSHA(f.Ingress.SHA256) {
				return ErrInput
			}
			policy, e := CanonicalPublicIngress(*f.Ingress)
			if e != nil {
				return e
			}
			f.Ingress = &policy
			// Store the fresh sorted copy, never mutate a caller's policy/rules.
			for i := range s.FloatingIPs {
				if s.FloatingIPs[i].ResourceID == f.ResourceID {
					s.FloatingIPs[i] = f
					break
				}
			}
		}
		ids[f.ResourceID] = true
		ips[f.PublicIPv4] = true
		targets[f.InstanceID] = true
	}
	return nil
}

// Absence denotes the historical contract; explicit null must never turn a
// policy-bearing intent into legacy unrestricted ingress.
func (f *FloatingIP) UnmarshalJSON(raw []byte) error {
	type wire FloatingIP
	var value wire
	if !strict(raw, &value) {
		return ErrInput
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return ErrInput
	}
	if p, ok := fields["ingress"]; ok && bytes.Equal(bytes.TrimSpace(p), []byte("null")) {
		return ErrInput
	}
	*f = FloatingIP(value)
	return nil
}

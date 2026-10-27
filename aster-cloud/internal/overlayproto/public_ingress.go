package overlayproto

import (
	"aster/cloud/internal/nodeproto"
	"encoding/json"
	"net/netip"
	"sort"
)

// These are instance-scoped public ingress allow rules, not a VPC security group.
// An explicit empty policy denies unsolicited public ingress. A missing policy
// exists only in the legacy immutable floating-IP contract.
type PublicIngressRule struct {
	ID         string `json:"id"`
	Protocol   string `json:"protocol"`
	SourceCIDR string `json:"source_cidr"`
	PortStart  int    `json:"port_start"`
	PortEnd    int    `json:"port_end"`
}
type PublicIngressPolicy struct {
	Schema     int                 `json:"schema"`
	InstanceID string              `json:"instance_id"`
	OwnerRef   string              `json:"owner_ref"`
	Revision   uint64              `json:"revision"`
	SHA256     string              `json:"sha256"`
	Rules      []PublicIngressRule `json:"rules"`
}

const MaxPublicIngressRevision uint64 = 9007199254740991

func CanonicalPublicIngress(p PublicIngressPolicy) (PublicIngressPolicy, error) {
	if p.Schema != 1 || !nodeproto.ValidID(p.InstanceID) || !nodeproto.ValidID(p.OwnerRef) || p.Revision > MaxPublicIngressRevision || p.Rules == nil || len(p.Rules) > 64 || p.Revision == 0 && len(p.Rules) != 0 {
		return p, ErrInput
	}
	p.Rules = append([]PublicIngressRule{}, p.Rules...)
	sort.Slice(p.Rules, func(i, j int) bool { return p.Rules[i].ID < p.Rules[j].ID })
	identities := map[string]bool{}
	for i, r := range p.Rules {
		prefix, e := netip.ParsePrefix(r.SourceCIDR)
		if !nodeproto.ValidID(r.ID) || i > 0 && r.ID == p.Rules[i-1].ID || e != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.String() != r.SourceCIDR {
			return p, ErrInput
		}
		switch r.Protocol {
		case "tcp", "udp":
			if r.PortStart < 1 || r.PortEnd > 65535 || r.PortEnd < r.PortStart {
				return p, ErrInput
			}
		case "icmp":
			if r.PortStart != 0 || r.PortEnd != 0 {
				return p, ErrInput
			}
		default:
			return p, ErrInput
		}
		raw, _ := json.Marshal(struct {
			Protocol, SourceCIDR string
			PortStart, PortEnd   int
		}{r.Protocol, r.SourceCIDR, r.PortStart, r.PortEnd})
		if identities[string(raw)] {
			return p, ErrInput
		}
		identities[string(raw)] = true
	}
	raw, _ := json.Marshal(struct {
		Schema     int                 `json:"schema"`
		InstanceID string              `json:"instance_id"`
		OwnerRef   string              `json:"owner_ref"`
		Revision   uint64              `json:"revision"`
		Rules      []PublicIngressRule `json:"rules"`
	}{p.Schema, p.InstanceID, p.OwnerRef, p.Revision, p.Rules})
	sha := Digest(raw)
	if p.SHA256 != "" && p.SHA256 != sha {
		return p, ErrInput
	}
	p.SHA256 = sha
	return p, nil
}

// Callers supply validated persistent identities. Invalid identities return an
// unusable zero policy rather than manufacturing a valid-looking authorization.
func DefaultPublicIngress(instance, owner string) PublicIngressPolicy {
	p, e := CanonicalPublicIngress(PublicIngressPolicy{Schema: 1, InstanceID: instance, OwnerRef: owner, Rules: []PublicIngressRule{}})
	if e != nil {
		return PublicIngressPolicy{}
	}
	return p
}

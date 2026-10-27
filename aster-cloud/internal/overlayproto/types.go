// Package overlayproto defines an explicit operator-authorized network change.
// It references, but never rewrites, original node/2 and financial snapshots.
package overlayproto

import (
	"aster/cloud/internal/nodeproto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strings"
)

const Protocol = "aster.overlay/1"
const MaxBytes = 512 << 10

var ErrInput = errors.New("invalid overlay contract")

type ProfilePin struct {
	NodeID        string `json:"node_id"`
	ProfileID     string `json:"profile_id"`
	ProfileSHA256 string `json:"profile_sha256"`
}
type VPC struct {
	ID       string `json:"id"`
	OwnerRef string `json:"owner_ref"`
	CIDR     string `json:"cidr"`
	VNI      int    `json:"vni"`
}
type Member struct {
	NodeID        string `json:"node_id"`
	InstanceID    string `json:"instance_id"`
	InterfaceID   string `json:"interface_id"`
	OwnerRef      string `json:"owner_ref"`
	VPCID         string `json:"vpc_id"`
	LocalVPCID    string `json:"local_vpc_id"`
	LeaseID       string `json:"lease_id"`
	PoolID        string `json:"pool_id"`
	NetworkSHA256 string `json:"network_sha256"`
	IPv4          string `json:"ipv4"`
	MAC           string `json:"mac"`
	InboundMbps   int    `json:"inbound_mbps"`
	OutboundMbps  int    `json:"outbound_mbps"`
	Enabled       bool   `json:"enabled"`
	Reserved      bool   `json:"reserved"`
}
type Gateway struct {
	NodeID          string   `json:"node_id"`
	InstanceID      string   `json:"instance_id"`
	InterfaceID     string   `json:"interface_id"`
	OwnerRef        string   `json:"owner_ref"`
	VPCID           string   `json:"vpc_id"`
	IPv4            string   `json:"ipv4"`
	MAC             string   `json:"mac"`
	AllowedPrefixes []string `json:"allowed_prefixes"`
}
type Snapshot struct {
	Protocol       string       `json:"protocol"`
	ClusterID      string       `json:"cluster_id"`
	Epoch          int64        `json:"epoch"`
	PreviousSHA256 string       `json:"previous_sha256"`
	Profiles       []ProfilePin `json:"profiles"`
	VPCs           []VPC        `json:"vpcs"`
	Members        []Member     `json:"members"`
	Gateways       []Gateway    `json:"gateways"`
	NATPolicies    []NATPolicy  `json:"nat_policies,omitempty"`
	FloatingIPs    []FloatingIP `json:"floating_ips,omitempty"`
}

// Head is an observed node journal position, not proof of connectivity.
type Head struct {
	NodeID         string `json:"node_id"`
	ClusterID      string `json:"cluster_id"`
	Epoch          int64  `json:"epoch"`
	SnapshotSHA256 string `json:"snapshot_sha256"`
}

func (h Head) Valid() bool {
	if !nodeproto.ValidNodeID(h.NodeID) {
		return false
	}
	if h.Epoch == 0 {
		return h.ClusterID == "" && h.SnapshotSHA256 == ""
	}
	return h.Epoch > 0 && nodeproto.ValidNodeID(h.ClusterID) && ValidSHA(h.SnapshotSHA256)
}
func DecodeHead(raw []byte) (Head, error) {
	var h Head
	if !strict(raw, &h) || !h.Valid() {
		return Head{}, ErrInput
	}
	return h, nil
}

type Recovery struct {
	Epoch          int64  `json:"epoch"`
	SnapshotSHA256 string `json:"snapshot_sha256"`
	Heads          []Head `json:"heads"`
}
type Task struct {
	Protocol       string    `json:"protocol"`
	OperationID    string    `json:"operation_id"`
	NodeID         string    `json:"node_id"`
	Phase          string    `json:"phase"`
	SnapshotSHA256 string    `json:"snapshot_sha256"`
	Snapshot       Snapshot  `json:"snapshot"`
	Recovery       *Recovery `json:"recovery,omitempty"`
}
type Receipt struct {
	Protocol       string `json:"protocol"`
	OperationID    string `json:"operation_id"`
	NodeID         string `json:"node_id"`
	ClusterID      string `json:"cluster_id"`
	Epoch          int64  `json:"epoch"`
	Phase          string `json:"phase"`
	SnapshotSHA256 string `json:"snapshot_sha256"`
	RequestSHA256  string `json:"request_sha256"`
	Status         string `json:"status"`
	Code           string `json:"code"`
}

func Digest(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func ValidSHA(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func ValidPhase(s string) bool { return s == "prepare" || s == "program" || s == "release" }
func Prefix(raw string) (netip.Prefix, bool) {
	p, e := netip.ParsePrefix(raw)
	return p, e == nil && p.Addr().Is4() && p == p.Masked() && p.String() == raw
}
func Usable(raw string, p netip.Prefix) bool {
	a, e := netip.ParseAddr(raw)
	return e == nil && a.Is4() && a.String() == raw && p.Contains(a) && a != p.Addr() && p.Contains(a.Next())
}
func validMAC(raw string) bool {
	a, e := net.ParseMAC(raw)
	return e == nil && len(a) == 6 && a.String() == raw && a[0]&1 == 0 && raw != "00:00:00:00:00:00"
}

// CanonicalSnapshot copies and sorts every array. Ordering never grants a
// different network; the complete resulting bytes are the immutable intent.
func CanonicalSnapshot(s Snapshot) (Snapshot, string, error) {
	if s.Protocol != Protocol || !nodeproto.ValidNodeID(s.ClusterID) || s.Epoch < 1 || s.Epoch == 1 && s.PreviousSHA256 != "" || s.Epoch > 1 && !ValidSHA(s.PreviousSHA256) || s.Profiles == nil || len(s.Profiles) < 1 || len(s.Profiles) > 32 || s.VPCs == nil || len(s.VPCs) < 1 || len(s.VPCs) > 32 || s.Members == nil || len(s.Members) > 128 || s.Gateways == nil || len(s.Gateways) > 32 {
		return Snapshot{}, "", ErrInput
	}
	s.Profiles = append([]ProfilePin{}, s.Profiles...)
	s.VPCs = append([]VPC{}, s.VPCs...)
	s.Members = append([]Member{}, s.Members...)
	s.Gateways = append([]Gateway{}, s.Gateways...)
	sort.Slice(s.Profiles, func(i, j int) bool { return s.Profiles[i].NodeID < s.Profiles[j].NodeID })
	sort.Slice(s.VPCs, func(i, j int) bool { return s.VPCs[i].ID < s.VPCs[j].ID })
	sort.Slice(s.Members, func(i, j int) bool { return s.Members[i].InstanceID < s.Members[j].InstanceID })
	sort.Slice(s.Gateways, func(i, j int) bool { return s.Gateways[i].VPCID < s.Gateways[j].VPCID })
	nodes := map[string]bool{}
	vpcs := map[string]VPC{}
	vnis := map[int]bool{}
	ids := map[string]bool{}
	ips := map[string]bool{}
	macs := map[string]bool{}
	leases := map[string]bool{}
	for _, p := range s.Profiles {
		if !nodeproto.ValidNodeID(p.NodeID) || !nodeproto.ValidNodeID(p.ProfileID) || !ValidSHA(p.ProfileSHA256) || nodes[p.NodeID] {
			return Snapshot{}, "", ErrInput
		}
		nodes[p.NodeID] = true
	}
	for _, v := range s.VPCs {
		p, ok := Prefix(v.CIDR)
		if !ok || !p.Addr().IsPrivate() || p.Bits() < 8 || p.Bits() > 30 || !nodeproto.ValidID(v.ID) || !nodeproto.ValidID(v.OwnerRef) || v.VNI < 1 || v.VNI > 16777215 || vpcs[v.ID].ID != "" || vnis[v.VNI] {
			return Snapshot{}, "", ErrInput
		}
		vpcs[v.ID] = v
		vnis[v.VNI] = true
	}
	for _, m := range s.Members {
		v, ok := vpcs[m.VPCID]
		p, _ := Prefix(v.CIDR)
		if !ok || !nodes[m.NodeID] || m.OwnerRef != v.OwnerRef || !nodeproto.ValidID(m.InstanceID) || !nodeproto.ValidID(m.LocalVPCID) || !nodeproto.ValidID(m.LeaseID) || !nodeproto.ValidID(m.PoolID) || !ValidSHA(m.NetworkSHA256) || m.InterfaceID != nodeproto.NetworkInterfaceID(m.InstanceID) || m.MAC != nodeproto.NetworkMAC(m.NodeID, m.InstanceID) || !Usable(m.IPv4, p) || m.InboundMbps < 1 || m.InboundMbps > 100000 || m.OutboundMbps < 1 || m.OutboundMbps > 100000 || ids[m.InstanceID] || ips[m.VPCID+":"+m.IPv4] || macs[m.MAC] || leases[m.LeaseID] {
			return Snapshot{}, "", ErrInput
		}
		ids[m.InstanceID] = true
		ips[m.VPCID+":"+m.IPv4] = true
		macs[m.MAC] = true
		leases[m.LeaseID] = true
	}
	gateways := map[string]bool{}
	for i, g := range s.Gateways {
		v, ok := vpcs[g.VPCID]
		p, _ := Prefix(v.CIDR)
		if !ok || !nodes[g.NodeID] || g.OwnerRef != v.OwnerRef || !nodeproto.ValidID(g.InstanceID) || g.InterfaceID != nodeproto.NetworkInterfaceID(g.InstanceID) || !validMAC(g.MAC) || !Usable(g.IPv4, p) || ids[g.InstanceID] || ips[g.VPCID+":"+g.IPv4] || macs[g.MAC] || gateways[g.VPCID] || g.AllowedPrefixes == nil || len(g.AllowedPrefixes) > 32 {
			return Snapshot{}, "", ErrInput
		}
		ids[g.InstanceID] = true
		ips[g.VPCID+":"+g.IPv4] = true
		macs[g.MAC] = true
		gateways[g.VPCID] = true
		g.AllowedPrefixes = append([]string{}, g.AllowedPrefixes...)
		sort.Strings(g.AllowedPrefixes)
		for j, raw := range g.AllowedPrefixes {
			route, ok := Prefix(raw)
			if !ok || route.Overlaps(p) || j > 0 && raw == g.AllowedPrefixes[j-1] {
				return Snapshot{}, "", ErrInput
			}
			for _, other := range s.VPCs {
				q, _ := Prefix(other.CIDR)
				if route.Overlaps(q) {
					return Snapshot{}, "", ErrInput
				}
			}
		}
		s.Gateways[i] = g
	}
	if err := canonicalFloatingIPs(&s); err != nil {
		return Snapshot{}, "", err
	}
	if err := canonicalNAT(&s); err != nil {
		return Snapshot{}, "", err
	}
	raw, e := json.Marshal(s)
	if e != nil || len(raw) > MaxBytes {
		return Snapshot{}, "", ErrInput
	}
	return s, Digest(raw), nil
}
func DecodeSnapshot(raw []byte) (Snapshot, error) {
	var s Snapshot
	if !strict(raw, &s) {
		return s, ErrInput
	}
	c, _, e := CanonicalSnapshot(s)
	return c, e
}
func (t Task) BytesAndDigest() ([]byte, string, error) {
	s, sha, e := CanonicalSnapshot(t.Snapshot)
	if e != nil || t.Protocol != Protocol || !nodeproto.ValidID(t.OperationID) || !ValidPhase(t.Phase) || sha != t.SnapshotSHA256 {
		return nil, "", ErrInput
	}
	found := false
	for _, p := range s.Profiles {
		if p.NodeID == t.NodeID {
			found = true
		}
	}
	if !found {
		return nil, "", ErrInput
	}
	t.Snapshot = s
	if t.Recovery != nil {
		r := *t.Recovery
		if r.Epoch != s.Epoch-1 || r.SnapshotSHA256 != s.PreviousSHA256 || !ValidSHA(r.SnapshotSHA256) || len(r.Heads) != len(s.Profiles) {
			return nil, "", ErrInput
		}
		r.Heads = append([]Head{}, r.Heads...)
		sort.Slice(r.Heads, func(i, j int) bool { return r.Heads[i].NodeID < r.Heads[j].NodeID })
		for i, h := range r.Heads {
			if !h.Valid() || h.NodeID != s.Profiles[i].NodeID || h.Epoch >= s.Epoch || h.Epoch > 0 && h.ClusterID != s.ClusterID {
				return nil, "", ErrInput
			}
		}
		t.Recovery = &r
	}
	b, e := json.Marshal(t)
	if e != nil || len(b) > MaxBytes {
		return nil, "", ErrInput
	}
	return b, Digest(b), nil
}
func DecodeTask(raw []byte) (Task, error) {
	var t Task
	if !strict(raw, &t) {
		return t, ErrInput
	}
	b, _, e := t.BytesAndDigest()
	if e != nil || string(b) != string(raw) {
		return Task{}, ErrInput
	}
	return t, nil
}
func DecodeReceipt(raw []byte) (Receipt, error) {
	var r Receipt
	if !strict(raw, &r) || !r.Valid() {
		return Receipt{}, ErrInput
	}
	return r, nil
}
func (r Receipt) Valid() bool {
	return r.Protocol == Protocol && nodeproto.ValidID(r.OperationID) && nodeproto.ValidNodeID(r.NodeID) && nodeproto.ValidNodeID(r.ClusterID) && r.Epoch > 0 && ValidPhase(r.Phase) && ValidSHA(r.SnapshotSHA256) && ValidSHA(r.RequestSHA256) && (r.Status == "succeeded" || r.Status == "rejected" || r.Status == "uncertain") && len(r.Code) > 0 && len(r.Code) <= 80 && strings.IndexFunc(r.Code, func(c rune) bool { return !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') }) < 0
}
func (r Receipt) Matches(t Task, sha string) bool {
	return r.Valid() && r.OperationID == t.OperationID && r.NodeID == t.NodeID && r.ClusterID == t.Snapshot.ClusterID && r.Epoch == t.Snapshot.Epoch && r.Phase == t.Phase && r.SnapshotSHA256 == t.SnapshotSHA256 && r.RequestSHA256 == sha
}

// PhaseOperationID prevents reuse across nodes, phases and parent intents.
func PhaseOperationID(operation, node, phase string) string {
	return Digest([]byte(Protocol + ":" + operation + ":" + node + ":" + phase))[:32]
}

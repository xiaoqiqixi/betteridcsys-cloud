package nodeproto

import (
	"encoding/json"
	"net"
	"net/netip"
)

const DirectPublicProtocol = "aster.node/3"
const DirectPublicProfile = "normal-public-ipv4"
const DirectPublicCapability = "normal-public-ipv4-controller-bound/1"
const StorageDirectProtocol = "aster.node.storage/2"

// DirectPublicBinding is the exact controller-reserved guest primary address.
// It is not a NAT mapping. No command, host path or mutable allocation hint is accepted.
type DirectPublicBinding struct {
	Generation    int64  `json:"generation"`
	Schema        int    `json:"schema"`
	LeaseID       string `json:"lease_id"`
	PoolID        string `json:"pool_id"`
	NodeID        string `json:"node_id"`
	OwnerRef      string `json:"owner_ref"`
	InstanceID    string `json:"instance_id"`
	ProfileID     string `json:"profile_id"`
	ProfileSHA256 string `json:"profile_sha256"`
	CIDR          string `json:"cidr"`
	Gateway       string `json:"gateway"`
	IPv4          string `json:"ipv4"`
	MAC           string `json:"mac"`
}

func (b DirectPublicBinding) IsZero() bool   { return b == (DirectPublicBinding{}) }
func (b DirectPublicBinding) Digest() string { raw, _ := json.Marshal(b); return Digest(raw) }
func publicIPv4(raw string) bool {
	a, e := netip.ParseAddr(raw)
	if e != nil || !a.Is4() || a.String() != raw || !a.IsGlobalUnicast() {
		return false
	}
	for _, p := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"} {
		if netip.MustParsePrefix(p).Contains(a) {
			return false
		}
	}
	return true
}
func (b DirectPublicBinding) ValidIdentity() bool {
	p, e := netip.ParsePrefix(b.CIDR)
	a, ae := netip.ParseAddr(b.IPv4)
	g, ge := netip.ParseAddr(b.Gateway)
	mac, me := net.ParseMAC(b.MAC)
	return b.Generation >= 1 && b.Generation < 1<<60 && b.Schema == 1 && ValidID(b.LeaseID) && ValidID(b.PoolID) && ValidNodeID(b.NodeID) && ValidID(b.OwnerRef) && ValidID(b.InstanceID) && b.ProfileID == DirectPublicProfile && digest.MatchString(b.ProfileSHA256) && e == nil && p.Addr().Is4() && p == p.Masked() && p.String() == b.CIDR && p.Bits() >= 1 && p.Bits() <= 30 && ae == nil && ge == nil && publicIPv4(b.IPv4) && publicIPv4(b.Gateway) && p.Contains(a) && p.Contains(g) && g != p.Addr() && p.Contains(g.Next()) && a != g && a != p.Addr() && p.Contains(a.Next()) && me == nil && len(mac) == 6 && mac.String() == b.MAC && mac[0]&1 == 0 && mac[0]&2 == 2
}
func (b DirectPublicBinding) ValidFor(t NodeTask) bool {
	r := t.Resources
	return b.ValidIdentity() && b.NodeID == t.NodeID && b.OwnerRef == t.OwnerRef && b.InstanceID == t.InstanceID && r.NetworkType == "normal" && r.IPv4Count == 1 && r.IPv6Count == 0 && r.BandwidthMbps == 0 && r.InboundBandwidthMbps == 0 && r.TransferGiB == 0 && r.TrafficDirection == "all"
}
func decodeDirectPublic(raw json.RawMessage) (DirectPublicBinding, error) {
	var b DirectPublicBinding
	var fields map[string]json.RawMessage
	keys := []string{"generation", "schema", "lease_id", "pool_id", "node_id", "owner_ref", "instance_id", "profile_id", "profile_sha256", "cidr", "gateway", "ipv4", "mac"}
	if !uniqueFields(raw) || json.Unmarshal(raw, &fields) != nil || len(fields) != len(keys) {
		return b, ErrInvalid
	}
	for _, k := range keys {
		if v, ok := fields[k]; !ok || string(v) == "null" {
			return b, ErrInvalid
		}
	}
	if json.Unmarshal(raw, &b) != nil || !b.ValidIdentity() {
		return DirectPublicBinding{}, ErrInvalid
	}
	return b, nil
}

// SameDirectAddress permits physical placement only; guest network identity never rotates.
func SameDirectAddress(a, b DirectPublicBinding) bool {
	a.NodeID = ""
	b.NodeID = ""
	a.Generation = 0
	b.Generation = 0
	return a == b
}

// PublicRetireProof freezes the controller's independently queried exact target
// activation receipt. It is authenticated by the existing pinned controller
// channel, not an unauthenticated source_fenced/target_active boolean.
type PublicRetireProof struct {
	ActivateOperationID   string `json:"activate_operation_id"`
	ActivateRequestSHA256 string `json:"activate_request_sha256"`
	ActivateReceiptSHA256 string `json:"activate_receipt_sha256"`
	TargetProfileSHA256   string `json:"target_profile_sha256"`
	TargetGeneration      int64  `json:"target_generation"`
	ConfirmInstanceID     string `json:"confirm_instance_id"`
}

func (p PublicRetireProof) IsZero() bool { return p == (PublicRetireProof{}) }
func (p PublicRetireProof) ValidFor(t TypedStorageTask) bool {
	if !ValidID(p.ActivateOperationID) || !digest.MatchString(p.ActivateRequestSHA256) || !digest.MatchString(p.ActivateReceiptSHA256) || p.TargetProfileSHA256 != t.DirectPublic.ProfileSHA256 || p.TargetGeneration != t.DirectPublic.Generation+1 || p.ConfirmInstanceID != t.InstanceID {
		return false
	}
	r := StorageResult{Protocol: StorageDirectProtocol, OperationID: p.ActivateOperationID, RequestSHA256: p.ActivateRequestSHA256, Status: "succeeded", InstanceID: t.InstanceID, ArtifactID: t.ArtifactID, ManifestSHA256: t.ManifestSHA256, FenceToken: t.FenceToken, SourceNodeID: t.NodeID, TargetNodeID: t.TargetNodeID, Items: []StorageArtifact{}}
	raw, _ := json.Marshal(r)
	return Digest(raw) == p.ActivateReceiptSHA256
}
func decodeRetireProof(raw json.RawMessage) (PublicRetireProof, error) {
	var p PublicRetireProof
	var fields map[string]json.RawMessage
	keys := []string{"activate_operation_id", "activate_request_sha256", "activate_receipt_sha256", "target_profile_sha256", "target_generation", "confirm_instance_id"}
	if !uniqueFields(raw) || json.Unmarshal(raw, &fields) != nil || len(fields) != len(keys) {
		return p, ErrInvalid
	}
	for _, k := range keys {
		if v, ok := fields[k]; !ok || string(v) == "null" {
			return p, ErrInvalid
		}
	}
	if json.Unmarshal(raw, &p) != nil {
		return p, ErrInvalid
	}
	return p, nil
}

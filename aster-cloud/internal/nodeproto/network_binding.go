package nodeproto

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
)

// NetworkProtocol is explicit: legacy tasks cannot silently acquire OVS semantics.
const NetworkProtocol = "aster.node/2"
const OVSNetworkCapability = "ovs-vpc-singlehost/1"

// NetworkBinding is an immutable controller/IPAM reservation, never a host path,
// command, ofport or a cached permission to start a guest. All fields are scalars
// so task comparisons include the complete binding rather than pointer identity.
type NetworkBinding struct {
	ProfileSHA256 string `json:"profile_sha256"`
	Schema        int    `json:"schema"`
	ProfileID     string `json:"profile_id"`
	LeaseID       string `json:"lease_id"`
	PoolID        string `json:"pool_id"`
	VPCID         string `json:"vpc_id"`
	NodeID        string `json:"node_id"`
	OwnerRef      string `json:"owner_ref"`
	InstanceID    string `json:"instance_id"`
	CIDR          string `json:"cidr"`
	IPv4          string `json:"ipv4"`
	MAC           string `json:"mac"`
	InterfaceID   string `json:"interface_id"`
	VLANID        int    `json:"vlan_id"`
	InboundMbps   int    `json:"inbound_mbps"`
	OutboundMbps  int    `json:"outbound_mbps"`
}

func (n NetworkBinding) IsZero() bool   { return n == (NetworkBinding{}) }
func (n NetworkBinding) Digest() string { raw, _ := json.Marshal(n); return Digest(raw) }
func NetworkMAC(node, instance string) string {
	if !ValidNodeID(node) || !ValidID(instance) {
		return ""
	}
	h := sha256.Sum256([]byte(node + ":" + instance))
	return fmt.Sprintf("52:54:%02x:%02x:%02x:%02x", h[0], h[1], h[2], h[3])
}
func NetworkInterfaceID(instance string) string {
	if !ValidID(instance) {
		return ""
	}
	h := sha256.Sum256([]byte("aster.fabric.interface/1:" + instance))
	h[6] = h[6]&15 | 0x80
	h[8] = h[8]&63 | 0x80
	s := hex.EncodeToString(h[:16])
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
}
func (n NetworkBinding) ValidFor(t NodeTask) bool {
	p, e := netip.ParsePrefix(n.CIDR)
	ip, ie := netip.ParseAddr(n.IPv4)
	if n.Schema != 1 || !digest.MatchString(n.ProfileSHA256) || !ValidNodeID(n.ProfileID) || !ValidID(n.LeaseID) || !ValidID(n.PoolID) || !ValidID(n.VPCID) || n.NodeID != t.NodeID || n.OwnerRef != t.OwnerRef || n.InstanceID != t.InstanceID || !ValidID(n.OwnerRef) || !ValidID(n.InstanceID) || !ValidNodeID(n.NodeID) {
		return false
	}
	if e != nil || !p.Addr().Is4() || !p.Addr().IsPrivate() || p.Masked() != p || p.String() != n.CIDR || p.Bits() < 8 || p.Bits() > 30 || ie != nil || !ip.Is4() || ip.String() != n.IPv4 || !p.Contains(ip) || ip == p.Addr() || !p.Contains(ip.Next()) {
		return false
	}
	r := t.Resources
	return n.VLANID >= 1 && n.VLANID <= 4094 && n.MAC == NetworkMAC(n.NodeID, n.InstanceID) && n.InterfaceID == NetworkInterfaceID(n.InstanceID) && n.InboundMbps >= 1 && n.InboundMbps <= 100000 && n.OutboundMbps >= 1 && n.OutboundMbps <= 100000 && r.NetworkType == "vpc" && r.IPv4Count == 1 && r.IPv6Count == 0 && r.BandwidthMbps == n.OutboundMbps && r.InboundBandwidthMbps == n.InboundMbps && r.TransferGiB == 0 && r.TrafficDirection == "all"
}
func decodeNetworkBinding(raw json.RawMessage) (NetworkBinding, error) {
	var n NetworkBinding
	if !uniqueFields(raw) {
		return n, ErrInvalid
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 16 {
		return n, ErrInvalid
	}
	expected := []string{"profile_sha256", "schema", "profile_id", "lease_id", "pool_id", "vpc_id", "node_id", "owner_ref", "instance_id", "cidr", "ipv4", "mac", "interface_id", "vlan_id", "inbound_mbps", "outbound_mbps"}
	for _, key := range expected {
		v, ok := fields[key]
		if !ok || string(v) == "null" {
			return n, ErrInvalid
		}
	}
	if json.Unmarshal(raw, &n) != nil {
		return n, ErrInvalid
	}
	return n, nil
}

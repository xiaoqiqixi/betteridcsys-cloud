// Package fabric applies a root-approved, single-host OVS microsegment fabric.
// The embedded lifecycle gate is independent from the financial protocol.
package fabric

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"regexp"
	"sort"
)

var ErrInvalid = errors.New("INVALID_FABRIC_INPUT")
var ErrConflict = errors.New("FABRIC_REVISION_CONFLICT")
var ErrUncertain = errors.New("FABRIC_OUTCOME_UNCERTAIN")
var ErrUnavailable = errors.New("FABRIC_UNAVAILABLE")
var idRE = regexp.MustCompile(`^[0-9a-f]{32}$`)
var nodeRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
var bridgeRE = regexp.MustCompile(`^aster-[a-z0-9][a-z0-9_-]{0,8}$`)
var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$`)

type Config struct {
	Schema         int    `json:"schema"`
	NodeID         string `json:"node_id"`
	Bridge         string `json:"bridge"`
	StateDirectory string `json:"state_directory"`
	DedicatedAck   bool   `json:"dedicated_ack"`
}
type VPC struct {
	ID       string `json:"id"`
	OwnerRef string `json:"owner_ref"`
	CIDR     string `json:"cidr"`
	VLANID   int    `json:"vlan_id"`
}
type Port struct {
	InstanceID   string `json:"instance_id"`
	InterfaceID  string `json:"interface_id"`
	OwnerRef     string `json:"owner_ref"`
	VPCID        string `json:"vpc_id"`
	IPv4         string `json:"ipv4"`
	MAC          string `json:"mac"`
	OFPort       int    `json:"ofport"`
	InboundMbps  int    `json:"inbound_mbps"`
	OutboundMbps int    `json:"outbound_mbps"`
}
type Topology struct {
	Schema   int    `json:"schema"`
	NodeID   string `json:"node_id"`
	Revision int64  `json:"revision"`
	VPCs     []VPC  `json:"vpcs"`
	Ports    []Port `json:"ports"`
}
type Receipt struct {
	Schema    int    `json:"schema"`
	NodeID    string `json:"node_id"`
	Revision  int64  `json:"revision"`
	Digest    string `json:"digest"`
	State     string `json:"state"`
	Stage     string `json:"stage"`
	UpdatedAt string `json:"updated_at"`
}
type Meter struct{ ID, Kbps int }
type Plan struct {
	Topology Topology
	Digest   string
	Flows    []string
	Meters   []Meter
}

// InterfaceID is a name-derived UUIDv8 (SHA-256 custom namespace), not UUIDv5.
// The stable identity must also be independently pinned on the OVS Interface.
func InterfaceID(instance string) string {
	if !idRE.MatchString(instance) {
		return ""
	}
	h := sha256.Sum256([]byte("aster.fabric.interface/1:" + instance))
	h[6] = h[6]&15 | 0x80
	h[8] = h[8]&63 | 0x80
	s := hex.EncodeToString(h[:16])
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
}
func (c Config) Validate() bool {
	return c.Schema == 1 && nodeRE.MatchString(c.NodeID) && bridgeRE.MatchString(c.Bridge) && c.DedicatedAck && filepath.IsAbs(c.StateDirectory) && filepath.Clean(c.StateDirectory) == c.StateDirectory && c.StateDirectory != "/" && !bytes.ContainsAny([]byte(c.StateDirectory), "\x00\r\n")
}

// Strict object decoding includes required fields, duplicate/case rejection and
// null rejection. It never uses encoding/json's case-insensitive fallback.
func object(raw []byte, keys []string, out any) error {
	if len(raw) == 0 || len(raw) > 8<<20 {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return ErrInvalid
	}
	m := map[string]json.RawMessage{}
	for d.More() {
		t, err = d.Token()
		k, ok := t.(string)
		if err != nil || !ok {
			return ErrInvalid
		}
		if _, exists := m[k]; exists {
			return ErrInvalid
		}
		var v json.RawMessage
		if d.Decode(&v) != nil || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return ErrInvalid
		}
		m[k] = v
	}
	if _, err = d.Token(); err != nil || d.Decode(new(any)) != io.EOF || len(m) != len(keys) {
		return ErrInvalid
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return ErrInvalid
		}
	}
	if json.Unmarshal(raw, out) != nil {
		return ErrInvalid
	}
	return nil
}
func DecodeConfig(raw []byte) (Config, error) {
	var c Config
	if object(raw, []string{"schema", "node_id", "bridge", "state_directory", "dedicated_ack"}, &c) != nil || !c.Validate() {
		return c, ErrInvalid
	}
	return c, nil
}
func DecodeTopology(raw []byte) (Topology, error) {
	var t Topology
	if len(raw) > 1<<20 {
		return t, ErrInvalid
	}
	if object(raw, []string{"schema", "node_id", "revision", "vpcs", "ports"}, &t) != nil {
		return t, ErrInvalid
	}
	var outer map[string]json.RawMessage
	_ = json.Unmarshal(raw, &outer)
	var vpcs, ports []json.RawMessage
	if json.Unmarshal(outer["vpcs"], &vpcs) != nil || json.Unmarshal(outer["ports"], &ports) != nil || len(vpcs) > 32 || len(ports) > 128 {
		return t, ErrInvalid
	}
	for _, v := range vpcs {
		var p VPC
		if object(v, []string{"id", "owner_ref", "cidr", "vlan_id"}, &p) != nil {
			return t, ErrInvalid
		}
	}
	for _, v := range ports {
		var p Port
		if object(v, []string{"instance_id", "interface_id", "owner_ref", "vpc_id", "ipv4", "mac", "ofport", "inbound_mbps", "outbound_mbps"}, &p) != nil {
			return t, ErrInvalid
		}
	}
	if _, err := Compile(t); err != nil {
		return t, err
	}
	return t, nil
}

const cookie = "0xa57efab000000001"

func isolationFlows() []string {
	return []string{"cookie=" + cookie + ",table=0,priority=0 actions=drop", "cookie=" + cookie + ",table=10,priority=0 actions=drop"}
}

func Compile(t Topology) (Plan, error) {
	var p Plan
	if t.Schema != 1 || !nodeRE.MatchString(t.NodeID) || t.Revision < 1 || t.VPCs == nil || t.Ports == nil || len(t.VPCs) > 32 || len(t.Ports) > 128 {
		return p, ErrInvalid
	}
	// Clone before sorting: planning must not mutate the caller's snapshot.
	t.VPCs = append([]VPC{}, t.VPCs...)
	t.Ports = append([]Port{}, t.Ports...)
	sort.Slice(t.VPCs, func(i, j int) bool { return t.VPCs[i].ID < t.VPCs[j].ID })
	sort.Slice(t.Ports, func(i, j int) bool { return t.Ports[i].InstanceID < t.Ports[j].InstanceID })
	vpcs := map[string]VPC{}
	prefixes := map[string]netip.Prefix{}
	vlans := map[int]bool{}
	for _, v := range t.VPCs {
		prefix, e := netip.ParsePrefix(v.CIDR)
		if !idRE.MatchString(v.ID) || !idRE.MatchString(v.OwnerRef) || e != nil || !prefix.Addr().Is4() || !prefix.Addr().IsPrivate() || prefix.Masked() != prefix || prefix.Bits() < 8 || prefix.Bits() > 30 || v.VLANID < 1 || v.VLANID > 4094 || vlans[v.VLANID] {
			return p, ErrInvalid
		}
		if _, exists := vpcs[v.ID]; exists {
			return p, ErrInvalid
		}
		vpcs[v.ID] = v
		prefixes[v.ID] = prefix
		vlans[v.VLANID] = true
	}
	instances := map[string]bool{}
	ofports := map[int]bool{}
	ips := map[string]bool{}
	macs := map[string]bool{}
	p.Flows = isolationFlows()
	p.Flows = append(p.Flows, "cookie="+cookie+",table=0,priority=500,vlan_tci=0x1000/0x1000 actions=drop")
	for _, n := range t.Ports {
		v, ok := vpcs[n.VPCID]
		addr, e := netip.ParseAddr(n.IPv4)
		mac, me := net.ParseMAC(n.MAC)
		prefix := prefixes[n.VPCID]
		if !ok || !idRE.MatchString(n.InstanceID) || n.InterfaceID != InterfaceID(n.InstanceID) || n.OwnerRef != v.OwnerRef || e != nil || !addr.Is4() || addr.String() != n.IPv4 || !prefix.Contains(addr) || addr == prefix.Addr() || addr.Next().IsValid() && !prefix.Contains(addr.Next()) || me != nil || len(mac) != 6 || mac[0]&1 != 0 || mac.String() != n.MAC || n.MAC == "00:00:00:00:00:00" || n.OFPort < 1 || n.OFPort > 32767 || n.InboundMbps < 1 || n.InboundMbps > 100000 || n.OutboundMbps < 1 || n.OutboundMbps > 100000 || instances[n.InstanceID] || ofports[n.OFPort] || ips[n.VPCID+":"+n.IPv4] || macs[n.MAC] {
			return Plan{}, ErrInvalid
		}
		instances[n.InstanceID] = true
		ofports[n.OFPort] = true
		ips[n.VPCID+":"+n.IPv4] = true
		macs[n.MAC] = true
		in, out := n.OFPort*2, n.OFPort*2+1
		p.Meters = append(p.Meters, Meter{in, n.InboundMbps * 1000}, Meter{out, n.OutboundMbps * 1000})
		src := fmt.Sprintf("cookie=%s,table=0,priority=200,in_port=%d,dl_vlan=0xffff,dl_src=%s,", cookie, n.OFPort, n.MAC)
		actions := fmt.Sprintf(" actions=meter:%d,write_metadata:0x%x/0xffff,goto_table:10", out, v.VLANID)
		p.Flows = append(p.Flows, src+"ip,nw_src="+n.IPv4+actions)
		for _, op := range []int{1, 2} {
			p.Flows = append(p.Flows, src+fmt.Sprintf("arp,arp_op=%d,arp_sha=%s,arp_spa=%s", op, n.MAC, n.IPv4)+actions)
		}
		dst := fmt.Sprintf("cookie=%s,table=10,priority=200,metadata=0x%x/0xffff,", cookie, v.VLANID)
		output := fmt.Sprintf(" actions=meter:%d,output:%d", in, n.OFPort)
		p.Flows = append(p.Flows, dst+"ip,nw_dst="+n.IPv4+",dl_dst="+n.MAC+output)
		for _, dm := range []string{"ff:ff:ff:ff:ff:ff", n.MAC} {
			p.Flows = append(p.Flows, dst+"arp,arp_op=1,arp_tpa="+n.IPv4+",dl_dst="+dm+output)
		}
		p.Flows = append(p.Flows, dst+"arp,arp_op=2,arp_tpa="+n.IPv4+",arp_tha="+n.MAC+",dl_dst="+n.MAC+output)
	}
	raw, _ := json.Marshal(t)
	h := sha256.Sum256(raw)
	p.Digest = hex.EncodeToString(h[:])
	p.Topology = t
	return p, nil
}

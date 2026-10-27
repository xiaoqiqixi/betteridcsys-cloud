package overlayproto

import (
	"aster/cloud/internal/nodeproto"
	"encoding/json"
	"strings"
	"testing"
)

func natSnapshot() Snapshot {
	s := fixture()
	id := strings.Repeat("1", 32)
	s.Gateways = []Gateway{{NodeID: "node-a", InstanceID: id, InterfaceID: nodeproto.NetworkInterfaceID(id), OwnerRef: s.VPCs[0].OwnerRef, VPCID: s.VPCs[0].ID, IPv4: "10.24.0.1", MAC: "52:54:00:00:00:01", AllowedPrefixes: []string{"198.51.100.0/24"}}}
	s.NATPolicies = []NATPolicy{{ID: strings.Repeat("2", 32), NodeID: "node-a", VPCID: s.VPCs[0].ID, GatewayInstanceID: id, ProfileID: "nat-a", ProfileSHA256: strings.Repeat("3", 64), SNATEnabled: true, Forwardings: []NATForwarding{{ID: strings.Repeat("4", 32), Protocol: "tcp", PublicPort: 18080, TargetInstanceID: s.Members[0].InstanceID, TargetPort: 80, SourceCIDR: "198.51.100.0/24"}}}}
	return s
}
func TestNATSnapshotCanonicalAndStrict(t *testing.T) {
	s, sha, err := CanonicalSnapshot(natSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(s)
	if _, err := DecodeSnapshot(raw); err != nil || Digest(raw) != sha {
		t.Fatal(err)
	}
	for _, edit := range []func(string) string{func(s string) string {
		return strings.Replace(s, `"nat_policies":[`, `"nat_policies":null,"nat_policies":[`, 1)
	}, func(s string) string { return strings.Replace(s, `"snat_enabled":true`, `"SNAT_ENABLED":true`, 1) }, func(s string) string {
		return strings.Replace(s, `"source_cidr":"198.51.100.0/24"`, `"source_cidr":null`, 1)
	}} {
		if _, err := DecodeSnapshot([]byte(edit(string(raw)))); err == nil {
			t.Fatal("ambiguous NAT accepted")
		}
	}
	original := natSnapshot()
	original.NATPolicies[0].Forwardings = append(original.NATPolicies[0].Forwardings, NATForwarding{ID: strings.Repeat("5", 32), Protocol: "udp", PublicPort: 18080, TargetInstanceID: s.Members[0].InstanceID, TargetPort: 53, SourceCIDR: "198.51.100.0/25"})
	a, sha, err := CanonicalSnapshot(original)
	if err != nil {
		t.Fatal(err)
	}
	original.NATPolicies[0].Forwardings[0], original.NATPolicies[0].Forwardings[1] = original.NATPolicies[0].Forwardings[1], original.NATPolicies[0].Forwardings[0]
	_, other, err := CanonicalSnapshot(original)
	if err != nil || other != sha || a.NATPolicies[0].Forwardings[0].Protocol != "tcp" || original.NATPolicies[0].Forwardings[0].Protocol != "udp" {
		t.Fatal("NAT canonical mutates caller or ordering changes intent")
	}
	old, oldsha, _ := CanonicalSnapshot(fixture())
	oldraw, _ := json.Marshal(old)
	if strings.Contains(string(oldraw), "nat_policies") {
		t.Fatal("old snapshot rewritten")
	}
	old.NATPolicies = []NATPolicy{}
	_, emptysha, _ := CanonicalSnapshot(old)
	if oldsha != emptysha {
		t.Fatal("empty optional NAT changed history")
	}
}
func TestNATSnapshotConfusedDeputyRejected(t *testing.T) {
	cases := map[string]func(*Snapshot){"foreign-gateway": func(s *Snapshot) { s.NATPolicies[0].GatewayInstanceID = strings.Repeat("f", 32) }, "foreign-node": func(s *Snapshot) { s.NATPolicies[0].NodeID = "node-b" }, "foreign-vpc": func(s *Snapshot) { s.NATPolicies[0].VPCID = strings.Repeat("9", 32) }, "disabled-member": func(s *Snapshot) { s.Members[0].Enabled = false }, "missing-target": func(s *Snapshot) { s.NATPolicies[0].Forwardings[0].TargetInstanceID = strings.Repeat("9", 32) }, "bad-pin": func(s *Snapshot) { s.NATPolicies[0].ProfileSHA256 = "bad" }, "bad-protocol": func(s *Snapshot) { s.NATPolicies[0].Forwardings[0].Protocol = "icmp" }, "zero-port": func(s *Snapshot) { s.NATPolicies[0].Forwardings[0].PublicPort = 0 }, "port-overflow": func(s *Snapshot) { s.NATPolicies[0].Forwardings[0].TargetPort = 65536 }, "duplicate-port": func(s *Snapshot) {
		f := s.NATPolicies[0].Forwardings[0]
		f.ID = strings.Repeat("5", 32)
		s.NATPolicies[0].Forwardings = append(s.NATPolicies[0].Forwardings, f)
	}, "duplicate-policy": func(s *Snapshot) {
		p := s.NATPolicies[0]
		p.ID = strings.Repeat("5", 32)
		s.NATPolicies = append(s.NATPolicies, p)
	}, "unbounded-source": func(s *Snapshot) { s.NATPolicies[0].Forwardings[0].SourceCIDR = "0.0.0.0/0" }, "noncanonical-source": func(s *Snapshot) { s.NATPolicies[0].Forwardings[0].SourceCIDR = "198.51.100.1/24" }, "null-forwardings": func(s *Snapshot) { s.NATPolicies[0].Forwardings = nil }}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			s := natSnapshot()
			edit(&s)
			if _, _, err := CanonicalSnapshot(s); err == nil {
				t.Fatal("invalid NAT snapshot accepted")
			}
		})
	}
}

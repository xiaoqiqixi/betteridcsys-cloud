package overlayproto

import (
	"encoding/json"
	"strings"
	"testing"
)

func floatingSnapshot() Snapshot {
	s := natSnapshot()
	s.NATPolicies = nil
	g, m := s.Gateways[0], s.Members[0]
	s.FloatingIPs = []FloatingIP{{ResourceID: strings.Repeat("8", 32), NodeID: g.NodeID, VPCID: g.VPCID, OwnerRef: g.OwnerRef, ProfileID: "nat-a", ProfileSHA256: strings.Repeat("3", 64), GatewayInstanceID: g.InstanceID, InstanceID: m.InstanceID, TargetIPv4: m.IPv4, PublicIPv4: "8.8.4.3"}}
	return s
}
func TestFloatingSnapshotCanonicalExactIdentityAndCompatibility(t *testing.T) {
	old, oldsha, e := CanonicalSnapshot(natSnapshot())
	if e != nil {
		t.Fatal(e)
	}
	old.FloatingIPs = []FloatingIP{}
	empty, sha, e := CanonicalSnapshot(old)
	if e != nil || sha != oldsha {
		t.Fatal("empty field changes old bytes", e)
	}
	raw, _ := json.Marshal(empty)
	if strings.Contains(string(raw), "floating_ips") {
		t.Fatal("rewrote old bytes")
	}
	s, sha, e := CanonicalSnapshot(floatingSnapshot())
	if e != nil {
		t.Fatal(e)
	}
	raw, _ = json.Marshal(s)
	if got, e := DecodeSnapshot(raw); e != nil || len(got.FloatingIPs) != 1 || Digest(raw) != sha {
		t.Fatal("roundtrip", e)
	}
	for _, bad := range []string{strings.Replace(string(raw), `"floating_ips":[`, `"floating_ips":null,"floating_ips":[`, 1), strings.Replace(string(raw), `"public_ipv4":"8.8.4.3"`, `"Public_ipv4":"8.8.4.3"`, 1), strings.Replace(string(raw), `"target_ipv4":`, `"target_ipv4":null,"x":`, 1)} {
		if _, e := DecodeSnapshot([]byte(bad)); e == nil {
			t.Fatal("ambiguous wire accepted")
		}
	}
}
func TestFloatingSnapshotRejectsCrossTenantDuplicateAndDisabledTargets(t *testing.T) {
	for name, edit := range map[string]func(*Snapshot){
		"private":          func(s *Snapshot) { s.FloatingIPs[0].PublicIPv4 = "10.0.0.2" },
		"owner":            func(s *Snapshot) { s.FloatingIPs[0].OwnerRef = strings.Repeat("f", 32) },
		"wrong-ip":         func(s *Snapshot) { s.FloatingIPs[0].TargetIPv4 = "10.24.0.29" },
		"unknown-instance": func(s *Snapshot) { s.FloatingIPs[0].InstanceID = strings.Repeat("f", 32) },
		"wrong-vpc":        func(s *Snapshot) { s.FloatingIPs[0].VPCID = strings.Repeat("f", 32) },
		"wrong-gateway":    func(s *Snapshot) { s.FloatingIPs[0].GatewayInstanceID = strings.Repeat("f", 32) },
		"wrong-node":       func(s *Snapshot) { s.FloatingIPs[0].NodeID = "node-b" },
		"reserved":         func(s *Snapshot) { s.Members[0].Reserved = true },
		"disabled":         func(s *Snapshot) { s.Members[0].Enabled = false },
		"duplicate":        func(s *Snapshot) { s.FloatingIPs = append(s.FloatingIPs, s.FloatingIPs[0]) },
		"target-duplicate": func(s *Snapshot) {
			f := s.FloatingIPs[0]
			f.ResourceID = strings.Repeat("9", 32)
			f.PublicIPv4 = "8.8.4.4"
			s.FloatingIPs = append(s.FloatingIPs, f)
		},
		"nat-conflict": func(s *Snapshot) {
			p := natSnapshot().NATPolicies[0]
			p.PublicIPv4 = s.FloatingIPs[0].PublicIPv4
			s.NATPolicies = []NATPolicy{p}
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := floatingSnapshot()
			edit(&s)
			if _, _, e := CanonicalSnapshot(s); e == nil {
				t.Fatal("unsafe floating mapping accepted")
			}
		})
	}
}

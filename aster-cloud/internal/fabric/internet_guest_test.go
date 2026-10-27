package fabric

import (
	"aster/cloud/internal/overlayproto"
	"encoding/json"
	"strings"
	"testing"
)

func TestInternetGuestApprovalIsIndependentOnEveryNodeAndExactVPC(t *testing.T) {
	_, _, original, snapshot := internetNATFixture(t)
	copyCase := func() (OverlayConfig, overlayproto.Snapshot) {
		raw, _ := json.Marshal(original)
		var c OverlayConfig
		_ = json.Unmarshal(raw, &c)
		raw, _ = json.Marshal(snapshot)
		var s overlayproto.Snapshot
		_ = json.Unmarshal(raw, &s)
		return c, s
	}
	for _, remote := range []bool{false, true} {
		t.Run(map[bool]string{false: "local-NAT", true: "remote-NAT"}[remote], func(t *testing.T) {
			for name, edit := range map[string]func(*OverlayConfig, *overlayproto.Snapshot){
				"missing-approval":      func(c *OverlayConfig, _ *overlayproto.Snapshot) { c.GuestNetworks = []OverlayGuestNetwork{} },
				"withdrawn":             func(c *OverlayConfig, _ *overlayproto.Snapshot) { c.GuestNetworks[0].AllowInternetEgress = false },
				"overlapping-other-vpc": func(c *OverlayConfig, _ *overlayproto.Snapshot) { c.GuestNetworks[0].VPCID = strings.Repeat("e", 32) },
				"other-owner": func(c *OverlayConfig, _ *overlayproto.Snapshot) {
					c.GuestNetworks[0].OwnerRef = strings.Repeat("e", 32)
				},
				"other-cidr":    func(c *OverlayConfig, _ *overlayproto.Snapshot) { c.GuestNetworks[0].CIDR = "10.12.0.0/24" },
				"other-gateway": func(c *OverlayConfig, _ *overlayproto.Snapshot) { c.GuestNetworks[0].GatewayIPv4 = "10.11.0.2" },
				"local-map-mismatch": func(c *OverlayConfig, _ *overlayproto.Snapshot) {
					c.GuestNetworks[0].LocalVPCID = strings.Repeat("e", 32)
				},
			} {
				t.Run(name, func(t *testing.T) {
					c, s := copyCase()
					if remote {
						s.Gateways[0].NodeID = "node-b"
						s.NATPolicies[0].NodeID = "node-b"
					}
					if !internetGuestApproval(c, s) {
						t.Fatal("approved intent rejected")
					}
					edit(&c, &s)
					if internetGuestApproval(c, s) {
						t.Fatal("controller intent expanded independent node approval")
					}
				})
			}
		})
	}
	c, s := copyCase()
	s.Members = []overlayproto.Member{}
	c.GuestNetworks = []OverlayGuestNetwork{}
	if internetGuestApproval(c, s) {
		t.Fatal("empty local inventory bypassed root Internet approval")
	}
	c, s = copyCase()
	s.NATPolicies[0].InternetEgressEnabled = false
	c.GuestNetworks = []OverlayGuestNetwork{}
	if !internetGuestApproval(c, s) {
		t.Fatal("legacy prefix intent now needs Internet approval")
	}
}

func TestInternetGuestRootConfigStrictAndCanonicalCompatibility(t *testing.T) {
	_, _, c, s := internetNATFixture(t)
	c.GuestNetworks[0].DNSIPv4 = []string{"1.1.1.1", "8.8.8.8"}
	raw, _ := json.Marshal(c)
	decoded, err := DecodeOverlayConfig(raw)
	if err != nil || !decoded.GuestNetworks[0].AllowInternetEgress || len(decoded.GuestNetworks[0].DNSIPv4) != 2 {
		t.Fatal("public root config decode", err)
	}
	for _, name := range []string{"missing-vpc", "wrong-vpc", "private-unrouted-dns", "metadata-dns", "duplicate-dns", "too-many-dns"} {
		t.Run(name, func(t *testing.T) {
			var bad OverlayConfig
			_ = json.Unmarshal(raw, &bad)
			switch name {
			case "missing-vpc":
				bad.GuestNetworks[0].VPCID = ""
			case "wrong-vpc":
				bad.GuestNetworks[0].VPCID = strings.Repeat("e", 32)
			case "private-unrouted-dns":
				bad.GuestNetworks[0].DNSIPv4 = []string{"10.200.0.53"}
			case "metadata-dns":
				bad.GuestNetworks[0].DNSIPv4 = []string{"169.254.169.254"}
			case "duplicate-dns":
				bad.GuestNetworks[0].DNSIPv4 = []string{"1.1.1.1", "1.1.1.1"}
			case "too-many-dns":
				bad.GuestNetworks[0].DNSIPv4 = []string{"1.1.1.1", "8.8.8.8", "9.9.9.9", "4.2.2.1", "4.2.2.2"}
			}
			if _, err := canonicalOverlayConfig(bad); err == nil {
				t.Fatal("unsafe config accepted")
			}
		})
	}
	for _, key := range []string{"vpc_id", "allow_internet_egress", "dns_ipv4"} {
		var top map[string]json.RawMessage
		_ = json.Unmarshal(raw, &top)
		var nets []map[string]json.RawMessage
		_ = json.Unmarshal(top["guest_networks"], &nets)
		nets[0][key] = json.RawMessage("null")
		top["guest_networks"], _ = json.Marshal(nets)
		bad, _ := json.Marshal(top)
		if _, err := DecodeOverlayConfig(bad); err == nil {
			t.Fatalf("null guest key accepted %s", key)
		}
	}
	// Removing only optional false values restores byte-identical legacy shape.
	g := OverlayGuestNetwork{LocalVPCID: s.Members[0].LocalVPCID, OwnerRef: s.VPCs[0].OwnerRef, CIDR: s.VPCs[0].CIDR, GatewayIPv4: s.Gateways[0].IPv4, AllowedPrefixes: []string{"198.51.100.0/24"}}
	legacy, _ := json.Marshal(g)
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(legacy, &fields)
	for _, key := range []string{"vpc_id", "allow_internet_egress", "dns_ipv4"} {
		if _, exists := fields[key]; exists {
			t.Fatalf("new field emitted in legacy root %s", key)
		}
	}
}

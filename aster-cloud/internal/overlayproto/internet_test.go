package overlayproto

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func TestPublicInternetIPv4ExcludesSpecialUseAndReturnsIndependentFloor(t *testing.T) {
	for _, raw := range []string{"1.1.1.1", "8.8.8.8", "93.184.216.34", "223.255.255.254"} {
		if !PublicInternetIPv4(raw) {
			t.Fatalf("public address rejected %s", raw)
		}
	}
	for _, raw := range InternetReservedCIDRs() {
		p := netip.MustParsePrefix(raw)
		if PublicInternetIPv4(p.Addr().String()) || PublicInternetIPv4(p.Addr().Next().String()) {
			t.Fatalf("special address accepted %s", raw)
		}
	}
	for _, raw := range []string{"", "8.8.8.8/32", "::ffff:8.8.8.8", "2001:4860:4860::8888", "008.8.8.8", "8.8.8.8 ", "255.255.255.255"} {
		if PublicInternetIPv4(raw) {
			t.Fatalf("noncanonical/nonpublic accepted %q", raw)
		}
	}
	copy := InternetReservedCIDRs()
	copy[0] = "8.0.0.0/8"
	if InternetReservedCIDRs()[0] != "0.0.0.0/8" {
		t.Fatal("caller changed common floor")
	}
}

func TestInternetEgressIsExplicitIndependentIntentAndPreservesLegacyBytes(t *testing.T) {
	old, oldSHA, err := CanonicalSnapshot(natSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	oldRaw, _ := json.Marshal(old)
	if strings.Contains(string(oldRaw), "internet_egress_enabled") {
		t.Fatal("legacy bytes changed")
	}
	s := natSnapshot()
	s.NATPolicies[0].InternetEgressEnabled = true
	s.Gateways[0].AllowedPrefixes = []string{}
	s.NATPolicies[0].Forwardings = []NATForwarding{}
	public, publicSHA, err := CanonicalSnapshot(s)
	if err != nil || publicSHA == oldSHA {
		t.Fatal("pure Internet intent rejected or lost", err)
	}
	raw, _ := json.Marshal(public)
	if !strings.Contains(string(raw), `"internet_egress_enabled":true`) {
		t.Fatal("Internet intent omitted")
	}
	decoded, err := DecodeSnapshot(raw)
	if err != nil || !decoded.NATPolicies[0].InternetEgressEnabled {
		t.Fatal("Internet intent not decoded", err)
	}
	s.NATPolicies[0].SNATEnabled = false
	if _, _, err := CanonicalSnapshot(s); err == nil {
		t.Fatal("Internet without SNAT accepted")
	}
	s = natSnapshot()
	s.NATPolicies[0].InternetEgressEnabled = false
	_, sha, err := CanonicalSnapshot(s)
	if err != nil || sha != oldSHA {
		t.Fatal("false changed historical bytes", err)
	}
}

func TestInternetEgressStrictWireAndEmptyGatewayNotDefaultRoute(t *testing.T) {
	s := natSnapshot()
	s.NATPolicies[0].InternetEgressEnabled = true
	raw, _ := json.Marshal(s)
	for _, replacement := range []string{`"internet_egress_enabled":null`, `"internet_egress_enabled":"true"`, `"Internet_Egress_Enabled":true`, `"internet_egress_enabled":true,"internet_egress_enabled":false`} {
		if _, err := DecodeSnapshot([]byte(strings.Replace(string(raw), `"internet_egress_enabled":true`, replacement, 1))); err == nil {
			t.Fatalf("ambiguous intent accepted %s", replacement)
		}
	}
	s = natSnapshot()
	s.Gateways[0].AllowedPrefixes = []string{}
	s.NATPolicies = nil
	if _, _, err := CanonicalSnapshot(s); err != nil {
		t.Fatal("explicit no-route gateway rejected", err)
	}
	s.Gateways[0].AllowedPrefixes = nil
	if _, _, err := CanonicalSnapshot(s); err == nil {
		t.Fatal("nil routes accepted")
	}
	s.Gateways[0].AllowedPrefixes = []string{"0.0.0.0/0"}
	if _, _, err := CanonicalSnapshot(s); err == nil {
		t.Fatal("default route smuggled through prefix policy")
	}
}

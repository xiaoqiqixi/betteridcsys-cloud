package fabric

import (
	"aster/cloud/internal/overlayproto"
	"encoding/json"
	"strings"
	"testing"
)

func TestFloatingPublicIngressDefaultDenyAndStatefulOutboundReplies(t *testing.T) {
	_, _, c, s := floatingNATFixture(t)
	f := &s.FloatingIPs[0]
	policy := overlayproto.DefaultPublicIngress(f.InstanceID, f.OwnerRef)
	f.Ingress = &policy
	objects, e := compileNAT(c, s, c.NATProfiles[0], false)
	if e != nil {
		t.Fatal(e)
	}
	for _, proto := range []int{6, 17, 1} {
		p := natPolicyPacket{in: c.NATProfiles[0].OutsideInterface, out: c.NATProfiles[0].InsideInterface, src: "9.9.9.9", dst: f.TargetIPv4, originalDestination: f.PublicIPv4, proto: proto, kind: 8, dport: 443, state: 8, status: 32}
		if r := evaluateNATPolicy(t, objects, "forward", p); r.verdict != "drop" {
			t.Fatal("default accepted unsolicited public ingress", proto, r)
		}
		p.status = 16
		p.state = 2
		p.originalDestination = "9.9.9.9"
		if proto == 1 {
			p.kind = 0
		}
		if r := evaluateNATPolicy(t, objects, "forward", p); r.verdict != "accept" {
			t.Fatal("default deny broke authorized outgoing replies", proto, r)
		}
	}
	p := natPolicyPacket{in: c.NATProfiles[0].InsideInterface, out: c.NATProfiles[0].OutsideInterface, src: f.TargetIPv4, dst: "9.9.9.9", proto: 6, state: 8}
	if r := evaluateNATPolicy(t, objects, "forward", p); r.verdict != "accept" {
		t.Fatal("ingress changed outbound grant", r)
	}
}
func TestFloatingPublicIngressExactSourcesPortsProtectedFloorAndSharedNATIsolation(t *testing.T) {
	_, _, c, s := floatingNATFixture(t)
	root := c.NATProfiles[0]
	f := &s.FloatingIPs[0]
	policy, e := overlayproto.CanonicalPublicIngress(overlayproto.PublicIngressPolicy{Schema: 1, InstanceID: f.InstanceID, OwnerRef: f.OwnerRef, Revision: 1, Rules: []overlayproto.PublicIngressRule{{ID: strings.Repeat("1", 32), Protocol: "tcp", SourceCIDR: "9.9.9.0/24", PortStart: 440, PortEnd: 443}, {ID: strings.Repeat("2", 32), Protocol: "udp", SourceCIDR: "9.9.9.9/32", PortStart: 53, PortEnd: 53}, {ID: strings.Repeat("3", 32), Protocol: "icmp", SourceCIDR: "9.9.9.9/32"}}})
	if e != nil {
		t.Fatal(e)
	}
	f.Ingress = &policy
	objects, e := compileNAT(c, s, root, false)
	if e != nil {
		t.Fatal(e)
	}
	base := natPolicyPacket{in: root.OutsideInterface, out: root.InsideInterface, src: "9.9.9.9", dst: f.TargetIPv4, originalDestination: f.PublicIPv4, proto: 6, dport: 443, state: 8, status: 32}
	for _, port := range []int{440, 441, 443} {
		p := base
		p.dport = port
		if r := evaluateNATPolicy(t, objects, "forward", p); r.verdict != "accept" {
			t.Fatal("allowed TCP range denied", port, r)
		}
	}
	for name, edit := range map[string]func(*natPolicyPacket){"source": func(p *natPolicyPacket) { p.src = "8.8.8.8" }, "port-low": func(p *natPolicyPacket) { p.dport = 439 }, "port-high": func(p *natPolicyPacket) { p.dport = 444 }, "protocol": func(p *natPolicyPacket) { p.proto = 17 }, "private-route": func(p *natPolicyPacket) { p.status = 0; p.originalDestination = f.TargetIPv4 }, "other-eip": func(p *natPolicyPacket) { p.originalDestination = root.PublicIPv4s[0] }} {
		t.Run(name, func(t *testing.T) {
			p := base
			edit(&p)
			if r := evaluateNATPolicy(t, objects, "forward", p); r.verdict != "drop" {
				t.Fatal("unapproved ingress accepted", r)
			}
		})
	}
	p := base
	p.proto = 17
	p.dport = 53
	if r := evaluateNATPolicy(t, objects, "forward", p); r.verdict != "accept" {
		t.Fatal("UDP grant", r)
	}
	p.src = "9.9.9.10"
	if r := evaluateNATPolicy(t, objects, "forward", p); r.verdict != "drop" {
		t.Fatal("UDP source broadened", r)
	}
	p = base
	p.proto = 1
	p.kind = 8
	if r := evaluateNATPolicy(t, objects, "forward", p); r.verdict != "accept" {
		t.Fatal("ICMP echo grant", r)
	}
	p.kind = 5
	if r := evaluateNATPolicy(t, objects, "forward", p); r.verdict != "drop" {
		t.Fatal("ICMP redirect accepted", r)
	}
	// Even an explicit all-public CIDR rule cannot override protected prefixes.
	policy.SHA256 = ""
	policy.Rules = []overlayproto.PublicIngressRule{{ID: strings.Repeat("1", 32), Protocol: "tcp", SourceCIDR: "0.0.0.0/0", PortStart: 1, PortEnd: 65535}}
	policy, _ = overlayproto.CanonicalPublicIngress(policy)
	f.Ingress = &policy
	objects, e = compileNAT(c, s, root, false)
	if e != nil {
		t.Fatal(e)
	}
	for _, bad := range internetBlockedCIDRs(c, s) {
		p = base
		p.src = strings.Split(bad, "/")[0]
		if r := evaluateNATPolicy(t, objects, "forward", p); r.verdict != "drop" {
			t.Fatal("policy overrode protected floor", bad, r)
		}
	}
	// A shared DNAT for the same private VM must neither bypass this address's
	// deny policy nor be silently revoked by an independent EIP-specific policy.
	deny := overlayproto.DefaultPublicIngress(f.InstanceID, f.OwnerRef)
	f.Ingress = &deny
	root.AllowedSourceCIDRs = []string{"9.9.9.0/24"}
	root.AllowedPorts = []NATPortRange{{Protocol: "tcp", Start: 18080, End: 18080}}
	c.NATProfiles[0] = root
	c.Gateways[0].AllowedPrefixes = []string{"9.9.9.0/24"}
	s.Gateways[0].AllowedPrefixes = []string{"9.9.9.0/24"}
	c.GuestNetworks[0].AllowedPrefixes = []string{"9.9.9.0/24"}
	f.ProfileSHA256, _ = NATProfileSHA256(root)
	s.Profiles[0].ProfileSHA256, _ = OverlayConfigSHA256(c)
	s.NATPolicies = []overlayproto.NATPolicy{{ID: strings.Repeat("d", 32), NodeID: rootNode(c), VPCID: f.VPCID, GatewayInstanceID: f.GatewayInstanceID, ProfileID: root.ID, ProfileSHA256: f.ProfileSHA256, PublicIPv4: root.PublicIPv4s[0], Forwardings: []overlayproto.NATForwarding{{ID: strings.Repeat("e", 32), Protocol: "tcp", PublicPort: 18080, TargetInstanceID: f.InstanceID, TargetPort: 18080, SourceCIDR: "9.9.9.0/24"}}}}
	objects, e = compileNAT(c, s, root, false)
	if e != nil {
		t.Fatal(e)
	}
	p = base
	p.dport = 18080
	if r := evaluateNATPolicy(t, objects, "forward", p); r.verdict != "drop" {
		t.Fatal("borrowed shared NAT DNAT permission", r)
	}
	p.originalDestination = root.PublicIPv4s[0]
	if r := evaluateNATPolicy(t, objects, "forward", p); r.verdict != "accept" {
		t.Fatal("independent explicit shared NAT was changed", r)
	}
	raw, _ := json.Marshal(objects)
	if !strings.Contains(string(raw), `"dir":"original"`) {
		t.Fatal("original public destination not pinned")
	}
}

func TestFloatingPublicIngressRelatedICMPOnlyForExistingNATFlows(t *testing.T) {
	_, _, c, s := floatingNATFixture(t)
	f := &s.FloatingIPs[0]
	policy := overlayproto.DefaultPublicIngress(f.InstanceID, f.OwnerRef)
	f.Ingress = &policy
	root := c.NATProfiles[0]
	objects, e := compileNAT(c, s, root, false)
	if e != nil {
		t.Fatal(e)
	}
	for _, kind := range []int{3, 11, 12} {
		incoming := natPolicyPacket{in: root.OutsideInterface, out: root.InsideInterface, src: "9.9.9.9", dst: f.TargetIPv4, originalDestination: "9.9.9.9", proto: 1, kind: kind, state: 4, status: 16}
		outgoing := natPolicyPacket{in: root.InsideInterface, out: root.OutsideInterface, src: f.TargetIPv4, dst: "9.9.9.9", originalDestination: f.PublicIPv4, proto: 1, kind: kind, state: 4, status: 32}
		for _, packet := range []natPolicyPacket{incoming, outgoing} {
			if r := evaluateNATPolicy(t, objects, "forward", packet); r.verdict != "accept" {
				t.Fatal("related NAT ICMP error denied", kind, r)
			}
			packet.state = 8
			if r := evaluateNATPolicy(t, objects, "forward", packet); r.verdict != "drop" {
				t.Fatal("unsolicited ICMP error accepted", kind, r)
			}
		}
		outgoing.status = 0
		if r := evaluateNATPolicy(t, objects, "forward", outgoing); r.verdict != "drop" {
			t.Fatal("unrelated outgoing ICMP error accepted", kind, r)
		}
		incoming.status = 0
		if r := evaluateNATPolicy(t, objects, "forward", incoming); r.verdict != "drop" {
			t.Fatal("private route borrowed SNAT error allowance", kind, r)
		}
	}
}

func TestFloatingPublicIngressNativeOriginalTupleShapeAndStrictReadback(t *testing.T) {
	_, _, c, s := floatingNATFixture(t)
	f := &s.FloatingIPs[0]
	policy := overlayproto.DefaultPublicIngress(f.InstanceID, f.OwnerRef)
	f.Ingress = &policy
	objects, err := compileNAT(c, s, c.NATProfiles[0], false)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(nftObject{"nftables": objects})
	want, _, err := normalizeNFT(raw)
	if err != nil {
		t.Fatal(err)
	}
	// This is the exact native Ubuntu22/24 readback shape: family is already
	// constrained by payload ip daddr. The tuple direction is never inferred.
	needle := `"ct":{"dir":"original","key":"daddr"}`
	if strings.Count(string(want), needle) != 1 || !strings.Contains(string(want), `"payload":{"field":"daddr","protocol":"ip"}`) {
		t.Fatal("missing native IPv4 original-tuple guard")
	}
	for name, bad := range map[string]string{
		"reply-direction":   strings.Replace(string(want), `"dir":"original"`, `"dir":"reply"`, 1),
		"missing-direction": strings.Replace(string(want), `"dir":"original",`, ``, 1),
		"wrong-tuple-key":   strings.Replace(string(want), needle, `"ct":{"dir":"original","key":"saddr"}`, 1),
		"wrong-family":      strings.Replace(string(want), needle, `"ct":{"dir":"original","family":"ip6","key":"daddr"}`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if bad == string(want) {
				t.Fatal("test failed to mutate readback")
			}
			got, _, err := normalizeNFT([]byte(`{"nftables":` + bad + `}`))
			if err == nil && string(got) == string(want) {
				t.Fatal("tuple change normalized into a successful proof")
			}
		})
	}
}

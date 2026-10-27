package fabric

import (
	"aster/cloud/internal/overlayproto"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func floatingNATFixture(t *testing.T) (*Executor, *natFake, OverlayConfig, overlayproto.Snapshot) {
	t.Helper()
	e, f, c, s := internetNATFixture(t)
	p := c.NATProfiles[0]
	p.AllowFloatingIP = true
	p.PublicIPv4s = []string{"8.8.4.3"}
	c.NATProfiles[0] = p
	sha, err := OverlayConfigSHA256(c)
	if err != nil {
		t.Fatal(err)
	}
	s.Profiles[0].ProfileSHA256 = sha
	nsha, _ := NATProfileSHA256(p)
	s.NATPolicies = nil
	m, g := s.Members[0], s.Gateways[0]
	s.FloatingIPs = []overlayproto.FloatingIP{{ResourceID: strings.Repeat("c", 32), NodeID: g.NodeID, VPCID: g.VPCID, OwnerRef: g.OwnerRef, ProfileID: p.ID, ProfileSHA256: nsha, GatewayInstanceID: g.InstanceID, InstanceID: m.InstanceID, TargetIPv4: m.IPv4, PublicIPv4: p.PublicIPv4}}
	f.config, f.profile, f.snapshot = c, p, s
	return e, f, c, s
}
func TestFloatingNATRealCompilerTargetAndSourceExclusivity(t *testing.T) {
	_, _, c, s := floatingNATFixture(t)
	root := c.NATProfiles[0]
	o, err := compileNAT(c, s, root, false)
	if err != nil {
		t.Fatal(err)
	}
	ip := s.Members[0].IPv4
	fip := s.FloatingIPs[0].PublicIPv4
	for _, proto := range []int{6, 17, 1} {
		in := natPolicyPacket{in: root.OutsideInterface, out: root.InsideInterface, src: "9.9.9.9", dst: fip, proto: proto, kind: 8, state: 8}
		if r := evaluateNATPolicy(t, o, "prerouting", in); r.verdict != "dnat" || r.translated != ip {
			t.Fatal("no whole address DNAT", proto, r)
		}
		in.dst = ip
		in.status = 32
		if r := evaluateNATPolicy(t, o, "forward", in); r.verdict != "accept" {
			t.Fatal("valid inbound denied", proto, r)
		}
		in.status = 0
		if r := evaluateNATPolicy(t, o, "forward", in); r.verdict != "drop" {
			t.Fatal("private route bypassed DNAT", r)
		}
		out := natPolicyPacket{in: root.InsideInterface, out: root.OutsideInterface, src: ip, dst: "9.9.9.9", proto: proto, kind: 8, state: 8}
		if r := evaluateNATPolicy(t, o, "forward", out); r.verdict != "accept" {
			t.Fatal("assigned VM outbound denied", r)
		}
		if r := evaluateNATPolicy(t, o, "postrouting", out); r.verdict != "snat" || r.translated != fip {
			t.Fatal("assigned VM source changed", r)
		}
		for _, bad := range []string{"169.254.169.254", "10.77.0.2", c.LocalIPv4, c.Peers[0].IPv4, "11.0.0.2", root.UplinkGatewayIPv4, root.PublicIPv4s[0]} {
			out.dst = bad
			if r := evaluateNATPolicy(t, o, "forward", out); r.verdict != "drop" {
				t.Fatal("protected destination reachable", bad, r)
			}
			in.src = bad
			in.status = 32
			if r := evaluateNATPolicy(t, o, "forward", in); r.verdict != "drop" {
				t.Fatal("protected source accepted", bad, r)
			}
		}
	}
	for _, other := range s.Members[1:] {
		out := natPolicyPacket{in: root.InsideInterface, out: root.OutsideInterface, src: other.IPv4, dst: "9.9.9.9", proto: 6, state: 8}
		if r := evaluateNATPolicy(t, o, "forward", out); r.verdict != "drop" {
			t.Fatal("other VM borrowed floating IP", r)
		}
	}
	// When shared NAT exists, this VM keeps its own public source, not the default.
	p := overlayproto.NATPolicy{ID: strings.Repeat("d", 32), NodeID: rootNode(c), VPCID: root.VPCID, GatewayInstanceID: root.GatewayInstanceID, ProfileID: root.ID, ProfileSHA256: s.FloatingIPs[0].ProfileSHA256, SNATEnabled: true, InternetEgressEnabled: true, PublicIPv4: root.PublicIPv4s[0], Forwardings: []overlayproto.NATForwarding{}}
	s.NATPolicies = []overlayproto.NATPolicy{p}
	o, err = compileNAT(c, s, root, false)
	if err != nil {
		t.Fatal(err)
	}
	out := natPolicyPacket{in: root.InsideInterface, out: root.OutsideInterface, src: ip, dst: "9.9.9.9", proto: 6, state: 8}
	if r := evaluateNATPolicy(t, o, "postrouting", out); r.translated != fip {
		t.Fatal("shared SNAT stole floating source", r)
	}
}
func rootNode(c OverlayConfig) string { return c.Base.NodeID }
func TestFloatingIndependentRootApprovalAndOldCanonicalPins(t *testing.T) {
	_, _, c, s := floatingNATFixture(t)
	raw, _ := json.Marshal(c)
	for name, edit := range map[string]func(*OverlayConfig){"missing-grant": func(c *OverlayConfig) { c.NATProfiles[0].AllowFloatingIP = false }, "address-withdrawn": func(c *OverlayConfig) { c.NATProfiles[0].PublicIPv4 = "8.8.4.5" }, "wrong-namespace": func(c *OverlayConfig) { c.NATProfiles[0].NamespaceInode++ }, "internet-withdrawn": func(c *OverlayConfig) { c.NATProfiles[0].AllowInternetEgress = false }, "guest-withdrawn": func(c *OverlayConfig) { c.GuestNetworks[0].AllowInternetEgress = false }} {
		t.Run(name, func(t *testing.T) {
			var bad OverlayConfig
			_ = json.Unmarshal(raw, &bad)
			edit(&bad)
			if _, _, _, err := validateOverlayApproval(bad, s); err == nil {
				t.Fatal("independent root withdrawal bypassed")
			}
		})
	}
	old := c
	old.NATProfiles = append([]NATProfile{}, c.NATProfiles...)
	old.NATProfiles[0].AllowFloatingIP = false
	oldsha, _ := NATProfileSHA256(old.NATProfiles[0])
	b, _ := json.Marshal(old.NATProfiles[0])
	if strings.Contains(string(b), "allow_floating_ip") {
		t.Fatal("false changed historical field set")
	}
	if oldsha == s.FloatingIPs[0].ProfileSHA256 {
		t.Fatal("new root capability did not change pin")
	}
	if _, err := DecodeOverlayConfig(raw); err != nil {
		t.Fatal("new strict root config", err)
	}
}
func TestFloatingThreePhaseReadbackAndRemovalAreFailClosed(t *testing.T) {
	e, f, c, s := floatingNATFixture(t)
	ctx := context.Background()
	noop := func(context.Context) error { return nil }
	if _, err := e.PrepareOverlay(ctx, c, overlayTask(t, s, "prepare"), noop); err != nil {
		t.Fatal(err)
	}
	if f.forward != "0" {
		t.Fatal("prepare forwarded")
	}
	if _, err := e.ProgramOverlay(ctx, c, overlayTask(t, s, "program")); err != nil || f.forward != "0" || f.flushes != 1 {
		t.Fatal("program", err, f.flushes)
	}
	if _, err := e.ReleaseOverlay(ctx, c, overlayTask(t, s, "release"), noop); err != nil || f.forward != "1" {
		t.Fatal("release", err)
	}
	s.PreviousSHA256 = overlayTask(t, s, "release").SnapshotSHA256
	s.Epoch++
	s.FloatingIPs = nil
	f.snapshot = s
	if _, err := e.PrepareOverlay(ctx, c, overlayTask(t, s, "prepare"), noop); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ProgramOverlay(ctx, c, overlayTask(t, s, "program")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ReleaseOverlay(ctx, c, overlayTask(t, s, "release"), noop); err != nil || f.forward != "0" || f.flushes != 2 {
		t.Fatal("unbound namespace remained forwarding", err)
	}
	raw, _ := json.Marshal(f.rules)
	if strings.Contains(string(raw), "dnat") || strings.Contains(string(raw), "snat") {
		t.Fatal("old floating rules survived")
	}
}

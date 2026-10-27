package fabric

import (
	"aster/cloud/internal/overlayproto"
	"testing"
)

func TestFloatingRemoteTargetRetainsOVSAndNamespaceIsolation(t *testing.T) {
	_, _, c, s := floatingNATFixture(t)
	target := s.Members[1]
	g := s.Gateways[0]
	s.FloatingIPs[0].InstanceID, s.FloatingIPs[0].TargetIPv4 = target.InstanceID, target.IPv4
	ports := []overlayPort{{Name: TAPName(s.Members[0].InstanceID), OFPort: 1}, {Name: overlayTunnelName(c.Base.NodeID, target.NodeID), OFPort: 7}, {Name: TAPName(g.InstanceID), OFPort: 8}}
	plan, err := compileOverlay(c, s, ports)
	if err != nil {
		t.Fatal(err)
	}
	egress := policyPacket{in: 7, kind: "ip", srcMAC: target.MAC, dstMAC: g.MAC, srcIP: target.IPv4, dstIP: "9.9.9.9", tunSrc: c.Peers[0].IPv4, tunDst: c.LocalIPv4, tunID: uint64(s.VPCs[0].VNI)}
	if out := policyEvaluate(t, plan, egress); len(out) != 1 || out[0].port != 8 {
		t.Fatal("remote target cannot reach owned egress", out)
	}
	reply := policyPacket{in: 8, kind: "ip", srcMAC: g.MAC, dstMAC: target.MAC, srcIP: "9.9.9.9", dstIP: target.IPv4}
	if out := policyEvaluate(t, plan, reply); len(out) != 1 || out[0].port != 7 || out[0].tunnel != uint64(s.VPCs[0].VNI) {
		t.Fatal("wrong VNI/return target", out)
	}
	for name, edit := range map[string]func(*policyPacket){"peer": func(p *policyPacket) { p.tunSrc = "12.0.0.99" }, "vni": func(p *policyPacket) { p.tunID++ }, "forged-mac": func(p *policyPacket) { p.srcMAC = g.MAC }, "forged-source": func(p *policyPacket) { p.srcIP = "10.11.0.99" }, "tagged": func(p *policyPacket) { p.tagged = true }, "metadata": func(p *policyPacket) { p.dstIP = "169.254.169.254" }, "own-public": func(p *policyPacket) { p.dstIP = s.FloatingIPs[0].PublicIPv4 }} {
		t.Run(name, func(t *testing.T) {
			p := egress
			edit(&p)
			if out := policyEvaluate(t, plan, p); len(out) != 0 {
				t.Fatal("remote floating granted a new packet capability", out)
			}
		})
	}
	// Root Internet grant is independent on participants, even without local NAT.
	c.GuestNetworks[0].AllowInternetEgress = false
	sha, err := OverlayConfigSHA256(c)
	if err != nil {
		t.Fatal(err)
	}
	s.Profiles[0].ProfileSHA256 = sha
	if _, _, _, err := validateOverlayApproval(c, s); err == nil {
		t.Fatal("floating bypassed per-node guest approval")
	}
	s.FloatingIPs = nil
	sha, _ = OverlayConfigSHA256(c)
	s.Profiles[0].ProfileSHA256 = sha
	if _, _, _, err := validateOverlayApproval(c, s); err != nil {
		t.Fatal("removal should not require a withdrawn Internet permission", err)
	}
	// An empty explicit optional array must still be omitted on the wire.
	s.FloatingIPs = []overlayproto.FloatingIP{}
	if _, _, err := overlayproto.CanonicalSnapshot(s); err != nil {
		t.Fatal(err)
	}
}

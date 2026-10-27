package fabric

import (
	"aster/cloud/internal/nodeproto"
	"aster/cloud/internal/overlayproto"
	"net/netip"
	"strconv"
	"strings"
	"testing"
)

// This evaluator consumes the real compiled match/action strings. It is not a
// replacement for OVS/packet testing; it exercises policy decisions instead of
// merely checking whether a rule's text occurs somewhere in the generated plan.
type policyPacket struct {
	in                                 int
	kind, srcMAC, dstMAC, srcIP, dstIP string
	arpOp                              int
	arpSHA, arpSPA, arpTHA, arpTPA     string
	tunSrc, tunDst                     string
	tunID                              uint64
	tagged                             bool
	metadata                           uint64
}
type policyOutput struct {
	port   int
	tunnel uint64
}

func policyNumber(t *testing.T, s string) uint64 {
	t.Helper()
	v, e := strconv.ParseUint(s, 0, 64)
	if e != nil {
		t.Fatalf("bad generated number %q", s)
	}
	return v
}
func policyPrefixMatches(t *testing.T, s, ip string) bool {
	t.Helper()
	a, e := netip.ParseAddr(ip)
	if e != nil {
		return false
	}
	if !strings.Contains(s, "/") {
		return a.String() == s
	}
	p, e := netip.ParsePrefix(s)
	if e != nil {
		t.Fatal(e)
	}
	return p.Contains(a)
}
func policyMaskMatches(t *testing.T, want string, actual uint64) bool {
	t.Helper()
	parts := strings.Split(want, "/")
	mask := ^uint64(0)
	if len(parts) == 2 {
		mask = policyNumber(t, parts[1])
	}
	return actual&mask == policyNumber(t, parts[0])&mask
}
func policyRuleMatches(t *testing.T, fields []string, p policyPacket) bool {
	for _, field := range fields {
		kv := strings.SplitN(field, "=", 2)
		if len(kv) == 1 {
			if kv[0] != p.kind {
				return false
			}
			continue
		}
		k, v := kv[0], kv[1]
		match := true
		switch k {
		case "cookie", "table", "priority":
			continue
		case "in_port":
			match = p.in == int(policyNumber(t, v))
		case "dl_vlan":
			match = v == "0xffff" && !p.tagged
		case "vlan_tci":
			match = p.tagged
		case "dl_src":
			match = p.srcMAC == v
		case "dl_dst":
			match = p.dstMAC == v
		case "nw_src":
			match = policyPrefixMatches(t, v, p.srcIP)
		case "nw_dst":
			match = policyPrefixMatches(t, v, p.dstIP)
		case "arp_op":
			match = p.arpOp == int(policyNumber(t, v))
		case "arp_sha":
			match = p.arpSHA == v
		case "arp_spa":
			match = p.arpSPA == v
		case "arp_tha":
			match = p.arpTHA == v
		case "arp_tpa":
			match = p.arpTPA == v
		case "tun_src":
			match = p.tunSrc == v
		case "tun_dst":
			match = p.tunDst == v
		case "tun_id":
			match = p.tunID == policyNumber(t, v)
		case "metadata":
			match = policyMaskMatches(t, v, p.metadata)
		default:
			t.Fatalf("unmodeled match field: %s", k)
		}
		if !match {
			return false
		}
	}
	return true
}
func policyEvaluate(t *testing.T, plan overlayPlan, p policyPacket) []policyOutput {
	t.Helper()
	p.metadata = 0
	meterIDs := map[int]bool{}
	for _, m := range plan.Meters {
		meterIDs[m.ID] = true
	}
	table := 0
	out := []policyOutput{}
	for step := 0; step < 3; step++ {
		priority := -1
		actions := ""
		for _, line := range plan.Flows {
			halves := strings.SplitN(line, " actions=", 2)
			if len(halves) != 2 {
				t.Fatal(line)
			}
			fields := strings.Split(halves[0], ",")
			tab, pri := -1, -1
			for _, f := range fields {
				if strings.HasPrefix(f, "table=") {
					tab = int(policyNumber(t, strings.TrimPrefix(f, "table=")))
				}
				if strings.HasPrefix(f, "priority=") {
					pri = int(policyNumber(t, strings.TrimPrefix(f, "priority=")))
				}
			}
			if tab != table || pri < priority || !policyRuleMatches(t, fields, p) {
				continue
			}
			if pri == priority && actions != "" && actions != halves[1] {
				t.Fatalf("ambiguous equal priority rules: %s vs %s", actions, line)
			}
			priority = pri
			actions = halves[1]
		}
		if actions == "" || actions == "drop" {
			return out
		}
		next := -1
		for _, a := range strings.Split(actions, ",") {
			kv := strings.SplitN(a, ":", 2)
			if len(kv) != 2 {
				t.Fatalf("unmodeled action %s", a)
			}
			switch kv[0] {
			case "meter":
				if !meterIDs[int(policyNumber(t, kv[1]))] {
					t.Fatalf("missing meter %s", a)
				}
			case "write_metadata":
				parts := strings.Split(kv[1], "/")
				if len(parts) != 2 {
					t.Fatal(a)
				}
				mask := policyNumber(t, parts[1])
				p.metadata = p.metadata&^mask | policyNumber(t, parts[0])&mask
			case "goto_table":
				next = int(policyNumber(t, kv[1]))
			case "set_tunnel":
				p.tunID = policyNumber(t, kv[1])
			case "output":
				port := int(policyNumber(t, kv[1]))
				if port != p.in {
					out = append(out, policyOutput{port, p.tunID})
				}
			default:
				t.Fatalf("unmodeled action %s", a)
			}
		}
		if next < 0 {
			return out
		}
		table = next
	}
	t.Fatal("unexpected loop")
	return nil
}
func TestOverlayPacketPolicyIsolationAndRouting(t *testing.T) {
	_, _, c, s := overlayFixture(t)
	owner2, vpc2, id2 := strings.Repeat("a", 32), strings.Repeat("b", 32), strings.Repeat("c", 32)
	s.VPCs = append(s.VPCs, overlayproto.VPC{ID: vpc2, OwnerRef: owner2, CIDR: "10.22.0.0/24", VNI: 5002})
	third := overlayproto.Member{NodeID: "node-a", InstanceID: id2, InterfaceID: InterfaceID(id2), OwnerRef: owner2, VPCID: vpc2, LocalVPCID: vpc2, LeaseID: strings.Repeat("d", 32), PoolID: strings.Repeat("e", 32), NetworkSHA256: strings.Repeat("a", 64), IPv4: "10.22.0.2", MAC: nodeproto.NetworkMAC("node-a", id2), InboundMbps: 100, OutboundMbps: 200, Enabled: true}
	s.Members = append(s.Members, third)
	gatewayID := strings.Repeat("8", 32)
	g := overlayproto.Gateway{NodeID: "node-a", InstanceID: gatewayID, InterfaceID: InterfaceID(gatewayID), OwnerRef: s.VPCs[0].OwnerRef, VPCID: s.VPCs[0].ID, IPv4: "10.11.0.1", MAC: "52:54:00:00:00:01", AllowedPrefixes: []string{"203.0.113.0/24"}}
	c.Gateways = []overlayproto.Gateway{g}
	s.Gateways = c.Gateways
	remoteCID := strings.Repeat("9", 32)
	remoteC := overlayproto.Member{NodeID: "node-c", InstanceID: remoteCID, InterfaceID: InterfaceID(remoteCID), OwnerRef: s.VPCs[0].OwnerRef, VPCID: s.VPCs[0].ID, LocalVPCID: s.VPCs[0].ID, LeaseID: strings.Repeat("f", 32), PoolID: strings.Repeat("7", 32), NetworkSHA256: strings.Repeat("a", 64), IPv4: "10.11.0.4", MAC: nodeproto.NetworkMAC("node-c", remoteCID), InboundMbps: 100, OutboundMbps: 200, Enabled: true}
	s.Members = append(s.Members, remoteC)
	s.Profiles = append(s.Profiles, overlayproto.ProfilePin{NodeID: "node-c", ProfileID: "fabric-c", ProfileSHA256: strings.Repeat("c", 64)})
	c.Peers = append(c.Peers, OverlayPeer{NodeID: "node-c", IPv4: "192.0.2.12"})
	sha, _ := OverlayConfigSHA256(c)
	s.Profiles[0].ProfileSHA256 = sha
	ports := []overlayPort{{Name: TAPName(s.Members[0].InstanceID), OFPort: 1}, {Name: TAPName(third.InstanceID), OFPort: 2}, {Name: overlayTunnelName("node-a", "node-b"), OFPort: 7}, {Name: TAPName(g.InstanceID), OFPort: 8}, {Name: overlayTunnelName("node-a", "node-c"), OFPort: 9}}
	plan, err := compileOverlay(c, s, ports)
	if err != nil {
		t.Fatal(err)
	}
	local, remote := s.Members[0], s.Members[1]
	localIP := policyPacket{in: 1, kind: "ip", srcMAC: local.MAC, dstMAC: remote.MAC, srcIP: local.IPv4, dstIP: remote.IPv4}
	remoteIP := policyPacket{in: 7, kind: "ip", srcMAC: remote.MAC, dstMAC: local.MAC, srcIP: remote.IPv4, dstIP: local.IPv4, tunSrc: "192.0.2.11", tunDst: "192.0.2.10", tunID: 5001}
	gatewayOut := localIP
	gatewayOut.dstIP = "203.0.113.20"
	gatewayOut.dstMAC = g.MAC
	remoteGateway := remoteIP
	remoteGateway.dstIP = "203.0.113.20"
	remoteGateway.dstMAC = g.MAC
	gatewayReturn := policyPacket{in: 8, kind: "ip", srcMAC: g.MAC, dstMAC: remote.MAC, srcIP: "203.0.113.20", dstIP: remote.IPv4}
	arp := policyPacket{in: 1, kind: "arp", srcMAC: local.MAC, dstMAC: "ff:ff:ff:ff:ff:ff", arpOp: 1, arpSHA: local.MAC, arpSPA: local.IPv4, arpTPA: g.IPv4}
	arpReturn := policyPacket{in: 8, kind: "arp", srcMAC: g.MAC, dstMAC: local.MAC, arpOp: 2, arpSHA: g.MAC, arpSPA: g.IPv4, arpTHA: local.MAC, arpTPA: local.IPv4}
	cases := []struct {
		name string
		p    policyPacket
		port int
		tun  uint64
	}{{"local-to-remote", localIP, 7, 5001}, {"remote-to-local", remoteIP, 1, 5001}, {"local-to-approved-route", gatewayOut, 8, 0}, {"remote-to-local-gateway", remoteGateway, 8, 5001}, {"gateway-return-to-remote", gatewayReturn, 7, 5001}, {"arp-gateway", arp, 8, 0}, {"gateway-arp-reply", arpReturn, 1, 0}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := policyEvaluate(t, plan, tc.p)
			if len(out) != 1 || out[0] != (policyOutput{tc.port, tc.tun}) {
				t.Fatal(out)
			}
		})
	}
	bad := map[string]policyPacket{}
	mutate := func(name string, base policyPacket, f func(*policyPacket)) { f(&base); bad[name] = base }
	mutate("wrong-source-ip", localIP, func(p *policyPacket) { p.srcIP = remote.IPv4 })
	mutate("wrong-source-mac", localIP, func(p *policyPacket) { p.srcMAC = remote.MAC })
	mutate("tagged", localIP, func(p *policyPacket) { p.tagged = true })
	mutate("cross-vpc", localIP, func(p *policyPacket) { p.dstMAC = third.MAC; p.dstIP = third.IPv4 })
	mutate("wrong-tunnel-peer", remoteIP, func(p *policyPacket) { p.tunSrc = "192.0.2.12" })
	mutate("wrong-tunnel-destination", remoteIP, func(p *policyPacket) { p.tunDst = "192.0.2.12" })
	mutate("wrong-vni", remoteIP, func(p *policyPacket) { p.tunID = 5002 })
	mutate("unknown-tunnel", remoteIP, func(p *policyPacket) { p.in = 10 })
	mutate("peer-transit", remoteIP, func(p *policyPacket) { p.dstIP = remoteC.IPv4; p.dstMAC = remoteC.MAC })
	mutate("underlay-route", gatewayOut, func(p *policyPacket) { p.dstIP = "192.0.2.11" })
	mutate("metadata-route", gatewayOut, func(p *policyPacket) { p.dstIP = "169.254.169.254" })
	mutate("gateway-return-spoof", gatewayReturn, func(p *policyPacket) { p.srcIP = "198.51.100.2" })
	mutate("forged-gateway-mac", localIP, func(p *policyPacket) { p.srcMAC = g.MAC; p.srcIP = g.IPv4 })
	mutate("forged-gateway-arp", arp, func(p *policyPacket) { p.arpSPA = g.IPv4 })
	mutate("forged-arp-sha", arp, func(p *policyPacket) { p.arpSHA = g.MAC })
	mutate("gateway-arp-vpc2", arpReturn, func(p *policyPacket) { p.arpTPA = third.IPv4; p.arpTHA = third.MAC; p.dstMAC = third.MAC })
	mutate("other-vpc-source", localIP, func(p *policyPacket) {
		p.in = 2
		p.srcMAC = third.MAC
		p.srcIP = third.IPv4
		p.dstIP = remote.IPv4
		p.dstMAC = remote.MAC
	})
	for name, p := range bad {
		t.Run(name, func(t *testing.T) {
			if out := policyEvaluate(t, plan, p); len(out) != 0 {
				t.Fatalf("unauthorized packet output: %+v", out)
			}
		})
	}
	t.Run("disabled-source-and-destination", func(t *testing.T) {
		disabled := s
		disabled.Members = append([]overlayproto.Member{}, s.Members...)
		disabled.Members[0].Enabled = false
		dp, err := compileOverlay(c, disabled, ports)
		if err != nil {
			t.Fatal(err)
		}
		if out := policyEvaluate(t, dp, localIP); len(out) != 0 {
			t.Fatal("disabled source forwarded", out)
		}
		if out := policyEvaluate(t, dp, remoteIP); len(out) != 0 {
			t.Fatal("disabled destination forwarded", out)
		}
	})

}

package fabric

import (
	"aster/cloud/internal/overlayproto"
	"strings"
	"testing"
)

func TestOverlayInternetPacketPolicyRetainsIdentityAndIsolation(t *testing.T) {
	for _, remoteGateway := range []bool{false, true} {
		name := "local_gateway"
		if remoteGateway {
			name = "remote_gateway"
		}
		t.Run(name, func(t *testing.T) {
			_, _, c, s := internetNATFixture(t)
			g := s.Gateways[0]
			ports := []overlayPort{{Name: TAPName(s.Members[0].InstanceID), OFPort: 1}, {Name: overlayTunnelName("node-a", "node-b"), OFPort: 7}}
			gatewayPort := 8
			if remoteGateway {
				g.NodeID = "node-b"
				c.Gateways[0], s.Gateways[0] = g, g
				s.NATPolicies[0].NodeID = g.NodeID
				c.NATProfiles = nil // No ownership of the other participant's namespace.
				gatewayPort = 7
			} else {
				ports = append(ports, overlayPort{Name: TAPName(g.InstanceID), OFPort: gatewayPort})
			}
			sha, err := OverlayConfigSHA256(c)
			if err != nil {
				t.Fatal(err)
			}
			s.Profiles[0].ProfileSHA256 = sha
			plan, err := compileOverlay(c, s, ports)
			if err != nil {
				t.Fatal(err)
			}
			local, remote := s.Members[0], s.Members[1]
			egress := policyPacket{in: 1, kind: "ip", srcMAC: local.MAC, dstMAC: g.MAC, srcIP: local.IPv4, dstIP: "9.9.9.9"}
			reply := policyPacket{in: gatewayPort, kind: "ip", srcMAC: g.MAC, dstMAC: local.MAC, srcIP: "9.9.9.9", dstIP: local.IPv4}
			if remoteGateway {
				reply.tunSrc = c.Peers[0].IPv4
				reply.tunDst = c.LocalIPv4
				reply.tunID = 5001
			}
			for _, tc := range []struct {
				name string
				p    policyPacket
				port int
			}{{"public_egress", egress, gatewayPort}, {"public_reply", reply, 1}} {
				t.Run(tc.name, func(t *testing.T) {
					out := policyEvaluate(t, plan, tc.p)
					if len(out) != 1 || out[0].port != tc.port {
						t.Fatal(out)
					}
				})
			}
			for _, addr := range []string{"10.99.0.1", "100.64.0.1", "127.0.0.1", "169.254.169.254", "172.16.0.1", "192.168.0.1", "192.0.2.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", c.LocalIPv4, c.Peers[0].IPv4, "11.0.0.2"} {
				packet := egress
				packet.dstIP = addr
				if out := policyEvaluate(t, plan, packet); len(out) != 0 {
					t.Error("protected egress", addr, out)
				}
				packet = reply
				packet.srcIP = addr
				if out := policyEvaluate(t, plan, packet); len(out) != 0 {
					t.Error("protected reply", addr, out)
				}
			}
			for name, edit := range map[string]func(*policyPacket){"wrong_mac": func(p *policyPacket) { p.srcMAC = remote.MAC }, "wrong_tap": func(p *policyPacket) { p.in = 77 }, "unknown_guest": func(p *policyPacket) { p.srcIP = "10.11.0.99" }, "forged_gateway": func(p *policyPacket) { p.srcMAC = g.MAC; p.srcIP = "9.9.9.9" }, "wrong_destination_mac": func(p *policyPacket) { p.dstMAC = "02:00:00:00:00:99" }, "tagged": func(p *policyPacket) { p.tagged = true }} {
				packet := egress
				edit(&packet)
				if out := policyEvaluate(t, plan, packet); len(out) != 0 {
					t.Error(name, out)
				}
			}
			if remoteGateway {
				for name, edit := range map[string]func(*policyPacket){"wrong_peer": func(p *policyPacket) { p.tunSrc = "12.0.0.99" }, "wrong_vni": func(p *policyPacket) { p.tunID++ }, "wrong_tunnel_destination": func(p *policyPacket) { p.tunDst = "12.0.0.99" }} {
					packet := reply
					edit(&packet)
					if out := policyEvaluate(t, plan, packet); len(out) != 0 {
						t.Error(name, out)
					}
				}
				packet := egress
				packet.in = 7
				packet.srcMAC = remote.MAC
				packet.srcIP = remote.IPv4
				packet.tunSrc = c.Peers[0].IPv4
				packet.tunDst = c.LocalIPv4
				packet.tunID = 5001
				if out := policyEvaluate(t, plan, packet); len(out) != 0 {
					t.Error("peer transit through another peer's Internet gateway", out)
				}
			} else {
				packet := egress
				packet.in = 7
				packet.srcMAC = remote.MAC
				packet.srcIP = remote.IPv4
				packet.tunSrc = c.Peers[0].IPv4
				packet.tunDst = c.LocalIPv4
				packet.tunID = 5001
				if out := policyEvaluate(t, plan, packet); len(out) != 1 || out[0].port != 8 {
					t.Error("remote member could not reach local NAT", out)
				}
				packet = reply
				packet.dstMAC = remote.MAC
				packet.dstIP = remote.IPv4
				if out := policyEvaluate(t, plan, packet); len(out) != 1 || out[0].port != 7 || out[0].tunnel != 5001 {
					t.Error("NAT could not return to remote member", out)
				}
			}
			// Source policing and local destination policing are still compiled;
			// the gateway fallback is not a replacement member ingress flow.
			if len(plan.Meters) != 2 {
				t.Fatal("Internet path changed local policing", plan.Meters)
			}
			for _, m := range plan.Meters {
				if m.Kbps != local.InboundMbps*1000 && m.Kbps != local.OutboundMbps*1000 {
					t.Fatal("member rate changed", m)
				}
			}
			s.NATPolicies[0].InternetEgressEnabled = false
			disabled, err := compileOverlay(c, s, ports)
			if err != nil {
				t.Fatal(err)
			}
			if out := policyEvaluate(t, disabled, egress); len(out) != 0 {
				t.Fatal("disabled Internet fallback retained", out)
			}
			if strings.Contains(strings.Join(disabled.Flows, "\n"), "priority=190,") {
				t.Fatal("disabled default flow retained")
			}
		})
	}
}

func TestInternetFallbackDoesNotReplaceExplicitApprovedRoutes(t *testing.T) {
	_, _, c, s := internetNATFixture(t)
	approved := []string{"198.51.100.0/24"}
	c.Gateways[0].AllowedPrefixes, s.Gateways[0].AllowedPrefixes, c.GuestNetworks[0].AllowedPrefixes = approved, approved, approved
	sha, err := OverlayConfigSHA256(c)
	if err != nil {
		t.Fatal(err)
	}
	s.Profiles[0].ProfileSHA256 = sha
	objects, err := compileNAT(c, s, c.NATProfiles[0], false)
	if err != nil {
		t.Fatal(err)
	}
	packet := natPolicyPacket{in: "inside", out: "outside", src: s.Members[0].IPv4, dst: "198.51.100.10", proto: 6, state: 8}
	if got := evaluateNATPolicy(t, objects, "forward", packet); got.verdict != "accept" {
		t.Fatal("explicit root route was shadowed by Internet reserved block", got)
	}
	ports := []overlayPort{{Name: TAPName(s.Members[0].InstanceID), OFPort: 1}, {Name: TAPName(s.Gateways[0].InstanceID), OFPort: 8}}
	plan, err := compileOverlay(c, s, ports)
	if err != nil {
		t.Fatal(err)
	}
	out := policyEvaluate(t, plan, policyPacket{in: 1, kind: "ip", srcMAC: s.Members[0].MAC, dstMAC: s.Gateways[0].MAC, srcIP: s.Members[0].IPv4, dstIP: packet.dst})
	if len(out) != 1 || out[0].port != 8 {
		t.Fatal("explicit root OVS route was shadowed", out)
	}
	// Protocol canonicality remains the authority; the explicit legacy prefix
	// never becomes a 0/0 approval when Internet permission is disabled.
	s.NATPolicies[0].InternetEgressEnabled = false
	if _, _, err := overlayproto.CanonicalSnapshot(s); err != nil {
		t.Fatal(err)
	}
}

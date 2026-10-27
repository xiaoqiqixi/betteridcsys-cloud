package fabric

import (
	"aster/cloud/internal/nodeproto"
	"aster/cloud/internal/overlayproto"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func internetNATFixture(t *testing.T) (*Executor, *natFake, OverlayConfig, overlayproto.Snapshot) {
	t.Helper()
	e, f, c, s := natFixture(t)
	p := c.NATProfiles[0]
	p.PublicIPv4, p.UplinkGatewayIPv4 = "8.8.4.2", "8.8.4.1"
	p.AllowInternetEgress = true
	p.AllowedSourceCIDRs, p.AllowedPorts = []string{}, []NATPortRange{}
	c.NATProfiles[0] = p
	c.Gateways[0].AllowedPrefixes = []string{}
	s.Gateways[0].AllowedPrefixes = []string{}
	c.LocalIPv4, c.Peers[0].IPv4 = "12.0.0.10", "12.0.0.11"
	c.ProtectedCIDRs = []string{"11.0.0.0/24"}
	c.GuestNetworks = []OverlayGuestNetwork{{LocalVPCID: s.Members[0].LocalVPCID, VPCID: s.VPCs[0].ID, OwnerRef: s.VPCs[0].OwnerRef, CIDR: p.VPCCIDR, GatewayIPv4: c.Gateways[0].IPv4, AllowedPrefixes: []string{}, AllowInternetEgress: true}}
	s.NATPolicies[0].InternetEgressEnabled = true
	s.NATPolicies[0].Forwardings = []overlayproto.NATForwarding{}
	sha, err := OverlayConfigSHA256(c)
	if err != nil {
		t.Fatal(err)
	}
	s.Profiles[0].ProfileSHA256 = sha
	s.NATPolicies[0].ProfileSHA256, err = NATProfileSHA256(p)
	if err != nil {
		t.Fatal(err)
	}
	f.config, f.profile, f.snapshot = c, p, s
	return e, f, c, s
}

// Evaluate the real compiler output, including ordinary-chain jump/return,
// exact prefix matches and conntrack bitmask guards. This model deliberately
// does not claim to emulate Linux conntrack; the native gate verifies packets.
type natPolicyPacket struct {
	in, out, src, dst                        string
	originalDestination                      string
	proto, kind, state, status, sport, dport int
}
type natPolicyResult struct{ verdict, translated string }

func evaluateNATPolicy(t *testing.T, objects []nftObject, chain string, packet natPolicyPacket) natPolicyResult {
	t.Helper()
	raw, _ := json.Marshal(objects)
	var parsed []map[string]map[string]any
	if json.Unmarshal(raw, &parsed) != nil {
		t.Fatal("bad compiled nft JSON")
	}
	rules := map[string][][]any{}
	policies := map[string]string{}
	for _, obj := range parsed {
		if v, ok := obj["chain"]; ok {
			if p, ok := v["policy"].(string); ok {
				policies[v["name"].(string)] = p
			}
		}
		if r, ok := obj["rule"]; ok {
			rules[r["chain"].(string)] = append(rules[r["chain"].(string)], r["expr"].([]any))
		}
	}
	var value func(any) any
	value = func(expr any) any {
		m, ok := expr.(map[string]any)
		if !ok {
			return expr
		}
		if raw, ok := m["range"]; ok {
			v, ok := raw.([]any)
			if !ok || len(v) != 2 {
				t.Fatal("bad nft range")
			}
			return [2]float64{v[0].(float64), v[1].(float64)}
		}
		for kind, val := range m {
			v := val.(map[string]any)
			switch kind {
			case "meta":
				switch v["key"] {
				case "iifname":
					return packet.in
				case "oifname":
					return packet.out
				case "l4proto":
					return float64(packet.proto)
				}
			case "payload":
				switch v["field"] {
				case "saddr":
					return packet.src
				case "daddr":
					return packet.dst
				case "type":
					if v["protocol"] == "icmp" && packet.proto == 1 {
						return float64(packet.kind)
					}
				case "sport":
					if (v["protocol"] == "tcp" && packet.proto == 6) || (v["protocol"] == "udp" && packet.proto == 17) {
						return float64(packet.sport)
					}
				case "dport":
					if (v["protocol"] == "tcp" && packet.proto == 6) || (v["protocol"] == "udp" && packet.proto == 17) {
						return float64(packet.dport)
					}
				}
			case "ct":
				if v["key"] == "daddr" && (v["family"] == nil || v["family"] == "ip") && v["dir"] == "original" {
					return packet.originalDestination
				}
				switch v["key"] {
				case "state":
					return float64(packet.state)
				case "status":
					return float64(packet.status)
				}
			case "prefix":
				return fmt.Sprintf("%s/%v", v["addr"], v["len"])
			default:
				t.Fatalf("unmodeled nft expression %s", kind)
			}
		}
		return nil
	}
	var walk func(string, int) natPolicyResult
	walk = func(name string, depth int) natPolicyResult {
		if depth > 3 {
			t.Fatal("unexpected nft recursion")
		}
		for _, expr := range rules[name] {
			matched := true
			for _, atom := range expr {
				for kind, body := range atom.(map[string]any) {
					if kind == "match" {
						m := body.(map[string]any)
						left, right := value(m["left"]), value(m["right"])
						if bounds, ok := right.([2]float64); ok {
							v, ok := left.(float64)
							if !ok || v < bounds[0] || v > bounds[1] {
								matched = false
							}
						} else if m["op"] == "in" {
							l, lok := left.(float64)
							r, rok := right.(float64)
							if bits, ok := right.([]any); ok {
								r, rok = 0, true
								for _, bit := range bits {
									v, ok := bit.(float64)
									if !ok {
										rok = false
										break
									}
									r = float64(int(r) | int(v))
								}
							}
							matched = lok && rok && int(l)&int(r) != 0
						} else if p, ok := right.(string); ok && strings.Contains(p, "/") {
							prefix, err := netip.ParsePrefix(p)
							addr, ae := netip.ParseAddr(fmt.Sprint(left))
							matched = err == nil && ae == nil && prefix.Contains(addr)
						} else {
							matched = reflect.DeepEqual(left, right)
						}
						if !matched {
							break
						}
					} else {
						switch kind {
						case "accept", "drop":
							return natPolicyResult{verdict: kind}
						case "jump":
							r := walk(body.(map[string]any)["target"].(string), depth+1)
							if r.verdict != "" {
								return r
							}
						case "snat", "dnat":
							return natPolicyResult{verdict: kind, translated: body.(map[string]any)["addr"].(string)}
						default:
							t.Fatalf("unmodeled nft statement %s", kind)
						}
					}
				}
				if !matched {
					break
				}
			}
		}
		return natPolicyResult{verdict: policies[name]}
	}
	return walk(chain, 0)
}

func TestNATInternetCompilerPacketPolicy(t *testing.T) {
	_, _, c, s := internetNATFixture(t)
	p := c.NATProfiles[0]
	objects, err := compileNAT(c, s, p, false)
	if err != nil {
		t.Fatal(err)
	}
	base := natPolicyPacket{in: p.InsideInterface, out: p.OutsideInterface, src: s.Members[0].IPv4, dst: "9.9.9.9", proto: 6, state: 8}
	for _, proto := range []int{6, 17, 1} {
		packet := base
		packet.proto, packet.kind = proto, 8
		if got := evaluateNATPolicy(t, objects, "forward", packet); got.verdict != "accept" {
			t.Fatalf("public %d outbound rejected: %+v", proto, got)
		}
		if got := evaluateNATPolicy(t, objects, "postrouting", packet); got != (natPolicyResult{"snat", p.PublicIPv4}) {
			t.Fatal("public source was not translated", got)
		}
		packet.in, packet.out, packet.src, packet.dst, packet.state, packet.status, packet.kind = p.OutsideInterface, p.InsideInterface, base.dst, base.src, 2, 16, 0
		if got := evaluateNATPolicy(t, objects, "forward", packet); got.verdict != "accept" {
			t.Fatalf("public %d tracked reply rejected: %+v", proto, got)
		}
		packet.state, packet.status = 8, 0
		if got := evaluateNATPolicy(t, objects, "forward", packet); got.verdict != "drop" {
			t.Fatal("unsolicited public ingress", got)
		}
	}
	for _, addr := range []string{"10.99.0.1", "100.64.0.1", "127.0.0.1", "169.254.169.254", "172.16.0.1", "192.168.0.1", "192.0.2.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", c.LocalIPv4, c.Peers[0].IPv4, "11.0.0.2", p.PublicIPv4, p.UplinkGatewayIPv4} {
		packet := base
		packet.dst = addr
		if got := evaluateNATPolicy(t, objects, "forward", packet); got.verdict != "drop" {
			t.Errorf("protected destination %s: %+v", addr, got)
		}
		packet.in, packet.out, packet.src, packet.dst, packet.state, packet.status = p.OutsideInterface, p.InsideInterface, addr, base.src, 2, 16
		if got := evaluateNATPolicy(t, objects, "forward", packet); got.verdict != "drop" {
			t.Errorf("protected return source %s: %+v", addr, got)
		}
	}
	for _, kind := range []int{3, 11, 12} {
		packet := natPolicyPacket{in: p.OutsideInterface, out: p.InsideInterface, src: "9.9.9.8", dst: base.src, proto: 1, kind: kind, state: 4}
		if got := evaluateNATPolicy(t, objects, "forward", packet); got.verdict != "accept" {
			t.Fatal("related ICMP/PMTU blocked", kind, got)
		}
		packet.state = 8
		if got := evaluateNATPolicy(t, objects, "forward", packet); got.verdict != "drop" {
			t.Fatal("unrelated ICMP/PMTU accepted", kind, got)
		}
	}
	for _, edit := range []func(*natPolicyPacket){func(p *natPolicyPacket) { p.src = "10.11.0.99" }, func(p *natPolicyPacket) { p.proto = 47 }, func(p *natPolicyPacket) { p.proto = 1; p.kind = 13 }, func(p *natPolicyPacket) { p.in = "foreign" }, func(p *natPolicyPacket) { p.out = "foreign" }} {
		packet := base
		edit(&packet)
		if got := evaluateNATPolicy(t, objects, "forward", packet); got.verdict != "drop" {
			t.Fatal("invalid packet accepted", packet, got)
		}
	}
	for _, state := range []int{0, 1, 64} {
		packet := base
		packet.state = state
		if got := evaluateNATPolicy(t, objects, "forward", packet); got.verdict != "drop" {
			t.Error("untracked/invalid Internet egress accepted", state, got)
		}
	}
}

func TestNATInternetRootApprovalAndRevocation(t *testing.T) {
	for _, name := range []string{"profile-permission", "guest-permission", "public-source", "snat-permission", "old-pin"} {
		t.Run(name, func(t *testing.T) {
			_, _, c, s := internetNATFixture(t)
			switch name {
			case "profile-permission":
				c.NATProfiles[0].AllowInternetEgress = false
			case "guest-permission":
				c.GuestNetworks[0].AllowInternetEgress = false
			case "public-source":
				c.NATProfiles[0].PublicIPv4 = "198.51.100.2"
			case "snat-permission":
				c.NATProfiles[0].AllowSNAT = false
			case "old-pin":
				s.NATPolicies[0].ProfileSHA256 = strings.Repeat("f", 64)
			}
			sha, _ := OverlayConfigSHA256(c)
			s.Profiles[0].ProfileSHA256 = sha
			if name != "old-pin" {
				s.NATPolicies[0].ProfileSHA256, _ = NATProfileSHA256(c.NATProfiles[0])
			}
			if _, err := compileNAT(c, s, c.NATProfiles[0], false); err == nil {
				t.Fatal("root permission escalation accepted")
			}
		})
	}
	e, f, c, s := internetNATFixture(t)
	overlayRun(t, e, c, s)
	_, previous, _ := overlayproto.CanonicalSnapshot(s)
	s.Epoch++
	s.PreviousSHA256 = previous
	s.NATPolicies[0].InternetEgressEnabled = false
	overlayRun(t, e, c, s)
	if f.flushes != 2 {
		t.Fatal("Internet permission removal retained cached translations", f.flushes)
	}
	raw, _ := json.Marshal(f.rules)
	if strings.Contains(string(raw), "internet_") {
		t.Fatal("Internet default path survived disable")
	}
}

func TestNATInternetProfileCanonicalityAndLegacyHash(t *testing.T) {
	_, _, legacy, _ := natFixture(t)
	sha, err := NATProfileSHA256(legacy.NATProfiles[0])
	if err != nil || sha != "34acf7b7ebb0f3ba2abf609eddb6505b581206ca6e33a41a3200f4ef8a7fa39c" {
		t.Fatal("legacy NAT profile canonical bytes changed", sha, err)
	}
	raw, _ := json.Marshal(legacy)
	if strings.Contains(string(raw), "allow_internet_egress") {
		t.Fatal("false Internet permission changed legacy configuration bytes")
	}
	_, _, c, _ := internetNATFixture(t)
	raw, _ = json.Marshal(c)
	decoded, err := DecodeOverlayConfig(raw)
	if err != nil || !decoded.NATProfiles[0].AllowInternetEgress {
		t.Fatal("Internet approval strict decode", err)
	}
	for _, malformed := range []string{strings.Replace(string(raw), `"allow_internet_egress":true`, `"allow_internet_egress":null`, 1), strings.Replace(string(raw), `"allow_internet_egress":true`, `"allow_internet_egress":true,"allow_internet_egress":true`, 1)} {
		if _, err := DecodeOverlayConfig([]byte(malformed)); err == nil {
			t.Fatal("ambiguous/null Internet approval accepted")
		}
	}
	for _, address := range []string{"10.0.0.2", "100.64.0.2", "127.0.0.2", "169.254.1.2", "172.16.0.2", "192.0.0.2", "192.0.2.2", "192.88.99.2", "192.168.0.2", "198.18.0.2", "198.51.100.2", "203.0.113.2", "224.0.0.2", "240.0.0.2"} {
		p := c.NATProfiles[0]
		p.PublicIPv4 = address
		if _, err := NATProfileSHA256(p); err == nil {
			t.Error("non-public Internet source approved", address)
		}
	}
}

func TestNATInternetRulesStayBoundedAndDriftSensitive(t *testing.T) {
	e, f, c, s := internetNATFixture(t)
	objects, err := compileNAT(c, s, c.NATProfiles[0], false)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []string{"return-conntrack", "public-exclusion", "ordinary-chain"} {
		// Work from serialized compiler output, not shared maps that could mutate
		// the expectation compiled by verifyNATRules itself.
		raw, _ := json.Marshal(objects)
		if err := json.Unmarshal(raw, &f.rules); err != nil {
			t.Fatal(err)
		}
		changed := false
		for i, object := range f.rules {
			if mutate == "ordinary-chain" {
				if chain, ok := object["chain"].(map[string]any); ok && chain["name"] == "internet_in" {
					f.rules = append(f.rules[:i], f.rules[i+1:]...)
					changed = true
					break
				}
			}
			rule, ok := object["rule"].(map[string]any)
			if !ok {
				continue
			}
			if mutate == "public-exclusion" && rule["chain"] == "internet_out" {
				f.rules = append(f.rules[:i], f.rules[i+1:]...)
				changed = true
				break
			}
			if mutate == "return-conntrack" && rule["chain"] == "internet_in" {
				expr := rule["expr"].([]any)
				for j, atom := range expr {
					raw, _ := json.Marshal(atom)
					if strings.Contains(string(raw), `"ct"`) {
						rule["expr"] = append(expr[:j], expr[j+1:]...)
						changed = true
						break
					}
				}
				if changed {
					break
				}
			}
		}
		if !changed {
			t.Fatalf("drift mutation %s did not affect real generated policy", mutate)
		}
		if err := e.verifyNATRules(context.Background(), c, s, c.NATProfiles[0]); err == nil {
			t.Errorf("hidden Internet policy drift: %s", mutate)
		}
	}
	first := s.Members[0]
	s.Members = nil
	for i := 0; i < 128; i++ {
		m := first
		m.InstanceID = overlayproto.Digest([]byte(fmt.Sprintf("bounded-internet-member-%d", i)))[:32]
		m.InterfaceID = InterfaceID(m.InstanceID)
		m.LeaseID = fmt.Sprintf("%032x", i+512)
		m.MAC = nodeproto.NetworkMAC(m.NodeID, m.InstanceID)
		m.IPv4 = fmt.Sprintf("10.11.0.%d", i+2)
		s.Members = append(s.Members, m)
	}
	objects, err = compileNAT(c, s, c.NATProfiles[0], false)
	if err != nil {
		if _, _, e := overlayproto.CanonicalSnapshot(s); e != nil {
			t.Fatal("maximum-member fixture invalid", e)
		}
		if _, _, _, e := validateOverlayApproval(c, s); e != nil {
			t.Fatal("maximum-member approval invalid", e)
		}
		t.Fatal("maximum supported public egress membership cannot compile", err)
	}
	raw, _ := json.Marshal(objects)
	if len(raw) > 512<<10 {
		t.Fatal("public rules exceed execution bound", len(raw))
	}
	t.Logf("128-member public egress rules: %d bytes", len(raw))
	s.Members[0].Enabled = false
	objects, err = compileNAT(c, s, c.NATProfiles[0], false)
	if err != nil {
		t.Fatal(err)
	}
	if got := evaluateNATPolicy(t, objects, "forward", natPolicyPacket{in: "inside", out: "outside", src: s.Members[0].IPv4, dst: "9.9.9.9", proto: 6, state: 8}); got.verdict != "drop" {
		t.Fatal("disabled member retained Internet", got)
	}
}

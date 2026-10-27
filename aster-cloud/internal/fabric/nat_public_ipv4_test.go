package fabric

import (
	"aster/cloud/internal/overlayproto"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
)

// This wrapper changes only independently provisioned interface/route inventory;
// the production compiler, executor, owner and conntrack code run unchanged.
type natPublicIPProbeRunner struct {
	*natFake
	configured []string
	mutate     func([]string, []byte) []byte
}

func (f *natPublicIPProbeRunner) RunNamespace(ctx context.Context, p NATProfile, binary string, args ...string) ([]byte, error) {
	raw, err := f.natFake.RunNamespace(ctx, p, binary, args...)
	if err != nil {
		return raw, err
	}
	if binary == NATIP && strings.Join(args, " ") == "-j -d address show" {
		var links []natLink
		if json.Unmarshal(raw, &links) != nil {
			return nil, ErrInvalid
		}
		for i := range links {
			if links[i].Name != p.OutsideInterface {
				continue
			}
			for _, ip := range f.configured {
				a := links[i].Addresses[0]
				a.Local, a.Prefix = ip, 32
				links[i].Addresses = append(links[i].Addresses, a)
			}
		}
		raw, err = json.Marshal(links)
	}
	if f.mutate != nil && binary == NATIP {
		raw = f.mutate(args, raw)
	}
	return raw, err
}

func publicIPPoolFixture(t *testing.T) (*Executor, *natPublicIPProbeRunner, OverlayConfig, overlayproto.Snapshot) {
	t.Helper()
	e, f, c, s := internetNATFixture(t)
	p := c.NATProfiles[0]
	p.PublicIPv4s = []string{"8.8.4.3", "8.8.4.4"}
	c.NATProfiles[0] = p
	s.Profiles[0].ProfileSHA256, _ = OverlayConfigSHA256(c)
	s.NATPolicies[0].ProfileSHA256, _ = NATProfileSHA256(p)
	s.NATPolicies[0].PublicIPv4 = "8.8.4.3"
	f.config, f.profile, f.snapshot = c, p, s
	runner := &natPublicIPProbeRunner{natFake: f, configured: []string{"8.8.4.3"}}
	e.Runner = runner
	return e, runner, c, s
}

func TestNATPublicIPPoolCanonicalAndHistoricalProfileBytes(t *testing.T) {
	_, _, c, _ := natFixture(t)
	p := c.NATProfiles[0]
	// Exact pre-pool profile wire form, not a second current-struct marshal.
	legacy := `{"id":"nat-a","namespace":"aster-nat-a","namespace_device":1,"namespace_inode":123,"dedicated_ack":true,"vpc_id":"11111111111111111111111111111111","vpc_cidr":"10.11.0.0/24","gateway_instance_id":"88888888888888888888888888888888","inside_interface":"inside","outside_interface":"outside","outside_peer":"nat-uplink","public_ipv4":"198.51.100.2","uplink_gateway_ipv4":"198.51.100.1","allow_snat":true,"allowed_source_cidrs":["198.51.100.0/24"],"allowed_ports":[{"protocol":"tcp","start":10000,"end":20000},{"protocol":"udp","start":10000,"end":20000}]}`
	old, err := canonicalNATProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(old)
	// Fixture IDs may evolve, but the old form is decoded independently and then
	// populated with the fixture's immutable VPC ID before exact-byte comparison.
	legacy = strings.Replace(legacy, `"vpc_id":"11111111111111111111111111111111"`, `"vpc_id":"`+p.VPCID+`"`, 1)
	if string(raw) != legacy {
		t.Fatalf("old profile bytes changed\ngot %s\nwant%s", raw, legacy)
	}
	oldSHA, err := NATProfileSHA256(p)
	if err != nil || oldSHA != overlayproto.Digest([]byte(legacy)) {
		t.Fatal("old profile digest changed", err)
	}
	p.PublicIPv4s = []string{}
	emptySHA, err := NATProfileSHA256(p)
	if err != nil || emptySHA != oldSHA {
		t.Fatal("empty grant changed old owner digest", err)
	}
	p.PublicIPv4s = []string{"8.8.4.4", "8.8.4.3", "8.8.4.4"}
	approved, err := canonicalNATProfile(p)
	if err != nil || !reflect.DeepEqual(approved.PublicIPv4s, []string{"8.8.4.3", "8.8.4.4"}) || p.PublicIPv4s[0] != "8.8.4.4" {
		t.Fatal("root pool not canonical/independent", approved.PublicIPv4s, err)
	}
	newSHA, err := NATProfileSHA256(p)
	if err != nil || newSHA == oldSHA {
		t.Fatal("new grant did not change root pin", err)
	}
	p.PublicIPv4s = []string{"8.8.4.3", "8.8.4.4"}
	if sha, _ := NATProfileSHA256(p); sha != newSHA {
		t.Fatal("pool ordering/duplicates changed canonical pin")
	}
	for _, bad := range []string{p.PublicIPv4, p.UplinkGatewayIPv4, "10.0.0.2", "127.0.0.1", "169.254.169.254", "198.51.100.3", "203.0.113.3", "224.0.0.1", "8.8.4.3/32", "::ffff:8.8.4.3", "8.8.4.3 "} {
		p.PublicIPv4s = []string{bad}
		if _, err := NATProfileSHA256(p); err == nil {
			t.Fatalf("unsafe additional grant accepted %q", bad)
		}
	}
	p.PublicIPv4s = nil
	for i := 0; i < 64; i++ {
		p.PublicIPv4s = append(p.PublicIPv4s, fmt.Sprintf("8.8.5.%d", i+1))
	}
	if _, err := NATProfileSHA256(p); err != nil {
		t.Fatal("bounded 64-address grant rejected", err)
	}
	p.PublicIPv4s = append(p.PublicIPv4s, "8.8.5.65")
	if _, err := NATProfileSHA256(p); err == nil {
		t.Fatal("unbounded root address grant accepted")
	}
}

func TestNATPublicIPPoolStrictRootConfigRoundTrip(t *testing.T) {
	_, _, c, _ := publicIPPoolFixture(t)
	raw, _ := json.Marshal(c)
	decoded, err := DecodeOverlayConfig(raw)
	if err != nil || !reflect.DeepEqual(decoded.NATProfiles[0].PublicIPv4s, []string{"8.8.4.3", "8.8.4.4"}) {
		t.Fatal("root pool grant not decoded", err)
	}
	oldSHA, _ := OverlayConfigSHA256(c)
	sha, err := OverlayConfigSHA256(decoded)
	if err != nil || sha != oldSHA {
		t.Fatal("root pool pin round-trip changed", err)
	}
	for _, replacement := range []string{`"public_ipv4s":null`, `"public_ipv4s":"8.8.4.3"`, `"public_ipv4s":[8]`, `"PUBLIC_IPV4S":["8.8.4.3","8.8.4.4"]`, `"public_ipv4s":["8.8.4.3"],"public_ipv4s":["8.8.4.4"]`} {
		bad := strings.Replace(string(raw), `"public_ipv4s":["8.8.4.3","8.8.4.4"]`, replacement, 1)
		if _, err := DecodeOverlayConfig([]byte(bad)); err == nil {
			t.Fatal("ambiguous root pool grant accepted", replacement)
		}
	}
}

func TestNATPublicIPPoolRejectsManagementUnderlayAndForeignVPCGrant(t *testing.T) {
	for _, addr := range []string{"11.0.0.2", "12.0.0.10", "12.0.0.11"} {
		t.Run(addr, func(t *testing.T) {
			_, _, c, _ := internetNATFixture(t)
			c.NATProfiles[0].PublicIPv4s = []string{addr}
			if _, err := OverlayConfigSHA256(c); err == nil {
				t.Fatal("protected/underlay address approved")
			}
		})
	}
	_, _, c, s := publicIPPoolFixture(t)
	s.NATPolicies[0].PublicIPv4 = "8.8.4.9"
	if err := validateNATApproval(c, s); err == nil {
		t.Fatal("controller-selected unapproved address accepted")
	}
	// Identically named root profile on another gateway/VPC grants nothing.
	s.NATPolicies[0].VPCID = strings.Repeat("f", 32)
	s.NATPolicies[0].PublicIPv4 = "8.8.4.3"
	if err := validateNATApproval(c, s); err == nil {
		t.Fatal("other VPC borrowed root address grant")
	}
}

func TestNATPublicIPPoolProvesSelectedAddressAndExactOutsideRoutes(t *testing.T) {
	for _, name := range []string{"ready-reserve-unconfigured", "selected-unconfigured", "unapproved-configured", "duplicate-configured", "missing-default-address", "bad-prefix", "different-default-interface", "no-uplink-connected", "foreign-connected", "policy-route"} {
		t.Run(name, func(t *testing.T) {
			e, f, c, s := publicIPPoolFixture(t)
			switch name {
			case "selected-unconfigured":
				f.configured = nil
			case "unapproved-configured":
				f.configured = append(f.configured, "8.8.4.9")
			case "duplicate-configured":
				f.configured = append(f.configured, "8.8.4.3")
			}
			f.mutate = func(args []string, raw []byte) []byte {
				cmd := strings.Join(args, " ")
				if cmd == "-j -d address show" && (name == "missing-default-address" || name == "bad-prefix") {
					var links []natLink
					_ = json.Unmarshal(raw, &links)
					for i := range links {
						if links[i].Name == c.NATProfiles[0].OutsideInterface {
							if name == "missing-default-address" {
								links[i].Addresses = links[i].Addresses[1:]
							} else {
								links[i].Addresses[1].Prefix = 33
							}
						}
					}
					raw, _ = json.Marshal(links)
				}
				if cmd == "-j -4 route show table all" {
					switch name {
					case "different-default-interface":
						raw = []byte(strings.Replace(string(raw), `"dst":"default","gateway":"8.8.4.1","dev":"outside"`, `"dst":"default","gateway":"8.8.4.1","dev":"inside"`, 1))
					case "no-uplink-connected":
						raw = []byte(strings.Replace(string(raw), `,{"dst":"8.8.4.0/24","dev":"outside"}`, "", 1))
					case "foreign-connected":
						raw = append(raw[:len(raw)-1], []byte(`,{"dst":"8.0.0.0/8","dev":"outside"}]`)...)
					}
				}
				if cmd == "-j -4 rule show" && name == "policy-route" {
					raw = []byte(strings.Replace(string(raw), `"priority":32766`, `"priority":1000`, 1))
				}
				return raw
			}
			err := e.probeNAT(context.Background(), c, s, c.NATProfiles[0])
			if (err == nil) != (name == "ready-reserve-unconfigured") {
				t.Fatal("selected-address route proof", err)
			}
			if f.flushes != 0 || len(f.rules) != 0 {
				t.Fatal("read-only probe mutated namespace")
			}
		})
	}
}

func TestNATSelectedPublicIPv4ChangesAllSNATAndDNATRules(t *testing.T) {
	for _, mode := range []string{"approved-prefix", "internet"} {
		t.Run(mode, func(t *testing.T) {
			_, f, c, s := publicIPPoolFixture(t)
			p := c.NATProfiles[0]
			if mode == "approved-prefix" {
				c.Gateways[0].AllowedPrefixes = []string{"93.184.216.0/24"}
				s.Gateways[0].AllowedPrefixes = []string{"93.184.216.0/24"}
				p.AllowedSourceCIDRs, p.AllowedPorts = []string{"93.184.216.0/24"}, []NATPortRange{{"tcp", 18080, 18080}}
				c.NATProfiles[0] = p
				c.GuestNetworks[0].AllowedPrefixes = []string{"93.184.216.0/24"}
				s.NATPolicies[0].InternetEgressEnabled = false
				s.NATPolicies[0].Forwardings = []overlayproto.NATForwarding{{ID: strings.Repeat("a", 32), Protocol: "tcp", PublicPort: 18080, TargetInstanceID: s.Members[0].InstanceID, TargetPort: 80, SourceCIDR: "93.184.216.0/24"}}
				s.Profiles[0].ProfileSHA256, _ = OverlayConfigSHA256(c)
				s.NATPolicies[0].ProfileSHA256, _ = NATProfileSHA256(p)
			}
			objects, err := compileNAT(c, s, p, false)
			if err != nil {
				t.Fatal(err)
			}
			packet := natPolicyPacket{in: p.InsideInterface, out: p.OutsideInterface, src: s.Members[0].IPv4, dst: "93.184.216.34", proto: 6, state: 8, dport: 18081}
			if got := evaluateNATPolicy(t, objects, "postrouting", packet); got != (natPolicyResult{"snat", "8.8.4.3"}) {
				t.Fatal("SNAT used default instead of selected", got)
			}
			if mode == "approved-prefix" {
				packet = natPolicyPacket{in: p.OutsideInterface, out: p.InsideInterface, src: "93.184.216.34", dst: "8.8.4.3", proto: 6, state: 8, dport: 18080}
				if got := evaluateNATPolicy(t, objects, "prerouting", packet); got != (natPolicyResult{"dnat", s.Members[0].IPv4}) {
					t.Fatal("DNAT did not bind selected public IP", got)
				}
				packet.dst = p.PublicIPv4
				if got := evaluateNATPolicy(t, objects, "prerouting", packet); got.verdict == "dnat" {
					t.Fatal("old default IP retained DNAT binding", got)
				}
			}
			if mode == "internet" {
				for _, ip := range natProfilePublicIPv4s(p) {
					packet.dst = ip
					if got := evaluateNATPolicy(t, objects, "postrouting", packet); got.verdict != "drop" {
						t.Fatal("pool address reachable through public egress", ip, got)
					}
				}
			}
			// No readback equivalence is invented for a different selected IP.
			f.rules = objects
			for _, object := range f.rules {
				rule, ok := object["rule"].(map[string]any)
				if !ok {
					continue
				}
				for _, expr := range rule["expr"].([]any) {
					if snat, ok := expr.(map[string]any)["snat"].(map[string]any); ok {
						snat["addr"] = p.PublicIPv4
					}
				}
			}
			e := &Executor{Config: c.Base, Runner: f}
			if err := e.verifyNATRules(context.Background(), c, s, p); err == nil {
				t.Fatal("wrong selected-IP SNAT readback accepted")
			}
		})
	}
}

func TestNATPublicIPSwitchAndReleasePreserveImmutableOldOperations(t *testing.T) {
	e, f, c, s := publicIPPoolFixture(t)
	overlayRun(t, e, c, s)
	old, previous, err := overlayproto.CanonicalSnapshot(s)
	if err != nil {
		t.Fatal(err)
	}
	oldBytes, _ := json.Marshal(old)
	oldFiles := map[string][]byte{}
	for _, phase := range []string{"prepare", "program", "release"} {
		name := overlayOpName(overlayTask(t, old, phase).OperationID)
		oldFiles[name] = readPublicIPTestFile(t, c, name)
	}
	for _, selected := range []string{"", "8.8.4.3"} {
		s.Epoch++
		s.PreviousSHA256 = previous
		s.NATPolicies[0].PublicIPv4 = selected
		f.snapshot = s
		overlayRun(t, e, c, s)
		objects, err := compileNAT(c, s, c.NATProfiles[0], false)
		if err != nil {
			t.Fatal(err)
		}
		packet := natPolicyPacket{in: c.NATProfiles[0].InsideInterface, out: c.NATProfiles[0].OutsideInterface, src: s.Members[0].IPv4, dst: "9.9.9.9", proto: 6, state: 8}
		want := natPolicyPublicIPv4(c.NATProfiles[0], s.NATPolicies[0])
		if got := evaluateNATPolicy(t, objects, "postrouting", packet); got != (natPolicyResult{"snat", want}) {
			t.Fatal("switched NAT source mismatch", got, want)
		}
		_, previous, _ = overlayproto.CanonicalSnapshot(s)
	}
	s.Epoch++
	s.PreviousSHA256 = previous
	s.NATPolicies = nil
	f.snapshot = s
	overlayRun(t, e, c, s)
	if f.flushes != 4 {
		t.Fatal("switch/remove did not revoke namespace conntrack", f.flushes)
	}
	raw, _ := json.Marshal(f.rules)
	if bytes.Contains(raw, []byte(`"snat"`)) || bytes.Contains(raw, []byte(`"dnat"`)) || f.forward != "0" {
		t.Fatal("released pool binding retained data path", string(raw), f.forward)
	}
	for name, original := range oldFiles {
		current := readPublicIPTestFile(t, c, name)
		if !bytes.Equal(original, current) || !bytes.Contains(current, oldBytes) {
			t.Fatal("switch/release rewrote old snapshot/task/receipt", name)
		}
	}
}

func readPublicIPTestFile(t *testing.T, c OverlayConfig, name string) []byte {
	t.Helper()
	raw, err := readPrivate(c.Base.StateDirectory+"/"+name, uint32(os.Geteuid()), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestNATPublicIPPoolExclusionsAreCanonicalAndIndependent(t *testing.T) {
	_, _, c, s := publicIPPoolFixture(t)
	got := internetBlockedCIDRs(c, s)
	for _, ip := range []string{"8.8.4.2", "8.8.4.3", "8.8.4.4"} {
		found := 0
		for _, prefix := range got {
			if prefix == ip+"/32" {
				found++
			}
		}
		if found != 1 {
			t.Fatal("pool IP not exactly excluded", ip, got)
		}
	}
	for i, prefix := range got {
		if _, err := netip.ParsePrefix(prefix); err != nil || i > 0 && got[i-1] >= prefix {
			t.Fatal("noncanonical exclusions", got)
		}
	}
	got[0] = "8.0.0.0/8"
	if internetBlockedCIDRs(c, s)[0] == got[0] {
		t.Fatal("caller changed root pool exclusions")
	}
}

func TestNATPublicIPPoolOVSIsolationIncludesConfiguredAndReservedAddresses(t *testing.T) {
	_, _, c, s := publicIPPoolFixture(t)
	g, local := s.Gateways[0], s.Members[0]
	ports := []overlayPort{{Name: TAPName(local.InstanceID), OFPort: 1}, {Name: TAPName(g.InstanceID), OFPort: 8}, {Name: overlayTunnelName("node-a", "node-b"), OFPort: 7}}
	plan, err := compileOverlay(c, s, ports)
	if err != nil {
		t.Fatal(err)
	}
	outbound := policyPacket{in: 1, kind: "ip", srcMAC: local.MAC, dstMAC: g.MAC, srcIP: local.IPv4, dstIP: "9.9.9.9"}
	if got := policyEvaluate(t, plan, outbound); len(got) != 1 || got[0].port != 8 {
		t.Fatal("public IP selection broke intended public path", got)
	}
	for _, ip := range natProfilePublicIPv4s(c.NATProfiles[0]) {
		packet := outbound
		packet.dstIP = ip
		if got := policyEvaluate(t, plan, packet); len(got) != 0 {
			t.Fatal("OVS allowed a configured/reserved pool destination", ip, got)
		}
		packet = policyPacket{in: 8, kind: "ip", srcMAC: g.MAC, dstMAC: local.MAC, srcIP: ip, dstIP: local.IPv4}
		if got := policyEvaluate(t, plan, packet); len(got) != 0 {
			t.Fatal("OVS accepted a configured/reserved pool source", ip, got)
		}
	}
	// A non-gateway node cannot see another node's private reserve grant, but
	// must at least exclude every explicit address in the approved snapshot.
	c.NATProfiles = nil
	blocked := internetBlockedCIDRs(c, s)
	found := false
	for _, prefix := range blocked {
		if prefix == s.NATPolicies[0].PublicIPv4+"/32" {
			found = true
		}
	}
	if !found {
		t.Fatal("explicit remote selection absent from participant exclusions")
	}
}

func TestNATPublicIPPoolSharedGrantCannotBindSameLocalAddressTwice(t *testing.T) {
	_, _, c, s := publicIPPoolFixture(t)
	g := c.Gateways[0]
	g.InstanceID, g.InterfaceID = strings.Repeat("7", 32), InterfaceID(strings.Repeat("7", 32))
	g.VPCID, g.IPv4, g.MAC = strings.Repeat("6", 32), "10.12.0.1", "02:00:00:00:00:02"
	c.Gateways = append(c.Gateways, g)
	p := c.NATProfiles[0]
	p.ID, p.Namespace, p.NamespaceInode, p.OutsidePeer = "nat-b", "aster-nat-b", 124, "nat-uplink-b"
	p.VPCID, p.VPCCIDR, p.GatewayInstanceID, p.PublicIPv4 = g.VPCID, "10.12.0.0/24", g.InstanceID, "8.8.4.5"
	c.NATProfiles = append(c.NATProfiles, p)
	c.NATProfiles[1].UplinkGatewayIPv4 = "8.8.4.9"
	c.NATProfiles[0].PublicIPv4s = append(c.NATProfiles[0].PublicIPv4s, "8.8.4.9")
	if _, err := OverlayConfigSHA256(c); err == nil {
		t.Fatal("pool grant included another NAT profile's uplink")
	}
	c.NATProfiles[0].PublicIPv4s = c.NATProfiles[0].PublicIPv4s[:2]
	c.NATProfiles[1].UplinkGatewayIPv4 = p.UplinkGatewayIPv4
	// The same reserve is root-approved for both namespaces; only the effective
	// immutable epoch binding must remain exclusive on this node.
	if _, err := OverlayConfigSHA256(c); err != nil {
		t.Fatal("independent profiles cannot share a root reserve", err)
	}
	policy := s.NATPolicies[0]
	policy.ID, policy.VPCID, policy.GatewayInstanceID, policy.ProfileID = strings.Repeat("5", 32), g.VPCID, g.InstanceID, p.ID
	policy.ProfileSHA256, _ = NATProfileSHA256(p)
	s.NATPolicies = append(s.NATPolicies, policy)
	s.Gateways = append(s.Gateways, g)
	s.VPCs = append(s.VPCs, overlayproto.VPC{ID: g.VPCID, OwnerRef: g.OwnerRef, CIDR: p.VPCCIDR, VNI: s.VPCs[0].VNI + 1})
	if _, _, err := overlayproto.CanonicalSnapshot(s); err != nil {
		t.Fatal("invalid duplicate-address test fixture", err)
	}
	if err := validateNATApproval(c, s); err == nil {
		t.Fatal("same selected public address bound to two local VPCs")
	}
	s.NATPolicies[1].PublicIPv4 = ""
	if err := validateNATApproval(c, s); err != nil {
		t.Fatal("distinct default and selected address rejected", err)
	}
	// Empty/default is a real binding too; selecting another profile's primary
	// from a shared grant must not steal that default.
	c.NATProfiles[0].PublicIPv4s = append(c.NATProfiles[0].PublicIPv4s, p.PublicIPv4)
	s.NATPolicies[0].ProfileSHA256, _ = NATProfileSHA256(c.NATProfiles[0])
	s.NATPolicies[0].PublicIPv4 = p.PublicIPv4
	if err := validateNATApproval(c, s); err == nil {
		t.Fatal("selected reserve stole another local default public address")
	}
}

func TestNATPublicIPRootGrantUpgradeRequiresExplicitPinRecovery(t *testing.T) {
	for _, name := range []string{"ordinary-prepare", "missing-old-pin", "explicit-recovery"} {
		t.Run(name, func(t *testing.T) {
			e, f, c, s := publicIPPoolFixture(t)
			c.NATProfiles[0].PublicIPv4s = nil
			s.NATPolicies[0].PublicIPv4 = ""
			oldFullSHA, _ := OverlayConfigSHA256(c)
			oldNATSHA, _ := NATProfileSHA256(c.NATProfiles[0])
			s.Profiles[0].ProfileSHA256, s.NATPolicies[0].ProfileSHA256 = oldFullSHA, oldNATSHA
			f.profile, f.config, f.snapshot, f.configured = c.NATProfiles[0], c, s, nil
			overlayRun(t, e, c, s)
			oldSnapshot, previous, _ := overlayproto.CanonicalSnapshot(s)
			oldFiles := map[string][]byte{}
			for _, phase := range []string{"prepare", "program", "release"} {
				file := overlayOpName(overlayTask(t, oldSnapshot, phase).OperationID)
				oldFiles[file] = readPublicIPTestFile(t, c, file)
			}
			oldOwner := readPublicIPTestFile(t, c, natOwnerName(c.NATProfiles[0]))
			oldCalls, oldNATCalls, oldForward := f.calls, f.callsNAT, f.forward
			c.PreviousProfileSHA256 = oldFullSHA
			c.NATProfiles[0].PublicIPv4s = []string{"8.8.4.3"}
			c.NATProfiles[0].PreviousProfileSHA256 = oldNATSHA
			if name == "missing-old-pin" {
				c.NATProfiles[0].PreviousProfileSHA256 = ""
			}
			newFullSHA, _ := OverlayConfigSHA256(c)
			newNATSHA, _ := NATProfileSHA256(c.NATProfiles[0])
			if newFullSHA == oldFullSHA || newNATSHA == oldNATSHA {
				t.Fatal("address grant did not change both root pins")
			}
			s.Epoch++
			s.PreviousSHA256 = previous
			s.Profiles[0].ProfileSHA256, s.NATPolicies[0].ProfileSHA256 = newFullSHA, newNATSHA
			s.NATPolicies[0].PublicIPv4 = "8.8.4.3"
			f.profile, f.config, f.snapshot, f.configured = c.NATProfiles[0], c, s, []string{"8.8.4.3"}
			recovery := &overlayproto.Recovery{Epoch: oldSnapshot.Epoch, SnapshotSHA256: previous, Heads: []overlayproto.Head{
				{NodeID: c.Base.NodeID, ClusterID: s.ClusterID, Epoch: oldSnapshot.Epoch, SnapshotSHA256: previous},
				{NodeID: "node-b", ClusterID: s.ClusterID, Epoch: oldSnapshot.Epoch, SnapshotSHA256: previous},
			}}
			task := overlayTask(t, s, "prepare")
			if name != "ordinary-prepare" {
				task.Recovery = recovery
			}
			nop := func(context.Context) error { return nil }
			r, err := e.PrepareOverlay(context.Background(), c, task, nop)
			if name != "explicit-recovery" {
				if err == nil || r.Status == "succeeded" {
					t.Fatal("unapproved pool grant adopted", r, err)
				}
				if name == "ordinary-prepare" && (f.calls != oldCalls || f.callsNAT != oldNATCalls || f.forward != oldForward) {
					t.Fatal("ordinary prepare mutated namespace while changing root pins")
				}
				if !bytes.Equal(oldOwner, readPublicIPTestFile(t, c, natOwnerName(c.NATProfiles[0]))) {
					t.Fatal("rejected pool grant replaced old root owner")
				}
				if name == "missing-old-pin" && f.forward != "0" {
					t.Fatal("rejected recovery did not remain fenced")
				}
			} else {
				if err != nil || r.Status != "succeeded" {
					t.Fatal("approved root pool recovery prepare", r, err)
				}
				for _, phase := range []string{"program", "release"} {
					next := overlayTask(t, s, phase)
					next.Recovery = recovery
					if phase == "program" {
						r, err = e.ProgramOverlay(context.Background(), c, next)
					} else {
						r, err = e.ReleaseOverlay(context.Background(), c, next, nop)
					}
					if err != nil || r.Status != "succeeded" {
						t.Fatal("approved root pool recovery "+phase, r, err)
					}
				}
				if _, err := e.CheckOverlay(context.Background(), c); err != nil || f.forward != "1" {
					t.Fatal("approved pool recovery readiness", err, f.forward)
				}
				readPublicIPTestFile(t, c, "overlay-profile-migration-"+task.OperationID+".json")
				readPublicIPTestFile(t, c, "nat-profile-migration-"+c.NATProfiles[0].ID+"-"+task.OperationID+".json")
				var owner natOwnership
				if json.Unmarshal(readPublicIPTestFile(t, c, natOwnerName(c.NATProfiles[0])), &owner) != nil || owner.ProfileSHA256 != newNATSHA || !reflect.DeepEqual(owner.Profile.PublicIPv4s, []string{"8.8.4.3"}) {
					t.Fatal("new exact root pool ownership missing")
				}
			}
			for file, original := range oldFiles {
				if !bytes.Equal(original, readPublicIPTestFile(t, c, file)) {
					t.Fatal("root pool migration rewrote old operation/snapshot/receipt", file)
				}
			}
		})
	}
}

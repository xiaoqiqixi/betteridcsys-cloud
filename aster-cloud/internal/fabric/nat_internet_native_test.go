package fabric

import (
	"aster/cloud/internal/overlayproto"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Addresses with public syntax are only assigned to loopback/veth interfaces
// inside three temporary namespaces. The host has no link, route or packet path
// to this topology; no public host or external Internet service is contacted.
func TestNativeNATInternetEgressAndRevocation(t *testing.T) {
	if os.Getenv("ASTER_NATIVE_NAT") != "1" {
		t.Skip("native Internet NAT gate runs separately on Ubuntu22/24")
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Fatal("ASTER_NATIVE_NAT requires native Linux root")
	}
	hostBefore, err := exec.Command(NATNFT, "-j", "-s", "-n", "list", "ruleset").CombinedOutput()
	if err != nil {
		t.Fatal("host rules inventory", err, string(hostBefore))
	}
	t.Cleanup(func() {
		after, err := exec.Command(NATNFT, "-j", "-s", "-n", "list", "ruleset").CombinedOutput()
		if err != nil || string(after) != string(hostBefore) {
			t.Error("host nft rules changed during isolated Internet test", err)
		}
	})
	e, _, c, s := internetNATFixture(t)
	p := c.NATProfiles[0]
	p.AllowFloatingIP = true // Independent whole-address grant, not a port-range expansion.
	// Two real source addresses on the same dedicated veth; a third approved
	// reserve stays unconfigured. Selection is controller intent, provisioning
	// and its bounded approval remain independent root operations.
	p.PublicIPv4s = []string{"8.8.4.3", "8.8.4.4"}
	p.AllowedSourceCIDRs = []string{p.UplinkGatewayIPv4 + "/32", "9.9.9.0/24"}
	p.AllowedPorts = []NATPortRange{{"tcp", 18080, 18080}, {"udp", 18083, 18083}, {"tcp", 2444, 2444}}
	c.Gateways[0].AllowedPrefixes = []string{p.UplinkGatewayIPv4 + "/32", "9.9.9.0/24"}
	c.GuestNetworks[0].AllowedPrefixes = []string{p.UplinkGatewayIPv4 + "/32", "9.9.9.0/24"}
	s.Gateways[0].AllowedPrefixes = []string{p.UplinkGatewayIPv4 + "/32"}
	s.NATPolicies[0].PublicIPv4 = p.PublicIPv4s[0]
	s.NATPolicies[0].Forwardings = []overlayproto.NATForwarding{
		{ID: strings.Repeat("a", 32), Protocol: "tcp", PublicPort: 18080, TargetInstanceID: s.Members[0].InstanceID, TargetPort: 80, SourceCIDR: p.UplinkGatewayIPv4 + "/32"},
		{ID: strings.Repeat("b", 32), Protocol: "udp", PublicPort: 18083, TargetInstanceID: s.Members[0].InstanceID, TargetPort: 53, SourceCIDR: p.UplinkGatewayIPv4 + "/32"},
	}
	suffix := fmt.Sprintf("%d", os.Getpid())
	p.Namespace = "aster-pub-" + suffix
	insideNS, outsideNS := "aster-pubin-"+suffix, "aster-pubout-"+suffix
	command := func(binary string, args ...string) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, binary, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v %s", binary, args, err, out)
		}
		return out
	}
	for _, ns := range []string{p.Namespace, insideNS, outsideNS} {
		command(NATIP, "netns", "add", ns)
		t.Cleanup(func() { _ = exec.Command(NATIP, "netns", "delete", ns).Run() })
	}
	inPeer := TAPName(p.GatewayInstanceID)
	for _, pair := range []struct{ local, peer, ns, side string }{{p.InsideInterface, inPeer, insideNS, "inside"}, {p.OutsideInterface, p.OutsidePeer, outsideNS, "outside"}} {
		command(NATIP, "-n", p.Namespace, "link", "add", pair.local, "type", "veth", "peer", "name", pair.peer)
		command(NATIP, "-n", p.Namespace, "link", "set", pair.peer, "netns", pair.ns)
		command(NATIP, "-n", p.Namespace, "link", "set", pair.local, "mtu", "1500", "alias", natAlias(c.Base.NodeID, p.ID, pair.side), "up")
		command(NATIP, "-n", pair.ns, "link", "set", pair.peer, "mtu", "1500", "alias", natAlias(c.Base.NodeID, p.ID, pair.side+"-peer"), "up")
	}
	g := s.Gateways[0]
	command(NATIP, "-n", p.Namespace, "link", "set", p.InsideInterface, "address", g.MAC)
	for _, ns := range []string{p.Namespace, insideNS, outsideNS} {
		command(NATIP, "-n", ns, "link", "set", "lo", "up")
	}
	command(NATIP, "-n", p.Namespace, "addr", "add", g.IPv4+"/24", "dev", p.InsideInterface)
	command(NATIP, "-n", p.Namespace, "addr", "add", p.PublicIPv4+"/24", "dev", p.OutsideInterface)
	command(NATIP, "-n", p.Namespace, "addr", "add", p.PublicIPv4s[0]+"/32", "dev", p.OutsideInterface)
	command(NATIP, "-n", p.Namespace, "route", "add", "default", "via", p.UplinkGatewayIPv4, "dev", p.OutsideInterface)
	command(NATIP, "-n", insideNS, "addr", "add", s.Members[0].IPv4+"/24", "dev", inPeer)
	command(NATIP, "-n", insideNS, "route", "add", "default", "via", g.IPv4, "dev", inPeer)
	command(NATIP, "-n", outsideNS, "addr", "add", p.UplinkGatewayIPv4+"/24", "dev", p.OutsidePeer)
	command(NATIP, "-n", outsideNS, "route", "add", "10.11.0.0/24", "via", p.PublicIPv4, "dev", p.OutsidePeer)
	publicRemote := "9.9.9.9"
	blocked := []string{"172.16.9.9", "169.254.169.254", c.LocalIPv4, c.Peers[0].IPv4, "11.0.0.2"}
	for _, addr := range append([]string{publicRemote}, blocked...) {
		command(NATIP, "-n", outsideNS, "addr", "add", addr+"/32", "dev", "lo")
	}
	st, err := os.Stat("/run/netns/" + p.Namespace)
	if err != nil {
		t.Fatal(err)
	}
	stat := st.Sys().(*syscall.Stat_t)
	p.NamespaceDevice, p.NamespaceInode = uint64(stat.Dev), stat.Ino
	c.NATProfiles[0] = p
	sha, err := OverlayConfigSHA256(c)
	if err != nil {
		t.Fatal(err)
	}
	s.Profiles[0].ProfileSHA256 = sha
	s.NATPolicies[0].ProfileSHA256, _ = NATProfileSHA256(p)
	e.Runner = nativeNATRunner{insideNS: insideNS, outsideNS: outsideNS, insidePeer: inPeer, outsidePeer: p.OutsidePeer}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	l, err := openLedger(c.Base, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer l.close()
	if err = l.save(); err != nil {
		t.Fatal(err)
	}
	if err = l.pinOverlay(sha); err != nil {
		t.Fatal(err)
	}
	startNativeNATServer(t, outsideNS, publicRemote+":18081")
	startNativeNATServer(t, outsideNS, publicRemote+":18082", "udp4")
	startNativeNATServer(t, insideNS, s.Members[0].IPv4+":80")
	startNativeNATServer(t, insideNS, s.Members[0].IPv4+":53", "udp4")
	for _, addr := range blocked {
		startNativeNATServer(t, outsideNS, addr+":18081")
	}
	missing := s
	missing.NATPolicies = append([]overlayproto.NATPolicy{}, s.NATPolicies...)
	missing.NATPolicies[0].PublicIPv4 = p.PublicIPv4s[1]
	if err := e.probeNAT(ctx, c, missing, p); err == nil {
		t.Fatal("approved but unconfigured public address passed native probe")
	}
	if err = e.prepareNAT(ctx, c, l, s); err != nil {
		t.Fatal("public prepare", err)
	}
	if err = e.programNAT(ctx, c, l, s); err != nil {
		dumpNativeNAT(t, p)
		t.Fatal("public program", err)
	}
	if out, err := nativeNATClient(insideNS, "http://"+publicRemote+":18081"); err == nil {
		t.Fatal("public forwarding released before barrier", string(out))
	}
	if err = e.releaseNAT(ctx, c, l, s); err != nil {
		dumpNativeNAT(t, p)
		t.Fatal("public release", err)
	}
	for _, network := range []string{"tcp4", "udp4"} {
		url := "http://" + publicRemote + ":18081"
		if network == "udp4" {
			url = publicRemote + ":18082"
		}
		out, err := nativeNATClient(insideNS, url, network)
		if err != nil || !strings.Contains(string(out), "NAT_REMOTE="+p.PublicIPv4s[0]+":") {
			dumpNativeNAT(t, p)
			t.Fatalf("public %s source/reply: %v %s", network, err, out)
		}
	}
	if out, err := nativeNATClient(insideNS, publicRemote, "icmp4"); err != nil || !strings.Contains(string(out), "NAT_ICMP_REPLY="+publicRemote) {
		dumpNativeNAT(t, p)
		t.Fatal("public ICMP echo/reply", err, string(out))
	}
	for _, network := range []string{"tcp4", "udp4"} {
		url := "http://" + p.PublicIPv4s[0] + ":18080"
		if network == "udp4" {
			url = p.PublicIPv4s[0] + ":18083"
		}
		if out, err := nativeNATClient(outsideNS, url, network); err != nil || !strings.Contains(string(out), "NAT_REMOTE="+p.UplinkGatewayIPv4+":") {
			t.Fatal("selected-IP DNAT source/target", network, err, string(out))
		}
	}
	// The peer can route directly to the guest; only the actual namespace rules
	// prevent a new inbound connection. A missing port mapping must not become a
	// blanket established/related accept or an implicit Internet DNAT service.
	if out, err := nativeNATClient(outsideNS, "http://"+s.Members[0].IPv4+":80"); err == nil {
		t.Fatal("unsolicited inbound Internet reached guest", string(out))
	}
	for _, addr := range blocked {
		if out, err := nativeNATClient(insideNS, "http://"+addr+":18081"); err == nil {
			t.Fatal("protected/metadata/underlay destination reached", addr, string(out))
		}
	}
	apply := func(label string) {
		t.Helper()
		for _, phase := range []struct {
			name string
			run  func(context.Context, OverlayConfig, *ledger, overlayproto.Snapshot) error
		}{{"prepare", func(ctx context.Context, c OverlayConfig, l *ledger, s overlayproto.Snapshot) error {
			return e.prepareNAT(ctx, c, l, s)
		}}, {"program", e.programNAT}, {"release", e.releaseNAT}} {
			if err := phase.run(ctx, c, l, s); err != nil {
				// Fixed isolated fixture data only. Keep exact readback enforcement;
				// expose the first structural difference rather than guessing at a
				// normalization exception or accepting a failed native program.
				objects, compileErr := compileNAT(c, s, p, false)
				raw, _ := json.Marshal(nftObject{"nftables": objects})
				want, _, wantErr := normalizeNFT(raw)
				actual, exists, readErr := e.natRules(ctx, p)
				t.Logf("NATIVE_NAT_DIAGNOSTIC compile=%v want=%v read=%v exists=%v", compileErr, wantErr, readErr, exists)
				var wanted, got []json.RawMessage
				if json.Unmarshal(want, &wanted) == nil && json.Unmarshal(actual, &got) == nil {
					t.Logf("NATIVE_NAT_OBJECT_COUNTS want=%d actual=%d", len(wanted), len(got))
					for i := 0; i < len(wanted) && i < len(got); i++ {
						if string(wanted[i]) != string(got[i]) {
							t.Logf("NATIVE_NAT_FIRST_DIFF index=%d want=%s actual=%s", i, wanted[i], got[i])
							break
						}
					}
				}
				t.Fatal(label+" "+phase.name, err)
			}
		}
	}
	assertHeldRevoked := func(held, label string) {
		t.Helper()
		if err := os.WriteFile(held+".continue", []byte("continue"), 0600); err != nil {
			t.Fatal(err)
		}
		waitNativeNATFile(t, held+".result")
		result, err := os.ReadFile(held + ".result")
		if err != nil || string(result) != "blocked" {
			t.Fatal(label, err, string(result))
		}
	}
	// Switching a live allocation must revoke old conntrack, not merely update
	// rules while an established flow retains the previous source identity.
	held := startNativeNATHeldClient(t, insideNS, "http://"+publicRemote+":18081")
	s.NATPolicies[0].PublicIPv4 = p.PublicIPv4
	apply("switch selected public IP")
	assertHeldRevoked(held, "existing TCP survived public-IP switch")
	for _, network := range []string{"tcp4", "udp4"} {
		url := "http://" + publicRemote + ":18081"
		if network == "udp4" {
			url = publicRemote + ":18082"
		}
		if out, err := nativeNATClient(insideNS, url, network); err != nil || !strings.Contains(string(out), "NAT_REMOTE="+p.PublicIPv4+":") {
			t.Fatal("switched public source/reply", network, err, string(out))
		}
		url = "http://" + p.PublicIPv4 + ":18080"
		if network == "udp4" {
			url = p.PublicIPv4 + ":18083"
		}
		if out, err := nativeNATClient(outsideNS, url, network); err != nil || !strings.Contains(string(out), "NAT_REMOTE="+p.UplinkGatewayIPv4+":") {
			t.Fatal("switched public DNAT", network, err, string(out))
		}
		old := "http://" + p.PublicIPv4s[0] + ":18080"
		if network == "udp4" {
			old = p.PublicIPv4s[0] + ":18083"
		}
		if out, err := nativeNATClient(outsideNS, old, network); err == nil {
			t.Fatal("old public IP retained DNAT binding", network, string(out))
		}
	}
	held = startNativeNATHeldClient(t, insideNS, "http://"+publicRemote+":18081")
	s.NATPolicies[0].InternetEgressEnabled = false
	apply("disable public egress")
	assertHeldRevoked(held, "existing public TCP survived disable")
	for _, network := range []string{"tcp4", "udp4"} {
		url := "http://" + publicRemote + ":18081"
		if network == "udp4" {
			url = publicRemote + ":18082"
		}
		if out, err := nativeNATClient(insideNS, url, network); err == nil {
			t.Fatal("disabled public egress survived", network, string(out))
		}
	}
	s.NATPolicies = nil
	apply("remove public IP binding")
	for _, address := range []string{p.PublicIPv4, p.PublicIPv4s[0]} {
		if out, err := nativeNATClient(outsideNS, "http://"+address+":18080"); err == nil {
			t.Fatal("released binding retained DNAT", address, string(out))
		}
	}
	if err = e.verifyNAT(ctx, c, l, s, true); err != nil {
		t.Fatal("public final readback", err)
	}
	// Reuse the owned isolated topology to exercise the new independent floating
	// resource through real nft/conntrack. No OVS or KVM success is inferred.
	target, other := s.Members[0], s.Members[1]
	command(NATIP, "-n", insideNS, "addr", "add", other.IPv4+"/24", "dev", inPeer)
	for _, m := range []string{target.IPv4, other.IPv4} {
		startNativeNATServer(t, insideNS, m+":2444")
		startNativeNATServer(t, insideNS, m+":2445", "udp4")
	}
	// The uplink's own IP is intentionally denied; use an ordinary public client
	// address on the isolated peer, with an explicit route-preferred source.
	command(NATIP, "-n", outsideNS, "route", "replace", p.PublicIPv4+"/32", "dev", p.OutsidePeer, "src", publicRemote)
	nsha, _ := NATProfileSHA256(p)
	fip := overlayproto.FloatingIP{ResourceID: strings.Repeat("c", 32), NodeID: c.Base.NodeID, VPCID: target.VPCID, OwnerRef: target.OwnerRef, ProfileID: p.ID, ProfileSHA256: nsha, GatewayInstanceID: p.GatewayInstanceID, InstanceID: target.InstanceID, TargetIPv4: target.IPv4, PublicIPv4: p.PublicIPv4}
	s.FloatingIPs = []overlayproto.FloatingIP{fip}
	missing = s
	missing.FloatingIPs = append([]overlayproto.FloatingIP{}, s.FloatingIPs...)
	missing.FloatingIPs[0].PublicIPv4 = p.PublicIPv4s[1]
	if err := e.probeNAT(ctx, c, missing, p); err == nil {
		t.Fatal("floating root grant confused with configured usable address")
	}
	apply("bind floating public IP")
	checkFloating := func(want string) {
		t.Helper()
		for _, network := range []string{"tcp4", "udp4"} {
			url, port := "http://"+p.PublicIPv4+":2444", "2444"
			if network == "udp4" {
				url, port = p.PublicIPv4+":2445", "2445"
			}
			out, err := nativeNATClient(outsideNS, url, network)
			if err != nil || !strings.Contains(string(out), "NAT_LOCAL="+want+":"+port) || !strings.Contains(string(out), "NAT_REMOTE="+publicRemote+":") {
				dumpNativeNAT(t, p)
				t.Fatal("floating target/source/port preservation", network, want, err, string(out))
			}
		}
		if out, err := nativeNATClient(outsideNS, p.PublicIPv4, "icmp4"); err != nil || !strings.Contains(string(out), "NAT_ICMP_REPLY="+p.PublicIPv4) {
			t.Fatal("floating inbound ICMP", err, string(out))
		}
		if out, err := nativeNATClient(insideNS, "http://"+publicRemote+":18081"); err != nil || !strings.Contains(string(out), "NAT_REMOTE="+p.PublicIPv4+":") {
			t.Fatal("floating VM outbound identity", err, string(out))
		}
		for _, addr := range blocked {
			if out, err := nativeNATClient(insideNS, "http://"+addr+":18081"); err == nil {
				t.Fatal("floating reached protected destination", addr, string(out))
			}
		}
		if out, err := nativeNATClient(outsideNS, "http://"+want+":2444"); err == nil {
			t.Fatal("peer private route bypassed floating DNAT", string(out))
		}
	}
	checkFloating(target.IPv4)
	held = startNativeNATHeldClient(t, insideNS, "http://"+publicRemote+":18081")
	s.FloatingIPs[0].InstanceID, s.FloatingIPs[0].TargetIPv4 = other.InstanceID, other.IPv4
	if err = e.prepareNAT(ctx, c, l, s); err != nil {
		t.Fatal("floating move prepare", err)
	}
	if err = e.programNAT(ctx, c, l, s); err != nil {
		t.Fatal("floating move program", err)
	}
	if out, err := nativeNATClient(outsideNS, "http://"+p.PublicIPv4+":2444"); err == nil {
		t.Fatal("floating move released before all phases", string(out))
	}
	if err = e.releaseNAT(ctx, c, l, s); err != nil {
		t.Fatal("floating move release", err)
	}
	assertHeldRevoked(held, "old VM kept an established floating source after move")
	command(NATIP, "-n", insideNS, "route", "replace", "default", "via", g.IPv4, "dev", inPeer, "src", other.IPv4)
	checkFloating(other.IPv4)
	s.FloatingIPs = nil
	apply("detach floating public IP")
	for _, network := range []string{"tcp4", "udp4"} {
		url := "http://" + p.PublicIPv4 + ":2444"
		if network == "udp4" {
			url = p.PublicIPv4 + ":2445"
		}
		if out, err := nativeNATClient(outsideNS, url, network); err == nil {
			t.Fatal("reclaimed floating mapping survived", network, string(out))
		}
	}
	if out, err := nativeNATClient(insideNS, "http://"+publicRemote+":18081"); err == nil {
		t.Fatal("detached VM kept floating source", string(out))
	}
	if err = e.verifyNAT(ctx, c, l, s, true); err != nil {
		t.Fatal("floating detach final readback", err)
	}
	// New bindings carry an instance-owned policy. Empty means deny public
	// initiations, not legacy full-address acceptance. Outbound replies survive.
	command(NATIP, "-n", insideNS, "route", "replace", "default", "via", g.IPv4, "dev", inPeer, "src", target.IPv4)
	policy := overlayproto.DefaultPublicIngress(target.InstanceID, target.OwnerRef)
	fip.Ingress = &policy
	s.FloatingIPs = []overlayproto.FloatingIP{fip}
	apply("bind public IP with default-deny ingress")
	publicTargets := []struct{ address, network string }{{"http://" + p.PublicIPv4 + ":2444", "tcp4"}, {p.PublicIPv4 + ":2445", "udp4"}, {p.PublicIPv4, "icmp4"}}
	for _, probe := range publicTargets {
		if out, err := nativeNATClient(outsideNS, probe.address, probe.network); err == nil {
			t.Fatal("empty ingress policy accepted public initiation", probe.network, string(out))
		}
	}
	if out, err := nativeNATClient(insideNS, "http://"+publicRemote+":18081"); err != nil || !strings.Contains(string(out), "NAT_REMOTE="+p.PublicIPv4+":") {
		t.Fatal("default ingress deny disabled outbound replies", err, string(out))
	}
	t.Log("PUBLIC_INGRESS_DEFAULT_DENY_AND_OUTBOUND_REPLY_CONFIRMED")
	policy.Revision = 1
	policy.SHA256 = ""
	policy.Rules = []overlayproto.PublicIngressRule{
		{ID: strings.Repeat("1", 32), Protocol: "tcp", SourceCIDR: publicRemote + "/32", PortStart: 2444, PortEnd: 2445},
		{ID: strings.Repeat("2", 32), Protocol: "udp", SourceCIDR: publicRemote + "/32", PortStart: 2444, PortEnd: 2445},
		{ID: strings.Repeat("3", 32), Protocol: "icmp", SourceCIDR: publicRemote + "/32"},
	}
	policy, err = overlayproto.CanonicalPublicIngress(policy)
	if err != nil {
		t.Fatal(err)
	}
	s.FloatingIPs[0].Ingress = &policy
	apply("allow exact public sources and service ports")
	checkFloating(target.IPv4)
	// Closed UDP ports generate actual kernel ICMP destination-unreachable
	// errors. Prove related traffic in both SNAT and DNAT directions, not a
	// blanket ICMP allow or merely an emulated packet verdict.
	for _, probe := range []struct{ ns, address string }{{insideNS, publicRemote + ":18084"}, {outsideNS, p.PublicIPv4 + ":2444"}} {
		if out, err := nativeNATClient(probe.ns, probe.address, "udp-icmp-unreachable"); err != nil || !strings.Contains(string(out), "NAT_RELATED_ICMP_UNREACHABLE_CONFIRMED") {
			t.Fatal("related ICMP NAT traversal", probe.ns, err, string(out))
		}
	}
	t.Log("PUBLIC_INGRESS_RELATED_ICMP_BOTH_DIRECTIONS_CONFIRMED")
	startNativeNATServer(t, insideNS, target.IPv4+":2446")
	startNativeNATServer(t, insideNS, target.IPv4+":2446", "udp4")
	for _, probe := range []struct{ address, network string }{{"http://" + p.PublicIPv4 + ":2446", "tcp4"}, {p.PublicIPv4 + ":2446", "udp4"}} {
		if out, err := nativeNATClient(outsideNS, probe.address, probe.network); err == nil {
			t.Fatal("unapproved live service port accepted", probe.network, string(out))
		}
	}
	otherPublicClient := "9.9.9.10"
	command(NATIP, "-n", outsideNS, "addr", "add", otherPublicClient+"/32", "dev", "lo")
	command(NATIP, "-n", outsideNS, "route", "replace", p.PublicIPv4+"/32", "dev", p.OutsidePeer, "src", otherPublicClient)
	for _, probe := range publicTargets {
		if out, err := nativeNATClient(outsideNS, probe.address, probe.network); err == nil {
			t.Fatal("unapproved public source accepted", probe.network, string(out))
		}
	}
	command(NATIP, "-n", outsideNS, "route", "replace", p.PublicIPv4+"/32", "dev", p.OutsidePeer, "src", publicRemote)
	t.Log("PUBLIC_INGRESS_EXACT_SOURCE_PORT_AND_ICMP_CONFIRMED")
	// The editor's common all-public source must also survive exact native
	// readback. It does not override the separate protected-source floor.
	policy.Revision++
	policy.SHA256 = ""
	for i := range policy.Rules {
		policy.Rules[i].SourceCIDR = "0.0.0.0/0"
	}
	policy, err = overlayproto.CanonicalPublicIngress(policy)
	if err != nil {
		t.Fatal(err)
	}
	s.FloatingIPs[0].Ingress = &policy
	apply("allow public CIDR without bypassing protected sources")
	command(NATIP, "-n", outsideNS, "route", "replace", p.PublicIPv4+"/32", "dev", p.OutsidePeer, "src", otherPublicClient)
	for _, probe := range publicTargets {
		if out, err := nativeNATClient(outsideNS, probe.address, probe.network); err != nil {
			t.Fatal("all-public source rule did not allow live service", probe.network, err, string(out))
		}
	}
	command(NATIP, "-n", outsideNS, "route", "replace", p.PublicIPv4+"/32", "dev", p.OutsidePeer, "src", "169.254.169.254")
	if out, err := nativeNATClient(outsideNS, "http://"+p.PublicIPv4+":2444"); err == nil {
		t.Fatal("all-public source rule overrode metadata protected floor", string(out))
	}
	command(NATIP, "-n", outsideNS, "route", "replace", p.PublicIPv4+"/32", "dev", p.OutsidePeer, "src", publicRemote)
	t.Log("PUBLIC_INGRESS_ALL_PUBLIC_CIDR_AND_PROTECTED_FLOOR_CONFIRMED")
	heldIncoming := startNativeNATHeldClient(t, outsideNS, "http://"+p.PublicIPv4+":2444")
	policy.Revision++
	policy.SHA256 = ""
	policy.Rules = []overlayproto.PublicIngressRule{}
	policy, err = overlayproto.CanonicalPublicIngress(policy)
	if err != nil {
		t.Fatal(err)
	}
	s.FloatingIPs[0].Ingress = &policy
	apply("revoke public ingress policy and its established connections")
	assertHeldRevoked(heldIncoming, "revoked ingress retained an established public TCP connection")
	for _, probe := range publicTargets {
		if out, err := nativeNATClient(outsideNS, probe.address, probe.network); err == nil {
			t.Fatal("revoked ingress service remained reachable", probe.network, string(out))
		}
	}
	if out, err := nativeNATClient(insideNS, "http://"+publicRemote+":18081"); err != nil {
		t.Fatal("ingress revoke disabled authorized outbound replies", err, string(out))
	}
	t.Log("PUBLIC_INGRESS_REVOKE_CONNTRACK_AND_FINAL_READBACK_CONFIRMED")
	if err = e.verifyNAT(ctx, c, l, s, true); err != nil {
		t.Fatal("public ingress revoke readback", err)
	}
	// Independent shared NAT and this EIP can target the same private VM.
	// A deny on the EIP must not borrow that other address's forwarding rule.
	s.Gateways[0].AllowedPrefixes = []string{p.UplinkGatewayIPv4 + "/32", "9.9.9.0/24"}
	s.NATPolicies = []overlayproto.NATPolicy{{ID: strings.Repeat("d", 32), NodeID: c.Base.NodeID, VPCID: target.VPCID, GatewayInstanceID: p.GatewayInstanceID, ProfileID: p.ID, ProfileSHA256: nsha, PublicIPv4: p.PublicIPv4s[0], Forwardings: []overlayproto.NATForwarding{{ID: strings.Repeat("e", 32), Protocol: "tcp", PublicPort: 2444, TargetInstanceID: target.InstanceID, TargetPort: 2444, SourceCIDR: publicRemote + "/32"}}}}
	command(NATIP, "-n", outsideNS, "route", "replace", p.PublicIPv4s[0]+"/32", "dev", p.OutsidePeer, "src", publicRemote)
	apply("preserve independent shared DNAT without bypassing EIP ingress")
	if out, err := nativeNATClient(outsideNS, "http://"+p.PublicIPv4s[0]+":2444"); err != nil || !strings.Contains(string(out), "NAT_LOCAL="+target.IPv4+":2444") {
		t.Fatal("independent shared DNAT lost", err, string(out))
	}
	if out, err := nativeNATClient(outsideNS, "http://"+p.PublicIPv4+":2444"); err == nil {
		t.Fatal("denied EIP borrowed shared DNAT allow", string(out))
	}
	t.Log("PUBLIC_INGRESS_SHARED_NAT_BOUNDARY_CONFIRMED")
}

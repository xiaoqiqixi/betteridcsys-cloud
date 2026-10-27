package fabric

import (
	"aster/cloud/internal/overlayproto"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// This mandatory Linux CI gate uses three short-lived network namespaces and
// two veth pairs. No host address/route/sysctl, physical NIC, OVS or KVM is used.
func TestNativeNATPacketFlowAndRevocation(t *testing.T) {
	if os.Getenv("ASTER_NATIVE_NAT") != "1" {
		t.Skip("native NAT namespace gate runs separately on Ubuntu22/24")
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Fatal("ASTER_NATIVE_NAT requires native Linux root")
	}
	for _, binary := range []string{NATIP, NATNFT, NATSysctl, NATConntrack, "/usr/bin/nsenter"} {
		if _, err := os.Stat(binary); err != nil {
			t.Fatal(err)
		}
	}
	hostRulesBefore, hostErr := exec.Command(NATNFT, "-j", "-s", "-n", "list", "ruleset").CombinedOutput()
	if hostErr != nil {
		t.Fatal("host rules inventory", hostErr, string(hostRulesBefore))
	}
	t.Cleanup(func() {
		after, err := exec.Command(NATNFT, "-j", "-s", "-n", "list", "ruleset").CombinedOutput()
		if err != nil || string(after) != string(hostRulesBefore) {
			t.Error("host nft rules changed during isolated test", err)
		}
	})
	e, _, c, s := natFixture(t)
	s.NATPolicies[0].Forwardings = append(s.NATPolicies[0].Forwardings, overlayproto.NATForwarding{ID: strings.Repeat("b", 32), Protocol: "udp", PublicPort: 18083, TargetInstanceID: s.Members[0].InstanceID, TargetPort: 53, SourceCIDR: "198.51.100.0/24"})
	p := c.NATProfiles[0]
	suffix := fmt.Sprintf("%d", os.Getpid())
	p.Namespace = "aster-nat-" + suffix
	insideNS := "aster-in-" + suffix
	outsideNS := "aster-out-" + suffix
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
	p.OutsidePeer = "nat-uplink"
	inPeer := TAPName(p.GatewayInstanceID)
	for _, pair := range []struct{ local, peer, otherNS, side string }{{p.InsideInterface, inPeer, insideNS, "inside"}, {p.OutsideInterface, p.OutsidePeer, outsideNS, "outside"}} {
		command(NATIP, "-n", p.Namespace, "link", "add", pair.local, "type", "veth", "peer", "name", pair.peer)
		command(NATIP, "-n", p.Namespace, "link", "set", pair.peer, "netns", pair.otherNS)
		command(NATIP, "-n", p.Namespace, "link", "set", pair.local, "mtu", "1500", "alias", natAlias(c.Base.NodeID, p.ID, pair.side), "up")
		command(NATIP, "-n", pair.otherNS, "link", "set", pair.peer, "mtu", "1500", "alias", natAlias(c.Base.NodeID, p.ID, pair.side+"-peer"), "up")
	}
	g := s.Gateways[0]
	command(NATIP, "-n", p.Namespace, "link", "set", p.InsideInterface, "address", g.MAC)
	for _, ns := range []string{p.Namespace, insideNS, outsideNS} {
		command(NATIP, "-n", ns, "link", "set", "lo", "up")
	}
	command(NATIP, "-n", p.Namespace, "addr", "add", g.IPv4+"/24", "dev", p.InsideInterface)
	command(NATIP, "-n", p.Namespace, "addr", "add", p.PublicIPv4+"/24", "dev", p.OutsideInterface)
	command(NATIP, "-n", p.Namespace, "route", "add", "default", "via", p.UplinkGatewayIPv4, "dev", p.OutsideInterface)
	command(NATIP, "-n", insideNS, "addr", "add", s.Members[0].IPv4+"/24", "dev", inPeer)
	command(NATIP, "-n", insideNS, "route", "add", "198.51.100.0/24", "via", g.IPv4, "dev", inPeer)
	command(NATIP, "-n", outsideNS, "addr", "add", p.UplinkGatewayIPv4+"/24", "dev", p.OutsidePeer)
	command(NATIP, "-n", outsideNS, "route", "add", "10.11.0.0/24", "via", p.PublicIPv4, "dev", p.OutsidePeer)
	st, err := os.Stat("/run/netns/" + p.Namespace)
	if err != nil {
		t.Fatal(err)
	}
	stat := st.Sys().(*syscall.Stat_t)
	p.NamespaceDevice = uint64(stat.Dev)
	p.NamespaceInode = stat.Ino
	c.NATProfiles = []NATProfile{p}
	sha, err := OverlayConfigSHA256(c)
	if err != nil {
		t.Fatal(err)
	}
	s.Profiles[0].ProfileSHA256 = sha
	s.NATPolicies[0].ProfileSHA256, _ = NATProfileSHA256(p)
	e.Runner = nativeNATRunner{insideNS: insideNS, outsideNS: outsideNS, insidePeer: inPeer, outsidePeer: p.OutsidePeer}
	// Actual namespace pinning must reject the host namespace and stale identity.
	wrong := p
	wrong.NamespaceInode++
	if _, err = (OSRunner{}).RunNamespace(context.Background(), wrong, NATSysctl, "-n", "net.ipv4.ip_forward"); err == nil {
		t.Fatal("stale inode accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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
	if err = e.prepareNAT(ctx, c, l, s); err != nil {
		t.Fatal("native prepare", err)
	}
	if err = e.programNAT(ctx, c, l, s); err != nil {
		dumpNativeNAT(t, p)
		t.Fatal("native program", err)
	}
	startNativeNATServer(t, outsideNS, p.UplinkGatewayIPv4+":18081")
	startNativeNATServer(t, insideNS, s.Members[0].IPv4+":80")
	startNativeNATServer(t, insideNS, s.Members[0].IPv4+":53", "udp4")
	if out, err := nativeNATClient(insideNS, "http://"+p.UplinkGatewayIPv4+":18081"); err == nil {
		t.Fatal("program released forwarding", string(out))
	}
	if err = e.releaseNAT(ctx, c, l, s); err != nil {
		dumpNativeNAT(t, p)
		t.Fatal("native release", err)
	}
	out, err := nativeNATClient(insideNS, "http://"+p.UplinkGatewayIPv4+":18081")
	if err != nil || !strings.Contains(string(out), "NAT_REMOTE="+p.PublicIPv4+":") {
		dumpNativeNAT(t, p)
		t.Fatalf("SNAT packet source not translated: %v %s", err, out)
	}
	out, err = nativeNATClient(outsideNS, "http://"+p.PublicIPv4+":18080")
	if err != nil || !strings.Contains(string(out), "NAT_REMOTE="+p.UplinkGatewayIPv4+":") {
		dumpNativeNAT(t, p)
		t.Fatalf("DNAT did not reach frozen target: %v %s", err, out)
	}
	out, err = nativeNATClient(outsideNS, p.PublicIPv4+":18083", "udp4")
	if err != nil || !strings.Contains(string(out), "NAT_REMOTE="+p.UplinkGatewayIPv4+":") {
		t.Fatalf("UDP DNAT did not reach exact target: %v %s", err, out)
	}
	if out, err = nativeNATClient(outsideNS, "http://"+p.PublicIPv4+":18082"); err == nil {
		t.Fatal("unapproved port reached", string(out))
	}
	// Keep an actual translated TCP connection open across policy removal.
	held := startNativeNATHeldClient(t, outsideNS, "http://"+p.PublicIPv4+":18080")
	// Existing cached state is cleared, not just new NAT rules removed.
	s.NATPolicies = nil
	if err = e.prepareNAT(ctx, c, l, s); err != nil {
		t.Fatal(err)
	}
	if err = e.programNAT(ctx, c, l, s); err != nil {
		t.Fatal(err)
	}
	if err = e.releaseNAT(ctx, c, l, s); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(held+".continue", []byte("continue"), 0600); err != nil {
		t.Fatal(err)
	}
	waitNativeNATFile(t, held+".result")
	heldResult, err := os.ReadFile(held + ".result")
	if err != nil || string(heldResult) != "blocked" {
		t.Fatal("existing NAT connection survived removal", err, string(heldResult))
	}
	for _, v := range []struct{ ns, url string }{{insideNS, "http://" + p.UplinkGatewayIPv4 + ":18081"}, {outsideNS, "http://" + p.PublicIPv4 + ":18080"}} {
		if out, err = nativeNATClient(v.ns, v.url); err == nil {
			t.Fatal("removed NAT survived", string(out))
		}
	}
	if err = e.verifyNAT(ctx, c, l, s, true); err != nil {
		t.Fatal("final readback", err)
	}
}

// Host-peer reads are mapped into the two isolated endpoint namespaces. Their
// real ifindex/iflink/alias and NAT namespace identities are still validated.
type nativeNATRunner struct{ insideNS, outsideNS, insidePeer, outsidePeer string }

func (r nativeNATRunner) Run(ctx context.Context, binary string, args ...string) ([]byte, error) {
	if binary != NATIP || len(args) != 6 {
		return nil, ErrInvalid
	}
	ns := r.insideNS
	if args[5] == r.outsidePeer {
		ns = r.outsideNS
	} else if args[5] != r.insidePeer {
		return nil, ErrInvalid
	}
	return exec.CommandContext(ctx, NATIP, append([]string{"-n", ns}, args...)...).CombinedOutput()
}
func (r nativeNATRunner) RunNamespace(ctx context.Context, p NATProfile, binary string, args ...string) ([]byte, error) {
	return (OSRunner{}).RunNamespace(ctx, p, binary, args...)
}
func dumpNativeNAT(t *testing.T, p NATProfile) {
	t.Helper()
	out, err := exec.Command(NATIP, "netns", "exec", p.Namespace, NATNFT, "-j", "-n", "list", "ruleset").CombinedOutput()
	t.Logf("native rules: %v %s", err, out)
}
func startNativeNATServer(t *testing.T, ns, address string, network ...string) {
	t.Helper()
	ready := filepath.Join(t.TempDir(), "ready")
	cmd := exec.Command(NATIP, "netns", "exec", ns, os.Args[0], "-test.run=^TestNativeNATHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), "ASTER_NAT_HELPER=server", "ASTER_NAT_ADDRESS="+address, "ASTER_NAT_READY="+ready)
	if len(network) > 0 {
		cmd.Env = append(cmd.Env, "ASTER_NAT_NETWORK="+network[0])
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(ready); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("NAT test server did not become ready")
}
func nativeNATClient(ns, url string, network ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, NATIP, "netns", "exec", ns, os.Args[0], "-test.run=^TestNativeNATHelper$", "-test.count=1")
	// These short, fully waited test helpers retain race instrumentation, but
	// do not each spend one fixed second in the race runtime's exit grace period.
	// Keep the existing packet/phase deadlines and every negative assertion.
	cmd.Env = append(os.Environ(), "GORACE="+os.Getenv("GORACE")+" atexit_sleep_ms=0", "ASTER_NAT_HELPER=client", "ASTER_NAT_ADDRESS="+url)
	if len(network) > 0 {
		cmd.Env = append(cmd.Env, "ASTER_NAT_NETWORK="+network[0])
	}
	return cmd.CombinedOutput()
}
func waitNativeNATFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("NAT helper did not signal", path)
}
func startNativeNATHeldClient(t *testing.T, ns, url string) string {
	t.Helper()
	ready := filepath.Join(t.TempDir(), "held")
	cmd := exec.Command(NATIP, "netns", "exec", ns, os.Args[0], "-test.run=^TestNativeNATHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), "ASTER_NAT_HELPER=hold", "ASTER_NAT_ADDRESS="+url, "ASTER_NAT_READY="+ready)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	waitNativeNATFile(t, ready)
	return ready
}
func TestNativeNATHelper(t *testing.T) {
	switch os.Getenv("ASTER_NAT_HELPER") {
	case "hold":
		var dials atomic.Int32
		client := http.Client{Timeout: 1200 * time.Millisecond, Transport: &http.Transport{Proxy: nil, MaxIdleConnsPerHost: 1, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if dials.Add(1) != 1 {
				return nil, fmt.Errorf("held-connection probe forbids reconnect")
			}
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}}}
		ready := os.Getenv("ASTER_NAT_READY")
		response, err := client.Get(os.Getenv("ASTER_NAT_ADDRESS"))
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(ready, []byte("connected"), 0600); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(15 * time.Second)
		found := false
		for time.Now().Before(deadline) {
			if _, err := os.Stat(ready + ".continue"); err == nil {
				found = true
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if !found {
			t.Fatal("held connection timeout")
		}
		response, err = client.Get(os.Getenv("ASTER_NAT_ADDRESS"))
		result := "blocked"
		if err == nil {
			response.Body.Close()
			result = "unexpected-success"
		}
		if err = os.WriteFile(ready+".result", []byte(result), 0600); err != nil {
			t.Fatal(err)
		}
	case "server":
		if os.Getenv("ASTER_NAT_NETWORK") == "udp4" {
			conn, err := net.ListenPacket("udp4", os.Getenv("ASTER_NAT_ADDRESS"))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err = os.WriteFile(os.Getenv("ASTER_NAT_READY"), []byte("ready"), 0600); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 512)
			for {
				_, addr, err := conn.ReadFrom(buf)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = conn.WriteTo([]byte("NAT_REMOTE="+addr.String()+"\nNAT_LOCAL="+conn.LocalAddr().String()), addr); err != nil {
					t.Fatal(err)
				}
			}
		}
		listener, err := net.Listen("tcp4", os.Getenv("ASTER_NAT_ADDRESS"))
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(os.Getenv("ASTER_NAT_READY"), []byte("ready"), 0600); err != nil {
			t.Fatal(err)
		}
		server := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, "NAT_REMOTE="+r.RemoteAddr+"\nNAT_LOCAL="+os.Getenv("ASTER_NAT_ADDRESS"))
		}), ReadHeaderTimeout: 2 * time.Second}
		_ = server.Serve(listener)
	case "client":
		if os.Getenv("ASTER_NAT_NETWORK") == "icmp4" {
			address := os.Getenv("ASTER_NAT_ADDRESS")
			conn, err := net.DialIP("ip4:icmp", nil, &net.IPAddr{IP: net.ParseIP(address)})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(1200 * time.Millisecond))
			request := []byte{8, 0, 0, 0, 0x4a, 0x53, 0, 1, 'n', 'a', 't', '-', 'e', 'c', 'h', 'o'}
			var sum uint32
			for i := 0; i < len(request); i += 2 {
				sum += uint32(binary.BigEndian.Uint16(request[i:]))
			}
			for sum>>16 != 0 {
				sum = (sum & 0xffff) + (sum >> 16)
			}
			binary.BigEndian.PutUint16(request[2:4], ^uint16(sum))
			if _, err = conn.Write(request); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 256)
			n, peer, err := conn.ReadFromIP(buf)
			if err != nil {
				t.Fatalf("ICMP echo reply: %v %x", err, buf[:n])
			}
			if peer == nil || !peer.IP.Equal(net.ParseIP(address)) {
				t.Fatal("ICMP reply source differs from probe target", peer)
			}
			// ReadFromIP strips the IPv4 header through net.IPConn.readFrom;
			// embedded conn.Read does not. Validate the complete ICMP payload.
			if err := nativeNATEchoReply(buf[:n]); err != nil {
				t.Fatalf("ICMP echo reply: %v %x", err, buf[:n])
			}
			fmt.Print("NAT_ICMP_REPLY=" + address)
			return
		}
		if os.Getenv("ASTER_NAT_NETWORK") == "udp4" || os.Getenv("ASTER_NAT_NETWORK") == "udp-icmp-unreachable" {
			conn, err := net.DialTimeout("udp4", os.Getenv("ASTER_NAT_ADDRESS"), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(1200 * time.Millisecond))
			if _, err = conn.Write([]byte("probe")); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 512)
			n, err := conn.Read(buf)
			if os.Getenv("ASTER_NAT_NETWORK") == "udp-icmp-unreachable" {
				if !errors.Is(err, syscall.ECONNREFUSED) {
					t.Fatal("related ICMP unreachable did not traverse NAT", err)
				}
				fmt.Print("NAT_RELATED_ICMP_UNREACHABLE_CONFIRMED")
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			fmt.Print(string(buf[:n]))
			return
		}
		client := http.Client{Timeout: 1200 * time.Millisecond, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
		response, err := client.Get(os.Getenv("ASTER_NAT_ADDRESS"))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 4096))
		if err != nil {
			t.Fatal(err)
		}
		fmt.Print(string(body))
	}
}

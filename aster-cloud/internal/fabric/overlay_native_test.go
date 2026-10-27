package fabric

import (
	"aster/cloud/internal/nodeproto"
	"aster/cloud/internal/overlayproto"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// This gate executes the distribution's real OVS parser/encoder without any
// bridge, system OVSDB, daemon, kernel datapath, physical interface or KVM guest.
// ovs-ofctl 2.17 source: utilities/ovs-ofctl.c ofctl_parse_flows and
// ofctl_meter_mod__. Meter bytes follow include/openflow/openflow-1.3.h.
func nativeOVSBinary(t *testing.T) string {
	t.Helper()
	if os.Getenv("ASTER_NATIVE_OVS_PARSER") != "1" {
		t.Skip("native OVS parser gate is a separate required Ubuntu22/24 CI job")
	}
	if runtime.GOOS != "linux" {
		t.Fatal("native gate requires Linux; no silent skip")
	}
	bin := os.Getenv("ASTER_TEST_OVS_OFCTL")
	if bin == "" {
		bin = Ofctl
	}
	if !filepath.IsAbs(bin) || filepath.Clean(bin) != bin {
		t.Fatal("OVS test binary must be an absolute clean path")
	}
	raw, err := nativeOVSCommand(bin, "--version")
	if err != nil || !versionRE.Match(raw) {
		t.Fatalf("required native OVS missing: %v %s", err, raw)
	}
	t.Log(strings.TrimSpace(string(raw)))
	return bin
}
func nativeOVSCommand(bin string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "LANG=C", "LC_ALL=C"}
	cmd.WaitDelay = time.Second
	raw, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return raw, ctx.Err()
	}
	return raw, err
}
func nativeOverlayPlans(t *testing.T) map[string]overlayPlan {
	t.Helper()
	out := map[string]overlayPlan{}
	for _, name := range []string{"cross_node", "local_router", "remote_router", "max_vni_port"} {
		_, _, c, s := overlayFixture(t)
		port := 1
		if name == "max_vni_port" {
			s.VPCs[0].VNI = 16777215
			port = 32767
		}
		ports := []overlayPort{{Name: TAPName(s.Members[0].InstanceID), OFPort: port, Kind: "member", Identity: s.Members[0].InstanceID}, {Name: overlayTunnelName("node-a", "node-b"), OFPort: 7, Kind: "tunnel", Identity: "node-b"}}
		if name == "local_router" || name == "remote_router" {
			node := "node-a"
			if name == "remote_router" {
				node = "node-b"
			}
			id := strings.Repeat("8", 32)
			g := overlayproto.Gateway{NodeID: node, InstanceID: id, InterfaceID: InterfaceID(id), OwnerRef: s.VPCs[0].OwnerRef, VPCID: s.VPCs[0].ID, IPv4: "10.11.0.1", MAC: nodeproto.NetworkMAC(node, id), AllowedPrefixes: []string{"172.20.0.0/16"}}
			c.Gateways = []overlayproto.Gateway{g}
			s.Gateways = []overlayproto.Gateway{g}
			sha, err := OverlayConfigSHA256(c)
			if err != nil {
				t.Fatal(err)
			}
			s.Profiles[0].ProfileSHA256 = sha
			if node == "node-a" {
				ports = append(ports, overlayPort{Name: TAPName(id), OFPort: 3, Kind: "gateway", Identity: id})
			}
		}
		p, err := compileOverlay(c, s, ports)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out[name] = p
	}
	for _, name := range []string{"internet_local_nat", "internet_remote_nat"} {
		_, _, c, s := internetNATFixture(t)
		g := s.Gateways[0]
		ports := []overlayPort{{Name: TAPName(s.Members[0].InstanceID), OFPort: 1}, {Name: overlayTunnelName("node-a", "node-b"), OFPort: 7}}
		if name == "internet_remote_nat" {
			g.NodeID = "node-b"
			c.Gateways[0], s.Gateways[0] = g, g
			s.NATPolicies[0].NodeID = g.NodeID
			c.NATProfiles = nil
		} else {
			ports = append(ports, overlayPort{Name: TAPName(g.InstanceID), OFPort: 32767})
		}
		sha, err := OverlayConfigSHA256(c)
		if err != nil {
			t.Fatal(err)
		}
		s.Profiles[0].ProfileSHA256 = sha
		p, err := compileOverlay(c, s, ports)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out[name] = p
	}
	single, err := Compile(topologyFixture())
	if err != nil {
		t.Fatal(err)
	}
	out["single_host"] = overlayPlan{Flows: single.Flows, Meters: single.Meters}
	return out
}
func TestNativeOVSParserFlows(t *testing.T) {
	bin := nativeOVSBinary(t)
	for name, plan := range nativeOverlayPlans(t) {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "flows")
			if err := os.WriteFile(path, []byte(strings.Join(plan.Flows, "\n")+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			raw, err := nativeOVSCommand(bin, "-O", "OpenFlow14", "--no-names", "parse-flows", path)
			if err != nil || !strings.Contains(string(raw), "chosen protocol: OXM-OpenFlow14") || strings.Count(string(raw), "OFPT_FLOW_MOD") != len(plan.Flows) {
				t.Fatalf("native parse/encode %d flows failed: %v\n%s", len(plan.Flows), err, raw)
			}
			t.Logf("native parser encoded %d OpenFlow14 flows", len(plan.Flows))
		})
	}
	t.Run("malformed_flow_must_fail", func(t *testing.T) {
		raw, err := nativeOVSCommand(bin, "-O", "OpenFlow14", "parse-flow", "table=0,ip,nw_src=10.0.0.1 actions=aster_invalid_action:1")
		if err == nil || len(raw) == 0 {
			t.Fatal("native parser accepted malformed negative control")
		}
	})
}

// A private Unix OpenFlow peer receives and verifies the actual ovs-ofctl meter
// wire message. Connection/parser/timeout errors are NEVER accepted as success.
// This peer deliberately does not pretend to be a dataplane or enforce packets.
func receiveNativeMeter(listener *net.UnixListener, want Meter) error {
	if err := listener.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	c, err := listener.AcceptUnix()
	if err != nil {
		return err
	}
	defer c.Close()
	if err = c.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	seen := false
	for n := 0; n < 12; n++ {
		h := make([]byte, 8)
		if _, err = io.ReadFull(c, h); err != nil {
			return err
		}
		length := int(binary.BigEndian.Uint16(h[2:4]))
		if h[0] != 5 || length < 8 || length > 65535 {
			return errors.New("invalid OF14 frame")
		}
		body := make([]byte, length-8)
		if _, err = io.ReadFull(c, body); err != nil {
			return err
		}
		reply := func(kind byte, payload []byte) error {
			out := append([]byte{}, h...)
			out[1] = kind
			binary.BigEndian.PutUint16(out[2:4], uint16(8+len(payload)))
			out = append(out, payload...)
			_, e := c.Write(out)
			return e
		}
		switch h[1] {
		case 0:
			if err = reply(0, nil); err != nil {
				return err
			}
		case 2:
			if err = reply(3, body); err != nil {
				return err
			}
		case 5:
			if err = reply(6, make([]byte, 24)); err != nil {
				return err
			}
		case 29:
			if seen || len(body) != 24 || binary.BigEndian.Uint16(body[0:2]) != 0 || binary.BigEndian.Uint16(body[2:4]) != 9 || int(binary.BigEndian.Uint32(body[4:8])) != want.ID || binary.BigEndian.Uint16(body[8:10]) != 1 || binary.BigEndian.Uint16(body[10:12]) != 16 || int(binary.BigEndian.Uint32(body[12:16])) != want.Kbps || binary.BigEndian.Uint32(body[16:20]) != 0 {
				return fmt.Errorf("unexpected encoded meter: %x", body)
			}
			seen = true
		case 20:
			if !seen {
				return errors.New("barrier before expected meter")
			}
			return reply(21, nil)
		default:
			return fmt.Errorf("unexpected OF14 message type %d", h[1])
		}
	}
	return errors.New("meter protocol did not complete")
}
func TestNativeOVSParserMeters(t *testing.T) {
	bin := nativeOVSBinary(t)
	seen := map[Meter]bool{}
	for _, p := range nativeOverlayPlans(t) {
		for _, m := range p.Meters {
			seen[m] = true
		}
	}
	if len(seen) == 0 {
		t.Fatal("fixture has no meters")
	}
	for m := range seen {
		t.Run(fmt.Sprintf("id_%d_rate_%d", m.ID, m.Kbps), func(t *testing.T) {
			dir, err := os.MkdirTemp("/tmp", "aster-ovs-parser-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir)
			sock := filepath.Join(dir, "meter.sock")
			l, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			done := make(chan error, 1)
			go func() { done <- receiveNativeMeter(l, m) }()
			spec := fmt.Sprintf("meter=%d,kbps,stats,bands=type=drop,rate=%d", m.ID, m.Kbps)
			raw, cmdErr := nativeOVSCommand(bin, "-O", "OpenFlow14", "--no-names", "add-meter", "unix:"+sock, spec)
			_ = l.Close()
			peerErr := <-done
			if cmdErr != nil || peerErr != nil {
				t.Fatalf("native meter parser/encoder failed: command=%v peer=%v output=%s", cmdErr, peerErr, raw)
			}
		})
	}
	t.Run("malformed_meter_must_fail_before_connect", func(t *testing.T) {
		socket := filepath.Join(t.TempDir(), "never-created.sock")
		raw, err := nativeOVSCommand(bin, "-O", "OpenFlow14", "add-meter", "unix:"+socket, "meter=2,kbps,stats,bands=type=aster_invalid,rate=100")
		if err == nil || len(raw) == 0 || strings.Contains(string(raw), "connecting to") {
			t.Fatalf("negative meter did not fail in parser: %v %s", err, raw)
		}
	})
}

func TestNativeOverlayParserFixturesCoverGatewayTunnelMeterAndBounds(t *testing.T) {
	plans := nativeOverlayPlans(t)
	if len(plans) != 7 {
		t.Fatal("native fixture coverage changed")
	}
	for _, name := range []string{"local_router", "remote_router"} {
		if !strings.Contains(strings.Join(plans[name].Flows, "\n"), "nw_dst=172.20.0.0/16") {
			t.Fatal("gateway route fixture missing", name)
		}
	}
	for _, name := range []string{"internet_local_nat", "internet_remote_nat"} {
		flows := strings.Join(plans[name].Flows, "\n")
		if !strings.Contains(flows, "priority=190,") || !strings.Contains(flows, "priority=195,") || !strings.Contains(flows, "nw_dst=169.254.0.0/16") {
			t.Fatal("Internet fallback/protected-range parser coverage missing", name)
		}
	}
	if !strings.Contains(strings.Join(plans["cross_node"].Flows, "\n"), "tun_id=") || len(plans["max_vni_port"].Meters) != 2 {
		t.Fatal("native fixture missing tunnel/meters")
	}
}

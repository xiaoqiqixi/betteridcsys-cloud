package fabric

import (
	"aster/cloud/internal/nodeproto"
	"aster/cloud/internal/overlayproto"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type overlayFakeInterface struct {
	port         overlayPort
	kind         string
	ids, options map[string]string
	mtu          int
}
type overlayFake struct {
	foreignTunnel map[string]string
	base          *fakeOVS
	ifaces        map[string]overlayFakeInterface
	config        OverlayConfig
	calls         int
	failAt        int
	badPort       bool
	driftAfter    int
	probes        int
}

func mapOVS(m map[string]string) any {
	kv := [][]string{}
	for k, v := range m {
		kv = append(kv, []string{k, v})
	}
	return []any{"map", kv}
}
func (f *overlayFake) Run(ctx context.Context, binary string, args ...string) ([]byte, error) {
	f.calls++
	if f.failAt == f.calls {
		return nil, ErrUnavailable
	}
	s := strings.Join(args, " ")
	if binary == Vsctl && len(args) == 8 && args[1] == "set" && args[2] == "Interface" {
		i, ok := f.ifaces[args[3]]
		if !ok {
			return nil, ErrUnavailable
		}
		for _, arg := range args[4:] {
			kv := strings.SplitN(arg, "=", 2)
			if len(kv) != 2 || !strings.HasPrefix(kv[0], "external_ids:aster-") {
				return nil, ErrInvalid
			}
			i.ids[strings.TrimPrefix(kv[0], "external_ids:")] = kv[1]
		}
		f.ifaces[args[3]] = i
		return nil, nil
	}
	if binary == Vsctl {
		if strings.Contains(s, "list-ifaces") {
			names := []string{}
			for n := range f.ifaces {
				names = append(names, n)
			}
			return []byte(strings.Join(names, "\n")), nil
		}
		if strings.Contains(s, "--columns=_uuid,name,ofport,type,external_ids,options,mtu") {
			f.probes++
			rows := [][]any{}
			for _, i := range f.ifaces {
				uuid := i.port.UUID
				if f.driftAfter > 0 && f.probes >= f.driftAfter {
					uuid = "99999999-9999-9999-9999-999999999999"
				}
				rows = append(rows, []any{[]any{"uuid", uuid}, i.port.Name, i.port.OFPort, i.kind, mapOVS(i.ids), mapOVS(i.options), i.mtu})
			}
			if f.foreignTunnel != nil {
				rows = append(rows, []any{[]any{"uuid", "66666666-6666-6666-6666-666666666666"}, "foreign-vxlan", 61, "vxlan", mapOVS(map[string]string{}), mapOVS(f.foreignTunnel), 65000})
			}
			return json.Marshal(map[string]any{"headings": []string{"_uuid", "name", "ofport", "type", "external_ids", "options", "mtu"}, "data": rows})
		}
		if strings.Contains(s, "--columns=name,interfaces,tag,trunks,vlan_mode") {
			rows := [][]any{}
			for _, i := range f.ifaces {
				tag := any([]any{"set", []any{}})
				if f.badPort {
					tag = 10
				}
				rows = append(rows, []any{i.port.Name, []any{"uuid", i.port.UUID}, tag, []any{"set", []any{}}, []any{"set", []any{}}})
			}
			return json.Marshal(map[string]any{"headings": []string{"name", "interfaces", "tag", "trunks", "vlan_mode"}, "data": rows})
		}
		if len(args) > 4 && args[1] == "add-port" {
			name := args[3]
			for _, p := range f.config.Peers {
				if overlayTunnelName(f.config.Base.NodeID, p.NodeID) == name {
					f.ifaces[name] = overlayFakeInterface{port: overlayPort{Name: name, UUID: "77777777-7777-7777-7777-777777777777", OFPort: 7, Kind: "tunnel", Identity: p.NodeID}, kind: "vxlan", ids: map[string]string{"aster-node-id": f.config.Base.NodeID, "aster-overlay-peer": p.NodeID, "aster-interface-id": overlayTunnelID(f.config.Base.NodeID, p.NodeID)}, options: overlayTunnelOptions(f.config, p), mtu: 65000}
					return nil, nil
				}
			}
			return nil, ErrInvalid
		}
	}
	return f.base.Run(ctx, binary, args...)
}
func overlayFixture(t *testing.T) (*Executor, *overlayFake, OverlayConfig, overlayproto.Snapshot) {
	t.Helper()
	e, base, _ := fixtureExecutor(t)
	c := OverlayConfig{Schema: 1, Base: e.Config, LocalIPv4: "192.0.2.10", UnderlayMTU: 1550, GuestMTU: 1500, UnderlayTrustedAck: true, TrustReference: "isolated-lab-ticket-1", ProtectedCIDRs: []string{"192.0.2.0/24"}, Peers: []OverlayPeer{{NodeID: "node-b", IPv4: "192.0.2.11"}}, Gateways: []overlayproto.Gateway{}, GuestNetworks: []OverlayGuestNetwork{}}
	sha, err := OverlayConfigSHA256(c)
	if err != nil {
		t.Fatal(err)
	}
	owner, vpc := strings.Repeat("1", 32), strings.Repeat("2", 32)
	members := []overlayproto.Member{}
	for j, node := range []string{"node-a", "node-b"} {
		id := strings.Repeat(fmt.Sprintf("%d", j+3), 32)
		members = append(members, overlayproto.Member{NodeID: node, InstanceID: id, InterfaceID: InterfaceID(id), OwnerRef: owner, VPCID: vpc, LocalVPCID: vpc, LeaseID: strings.Repeat(fmt.Sprintf("%d", j+5), 32), PoolID: strings.Repeat("7", 32), NetworkSHA256: strings.Repeat("a", 64), IPv4: fmt.Sprintf("10.11.0.%d", j+2), MAC: nodeproto.NetworkMAC(node, id), InboundMbps: 100, OutboundMbps: 200, Enabled: true})
	}
	s := overlayproto.Snapshot{Protocol: overlayproto.Protocol, ClusterID: "cluster-a", Epoch: 1, Profiles: []overlayproto.ProfilePin{{NodeID: "node-a", ProfileID: "fabric-a", ProfileSHA256: sha}, {NodeID: "node-b", ProfileID: "fabric-b", ProfileSHA256: strings.Repeat("b", 64)}}, VPCs: []overlayproto.VPC{{ID: vpc, OwnerRef: owner, CIDR: "10.11.0.0/24", VNI: 5001}}, Members: members, Gateways: []overlayproto.Gateway{}}
	f := &overlayFake{base: base, config: c, ifaces: map[string]overlayFakeInterface{}}
	m := members[0]
	name := TAPName(m.InstanceID)
	f.ifaces[name] = overlayFakeInterface{port: overlayPort{Name: name, UUID: "33333333-3333-3333-3333-333333333333", OFPort: 1, Kind: "member", Identity: m.InstanceID}, ids: map[string]string{"aster-node-id": m.NodeID, "aster-instance": m.InstanceID, "aster-owner": m.OwnerRef, "aster-vpc": m.LocalVPCID, "iface-id": m.InterfaceID, "attached-mac": m.MAC, "vm-id": DomainID(m.InstanceID), "iface-status": "active"}, options: map[string]string{}, mtu: 1500}
	e.Runner = f
	e.overlayUnderlay = func(OverlayConfig) error { return nil }
	return e, f, c, s
}
func overlayTask(t *testing.T, s overlayproto.Snapshot, phase string) overlayproto.Task {
	t.Helper()
	s, sha, err := overlayproto.CanonicalSnapshot(s)
	if err != nil {
		t.Fatal(err)
	}
	return overlayproto.Task{Protocol: overlayproto.Protocol, OperationID: overlayproto.Digest([]byte(fmt.Sprintf("%s:%d:%s", s.ClusterID, s.Epoch, phase)))[:32], NodeID: "node-a", Phase: phase, SnapshotSHA256: sha, Snapshot: s}
}
func overlayRun(t *testing.T, e *Executor, c OverlayConfig, s overlayproto.Snapshot) {
	t.Helper()
	ctx := context.Background()
	nop := func(context.Context) error { return nil }
	if r, err := e.PrepareOverlay(ctx, c, overlayTask(t, s, "prepare"), nop); err != nil || r.Status != "succeeded" {
		t.Fatalf("prepare %+v %v", r, err)
	}
	if r, err := e.ProgramOverlay(ctx, c, overlayTask(t, s, "program")); err != nil || r.Status != "succeeded" {
		t.Fatalf("program %+v %v", r, err)
	}
	if r, err := e.ReleaseOverlay(ctx, c, overlayTask(t, s, "release"), nop); err != nil || r.Status != "succeeded" {
		t.Fatalf("release %+v %v", r, err)
	}
}
func TestOverlayThreePhaseReplayAndReadback(t *testing.T) {
	e, f, c, s := overlayFixture(t)
	ctx := context.Background()
	count := 0
	cb := func(context.Context) error { count++; return nil }
	prepare := overlayTask(t, s, "prepare")
	if _, err := e.ProgramOverlay(ctx, c, overlayTask(t, s, "program")); err == nil {
		t.Fatal("program before prepare")
	}
	if _, err := e.PrepareOverlay(ctx, c, prepare, cb); err != nil {
		t.Fatal(err)
	}
	if count != 1 || f.base.flows != strings.Join(isolationFlows(), "\n")+"\n" {
		t.Fatal("prepare not held isolated")
	}
	if _, err := e.ReleaseOverlay(ctx, c, overlayTask(t, s, "release"), cb); err == nil {
		t.Fatal("release before program")
	}
	if _, err := e.ProgramOverlay(ctx, c, overlayTask(t, s, "program")); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatal("program released callback")
	}
	if _, err := e.ReleaseOverlay(ctx, c, overlayTask(t, s, "release"), cb); err != nil {
		t.Fatal(err)
	}
	calls := f.calls
	if _, err := e.PrepareOverlay(ctx, c, prepare, cb); err != nil || count != 2 || f.calls != calls {
		t.Fatal("replay mutated")
	}
	_, sha, _ := prepare.BytesAndDigest()
	if r, err := e.LookupOverlay(ctx, c, prepare.OperationID, sha); err != nil || !r.Matches(prepare, sha) {
		t.Fatal(r, err)
	}
	if _, err := e.CheckOverlay(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := legacyOverlayGuard(c.Base); err == nil {
		t.Fatal("legacy overwrite allowed")
	}
	before := f.base.flows
	f.base.flows = "drift"
	if _, err := e.CheckOverlay(ctx, c); err == nil || f.base.flows != "drift" {
		t.Fatal("check repaired drift")
	}
	f.base.flows = before
}
func TestOverlayCompilerExactTunnelAndNoTransit(t *testing.T) {
	e, f, c, s := overlayFixture(t)
	overlayRun(t, e, c, s)
	flows := f.base.flows
	for _, need := range []string{"tun_src=192.0.2.11,tun_dst=192.0.2.10,tun_id=0x1389", "metadata=0x1389/0x1ffffff", "set_tunnel:0x1389,output:7", "write_metadata:0x1001389/0x1ffffff", "nw_src=" + s.Members[1].IPv4, "arp_sha=" + s.Members[1].MAC} {
		if !strings.Contains(flows, need) {
			t.Fatalf("missing %s", need)
		}
	}
	for _, bad := range []string{"NORMAL", "FLOOD", "LOCAL", "remote_ip=flow", "metadata=0x1001389/0x1ffffff,ip,nw_dst=" + s.Members[1].IPv4} {
		if strings.Contains(flows, bad) {
			t.Fatalf("unsafe %s", bad)
		}
	}
}
func TestOverlayInputApprovalRejects(t *testing.T) {
	for _, name := range []string{"underlay-untrusted", "mtu", "unknown-peer", "pin", "route-protected", "duplicate-tap", "null-guests"} {
		t.Run(name, func(t *testing.T) {
			_, _, c, s := overlayFixture(t)
			switch name {
			case "underlay-untrusted":
				c.UnderlayTrustedAck = false
			case "mtu":
				c.GuestMTU = c.UnderlayMTU
			case "unknown-peer":
				c.Peers = []OverlayPeer{}
			case "pin":
				s.Profiles[0].ProfileSHA256 = strings.Repeat("f", 64)
			case "route-protected":
				c.Gateways = []overlayproto.Gateway{{NodeID: "node-a", InstanceID: strings.Repeat("8", 32), InterfaceID: InterfaceID(strings.Repeat("8", 32)), OwnerRef: s.VPCs[0].OwnerRef, VPCID: s.VPCs[0].ID, IPv4: "10.11.0.1", MAC: "52:54:00:00:00:01", AllowedPrefixes: []string{"192.0.2.0/24"}}}
			case "duplicate-tap":
				s.Members[1].NodeID = "node-a"
				s.Members[1].InstanceID = s.Members[0].InstanceID[:12] + strings.Repeat("9", 20)
				s.Members[1].InterfaceID = InterfaceID(s.Members[1].InstanceID)
				s.Members[1].MAC = nodeproto.NetworkMAC("node-a", s.Members[1].InstanceID)
			case "null-guests":
				c.GuestNetworks = nil
			}
			if _, _, _, err := validateOverlayApproval(c, s); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}
func TestOverlayRejectsIdentityAndMTUDrift(t *testing.T) {
	for _, which := range []string{"mtu", "vlan", "underlay", "type", "mac", "unknown"} {
		t.Run(which, func(t *testing.T) {
			e, f, c, s := overlayFixture(t)
			name := TAPName(s.Members[0].InstanceID)
			i := f.ifaces[name]
			switch which {
			case "mtu":
				i.mtu = 1400
			case "vlan":
				f.badPort = true
			case "underlay":
				e.overlayUnderlay = func(OverlayConfig) error { return ErrUnavailable }
			case "type":
				i.kind = "internal"
			case "mac":
				i.ids["attached-mac"] = "52:54:00:00:00:01"
			case "unknown":
				f.ifaces["foreign0"] = i
			}
			f.ifaces[name] = i
			calls := 0
			r, err := e.PrepareOverlay(context.Background(), c, overlayTask(t, s, "prepare"), func(context.Context) error { calls++; return nil })
			if err == nil || r.Status != "uncertain" || calls != 0 {
				t.Fatal(r, err, calls)
			}
		})
	}
}
func TestOverlayOperationStoreHasNo64Limit(t *testing.T) {
	e, f, c, s := overlayFixture(t)
	first := overlayTask(t, s, "prepare")
	for epoch := int64(1); epoch <= 70; epoch++ {
		s.Epoch = epoch
		overlayRun(t, e, c, s)
		_, s.PreviousSHA256, _ = overlayproto.CanonicalSnapshot(s)
	}
	calls := f.calls
	_, sha, _ := first.BytesAndDigest()
	if r, err := e.LookupOverlay(context.Background(), c, first.OperationID, sha); err != nil || r.Status != "succeeded" {
		t.Fatal(r, err)
	}
	if _, err := e.PrepareOverlay(context.Background(), c, first, func(context.Context) error { t.Fatal("replayed old callback"); return nil }); err != nil || f.calls != calls {
		t.Fatal("old replay failed", err)
	}
	files, err := filepath.Glob(filepath.Join(c.Base.StateDirectory, "overlay-op-*.json"))
	if err != nil || len(files) != 210 {
		t.Fatal(len(files), err)
	}
}
func TestOverlayStrictConfigRejectsDuplicateNested(t *testing.T) {
	_, _, c, _ := overlayFixture(t)
	raw, _ := json.Marshal(c)
	if _, err := DecodeOverlayConfig(raw); err != nil {
		t.Fatal(err)
	}
	bad := strings.Replace(string(raw), `"node_id":"node-a"`, `"node_id":"node-a","node_id":"node-a"`, 1)
	if _, err := DecodeOverlayConfig([]byte(bad)); err == nil {
		t.Fatal("duplicate accepted")
	}
}
func TestOverlayStorageFailureNeverReplaysCallback(t *testing.T) {
	for _, phase := range []string{"prepare", "program", "release"} {
		t.Run(phase, func(t *testing.T) {
			e, _, c, s := overlayFixture(t)
			ctx := context.Background()
			nop := func(context.Context) error { return nil }
			if phase != "prepare" {
				if _, err := e.PrepareOverlay(ctx, c, overlayTask(t, s, "prepare"), nop); err != nil {
					t.Fatal(err)
				}
			}
			if phase == "release" {
				if _, err := e.ProgramOverlay(ctx, c, overlayTask(t, s, "program")); err != nil {
					t.Fatal(err)
				}
			}
			task := overlayTask(t, s, phase)
			e.fault = func(stage string) error {
				if stage == overlayOpName(task.OperationID)+":after_dir_sync" {
					return ErrUnavailable
				}
				return nil
			}
			calls := 0
			run := func() (overlayproto.Receipt, error) {
				switch phase {
				case "prepare":
					return e.PrepareOverlay(ctx, c, task, func(context.Context) error { calls++; return nil })
				case "program":
					return e.ProgramOverlay(ctx, c, task)
				default:
					return e.ReleaseOverlay(ctx, c, task, func(context.Context) error { calls++; return nil })
				}
			}
			if r, err := run(); err == nil || r.Status != "uncertain" || calls != 0 {
				t.Fatal(r, err, calls)
			}
			e.fault = nil
			if _, err := run(); err == nil || calls != 0 {
				t.Fatal("uncertain operation replayed", err, calls)
			}
			if _, err := os.Stat(filepath.Join(c.Base.StateDirectory, overlayOpName(task.OperationID))); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestOverlayLocalLifecycleRetainsFrozenSnapshot(t *testing.T) {
	e, f, c, s := overlayFixture(t)
	overlayRun(t, e, c, s)
	m := s.Members[0]
	port := f.ifaces[TAPName(m.InstanceID)]
	in := ActivationIntent{OperationID: strings.Repeat("9", 32), RequestSHA256: strings.Repeat("9", 64), InstanceID: m.InstanceID, VPCs: []VPC{{ID: m.LocalVPCID, OwnerRef: m.OwnerRef, CIDR: s.VPCs[0].CIDR, VLANID: 10}}, Ports: []PortIntent{{InstanceID: m.InstanceID, InterfaceID: m.InterfaceID, OwnerRef: m.OwnerRef, VPCID: m.LocalVPCID, IPv4: m.IPv4, MAC: m.MAC, InboundMbps: m.InboundMbps, OutboundMbps: m.OutboundMbps, Enabled: false}}}
	ctx := context.Background()
	stops := 0
	if _, err := e.OverlayDeactivate(ctx, c, in, m.NetworkSHA256, func(context.Context) error { stops++; delete(f.ifaces, port.port.Name); return nil }); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(f.base.flows, "output:1\n") {
		t.Fatal("stopped local still allowed")
	}
	if _, err := e.OverlayDeactivate(ctx, c, in, m.NetworkSHA256, func(context.Context) error { stops++; return nil }); err != nil || stops != 1 {
		t.Fatal("stop replay", err, stops)
	}
	in.OperationID = strings.Repeat("a", 32)
	in.RequestSHA256 = strings.Repeat("a", 64)
	in.Ports[0].Enabled = true
	if _, err := e.OverlayCheck(ctx, c, in, m.NetworkSHA256); err == nil {
		t.Fatal("absent enabled member proved")
	}
	start, releases := 0, 0
	if _, err := e.OverlayActivate(ctx, c, in, m.NetworkSHA256, func(context.Context) error { start++; f.ifaces[port.port.Name] = port; return nil }, func(context.Context) error { releases++; return nil }); err != nil {
		t.Fatal(err)
	}
	if start != 1 || releases != 1 {
		t.Fatal(start, releases)
	}
	if _, err := e.OverlayCheck(ctx, c, in, m.NetworkSHA256); err != nil {
		t.Fatal(err)
	}
	got, state, err := ReadOverlaySnapshot(c)
	_, wantSHA, _ := overlayproto.CanonicalSnapshot(s)
	_, gotSHA, _ := overlayproto.CanonicalSnapshot(got)
	if err != nil || state != "applied" || wantSHA != gotSHA {
		t.Fatal("snapshot rewritten", state, err)
	}
	in.Ports[0].Enabled = false
	if _, err := e.OverlayCheck(ctx, c, in, m.NetworkSHA256); err == nil {
		t.Fatal("disabled target accepted")
	}
}
func TestOverlayGatewayRoutingIsExplicitNotTransit(t *testing.T) {
	e, f, c, s := overlayFixture(t)
	id := strings.Repeat("8", 32)
	g := overlayproto.Gateway{NodeID: "node-a", InstanceID: id, InterfaceID: InterfaceID(id), OwnerRef: s.VPCs[0].OwnerRef, VPCID: s.VPCs[0].ID, IPv4: "10.11.0.1", MAC: "52:54:00:00:00:01", AllowedPrefixes: []string{"203.0.113.0/24"}}
	c.Gateways = []overlayproto.Gateway{g}
	c.GuestNetworks = []OverlayGuestNetwork{{LocalVPCID: s.Members[0].LocalVPCID, OwnerRef: g.OwnerRef, CIDR: s.VPCs[0].CIDR, GatewayIPv4: g.IPv4, AllowedPrefixes: g.AllowedPrefixes}}
	sha, err := OverlayConfigSHA256(c)
	if err != nil {
		t.Fatal(err)
	}
	s.Profiles[0].ProfileSHA256 = sha
	s.Gateways = c.Gateways
	f.config = c
	n := TAPName(id)
	f.ifaces[n] = overlayFakeInterface{port: overlayPort{Name: n, UUID: "88888888-8888-8888-8888-888888888888", OFPort: 8, Kind: "gateway", Identity: id}, ids: map[string]string{"aster-node-id": "node-a", "aster-owner": g.OwnerRef, "aster-gateway-vpc": g.VPCID, "iface-id": g.InterfaceID, "attached-mac": g.MAC, "vm-id": DomainID(g.InstanceID), "iface-status": "active"}, options: map[string]string{}, mtu: c.GuestMTU}
	overlayRun(t, e, c, s)
	for _, need := range []string{"nw_src=203.0.113.0/24", "nw_dst=203.0.113.0/24,dl_dst=" + g.MAC + " actions=output:8", "arp_sha=" + g.MAC + ",arp_spa=" + g.IPv4, "metadata=0x1389/0x1ffffff,ip,nw_dst=" + s.Members[1].IPv4} {
		if !strings.Contains(f.base.flows, need) {
			t.Fatalf("missing gateway rule %s", need)
		}
	}
	for _, bad := range []string{"nw_dst=0.0.0.0/0", "NORMAL", "nw_dst=192.0.2.0/24", "nw_src=10.11.0.0/24"} {
		if strings.Contains(f.base.flows, bad) {
			t.Fatal("gateway leak", bad)
		}
	}
}
func TestOverlayRecoveryPinsLaggingHeadsAndPreservesUnknown(t *testing.T) {
	e, f, c, s := overlayFixture(t)
	ctx := context.Background()
	p := overlayTask(t, s, "prepare")
	if _, err := e.PrepareOverlay(ctx, c, p, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	program := overlayTask(t, s, "program")
	f.failAt = f.calls + 1
	old, err := e.ProgramOverlay(ctx, c, program)
	if err == nil || old.Status != "uncertain" {
		t.Fatal(old, err)
	}
	head, err := ReadOverlayHead(c)
	if err != nil {
		t.Fatal(err)
	}
	oldS := s
	_, oldSHA, _ := overlayproto.CanonicalSnapshot(oldS)
	s.Epoch = 3
	s.PreviousSHA256 = strings.Repeat("f", 64)
	rec := &overlayproto.Recovery{Epoch: 2, SnapshotSHA256: s.PreviousSHA256, Heads: []overlayproto.Head{head, {NodeID: "node-b", ClusterID: s.ClusterID, Epoch: 2, SnapshotSHA256: s.PreviousSHA256}}}
	f.failAt = 0
	calls := 0
	for _, phase := range []string{"prepare", "program", "release"} {
		task := overlayTask(t, s, phase)
		task.Recovery = rec
		var err error
		switch phase {
		case "prepare":
			_, err = e.PrepareOverlay(ctx, c, task, func(context.Context) error { calls++; return nil })
		case "program":
			_, err = e.ProgramOverlay(ctx, c, task)
		case "release":
			_, err = e.ReleaseOverlay(ctx, c, task, func(context.Context) error { calls++; return nil })
		}
		if err != nil {
			t.Fatalf("recovery %s: %v", phase, err)
		}
	}
	if calls != 2 {
		t.Fatal(calls)
	}
	_, requestSHA, _ := program.BytesAndDigest()
	got, err := e.LookupOverlay(ctx, c, program.OperationID, requestSHA)
	if err == nil || got != old || got.SnapshotSHA256 != oldSHA {
		t.Fatal("original uncertainty overwritten", got, err)
	}
}
func TestOverlayOwnerLossCannotBecomeFreshOrLegacy(t *testing.T) {
	e, _, c, s := overlayFixture(t)
	overlayRun(t, e, c, s)
	if err := os.Remove(filepath.Join(c.Base.StateDirectory, "overlay.owner")); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadOverlayHead(c); err == nil {
		t.Fatal("lost owner treated empty")
	}
	newTask := overlayTask(t, s, "prepare")
	newTask.OperationID = strings.Repeat("e", 32)
	if _, err := e.PrepareOverlay(context.Background(), c, newTask, func(context.Context) error { t.Fatal("reinitialization callback"); return nil }); err == nil {
		t.Fatal("reinitialized")
	}
	top := topologyFixture()
	if _, err := e.Apply(context.Background(), top, c.Base.Bridge); err == nil {
		t.Fatal("downgraded legacy")
	}
}
func TestOverlayEveryPrepareCommandFailureFencesAndDoesNotRetry(t *testing.T) {
	e, f, c, s := overlayFixture(t)
	if _, err := e.PrepareOverlay(context.Background(), c, overlayTask(t, s, "prepare"), func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	count := f.calls
	for n := 1; n <= count; n++ {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			e, f, c, s := overlayFixture(t)
			f.failAt = n
			calls := 0
			task := overlayTask(t, s, "prepare")
			_, err := e.PrepareOverlay(context.Background(), c, task, func(context.Context) error { calls++; return nil })
			if err == nil {
				t.Fatalf("command %d accepted", n)
			}
			before := calls
			f.failAt = 0
			if _, err := e.PrepareOverlay(context.Background(), c, task, func(context.Context) error { calls++; return nil }); err == nil || calls != before {
				t.Fatal("retry mutated", err, calls)
			}
		})
	}
}
func TestOverlayProgramReleaseCommandFailuresRetainUncertainty(t *testing.T) {
	for _, phase := range []string{"program", "release"} {
		t.Run(phase, func(t *testing.T) {
			prepare := func(t *testing.T) (*Executor, *overlayFake, OverlayConfig, overlayproto.Snapshot) {
				e, f, c, s := overlayFixture(t)
				if _, err := e.PrepareOverlay(context.Background(), c, overlayTask(t, s, "prepare"), func(context.Context) error { return nil }); err != nil {
					t.Fatal(err)
				}
				if phase == "release" {
					if _, err := e.ProgramOverlay(context.Background(), c, overlayTask(t, s, "program")); err != nil {
						t.Fatal(err)
					}
				}
				return e, f, c, s
			}
			run := func(e *Executor, c OverlayConfig, s overlayproto.Snapshot, cb func(context.Context) error) (overlayproto.Receipt, error) {
				if phase == "program" {
					return e.ProgramOverlay(context.Background(), c, overlayTask(t, s, phase))
				}
				return e.ReleaseOverlay(context.Background(), c, overlayTask(t, s, phase), cb)
			}
			e, f, c, s := prepare(t)
			before := f.calls
			if _, err := run(e, c, s, func(context.Context) error { return nil }); err != nil {
				t.Fatal(err)
			}
			total := f.calls - before
			for n := 1; n <= total; n++ {
				t.Run(fmt.Sprint(n), func(t *testing.T) {
					e, f, c, s := prepare(t)
					f.failAt = f.calls + n
					callbacks := 0
					cb := func(context.Context) error { callbacks++; return nil }
					r, err := run(e, c, s, cb)
					if err == nil || r.Status != "uncertain" {
						t.Fatalf("failure %d accepted %+v %v", n, r, err)
					}
					before := callbacks
					f.failAt = 0
					if _, err := run(e, c, s, cb); err == nil || callbacks != before {
						t.Fatal("replayed failed phase", err)
					}
				})
			}
		})
	}
}
func TestOverlayForeignMeterNeverDeleted(t *testing.T) {
	e, f, c, s := overlayFixture(t)
	if _, err := e.PrepareOverlay(context.Background(), c, overlayTask(t, s, "prepare"), func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	f.base.meters[61001] = 1234
	if _, err := e.ProgramOverlay(context.Background(), c, overlayTask(t, s, "program")); err == nil {
		t.Fatal("foreign meter accepted")
	}
	if f.base.meters[61001] != 1234 {
		t.Fatal("foreign meter deleted")
	}
}
func TestOverlayWrongFrozenBindingCannotStartOrCheck(t *testing.T) {
	e, _, c, s := overlayFixture(t)
	overlayRun(t, e, c, s)
	m := s.Members[0]
	in := ActivationIntent{OperationID: strings.Repeat("9", 32), RequestSHA256: strings.Repeat("9", 64), InstanceID: m.InstanceID, VPCs: []VPC{{ID: m.LocalVPCID, OwnerRef: m.OwnerRef, CIDR: s.VPCs[0].CIDR, VLANID: 10}}, Ports: []PortIntent{{InstanceID: m.InstanceID, InterfaceID: m.InterfaceID, OwnerRef: m.OwnerRef, VPCID: m.LocalVPCID, IPv4: m.IPv4, MAC: m.MAC, InboundMbps: m.InboundMbps, OutboundMbps: m.OutboundMbps, Enabled: true}}}
	if _, err := e.OverlayCheck(context.Background(), c, in, strings.Repeat("b", 64)); err == nil {
		t.Fatal("wrong lease binding proved")
	}
	if _, err := e.OverlayActivate(context.Background(), c, in, strings.Repeat("b", 64), func(context.Context) error { t.Fatal("wrong lease started"); return nil }, func(context.Context) error { return nil }); err == nil {
		t.Fatal("wrong lease accepted")
	}
}
func TestOverlayHostWideTunnelTupleCollision(t *testing.T) {
	for _, tc := range []struct {
		name, local, remote, port string
		allow                     bool
	}{{"identical", "192.0.2.10", "192.0.2.11", "4789", false}, {"default-port", "192.0.2.10", "192.0.2.11", "", false}, {"numeric-alias-port", "192.0.2.10", "192.0.2.11", "04789", false}, {"remote-flow", "192.0.2.10", "flow", "4789", false}, {"local-flow", "flow", "192.0.2.11", "4789", false}, {"both-flow", "flow", "flow", "4789", false}, {"wildcard-local", "", "192.0.2.11", "4789", false}, {"zero-local", "0.0.0.0", "192.0.2.11", "4789", false}, {"zero-remote", "192.0.2.10", "0.0.0.0", "4789", false}, {"distinct-local", "192.0.2.20", "192.0.2.11", "4789", true}, {"distinct-remote", "192.0.2.10", "192.0.2.12", "4789", true}, {"distinct-port", "192.0.2.10", "192.0.2.11", "4790", true}} {
		t.Run(tc.name, func(t *testing.T) {
			e, f, c, s := overlayFixture(t)
			f.foreignTunnel = map[string]string{"local_ip": tc.local, "remote_ip": tc.remote, "dst_port": tc.port, "key": "flow"}
			callbacks := 0
			_, err := e.PrepareOverlay(context.Background(), c, overlayTask(t, s, "prepare"), func(context.Context) error { callbacks++; return nil })
			if tc.allow {
				if err != nil || callbacks != 1 {
					t.Fatal("nonoverlapping tuple rejected", err, callbacks)
				}
			} else if err == nil || callbacks != 0 {
				t.Fatal("cross-bridge tunnel collision admitted", err, callbacks)
			}
		})
	}
}
func TestOverlayNewTAPLabelsOnlyExactAuthorizedTarget(t *testing.T) {
	e, f, c, s := overlayFixture(t)
	m := s.Members[0]
	delete(f.ifaces, TAPName(m.InstanceID))
	overlayRun(t, e, c, s)
	in := ActivationIntent{OperationID: strings.Repeat("9", 32), RequestSHA256: strings.Repeat("9", 64), InstanceID: m.InstanceID, VPCs: []VPC{{ID: m.LocalVPCID, OwnerRef: m.OwnerRef, CIDR: s.VPCs[0].CIDR, VLANID: 10}}, Ports: []PortIntent{{InstanceID: m.InstanceID, InterfaceID: m.InterfaceID, OwnerRef: m.OwnerRef, VPCID: m.LocalVPCID, IPv4: m.IPv4, MAC: m.MAC, InboundMbps: m.InboundMbps, OutboundMbps: m.OutboundMbps, Enabled: true}}}
	released := 0
	_, err := e.OverlayActivate(context.Background(), c, in, m.NetworkSHA256, func(context.Context) error {
		f.ifaces[TAPName(m.InstanceID)] = overlayFakeInterface{port: overlayPort{Name: TAPName(m.InstanceID), UUID: "33333333-3333-3333-3333-333333333333", OFPort: 1, Kind: "member", Identity: m.InstanceID}, ids: map[string]string{"iface-id": m.InterfaceID, "attached-mac": m.MAC, "vm-id": DomainID(m.InstanceID), "iface-status": "active", "aster-owner": strings.Repeat("f", 32)}, options: map[string]string{}, mtu: c.GuestMTU}
		return nil
	}, func(context.Context) error { released++; return nil })
	if err == nil || released != 0 {
		t.Fatal("conflicting ownership adopted", err, released)
	}
	if f.ifaces[TAPName(m.InstanceID)].ids["aster-owner"] != strings.Repeat("f", 32) {
		t.Fatal("foreign owner overwritten")
	}
}
func TestOverlayDisabledPeerDoesNotBlockAnotherLifecycleOrGainFlows(t *testing.T) {
	e, f, c, s := overlayFixture(t)
	peer := s.Members[1]
	peer.NodeID = "node-a"
	peer.MAC = nodeproto.NetworkMAC(peer.NodeID, peer.InstanceID)
	peer.Enabled = false
	s.Members[1] = peer
	name := TAPName(peer.InstanceID)
	f.ifaces[name] = overlayFakeInterface{port: overlayPort{Name: name, UUID: "44444444-4444-4444-4444-444444444444", OFPort: 4, Kind: "member", Identity: peer.InstanceID}, ids: map[string]string{"aster-node-id": peer.NodeID, "aster-owner": peer.OwnerRef, "aster-instance": peer.InstanceID, "aster-vpc": peer.LocalVPCID, "iface-id": peer.InterfaceID, "attached-mac": peer.MAC, "vm-id": DomainID(peer.InstanceID), "iface-status": "active"}, options: map[string]string{}, mtu: c.GuestMTU}
	overlayRun(t, e, c, s)
	m := s.Members[0]
	in := ActivationIntent{OperationID: strings.Repeat("9", 32), RequestSHA256: strings.Repeat("9", 64), InstanceID: m.InstanceID, VPCs: []VPC{{ID: m.LocalVPCID, OwnerRef: m.OwnerRef, CIDR: s.VPCs[0].CIDR, VLANID: 10}}, Ports: []PortIntent{}}
	for _, member := range s.Members {
		in.Ports = append(in.Ports, PortIntent{InstanceID: member.InstanceID, InterfaceID: member.InterfaceID, OwnerRef: member.OwnerRef, VPCID: member.LocalVPCID, IPv4: member.IPv4, MAC: member.MAC, InboundMbps: member.InboundMbps, OutboundMbps: member.OutboundMbps, Enabled: member.InstanceID == peer.InstanceID})
	}
	if _, err := e.OverlayDeactivate(context.Background(), c, in, m.NetworkSHA256, func(context.Context) error { delete(f.ifaces, TAPName(m.InstanceID)); return nil }); err != nil {
		t.Fatal("disabled peer blocked unrelated stop", err)
	}
	if strings.Contains(f.base.flows, "output:4") || strings.Contains(f.base.flows, "in_port=4,") {
		t.Fatal("disabled peer got allow rules")
	}
}

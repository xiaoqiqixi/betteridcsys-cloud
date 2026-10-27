package fabric

import (
	"aster/cloud/internal/overlayproto"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type natFake struct {
	*overlayFake
	profile                                  NATProfile
	snapshot                                 overlayproto.Snapshot
	rules                                    []nftObject
	forward                                  string
	callsNAT, failNAT, flushes               int
	badNamespace, badRoute, badPeer, foreign bool
}

func natFakeLink(name, alias, mac string, index, peer int) natLink {
	v := natLink{Name: name, Alias: alias, MAC: mac, Index: index, PeerIndex: peer, MTU: 1500, Flags: []string{"UP"}}
	v.Info.Kind = "veth"
	return v
}
func (f *natFake) Run(ctx context.Context, binary string, args ...string) ([]byte, error) {
	if binary == NATIP {
		p := f.profile
		name := args[len(args)-1]
		v := natFakeLink(TAPName(p.GatewayInstanceID), natAlias(f.config.Base.NodeID, p.ID, "inside-peer"), "02:00:00:00:00:11", 10, 20)
		if name == p.OutsidePeer {
			v = natFakeLink(name, natAlias(f.config.Base.NodeID, p.ID, "outside-peer"), "02:00:00:00:00:12", 11, 21)
		}
		if f.badPeer {
			v.PeerIndex++
		}
		return json.Marshal([]natLink{v})
	}
	return f.overlayFake.Run(ctx, binary, args...)
}
func (f *natFake) RunNamespace(ctx context.Context, p NATProfile, binary string, args ...string) ([]byte, error) {
	f.callsNAT++
	if f.badNamespace || f.callsNAT == f.failNAT || p.NamespaceInode != f.profile.NamespaceInode {
		return nil, ErrUnavailable
	}
	a := strings.Join(args, " ")
	switch binary {
	case NATSysctl:
		if strings.HasPrefix(a, "-w net.ipv4.ip_forward=") {
			f.forward = strings.TrimPrefix(a, "-w net.ipv4.ip_forward=")
			return []byte("net.ipv4.ip_forward = " + f.forward), nil
		}
		if a == "-n net.ipv4.ip_forward" {
			return []byte(f.forward + "\n"), nil
		}
	case NATConntrack:
		if a == "-F" {
			f.flushes++
			return []byte("0 flow entries have been deleted."), nil
		}
	case NATNFT:
		if a == "-j -n list ruleset" {
			v := f.rules
			if v == nil {
				v = []nftObject{}
			}
			if f.foreign {
				v = append(v, nftObject{"table": nftObject{"family": "inet", "name": "foreign"}})
			}
			return json.Marshal(nftObject{"nftables": v})
		}
		if len(args) == 4 && args[1] == "-c" {
			return nil, nil
		}
		if len(args) == 3 && args[1] == "-f" {
			raw, err := os.ReadFile(args[2])
			if err != nil {
				return nil, err
			}
			var doc struct {
				Commands []map[string]nftObject `json:"nftables"`
			}
			if json.Unmarshal(raw, &doc) != nil {
				return nil, ErrInvalid
			}
			f.rules = nil
			for _, o := range doc.Commands {
				if r, ok := o["add"]; ok {
					f.rules = append(f.rules, r)
				} else if _, ok := o["delete"]; !ok {
					return nil, ErrInvalid
				}
			}
			return nil, nil
		}
	case NATIP:
		if a == "-j -d address show" {
			g := f.config.Gateways[0]
			inside := natFakeLink(p.InsideInterface, natAlias(f.config.Base.NodeID, p.ID, "inside"), g.MAC, 20, 10)
			outside := natFakeLink(p.OutsideInterface, natAlias(f.config.Base.NodeID, p.ID, "outside"), "02:00:00:00:00:13", 21, 11)
			type addr = struct {
				Family string `json:"family"`
				Local  string `json:"local"`
				Prefix int    `json:"prefixlen"`
			}
			inside.Addresses = []addr{{"inet", g.IPv4, 24}}
			outside.Addresses = []addr{{"inet", p.PublicIPv4, 24}}
			return json.Marshal([]natLink{{Name: "lo"}, inside, outside})
		}
		if a == "-j -4 route show table all" {
			gw := p.UplinkGatewayIPv4
			if f.badRoute {
				gw = "203.0.113.123"
			}
			public, _ := netip.ParseAddr(p.PublicIPv4)
			connected := netip.PrefixFrom(public, 24).Masked().String()
			return []byte(fmt.Sprintf(`[{"dst":"default","gateway":%q,"dev":%q},{"dst":"10.11.0.0/24","dev":%q},{"dst":%q,"dev":%q}]`, gw, p.OutsideInterface, p.InsideInterface, connected, p.OutsideInterface)), nil
		}
		if a == "-j -4 rule show" {
			return []byte(`[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"},{"priority":32767,"src":"all","table":"default"}]`), nil
		}
	}
	return nil, ErrInvalid
}
func natFixture(t *testing.T) (*Executor, *natFake, OverlayConfig, overlayproto.Snapshot) {
	t.Helper()
	e, base, c, s := overlayFixture(t)
	gid := strings.Repeat("8", 32)
	g := overlayproto.Gateway{NodeID: c.Base.NodeID, InstanceID: gid, InterfaceID: InterfaceID(gid), OwnerRef: s.VPCs[0].OwnerRef, VPCID: s.VPCs[0].ID, IPv4: "10.11.0.1", MAC: "02:00:00:00:00:01", AllowedPrefixes: []string{"198.51.100.0/24"}}
	p := NATProfile{ID: "nat-a", Namespace: "aster-nat-a", NamespaceDevice: 1, NamespaceInode: 123, DedicatedAck: true, VPCID: g.VPCID, VPCCIDR: "10.11.0.0/24", GatewayInstanceID: gid, InsideInterface: "inside", OutsideInterface: "outside", OutsidePeer: "nat-uplink", PublicIPv4: "198.51.100.2", UplinkGatewayIPv4: "198.51.100.1", AllowSNAT: true, AllowedSourceCIDRs: []string{"198.51.100.0/24"}, AllowedPorts: []NATPortRange{{"tcp", 10000, 20000}, {"udp", 10000, 20000}}}
	c.Gateways = []overlayproto.Gateway{g}
	c.NATProfiles = []NATProfile{p}
	sha, err := OverlayConfigSHA256(c)
	if err != nil {
		t.Fatal(err)
	}
	s.Profiles[0].ProfileSHA256 = sha
	s.Gateways = []overlayproto.Gateway{g}
	nsha, _ := NATProfileSHA256(p)
	s.NATPolicies = []overlayproto.NATPolicy{{ID: strings.Repeat("9", 32), NodeID: c.Base.NodeID, VPCID: g.VPCID, GatewayInstanceID: gid, ProfileID: p.ID, ProfileSHA256: nsha, SNATEnabled: true, Forwardings: []overlayproto.NATForwarding{{ID: strings.Repeat("a", 32), Protocol: "tcp", PublicPort: 18080, TargetInstanceID: s.Members[0].InstanceID, TargetPort: 80, SourceCIDR: "198.51.100.0/24"}}}}
	base.config = c
	f := &natFake{overlayFake: base, profile: p, snapshot: s, forward: "1"}
	name := TAPName(gid)
	base.ifaces[name] = overlayFakeInterface{port: overlayPort{Name: name, UUID: "88888888-8888-8888-8888-888888888888", OFPort: 8, Kind: "gateway", Identity: gid}, mtu: 1500, options: map[string]string{}, ids: map[string]string{"aster-node-id": c.Base.NodeID, "aster-owner": g.OwnerRef, "aster-gateway-vpc": g.VPCID, "aster-nat-profile": p.ID, "aster-interface-id": g.InterfaceID, "aster-gateway-mac": g.MAC}}
	e.Runner = f
	return e, f, c, s
}
func TestNATThreePhaseHeldUntilReleaseReplayAndDrift(t *testing.T) {
	e, f, c, s := natFixture(t)
	ctx := context.Background()
	nop := func(context.Context) error { return nil }
	if err := e.probeNAT(ctx, c, s, f.profile); err != nil {
		t.Fatal("direct probe", err)
	}
	if r, err := e.PrepareOverlay(ctx, c, overlayTask(t, s, "prepare"), nop); err != nil || f.forward != "0" {
		t.Logf("receipt %+v", r)
		t.Fatalf("prepare: %v forward=%s", err, f.forward)
	}
	if _, err := e.ProgramOverlay(ctx, c, overlayTask(t, s, "program")); err != nil || f.forward != "0" || f.flushes != 1 {
		t.Fatalf("program: %v forward=%s flush=%d", err, f.forward, f.flushes)
	}
	if _, err := e.ReleaseOverlay(ctx, c, overlayTask(t, s, "release"), nop); err != nil || f.forward != "1" {
		t.Fatalf("release: %v", err)
	}
	calls := f.callsNAT
	if _, err := e.ReleaseOverlay(ctx, c, overlayTask(t, s, "release"), nop); err != nil || f.callsNAT != calls {
		t.Fatal("replay mutated", err)
	}
	if _, err := e.CheckOverlay(ctx, c); err != nil {
		t.Fatal("live check", err)
	}
	f.rules = append(f.rules, nftObject{"rule": nftObject{"family": "inet", "table": natTable, "chain": "forward", "expr": []any{nftObject{"accept": nil}}}})
	if _, err := e.CheckOverlay(ctx, c); err == nil {
		t.Fatal("drift accepted")
	}
}
func TestNATProgramFailureNeverReplaysAndFences(t *testing.T) {
	for _, offset := range []int{1, 4, 8, 10, 12, 16, 19, 22, 24} {
		t.Run(fmt.Sprint(offset), func(t *testing.T) {
			e, f, c, s := natFixture(t)
			ctx := context.Background()
			nop := func(context.Context) error { return nil }
			if _, err := e.PrepareOverlay(ctx, c, overlayTask(t, s, "prepare"), nop); err != nil {
				t.Fatal(err)
			}
			f.failNAT = f.callsNAT + offset
			task := overlayTask(t, s, "program")
			r, err := e.ProgramOverlay(ctx, c, task)
			if err == nil {
				return
			}
			if r.Status != "uncertain" || f.forward != "0" {
				t.Fatal(r, err, f.forward)
			}
			f.failNAT = 0
			calls := f.callsNAT
			if _, err = e.ProgramOverlay(ctx, c, task); err == nil || calls != f.callsNAT {
				t.Fatal("unknown replay reran", err)
			}
		})
	}
}
func TestNATPolicyRemovalProgramsDenyAndClearsConntrack(t *testing.T) {
	e, f, c, s := natFixture(t)
	overlayRun(t, e, c, s)
	_, prev, _ := overlayproto.CanonicalSnapshot(s)
	s.Epoch++
	s.PreviousSHA256 = prev
	s.NATPolicies = nil
	f.snapshot = s
	overlayRun(t, e, c, s)
	if f.flushes != 2 {
		t.Fatal("cached NAT retained")
	}
	raw, _ := json.Marshal(f.rules)
	if strings.Contains(string(raw), `"snat"`) || strings.Contains(string(raw), `"dnat"`) {
		t.Fatal(string(raw))
	}
}
func TestNATApprovalAndOwnershipRejects(t *testing.T) {
	for _, name := range []string{"namespace", "route", "peer", "foreign", "profile", "port", "source", "target", "default", "management"} {
		t.Run(name, func(t *testing.T) {
			e, f, c, s := natFixture(t)
			switch name {
			case "namespace":
				f.badNamespace = true
			case "route":
				f.badRoute = true
			case "peer":
				f.badPeer = true
			case "foreign":
				f.foreign = true
			case "profile":
				s.NATPolicies[0].ProfileSHA256 = strings.Repeat("d", 64)
			case "port":
				s.NATPolicies[0].Forwardings[0].PublicPort = 22
			case "source":
				s.NATPolicies[0].Forwardings[0].SourceCIDR = "203.0.113.0/24"
			case "target":
				s.Members[0].Enabled = false
			case "default":
				s.Gateways[0].AllowedPrefixes = []string{"0.0.0.0/0"}
			case "management":
				c.NATProfiles[0].PublicIPv4 = c.LocalIPv4
			}
			task := overlayproto.Task{Protocol: overlayproto.Protocol, OperationID: strings.Repeat("e", 32), NodeID: c.Base.NodeID, Phase: "prepare", Snapshot: s}
			_, task.SnapshotSHA256, _ = overlayproto.CanonicalSnapshot(s)
			if _, err := e.PrepareOverlay(context.Background(), c, task, func(context.Context) error { return nil }); err == nil {
				t.Fatal("unsafe approval accepted")
			}
			if f.flushes != 0 || len(f.rules) > 0 {
				t.Fatal("foreign data mutated")
			}
		})
	}
}
func TestNATCompilerOnlyExactFrozenMembersAndSelectedRoutes(t *testing.T) {
	_, f, c, s := natFixture(t)
	s.Gateways[0].AllowedPrefixes = []string{"198.51.100.0/25"}
	s.NATPolicies[0].Forwardings[0].SourceCIDR = "198.51.100.0/25"
	objects, err := compileNAT(c, s, f.profile, false)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(objects)
	for _, want := range []string{`"snat"`, `"dnat"`, `"policy":"drop"`, `"len":25`, `"iifname"`, `"status"`, `"198.51.100.2"`} {
		if !strings.Contains(string(raw), want) {
			t.Fatal("missing", want)
		}
	}
	if strings.Contains(string(raw), "masquerade") || strings.Contains(string(raw), "0.0.0.0") {
		t.Fatal("unbounded rule")
	}
}
func TestNATConfigCanonicalAndOldBytes(t *testing.T) {
	_, _, c, s := overlayFixture(t)
	raw, _ := json.Marshal(c)
	if strings.Contains(string(raw), "nat_profiles") {
		t.Fatal("legacy config changed")
	}
	wire, _ := json.Marshal(s)
	if strings.Contains(string(wire), "nat_policies") {
		t.Fatal("legacy snapshot changed")
	}
	_, _, c, _ = natFixture(t)
	raw, _ = json.Marshal(c)
	got, err := DecodeOverlayConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := OverlayConfigSHA256(c)
	b, _ := OverlayConfigSHA256(got)
	if a != b {
		t.Fatal("roundtrip")
	}
	for _, bad := range []string{strings.Replace(string(raw), `"nat_profiles":`, `"NAT_PROFILES":`, 1), strings.Replace(string(raw), `"namespace":`, `"namespace":null,"namespace":`, 1)} {
		if _, err := DecodeOverlayConfig([]byte(bad)); err == nil {
			t.Fatal("accepted malformed NAT")
		}
	}
}

func TestNATRouteAndVPCRemovalRetainsOwnedPortButDeniesFlows(t *testing.T) {
	e, f, c, s := natFixture(t)
	overlayRun(t, e, c, s)
	_, prev, _ := overlayproto.CanonicalSnapshot(s)
	s.Epoch++
	s.PreviousSHA256 = prev
	s.NATPolicies = nil
	s.Gateways = []overlayproto.Gateway{}
	f.snapshot = s
	overlayRun(t, e, c, s)
	if strings.Contains(f.base.flows, "nw_dst=198.51.100.") {
		t.Fatal("removed route still forwards")
	}
	if _, err := e.CheckOverlay(context.Background(), c); err != nil {
		t.Fatal("removed root gateway incorrectly became foreign", err)
	}
	raw, _ := json.Marshal(f.rules)
	if strings.Contains(string(raw), `"snat"`) || strings.Contains(string(raw), `"dnat"`) {
		t.Fatal("removed gateway NAT survived")
	}
}
func TestNATReadbackIgnoresOnlyHandlesAndCrossChainOrdering(t *testing.T) {
	_, f, c, s := natFixture(t)
	objects, err := compileNAT(c, s, f.profile, false)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(nftObject{"nftables": objects})
	want, _, err := normalizeNFT(raw)
	if err != nil {
		t.Fatal(err)
	}
	grouped := []nftObject{objects[0]}
	for _, chain := range []string{"input", "output", "forward", "prerouting", "postrouting"} {
		for _, o := range objects {
			if cc, ok := o["chain"].(map[string]any); ok && cc["name"] == chain {
				grouped = append(grouped, o)
			}
		}
		for _, o := range objects {
			if r, ok := o["rule"].(map[string]any); ok && r["chain"] == chain {
				grouped = append(grouped, o)
			}
		}
	}
	raw, _ = json.Marshal(nftObject{"nftables": grouped})
	got, _, err := normalizeNFT(raw)
	if err != nil || string(got) != string(want) {
		t.Fatal("equivalent nft listing order rejected", err)
	}
	for _, o := range grouped {
		if r, ok := o["chain"].(map[string]any); ok && r["name"] == "forward" {
			r["policy"] = "accept"
		}
	}
	raw, _ = json.Marshal(nftObject{"nftables": grouped})
	got, _, err = normalizeNFT(raw)
	if err == nil && string(got) == string(want) {
		t.Fatal("default permit drift hidden")
	}
}

func natMigrationFixture(t *testing.T, rebuild, ack bool) (*Executor, *natFake, OverlayConfig, overlayproto.Snapshot, overlayproto.Task) {
	t.Helper()
	e, f, c, s := natFixture(t)
	overlayRun(t, e, c, s)
	oldSHA, _ := OverlayConfigSHA256(c)
	_, oldSnapshot, _ := overlayproto.CanonicalSnapshot(s)
	oldNAT, _ := NATProfileSHA256(c.NATProfiles[0])
	p := c.NATProfiles[0]
	p.PreviousProfileSHA256 = oldNAT
	p.AllowedPorts[0].End = 21000
	if rebuild {
		p.NamespaceInode++
		p.RetiredPreviousNamespaceAck = ack
		f.rules = nil
	}
	c.PreviousProfileSHA256 = oldSHA
	c.NATProfiles = []NATProfile{p}
	sha, err := OverlayConfigSHA256(c)
	if err != nil {
		t.Fatal(err)
	}
	s.Epoch++
	s.PreviousSHA256 = oldSnapshot
	s.Profiles[0].ProfileSHA256 = sha
	s.NATPolicies[0].ProfileSHA256, _ = NATProfileSHA256(p)
	task := overlayTask(t, s, "prepare")
	task.Recovery = &overlayproto.Recovery{Epoch: s.Epoch - 1, SnapshotSHA256: oldSnapshot, Heads: []overlayproto.Head{{NodeID: c.Base.NodeID, ClusterID: s.ClusterID, Epoch: s.Epoch - 1, SnapshotSHA256: oldSnapshot}, {NodeID: "node-b", ClusterID: s.ClusterID, Epoch: s.Epoch - 1, SnapshotSHA256: oldSnapshot}}}
	f.config = c
	f.profile = p
	f.snapshot = s
	return e, f, c, s, task
}
func TestNATOwnerMigrationAndRebuiltNamespaceRecovery(t *testing.T) {
	for _, name := range []string{"same-namespace", "rebuilt-ack", "rebuilt-no-ack", "wrong-old-pin", "foreign-new-table", "changed-namespace-name"} {
		t.Run(name, func(t *testing.T) {
			rebuild := strings.HasPrefix(name, "rebuilt") || name == "foreign-new-table"
			e, f, c, s, task := natMigrationFixture(t, rebuild, name != "rebuilt-no-ack")
			switch name {
			case "wrong-old-pin":
				c.NATProfiles[0].PreviousProfileSHA256 = strings.Repeat("d", 64)
			case "foreign-new-table":
				f.rules = []nftObject{{"table": nftObject{"family": "inet", "name": natTable}}}
			case "changed-namespace-name":
				c.NATProfiles[0].Namespace = "aster-new-namespace"
			}
			if name == "wrong-old-pin" || name == "changed-namespace-name" {
				sha, _ := OverlayConfigSHA256(c)
				s.Profiles[0].ProfileSHA256 = sha
				s.NATPolicies[0].ProfileSHA256, _ = NATProfileSHA256(c.NATProfiles[0])
				task.Snapshot, task.SnapshotSHA256, _ = overlayproto.CanonicalSnapshot(s)
				f.config = c
				f.profile = c.NATProfiles[0]
			}
			r, err := e.PrepareOverlay(context.Background(), c, task, func(context.Context) error { return nil })
			success := name == "same-namespace" || name == "rebuilt-ack"
			if !success {
				if err == nil || f.forward != "0" {
					t.Fatal("unsafe migration accepted/not isolated", r, err)
				}
				return
			}
			if err != nil {
				t.Fatal(r, err)
			}
			for _, phase := range []string{"program", "release"} {
				next := overlayTask(t, s, phase)
				next.Recovery = task.Recovery
				if phase == "program" {
					_, err = e.ProgramOverlay(context.Background(), c, next)
				} else {
					_, err = e.ReleaseOverlay(context.Background(), c, next, func(context.Context) error { return nil })
				}
				if err != nil {
					t.Fatal(phase, err)
				}
			}
			if _, err = e.CheckOverlay(context.Background(), c); err != nil {
				t.Fatal("new NAT owner not usable", err)
			}
			if f.forward != "1" {
				t.Fatal("successful NAT recovery not enabled")
			}
		})
	}
}
func TestNATOwnerTombstoneRejectsRootDeletionOrMissingOwner(t *testing.T) {
	for _, missingOwner := range []bool{false, true} {
		t.Run(fmt.Sprint(missingOwner), func(t *testing.T) {
			e, _, c, s := natFixture(t)
			overlayRun(t, e, c, s)
			oldSHA, _ := OverlayConfigSHA256(c)
			_, snapshotSHA, _ := overlayproto.CanonicalSnapshot(s)
			if missingOwner {
				if err := os.Remove(filepath.Join(c.Base.StateDirectory, natOwnerName(c.NATProfiles[0]))); err != nil {
					t.Fatal(err)
				}
			} else {
				c.PreviousProfileSHA256 = oldSHA
				c.NATProfiles = nil
				s.NATPolicies = nil
				sha, _ := OverlayConfigSHA256(c)
				s.Profiles[0].ProfileSHA256 = sha
			}
			s.Epoch++
			s.PreviousSHA256 = snapshotSHA
			task := overlayTask(t, s, "prepare")
			task.Recovery = &overlayproto.Recovery{Epoch: 1, SnapshotSHA256: snapshotSHA, Heads: []overlayproto.Head{{NodeID: c.Base.NodeID, ClusterID: s.ClusterID, Epoch: 1, SnapshotSHA256: snapshotSHA}, {NodeID: "node-b", ClusterID: s.ClusterID, Epoch: 1, SnapshotSHA256: snapshotSHA}}}
			if _, err := e.PrepareOverlay(context.Background(), c, task, func(context.Context) error { return nil }); err == nil {
				t.Fatal("persistent NAT owner was silently forgotten")
			}
		})
	}
}
func TestNATOwnerMigrationDurableFailuresStayUnknown(t *testing.T) {
	for _, stage := range []string{"before_write", "before_sync", "before_rename", "after_rename", "after_dir_sync"} {
		for _, target := range []string{"nat-profile-migration-", "nat-owner-"} {
			t.Run(stage+target, func(t *testing.T) {
				e, f, c, _, task := natMigrationFixture(t, false, false)
				fired := false
				e.fault = func(event string) error {
					if !fired && strings.HasPrefix(event, target) && strings.HasSuffix(event, ":"+stage) {
						fired = true
						return ErrUnavailable
					}
					return nil
				}
				r, err := e.PrepareOverlay(context.Background(), c, task, func(context.Context) error { return nil })
				if !fired || err == nil || r.Status != "uncertain" || f.forward != "0" {
					t.Fatal("owner failure fabricated success", fired, r, err)
				}
				e.fault = nil
				calls := f.callsNAT
				if _, err = e.PrepareOverlay(context.Background(), c, task, func(context.Context) error { return nil }); err == nil || f.callsNAT != calls {
					t.Fatal("unknown owner migration repeated effects")
				}
			})
		}
	}
}

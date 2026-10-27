package fabric

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func topologyFixture() Topology {
	owner := strings.Repeat("1", 32)
	vpc := strings.Repeat("2", 32)
	instance := strings.Repeat("3", 32)
	return Topology{Schema: 1, NodeID: "node-a", Revision: 1, VPCs: []VPC{{vpc, owner, "10.11.0.0/24", 10}}, Ports: []Port{{instance, InterfaceID(instance), owner, vpc, "10.11.0.2", "52:54:00:01:02:03", 1, 100, 200}}}
}

type command struct {
	binary string
	args   []string
}
type fakeOVS struct {
	mu          sync.Mutex
	calls       []command
	topology    Topology
	names       map[string]string
	externalIDs map[string]map[string]string
	failAt      int
	driftAt     int
	probes      int
	foreign     bool
	controller  bool
	physical    bool
	flows       string
	meters      map[int]int
}

func (f *fakeOVS) name(p Port) string {
	if name, ok := f.names[p.InstanceID]; ok {
		return name
	}
	return "vnet" + strconv.Itoa(p.OFPort)
}

func (f *fakeOVS) Run(ctx context.Context, binary string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, command{binary, append([]string{}, args...)})
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if f.failAt == len(f.calls) {
		return nil, errors.New("private command/path failure")
	}
	s := strings.Join(args, " ")
	if binary == Vsctl {
		if len(args) == 8 && args[0] == "--timeout=3" && args[1] == "set" && args[2] == "Interface" {
			for _, p := range f.topology.Ports {
				if f.name(p) == args[3] {
					ids := f.externalIDs[p.InstanceID]
					if ids == nil {
						return nil, ErrInvalid
					}
					for _, arg := range args[4:] {
						kv := strings.SplitN(arg, "=", 2)
						if len(kv) != 2 || !strings.HasPrefix(kv[0], "external_ids:aster-") {
							return nil, ErrInvalid
						}
						ids[strings.TrimPrefix(kv[0], "external_ids:")] = kv[1]
					}
					return nil, nil
				}
			}
			return nil, ErrInvalid
		}
		if strings.Contains(s, "br-exists") {
			return nil, nil
		}
		if strings.Contains(s, "list Bridge") {
			controller := []any{"set", []any{}}
			if f.controller {
				controller = []any{"set", []any{[]any{"uuid", "foreign-controller"}}}
			}
			return json.Marshal(map[string]any{"headings": []string{"name", "controller", "fail_mode", "external_ids", "protocols"}, "data": [][]any{{"aster-vpc", controller, "secure", []any{"map", [][]string{{"aster-node-id", "node-a"}, {"aster-dedicated", "true"}}}, []any{"set", []string{"OpenFlow13", "OpenFlow14"}}}}})
		}
		if strings.Contains(s, "list-ifaces") {
			names := []string{}
			for _, p := range f.topology.Ports {
				names = append(names, f.name(p))
			}
			return []byte(strings.Join(names, "\n")), nil
		}
		if strings.Contains(s, "list Interface") {
			f.probes++
			data := [][]any{}
			for _, p := range f.topology.Ports {
				if f.driftAt > 0 && f.probes >= f.driftAt {
					p.InstanceID = strings.Repeat("8", 32)
					p.InterfaceID = InterfaceID(p.InstanceID)
				}
				ids := map[string]string{"aster-node-id": "node-a", "iface-id": p.InterfaceID, "aster-owner": p.OwnerRef, "aster-instance": p.InstanceID, "aster-vpc": p.VPCID}
				if custom, ok := f.externalIDs[p.InstanceID]; ok {
					ids = custom
				}
				items := [][]string{}
				for k, v := range ids {
					items = append(items, []string{k, v})
				}
				sort.Slice(items, func(i, j int) bool { return items[i][0] < items[j][0] })
				data = append(data, []any{f.name(p), p.OFPort, "", []any{"map", items}})
			}
			return json.Marshal(map[string]any{"headings": []string{"name", "ofport", "type", "external_ids"}, "data": data})
		}
	}
	if binary != Ofctl {
		return nil, errors.New("unapproved binary")
	}
	if s == "--version" {
		return []byte("ovs-ofctl (Open vSwitch) 2.17.9\n"), nil
	}
	if len(args) < 4 || args[0] != "-O" || args[1] != "OpenFlow14" || args[2] != "--no-names" {
		return nil, errors.New("missing bundle-capable protocol")
	}
	args = args[3:]
	if args[0] == "--read-only" {
		args = args[1:]
		if args[0] != "dump-flows" && args[0] != "dump-meters" && args[0] != "diff-flows" {
			return nil, errors.New("mutation on readonly connection")
		}
	}
	if args[0] == "--bundle" {
		if args[1] != "replace-flows" || args[2] != "aster-vpc" {
			return nil, ErrInvalid
		}
		raw, e := os.ReadFile(args[3])
		if e != nil {
			return nil, e
		}
		f.flows = string(raw)
		return nil, nil
	}
	switch args[0] {
	case "dump-flows":
		if f.foreign {
			return []byte("OFPST_FLOW reply (OF1.4):\n cookie=0x0,table=0,priority=0 actions=NORMAL\n"), nil
		}
		return []byte("OFPST_FLOW reply (OF1.4):\n" + f.flows), nil
	case "dump-meters":
		out := "OFPST_METER_CONFIG reply (OF1.4):\n"
		ids := []int{}
		for id := range f.meters {
			ids = append(ids, id)
		}
		sort.Ints(ids)
		for _, id := range ids {
			out += fmt.Sprintf("meter=%d kbps stats bands=\n type=drop rate=%d\n", id, f.meters[id])
		}
		return []byte(out), nil
	case "del-meters":
		f.meters = map[int]int{}
		return nil, nil
	case "add-meter":
		var id, rate int
		for _, part := range strings.Split(args[2], ",") {
			if strings.HasPrefix(part, "meter=") {
				id, _ = strconv.Atoi(strings.TrimPrefix(part, "meter="))
			}
			if strings.HasPrefix(part, "rate=") {
				rate, _ = strconv.Atoi(strings.TrimPrefix(part, "rate="))
			}
		}
		f.meters[id] = rate
		return nil, nil
	case "diff-flows":
		raw, e := os.ReadFile(args[1])
		if e != nil || string(raw) != f.flows {
			return nil, ErrUnavailable
		}
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected command %s", s)
}
func fixtureExecutor(t *testing.T) (*Executor, *fakeOVS, Topology) {
	t.Helper()
	// testing.TempDir follows the platform's temporary root (Ubuntu: /tmp).
	// macOS may expose that root through /tmp or /var symlinks; resolve them
	// before using the real production ancestor/symlink security checks.
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	c := Config{1, "node-a", "aster-vpc", filepath.Join(root, "state"), true}
	top := topologyFixture()
	fake := &fakeOVS{topology: top, meters: map[int]int{}}
	executor, e := NewExecutor(c, fake)
	if e != nil {
		t.Fatal(e)
	}
	executor.euid = func() int { return 0 }
	executor.tap = func(string) error {
		if fake.physical {
			return ErrUnavailable
		}
		return nil
	}
	return executor, fake, top
}

func TestFabricFixtureUsesPlatformTemporaryRoot(t *testing.T) {
	// Exercise the Ubuntu default even when the regression is run on a Mac;
	// t.Run gets a fresh testing.TempDir cache after changing TMPDIR.
	t.Setenv("TMPDIR", "")
	t.Run("platform-default", func(t *testing.T) {
		if runtime.GOOS == "linux" && os.TempDir() != "/tmp" {
			t.Fatalf("Ubuntu/Linux default temporary root = %q, want /tmp", os.TempDir())
		}
		assertFixtureTemporaryRoot(t)
	})
}

func TestFabricFixtureCanonicalizesSymlinkedTemporaryRoot(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	realRoot := filepath.Join(base, "real-temp")
	if err = os.Mkdir(realRoot, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(base, "temp-alias")
	if err = os.Symlink(realRoot, alias); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", alias)
	t.Run("symlinked-tmpdir", func(t *testing.T) { assertFixtureTemporaryRoot(t) })
}

func assertFixtureTemporaryRoot(t *testing.T) {
	t.Helper()
	wantRoot, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	e, _, top := fixtureExecutor(t)
	root := filepath.Dir(e.Config.StateDirectory)
	rel, err := filepath.Rel(wantRoot, root)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		t.Fatalf("fixture root %q is not a child of platform temporary root %q: %v", root, wantRoot, err)
	}
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil || canonical != root || securePath(root) != nil {
		t.Fatalf("fixture did not preserve production path validation: %q, %q, %v", root, canonical, err)
	}
	if receipt, err := e.Apply(context.Background(), top, e.Config.Bridge); err != nil || receipt.State != "applied" {
		t.Fatalf("canonical platform-temp fixture failed real security checks: %+v, %v", receipt, err)
	}
}
func mutationCount(f *fakeOVS) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		for _, a := range c.args {
			if a == "replace-flows" || a == "add-meter" || a == "del-meters" {
				n++
				break
			}
		}
	}
	return n
}

func TestCompileAntiSpoofVPCIsolationAndDirectionalPolicers(t *testing.T) {
	top := topologyFixture()
	p, e := Compile(top)
	if e != nil {
		t.Fatal(e)
	}
	s := strings.Join(p.Flows, "\n")
	for _, required := range []string{"table=0,priority=0 actions=drop", "table=10,priority=0 actions=drop", "vlan_tci=0x1000/0x1000 actions=drop", "in_port=1,dl_vlan=0xffff,dl_src=52:54:00:01:02:03,ip,nw_src=10.11.0.2", "arp_sha=52:54:00:01:02:03,arp_spa=10.11.0.2", "meter:3,write_metadata:0xa/0xffff,goto_table:10", "metadata=0xa/0xffff,ip,nw_dst=10.11.0.2,dl_dst=52:54:00:01:02:03 actions=meter:2,output:1", "arp_tpa=10.11.0.2"} {
		if !strings.Contains(s, required) {
			t.Fatal("missing guard", required, s)
		}
	}
	for _, forbidden := range []string{"NORMAL", "LOCAL", "FLOOD", "CONTROLLER", "strip_vlan", "mod_vlan", "output:ALL"} {
		if strings.Contains(s, forbidden) {
			t.Fatal("unsafe action", forbidden)
		}
	}
	if !reflect.DeepEqual(p.Meters, []Meter{{2, 100000}, {3, 200000}}) {
		t.Fatal("wrong directional rates", p.Meters)
	}
	before, _ := json.Marshal(top)
	_, _ = Compile(top)
	after, _ := json.Marshal(top)
	if !bytes.Equal(before, after) {
		t.Fatal("compile mutated topology")
	}
}

func TestCompileRejectInvalidInputAndCommandInjection(t *testing.T) {
	for name, mutate := range map[string]func(*Topology){
		"schema": func(t *Topology) { t.Schema = 2 }, "node_injection": func(t *Topology) { t.NodeID = "node;id" }, "zero_revision": func(t *Topology) { t.Revision = 0 }, "nil_ports": func(t *Topology) { t.Ports = nil }, "nil_vpcs": func(t *Topology) { t.VPCs = nil },
		"cidr_hostbits": func(t *Topology) { t.VPCs[0].CIDR = "10.11.0.1/24" }, "public_cidr": func(t *Topology) { t.VPCs[0].CIDR = "8.8.8.0/24" }, "ipv6": func(t *Topology) { t.VPCs[0].CIDR = "fd00::/64" }, "host_prefix": func(t *Topology) { t.VPCs[0].CIDR = "10.11.0.2/32" }, "vlan0": func(t *Topology) { t.VPCs[0].VLANID = 0 }, "vlan4095": func(t *Topology) { t.VPCs[0].VLANID = 4095 },
		"owner": func(t *Topology) { t.Ports[0].OwnerRef = strings.Repeat("8", 32) }, "foreign_vpc": func(t *Topology) { t.Ports[0].VPCID = strings.Repeat("8", 32) }, "network": func(t *Topology) { t.Ports[0].IPv4 = "10.11.0.0" }, "broadcast": func(t *Topology) { t.Ports[0].IPv4 = "10.11.0.255" }, "outside": func(t *Topology) { t.Ports[0].IPv4 = "10.12.0.1" }, "ip_injection": func(t *Topology) { t.Ports[0].IPv4 = "10.11.0.2,actions=NORMAL" },
		"interface_id": func(t *Topology) { t.Ports[0].InterfaceID = "bad" }, "ofport0": func(t *Topology) { t.Ports[0].OFPort = 0 }, "reserved_port": func(t *Topology) { t.Ports[0].OFPort = 65534 }, "limit0": func(t *Topology) { t.Ports[0].InboundMbps = 0 }, "huge_limit": func(t *Topology) { t.Ports[0].OutboundMbps = 100001 }, "multicast_mac": func(t *Topology) { t.Ports[0].MAC = "ff:ff:ff:ff:ff:ff" }, "mac_injection": func(t *Topology) { t.Ports[0].MAC = "52:54:00:01:02:03;sh" },
		"duplicate_port": func(t *Topology) { t.Ports = append(t.Ports, t.Ports[0]) }, "duplicate_vpc": func(t *Topology) { t.VPCs = append(t.VPCs, t.VPCs[0]) },
	} {
		t.Run(name, func(t *testing.T) {
			top := topologyFixture()
			mutate(&top)
			if _, e := Compile(top); e == nil {
				t.Fatal("invalid topology accepted")
			}
		})
	}
	for _, bridge := range []string{"br0", "eth0", "aster-a;id", "tcp:host:6653", "aster-"} {
		c := Config{1, "node-a", bridge, filepath.Join(os.TempDir(), "aster-fabric-invalid"), true}
		if c.Validate() {
			t.Fatal("unsafe bridge", bridge)
		}
	}
}

func TestTopologyStrictDecodeAndStableDigest(t *testing.T) {
	top := topologyFixture()
	raw, _ := json.Marshal(top)
	if _, e := DecodeTopology(raw); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{strings.Replace(string(raw), `"revision":1`, `"revision":1,"revision":2`, 1), strings.Replace(string(raw), `"owner_ref"`, `"Owner_Ref"`, 1), strings.Replace(string(raw), `"inbound_mbps":100`, `"inbound_mbps":100,"inbound_mbps":200`, 1), strings.Replace(string(raw), `"ports":[`, `"ports":null,"unknown":[`, 1), string(raw) + "{}"} {
		if _, e := DecodeTopology([]byte(bad)); e == nil {
			t.Fatal("ambiguous wire accepted", bad)
		}
	}
	p, e := Compile(top)
	if e != nil || len(p.Digest) != 64 {
		t.Fatal(p, e)
	}
	top.Revision++
	p2, _ := Compile(top)
	if p.Digest == p2.Digest {
		t.Fatal("revision not digest-bound")
	}
}

func TestApplyIntentIsolationMetersBundleReadbackReplayAndReadonlyStatus(t *testing.T) {
	e, f, top := fixtureExecutor(t)
	r, err := e.Apply(context.Background(), top, e.Config.Bridge)
	if err != nil || r.State != "applied" {
		t.Fatal(r, err)
	}
	if len(f.meters) != 2 || f.meters[2] != 100000 || f.meters[3] != 200000 {
		t.Fatal(f.meters)
	}
	firstAllow, firstDrop, firstMeter := -1, -1, -1
	for n, c := range f.calls {
		joined := strings.Join(c.args, " ")
		if strings.Contains(joined, "isolation.flows") {
			firstDrop = n
		}
		if firstMeter < 0 && strings.Contains(joined, "add-meter") {
			firstMeter = n
		}
		if strings.Contains(joined, "replace-flows") && strings.Contains(joined, "desired.flows") {
			firstAllow = n
		}
	}
	if firstDrop < 0 || firstMeter <= firstDrop || firstAllow <= firstMeter {
		t.Fatal("isolation ordering failed", firstDrop, firstMeter, firstAllow)
	}
	calls := len(f.calls)
	again, err := e.Apply(context.Background(), top, e.Config.Bridge)
	if err != nil || again != r || len(f.calls) != calls {
		t.Fatal("replay executed", again, err)
	}
	path := filepath.Join(e.Config.StateDirectory, "journal.json")
	before, _ := os.ReadFile(path)
	got, err := Status(e.Config, 0)
	after, _ := os.ReadFile(path)
	if err != nil || got != r || !bytes.Equal(before, after) || len(f.calls) != calls {
		t.Fatal("status changed/queried network", got, err)
	}
	top.Ports[0].OutboundMbps++
	if _, err = e.Apply(context.Background(), top, e.Config.Bridge); !errors.Is(err, ErrConflict) || len(f.calls) != calls {
		t.Fatal("same revision changed digest accepted", err)
	}
}

func TestEveryCommandFailureUncertainNeverRetries(t *testing.T) {
	e, f, top := fixtureExecutor(t)
	if _, err := e.Apply(context.Background(), top, e.Config.Bridge); err != nil {
		t.Fatal(err)
	}
	total := len(f.calls)
	for n := 1; n <= total; n++ {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			e, f, top := fixtureExecutor(t)
			f.failAt = n
			r, err := e.Apply(context.Background(), top, e.Config.Bridge)
			if !errors.Is(err, ErrUncertain) || r.State != "uncertain" {
				t.Fatal("failure invented success", r, err)
			}
			calls := len(f.calls)
			f.failAt = 0
			again, err := e.Apply(context.Background(), top, e.Config.Bridge)
			if !errors.Is(err, ErrUncertain) || again.State != "uncertain" || len(f.calls) != calls {
				t.Fatal("unknown operation re-executed", again, err)
			}
			top.Revision++
			if _, err = e.Apply(context.Background(), top, e.Config.Bridge); !errors.Is(err, ErrUncertain) || len(f.calls) != calls {
				t.Fatal("new revision bypassed uncertainty", err)
			}
		})
	}
}

func TestPortReusePhysicalForeignRulesAndControllersFailClosed(t *testing.T) {
	for _, name := range []string{"foreign_rules", "foreign_controller", "physical", "initial_reuse", "mid_apply_reuse", "post_commit_reuse", "foreign_meter"} {
		t.Run(name, func(t *testing.T) {
			e, f, top := fixtureExecutor(t)
			switch name {
			case "foreign_rules":
				f.foreign = true
			case "foreign_controller":
				f.controller = true
			case "physical":
				f.physical = true
			case "initial_reuse":
				f.driftAt = 1
			case "mid_apply_reuse":
				f.driftAt = 3
			case "post_commit_reuse":
				f.driftAt = 4
			case "foreign_meter":
				f.meters[777] = 1
			}
			r, err := e.Apply(context.Background(), top, e.Config.Bridge)
			if !errors.Is(err, ErrUncertain) || r.State != "uncertain" {
				t.Fatal(r, err)
			}
			if (name == "foreign_rules" || name == "foreign_controller") && mutationCount(f) != 0 {
				t.Fatal("automatically took over foreign bridge/rules")
			}
			if strings.Contains(name, "reuse") || name == "physical" || name == "foreign_meter" {
				if f.flows != strings.Join(isolationFlows(), "\n")+"\n" {
					t.Fatal("unsafe port mapping not quarantined", f.flows)
				}
			}
		})
	}
}

func TestFilesystemFaultsRetainIntentAndBlockNewApply(t *testing.T) {
	for _, point := range []string{"isolation.flows:before_write", "desired.flows:before_sync", "desired.flows:before_rename", "desired.flows:after_rename", "desired.flows:after_dir_sync"} {
		t.Run(point, func(t *testing.T) {
			e, f, top := fixtureExecutor(t)
			e.fault = func(stage string) error {
				if stage == point {
					return ErrUnavailable
				}
				return nil
			}
			r, err := e.Apply(context.Background(), top, e.Config.Bridge)
			if !errors.Is(err, ErrUncertain) || r.State != "uncertain" {
				t.Fatal(r, err)
			}
			calls := len(f.calls)
			e.fault = nil
			top.Revision++
			if _, err = e.Apply(context.Background(), top, e.Config.Bridge); !errors.Is(err, ErrUncertain) || len(f.calls) != calls {
				t.Fatal("filesystem fault retried", err)
			}
		})
	}
	e, f, top := fixtureExecutor(t)
	writes := 0
	e.fault = func(point string) error {
		if point == "journal.json:before_write" {
			writes++
			if writes == 2 {
				return ErrUnavailable
			}
		}
		return nil
	}
	r, err := e.Apply(context.Background(), top, e.Config.Bridge)
	if !errors.Is(err, ErrUncertain) || r.State != "uncertain" || f.flows != strings.Join(isolationFlows(), "\n")+"\n" {
		t.Fatal("lost final receipt not quarantined", r, err)
	}
}

func TestFirstIntentStorageFaultLeavesDurableInitializationTombstone(t *testing.T) {
	for _, point := range []string{"journal.json:before_write", "journal.json:before_sync", "journal.json:before_rename", "journal.json:after_rename", "journal.json:after_dir_sync"} {
		t.Run(point, func(t *testing.T) {
			e, f, top := fixtureExecutor(t)
			e.fault = func(stage string) error {
				if stage == point {
					return ErrUnavailable
				}
				return nil
			}
			r, err := e.Apply(context.Background(), top, e.Config.Bridge)
			if !errors.Is(err, ErrUncertain) || r.State != "uncertain" || mutationCount(f) != 0 {
				t.Fatal("intent not durable before mutation", r, err)
			}
			calls := len(f.calls)
			e.fault = nil
			top.Revision++
			if _, err = e.Apply(context.Background(), top, e.Config.Bridge); err == nil || len(f.calls) != calls {
				t.Fatal("first journal save failure silently initialized/retried", err)
			}
		})
	}
}

func TestMultiVPCOverlappingIPUsesDistinctMetadataAndNoCrossVPCOutput(t *testing.T) {
	top := topologyFixture()
	owner := strings.Repeat("5", 32)
	vpc := strings.Repeat("6", 32)
	instance := strings.Repeat("7", 32)
	top.VPCs = append(top.VPCs, VPC{vpc, owner, "10.11.0.0/24", 20})
	top.Ports = append(top.Ports, Port{instance, InterfaceID(instance), owner, vpc, "10.11.0.2", "52:54:00:01:02:04", 2, 300, 400})
	p, err := Compile(top)
	if err != nil {
		t.Fatal(err)
	}
	for _, flow := range p.Flows {
		if strings.Contains(flow, "output:1") && !strings.Contains(flow, "metadata=0xa/0xffff") {
			t.Fatal("VPC1 target lacks its immutable label", flow)
		}
		if strings.Contains(flow, "output:2") && !strings.Contains(flow, "metadata=0x14/0xffff") {
			t.Fatal("VPC2 target lacks distinct label", flow)
		}
	}
	top.Ports[1].OwnerRef = top.Ports[0].OwnerRef
	if _, err = Compile(top); err == nil {
		t.Fatal("cross-owner VPC port accepted")
	}
}

func TestTopologyEmptyAndCapacityLimits(t *testing.T) {
	top := Topology{Schema: 1, NodeID: "node-a", Revision: 1, VPCs: []VPC{}, Ports: []Port{}}
	p, err := Compile(top)
	if err != nil || len(p.Meters) != 0 || len(p.Flows) != 3 {
		t.Fatal(p, err)
	}
	top = topologyFixture()
	for len(top.Ports) < 129 {
		top.Ports = append(top.Ports, top.Ports[0])
	}
	if _, err = Compile(top); err == nil {
		t.Fatal("port budget exceeded")
	}
	top = topologyFixture()
	for len(top.VPCs) < 33 {
		top.VPCs = append(top.VPCs, top.VPCs[0])
	}
	if _, err = Compile(top); err == nil {
		t.Fatal("VPC budget exceeded")
	}
}

func TestPrivateFilesSymlinksHardlinksLockAndCrashIntent(t *testing.T) {
	for _, name := range []string{"symlink", "hardlink", "world_readable", "bad_journal", "lock_held"} {
		t.Run(name, func(t *testing.T) {
			e, f, top := fixtureExecutor(t)
			if err := os.MkdirAll(e.Config.StateDirectory, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(e.Config.StateDirectory, "journal.json")
			switch name {
			case "symlink":
				_ = os.Symlink("/etc/passwd", path)
			case "hardlink":
				other := filepath.Join(filepath.Dir(path), "source")
				_ = os.WriteFile(other, []byte("{}"), 0600)
				_ = os.Link(other, path)
			case "world_readable":
				_ = os.WriteFile(path, []byte("{}"), 0644)
			case "bad_journal":
				_ = os.WriteFile(path, []byte(`{"schema":1,"schema":1}`), 0600)
			case "lock_held":
				l, err := openLedger(e.Config, true, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer l.close()
			}
			if _, err := e.Apply(context.Background(), top, e.Config.Bridge); err == nil || len(f.calls) != 0 {
				t.Fatal("unsafe state touched network", err)
			}
		})
	}
	e, f, top := fixtureExecutor(t)
	p, _ := Compile(top)
	l, err := openLedger(e.Config, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	l.state.Records = append(l.state.Records, record{Receipt: Receipt{1, top.NodeID, top.Revision, p.Digest, "intent", "recorded", "2026-10-23T01:02:03Z"}, Topology: top, Bindings: []binding{}})
	if err = l.save(); err != nil {
		t.Fatal(err)
	}
	l.close()
	status, err := Status(e.Config, 0)
	if err != nil || status.State != "uncertain" || status.Stage != "interrupted" {
		t.Fatal(status, err)
	}
	if _, err = e.Apply(context.Background(), top, e.Config.Bridge); !errors.Is(err, ErrUncertain) || len(f.calls) != 0 {
		t.Fatal("interrupted intent replayed", err)
	}
}

func TestRootConfirmationPlanAndOSRunnerCommandBoundary(t *testing.T) {
	e, f, top := fixtureExecutor(t)
	for _, confirm := range []string{"", "aster-other", "aster-vpc;id"} {
		if _, err := e.Apply(context.Background(), top, confirm); err == nil || len(f.calls) != 0 {
			t.Fatal("unconfirmed apply", err)
		}
	}
	e.euid = func() int { return 1000 }
	if _, err := e.Apply(context.Background(), top, e.Config.Bridge); err == nil || len(f.calls) != 0 {
		t.Fatal("non-root apply", err)
	}
	if _, err := (OSRunner{}).Run(context.Background(), "/bin/sh", "-c", "id"); !errors.Is(err, ErrInvalid) {
		t.Fatal("shell execution allowed", err)
	}
	if _, err := Compile(top); err != nil || len(f.calls) != 0 {
		t.Fatal("plan executed host commands")
	}
}

func TestQuarantineFailureIsExplicitAndDoesNotPretendIsolation(t *testing.T) {
	e, f, top := fixtureExecutor(t)
	if _, err := e.Apply(context.Background(), top, e.Config.Bridge); err != nil {
		t.Fatal(err)
	}
	total := len(f.calls)
	e, f, top = fixtureExecutor(t)
	f.driftAt = 4
	f.failAt = total + 1
	r, err := e.Apply(context.Background(), top, e.Config.Bridge)
	if !errors.Is(err, ErrUncertain) || r.Stage != "isolation_unconfirmed" || r.State != "uncertain" {
		t.Fatal("failed quarantine presented as safe", r, err)
	}
	calls := len(f.calls)
	top.Revision++
	if _, err = e.Apply(context.Background(), top, e.Config.Bridge); !errors.Is(err, ErrUncertain) || len(f.calls) != calls {
		t.Fatal("quarantine failure allowed further programming", err)
	}
}

func TestCompiledFlowFileSymlinkOrHardlinkNeverReachesOVS(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			e, f, top := fixtureExecutor(t)
			if os.Mkdir(e.Config.StateDirectory, 0700) != nil {
				t.Fatal("prepare")
			}
			outside := filepath.Join(filepath.Dir(e.Config.StateDirectory), "outside")
			if os.WriteFile(outside, []byte("untouched"), 0600) != nil {
				t.Fatal("prepare outside")
			}
			path := filepath.Join(e.Config.StateDirectory, "desired.flows")
			var err error
			if kind == "symlink" {
				err = os.Symlink(outside, path)
			} else {
				err = os.Link(outside, path)
			}
			if err != nil {
				t.Fatal(err)
			}
			r, err := e.Apply(context.Background(), top, e.Config.Bridge)
			raw, _ := os.ReadFile(outside)
			if !errors.Is(err, ErrUncertain) || r.State != "uncertain" || mutationCount(f) != 0 || string(raw) != "untouched" {
				t.Fatal("linked application file reached dataplane", r, err, string(raw))
			}
		})
	}
}

func TestCancelledContextNeverAppliesOrAutoRetries(t *testing.T) {
	e, f, top := fixtureExecutor(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, err := e.Apply(ctx, top, e.Config.Bridge)
	if !errors.Is(err, ErrUncertain) || r.State != "uncertain" || mutationCount(f) != 0 {
		t.Fatal(r, err)
	}
	calls := len(f.calls)
	if _, err = e.Apply(context.Background(), top, e.Config.Bridge); !errors.Is(err, ErrUncertain) || len(f.calls) != calls {
		t.Fatal("cancelled apply retried", err)
	}
}

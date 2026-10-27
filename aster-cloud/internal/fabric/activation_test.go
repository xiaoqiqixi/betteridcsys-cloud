package fabric

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func activationFixture(t *testing.T) (*Executor, *fakeOVS, ActivationIntent, func(context.Context) error) {
	t.Helper()
	e, f, top := fixtureExecutor(t)
	p := top.Ports[0]
	in := ActivationIntent{OperationID: strings.Repeat("a", 32), RequestSHA256: strings.Repeat("b", 64), InstanceID: p.InstanceID, VPCs: top.VPCs, Ports: []PortIntent{{p.InstanceID, p.InterfaceID, p.OwnerRef, p.VPCID, p.IPv4, p.MAC, p.InboundMbps, p.OutboundMbps, true}}}
	f.topology.Ports = []Port{}
	f.names = map[string]string{p.InstanceID: TAPName(p.InstanceID)}
	f.externalIDs = map[string]map[string]string{}
	bootstrap := func(context.Context) error {
		f.topology = top
		f.externalIDs[p.InstanceID] = map[string]string{"iface-id": p.InterfaceID, "attached-mac": p.MAC, "vm-id": DomainID(p.InstanceID), "iface-status": "active"}
		return nil
	}
	return e, f, in, bootstrap
}
func assertDrop(t *testing.T, f *fakeOVS) {
	t.Helper()
	if f.flows != strings.Join(isolationFlows(), "\n")+"\n" {
		t.Fatal("bridge not quarantined", f.flows)
	}
}

func TestActivationIsolatesBootstrapsFreshIdentityAppliesVerifiesReleasesUnderOneLock(t *testing.T) {
	e, f, in, boot := activationFixture(t)
	original, _ := json.Marshal(in)
	calls := []string{}
	blocked := func() {
		t.Helper()
		if _, err := Status(e.Config, 0); err == nil {
			t.Fatal("cross-process read escaped EX flock")
		}
		if _, err := e.Apply(context.Background(), topologyFixture(), e.Config.Bridge); err == nil {
			t.Fatal("apply escaped EX flock")
		}
		if _, err := e.VerifyLive(context.Background()); err == nil {
			t.Fatal("verify escaped EX flock")
		}
	}
	bootstrap := func(c context.Context) error {
		calls = append(calls, "bootstrap")
		assertDrop(t, f)
		blocked()
		return boot(c)
	}
	release := func(context.Context) error {
		calls = append(calls, "release")
		blocked()
		if f.externalIDs[in.InstanceID]["aster-owner"] != in.Ports[0].OwnerRef {
			t.Fatal("release before owner label")
		}
		if !strings.Contains(f.flows, "nw_src="+in.Ports[0].IPv4) || len(f.meters) != 2 {
			t.Fatal("release before flows/meters")
		}
		return nil
	}
	live, err := e.Activate(context.Background(), in, bootstrap, release)
	if err != nil || live.State != "verified" || live.Revision != 1 || !reflect.DeepEqual(calls, []string{"bootstrap", "release"}) {
		t.Fatal(live, calls, err)
	}
	after, _ := json.Marshal(in)
	if !bytes.Equal(original, after) {
		t.Fatal("intent mutated")
	}
	l, err := openLedger(e.Config, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if l.state.Schema != 2 || l.state.Activations[0].State != "completed" {
		t.Fatal(l.state)
	}
	l.close()
	if _, err = e.VerifyLive(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := len(f.calls)
	files := snapshotFiles(t, e.Config.StateDirectory)
	proof, err := e.Check(context.Background(), in)
	if err != nil || proof.Digest != live.Digest {
		t.Fatal(proof, err)
	}
	if !reflect.DeepEqual(files, snapshotFiles(t, e.Config.StateDirectory)) {
		t.Fatal("check wrote files")
	}
	for _, call := range f.calls[before:] {
		if !readOnlyCommand(e.Config, call.binary, call.args) {
			t.Fatal("nonreadonly check", call)
		}
	}
	before = len(f.calls)
	proof, err = e.Activate(context.Background(), in, bootstrap, release)
	if !errors.Is(err, ErrConflict) || proof != (LiveVerification{}) || len(f.calls) != before {
		t.Fatal("replay executed or returned cached permit", proof, err)
	}
	in.RequestSHA256 = strings.Repeat("c", 64)
	if proof, err = e.Activate(context.Background(), in, bootstrap, release); !errors.Is(err, ErrConflict) || proof != (LiveVerification{}) {
		t.Fatal("changed replay accepted", err)
	}
}

func TestActivationRejectsInvalidIntentBeforeAnyHostCall(t *testing.T) {
	mutations := map[string]func(*ActivationIntent){"missing_target": func(in *ActivationIntent) { in.InstanceID = strings.Repeat("f", 32) }, "disabled_target": func(in *ActivationIntent) { in.Ports[0].Enabled = false }, "invalid_operation": func(in *ActivationIntent) { in.OperationID = "x;echo bad" }, "request_sha": func(in *ActivationIntent) { in.RequestSHA256 = strings.Repeat("A", 64) }, "owner": func(in *ActivationIntent) { in.Ports[0].OwnerRef = strings.Repeat("8", 32) }, "nil_ports": func(in *ActivationIntent) { in.Ports = nil }, "limit_zero": func(in *ActivationIntent) { in.Ports[0].InboundMbps = 0 }, "duplicate_tap_name": func(in *ActivationIntent) {
		p := in.Ports[0]
		p.InstanceID = p.InstanceID[:12] + strings.Repeat("8", 20)
		p.InterfaceID = InterfaceID(p.InstanceID)
		p.IPv4 = "10.11.0.3"
		p.MAC = "52:54:00:01:02:04"
		in.Ports = append(in.Ports, p)
	}}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			e, f, in, boot := activationFixture(t)
			mutate(&in)
			if r, err := e.Activate(context.Background(), in, boot, func(context.Context) error { t.Fatal("released invalid intent"); return nil }); err == nil || r != (LiveVerification{}) || len(f.calls) != 0 {
				t.Fatal(r, err)
			}
		})
	}
	for _, s := range []string{"", strings.Repeat("A", 32), "../../etc/passwd", strings.Repeat("f", 33)} {
		if TAPName(s) != "" || DomainID(s) != "" {
			t.Fatal("invalid static identity", s)
		}
	}
	id := strings.Repeat("3", 32)
	if len(TAPName(id)) != 15 || TAPName(id) != TAPName(id) || DomainID(id) == InterfaceID(id) || len(DomainID(id)) != 36 {
		t.Fatal("unstable/aliased identity")
	}
}

func TestActivationBootstrapOrReleaseFailureNeverAutomaticallyReleasesAndRetainsUncertainty(t *testing.T) {
	for _, name := range []string{"bootstrap", "release", "cancel_bootstrap", "cancel_release"} {
		t.Run(name, func(t *testing.T) {
			e, f, in, boot := activationFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			releases := 0
			bootstrap := func(c context.Context) error {
				if err := boot(c); err != nil {
					return err
				}
				if name == "cancel_bootstrap" {
					cancel()
				}
				if name == "bootstrap" {
					return ErrUnavailable
				}
				return nil
			}
			release := func(context.Context) error {
				releases++
				if name == "cancel_release" {
					cancel()
				}
				if name == "release" {
					return ErrUnavailable
				}
				return nil
			}
			r, err := e.Activate(ctx, in, bootstrap, release)
			if !errors.Is(err, ErrUncertain) || r != (LiveVerification{}) {
				t.Fatal(r, err)
			}
			assertDrop(t, f)
			if (name == "bootstrap" || name == "cancel_bootstrap") && releases != 0 {
				t.Fatal("released failed bootstrap")
			}
			l, err := openLedger(e.Config, false, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !l.activationPending() || l.state.Activations[0].State != "uncertain" {
				t.Fatal(l.state)
			}
			l.close()
			calls := len(f.calls)
			in.OperationID = strings.Repeat("d", 32)
			if _, err = e.Activate(context.Background(), in, boot, release); !errors.Is(err, ErrUncertain) || len(f.calls) != calls {
				t.Fatal("retried uncertain activation", err)
			}
			if r, err = e.VerifyLive(context.Background()); err == nil || r != (LiveVerification{}) {
				t.Fatal("pending activation became live permit", r, err)
			}
			if _, err = e.Apply(context.Background(), topologyFixture(), e.Config.Bridge); !errors.Is(err, ErrUncertain) {
				t.Fatal("CLI apply bypassed pending activation", err)
			}
		})
	}
}

func TestActivationRejectsBootstrapIdentityMismatchAndForeignPorts(t *testing.T) {
	for _, name := range []string{"iface_id", "mac", "vm_id", "inactive", "owner_label", "node_label", "foreign_name", "missing_target", "physical", "new_unknown_port", "ofport_reused_identity"} {
		t.Run(name, func(t *testing.T) {
			e, f, in, boot := activationFixture(t)
			releases := 0
			bootstrap := func(c context.Context) error {
				if err := boot(c); err != nil {
					return err
				}
				ids := f.externalIDs[in.InstanceID]
				switch name {
				case "iface_id":
					ids["iface-id"] = DomainID(in.InstanceID)
				case "mac":
					ids["attached-mac"] = "52:54:00:00:00:09"
				case "vm_id":
					ids["vm-id"] = InterfaceID(in.InstanceID)
				case "inactive":
					ids["iface-status"] = "inactive"
				case "owner_label":
					ids["aster-owner"] = strings.Repeat("7", 32)
				case "node_label":
					ids["aster-node-id"] = "other"
				case "foreign_name":
					f.names[in.InstanceID] = "eth0"
				case "missing_target":
					f.topology.Ports = []Port{}
				case "physical":
					f.physical = true
				case "new_unknown_port":
					p := f.topology.Ports[0]
					p.InstanceID = strings.Repeat("9", 32)
					p.InterfaceID = InterfaceID(p.InstanceID)
					p.OFPort = 2
					f.topology.Ports = append(f.topology.Ports, p)
				case "ofport_reused_identity":
					f.driftAt = f.probes + 1
				}
				return nil
			}
			if r, err := e.Activate(context.Background(), in, bootstrap, func(context.Context) error { releases++; return nil }); err == nil || r != (LiveVerification{}) || releases != 0 {
				t.Fatal("foreign target released", r, err)
			}
			assertDrop(t, f)
		})
	}
}

func TestActivationEveryCommandFaultFailsClosedWithoutRepeatedBootstrapOrRelease(t *testing.T) {
	e, f, in, boot := activationFixture(t)
	if _, err := e.Activate(context.Background(), in, boot, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	count := len(f.calls)
	for n := 1; n <= count; n++ {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			e, f, in, boot := activationFixture(t)
			f.failAt = n
			boots, releases := 0, 0
			r, err := e.Activate(context.Background(), in, func(c context.Context) error { boots++; return boot(c) }, func(context.Context) error { releases++; return nil })
			if err == nil || r != (LiveVerification{}) || boots > 1 || releases > 1 {
				t.Fatal("fault permitted/retried", n, r, err, boots, releases)
			}
			if releases > 0 {
				assertDrop(t, f)
			}
		})
	}
}

func TestActivationStorageFaultNeverReleasesOrAdvertisesLiveSuccess(t *testing.T) {
	for _, at := range []string{"journal.json:before_write", "journal.json:before_sync", "journal.json:before_rename", "journal.json:after_rename", "journal.json:after_dir_sync", "isolation.flows:before_write", "desired.flows:before_write"} {
		t.Run(at, func(t *testing.T) {
			e, _, in, boot := activationFixture(t)
			e.fault = func(s string) error {
				if s == at {
					return ErrUnavailable
				}
				return nil
			}
			releases := 0
			r, err := e.Activate(context.Background(), in, boot, func(context.Context) error { releases++; return nil })
			if err == nil || r != (LiveVerification{}) || releases != 0 {
				t.Fatal(r, err, releases)
			}
		})
	}
}

func TestActivationDisabledPresentPortIsCheckedButNeverGetsAllowOrMeter(t *testing.T) {
	e, f, in, boot := activationFixture(t)
	peer := in.Ports[0]
	peer.InstanceID = strings.Repeat("4", 32)
	peer.InterfaceID = InterfaceID(peer.InstanceID)
	peer.IPv4 = "10.11.0.3"
	peer.MAC = "52:54:00:01:02:04"
	peer.Enabled = false
	in.Ports = append(in.Ports, peer)
	f.names[peer.InstanceID] = TAPName(peer.InstanceID)
	f.topology.Ports = []Port{peer.port(2)}
	f.externalIDs[peer.InstanceID] = map[string]string{"iface-id": peer.InterfaceID, "attached-mac": peer.MAC, "vm-id": DomainID(peer.InstanceID), "iface-status": "active", "aster-node-id": e.Config.NodeID, "aster-owner": peer.OwnerRef, "aster-instance": peer.InstanceID, "aster-vpc": peer.VPCID}
	bootstrap := func(c context.Context) error {
		if err := boot(c); err != nil {
			return err
		}
		f.topology.Ports = append(f.topology.Ports, peer.port(2))
		return nil
	}
	if _, err := e.Activate(context.Background(), in, bootstrap, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(f.flows, peer.IPv4) || strings.Contains(f.flows, peer.MAC) || len(f.meters) != 2 {
		t.Fatal("disabled peer allowed")
	}
	if _, err := e.Check(context.Background(), in); err != nil {
		t.Fatal("disabled peer identity check", err)
	}
	f.externalIDs[peer.InstanceID]["aster-owner"] = strings.Repeat("8", 32)
	if r, err := e.Check(context.Background(), in); err == nil || r != (LiveVerification{}) {
		t.Fatal("disabled foreign peer accepted", r, err)
	}
}

func TestActivationCheckRejectsDriftWithoutRepairAndJournalSchemaCannotDowngrade(t *testing.T) {
	e, f, in, boot := activationFixture(t)
	if _, err := e.Activate(context.Background(), in, boot, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	f.meters[2]++
	files := snapshotFiles(t, e.Config.StateDirectory)
	mutations := mutationCount(f)
	if r, err := e.Check(context.Background(), in); err == nil || r != (LiveVerification{}) {
		t.Fatal("check approved drift", r, err)
	}
	if mutationCount(f) != mutations || !reflect.DeepEqual(files, snapshotFiles(t, e.Config.StateDirectory)) {
		t.Fatal("check repaired drift")
	}
	path := filepath.Join(e.Config.StateDirectory, "journal.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte(`"schema":2`), []byte(`"schema":1`), 1)
	if os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("write fixture")
	}
	if _, err = openLedger(e.Config, false, nil); err == nil {
		t.Fatal("downgraded schema ignored activation guard")
	}
}

func TestDeactivateRemovesStalePortFlowsBeforeStopAndHoldsExclusiveLock(t *testing.T) {
	e, f, in, boot := activationFixture(t)
	if _, err := e.Activate(context.Background(), in, boot, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	in.OperationID = strings.Repeat("c", 32)
	in.RequestSHA256 = strings.Repeat("d", 64)
	in.Ports[0].Enabled = false
	stops := 0
	stop := func(context.Context) error {
		stops++
		assertDrop(t, f)
		if _, err := Status(e.Config, 0); err == nil {
			t.Fatal("stop released fabric lock")
		}
		f.topology.Ports = []Port{}
		return nil
	}
	live, err := e.Deactivate(context.Background(), in, stop)
	if err != nil || live.State != "verified" || live.Revision != 2 || stops != 1 || len(f.meters) != 0 || strings.Contains(f.flows, "nw_src=") {
		t.Fatal(live, err, stops, f.meters, f.flows)
	}
	if _, err = e.VerifyLive(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := len(f.calls)
	if r, err := e.Deactivate(context.Background(), in, stop); err == nil || r != (LiveVerification{}) || len(f.calls) != before || stops != 1 {
		t.Fatal("replayed stop", r, err)
	}
}

func TestDeactivateFailureNeverLeavesStaleAllowOrReturnsProof(t *testing.T) {
	for _, name := range []string{"stop_error", "target_remains", "map_drift", "stop_cancel"} {
		t.Run(name, func(t *testing.T) {
			e, f, in, boot := activationFixture(t)
			if _, err := e.Activate(context.Background(), in, boot, func(context.Context) error { return nil }); err != nil {
				t.Fatal(err)
			}
			in.OperationID = strings.Repeat("c", 32)
			in.Ports[0].Enabled = false
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stop := func(context.Context) error {
				assertDrop(t, f)
				switch name {
				case "stop_error":
					return ErrUnavailable
				case "target_remains":
					return nil
				case "map_drift":
					f.externalIDs[in.InstanceID]["aster-owner"] = strings.Repeat("f", 32)
				case "stop_cancel":
					f.topology.Ports = []Port{}
					cancel()
				}
				return nil
			}
			if r, err := e.Deactivate(ctx, in, stop); err == nil || r != (LiveVerification{}) {
				t.Fatal("bad stop succeeded", r, err)
			}
			assertDrop(t, f)
			if _, err := e.VerifyLive(context.Background()); err == nil {
				t.Fatal("uncertain teardown verified")
			}
		})
	}
}

func TestActivationDynamicOfportReassignmentOnlyAfterVerifiedQuarantine(t *testing.T) {
	e, f, in, boot := activationFixture(t)
	if _, err := e.Activate(context.Background(), in, boot, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	in.OperationID = strings.Repeat("c", 32)
	in.Ports[0].Enabled = false
	if _, err := e.Deactivate(context.Background(), in, func(context.Context) error { f.topology.Ports = []Port{}; return nil }); err != nil {
		t.Fatal(err)
	}
	in.OperationID = strings.Repeat("d", 32)
	in.Ports[0].Enabled = true
	if _, err := e.Activate(context.Background(), in, func(c context.Context) error {
		assertDrop(t, f)
		if err := boot(c); err != nil {
			return err
		}
		f.topology.Ports[0].OFPort = 7
		return nil
	}, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.flows, "in_port=7,") || strings.Contains(f.flows, "in_port=1,") || len(f.meters) != 2 || f.meters[14] != 100000 || f.meters[15] != 200000 {
		t.Fatal("stale ofport retained", f.flows, f.meters)
	}
}

func TestActivationPreservesRunningPeerAndAllowsOfportReuseOnlyInsideDropWindow(t *testing.T) {
	e, f, in, boot := activationFixture(t)
	if _, err := e.Activate(context.Background(), in, boot, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	old := in.Ports[0]
	next := old
	next.InstanceID = strings.Repeat("4", 32)
	next.InterfaceID = InterfaceID(next.InstanceID)
	next.IPv4 = "10.11.0.3"
	next.MAC = "52:54:00:01:02:04"
	in.InstanceID = next.InstanceID
	in.OperationID = strings.Repeat("c", 32)
	in.Ports = append(in.Ports, next)
	f.names[next.InstanceID] = TAPName(next.InstanceID)
	bootstrap := func(context.Context) error {
		assertDrop(t, f)
		f.topology.Ports = []Port{old.port(2), next.port(1)}
		f.externalIDs[next.InstanceID] = map[string]string{"iface-id": next.InterfaceID, "attached-mac": next.MAC, "vm-id": DomainID(next.InstanceID), "iface-status": "active"}
		return nil
	}
	if _, err := e.Activate(context.Background(), in, bootstrap, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"in_port=2,dl_vlan=0xffff,dl_src=" + old.MAC, "in_port=1,dl_vlan=0xffff,dl_src=" + next.MAC, "nw_dst=" + old.IPv4, "nw_dst=" + next.IPv4} {
		if !strings.Contains(f.flows, want) {
			t.Fatal("missing current peer rule", want)
		}
	}
	if len(f.meters) != 4 {
		t.Fatal("missing directional peer meters", f.meters)
	}
	// Teardown of the new guest must restore only the still-running old guest.
	in.OperationID = strings.Repeat("d", 32)
	in.Ports[1].Enabled = false
	if _, err := e.Deactivate(context.Background(), in, func(context.Context) error { assertDrop(t, f); f.topology.Ports = []Port{old.port(2)}; return nil }); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(f.flows, next.IPv4) || !strings.Contains(f.flows, old.IPv4) || len(f.meters) != 2 {
		t.Fatal("stale teardown or lost peer", f.flows, f.meters)
	}
}

func TestActivationMissingEnabledPeerFailsBeforeBootstrap(t *testing.T) {
	e, f, in, boot := activationFixture(t)
	peer := in.Ports[0]
	peer.InstanceID = strings.Repeat("4", 32)
	peer.InterfaceID = InterfaceID(peer.InstanceID)
	peer.IPv4 = "10.11.0.3"
	peer.MAC = "52:54:00:01:02:04"
	in.Ports = append(in.Ports, peer)
	boots := 0
	if r, err := e.Activate(context.Background(), in, func(c context.Context) error { boots++; return boot(c) }, func(context.Context) error { t.Fatal("released missing peer"); return nil }); err == nil || r != (LiveVerification{}) || boots != 0 {
		t.Fatal(r, err, boots)
	}
	assertDrop(t, f)
}

func TestActivationEveryDurableWriteFaultRetainsFailClosedBoundary(t *testing.T) {
	e, _, in, boot := activationFixture(t)
	stages := []string{}
	e.fault = func(s string) error { stages = append(stages, s); return nil }
	if _, err := e.Activate(context.Background(), in, boot, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	for n, want := range stages {
		t.Run(strconv.Itoa(n)+"_"+strings.ReplaceAll(want, ":", "_"), func(t *testing.T) {
			e, f, in, boot := activationFixture(t)
			index := 0
			injected := false
			e.fault = func(s string) error {
				current := index
				index++
				if current == n {
					if s != want {
						t.Fatalf("fault path changed %q != %q", s, want)
					}
					injected = true
					return ErrUnavailable
				}
				return nil
			}
			releases := 0
			r, err := e.Activate(context.Background(), in, boot, func(context.Context) error { releases++; return nil })
			if !injected || err == nil || r != (LiveVerification{}) || releases > 1 {
				t.Fatal("durable fault became success", r, err, releases)
			}
			if mutationCount(f) > 0 {
				assertDrop(t, f)
			}
			if r, err := e.VerifyLive(context.Background()); err == nil || r != (LiveVerification{}) {
				t.Fatal("durable failure advertised live success", r, err)
			}
		})
	}
}

func TestDeactivateEveryCommandFaultLeavesNoLiveProofOrAutomaticStopRetry(t *testing.T) {
	prepare := func(t *testing.T) (*Executor, *fakeOVS, ActivationIntent) {
		e, f, in, boot := activationFixture(t)
		if _, err := e.Activate(context.Background(), in, boot, func(context.Context) error { return nil }); err != nil {
			t.Fatal(err)
		}
		in.OperationID = strings.Repeat("c", 32)
		in.Ports[0].Enabled = false
		return e, f, in
	}
	e, f, in := prepare(t)
	start := len(f.calls)
	if _, err := e.Deactivate(context.Background(), in, func(context.Context) error { f.topology.Ports = []Port{}; return nil }); err != nil {
		t.Fatal(err)
	}
	count := len(f.calls) - start
	for n := 1; n <= count; n++ {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			e, f, in := prepare(t)
			f.failAt = len(f.calls) + n
			stops := 0
			r, err := e.Deactivate(context.Background(), in, func(context.Context) error { stops++; f.topology.Ports = []Port{}; return nil })
			if err == nil || r != (LiveVerification{}) || stops > 1 {
				t.Fatal(r, err, stops)
			}
			if stops > 0 {
				assertDrop(t, f)
			}
		})
	}
}

func TestActivationInterruptedRecordBlocksAllFurtherMutationsAndCheck(t *testing.T) {
	e, f, in, boot := activationFixture(t)
	if _, err := e.Activate(context.Background(), in, boot, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	l, err := openLedger(e.Config, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	l.state.Activations[0].State = "preparing"
	l.state.Activations[0].Stage = "releasing"
	if l.save() != nil {
		t.Fatal("fixture journal")
	}
	l.close()
	calls := len(f.calls)
	if r, err := e.Check(context.Background(), in); err == nil || r != (LiveVerification{}) {
		t.Fatal("crash intent became read permit", r, err)
	}
	in.OperationID = strings.Repeat("c", 32)
	if _, err = e.Activate(context.Background(), in, boot, func(context.Context) error { t.Fatal("automatic release after crash"); return nil }); err == nil {
		t.Fatal("crash automatically retried")
	}
	if len(f.calls) != calls {
		t.Fatal("crashed activation queried/programmed host")
	}
}

func TestInspectEmptyApprovedBridgeRequiresNoJournalAndNeverWrites(t *testing.T) {
	e, f, _, _ := activationFixture(t)
	if err := e.Inspect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(e.Config.StateDirectory); !os.IsNotExist(err) {
		t.Fatal("inspect created journal directory", err)
	}
	for _, c := range f.calls {
		if !readOnlyCommand(e.Config, c.binary, c.args) {
			t.Fatal("inspect used writable command", c)
		}
	}
	for _, name := range []string{"foreign_flows", "controller", "physical", "command", "non_root"} {
		t.Run(name, func(t *testing.T) {
			e, f, _, boot := activationFixture(t)
			switch name {
			case "foreign_flows":
				f.foreign = true
			case "controller":
				f.controller = true
			case "physical":
				_ = boot(context.Background())
				f.physical = true
			case "command":
				f.failAt = 1
			case "non_root":
				e.euid = func() int { return 1000 }
			}
			if err := e.Inspect(context.Background()); err == nil {
				t.Fatal("inspect approved bad prerequisite")
			}
			if mutationCount(f) != 0 {
				t.Fatal("inspect changed host")
			}
			if _, err := os.Lstat(e.Config.StateDirectory); !os.IsNotExist(err) {
				t.Fatal("inspect created files", err)
			}
		})
	}
}

func TestActivationCallbackPanicIsUncertainAndQuarantines(t *testing.T) {
	for _, name := range []string{"bootstrap", "release", "stop"} {
		t.Run(name, func(t *testing.T) {
			e, f, in, boot := activationFixture(t)
			var r LiveVerification
			var err error
			if name == "stop" {
				if _, err = e.Activate(context.Background(), in, boot, func(context.Context) error { return nil }); err != nil {
					t.Fatal(err)
				}
				in.OperationID = strings.Repeat("c", 32)
				in.Ports[0].Enabled = false
				r, err = e.Deactivate(context.Background(), in, func(context.Context) error { panic("private lifecycle failure") })
			} else {
				r, err = e.Activate(context.Background(), in, func(c context.Context) error {
					if name == "bootstrap" {
						panic("private lifecycle failure")
					}
					return boot(c)
				}, func(context.Context) error { panic("private lifecycle failure") })
			}
			if err == nil || r != (LiveVerification{}) {
				t.Fatal(r, err)
			}
			assertDrop(t, f)
		})
	}
}

func TestInspectExistingUncertainJournalNeverAdvertisesFreshReadiness(t *testing.T) {
	e, f, in, boot := activationFixture(t)
	if _, err := e.Activate(context.Background(), in, boot, func(context.Context) error { return ErrUnavailable }); err == nil {
		t.Fatal("fixture failure")
	}
	before := len(f.calls)
	if err := e.Inspect(context.Background()); err == nil || len(f.calls) != before {
		t.Fatal("pending activation ignored", err)
	}
}

func TestActivationJournalStrictNestedContractAndFailClosedSchema(t *testing.T) {
	for _, name := range []string{"activation_missing", "activation_null", "intent_duplicate", "intent_wrongcase", "port_unknown", "port_null", "intent_sha_changed", "state_unknown", "stage_wrong"} {
		t.Run(name, func(t *testing.T) {
			e, _, in, boot := activationFixture(t)
			if _, err := e.Activate(context.Background(), in, boot, func(context.Context) error { return nil }); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(e.Config.StateDirectory, "journal.json")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "activation_missing":
				var obj map[string]json.RawMessage
				_ = json.Unmarshal(raw, &obj)
				delete(obj, "activations")
				raw, _ = json.Marshal(obj)
			case "activation_null":
				var obj map[string]json.RawMessage
				_ = json.Unmarshal(raw, &obj)
				obj["activations"] = json.RawMessage(`null`)
				raw, _ = json.Marshal(obj)
			case "intent_duplicate":
				raw = bytes.Replace(raw, []byte(`"operation_id":`), []byte(`"operation_id":"`+in.OperationID+`","operation_id":`), 1)
			case "intent_wrongcase":
				raw = bytes.Replace(raw, []byte(`"request_sha256":`), []byte(`"Request_SHA256":`), 1)
			case "port_unknown":
				raw = bytes.Replace(raw, []byte(`"enabled":true`), []byte(`"enabled":true,"other":1`), 1)
			case "port_null":
				raw = bytes.Replace(raw, []byte(`"enabled":true`), []byte(`"enabled":null`), 1)
			case "intent_sha_changed":
				raw = bytes.Replace(raw, []byte(`"intent_sha256":"`), []byte(`"intent_sha256":"0`), 1)
			case "state_unknown":
				raw = bytes.Replace(raw, []byte(`"state":"completed"`), []byte(`"state":"success"`), 1)
			case "stage_wrong":
				raw = bytes.Replace(raw, []byte(`"stage":"completed"`), []byte(`"stage":"releasing"`), 1)
			}
			if err = os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if l, err := openLedger(e.Config, false, nil); err == nil {
				l.close()
				t.Fatal("invalid activation journal accepted", name)
			}
		})
	}
}

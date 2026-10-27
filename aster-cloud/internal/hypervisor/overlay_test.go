package hypervisor

import (
	"aster/cloud/internal/fabric"
	"aster/cloud/internal/nodeproto"
	"aster/cloud/internal/overlayproto"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeOverlayGate struct {
	calls    []string
	receipts map[string]overlayproto.Receipt
	fail     string
}

func (g *fakeOverlayGate) run(ctx context.Context, t overlayproto.Task, callback func(context.Context) error) (overlayproto.Receipt, error) {
	_, sha, _ := t.BytesAndDigest()
	r := overlayproto.Receipt{Protocol: overlayproto.Protocol, OperationID: t.OperationID, NodeID: t.NodeID, ClusterID: t.Snapshot.ClusterID, Epoch: t.Snapshot.Epoch, Phase: t.Phase, SnapshotSHA256: t.SnapshotSHA256, RequestSHA256: sha, Status: "uncertain", Code: "TEST_UNCONFIRMED"}
	g.calls = append(g.calls, t.Phase)
	if callback != nil {
		if e := callback(ctx); e != nil {
			g.receipts[t.OperationID] = r
			return r, e
		}
	}
	if g.fail == t.Phase {
		g.receipts[t.OperationID] = r
		return r, errors.New("lost ack")
	}
	r.Status = "succeeded"
	r.Code = "TEST_CONFIRMED"
	g.receipts[t.OperationID] = r
	return r, nil
}
func (g *fakeOverlayGate) PrepareOverlay(ctx context.Context, _ fabric.OverlayConfig, t overlayproto.Task, f func(context.Context) error) (overlayproto.Receipt, error) {
	return g.run(ctx, t, f)
}
func (g *fakeOverlayGate) ProgramOverlay(ctx context.Context, _ fabric.OverlayConfig, t overlayproto.Task) (overlayproto.Receipt, error) {
	return g.run(ctx, t, nil)
}
func (g *fakeOverlayGate) ReleaseOverlay(ctx context.Context, _ fabric.OverlayConfig, t overlayproto.Task, f func(context.Context) error) (overlayproto.Receipt, error) {
	return g.run(ctx, t, f)
}
func (g *fakeOverlayGate) LookupOverlay(_ context.Context, _ fabric.OverlayConfig, id, sha string) (overlayproto.Receipt, error) {
	r, ok := g.receipts[id]
	if !ok || r.RequestSHA256 != sha {
		return r, ErrNotFound
	}
	return r, nil
}
func newOverlayFixture(t *testing.T) (*Manager, *ovsRunner, *fakeOverlayGate, overlayproto.Task) {
	t.Helper()
	m, r, _, task := newOVSFixture(t)
	requireOVSSuccess(t, m, task)
	p := m.Config.OVSProfiles[task.Network.ProfileID]
	p.OverlayConfig = "/etc/aster/overlay.json"
	m.Config.OVSProfiles[task.Network.ProfileID] = p
	base, _ := m.loadOVSConfig(p.FabricConfig)
	cfg := fabric.OverlayConfig{Schema: 1, Base: base, LocalIPv4: "192.0.2.1", UnderlayMTU: 1550, GuestMTU: 1500, UnderlayTrustedAck: true, TrustReference: "isolated-test-underlay", ProtectedCIDRs: []string{"192.0.2.0/24"}, Peers: []fabric.OverlayPeer{}, Gateways: []overlayproto.Gateway{}}
	// Non-nil arrays are part of the root config contract.
	cfg.GuestNetworks = []fabric.OverlayGuestNetwork{}
	m.loadOverlayConfig = func(string) (fabric.OverlayConfig, error) { return cfg, nil }
	g := &fakeOverlayGate{receipts: map[string]overlayproto.Receipt{}}
	m.overlayFactory = func(fabric.Config) (overlayGate, error) { return g, nil }
	pin, e := fabric.OverlayConfigSHA256(cfg)
	if e != nil {
		t.Fatal(e)
	}
	n := task.Network
	s := overlayproto.Snapshot{Protocol: overlayproto.Protocol, ClusterID: "test-cluster", Epoch: 1, Profiles: []overlayproto.ProfilePin{{NodeID: task.NodeID, ProfileID: n.ProfileID, ProfileSHA256: pin}}, VPCs: []overlayproto.VPC{{ID: strings.Repeat("a", 32), OwnerRef: n.OwnerRef, CIDR: n.CIDR, VNI: 9001}}, Members: []overlayproto.Member{{NodeID: n.NodeID, InstanceID: n.InstanceID, InterfaceID: n.InterfaceID, OwnerRef: n.OwnerRef, VPCID: strings.Repeat("a", 32), LocalVPCID: n.VPCID, LeaseID: n.LeaseID, PoolID: n.PoolID, NetworkSHA256: n.Digest(), IPv4: n.IPv4, MAC: n.MAC, InboundMbps: n.InboundMbps, OutboundMbps: n.OutboundMbps, Enabled: true}}, Gateways: []overlayproto.Gateway{}}
	s, sha, e := overlayproto.CanonicalSnapshot(s)
	if e != nil {
		t.Fatal(e)
	}
	return m, r, g, overlayproto.Task{Protocol: overlayproto.Protocol, OperationID: strings.Repeat("c", 32), NodeID: task.NodeID, Phase: "prepare", Snapshot: s, SnapshotSHA256: sha}
}
func phaseTask(t overlayproto.Task, phase string) overlayproto.Task {
	t.Phase = phase
	t.OperationID = overlayproto.PhaseOperationID(strings.Repeat("c", 32), t.NodeID, phase)
	return t
}
func TestOverlayNodeThreePhasesFenceAllBeforeRelease(t *testing.T) {
	m, r, g, task := newOverlayFixture(t)
	i, _ := m.Ledger.Instance(task.Snapshot.Members[0].InstanceID)
	original, _ := json.Marshal(i.Network)
	ctx := context.Background()
	if _, e := m.ApplyOverlay(ctx, task); e != nil {
		t.Fatal(e)
	}
	if r.states[i.Domain] != "paused" || r.links[i.Domain] != "down" {
		t.Fatal("prepare released guest")
	}
	if _, e := m.ApplyOverlay(ctx, phaseTask(task, "program")); e != nil {
		t.Fatal(e)
	}
	if r.states[i.Domain] != "paused" || r.links[i.Domain] != "down" {
		t.Fatal("program released guest")
	}
	release := phaseTask(task, "release")
	result, e := m.ApplyOverlay(ctx, release)
	if e != nil || result.Status != "succeeded" {
		t.Fatal(result, e)
	}
	if r.states[i.Domain] != "running" || r.links[i.Domain] != "up" {
		t.Fatal("release did not complete")
	}
	before := len(r.commands)
	replay, e := m.ApplyOverlay(ctx, release)
	if e != nil || replay != result || len(r.commands) != before || len(g.calls) != 3 {
		t.Fatal("historical phase re-executed", e)
	}
	now, _ := m.Ledger.Instance(i.ID)
	raw, _ := json.Marshal(now.Network)
	if string(raw) != string(original) {
		t.Fatal("original frozen binding changed")
	}
}
func TestOverlayNodeProgramCannotRunUnfenced(t *testing.T) {
	m, _, g, task := newOverlayFixture(t)
	if _, e := m.ApplyOverlay(context.Background(), phaseTask(task, "program")); e == nil || len(g.calls) != 0 {
		t.Fatal("program without local fence", e, g.calls)
	}
}
func TestOverlayNodeRejectsMissingOrChangedInventory(t *testing.T) {
	for _, name := range []string{"missing", "binding", "lease", "local-vpc", "owner", "profile", "extra"} {
		t.Run(name, func(t *testing.T) {
			m, r, _, task := newOverlayFixture(t)
			switch name {
			case "missing":
				task.Snapshot.Members = []overlayproto.Member{}
			case "binding":
				task.Snapshot.Members[0].NetworkSHA256 = strings.Repeat("b", 64)
			case "lease":
				task.Snapshot.Members[0].LeaseID = strings.Repeat("b", 32)
			case "local-vpc":
				task.Snapshot.Members[0].LocalVPCID = strings.Repeat("b", 32)
			case "owner":
				task.Snapshot.Members[0].OwnerRef = strings.Repeat("b", 32)
			case "profile":
				task.Snapshot.Profiles[0].ProfileSHA256 = strings.Repeat("b", 64)
			case "extra":
				extra := task.Snapshot.Members[0]
				extra.InstanceID = strings.Repeat("e", 32)
				task.Snapshot.Members = append(task.Snapshot.Members, extra)
			}
			s, sha, e := overlayproto.CanonicalSnapshot(task.Snapshot)
			if e == nil {
				task.Snapshot = s
				task.SnapshotSHA256 = sha
			}
			before := r.count(" resume ")
			if _, e := m.ApplyOverlay(context.Background(), task); e == nil {
				t.Fatal("bad inventory accepted")
			}
			if r.count(" resume ") != before {
				t.Fatal("invalid inventory resumed a VM")
			}
		})
	}
}
func TestOverlayNodeLostReleaseAckFencesGuest(t *testing.T) {
	m, r, g, task := newOverlayFixture(t)
	ctx := context.Background()
	if _, e := m.ApplyOverlay(ctx, task); e != nil {
		t.Fatal(e)
	}
	if _, e := m.ApplyOverlay(ctx, phaseTask(task, "program")); e != nil {
		t.Fatal(e)
	}
	g.fail = "release"
	if _, e := m.ApplyOverlay(ctx, phaseTask(task, "release")); e == nil {
		t.Fatal("lost ack succeeded")
	}
	i, _ := m.Ledger.Instance(task.Snapshot.Members[0].InstanceID)
	if r.states[i.Domain] != "paused" || r.links[i.Domain] != "down" {
		t.Fatal("failed release left active guest")
	}
}

func (g *fakeOverlayGate) OverlayActivate(ctx context.Context, c fabric.OverlayConfig, in fabric.ActivationIntent, sha string, bootstrap, release func(context.Context) error) (fabric.LiveVerification, error) {
	if !overlayproto.ValidSHA(sha) {
		return fabric.LiveVerification{}, ErrOwnership
	}
	g.calls = append(g.calls, "local-activate:"+sha)
	f := &fakeOVSGate{}
	return f.Activate(ctx, in, bootstrap, release)
}
func (g *fakeOverlayGate) OverlayDeactivate(ctx context.Context, c fabric.OverlayConfig, in fabric.ActivationIntent, sha string, stop func(context.Context) error) (fabric.LiveVerification, error) {
	g.calls = append(g.calls, "local-deactivate:"+sha)
	return fabric.LiveVerification{}, stop(ctx)
}
func (g *fakeOverlayGate) OverlayCheck(ctx context.Context, c fabric.OverlayConfig, in fabric.ActivationIntent, sha string) (fabric.LiveVerification, error) {
	g.calls = append(g.calls, "local-check:"+sha)
	return fabric.LiveVerification{}, nil
}

func TestOverlayNewCreateWaitsForAppliedEpochAndKeepsFrozenBinding(t *testing.T) {
	m, r, g, epoch := newOverlayFixture(t)
	first := epoch.Snapshot.Members[0]
	original, _ := m.Ledger.Instance(first.InstanceID)
	task := nodeproto.NodeTask{Protocol: nodeproto.NetworkProtocol, OperationID: strings.Repeat("d", 32), NodeID: m.Config.NodeID, Action: "create", InstanceID: strings.Repeat("e", 32), OwnerRef: original.OwnerRef, Hostname: "second-vm", Resources: original.Resources, Network: original.Network}
	task.Network.InstanceID = task.InstanceID
	task.Network.IPv4 = "10.20.0.11"
	task.Network.LeaseID = strings.Repeat("e", 32)
	task.Network.MAC = nodeproto.NetworkMAC(task.NodeID, task.InstanceID)
	task.Network.InterfaceID = nodeproto.NetworkInterfaceID(task.InstanceID)
	member := first
	member.InstanceID = task.InstanceID
	member.IPv4 = task.Network.IPv4
	member.LeaseID = task.Network.LeaseID
	member.MAC = task.Network.MAC
	member.InterfaceID = task.Network.InterfaceID
	member.NetworkSHA256 = task.Network.Digest()
	member.Reserved = true
	epoch.Snapshot.Members = append(epoch.Snapshot.Members, member)
	var e error
	epoch.Snapshot, epoch.SnapshotSHA256, e = overlayproto.CanonicalSnapshot(epoch.Snapshot)
	if e != nil {
		t.Fatal(e)
	}
	stage := "prepared"
	m.readOverlaySnapshot = func(fabric.OverlayConfig) (overlayproto.Snapshot, string, error) { return epoch.Snapshot, stage, nil }
	denied := submit(t, m, task)
	if denied.Status != "rejected" {
		t.Fatal("early create not rejected", denied)
	}
	if _, ok := m.Ledger.Instance(task.InstanceID); ok {
		t.Fatal("early create reserved files/instance")
	}
	stage = "applied"
	task.OperationID = strings.Repeat("f", 32)
	requireOVSSuccess(t, m, task)
	i, _ := m.Ledger.Instance(task.InstanceID)
	if i.Network != task.Network || r.states[i.Domain] != "running" || g.calls[len(g.calls)-1] != "local-activate:"+task.Network.Digest() {
		t.Fatal("create bypassed overlay full binding gate")
	}
	seed, e := os.ReadFile(filepath.Join(i.Directory, "network-config"))
	if e != nil || !strings.Contains(string(seed), "mtu: 1500") {
		t.Fatal("guest MTU absent", e)
	}
	var domain domainXML
	if xml.Unmarshal(r.domains[i.Domain], &domain) != nil || domain.Devices.Interfaces[0].MTU.Size != 1500 {
		t.Fatal("libvirt MTU absent")
	}
	requireOVSSuccess(t, m, next(task, "8", "shutdown"))
	requireOVSSuccess(t, m, next(task, "9", "start"))
	if i.Network != task.Network {
		t.Fatal("financial/create snapshot changed")
	}
}
func TestOverlayNextEpochDoesNotBootStoppedEligiblePeer(t *testing.T) {
	m, r, _, task := newOverlayFixture(t)
	i, _ := m.Ledger.Instance(task.Snapshot.Members[0].InstanceID)
	// A prior normal shutdown has completed, while membership eligibility stays true.
	m.Ledger.mu.Lock()
	i.State = "shut off"
	m.Ledger.state.Instances[i.ID] = i
	m.Ledger.mu.Unlock()
	r.states[i.Domain] = "shut off"
	r.links[i.Domain] = "down"
	before := r.count(" resume ")
	for _, phase := range []string{"prepare", "program", "release"} {
		if _, e := m.ApplyOverlay(context.Background(), phaseTask(task, phase)); e != nil {
			t.Fatal(phase, e)
		}
	}
	if r.states[i.Domain] != "shut off" || r.count(" resume ") != before {
		t.Fatal("eligible stopped peer was started by network change")
	}
}
func TestOVSPendingBridgeRejectsAnotherCreateBeforeReservation(t *testing.T) {
	m, _, _, task, _ := recoveryFixture(t, false)
	second := task
	second.OperationID = strings.Repeat("e", 32)
	second.InstanceID = strings.Repeat("f", 32)
	second.Network.InstanceID = second.InstanceID
	second.Network.LeaseID = strings.Repeat("f", 32)
	second.Network.IPv4 = "10.20.0.12"
	second.Network.MAC = nodeproto.NetworkMAC(second.NodeID, second.InstanceID)
	second.Network.InterfaceID = nodeproto.NetworkInterfaceID(second.InstanceID)
	result := submit(t, m, second)
	if result.Status != "rejected" {
		t.Fatal("profile failure produced another uncertain create", result)
	}
	if _, ok := m.Ledger.Instance(second.InstanceID); ok {
		t.Fatal("pending bridge reserved a second guest")
	}
}

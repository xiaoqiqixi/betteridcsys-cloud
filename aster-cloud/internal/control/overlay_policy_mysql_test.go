package control

import (
	"aster/cloud/internal/nodeproto"
	"aster/cloud/internal/overlayproto"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func (f *overlayFixture) approveNAT(t *testing.T) (overlayproto.Gateway, []overlayproto.NATPolicy) {
	t.Helper()
	node, gateway := f.config.Nodes[0].ID, id()
	g := overlayproto.Gateway{NodeID: node, InstanceID: gateway, InterfaceID: nodeproto.NetworkInterfaceID(gateway), OwnerRef: f.vpc.OwnerRef, VPCID: f.vpc.ID, IPv4: "10.25.0.1", MAC: nodeproto.NetworkMAC(node, gateway), AllowedPrefixes: []string{"192.0.2.0/24"}}
	p := OverlayNATProfile{NodeID: node, VPCID: f.vpc.ID, GatewayInstanceID: gateway, ProfileID: "approved-nat", ProfileSHA256: strings.Repeat("a", 64), PublicIPv4: "198.51.100.2", AllowSNAT: true, AllowedSourceCIDRs: []string{"192.0.2.0/24"}, AllowedPorts: []OverlayNATPortRange{{Protocol: "tcp", Start: 40000, End: 41000}}}
	f.config.OverlayClusters[0].Gateways = []overlayproto.Gateway{g}
	f.config.OverlayClusters[0].NATProfiles = []OverlayNATProfile{p}
	if !f.config.Valid() {
		t.Fatal("NAT fixture root config invalid")
	}
	return g, []overlayproto.NATPolicy{{ID: id(), NodeID: node, VPCID: f.vpc.ID, GatewayInstanceID: gateway, ProfileID: p.ProfileID, ProfileSHA256: p.ProfileSHA256, SNATEnabled: true, Forwardings: []overlayproto.NATForwarding{{ID: id(), Protocol: "tcp", PublicPort: 40001, TargetInstanceID: f.members[0].InstanceID, TargetPort: 22, SourceCIDR: "192.0.2.0/25"}}}}
}

func advanceOverlayFixture(t *testing.T, w OverlayWorker, id string) {
	t.Helper()
	for i := 0; i < 6; i++ {
		if _, err := w.Advance(context.Background(), id); err != nil {
			t.Fatal("phase", i, err)
		}
	}
	got, err := w.Store.OverlayEpoch(context.Background(), id)
	if err != nil || got.State != "succeeded" {
		t.Fatal("incomplete epoch", got.State, err)
	}
}

func TestMySQLOverlayNATPoliciesPreserveClearRecoverAndAuditRollback(t *testing.T) {
	f := mysqlOverlayFixture(t)
	g, policies := f.approveNAT(t)
	ctx := context.Background()
	in := OverlayEpochInput{ClusterID: f.vpc.ClusterID, Members: f.members, Gateways: []overlayproto.Gateway{g}, NATPolicies: &policies}
	op := id()
	if _, err := f.store.DB.Exec("CREATE TRIGGER overlay_nat_fail_audit BEFORE INSERT ON controller_audit FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='injected'"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.store.PlanOverlayEpoch(ctx, f.config, f.actor, op, in, f.now); err == nil {
		t.Fatal("NAT bypassed audit failure")
	}
	for _, table := range []string{"controller_overlay_epochs", "controller_overlay_tasks", "controller_overlay_members"} {
		var n int
		if err := f.store.DB.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil || n != 0 {
			t.Fatal("partial NAT transaction", table, n, err)
		}
	}
	if _, err := f.store.DB.Exec("DROP TRIGGER overlay_nat_fail_audit"); err != nil {
		t.Fatal(err)
	}
	initial, replay, err := f.store.PlanOverlayEpoch(ctx, f.config, f.actor, op, in, f.now)
	if err != nil || replay || len(initial.Snapshot.NATPolicies) != 1 {
		t.Fatal(initial, err)
	}
	if _, replay, err := f.store.PlanOverlayEpoch(ctx, f.config, f.actor, op, in, f.now); err != nil || !replay {
		t.Fatal("NAT replay", err)
	}
	rpc := &overlayFakeRPC{}
	w := f.worker(rpc)
	// Withdrawing root approval fences new sends without consuming a phase.
	withdrawn := w
	withdrawn.Config = f.config
	withdrawn.Config.OverlayClusters = append([]OverlayCluster{}, f.config.OverlayClusters...)
	withdrawn.Config.OverlayClusters[0].NATProfiles = nil
	if _, err := withdrawn.Advance(ctx, op); !errors.Is(err, ErrState) || len(rpc.posts) != 0 {
		t.Fatal("withdrawn root NAT dispatched", err)
	}
	advanceOverlayFixture(t, w, op)
	tasks, err := f.store.OverlayTasks(ctx, op)
	if err != nil {
		t.Fatal(err)
	}
	for _, task := range tasks {
		if task.Result == nil || task.Result.Status != "succeeded" || task.Result.Code != "CONFIRMED" {
			t.Fatal("confirmed receipt missing from safe result")
		}
	}
	// An old UI omitting NAT cannot silently erase a live policy.
	keep := OverlayEpochInput{ClusterID: f.vpc.ClusterID, ExpectedEpoch: 1, Members: f.members, Gateways: []overlayproto.Gateway{g}}
	next, _, err := f.store.PlanOverlayEpoch(ctx, f.config, f.actor, id(), keep, f.now)
	if err != nil || len(next.Snapshot.NATPolicies) != 1 || next.Snapshot.NATPolicies[0].ID != policies[0].ID {
		t.Fatal("omitted NAT removed policy", err)
	}
	empty := []overlayproto.NATPolicy{}
	changed := keep
	changed.NATPolicies = &empty
	if _, _, err := f.store.PlanOverlayEpoch(ctx, f.config, f.actor, next.ID, changed, f.now); !errors.Is(err, ErrConflict) {
		t.Fatal("preserve and removal same intent", err)
	}
	advanceOverlayFixture(t, w, next.ID)
	// Explicit recovery replacement may remove NAT without mutating old bytes.
	replacement := OverlayRecoveryInput{ExpectedSnapshotSHA256: next.SnapshotSHA256, Replacement: &OverlayReplacementInput{Members: f.members, Gateways: []overlayproto.Gateway{g}, NATPolicies: &empty}}
	recovered, _, err := w.Recover(ctx, f.actor, next.ID, id(), replacement)
	if err != nil || len(recovered.Snapshot.NATPolicies) != 0 {
		t.Fatal("explicit clear failed", err)
	}
	old, err := f.store.OverlayEpoch(ctx, next.ID)
	if err != nil || old.SnapshotSHA256 != next.SnapshotSHA256 || len(old.Snapshot.NATPolicies) != 1 {
		t.Fatal("old NAT rewritten", err)
	}
	advanceOverlayFixture(t, w, recovered.ID)
	for _, j := range f.jobs {
		saved, err := f.store.Lookup(ctx, j.OperationID)
		if err != nil || saved.RequestSHA != j.RequestSHA || saved.NodeRequestSHA != j.NodeRequestSHA || string(saved.RequestJSON) != string(j.RequestJSON) || string(saved.NodeRequest) != string(j.NodeRequest) {
			t.Fatal("financial or node snapshot changed", err)
		}
	}
}

func TestMySQLOverlayOptionsSafeCompleteAndReadOnly(t *testing.T) {
	f := mysqlOverlayFixture(t)
	g, policies := f.approveNAT(t)
	ctx := context.Background()
	var auditBefore int
	if err := f.store.DB.QueryRow("SELECT COUNT(*) FROM controller_audit").Scan(&auditBefore); err != nil {
		t.Fatal(err)
	}
	options, err := f.store.OverlayOptions(ctx, f.config, f.vpc.ClusterID)
	if err != nil || len(options.Instances) != 2 || options.LatestEpoch != nil || len(options.Gateways) != 1 || len(options.NATProfiles) != 1 {
		t.Fatal("options", options, err)
	}
	for _, v := range options.Instances {
		if !v.Eligible || v.VPCID != f.vpc.ID || v.Hostname == "" || v.Reason != "" {
			t.Fatal("invalid candidate", v)
		}
	}
	raw, _ := json.Marshal(options)
	for _, secret := range []string{f.config.DSNFile, f.config.BillingTokenFile, f.config.TLSKeyFile, f.config.Nodes[0].ClientKeyFile, f.config.Nodes[0].Endpoint} {
		if secret != "" && strings.Contains(string(raw), secret) {
			t.Fatal("private config leaked")
		}
	}
	var auditAfter int
	if err := f.store.DB.QueryRow("SELECT COUNT(*) FROM controller_audit").Scan(&auditAfter); err != nil || auditAfter != auditBefore {
		t.Fatal("options mutated audit", err)
	}
	epoch, _, err := f.store.PlanOverlayEpoch(ctx, f.config, f.actor, id(), OverlayEpochInput{ClusterID: f.vpc.ClusterID, Members: f.members, Gateways: []overlayproto.Gateway{g}, NATPolicies: &policies}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	options, err = f.store.OverlayOptions(ctx, f.config, f.vpc.ClusterID)
	if err != nil || options.LatestEpoch == nil || options.LatestEpoch.ID != epoch.ID || len(options.LatestEpoch.Snapshot.NATPolicies) != 1 {
		t.Fatal("latest policy not projected", err)
	}
	// Root mapping withdrawal is visible, never an excuse to omit a live guest.
	f.config.OverlayClusters[0].Mappings = nil
	options, err = f.store.OverlayOptions(ctx, f.config, f.vpc.ClusterID)
	if err != nil || len(options.Instances) != 2 {
		t.Fatal(err)
	}
	for _, v := range options.Instances {
		if v.Eligible || v.VPCID != "" || v.Reason != "ROOT_MAPPING_REQUIRED" {
			t.Fatal("unapproved candidate usable", v)
		}
	}
	got, err := f.store.OverlayVPC(ctx, f.vpc.ID)
	if err != nil || got != f.vpc {
		t.Fatal("exact VPC lookup", got, err)
	}
	if _, err := f.store.OverlayVPC(ctx, id()); !errors.Is(err, ErrNotFound) {
		t.Fatal("unknown ID guessed successful", err)
	}
}

func TestMySQLOverlayRootProfileMigrationOnlyThroughExplicitRecovery(t *testing.T) {
	f := mysqlOverlayFixture(t)
	ctx := context.Background()
	initial := f.plan(t)
	rpc := &overlayFakeRPC{}
	w := f.worker(rpc)
	advanceOverlayFixture(t, w, initial.ID)
	oldPins := append([]overlayproto.ProfilePin{}, f.config.OverlayClusters[0].Profiles...)
	g, policies := f.approveNAT(t)
	f.config.OverlayClusters[0].Profiles = append([]overlayproto.ProfilePin{}, oldPins...)
	f.config.OverlayClusters[0].Profiles[0].ProfileSHA256 = strings.Repeat("9", 64)
	w.Config = f.config
	options, err := f.store.OverlayOptions(ctx, f.config, f.vpc.ClusterID)
	if err != nil || !options.ProfileMigrationRequired || options.ProfileMigrationApproved {
		t.Fatal("unapproved upgrade not explained", err)
	}
	in := OverlayRecoveryInput{ExpectedSnapshotSHA256: initial.SnapshotSHA256, Replacement: &OverlayReplacementInput{Members: f.members, Gateways: []overlayproto.Gateway{g}, NATPolicies: &policies}}
	if _, _, err := w.Recover(ctx, f.actor, initial.ID, id(), in); !errors.Is(err, ErrState) {
		t.Fatal("unapproved root migration accepted", err)
	}
	f.config.OverlayClusters[0].PreviousProfiles = []overlayproto.ProfilePin{oldPins[0]}
	w.Config = f.config
	options, err = f.store.OverlayOptions(ctx, f.config, f.vpc.ClusterID)
	if err != nil || !options.ProfileMigrationRequired || !options.ProfileMigrationApproved {
		t.Fatal("approved upgrade not explained", err)
	}
	normal := OverlayEpochInput{ClusterID: f.vpc.ClusterID, ExpectedEpoch: 1, Members: f.members, Gateways: []overlayproto.Gateway{g}, NATPolicies: &policies}
	if _, _, err := f.store.PlanOverlayEpoch(ctx, f.config, f.actor, id(), normal, f.now); !errors.Is(err, ErrState) {
		t.Fatal("normal edit migrated root pin", err)
	}
	upgraded, _, err := w.Recover(ctx, f.actor, initial.ID, id(), in)
	if err != nil || len(upgraded.Snapshot.NATPolicies) != 1 {
		t.Fatal("explicit NAT upgrade failed", err)
	}
	for _, pin := range upgraded.Snapshot.Profiles {
		if pin.NodeID == oldPins[0].NodeID && pin.ProfileSHA256 != strings.Repeat("9", 64) {
			t.Fatal("new current pin not frozen")
		}
	}
	for i, member := range upgraded.Snapshot.Members {
		if member.NetworkSHA256 != initial.Snapshot.Members[i].NetworkSHA256 {
			t.Fatal("immutable node binding migrated")
		}
	}
	old, err := f.store.OverlayEpoch(ctx, initial.ID)
	if err != nil || old.SnapshotSHA256 != initial.SnapshotSHA256 {
		t.Fatal("old root snapshot altered", err)
	}
	for _, pin := range old.Snapshot.Profiles {
		if pin.NodeID == oldPins[0].NodeID && pin != oldPins[0] {
			t.Fatal("historical root pin overwritten")
		}
	}
	advanceOverlayFixture(t, w, upgraded.ID)
	options, err = f.store.OverlayOptions(ctx, f.config, f.vpc.ClusterID)
	if err != nil || options.ProfileMigrationRequired {
		t.Fatal("completed migration still required", err)
	}
}

func TestMySQLOverlayOptionsRetainDeletedIdentityForExplicitRemoval(t *testing.T) {
	f := mysqlOverlayFixture(t)
	ctx := context.Background()
	epoch := f.plan(t)
	w := f.worker(&overlayFakeRPC{})
	advanceOverlayFixture(t, w, epoch.ID)
	instance := f.members[0].InstanceID
	op, _, err := f.store.CreateOperation(ctx, f.config, f.actor, instance, id(), OperationInput{Action: "delete", Confirmation: instance}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.ClaimOperation(ctx, op.ID, f.config, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.CompleteOperation(ctx, f.config, op.ID, "succeeded", nil, f.now); err != nil {
		t.Fatal(err)
	}
	options, err := f.store.OverlayOptions(ctx, f.config, f.vpc.ClusterID)
	if err != nil || len(options.Instances) != 2 {
		t.Fatal("retained deleted identity omitted", err)
	}
	found := false
	for _, v := range options.Instances {
		if v.InstanceID == instance {
			found = v.State == "deleted" && !v.Eligible && v.Reason == "INSTANCE_DELETED" && v.VPCID == f.vpc.ID
		}
	}
	if !found {
		t.Fatal("deleted identity not safely removable")
	}
	_, _, err = f.store.PlanOverlayEpoch(ctx, f.config, f.actor, id(), OverlayEpochInput{ClusterID: f.vpc.ClusterID, ExpectedEpoch: 1, Members: f.members[1:], Gateways: []overlayproto.Gateway{}}, f.now)
	if err != nil {
		t.Fatal("explicit deleted removal rejected", err)
	}
	options, err = f.store.OverlayOptions(ctx, f.config, f.vpc.ClusterID)
	if err != nil || len(options.Instances) != 1 {
		t.Fatal("old deleted history leaked into current candidates", err)
	}
}

func TestMySQLOverlayNATUnknownACKRejectsForeignReceiptAndRevokedRootPOST(t *testing.T) {
	f := mysqlOverlayFixture(t)
	g, policies := f.approveNAT(t)
	ctx := context.Background()
	epoch, _, err := f.store.PlanOverlayEpoch(ctx, f.config, f.actor, id(), OverlayEpochInput{ClusterID: f.vpc.ClusterID, Members: f.members, Gateways: []overlayproto.Gateway{g}, NATPolicies: &policies}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	rpc := &overlayFakeRPC{lose: "prepare"}
	w := f.worker(rpc)
	unknown, err := w.Advance(ctx, epoch.ID)
	if !errors.Is(err, ErrUnavailable) || unknown.State != "uncertain" || len(rpc.posts) != 1 {
		t.Fatal("lost NAT acknowledgement became success", unknown.State, err)
	}
	sent := rpc.posts[0]
	original := rpc.receipts[sent.OperationID]
	wrong := original
	wrong.SnapshotSHA256 = strings.Repeat("0", 64)
	rpc.receipts[sent.OperationID] = wrong
	if _, err = w.Reconcile(ctx, epoch.ID); !errors.Is(err, ErrUnavailable) {
		t.Fatal("foreign NAT receipt accepted", err)
	}
	still, err := f.store.OverlayEpoch(ctx, epoch.ID)
	if err != nil || still.State != "uncertain" {
		t.Fatal("mismatched receipt changed unknown outcome", err)
	}
	if _, err = w.Advance(ctx, epoch.ID); !errors.Is(err, ErrState) || len(rpc.posts) != 1 {
		t.Fatal("unknown NAT POST repeated", err)
	}
	// Revocation blocks new network writes, not read-only reconciliation of an
	// immutable receipt that was already earned under the previous approval.
	w.Config.OverlayClusters = append([]OverlayCluster{}, f.config.OverlayClusters...)
	w.Config.OverlayClusters[0].NATProfiles = nil
	rpc.receipts[sent.OperationID] = original
	if got, err := w.Reconcile(ctx, epoch.ID); err != nil || got.State != "pending" || len(rpc.posts) != 1 {
		t.Fatal("historical exact receipt could not be observed", err)
	}
	if _, err = w.Advance(ctx, epoch.ID); !errors.Is(err, ErrState) || len(rpc.posts) != 1 {
		t.Fatal("revoked NAT root approval dispatched", err)
	}
	w.Config = f.config
	for i := 0; i < 5; i++ {
		if _, err = w.Advance(ctx, epoch.ID); err != nil {
			t.Fatal(err)
		}
	}
	if len(rpc.posts) != 6 {
		t.Fatal("reconciled phase resent")
	}
}

func TestMySQLOverlayNATMigrationRepeatedRecoveryPinsActualMixedHeads(t *testing.T) {
	f := mysqlOverlayFixture(t)
	ctx := context.Background()
	initial := f.plan(t)
	rpc := &overlayFakeRPC{}
	w := f.worker(rpc)
	advanceOverlayFixture(t, w, initial.ID)
	g, policies := f.approveNAT(t)
	oldPin := f.config.OverlayClusters[0].Profiles[0]
	f.config.OverlayClusters[0].Profiles = append([]overlayproto.ProfilePin{}, f.config.OverlayClusters[0].Profiles...)
	f.config.OverlayClusters[0].Profiles[0].ProfileSHA256 = strings.Repeat("9", 64)
	f.config.OverlayClusters[0].PreviousProfiles = []overlayproto.ProfilePin{oldPin}
	w.Config = f.config
	upgrade, _, err := w.Recover(ctx, f.actor, initial.ID, id(), OverlayRecoveryInput{ExpectedSnapshotSHA256: initial.SnapshotSHA256, Replacement: &OverlayReplacementInput{Members: f.members, Gateways: []overlayproto.Gateway{g}, NATPolicies: &policies}})
	if err != nil {
		t.Fatal(err)
	}
	rpc.lose = "prepare"
	if _, err = w.Advance(ctx, upgrade.ID); !errors.Is(err, ErrUnavailable) {
		t.Fatal("migration failure fixture", err)
	}
	// Only the attempted node moved; the other node still proves the old pin's
	// epoch. The next recovery must freeze these exact mixed heads, not guess.
	next, _, err := w.Recover(ctx, f.actor, upgrade.ID, id(), OverlayRecoveryInput{ExpectedSnapshotSHA256: upgrade.SnapshotSHA256})
	if err != nil || len(next.Snapshot.NATPolicies) != 1 {
		t.Fatal("retry lost desired NAT", err)
	}
	seen := map[int64]bool{}
	for _, h := range next.Recovery.Heads {
		if h != rpc.heads[h.NodeID] {
			t.Fatal("head synthesized instead of read")
		}
		seen[h.Epoch] = true
	}
	if !seen[initial.Epoch] || !seen[upgrade.Epoch] {
		t.Fatal("fixture did not cover mixed heads")
	}
	for _, pin := range next.Snapshot.Profiles {
		if pin.NodeID == oldPin.NodeID && pin.ProfileSHA256 != strings.Repeat("9", 64) {
			t.Fatal("retry downgraded root approval")
		}
	}
	rpc.reject = "program"
	for i := 0; i < 3; i++ {
		if _, err = w.Advance(ctx, next.ID); err != nil {
			t.Fatal("reject fixture", err)
		}
	}
	failed, err := f.store.OverlayEpoch(ctx, next.ID)
	if err != nil || failed.State != "rejected" {
		t.Fatal("second failure not retained", err)
	}
	oldTasks, err := f.store.OverlayTasks(ctx, next.ID)
	if err != nil {
		t.Fatal(err)
	}
	final, _, err := w.Recover(ctx, f.actor, next.ID, id(), OverlayRecoveryInput{ExpectedSnapshotSHA256: next.SnapshotSHA256})
	if err != nil {
		t.Fatal("second explicit recovery stuck", err)
	}
	rpc.reject = ""
	advanceOverlayFixture(t, w, final.ID)
	after, err := f.store.OverlayTasks(ctx, next.ID)
	if err != nil {
		t.Fatal(err)
	}
	for i := range after {
		if after[i].State != oldTasks[i].State || string(after[i].Receipt) != string(oldTasks[i].Receipt) {
			t.Fatal("failed migration receipt overwritten")
		}
	}
	firstUnknown, err := f.store.OverlayTasks(ctx, upgrade.ID)
	if err != nil {
		t.Fatal(err)
	}
	unknownFound := false
	for _, task := range firstUnknown {
		if task.State == "uncertain" {
			unknownFound = true
		}
	}
	if !unknownFound {
		t.Fatal("first unknown was fabricated into success")
	}
	for _, job := range f.jobs {
		saved, err := f.store.Lookup(ctx, job.OperationID)
		if err != nil || saved.NodeRequestSHA != job.NodeRequestSHA || saved.RequestSHA != job.RequestSHA || string(saved.NodeRequest) != string(job.NodeRequest) || string(saved.RequestJSON) != string(job.RequestJSON) {
			t.Fatal("migration rewrote original request", err)
		}
	}
}

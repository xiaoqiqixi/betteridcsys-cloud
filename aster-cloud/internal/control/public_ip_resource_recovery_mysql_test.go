package control

import (
	"aster/cloud/internal/overlayproto"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func mysqlFloatingRecoveryFixture(t *testing.T) (overlayFixture, OverlayWorker, *overlayFakeRPC, PublicIPResource) {
	t.Helper()
	f, g, _, in := mysqlPublicIPFixture(t)
	f.config.OverlayClusters[0].NATProfiles[0].AllowFloatingIP = true
	ctx := context.Background()
	pool, _, _, e := f.store.CreatePublicIPPool(ctx, f.config, f.actor, id(), in, f.now)
	if e != nil {
		t.Fatal(e)
	}
	none := []overlayproto.NATPolicy{}
	initial, _, e := f.store.PlanOverlayEpoch(ctx, f.config, f.actor, id(), OverlayEpochInput{ClusterID: f.vpc.ClusterID, Members: f.members, Gateways: []overlayproto.Gateway{g}, NATPolicies: &none}, f.now)
	if e != nil {
		t.Fatal(e)
	}
	rpc := &overlayFakeRPC{}
	w := f.worker(rpc)
	advanceOverlayFixture(t, w, initial.ID)
	p := f.config.OverlayClusters[0].NATProfiles[0]
	r, _, _, e := f.store.AllocatePublicIPResource(ctx, f.config, f.actor, id(), PublicIPResourceInput{PoolID: pool.ID, OwnerRef: f.vpc.OwnerRef, Mode: "floating", NodeID: p.NodeID, ProfileID: p.ProfileID, VPCID: f.vpc.ID, Address: "8.8.8.9"}, f.now)
	if e != nil {
		t.Fatal(e)
	}
	r, _, _, e = f.store.BindPublicIPResource(ctx, f.config, f.actor, id(), r.ID, f.members[0].InstanceID, false, 0, f.now)
	if e != nil {
		t.Fatal(e)
	}
	return f, w, rpc, r
}
func TestMySQLPublicVMFloatingRecoveryRevokedRootUnknownAndImmutableReplay(t *testing.T) {
	f, w, rpc, r := mysqlFloatingRecoveryFixture(t)
	ctx := context.Background()
	old, e := f.store.OverlayEpoch(ctx, r.EpochID)
	if e != nil {
		t.Fatal(e)
	}
	oldBytes, _ := json.Marshal(old.Snapshot)
	rpc.lose = "prepare"
	if _, e = w.Advance(ctx, r.EpochID); !errors.Is(e, ErrUnavailable) {
		t.Fatal("fixture did not lose receipt", e)
	}
	cluster := &f.config.OverlayClusters[0]
	cluster.PreviousProfiles = append([]overlayproto.ProfilePin{}, cluster.Profiles...)
	for i := range cluster.Profiles {
		cluster.Profiles[i].ProfileSHA256 = strings.Repeat("c", 64)
	}
	cluster.NATProfiles[0].AllowFloatingIP = false
	cluster.NATProfiles[0].ProfileSHA256 = strings.Repeat("d", 64)
	if !f.config.Valid() {
		t.Fatal("bad revoked root config")
	}
	w = f.worker(rpc)
	op := id()
	pending, result, replay, e := w.RecoverPublicIPResource(ctx, f.actor, op, r.ID, r.BindingGeneration, old.SnapshotSHA256)
	if e != nil || replay || pending.BindingState != "pending" || pending.InstanceID != "" || pending.BindingGeneration != r.BindingGeneration+1 || pending.Releasable {
		t.Fatal("recovery ack", pending, e)
	}
	if len(rpc.posts) != 7 || rpc.headGets != 2 {
		t.Fatal("recovery preparation wrote to nodes", len(rpc.posts), rpc.headGets)
	}
	recovery, e := f.store.OverlayEpoch(ctx, pending.EpochID)
	if e != nil || recovery.Recovery == nil || len(recovery.Snapshot.FloatingIPs) != 0 || recovery.Snapshot.PreviousSHA256 != old.SnapshotSHA256 {
		t.Fatal(recovery, e)
	}
	if _, _, _, e = f.store.ReleasePublicIPResource(ctx, f.config, f.actor, id(), r.ID, pending.BindingGeneration, f.now); !errors.Is(e, ErrState) {
		t.Fatal("pending recovery freed IP", e)
	}
	// An old unknown receipt is preserved, not relabelled as successful.
	original, e := f.store.OverlayEpoch(ctx, old.ID)
	if e != nil {
		t.Fatal(e)
	}
	gotBytes, _ := json.Marshal(original.Snapshot)
	if string(gotBytes) != string(oldBytes) || original.State != "superseded" {
		t.Fatal("old snapshot was edited")
	}
	tasks, e := f.store.OverlayTasks(ctx, old.ID)
	if e != nil {
		t.Fatal(e)
	}
	unknown := 0
	for _, task := range tasks {
		if task.State == "uncertain" {
			unknown++
		}
	}
	if unknown != 1 {
		t.Fatal("unknown receipt changed", unknown)
	}
	for i := 0; i < 5; i++ {
		if _, e = w.Advance(ctx, pending.EpochID); e != nil {
			t.Fatal(e)
		}
	}
	if _, _, _, e = f.store.ReleasePublicIPResource(ctx, f.config, f.actor, id(), r.ID, pending.BindingGeneration, f.now); !errors.Is(e, ErrState) {
		t.Fatal("partial release freed IP", e)
	}
	if _, e = w.Advance(ctx, pending.EpochID); e != nil {
		t.Fatal(e)
	}
	ready, e := f.store.PublicIPResource(ctx, f.config, r.ID)
	if e != nil || ready.BindingState != "unbound" || !ready.Releasable {
		t.Fatal(ready, e)
	}
	if _, _, _, e = f.store.ReleasePublicIPResource(ctx, f.config, f.actor, id(), r.ID, pending.BindingGeneration, f.now); e != nil {
		t.Fatal(e)
	}
	frozen, again, replay, e := w.RecoverPublicIPResource(ctx, f.actor, op, r.ID, r.BindingGeneration, old.SnapshotSHA256)
	if e != nil || !replay || !reflect.DeepEqual(again, result) || frozen.State != "reserved" || frozen.BindingState != "pending" || rpc.headGets != 2 {
		t.Fatal("replay did not preserve fixed result", frozen, e)
	}
}
func TestMySQLPublicVMFloatingRecoveryAuditRollbackAndStaleCAS(t *testing.T) {
	f, w, rpc, r := mysqlFloatingRecoveryFixture(t)
	ctx := context.Background()
	old, e := f.store.OverlayEpoch(ctx, r.EpochID)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, _, e = w.RecoverPublicIPResource(ctx, f.actor, id(), r.ID, 0, old.SnapshotSHA256); !errors.Is(e, ErrState) || rpc.headGets != 0 {
		t.Fatal("stale edit probed nodes", e)
	}
	if _, _, _, e = w.RecoverPublicIPResource(ctx, f.actor, id(), r.ID, r.BindingGeneration, strings.Repeat("f", 64)); !errors.Is(e, ErrState) || rpc.headGets != 0 {
		t.Fatal("wrong snapshot probed nodes", e)
	}
	if _, e = f.store.DB.Exec("CREATE TRIGGER resource_recovery_audit_refusal BEFORE INSERT ON controller_audit FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='fixture refusal'"); e != nil {
		t.Fatal(e)
	}
	key := id()
	if _, _, _, e = w.RecoverPublicIPResource(ctx, f.actor, key, r.ID, r.BindingGeneration, old.SnapshotSHA256); e == nil {
		t.Fatal("audit refusal admitted recovery")
	}
	var epochs, bindings, ops int
	if e = f.store.DB.QueryRow("SELECT COUNT(*) FROM controller_overlay_epochs").Scan(&epochs); e != nil {
		t.Fatal(e)
	}
	if e = f.store.DB.QueryRow("SELECT COUNT(*) FROM controller_public_ip_bindings WHERE resource_id=?", r.ID).Scan(&bindings); e != nil {
		t.Fatal(e)
	}
	if e = f.store.DB.QueryRow("SELECT COUNT(*) FROM controller_public_ip_resource_operations WHERE id=?", key).Scan(&ops); e != nil {
		t.Fatal(e)
	}
	if epochs != 2 || bindings != 1 || ops != 0 {
		t.Fatal("partial recovery committed", epochs, bindings, ops)
	}
	current, e := scanPublicResource(f.store.DB.QueryRow("SELECT "+publicResourceColumns+" FROM controller_public_ip_resources WHERE id=?", r.ID))
	if e != nil || current.BindingGeneration != r.BindingGeneration {
		t.Fatal("failed audit changed generation", current, e)
	}
	original, e := f.store.OverlayEpoch(ctx, old.ID)
	if e != nil || original.State != "pending" || original.SupersededBy != "" {
		t.Fatal("original superseded on rollback", original, e)
	}
	if len(rpc.posts) != 6 {
		t.Fatal("recovery planning emitted node writes")
	}
}
func TestMySQLPublicVMFloatingRecoveryRejectsAheadOrForeignHeads(t *testing.T) {
	for _, kind := range []string{"ahead", "foreign"} {
		t.Run(kind, func(t *testing.T) {
			f, w, rpc, r := mysqlFloatingRecoveryFixture(t)
			ctx := context.Background()
			old, e := f.store.OverlayEpoch(ctx, r.EpochID)
			if e != nil {
				t.Fatal(e)
			}
			node := old.Snapshot.Profiles[0].NodeID
			h := overlayproto.Head{NodeID: node, ClusterID: old.ClusterID, Epoch: old.Epoch, SnapshotSHA256: old.SnapshotSHA256}
			if kind == "ahead" {
				h.Epoch++
			} else {
				h.ClusterID = "foreign"
			}
			rpc.heads[node] = h
			if _, _, _, e = w.RecoverPublicIPResource(ctx, f.actor, id(), r.ID, r.BindingGeneration, old.SnapshotSHA256); !errors.Is(e, ErrUnavailable) {
				t.Fatal("unsafe head accepted", e)
			}
			var n int
			if e = f.store.DB.QueryRow("SELECT COUNT(*) FROM controller_overlay_epochs").Scan(&n); e != nil || n != 2 {
				t.Fatal("unsafe head committed recovery", n, e)
			}
		})
	}
}

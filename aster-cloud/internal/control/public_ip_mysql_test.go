package control

import (
	"aster/cloud/internal/identity"
	"aster/cloud/internal/networking"
	"aster/cloud/internal/overlayproto"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func mysqlPublicIPFixture(t *testing.T) (overlayFixture, overlayproto.Gateway, []overlayproto.NATPolicy, PublicIPPoolInput) {
	t.Helper()
	f := mysqlOverlayFixture(t)
	g, policies := f.approveInternetNAT(t)
	f.config.OverlayClusters[0].NATProfiles[0].PublicIPv4s = []string{"8.8.8.9", "8.8.8.10"}
	if !f.config.Valid() {
		t.Fatal("invalid public approval")
	}
	return f, g, policies, PublicIPPoolInput{ClusterID: f.vpc.ClusterID, Name: "公网池", CIDR: "8.8.8.0/24", Addresses: []string{"8.8.8.10", "8.8.8.9"}, Enabled: true}
}
func publicLeaseFixtureInput(f overlayFixture, pool PublicIPPool, address string) PublicIPLeaseInput {
	p := f.config.OverlayClusters[0].NATProfiles[0]
	return PublicIPLeaseInput{PoolID: pool.ID, OwnerRef: f.vpc.OwnerRef, VPCID: f.vpc.ID, NodeID: p.NodeID, ProfileID: p.ProfileID, Address: address}
}
func TestMySQLPublicIPLifecycleBindingUnknownAndCompleteDetach(t *testing.T) {
	f, g, policies, in := mysqlPublicIPFixture(t)
	ctx := context.Background()
	pool, operation, replay, e := f.store.CreatePublicIPPool(ctx, f.config, f.actor, id(), in, f.now)
	if e != nil || replay || operation.Result.Pool.ID != pool.ID || pool.Addresses[0] != "8.8.8.10" {
		t.Fatal("pool create", e)
	}
	leaseIn := publicLeaseFixtureInput(f, pool, "8.8.8.9")
	op := id()
	lease, allocation, replay, e := f.store.AllocatePublicIP(ctx, f.config, f.actor, op, leaseIn, f.now)
	if e != nil || replay || !lease.Releasable {
		t.Fatal("allocation", e)
	}
	options, e := f.store.PublicIPOptions(ctx, f.config)
	if e != nil || !options.Complete || len(options.Approvals) != 1 || len(options.Approvals[0].PublicIPv4s) != 3 || options.Approvals[0].OwnerRef != f.vpc.OwnerRef {
		t.Fatal("safe projection", e)
	}
	policies[0].PublicIPv4 = "8.8.8.10"
	epochIn := OverlayEpochInput{ClusterID: f.vpc.ClusterID, Members: f.members, Gateways: []overlayproto.Gateway{g}, NATPolicies: &policies}
	if _, _, e = f.store.PlanOverlayEpoch(ctx, f.config, f.actor, id(), epochIn, f.now); !errors.Is(e, ErrState) {
		t.Fatal("unallocated root-approved selector admitted", e)
	}
	policies[0].PublicIPv4 = lease.Address
	epoch, _, e := f.store.PlanOverlayEpoch(ctx, f.config, f.actor, id(), epochIn, f.now)
	if e != nil {
		t.Fatal("leased selection", e)
	}
	if _, _, _, e = f.store.ReleasePublicIP(ctx, f.config, f.actor, id(), lease.ID, f.now); !errors.Is(e, ErrState) {
		t.Fatal("pending release freed IP", e)
	}
	rpc := &overlayFakeRPC{}
	w := f.worker(rpc)
	advanceOverlayFixture(t, w, epoch.ID)
	if _, _, _, e = f.store.ReleasePublicIP(ctx, f.config, f.actor, id(), lease.ID, f.now); !errors.Is(e, ErrState) {
		t.Fatal("active NAT IP freed", e)
	}
	if got, e := f.store.PublicIPLease(ctx, f.config, lease.ID); e != nil || got.Releasable || got.BindingState != "bound" {
		t.Fatal("bound projection", got, e)
	}
	// Disabling inventory is admission-only, not an implicit network disconnect.
	if _, _, _, e = f.store.SetPublicIPPoolState(ctx, f.config, f.actor, id(), pool.ID, false, f.now); e != nil {
		t.Fatal(e)
	}
	if _, _, _, e = f.store.AllocatePublicIP(ctx, f.config, f.actor, id(), publicLeaseFixtureInput(f, pool, "8.8.8.10"), f.now); !errors.Is(e, ErrState) {
		t.Fatal("disabled pool allocated", e)
	}
	empty := []overlayproto.NATPolicy{}
	clear := OverlayEpochInput{ClusterID: f.vpc.ClusterID, ExpectedEpoch: epoch.Epoch, Members: f.members, Gateways: []overlayproto.Gateway{g}, NATPolicies: &empty}
	detached, _, e := f.store.PlanOverlayEpoch(ctx, f.config, f.actor, id(), clear, f.now)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 5; i++ {
		if _, e = w.Advance(ctx, detached.ID); e != nil {
			t.Fatal(e)
		}
	}
	if _, _, _, e = f.store.ReleasePublicIP(ctx, f.config, f.actor, id(), lease.ID, f.now); !errors.Is(e, ErrState) {
		t.Fatal("partial release freed IP", e)
	}
	if _, e = w.Advance(ctx, detached.ID); e != nil {
		t.Fatal(e)
	}
	releaseOp := id()
	released, releaseResult, replay, e := f.store.ReleasePublicIP(ctx, f.config, f.actor, releaseOp, lease.ID, f.now)
	if e != nil || replay || released.State != "released" {
		t.Fatal("confirmed detach refused", e)
	}
	if got, again, replay, e := f.store.ReleasePublicIP(ctx, f.config, f.actor, releaseOp, lease.ID, f.now); e != nil || !replay || !reflect.DeepEqual(got, released) || !reflect.DeepEqual(again, releaseResult) {
		t.Fatal("release exact replay", e)
	}
	// Loss of an allocation ACK is resolved from the immutable operation, not the
	// now-released mutable row. Same key across actors/actions must conflict.
	got, e := f.store.PublicIPOperation(ctx, f.actor, op)
	if e != nil || got.Result.Lease.State != "reserved" || !reflect.DeepEqual(got, allocation) {
		t.Fatal("allocation ACK changed after release", e)
	}
	if _, e = f.store.PublicIPOperation(ctx, id(), op); !errors.Is(e, ErrNotFound) {
		t.Fatal("cross-actor ACK exposed", e)
	}
	if _, _, _, e = f.store.AllocatePublicIP(ctx, f.config, id(), op, leaseIn, f.now); !errors.Is(e, ErrConflict) {
		t.Fatal("cross actor replay", e)
	}
	if _, _, _, e = f.store.SetPublicIPPoolState(ctx, f.config, f.actor, op, pool.ID, false, f.now); !errors.Is(e, ErrConflict) {
		t.Fatal("cross kind replay", e)
	}
	assertOriginalOverlayJobs(t, f)
}
func TestMySQLPublicIPPoolInventoryAndLeaseLastAddressSerializes(t *testing.T) {
	f, _, _, in := mysqlPublicIPFixture(t)
	ctx := context.Background()
	in.Addresses = []string{"8.8.8.9"}
	pool, _, _, e := f.store.CreatePublicIPPool(ctx, f.config, f.actor, id(), in, f.now)
	if e != nil {
		t.Fatal(e)
	}
	overlap := in
	overlap.CIDR = "8.8.8.8/30"
	overlap.Addresses = []string{"8.8.8.10"}
	if _, _, _, e = f.store.CreatePublicIPPool(ctx, f.config, f.actor, id(), overlap, f.now); !errors.Is(e, ErrConflict) {
		t.Fatal("overlap stole reserved inventory", e)
	}
	in.Addresses = []string{"8.8.8.11"}
	if _, _, _, e = f.store.CreatePublicIPPool(ctx, f.config, f.actor, id(), in, f.now); !errors.Is(e, ErrState) {
		t.Fatal("DB expanded root inventory", e)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _, e := f.store.AllocatePublicIP(ctx, f.config, f.actor, id(), publicLeaseFixtureInput(f, pool, "8.8.8.9"), f.now)
			results <- e
		}()
	}
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for e := range results {
		if e == nil {
			success++
		} else if errors.Is(e, ErrConflict) {
			conflict++
		} else {
			t.Fatal(e)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatal("last IP not exclusive", success, conflict)
	}
}
func TestMySQLPublicIPRootWithdrawalAndAuditRollback(t *testing.T) {
	f, _, _, in := mysqlPublicIPFixture(t)
	ctx := context.Background()
	op := id()
	if _, e := f.store.DB.Exec("CREATE TRIGGER public_ip_audit_fail BEFORE INSERT ON controller_audit FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='injected'"); e != nil {
		t.Fatal(e)
	}
	if _, _, _, e := f.store.CreatePublicIPPool(ctx, f.config, f.actor, op, in, f.now); e == nil {
		t.Fatal("audit failure succeeded")
	}
	for _, table := range []string{"controller_public_ip_pools", "controller_public_ip_inventory", "controller_public_ip_operations"} {
		var n int
		if e := f.store.DB.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); e != nil || n != 0 {
			t.Fatal("audit rollback partial", table, n, e)
		}
	}
	if _, e := f.store.DB.Exec("DROP TRIGGER public_ip_audit_fail"); e != nil {
		t.Fatal(e)
	}
	pool, _, _, e := f.store.CreatePublicIPPool(ctx, f.config, f.actor, op, in, f.now)
	if e != nil {
		t.Fatal(e)
	}
	leaseIn := publicLeaseFixtureInput(f, pool, "8.8.8.9")
	leaseOp := id()
	lease, _, _, e := f.store.AllocatePublicIP(ctx, f.config, f.actor, leaseOp, leaseIn, f.now)
	if e != nil {
		t.Fatal(e)
	}
	changed := f.config
	changed.OverlayClusters = append([]OverlayCluster{}, f.config.OverlayClusters...)
	changed.OverlayClusters[0].NATProfiles = nil
	if _, _, _, e = f.store.AllocatePublicIP(ctx, changed, f.actor, leaseOp, leaseIn, f.now); !errors.Is(e, ErrState) {
		t.Fatal("root withdrawn replay accepted", e)
	}
	if _, _, _, e = f.store.CreatePublicIPPool(ctx, changed, f.actor, op, in, f.now); !errors.Is(e, ErrState) {
		t.Fatal("root withdrawn pool replay accepted", e)
	}
	if _, _, _, e = f.store.ReleasePublicIP(ctx, changed, f.actor, id(), lease.ID, f.now); e != nil {
		t.Fatal("unused detached lease cannot be reclaimed after withdrawal", e)
	}
}
func TestMySQLPublicIPLegacyPrimaryOccupancyAndUnknownRecovery(t *testing.T) {
	t.Run("legacy_active_primary", func(t *testing.T) {
		f, g, policies, in := mysqlPublicIPFixture(t)
		ctx := context.Background()
		in.Addresses = []string{"8.8.8.8"}
		epoch, _, e := f.store.PlanOverlayEpoch(ctx, f.config, f.actor, id(), OverlayEpochInput{ClusterID: f.vpc.ClusterID, Members: f.members, Gateways: []overlayproto.Gateway{g}, NATPolicies: &policies}, f.now)
		if e != nil {
			t.Fatal(e)
		}
		advanceOverlayFixture(t, f.worker(&overlayFakeRPC{}), epoch.ID)
		pool, _, _, e := f.store.CreatePublicIPPool(ctx, f.config, f.actor, id(), in, f.now)
		if e != nil {
			t.Fatal(e)
		}
		keep := OverlayEpochInput{ClusterID: f.vpc.ClusterID, ExpectedEpoch: epoch.Epoch, Members: f.members, Gateways: []overlayproto.Gateway{g}, NATPolicies: &policies}
		kept, _, e := f.store.PlanOverlayEpoch(ctx, f.config, f.actor, id(), keep, f.now)
		if e != nil {
			t.Fatal("pre-pool legacy continuity refused", e)
		}
		advanceOverlayFixture(t, f.worker(&overlayFakeRPC{}), kept.ID)

		if _, _, _, e = f.store.AllocatePublicIP(ctx, f.config, f.actor, id(), publicLeaseFixtureInput(f, pool, "8.8.8.8"), f.now); !errors.Is(e, ErrState) {
			t.Fatal("legacy default IP stolen", e)
		}
	})
	t.Run("unknown_not_freed_until_complete_fence", func(t *testing.T) {
		f, g, policies, in := mysqlPublicIPFixture(t)
		ctx := context.Background()
		pool, _, _, e := f.store.CreatePublicIPPool(ctx, f.config, f.actor, id(), in, f.now)
		if e != nil {
			t.Fatal(e)
		}
		lease, _, _, e := f.store.AllocatePublicIP(ctx, f.config, f.actor, id(), publicLeaseFixtureInput(f, pool, "8.8.8.9"), f.now)
		if e != nil {
			t.Fatal(e)
		}
		policies[0].PublicIPv4 = lease.Address
		epoch, _, e := f.store.PlanOverlayEpoch(ctx, f.config, f.actor, id(), OverlayEpochInput{ClusterID: f.vpc.ClusterID, Members: f.members, Gateways: []overlayproto.Gateway{g}, NATPolicies: &policies}, f.now)
		if e != nil {
			t.Fatal(e)
		}
		rpc := &overlayFakeRPC{lose: "prepare"}
		w := f.worker(rpc)
		unknown, callErr := w.Advance(ctx, epoch.ID)
		if !errors.Is(callErr, ErrUnavailable) || unknown.State != "uncertain" || len(rpc.posts) != 1 {
			t.Fatal("lost ACK did not preserve unknown state", unknown.State, len(rpc.posts), callErr)
		}
		pendingTasks, taskErr := f.store.OverlayTasks(ctx, epoch.ID)
		if taskErr != nil {
			t.Fatal(taskErr)
		}
		uncertain := 0
		for _, task := range pendingTasks {
			if task.State == "uncertain" {
				uncertain++
				if len(task.Receipt) != 0 {
					t.Fatal("lost ACK fabricated a receipt")
				}
			}
		}
		if uncertain != 1 {
			t.Fatal("unknown operation was not durably fenced", uncertain)
		}

		if _, _, _, e = f.store.ReleasePublicIP(ctx, f.config, f.actor, id(), lease.ID, f.now); !errors.Is(e, ErrState) {
			t.Fatal("unknown freed", e)
		}
		rpc.lose = ""
		empty := []overlayproto.NATPolicy{}
		recovery, _, e := w.Recover(ctx, f.actor, epoch.ID, id(), OverlayRecoveryInput{ExpectedSnapshotSHA256: epoch.SnapshotSHA256, Replacement: &OverlayReplacementInput{Members: f.members, Gateways: []overlayproto.Gateway{g}, NATPolicies: &empty}})
		if e != nil {
			t.Fatal(e)
		}
		if _, _, _, e = f.store.ReleasePublicIP(ctx, f.config, f.actor, id(), lease.ID, f.now); !errors.Is(e, ErrState) {
			t.Fatal("superseded means released", e)
		}
		advanceOverlayFixture(t, w, recovery.ID)
		if _, _, _, e = f.store.ReleasePublicIP(ctx, f.config, f.actor, id(), lease.ID, f.now); e != nil {
			t.Fatal("complete recovery did not detach", e)
		}
	})
}
func TestMySQLPublicIPSchemaReentryAndDrift(t *testing.T) {
	s := consoleHTTPStore(t)
	ctx := context.Background()
	if _, e := s.DB.Exec("DELETE FROM controller_schema WHERE version=8"); e != nil {
		t.Fatal(e)
	}
	if _, e := s.DB.Exec("DROP TABLE controller_public_ip_active"); e != nil {
		t.Fatal(e)
	}
	if e := s.Migrate(ctx); e != nil {
		t.Fatal("partial DDL reentry", e)
	}
	if e := s.Migrate(ctx); e != nil {
		t.Fatal("recorded reentry", e)
	}
	if _, e := s.DB.Exec("ALTER TABLE controller_public_ip_leases MODIFY address VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL"); e != nil {
		t.Fatal(e)
	}
	if e := networking.CheckPublicIPMigration(ctx, s.DB, false); !errors.Is(e, networking.ErrConflict) {
		t.Fatal("drift accepted", e)
	}
	if e := s.Check(ctx); e == nil {
		t.Fatal("runtime accepted schema drift")
	}
}
func TestMySQLPublicIPConsoleTLSGrantsCSRFAndExactACK(t *testing.T) {
	f, _, _, in := mysqlPublicIPFixture(t)
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	ident, e := identity.New(f.store.DB, identity.Config{Origin: server.URL})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ident.Bootstrap(context.Background(), "public-admin@example.invalid", "Public IP fixture", []byte(consoleHTTPPassword)); e != nil {
		t.Fatal(e)
	}
	mux.Handle("/", (Console{Store: f.store, Config: f.config, Identity: ident}).Handler())
	admin := newConsoleHTTPBrowser(t, server)
	admin.login(t, "public-admin@example.invalid")
	admin.createUser(t, "public-read@example.invalid", "custom", []string{"nodes.read"})
	admin.createUser(t, "public-network@example.invalid", "custom", []string{"nodes.read", "nodes.manage"})
	reader := newConsoleHTTPBrowser(t, server)
	reader.login(t, "public-read@example.invalid")
	manager := newConsoleHTTPBrowser(t, server)
	manager.login(t, "public-network@example.invalid")
	body := consoleHTTPJSON(t, in)
	path := "/console/v1/public-ips/pools"
	key := id()
	for name, b := range map[string]*consoleHTTPBrowser{"reader": reader, "network_only": manager} {
		if status, _ := b.request(t, "POST", path, body, consoleHTTPOptions{idempotency: key}); status != 403 {
			t.Fatal(name, "mutated", status)
		}
	}
	if status, _ := admin.request(t, "POST", path, body, consoleHTTPOptions{idempotency: key, csrf: ptr("")}); status != 403 {
		t.Fatal("CSRF bypass", status)
	}
	if status, _ := admin.request(t, "POST", path, body, consoleHTTPOptions{idempotency: key, origin: ptr("https://evil.invalid")}); status != 403 {
		t.Fatal("Origin bypass", status)
	}
	if status, _ := reader.request(t, "GET", "/console/v1/public-ips/options", "", consoleHTTPOptions{}); status != 200 {
		t.Fatal("reader missing safe options", status)
	}
	status, raw := admin.request(t, "POST", path, body, consoleHTTPOptions{idempotency: key})
	var result struct {
		Pool      PublicIPPool      `json:"pool"`
		Operation PublicIPOperation `json:"operation"`
	}
	if status != 201 || json.Unmarshal(raw, &result) != nil || result.Pool.ID != key || result.Operation.ID != key {
		t.Fatal("real API create", status, string(raw))
	}
	status, raw = admin.request(t, "GET", "/console/v1/public-ips/operations/"+key, "", consoleHTTPOptions{})
	var ack struct {
		Operation PublicIPOperation `json:"operation"`
	}
	if status != 200 || json.Unmarshal(raw, &ack) != nil || !reflect.DeepEqual(ack.Operation, result.Operation) {
		t.Fatal("lost ACK resolution", status, string(raw))
	}
	if status, _ := reader.request(t, "GET", "/console/v1/public-ips/operations/"+key, "", consoleHTTPOptions{}); status != 404 {
		t.Fatal("other actor sees ACK", status)
	}
	for _, query := range []string{"?cluster_id=bad&cluster_id=other", "?cursor=", "?limit=100", "?cluster_id="} {
		if status, _ := admin.request(t, "GET", path+query, "", consoleHTTPOptions{}); status != 400 {
			t.Fatal("loose query", query, status)
		}
	}
	for name, body := range map[string]string{"unknown": strings.TrimSuffix(consoleHTTPJSON(t, in), "}") + `,"device":"eth0"}`, "duplicate": `{"cluster_id":"cluster-fixture","cluster_id":"other"}`, "oversize": `{"name":"` + strings.Repeat("x", 70000) + `"}`} {
		if status, _ := admin.request(t, "POST", path, body, consoleHTTPOptions{idempotency: id()}); status != 400 {
			t.Fatal("loose JSON", name, status)
		}
	}
}

func TestMySQLPublicIPInventoryStopsNewImplicitPolicyAndRetainsImmutableHistory(t *testing.T) {
	f, g, policies, in := mysqlPublicIPFixture(t)
	ctx := context.Background()
	in.Addresses = []string{"8.8.8.8"}
	pool, _, _, e := f.store.CreatePublicIPPool(ctx, f.config, f.actor, id(), in, f.now)
	if e != nil {
		t.Fatal(e)
	}
	intent := OverlayEpochInput{ClusterID: f.vpc.ClusterID, Members: f.members, Gateways: []overlayproto.Gateway{g}, NATPolicies: &policies}
	if _, _, e = f.store.PlanOverlayEpoch(ctx, f.config, f.actor, id(), intent, f.now); !errors.Is(e, ErrState) {
		t.Fatal("new implicit NAT bypassed inventory", e)
	}
	lease, _, _, e := f.store.AllocatePublicIP(ctx, f.config, f.actor, id(), publicLeaseFixtureInput(f, pool, "8.8.8.8"), f.now)
	if e != nil {
		t.Fatal(e)
	}
	policies[0].PublicIPv4 = lease.Address
	if _, _, e = f.store.PlanOverlayEpoch(ctx, f.config, f.actor, id(), intent, f.now); e != nil {
		t.Fatal("explicit primary lease rejected", e)
	}
}
func TestMySQLPublicIPUpgradeChangedRootPinsRequiresCompleteRelease(t *testing.T) {
	f := mysqlOverlayFixture(t)
	g, policies := f.approveInternetNAT(t)
	ctx := context.Background()
	initial, _, e := f.store.PlanOverlayEpoch(ctx, f.config, f.actor, id(), OverlayEpochInput{ClusterID: f.vpc.ClusterID, Members: f.members, Gateways: []overlayproto.Gateway{g}, NATPolicies: &policies}, f.now)
	if e != nil {
		t.Fatal(e)
	}
	rpc := &overlayFakeRPC{}
	w := f.worker(rpc)
	advanceOverlayFixture(t, w, initial.ID)
	oldSnapshot, _ := json.Marshal(initial.Snapshot)
	oldTasks, e := f.store.OverlayTasks(ctx, initial.ID)
	if e != nil {
		t.Fatal(e)
	}
	cluster := &f.config.OverlayClusters[0]
	cluster.PreviousProfiles = append([]overlayproto.ProfilePin{}, cluster.Profiles...)
	for i := range cluster.Profiles {
		cluster.Profiles[i].ProfileSHA256 = strings.Repeat("c", 64)
	}
	cluster.NATProfiles[0].ProfileSHA256 = strings.Repeat("d", 64)
	cluster.NATProfiles[0].PublicIPv4s = []string{"8.8.8.9"}
	if !f.config.Valid() {
		t.Fatal("invalid upgraded roots")
	}
	w = f.worker(rpc)
	poolIn := PublicIPPoolInput{ClusterID: f.vpc.ClusterID, Name: "升级出口", CIDR: "8.8.8.9/32", Addresses: []string{"8.8.8.9"}, Enabled: true}
	if _, _, _, e = f.store.CreatePublicIPPool(ctx, f.config, f.actor, id(), poolIn, f.now); !errors.Is(e, ErrState) {
		t.Fatal("unknown legacy pin guessed before root recovery", e)
	}
	replacement := append([]overlayproto.NATPolicy{}, policies...)
	replacement[0].ProfileSHA256 = cluster.NATProfiles[0].ProfileSHA256
	recovered, _, e := w.Recover(ctx, f.actor, initial.ID, id(), OverlayRecoveryInput{ExpectedSnapshotSHA256: initial.SnapshotSHA256, Replacement: &OverlayReplacementInput{Members: f.members, Gateways: []overlayproto.Gateway{g}, NATPolicies: &replacement}})
	if e != nil {
		t.Fatal("new root-pin replacement", e)
	}
	// A pending newer snapshot may be known, but cannot retire the old unknown
	// source IP. Its final all-node release remains the authoritative boundary.
	tx, e := f.store.locked(ctx)
	if e != nil {
		t.Fatal(e)
	}
	blocked := publicAddressDetachedTx(ctx, tx, f.config, "8.8.8.9")
	tx.Rollback()
	if !errors.Is(blocked, ErrState) {
		t.Fatal("pending migration freed old unknown source", blocked)
	}
	advanceOverlayFixture(t, w, recovered.ID)
	pool, _, _, e := f.store.CreatePublicIPPool(ctx, f.config, f.actor, id(), poolIn, f.now)
	if e != nil {
		t.Fatal("completed root migration locked aliases forever", e)
	}
	alias, _, _, e := f.store.AllocatePublicIP(ctx, f.config, f.actor, id(), publicLeaseFixtureInput(f, pool, "8.8.8.9"), f.now)
	if e != nil {
		t.Fatal("approved migrated alias allocation", e)
	}
	explicit := append([]overlayproto.NATPolicy{}, replacement...)
	explicit[0].PublicIPv4 = alias.Address
	use, _, e := f.store.PlanOverlayEpoch(ctx, f.config, f.actor, id(), OverlayEpochInput{ClusterID: f.vpc.ClusterID, ExpectedEpoch: recovered.Epoch, Members: f.members, Gateways: []overlayproto.Gateway{g}, NATPolicies: &explicit}, f.now)
	if e != nil {
		t.Fatal(e)
	}
	advanceOverlayFixture(t, w, use.ID)
	empty := []overlayproto.NATPolicy{}
	cleared, _, e := f.store.PlanOverlayEpoch(ctx, f.config, f.actor, id(), OverlayEpochInput{ClusterID: f.vpc.ClusterID, ExpectedEpoch: use.Epoch, Members: f.members, Gateways: []overlayproto.Gateway{g}, NATPolicies: &empty}, f.now)
	if e != nil {
		t.Fatal(e)
	}
	advanceOverlayFixture(t, w, cleared.ID)
	if _, _, _, e = f.store.ReleasePublicIP(ctx, f.config, f.actor, id(), alias.ID, f.now); e != nil {
		t.Fatal("migrated alias reclaim", e)
	}
	primaryIn := PublicIPPoolInput{ClusterID: f.vpc.ClusterID, Name: "迁移后主地址", CIDR: "8.8.8.8/32", Addresses: []string{"8.8.8.8"}, Enabled: true}
	primaryPool, _, _, e := f.store.CreatePublicIPPool(ctx, f.config, f.actor, id(), primaryIn, f.now)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, _, e = f.store.AllocatePublicIP(ctx, f.config, f.actor, id(), publicLeaseFixtureInput(f, primaryPool, "8.8.8.8"), f.now); e != nil {
		t.Fatal("cleared legacy primary stayed permanently locked", e)
	}
	historical, e := f.store.OverlayEpoch(ctx, initial.ID)
	after, _ := json.Marshal(historical.Snapshot)
	tasks, e2 := f.store.OverlayTasks(ctx, initial.ID)
	if e != nil || e2 != nil || string(oldSnapshot) != string(after) || !reflect.DeepEqual(oldTasks, tasks) {
		t.Fatal("upgrade rewrote old snapshot or receipts", e, e2)
	}
	assertOriginalOverlayJobs(t, f)
}

func TestMySQLPublicIPAuditFailureRollsBackAllocateReleaseAndActiveIndex(t *testing.T) {
	f, _, _, in := mysqlPublicIPFixture(t)
	ctx := context.Background()
	pool, _, _, e := f.store.CreatePublicIPPool(ctx, f.config, f.actor, id(), in, f.now)
	if e != nil {
		t.Fatal(e)
	}
	lease, _, _, e := f.store.AllocatePublicIP(ctx, f.config, f.actor, id(), publicLeaseFixtureInput(f, pool, "8.8.8.9"), f.now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.store.DB.Exec("CREATE TRIGGER public_ip_audit_fail BEFORE INSERT ON controller_audit FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='injected'"); e != nil {
		t.Fatal(e)
	}
	allocateOp, releaseOp := id(), id()
	if _, _, _, e = f.store.AllocatePublicIP(ctx, f.config, f.actor, allocateOp, publicLeaseFixtureInput(f, pool, "8.8.8.10"), f.now); e == nil {
		t.Fatal("allocate bypassed audit")
	}
	if _, _, _, e = f.store.ReleasePublicIP(ctx, f.config, f.actor, releaseOp, lease.ID, f.now); e == nil {
		t.Fatal("release bypassed audit")
	}
	var n int
	if e = f.store.DB.QueryRow("SELECT COUNT(*) FROM controller_public_ip_operations WHERE id IN (?,?)", allocateOp, releaseOp).Scan(&n); e != nil || n != 0 {
		t.Fatal("failed action left immutable operation", n, e)
	}
	if e = f.store.DB.QueryRow("SELECT COUNT(*) FROM controller_public_ip_active WHERE address='8.8.8.10'").Scan(&n); e != nil || n != 0 {
		t.Fatal("failed allocation leaked active index", n, e)
	}
	if got, e := f.store.PublicIPLease(ctx, f.config, lease.ID); e != nil || got.State != "reserved" || !got.Releasable {
		t.Fatal("failed release freed prior lease", got, e)
	}
}
func TestMySQLPublicIPDetachRequiresEveryExactReceiptAndHasNo64EpochLimit(t *testing.T) {
	f, g, policies, in := mysqlPublicIPFixture(t)
	ctx := context.Background()
	pool, _, _, e := f.store.CreatePublicIPPool(ctx, f.config, f.actor, id(), in, f.now)
	if e != nil {
		t.Fatal(e)
	}
	lease, _, _, e := f.store.AllocatePublicIP(ctx, f.config, f.actor, id(), publicLeaseFixtureInput(f, pool, "8.8.8.9"), f.now)
	if e != nil {
		t.Fatal(e)
	}
	policies[0].PublicIPv4 = lease.Address
	epoch, _, e := f.store.PlanOverlayEpoch(ctx, f.config, f.actor, id(), OverlayEpochInput{ClusterID: f.vpc.ClusterID, Members: f.members, Gateways: []overlayproto.Gateway{g}, NATPolicies: &policies}, f.now)
	if e != nil {
		t.Fatal(e)
	}
	w := f.worker(&overlayFakeRPC{})
	advanceOverlayFixture(t, w, epoch.ID)
	empty := []overlayproto.NATPolicy{}
	for i := 0; i < 65; i++ {
		next, _, err := f.store.PlanOverlayEpoch(ctx, f.config, f.actor, id(), OverlayEpochInput{ClusterID: f.vpc.ClusterID, ExpectedEpoch: epoch.Epoch, Members: f.members, Gateways: []overlayproto.Gateway{g}, NATPolicies: &empty}, f.now)
		if err != nil {
			t.Fatal(i, err)
		}
		advanceOverlayFixture(t, w, next.ID)
		epoch = next
	}
	tasks, e := f.store.OverlayTasks(ctx, epoch.ID)
	if e != nil {
		t.Fatal(e)
	}
	var selected OverlayNodeTask
	for _, task := range tasks {
		if task.Phase == "release" {
			selected = task
			break
		}
	}
	if selected.OperationID == "" {
		t.Fatal("no release task")
	}
	if _, e = f.store.DB.Exec("UPDATE controller_overlay_tasks SET receipt=? WHERE operation_id=?", []byte{}, selected.OperationID); e != nil {
		t.Fatal(e)
	}
	if _, _, _, e = f.store.ReleasePublicIP(ctx, f.config, f.actor, id(), lease.ID, f.now); !errors.Is(e, ErrState) {
		t.Fatal("missing final receipt ignored", e)
	}
	if _, e = f.store.DB.Exec("UPDATE controller_overlay_tasks SET receipt=? WHERE operation_id=?", selected.Receipt, selected.OperationID); e != nil {
		t.Fatal(e)
	}
	if _, _, _, e = f.store.ReleasePublicIP(ctx, f.config, f.actor, id(), lease.ID, f.now); e != nil {
		t.Fatal("history beyond64 incorrectly locked reclaim", e)
	}
	assertOriginalOverlayJobs(t, f)
}
func TestMySQLPublicIPExplicitLeaseRootAndDBDriftFenceDispatch(t *testing.T) {
	f, g, policies, in := mysqlPublicIPFixture(t)
	ctx := context.Background()
	pool, _, _, e := f.store.CreatePublicIPPool(ctx, f.config, f.actor, id(), in, f.now)
	if e != nil {
		t.Fatal(e)
	}
	lease, _, _, e := f.store.AllocatePublicIP(ctx, f.config, f.actor, id(), publicLeaseFixtureInput(f, pool, "8.8.8.9"), f.now)
	if e != nil {
		t.Fatal(e)
	}
	policies[0].PublicIPv4 = lease.Address
	epoch, _, e := f.store.PlanOverlayEpoch(ctx, f.config, f.actor, id(), OverlayEpochInput{ClusterID: f.vpc.ClusterID, Members: f.members, Gateways: []overlayproto.Gateway{g}, NATPolicies: &policies}, f.now)
	if e != nil {
		t.Fatal(e)
	}
	rpc := &overlayFakeRPC{}
	w := f.worker(rpc)
	original := f.config.OverlayClusters[0].NATProfiles[0].PublicIPv4s
	w.Config.OverlayClusters[0].NATProfiles[0].PublicIPv4s = []string{"8.8.8.10"}
	if _, e = w.Advance(ctx, epoch.ID); !errors.Is(e, ErrState) || len(rpc.posts) != 0 {
		t.Fatal("withdrawn address dispatched", e)
	}
	w.Config.OverlayClusters[0].NATProfiles[0].PublicIPv4s = original
	if _, e = f.store.DB.Exec("UPDATE controller_public_ip_leases SET owner_ref=? WHERE id=?", id(), lease.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = w.Advance(ctx, epoch.ID); !errors.Is(e, ErrState) || len(rpc.posts) != 0 {
		t.Fatal("forged lease owner dispatched", e)
	}
}

func TestMySQLPublicIPAutoAllocationLastAddressReplayDisabledAndRootWithdrawal(t *testing.T) {
	f, _, _, in := mysqlPublicIPFixture(t)
	ctx := context.Background()
	in.Addresses = []string{"8.8.8.9"}
	pool, _, _, e := f.store.CreatePublicIPPool(ctx, f.config, f.actor, id(), in, f.now)
	if e != nil {
		t.Fatal(e)
	}
	auto := publicLeaseFixtureInput(f, pool, "")
	type outcome struct {
		lease     PublicIPLease
		operation PublicIPOperation
		err       error
	}
	results := make(chan outcome, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l, o, _, e := f.store.AllocatePublicIP(ctx, f.config, f.actor, id(), auto, f.now)
			results <- outcome{l, o, e}
		}()
	}
	wg.Wait()
	close(results)
	success, exhausted := 0, 0
	var allocated outcome
	for result := range results {
		if result.err == nil {
			success++
			allocated = result
		} else if errors.Is(result.err, ErrPublicIPCapacity) {
			exhausted++
		} else {
			t.Fatal(result.err)
		}
	}
	if success != 1 || exhausted != 1 || allocated.lease.Address != "8.8.8.9" {
		t.Fatal("auto last address race", success, exhausted)
	}
	var request PublicIPLeaseInput
	if !strict(allocated.operation.Request, &request) || request.Address != "" {
		t.Fatal("auto intent rewritten to actual IP")
	}
	if got, op, replay, e := f.store.AllocatePublicIP(ctx, f.config, f.actor, allocated.operation.ID, auto, f.now); e != nil || !replay || !reflect.DeepEqual(got, allocated.lease) || !reflect.DeepEqual(op, allocated.operation) {
		t.Fatal("auto lost ACK did not return original allocation", e)
	}
	if _, _, _, e = f.store.SetPublicIPPoolState(ctx, f.config, f.actor, id(), pool.ID, false, f.now); e != nil {
		t.Fatal(e)
	}
	if _, _, _, e = f.store.AllocatePublicIP(ctx, f.config, f.actor, id(), auto, f.now); !errors.Is(e, ErrState) {
		t.Fatal("disabled auto allocation", e)
	}
	if _, _, replay, e := f.store.AllocatePublicIP(ctx, f.config, f.actor, allocated.operation.ID, auto, f.now); e != nil || !replay {
		t.Fatal("disabled pool erased prior ACK", e)
	}
	f.config.OverlayClusters[0].NATProfiles[0].PublicIPv4s = []string{"8.8.8.10"}
	if _, _, _, e = f.store.AllocatePublicIP(ctx, f.config, f.actor, allocated.operation.ID, auto, f.now); !errors.Is(e, ErrState) {
		t.Fatal("auto replay escaped withdrawn root address", e)
	}
}

func TestMySQLPublicIPAppendInventoryAuditReplayConcurrentAndRootWithdrawal(t *testing.T) {
	f, _, _, in := mysqlPublicIPFixture(t)
	ctx := context.Background()
	in.Addresses = []string{"8.8.8.9"}
	createOp := id()
	pool, original, _, e := f.store.CreatePublicIPPool(ctx, f.config, f.actor, createOp, in, f.now)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, _, e = f.store.SetPublicIPPoolState(ctx, f.config, f.actor, id(), pool.ID, false, f.now); e != nil {
		t.Fatal(e)
	}
	if _, e = f.store.DB.Exec("CREATE TRIGGER public_ip_audit_fail BEFORE INSERT ON controller_audit FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='injected'"); e != nil {
		t.Fatal(e)
	}
	extendOp := id()
	if _, _, _, e = f.store.ExtendPublicIPPool(ctx, f.config, f.actor, extendOp, pool.ID, []string{"8.8.8.10"}, f.now); e == nil {
		t.Fatal("append bypassed audit")
	}
	var n int
	if e = f.store.DB.QueryRow("SELECT COUNT(*) FROM controller_public_ip_inventory WHERE address='8.8.8.10'").Scan(&n); e != nil || n != 0 {
		t.Fatal("failed append left inventory", n, e)
	}
	if _, e = f.store.DB.Exec("DROP TRIGGER public_ip_audit_fail"); e != nil {
		t.Fatal(e)
	}
	extended, operation, replay, e := f.store.ExtendPublicIPPool(ctx, f.config, f.actor, extendOp, pool.ID, []string{"8.8.8.10"}, f.now)
	if e != nil || replay || extended.Enabled || len(extended.Addresses) != 2 {
		t.Fatal("disabled append changed admission", extended, e)
	}
	if got, op, replay, e := f.store.ExtendPublicIPPool(ctx, f.config, f.actor, extendOp, pool.ID, []string{"8.8.8.10"}, f.now); e != nil || !replay || !reflect.DeepEqual(got, extended) || !reflect.DeepEqual(op, operation) {
		t.Fatal("append exact replay", e)
	}
	if old, e := f.store.PublicIPOperation(ctx, f.actor, createOp); e != nil || !reflect.DeepEqual(old, original) || len(old.Result.Pool.Addresses) != 1 {
		t.Fatal("append rewrote create history", e)
	}
	if _, _, _, e = f.store.AllocatePublicIP(ctx, f.config, f.actor, id(), publicLeaseFixtureInput(f, pool, "8.8.8.10"), f.now); !errors.Is(e, ErrState) {
		t.Fatal("append silently enabled pool", e)
	}
	if _, _, _, e = f.store.SetPublicIPPoolState(ctx, f.config, f.actor, id(), pool.ID, true, f.now); e != nil {
		t.Fatal(e)
	}
	if _, _, _, e = f.store.AllocatePublicIP(ctx, f.config, f.actor, id(), publicLeaseFixtureInput(f, pool, "8.8.8.10"), f.now); e != nil {
		t.Fatal("appended stock not allocatable", e)
	}
	// A second append operation cannot acquire even the same pool's already owned
	// address; exact ACK replay is the only exception and never adds a second row.
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _, e := f.store.ExtendPublicIPPool(ctx, f.config, f.actor, id(), pool.ID, []string{"8.8.8.10"}, f.now)
			results <- e
		}()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if !errors.Is(err, ErrConflict) {
			t.Fatal("concurrent duplicate stock accepted", err)
		}
	}
	f.config.OverlayClusters[0].NATProfiles[0].PublicIPv4s = []string{"8.8.8.9"}
	if _, _, _, e = f.store.ExtendPublicIPPool(ctx, f.config, f.actor, extendOp, pool.ID, []string{"8.8.8.10"}, f.now); !errors.Is(e, ErrState) {
		t.Fatal("withdrawn root append replay accepted", e)
	}
}

func TestMySQLPublicIPMissingActiveIndexNeverFreesHistoricalReservedLease(t *testing.T) {
	f, _, _, in := mysqlPublicIPFixture(t)
	ctx := context.Background()
	pool, _, _, e := f.store.CreatePublicIPPool(ctx, f.config, f.actor, id(), in, f.now)
	if e != nil {
		t.Fatal(e)
	}
	lease, _, _, e := f.store.AllocatePublicIP(ctx, f.config, f.actor, id(), publicLeaseFixtureInput(f, pool, "8.8.8.9"), f.now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.store.DB.Exec("DELETE FROM controller_public_ip_active WHERE lease_id=?", lease.ID); e != nil {
		t.Fatal(e)
	}
	if _, _, _, e = f.store.AllocatePublicIP(ctx, f.config, f.actor, id(), publicLeaseFixtureInput(f, pool, ""), f.now); !errors.Is(e, ErrState) {
		t.Fatal("missing index silently freed reserved history", e)
	}
	var count int
	if e = f.store.DB.QueryRow("SELECT COUNT(*) FROM controller_public_ip_leases WHERE state='reserved'").Scan(&count); e != nil || count != 1 {
		t.Fatal("corrupt active index duplicated historical claim", count, e)
	}
}

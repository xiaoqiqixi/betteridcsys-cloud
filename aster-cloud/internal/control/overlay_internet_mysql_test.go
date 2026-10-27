package control

import (
	"aster/cloud/internal/identity"
	"aster/cloud/internal/overlayproto"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func (f *overlayFixture) approveInternetNAT(t *testing.T) (overlayproto.Gateway, []overlayproto.NATPolicy) {
	t.Helper()
	g, policies := f.approveNAT(t)
	g.AllowedPrefixes = []string{}
	f.config.OverlayClusters[0].Gateways = []overlayproto.Gateway{g}
	p := &f.config.OverlayClusters[0].NATProfiles[0]
	p.AllowInternetEgress = true
	p.PublicIPv4 = "8.8.8.8"
	p.AllowedSourceCIDRs = []string{}
	policies[0].InternetEgressEnabled = true
	policies[0].Forwardings = []overlayproto.NATForwarding{}
	if !f.config.Valid() {
		t.Fatal("Internet fixture root config invalid")
	}
	return g, policies
}

func assertOriginalOverlayJobs(t *testing.T, f overlayFixture) {
	t.Helper()
	for _, job := range f.jobs {
		saved, err := f.store.Lookup(context.Background(), job.OperationID)
		if err != nil || saved.RequestSHA != job.RequestSHA || saved.NodeRequestSHA != job.NodeRequestSHA || !bytes.Equal(saved.RequestJSON, job.RequestJSON) || !bytes.Equal(saved.NodeRequest, job.NodeRequest) {
			t.Fatal("Internet change rewrote original financial / node request", err)
		}
	}
}

func TestMySQLOverlayInternetPoliciesPersistPreserveDisableClearRecover(t *testing.T) {
	f := mysqlOverlayFixture(t)
	g, policies := f.approveInternetNAT(t)
	ctx := context.Background()
	in := OverlayEpochInput{ClusterID: f.vpc.ClusterID, Members: f.members, Gateways: []overlayproto.Gateway{g}, NATPolicies: &policies}
	op := id()
	if _, err := f.store.DB.Exec("CREATE TRIGGER overlay_internet_fail_audit BEFORE INSERT ON controller_audit FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='injected'"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.store.PlanOverlayEpoch(ctx, f.config, f.actor, op, in, f.now); err == nil {
		t.Fatal("Internet plan bypassed audit failure")
	}
	for _, table := range []string{"controller_overlay_epochs", "controller_overlay_tasks", "controller_overlay_members"} {
		var count int
		if err := f.store.DB.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != 0 {
			t.Fatal("Internet audit failure left partial transaction", table, count, err)
		}
	}
	if _, err := f.store.DB.Exec("DROP TRIGGER overlay_internet_fail_audit"); err != nil {
		t.Fatal(err)
	}
	epoch, replay, err := f.store.PlanOverlayEpoch(ctx, f.config, f.actor, op, in, f.now)
	if err != nil || replay || len(epoch.Snapshot.NATPolicies) != 1 || !epoch.Snapshot.NATPolicies[0].InternetEgressEnabled || len(epoch.Snapshot.Gateways[0].AllowedPrefixes) != 0 {
		t.Fatal("Internet-only plan not persisted", epoch, err)
	}
	before, _ := json.Marshal(epoch.Snapshot)
	if got, replay, err := f.store.PlanOverlayEpoch(ctx, f.config, f.actor, op, in, f.now); err != nil || !replay || got.SnapshotSHA256 != epoch.SnapshotSHA256 {
		t.Fatal("Internet exact replay rejected", err)
	}
	changedPolicies := append([]overlayproto.NATPolicy{}, policies...)
	changedPolicies[0].InternetEgressEnabled = false
	changed := in
	changed.NATPolicies = &changedPolicies
	if _, _, err = f.store.PlanOverlayEpoch(ctx, f.config, f.actor, op, changed, f.now); !errors.Is(err, ErrConflict) {
		t.Fatal("Internet off reused on intent", err)
	}
	w := f.worker(&overlayFakeRPC{})
	advanceOverlayFixture(t, w, op)
	options, err := f.store.OverlayOptions(ctx, f.config, f.vpc.ClusterID)
	if err != nil || !options.NATProfiles[0].AllowInternetEgress || options.LatestEpoch == nil || !options.LatestEpoch.Snapshot.NATPolicies[0].InternetEgressEnabled {
		t.Fatal("Internet approval / actual selection not projected", err)
	}
	// An old client must retain the active Internet policy, not silently drop it.
	keep := OverlayEpochInput{ClusterID: f.vpc.ClusterID, ExpectedEpoch: 1, Members: f.members, Gateways: []overlayproto.Gateway{g}}
	next, _, err := f.store.PlanOverlayEpoch(ctx, f.config, f.actor, id(), keep, f.now)
	if err != nil || !next.Snapshot.NATPolicies[0].InternetEgressEnabled {
		t.Fatal("omitted NAT erased Internet selection", err)
	}
	advanceOverlayFixture(t, w, next.ID)
	// UI may switch both SNAT and Internet off while retaining the empty gateway.
	disabled := append([]overlayproto.NATPolicy{}, policies...)
	disabled[0].SNATEnabled, disabled[0].InternetEgressEnabled = false, false
	recovery := OverlayRecoveryInput{ExpectedSnapshotSHA256: next.SnapshotSHA256, Replacement: &OverlayReplacementInput{Members: f.members, Gateways: []overlayproto.Gateway{g}, NATPolicies: &disabled}}
	disabledEpoch, replay, err := w.Recover(ctx, f.actor, next.ID, id(), recovery)
	if err != nil || replay || disabledEpoch.Snapshot.NATPolicies[0].InternetEgressEnabled || disabledEpoch.Snapshot.NATPolicies[0].SNATEnabled {
		t.Fatal("explicit Internet disable failed", err)
	}
	advanceOverlayFixture(t, w, disabledEpoch.ID)
	empty := []overlayproto.NATPolicy{}
	clear := OverlayEpochInput{ClusterID: f.vpc.ClusterID, ExpectedEpoch: disabledEpoch.Epoch, Members: f.members, Gateways: []overlayproto.Gateway{g}, NATPolicies: &empty}
	cleared, _, err := f.store.PlanOverlayEpoch(ctx, f.config, f.actor, id(), clear, f.now)
	if err != nil || len(cleared.Snapshot.NATPolicies) != 0 || cleared.Snapshot.Gateways[0].AllowedPrefixes == nil {
		t.Fatal("explicit clear lost inactive gateway", err)
	}
	advanceOverlayFixture(t, w, cleared.ID)
	// Recovery reuses a separate approved intent and immutable history, never
	// retroactively enables Internet on an older successful epoch.
	recovery.ExpectedSnapshotSHA256 = cleared.SnapshotSHA256
	recovery.Replacement.NATPolicies = &policies
	restored, _, err := w.Recover(ctx, f.actor, cleared.ID, id(), recovery)
	if err != nil || !restored.Snapshot.NATPolicies[0].InternetEgressEnabled {
		t.Fatal("Internet recovery not persisted", err)
	}
	advanceOverlayFixture(t, w, restored.ID)
	old, err := f.store.OverlayEpoch(ctx, epoch.ID)
	after, _ := json.Marshal(old.Snapshot)
	if err != nil || old.SnapshotSHA256 != epoch.SnapshotSHA256 || !bytes.Equal(before, after) {
		t.Fatal("historical Internet snapshot overwritten", err)
	}
	assertOriginalOverlayJobs(t, f)
}

func TestMySQLOverlayInternetRejectedApprovalHasNoMutation(t *testing.T) {
	cases := map[string]func(*overlayFixture, *[]overlayproto.NATPolicy){
		"approval_absent": func(f *overlayFixture, _ *[]overlayproto.NATPolicy) {
			f.config.OverlayClusters[0].NATProfiles[0].AllowInternetEgress = false
		},
		"snat_unapproved": func(f *overlayFixture, _ *[]overlayproto.NATPolicy) {
			f.config.OverlayClusters[0].NATProfiles[0].AllowSNAT = false
		},
		"non_public_source": func(f *overlayFixture, _ *[]overlayproto.NATPolicy) {
			f.config.OverlayClusters[0].NATProfiles[0].PublicIPv4 = "198.51.100.2"
		},
		"private_source": func(f *overlayFixture, _ *[]overlayproto.NATPolicy) {
			f.config.OverlayClusters[0].NATProfiles[0].PublicIPv4 = "10.0.0.1"
		},
		"snat_disabled":  func(_ *overlayFixture, policies *[]overlayproto.NATPolicy) { (*policies)[0].SNATEnabled = false },
		"root_withdrawn": func(f *overlayFixture, _ *[]overlayproto.NATPolicy) { f.config.OverlayClusters[0].NATProfiles = nil },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			f := mysqlOverlayFixture(t)
			g, policies := f.approveInternetNAT(t)
			var auditBefore int
			if err := f.store.DB.QueryRow("SELECT COUNT(*) FROM controller_audit").Scan(&auditBefore); err != nil {
				t.Fatal(err)
			}
			edit(&f, &policies)
			if _, _, err := f.store.PlanOverlayEpoch(context.Background(), f.config, f.actor, id(), OverlayEpochInput{ClusterID: f.vpc.ClusterID, Members: f.members, Gateways: []overlayproto.Gateway{g}, NATPolicies: &policies}, f.now); err == nil {
				t.Fatal("unapproved Internet plan persisted")
			}
			for _, table := range []string{"controller_overlay_epochs", "controller_overlay_tasks", "controller_overlay_members"} {
				var count int
				if err := f.store.DB.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != 0 {
					t.Fatal("rejected Internet plan mutated ledger", table, count, err)
				}
			}
			var auditAfter int
			if err := f.store.DB.QueryRow("SELECT COUNT(*) FROM controller_audit").Scan(&auditAfter); err != nil || auditAfter != auditBefore {
				t.Fatal("rejected Internet plan wrote audit", err)
			}
			assertOriginalOverlayJobs(t, f)
		})
	}
}

func TestMySQLOverlayInternetLostACKRequiresExactGETAndHonorsRevocation(t *testing.T) {
	f := mysqlOverlayFixture(t)
	g, policies := f.approveInternetNAT(t)
	ctx := context.Background()
	epoch, _, err := f.store.PlanOverlayEpoch(ctx, f.config, f.actor, id(), OverlayEpochInput{ClusterID: f.vpc.ClusterID, Members: f.members, Gateways: []overlayproto.Gateway{g}, NATPolicies: &policies}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	rpc := &overlayFakeRPC{lose: "prepare"}
	w := f.worker(rpc)
	unknown, err := w.Advance(ctx, epoch.ID)
	if !errors.Is(err, ErrUnavailable) || unknown.State != "uncertain" || len(rpc.posts) != 1 || !rpc.posts[0].Snapshot.NATPolicies[0].InternetEgressEnabled {
		t.Fatal("lost Internet ACK became success", err)
	}
	sent := rpc.posts[0]
	original := rpc.receipts[sent.OperationID]
	// A receipt for the same epoch/node/phase but a no-Internet snapshot is not
	// evidence for the requested Internet mode, even if every other field agrees.
	wrongSnapshot := epoch.Snapshot
	wrongSnapshot.NATPolicies = append([]overlayproto.NATPolicy{}, epoch.Snapshot.NATPolicies...)
	wrongSnapshot.NATPolicies[0].InternetEgressEnabled = false
	_, wrongSHA, err := overlayproto.CanonicalSnapshot(wrongSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	wrong := original
	wrong.SnapshotSHA256 = wrongSHA
	rpc.receipts[sent.OperationID] = wrong
	if _, err = w.Reconcile(ctx, epoch.ID); !errors.Is(err, ErrUnavailable) || len(rpc.posts) != 1 {
		t.Fatal("wrong Internet receipt adopted or POST repeated", err)
	}
	if _, err = w.Advance(ctx, epoch.ID); !errors.Is(err, ErrState) || len(rpc.posts) != 1 {
		t.Fatal("uncertain Internet write retried", err)
	}
	w.Config.OverlayClusters = append([]OverlayCluster{}, f.config.OverlayClusters...)
	w.Config.OverlayClusters[0].NATProfiles = append([]OverlayNATProfile{}, f.config.OverlayClusters[0].NATProfiles...)
	w.Config.OverlayClusters[0].NATProfiles[0].AllowInternetEgress = false
	rpc.receipts[sent.OperationID] = original
	if got, err := w.Reconcile(ctx, epoch.ID); err != nil || got.State != "pending" || len(rpc.posts) != 1 {
		t.Fatal("approved historical exact GET blocked by later withdrawal", err)
	}
	var auditBefore, auditAfter int
	if err := f.store.DB.QueryRow("SELECT COUNT(*) FROM controller_audit").Scan(&auditBefore); err != nil {
		t.Fatal(err)
	}
	tasksBefore, _ := f.store.OverlayTasks(ctx, epoch.ID)
	if _, err = w.Advance(ctx, epoch.ID); !errors.Is(err, ErrState) || len(rpc.posts) != 1 {
		t.Fatal("withdrawn Internet approval dispatched", err)
	}
	tasksAfter, _ := f.store.OverlayTasks(ctx, epoch.ID)
	before, _ := json.Marshal(tasksBefore)
	after, _ := json.Marshal(tasksAfter)
	if err := f.store.DB.QueryRow("SELECT COUNT(*) FROM controller_audit").Scan(&auditAfter); err != nil || auditAfter != auditBefore || !bytes.Equal(before, after) {
		t.Fatal("withdrawal consumed phase or rewrote receipt", err)
	}
	w.Config = f.config
	for i := 0; i < 5; i++ {
		if _, err = w.Advance(ctx, epoch.ID); err != nil {
			t.Fatal(err)
		}
	}
	if len(rpc.posts) != 6 || rpc.gets != 2 {
		t.Fatal("reconciled Internet phase was resent", len(rpc.posts), rpc.gets)
	}
	assertOriginalOverlayJobs(t, f)
}

func TestMySQLOverlayInternetConsoleUsesExistingTLSGrantsAndCSRF(t *testing.T) {
	f := mysqlOverlayFixture(t)
	g, policies := f.approveInternetNAT(t)
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	ident, err := identity.New(f.store.DB, identity.Config{Origin: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ident.Bootstrap(context.Background(), "internet-admin@example.invalid", "Internet fixture", []byte(consoleHTTPPassword)); err != nil {
		t.Fatal(err)
	}
	rpc := &overlayFakeRPC{}
	worker := f.worker(rpc)
	mux.Handle("/", (Console{Store: f.store, Config: f.config, Identity: ident, OverlayWorker: &worker}).Handler())
	admin := newConsoleHTTPBrowser(t, server)
	admin.login(t, "internet-admin@example.invalid")
	admin.createUser(t, "internet-network@example.invalid", "custom", []string{"nodes.read", "nodes.manage"})
	network := newConsoleHTTPBrowser(t, server)
	network.login(t, "internet-network@example.invalid")
	path := "/console/v1/overlays/epochs"
	body := consoleHTTPJSON(t, OverlayEpochInput{ClusterID: f.vpc.ClusterID, Members: f.members, Gateways: []overlayproto.Gateway{g}, NATPolicies: &policies})
	if status, _ := network.request(t, "POST", path, body, consoleHTTPOptions{idempotency: id()}); status != 403 {
		t.Fatal("Internet bypassed instance grant", status)
	}
	op := id()
	if status, _ := admin.request(t, "POST", path, body, consoleHTTPOptions{idempotency: op, csrf: ptr("")}); status != 403 {
		t.Fatal("Internet bypassed CSRF", status)
	}
	status, raw := admin.request(t, "POST", path, body, consoleHTTPOptions{idempotency: op})
	var result struct {
		Epoch OverlayEpoch `json:"epoch"`
	}
	if status != 202 || json.Unmarshal(raw, &result) != nil || result.Epoch.ID != op || !result.Epoch.Snapshot.NATPolicies[0].InternetEgressEnabled || len(rpc.posts) != 0 {
		t.Fatal("Internet API plan not confirmed / planning performed RPC", status, string(raw))
	}
	status, raw = network.request(t, "GET", "/console/v1/overlays/options?cluster_id="+f.vpc.ClusterID, "", consoleHTTPOptions{})
	var options OverlayOptions
	if status != 200 || json.Unmarshal(raw, &options) != nil || len(options.NATProfiles) != 1 || !options.NATProfiles[0].AllowInternetEgress || options.LatestEpoch == nil || options.LatestEpoch.ID != op {
		t.Fatal("Internet approval / epoch not readable", status, string(raw))
	}
	assertOriginalOverlayJobs(t, f)
}

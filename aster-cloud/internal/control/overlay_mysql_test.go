package control

import (
	"aster/cloud/internal/identity"
	"aster/cloud/internal/networking"
	"aster/cloud/internal/nodeproto"
	"aster/cloud/internal/overlayproto"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type overlayFixture struct {
	store   *SQLStore
	config  Config
	actor   string
	now     time.Time
	vpc     OverlayVPC
	members []OverlayMemberInput
	jobs    []Job
}

func mysqlOverlayFixture(t *testing.T) overlayFixture {
	t.Helper()
	s := consoleHTTPStore(t)
	ctx := context.Background()
	f := overlayFixture{store: s, actor: id(), members: []OverlayMemberInput{}, jobs: []Job{}}
	owner := id()
	var config Config
	for index := 0; index < 2; index++ {
		p, now := mysqlNode(t, s)
		f.now = now
		n := &networking.Store{DB: s.DB}
		v, _, e := n.CreateVPC(ctx, f.actor, id(), networking.CreateVPCInput{OwnerRef: owner, NodeID: p.ID, Name: "local fixture", CIDR: "10.25.0.0/24", VLANID: 25}, now)
		if e != nil {
			t.Fatal(e)
		}
		pool, _, e := n.CreatePool(ctx, f.actor, id(), networking.CreatePoolInput{NodeID: p.ID, VPCID: v.ID, Name: "local pool", CIDR: v.CIDR, Gateway: "10.25.0.1", Addresses: []string{fmt.Sprintf("10.25.0.%d", index+10)}, Enabled: true}, now)
		if e != nil {
			t.Fatal(e)
		}
		c := vpcTestConfig(p, pool.ID)
		c.NetworkProfiles[0].OwnerRef = owner
		c.NetworkProfiles[0].ID = fmt.Sprintf("vpc-node-%d", index)
		c.Presets[0].NetworkProfileID = c.NetworkProfiles[0].ID
		c.Presets[0].ID = fmt.Sprintf("ovs-vpc-node-%d-v1", index)
		caps := vpcTestCapabilities(p, now)
		caps.OVSNetworkProfiles = []string{c.NetworkProfiles[0].ID}
		if e = s.Heartbeat(ctx, p, caps, now, time.Minute); e != nil {
			t.Fatal(e)
		}
		r := mysqlVPCRequest(p, owner)
		c.NetworkProfiles[0].ConfigurationSHA256 = r.ConfigurationSHA256
		j, _, e := s.Admit(ctx, r, c.Candidates(r), now, time.Minute)
		if e != nil || j.State != "accepted" {
			t.Fatal(j, e)
		}
		if _, e = s.Claim(ctx, j.OperationID, p.Digest(), now, time.Minute); e != nil {
			t.Fatal(e)
		}
		if _, e = s.Complete(ctx, j.OperationID, "succeeded", now); e != nil {
			t.Fatal(e)
		}
		if index == 0 {
			config = c
			config.Nodes = []NodeProfile{}
			config.Presets = []Preset{}
			config.NetworkProfiles = []NetworkProfile{}
			config.OverlayClusters = []OverlayCluster{{ClusterID: "cluster-fixture", Profiles: []overlayproto.ProfilePin{}}}
		}
		config.Nodes = append(config.Nodes, p)
		config.Presets = append(config.Presets, c.Presets...)
		config.NetworkProfiles = append(config.NetworkProfiles, c.NetworkProfiles...)
		config.OverlayClusters[0].Profiles = append(config.OverlayClusters[0].Profiles, overlayproto.ProfilePin{NodeID: p.ID, ProfileID: c.NetworkProfiles[0].ID, ProfileSHA256: strings.Repeat(fmt.Sprint(index+1), 64)})
		f.jobs = append(f.jobs, j)
		f.members = append(f.members, OverlayMemberInput{InstanceID: j.InstanceID, Enabled: true})
	}
	if !config.Valid() {
		t.Fatal("invalid fixture config")
	}
	f.config = config
	v, _, e := s.CreateOverlayVPC(ctx, config, f.actor, id(), OverlayVPCInput{ClusterID: "cluster-fixture", OwnerRef: owner, Name: "global fixture", CIDR: "10.25.0.0/24", VNI: 501}, f.now)
	if e != nil {
		t.Fatal(e)
	}
	f.vpc = v
	for i := range f.members {
		f.members[i].VPCID = v.ID
	}
	for _, job := range f.jobs {
		task, e := nodeproto.DecodeTask(job.NodeRequest)
		if e != nil {
			t.Fatal(e)
		}
		f.config.OverlayClusters[0].Mappings = append(f.config.OverlayClusters[0].Mappings, OverlayMapping{NodeID: task.NodeID, LocalVPCID: task.Network.VPCID, VPCID: v.ID})
	}
	if !f.config.Valid() {
		t.Fatal("fixture mapping invalid")
	}
	return f
}
func (f overlayFixture) plan(t *testing.T) OverlayEpoch {
	t.Helper()
	e, replay, err := f.store.PlanOverlayEpoch(context.Background(), f.config, f.actor, id(), OverlayEpochInput{ClusterID: f.vpc.ClusterID, Members: f.members, Gateways: []overlayproto.Gateway{}}, f.now)
	if err != nil || replay {
		t.Fatal(err)
	}
	return e
}

type overlayFakeRPC struct {
	mu         sync.Mutex
	posts      []overlayproto.Task
	gets       int
	headGets   int
	receipts   map[string]overlayproto.Receipt
	heads      map[string]overlayproto.Head
	lose       string
	reject     string
	denyPrefix string
	node       string
	parent     *overlayFakeRPC
}

func (f *overlayFakeRPC) root() *overlayFakeRPC {
	if f.parent != nil {
		return f.parent
	}
	return f
}
func (f *overlayFakeRPC) SendOverlay(_ context.Context, t overlayproto.Task) (overlayproto.Receipt, error) {
	r := f.root()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.posts = append(r.posts, t)
	_, sha, _ := t.BytesAndDigest()
	out := overlayproto.Receipt{Protocol: overlayproto.Protocol, OperationID: t.OperationID, NodeID: t.NodeID, ClusterID: t.Snapshot.ClusterID, Epoch: t.Snapshot.Epoch, Phase: t.Phase, SnapshotSHA256: t.SnapshotSHA256, RequestSHA256: sha, Status: "succeeded", Code: "CONFIRMED"}
	if r.reject == t.Phase {
		out.Status = "rejected"
		out.Code = "DENIED"
	}
	for _, gateway := range t.Snapshot.Gateways {
		for _, prefix := range gateway.AllowedPrefixes {
			if prefix == r.denyPrefix {
				out.Status, out.Code = "rejected", "ROOT_POLICY_DENIED"
			}
		}
	}
	r.receipts[t.OperationID] = out
	r.heads[t.NodeID] = overlayproto.Head{NodeID: t.NodeID, ClusterID: t.Snapshot.ClusterID, Epoch: t.Snapshot.Epoch, SnapshotSHA256: t.SnapshotSHA256}
	if r.lose == t.Phase {
		r.lose = ""
		return overlayproto.Receipt{}, ErrUnavailable
	}
	return out, nil
}
func (f *overlayFakeRPC) LookupOverlay(_ context.Context, t overlayproto.Task) (overlayproto.Receipt, error) {
	r := f.root()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gets++
	out, ok := r.receipts[t.OperationID]
	if !ok {
		return out, ErrUnavailable
	}
	return out, nil
}
func (f *overlayFakeRPC) OverlayHead(_ context.Context, _ string) (overlayproto.Head, error) {
	r := f.root()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.headGets++
	h, ok := r.heads[f.node]
	if !ok {
		return overlayproto.Head{NodeID: f.node}, nil
	}
	return h, nil
}
func (f overlayFixture) worker(rpc *overlayFakeRPC) OverlayWorker {
	if rpc.receipts == nil {
		rpc.receipts = map[string]overlayproto.Receipt{}
	}
	if rpc.heads == nil {
		rpc.heads = map[string]overlayproto.Head{}
	}
	return OverlayWorker{Store: f.store, Config: f.config, Now: func() time.Time { return f.now }, RPC: func(_ context.Context, p NodeProfile) (OverlayRPC, error) {
		return &overlayFakeRPC{node: p.ID, parent: rpc}, nil
	}}
}
func TestMySQLOverlayFullBarriersAndImmutableFinancialBindings(t *testing.T) {
	f := mysqlOverlayFixture(t)
	ctx := context.Background()
	e := f.plan(t)
	rpc := &overlayFakeRPC{}
	w := f.worker(rpc)
	for i := 0; i < 6; i++ {
		got, err := w.Advance(ctx, e.ID)
		if err != nil {
			t.Fatal(i, err)
		}
		if i < 5 && got.State == "succeeded" {
			t.Fatal("premature cluster success")
		}
		if i == 5 && got.State != "succeeded" {
			t.Fatal("all confirmations missing", got.State)
		}
	}
	if len(rpc.posts) != 6 {
		t.Fatal(len(rpc.posts))
	}
	for i, p := range rpc.posts {
		if p.Phase != []string{"prepare", "prepare", "program", "program", "release", "release"}[i] {
			t.Fatal("barrier crossed", i, p.Phase)
		}
	}
	for _, j := range f.jobs {
		saved, err := f.store.Lookup(ctx, j.OperationID)
		if err != nil || saved.RequestSHA != j.RequestSHA || saved.NodeRequestSHA != j.NodeRequestSHA || string(saved.RequestJSON) != string(j.RequestJSON) || string(saved.NodeRequest) != string(j.NodeRequest) {
			t.Fatal("historical financial/node snapshot changed", err)
		}
	}
	f.members[0].Enabled = false
	next, _, err := f.store.PlanOverlayEpoch(ctx, f.config, f.actor, id(), OverlayEpochInput{ClusterID: f.vpc.ClusterID, ExpectedEpoch: 1, Members: f.members, Gateways: []overlayproto.Gateway{}}, f.now)
	if err != nil || next.Epoch != 2 || next.Snapshot.PreviousSHA256 != e.SnapshotSHA256 {
		t.Fatal("membership change not a new epoch", err)
	}
	if _, _, err = f.store.CreateOperation(ctx, f.config, f.actor, f.members[0].InstanceID, id(), OperationInput{Action: "shutdown"}, f.now); !errors.Is(err, ErrState) {
		t.Fatal("lifecycle raced epoch", err)
	}
}
func TestMySQLOverlayLostACKReadOnlyReconcileNoSilentPOST(t *testing.T) {
	f := mysqlOverlayFixture(t)
	e := f.plan(t)
	rpc := &overlayFakeRPC{lose: "prepare"}
	w := f.worker(rpc)
	got, err := w.Advance(context.Background(), e.ID)
	if !errors.Is(err, ErrUnavailable) || got.State != "uncertain" {
		t.Fatal(got.State, err)
	}
	for i := 0; i < 3; i++ {
		if _, err = w.Advance(context.Background(), e.ID); !errors.Is(err, ErrState) {
			t.Fatal("unknown retried", err)
		}
	}
	if len(rpc.posts) != 1 {
		t.Fatal("duplicate POST", len(rpc.posts))
	}
	got, err = w.Reconcile(context.Background(), e.ID)
	if err != nil || got.State != "pending" || rpc.gets != 1 || len(rpc.posts) != 1 {
		t.Fatal("GET reconcile failed", err)
	}
	for i := 0; i < 5; i++ {
		if _, err = w.Advance(context.Background(), e.ID); err != nil {
			t.Fatal(err)
		}
	}
}
func TestMySQLOverlayRecoveryPinsLaggingHeadsAndKeepsUnknownHistory(t *testing.T) {
	f := mysqlOverlayFixture(t)
	e := f.plan(t)
	rpc := &overlayFakeRPC{lose: "prepare"}
	w := f.worker(rpc)
	_, _ = w.Advance(context.Background(), e.ID)
	newID := id()
	in := OverlayRecoveryInput{ExpectedSnapshotSHA256: e.SnapshotSHA256}
	recovered, replay, err := w.Recover(context.Background(), f.actor, e.ID, newID, in)
	if err != nil || replay || recovered.Epoch != 2 || recovered.Recovery == nil {
		t.Fatal(err)
	}
	if rpc.headGets != 2 || len(rpc.posts) != 1 {
		t.Fatal("recovery preparation mutated nodes")
	}
	empty := 0
	for _, h := range recovered.Recovery.Heads {
		if h.Epoch == 0 {
			empty++
		}
	}
	if empty != 1 {
		t.Fatal("lagging empty node not pinned")
	}
	old, err := f.store.OverlayEpoch(context.Background(), e.ID)
	if err != nil || old.State != "superseded" || old.SupersededBy != newID || old.SnapshotSHA256 != e.SnapshotSHA256 {
		t.Fatal("history rewritten", err)
	}
	tasks, _ := f.store.OverlayTasks(context.Background(), e.ID)
	unknown := 0
	for _, task := range tasks {
		if task.State == "uncertain" {
			unknown++
		}
	}
	if unknown != 1 {
		t.Fatal("old unknown receipt converted to success")
	}
	again, replay, err := w.Recover(context.Background(), f.actor, e.ID, newID, in)
	if err != nil || !replay || again.SnapshotSHA256 != recovered.SnapshotSHA256 || rpc.headGets != 2 {
		t.Fatal("replay replaced pinned observed heads", err)
	}
	// Recovery itself can fail. A second explicit epoch must pin different old
	// heads rather than assuming all participants received its predecessor.
	rpc.lose = "prepare"
	_, _ = w.Advance(context.Background(), newID)
	third, _, err := w.Recover(context.Background(), f.actor, newID, id(), OverlayRecoveryInput{ExpectedSnapshotSHA256: recovered.SnapshotSHA256})
	if err != nil || third.Epoch != 3 {
		t.Fatal("second recovery blocked lagging node", err)
	}
	for i := 0; i < 6; i++ {
		if _, err = w.Advance(context.Background(), third.ID); err != nil {
			t.Fatal(err)
		}
	}
}
func TestMySQLOverlayAtomicAdmissionConflictAndFailureRollback(t *testing.T) {
	f := mysqlOverlayFixture(t)
	ctx := context.Background()
	in := OverlayEpochInput{ClusterID: f.vpc.ClusterID, Members: f.members, Gateways: []overlayproto.Gateway{}}
	op := id()
	if _, err := f.store.DB.Exec("CREATE TRIGGER overlay_fail_audit BEFORE INSERT ON controller_audit FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='injected'"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.store.PlanOverlayEpoch(ctx, f.config, f.actor, op, in, f.now); err == nil {
		t.Fatal("audit failure accepted")
	}
	for _, table := range []string{"controller_overlay_epochs", "controller_overlay_tasks", "controller_overlay_members"} {
		var n int
		if err := f.store.DB.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil || n != 0 {
			t.Fatal("partial transaction", table, n, err)
		}
	}
	if _, err := f.store.DB.Exec("DROP TRIGGER overlay_fail_audit"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.store.PlanOverlayEpoch(ctx, f.config, f.actor, op, in, f.now); err != nil {
		t.Fatal(err)
	}
	if _, replay, err := f.store.PlanOverlayEpoch(ctx, f.config, f.actor, op, in, f.now); err != nil || !replay {
		t.Fatal("idempotent replay rejected", err)
	}
	in.Members = append([]OverlayMemberInput{}, in.Members...)
	in.Members[0].Enabled = false
	if _, _, err := f.store.PlanOverlayEpoch(ctx, f.config, f.actor, op, in, f.now); !errors.Is(err, ErrConflict) {
		t.Fatal("same key changed member", err)
	}
	if _, _, err := f.store.PlanOverlayEpoch(ctx, f.config, id(), op, in, f.now); !errors.Is(err, ErrConflict) {
		t.Fatal("different actor adopted epoch", err)
	}
}
func TestMySQLOverlayConsoleRequiresNetworkAndInstanceGrants(t *testing.T) {
	f := mysqlOverlayFixture(t)
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	ident, err := identity.New(f.store.DB, identity.Config{Origin: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ident.Bootstrap(context.Background(), "overlay-admin@example.invalid", "Overlay fixture", []byte(consoleHTTPPassword)); err != nil {
		t.Fatal(err)
	}
	rpc := &overlayFakeRPC{}
	worker := f.worker(rpc)
	mux.Handle("/", (Console{Store: f.store, Config: f.config, Identity: ident, OverlayWorker: &worker}).Handler())
	admin := newConsoleHTTPBrowser(t, server)
	admin.login(t, "overlay-admin@example.invalid")
	admin.createUser(t, "overlay-read@example.invalid", "custom", []string{"nodes.read"})
	admin.createUser(t, "overlay-network@example.invalid", "custom", []string{"nodes.read", "nodes.manage"})
	read := newConsoleHTTPBrowser(t, server)
	read.login(t, "overlay-read@example.invalid")
	for _, path := range []string{"/console/v1/overlays/options?cluster_id=" + f.vpc.ClusterID, "/console/v1/overlays/vpcs/" + f.vpc.ID} {
		status, raw := read.request(t, "GET", path, "", consoleHTTPOptions{})
		if status != 200 {
			t.Fatal("safe read endpoint not wired", path, status, string(raw))
		}
		for _, value := range []string{f.config.Nodes[0].ClientKeyFile, f.config.Nodes[0].Endpoint, f.config.DSNFile} {
			if value != "" && strings.Contains(string(raw), value) {
				t.Fatal("options leaked private profile")
			}
		}
	}
	for _, path := range []string{"/console/v1/overlays/options?cluster_id=" + f.vpc.ClusterID + "&cluster_id=" + f.vpc.ClusterID, "/console/v1/overlays/options?cluster_id=" + f.vpc.ClusterID + "&host_path=/root", "/console/v1/overlays/vpcs/" + f.vpc.ID + "?cluster_id=" + f.vpc.ClusterID} {
		status, _ := read.request(t, "GET", path, "", consoleHTTPOptions{})
		if status == 200 {
			t.Fatal("ambiguous query accepted", path)
		}
	}
	network := newConsoleHTTPBrowser(t, server)
	network.login(t, "overlay-network@example.invalid")
	// An unknown VPC creation acknowledgement is resolved by the exact ID;
	// matching the complete original intent is possible without another POST.
	vpcKey := id()
	vpcInput := OverlayVPCInput{ClusterID: f.vpc.ClusterID, OwnerRef: f.vpc.OwnerRef, Name: "console-created", CIDR: "10.26.0.0/24", VNI: 502}
	vpcBody := consoleHTTPJSON(t, vpcInput)
	if status, _ := read.request(t, "POST", "/console/v1/overlays/vpcs", vpcBody, consoleHTTPOptions{idempotency: vpcKey}); status != 403 {
		t.Fatal("read-only created VPC")
	}
	if status, _ := network.request(t, "POST", "/console/v1/overlays/vpcs", vpcBody, consoleHTTPOptions{idempotency: vpcKey, csrf: ptr("")}); status != 403 {
		t.Fatal("VPC without CSRF")
	}
	if status, _ := network.request(t, "POST", "/console/v1/overlays/vpcs", vpcBody, consoleHTTPOptions{idempotency: vpcKey}); status != 201 {
		t.Fatal("network manager cannot create VPC", status)
	}
	statusVPC, rawVPC := network.request(t, "GET", "/console/v1/overlays/vpcs/"+vpcKey, "", consoleHTTPOptions{})
	var readVPC struct {
		VPC OverlayVPC `json:"vpc"`
	}
	if statusVPC != 200 || json.Unmarshal(rawVPC, &readVPC) != nil || readVPC.VPC.ID != vpcKey || readVPC.VPC.Name != vpcInput.Name || readVPC.VPC.CIDR != vpcInput.CIDR || readVPC.VPC.OwnerRef != vpcInput.OwnerRef || readVPC.VPC.VNI != vpcInput.VNI || readVPC.VPC.ClusterID != vpcInput.ClusterID {
		t.Fatal("exact create outcome not recoverable", statusVPC, string(rawVPC))
	}
	path := "/console/v1/overlays/epochs"
	body := consoleHTTPJSON(t, OverlayEpochInput{ClusterID: f.vpc.ClusterID, Members: f.members, Gateways: []overlayproto.Gateway{}})
	for _, b := range []*consoleHTTPBrowser{read, network} {
		if status, _ := b.request(t, "POST", path, body, consoleHTTPOptions{idempotency: id()}); status != 403 {
			t.Fatal("epoch did not require instance + node privileges", status)
		}
	}
	key := id()
	if status, _ := admin.request(t, "POST", path, body, consoleHTTPOptions{idempotency: key, csrf: ptr("")}); status != 403 {
		t.Fatal("missing CSRF accepted")
	}
	status, raw := admin.request(t, "POST", path, body, consoleHTTPOptions{idempotency: key})
	var result struct {
		Epoch OverlayEpoch `json:"epoch"`
	}
	if status != 202 || json.Unmarshal(raw, &result) != nil || result.Epoch.ID != key {
		t.Fatal("epoch route not wired", status, string(raw))
	}
	if len(rpc.posts) != 0 {
		t.Fatal("planning dispatched host commands")
	}
	for i := 0; i < 6; i++ {
		status, _ = admin.request(t, "POST", path+"/"+key+"/advance", "{}", consoleHTTPOptions{idempotency: key})
		if status != 202 {
			t.Fatal("advance route", i, status)
		}
	}
	if len(rpc.posts) != 6 {
		t.Fatal("real handler did not dispatch")
	}
	status, _ = read.request(t, "GET", path+"/"+key, "", consoleHTTPOptions{})
	if status != 200 {
		t.Fatal("read-only epoch inaccessible", status)
	}
}
func TestMySQLOverlayMigrationRejectsDriftAndReenters(t *testing.T) {
	s := consoleHTTPStore(t)
	if _, e := s.DB.Exec("DELETE FROM controller_schema WHERE version=7"); e != nil {
		t.Fatal(e)
	}
	if e := s.Migrate(context.Background()); e != nil {
		t.Fatal(e)
	}
	if _, e := s.DB.Exec("DROP INDEX controller_overlay_member_address ON controller_overlay_members"); e != nil {
		t.Fatal(e)
	}
	if e := s.Check(context.Background()); !errors.Is(e, networking.ErrConflict) {
		t.Fatal("lost IP uniqueness accepted", e)
	}
}

func TestMySQLOverlayNewCreateReservesEpochBeforeNodeDispatch(t *testing.T) {
	for _, kind := range []string{"billing", "console", "billing_after_delete", "billing_lost_ack", "console_lost_ack", "billing_nat"} {
		t.Run(kind, func(t *testing.T) {
			f := mysqlOverlayFixture(t)
			ctx := context.Background()
			var initial OverlayEpoch
			if kind == "billing_nat" {
				g, policies := f.approveNAT(t)
				var err error
				initial, _, err = f.store.PlanOverlayEpoch(ctx, f.config, f.actor, id(), OverlayEpochInput{ClusterID: f.vpc.ClusterID, Members: f.members, Gateways: []overlayproto.Gateway{g}, NATPolicies: &policies}, f.now)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				initial = f.plan(t)
			}
			rpc := &overlayFakeRPC{}
			worker := f.worker(rpc)
			for i := 0; i < 6; i++ {
				if _, e := worker.Advance(ctx, initial.ID); e != nil {
					t.Fatal(e)
				}
			}
			oldTask, _ := nodeproto.DecodeTask(f.jobs[0].NodeRequest)
			expectedMembers := 3
			if kind == "billing_after_delete" {
				op, _, e := f.store.CreateOperation(ctx, f.config, f.actor, oldTask.InstanceID, id(), OperationInput{Action: "delete", Confirmation: oldTask.InstanceID}, f.now)
				if e != nil {
					t.Fatal(e)
				}
				if _, e = f.store.ClaimOperation(ctx, op.ID, f.config, f.now); e != nil {
					t.Fatal(e)
				}
				if _, e = f.store.CompleteOperation(ctx, f.config, op.ID, "succeeded", nil, f.now); e != nil {
					t.Fatal(e)
				}
				expectedMembers = 2
			}

			addresses, _ := json.Marshal([]string{oldTask.Network.IPv4, "10.25.0.30"})
			if _, e := f.store.DB.Exec("UPDATE controller_network_pools SET addresses=? WHERE id=?", addresses, oldTask.Network.PoolID); e != nil {
				t.Fatal(e)
			}
			var opID, instance string
			var request []byte
			var financialBefore []byte
			if strings.HasPrefix(kind, "billing") {
				p, _ := f.config.Node(oldTask.NodeID)
				r := mysqlVPCRequest(p, oldTask.OwnerRef)
				financialBefore, _, _ = r.BytesAndDigest()
				j, replay, e := f.store.Admit(ctx, r, f.config.Candidates(r), f.now, time.Minute)
				if e != nil || replay || j.State != "accepted" {
					t.Fatal(j, e)
				}
				opID, instance, request = j.OperationID, j.InstanceID, j.NodeRequest
				if string(j.RequestJSON) != string(financialBefore) {
					t.Fatal("financial bytes rewritten")
				}
				if _, e = f.store.Claim(ctx, j.OperationID, p.Digest(), f.now, time.Minute); !errors.Is(e, ErrState) {
					t.Fatal("create dispatched before epoch", e)
				}
			} else {
				preset := ""
				for _, p := range f.config.Presets {
					if p.NodeID == oldTask.NodeID {
						preset = p.ID
					}
				}
				o, replay, e := f.store.CreateInstance(ctx, f.config, f.actor, id(), CreateInstanceInput{OwnerRef: oldTask.OwnerRef, Hostname: "reserved-vm", PresetID: preset}, f.now)
				if e != nil || replay {
					t.Fatal(e)
				}
				opID, instance, request = o.ID, o.InstanceID, o.Request
				if _, e = f.store.ClaimOperation(ctx, opID, f.config, f.now); !errors.Is(e, ErrState) {
					t.Fatal("staff create dispatched before epoch", e)
				}
			}
			task, e := nodeproto.DecodeTask(request)
			if e != nil || task.Protocol != nodeproto.NetworkProtocol || task.Network.IPv4 != "10.25.0.30" {
				t.Fatal("old immutable node/2 shape changed", e)
			}
			epochID := overlayproto.Digest([]byte("aster.overlay.admission/1:" + opID))[:32]
			epoch, e := f.store.OverlayEpoch(ctx, epochID)
			if e != nil || epoch.Epoch != 2 || len(epoch.Snapshot.Members) != expectedMembers {
				t.Fatal("future member not atomically reserved", e)
			}
			if kind == "billing_nat" {
				before, _ := json.Marshal(initial.Snapshot.NATPolicies)
				after, _ := json.Marshal(epoch.Snapshot.NATPolicies)
				if string(before) != string(after) {
					t.Fatal("automatic create rewrote existing NAT policy")
				}
			}
			found := false
			for _, m := range epoch.Snapshot.Members {
				if m.InstanceID == instance {
					found = m.Reserved && m.Enabled && m.NetworkSHA256 == task.Network.Digest() && m.LeaseID == task.Network.LeaseID
				}
			}
			if !found {
				t.Fatal("missing immutable future authorization")
			}
			worker.Config = f.config
			for i := 0; i < 6; i++ {
				if _, e := worker.Advance(ctx, epochID); e != nil {
					t.Fatal("reserved absent instance could not prepare", i, e)
				}
			}

			runner := NewOverlayRunner(worker)
			defer runner.Close()
			node := &overlayCreateRPC{drop: strings.HasSuffix(kind, "lost_ack"), tasks: map[string]nodeproto.NodeTask{}}
			nodeRPC := func(context.Context, NodeProfile) (NodeRPC, error) { return node, nil }
			runner.billing.RPC = nodeRPC
			runner.billing.Now = func() time.Time { return f.now }
			runner.operations.RPC = nodeRPC
			runner.operations.Now = func() time.Time { return f.now }
			category := "console"
			if strings.HasPrefix(kind, "billing") {
				category = "billing"
			}
			runner.dispatchCreate(ctx, category)
			want := "dispatched"
			if node.drop {
				want = "uncertain"
			}
			if category == "billing" {
				j, e := f.store.Lookup(ctx, opID)
				if e != nil || j.State != want {
					t.Fatal("async create outcome", j.State, e)
				}
			} else {
				o, e := f.store.Operation(ctx, opID)
				if e != nil || o.State != want {
					t.Fatal("async staff outcome", o.State, e)
				}
			}
			runner.dispatchCreate(ctx, category)
			if node.posts != 1 {
				t.Fatal("async/unknown create re-POSTed", node.posts)
			}
			runner.reconcileOutcome(ctx, category)
			if node.posts != 1 || node.gets != 1 {
				t.Fatal("missing GET-only async reconciliation", node.posts, node.gets)
			}
			if category == "billing" {
				j, e := f.store.Lookup(ctx, opID)
				if e != nil || j.State != "succeeded" {
					t.Fatal("asynchronous success never persisted", j.State, e)
				}
			} else {
				o, e := f.store.Operation(ctx, opID)
				if e != nil || o.State != "succeeded" {
					t.Fatal("asynchronous staff success never persisted", o.State, e)
				}
			}
			runner.reconcileOutcome(ctx, category)
			runner.dispatchCreate(ctx, category)
			if node.posts != 1 || node.gets != 1 {
				t.Fatal("terminal result retried")
			}

		})
	}
}

// Deterministic node/2 asynchronous result, not a libvirt/KVM acceptance claim.
type overlayCreateRPC struct {
	posts, gets int
	drop        bool
	tasks       map[string]nodeproto.NodeTask
}

func (r *overlayCreateRPC) Send(_ context.Context, raw []byte, sha string) (nodeproto.NodeResult, error) {
	task, e := nodeproto.DecodeTask(raw)
	if e != nil || nodeproto.Digest(raw) != sha {
		return nodeproto.NodeResult{}, ErrInput
	}
	r.posts++
	r.tasks[task.OperationID] = task
	if r.drop {
		return nodeproto.NodeResult{}, ErrUnavailable
	}
	return nodeproto.NodeResult{Protocol: task.Protocol, OperationID: task.OperationID, InstanceID: task.InstanceID, RequestSHA256: sha, Status: "accepted"}, nil
}
func (r *overlayCreateRPC) Lookup(_ context.Context, op, sha string) (nodeproto.NodeResult, error) {
	r.gets++
	task, ok := r.tasks[op]
	if !ok {
		return nodeproto.NodeResult{}, ErrNotFound
	}
	_, want, e := task.BytesAndDigest()
	if e != nil || sha != want {
		return nodeproto.NodeResult{}, ErrInput
	}
	return nodeproto.NodeResult{Protocol: task.Protocol, OperationID: op, InstanceID: task.InstanceID, RequestSHA256: sha, Status: "succeeded"}, nil
}
func (r *overlayCreateRPC) Capabilities(context.Context) (Capability, error) {
	return Capability{}, ErrUnavailable
}
func TestMySQLOverlaySuccessfulEpochCanRecoverLaterLifecycleFailure(t *testing.T) {
	f := mysqlOverlayFixture(t)
	ctx := context.Background()
	epoch := f.plan(t)
	rpc := &overlayFakeRPC{}
	w := f.worker(rpc)
	for n := 0; n < 6; n++ {
		if _, e := w.Advance(ctx, epoch.ID); e != nil {
			t.Fatal(e)
		}
	}
	oldTasks, e := f.store.OverlayTasks(ctx, epoch.ID)
	if e != nil {
		t.Fatal(e)
	}
	// A later failed power/lifecycle operation may have made the VM unknown even
	// though the cluster's earlier release receipts remain genuinely successful.
	if _, e = f.store.DB.Exec("UPDATE controller_instances SET state='unknown' WHERE id=?", f.members[0].InstanceID); e != nil {
		t.Fatal(e)
	}
	recovered, replay, e := w.Recover(ctx, f.actor, epoch.ID, id(), OverlayRecoveryInput{ExpectedSnapshotSHA256: epoch.SnapshotSHA256})
	if e != nil || replay || recovered.Epoch != 2 {
		t.Fatal("latest successful epoch permanently blocked recovery", e)
	}
	old, e := f.store.OverlayEpoch(ctx, epoch.ID)
	if e != nil || old.State != "superseded" || old.SnapshotSHA256 != epoch.SnapshotSHA256 || old.SupersededBy != recovered.ID {
		t.Fatal("old successful snapshot changed", e)
	}
	after, e := f.store.OverlayTasks(ctx, epoch.ID)
	if e != nil || len(after) != len(oldTasks) {
		t.Fatal(e)
	}
	for n := range after {
		if after[n].State != "succeeded" || string(after[n].Receipt) != string(oldTasks[n].Receipt) {
			t.Fatal("historical successful receipt rewritten")
		}
	}
	for n := 0; n < 6; n++ {
		if _, e := w.Advance(ctx, recovered.ID); e != nil {
			t.Fatal("explicit recovery phase", n, e)
		}
	}
	if _, _, e = w.Recover(ctx, f.actor, epoch.ID, id(), OverlayRecoveryInput{ExpectedSnapshotSHA256: epoch.SnapshotSHA256}); !errors.Is(e, ErrState) {
		t.Fatal("superseded epoch reclaimed", e)
	}
}

func TestMySQLOverlayRejectedGatewayCanRecoverWithApprovedReplacement(t *testing.T) {
	f := mysqlOverlayFixture(t)
	ctx := context.Background()
	gatewayID := id()
	gateway := overlayproto.Gateway{NodeID: f.config.Nodes[0].ID, InstanceID: gatewayID, InterfaceID: nodeproto.NetworkInterfaceID(gatewayID), OwnerRef: f.vpc.OwnerRef, VPCID: f.vpc.ID, IPv4: "10.25.0.1", MAC: nodeproto.NetworkMAC(f.config.Nodes[0].ID, gatewayID), AllowedPrefixes: []string{"192.0.2.0/24"}}
	approvedGateway := gateway
	approvedGateway.AllowedPrefixes = []string{"192.0.2.0/24", "172.20.0.0/16"}
	f.config.OverlayClusters[0].Gateways = []overlayproto.Gateway{approvedGateway}
	initial, _, err := f.store.PlanOverlayEpoch(ctx, f.config, f.actor, id(), OverlayEpochInput{ClusterID: f.vpc.ClusterID, Members: f.members, Gateways: []overlayproto.Gateway{gateway}}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	// A syntactically valid route can still be denied by the node's root policy.
	// This test exercises controller recovery, not a real router/OVS acceptance.
	rpc := &overlayFakeRPC{denyPrefix: "192.0.2.0/24"}
	worker := f.worker(rpc)
	_, _ = worker.Advance(ctx, initial.ID)
	failed, err := f.store.OverlayEpoch(ctx, initial.ID)
	if err != nil || failed.State != "rejected" {
		t.Fatal("fixture not denied", failed.State, err)
	}
	oldTasks, err := f.store.OverlayTasks(ctx, initial.ID)
	if err != nil {
		t.Fatal(err)
	}
	gateway.AllowedPrefixes = []string{"172.20.0.0/16"}
	in := OverlayRecoveryInput{ExpectedSnapshotSHA256: initial.SnapshotSHA256, Replacement: &OverlayReplacementInput{Members: append([]OverlayMemberInput{}, f.members...), Gateways: []overlayproto.Gateway{gateway}}}
	missing := in
	missing.Replacement = &OverlayReplacementInput{Members: in.Replacement.Members[:1], Gateways: in.Replacement.Gateways}
	if _, _, err = worker.Recover(ctx, f.actor, initial.ID, id(), missing); !errors.Is(err, ErrState) {
		t.Fatal("replacement omitted live member", err)
	}
	wrongMapping := f.config
	wrongMapping.OverlayClusters = append([]OverlayCluster{}, f.config.OverlayClusters...)
	wrongMapping.OverlayClusters[0].Mappings = append([]OverlayMapping{}, f.config.OverlayClusters[0].Mappings...)
	wrongMapping.OverlayClusters[0].Mappings[0].VPCID = id()
	badWorker := worker
	badWorker.Config = wrongMapping
	if _, _, err = badWorker.Recover(ctx, f.actor, initial.ID, id(), in); !errors.Is(err, ErrState) {
		t.Fatal("replacement bypassed root mapping", err)
	}
	// Audit failure must not supersede the original or leave any new task/member.
	newID := id()
	if _, err = f.store.DB.Exec("CREATE TRIGGER overlay_fail_recovery_audit BEFORE INSERT ON controller_audit FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='injected'"); err != nil {
		t.Fatal(err)
	}
	if _, _, err = worker.Recover(ctx, f.actor, initial.ID, newID, in); err == nil {
		t.Fatal("replacement ignored audit failure")
	}
	if _, err = f.store.OverlayEpoch(ctx, newID); !errors.Is(err, ErrNotFound) {
		t.Fatal("partial replacement epoch persisted", err)
	}
	if _, err = f.store.DB.Exec("DROP TRIGGER overlay_fail_recovery_audit"); err != nil {
		t.Fatal(err)
	}
	recovered, replay, err := worker.Recover(ctx, f.actor, initial.ID, newID, in)
	if err != nil || replay || recovered.Epoch != 2 || recovered.Snapshot.Gateways[0].AllowedPrefixes[0] != "172.20.0.0/16" {
		t.Fatal("corrected route stuck", err)
	}
	if recovered.Snapshot.PreviousSHA256 != initial.SnapshotSHA256 || recovered.Recovery.SnapshotSHA256 != initial.SnapshotSHA256 {
		t.Fatal("replacement lost exact predecessor")
	}
	for _, h := range recovered.Recovery.Heads {
		want, ok := rpc.heads[h.NodeID]
		if !ok {
			want = overlayproto.Head{NodeID: h.NodeID}
		}
		if h != want {
			t.Fatal("actual head replaced by guess")
		}
	}
	beforeGets := rpc.headGets
	reordered := in
	reordered.Replacement = &OverlayReplacementInput{Members: []OverlayMemberInput{in.Replacement.Members[1], in.Replacement.Members[0]}, Gateways: in.Replacement.Gateways}
	if again, replay, err := worker.Recover(ctx, f.actor, initial.ID, newID, reordered); err != nil || !replay || again.SnapshotSHA256 != recovered.SnapshotSHA256 || rpc.headGets != beforeGets {
		t.Fatal("canonical replay changed heads", err)
	}
	changed := in
	changed.Replacement = &OverlayReplacementInput{Members: in.Replacement.Members, Gateways: []overlayproto.Gateway{}}
	if _, _, err = worker.Recover(ctx, f.actor, initial.ID, newID, changed); !errors.Is(err, ErrConflict) {
		t.Fatal("same key changed routes", err)
	}
	for n := 0; n < 6; n++ {
		if _, err = worker.Advance(ctx, recovered.ID); err != nil {
			t.Fatal("replacement phase", n, err)
		}
	}
	done, err := f.store.OverlayEpoch(ctx, newID)
	if err != nil || done.State != "succeeded" {
		t.Fatal("replacement did not complete", err)
	}
	old, err := f.store.OverlayEpoch(ctx, initial.ID)
	if err != nil || old.SnapshotSHA256 != initial.SnapshotSHA256 || old.Snapshot.Gateways[0].AllowedPrefixes[0] != "192.0.2.0/24" {
		t.Fatal("old intent rewritten", err)
	}
	after, err := f.store.OverlayTasks(ctx, initial.ID)
	if err != nil || len(after) != len(oldTasks) {
		t.Fatal(err)
	}
	for i := range after {
		if after[i].State != oldTasks[i].State || string(after[i].Receipt) != string(oldTasks[i].Receipt) {
			t.Fatal("old rejected receipt rewritten")
		}
	}
	var audited int
	if err = f.store.DB.QueryRow("SELECT COUNT(*) FROM controller_audit WHERE action='overlay.recovery.replacement' AND target=?", newID+":"+recovered.SnapshotSHA256).Scan(&audited); err != nil || audited != 1 {
		t.Fatal("replacement SHA not audited", audited, err)
	}
	for _, before := range f.jobs {
		after, err := f.store.Lookup(ctx, before.OperationID)
		if err != nil || string(after.RequestJSON) != string(before.RequestJSON) || string(after.NodeRequest) != string(before.NodeRequest) {
			t.Fatal("replacement changed financial/node2 bytes", err)
		}
	}
}

func TestMySQLOverlayDispatchRoundRobinDoesNotStarveAnotherNode(t *testing.T) {
	for _, kind := range []string{"billing", "console"} {
		for _, blocked := range []string{"maintenance", "stale", "unknown"} {
			t.Run(kind+"/"+blocked, func(t *testing.T) {
				f := mysqlOverlayFixture(t)
				ctx := context.Background()
				epoch := f.plan(t)
				rpc := &overlayFakeRPC{}
				worker := f.worker(rpc)
				for n := 0; n < 6; n++ {
					if _, e := worker.Advance(ctx, epoch.ID); e != nil {
						t.Fatal(e)
					}
				}
				ops := []string{strings.Repeat("1", 32), strings.Repeat("2", 32)}
				for index, job := range f.jobs {
					old, _ := nodeproto.DecodeTask(job.NodeRequest)
					p, _ := f.config.Node(old.NodeID)
					addresses, _ := json.Marshal([]string{old.Network.IPv4, fmt.Sprintf("10.25.0.%d", 30+index)})
					if _, e := f.store.DB.Exec("UPDATE controller_network_pools SET addresses=? WHERE id=?", addresses, old.Network.PoolID); e != nil {
						t.Fatal(e)
					}
					if kind == "billing" {
						r := mysqlVPCRequest(p, old.OwnerRef)
						r.OperationID = ops[index]
						j, _, e := f.store.Admit(ctx, r, f.config.Candidates(r), f.now, time.Minute)
						if e != nil || j.State != "accepted" {
							t.Fatal("admission", e)
						}
					} else {
						preset := ""
						for _, v := range f.config.Presets {
							if v.NodeID == old.NodeID {
								preset = v.ID
							}
						}
						if _, _, e := f.store.CreateInstance(ctx, f.config, f.actor, ops[index], CreateInstanceInput{OwnerRef: old.OwnerRef, Hostname: fmt.Sprintf("round-robin-%d", index), PresetID: preset}, f.now); e != nil {
							t.Fatal(e)
						}
					}
					next := overlayproto.Digest([]byte("aster.overlay.admission/1:" + ops[index]))[:32]
					for n := 0; n < 6; n++ {
						if _, e := worker.Advance(ctx, next); e != nil {
							t.Fatal("reserve epoch", e)
						}
					}
				}
				switch blocked {
				case "maintenance":
					if _, e := f.store.DB.Exec("UPDATE controller_nodes SET maintenance=TRUE WHERE id=?", f.jobs[0].NodeID); e != nil {
						t.Fatal(e)
					}
				case "stale":
					if _, e := f.store.DB.Exec("UPDATE controller_nodes SET heartbeat_at=? WHERE id=?", f.now.Add(-time.Hour), f.jobs[0].NodeID); e != nil {
						t.Fatal(e)
					}
				case "unknown":
					// Existing separate unknown operation keeps its node busy.
					if _, e := f.store.DB.Exec("UPDATE controller_jobs SET state='uncertain' WHERE operation_id=?", f.jobs[0].OperationID); e != nil {
						t.Fatal(e)
					}
				}
				runner := NewOverlayRunner(worker)
				defer runner.Close()
				node := &overlayCreateRPC{tasks: map[string]nodeproto.NodeTask{}}
				factory := func(context.Context, NodeProfile) (NodeRPC, error) { return node, nil }
				runner.billing.RPC, runner.operations.RPC = factory, factory
				runner.billing.Now = func() time.Time { return f.now }
				runner.operations.Now = runner.billing.Now
				runner.dispatchCreate(ctx, "other")
				runner.dispatchCreate(ctx, kind)
				if node.posts != 0 {
					t.Fatal("blocked node sent")
				}
				runner.dispatchCreate(ctx, kind)
				if node.posts != 1 || node.tasks[ops[1]].OperationID != ops[1] {
					t.Fatal("blocked oldest starved eligible node", node.posts)
				}
				for n := 0; n < 5; n++ {
					runner.dispatchCreate(ctx, kind)
				}
				if node.posts != 1 {
					t.Fatal("unknown/async task re-POSTed")
				}
				if kind == "billing" {
					j, e := f.store.Lookup(ctx, ops[0])
					if e != nil || j.State != "accepted" {
						t.Fatal("failed claim consumed queue", e)
					}
				} else {
					j, e := f.store.Operation(ctx, ops[0])
					if e != nil || j.State != "accepted" {
						t.Fatal("failed claim consumed queue", e)
					}
				}
			})
		}
	}
}

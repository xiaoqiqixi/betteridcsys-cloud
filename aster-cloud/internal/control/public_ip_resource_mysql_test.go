package control

import (
	"aster/cloud/internal/identity"
	"aster/cloud/internal/nodeproto"
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
	"time"
)

func (r *publicVMRPC) Capabilities(context.Context) (Capability, error) {
	return Capability{}, ErrUnavailable
}

type publicVMRPC struct {
	mu      sync.Mutex
	tasks   map[string]nodeproto.NodeTask
	storage map[string]nodeproto.TypedStorageTask
	posts   map[string]int
	drop    bool
	status  string
}

func (r *publicVMRPC) Send(_ context.Context, raw []byte, sha string) (nodeproto.NodeResult, error) {
	t, e := nodeproto.DecodeTask(raw)
	if e != nil || nodeproto.Digest(raw) != sha {
		return nodeproto.NodeResult{}, ErrInput
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.tasks == nil {
		r.tasks = map[string]nodeproto.NodeTask{}
		r.posts = map[string]int{}
	}
	r.tasks[t.OperationID] = t
	r.posts[t.OperationID]++
	if r.drop {
		return nodeproto.NodeResult{}, ErrUnavailable
	}
	status := r.status
	if status == "" {
		status = "succeeded"
	}
	return nodeproto.NodeResult{Protocol: t.Protocol, OperationID: t.OperationID, RequestSHA256: sha, InstanceID: t.InstanceID, Status: status}, nil
}
func (r *publicVMRPC) Lookup(_ context.Context, op, sha string) (nodeproto.NodeResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.tasks[op]
	if !ok {
		return nodeproto.NodeResult{}, ErrNotFound
	}
	return nodeproto.NodeResult{Protocol: t.Protocol, OperationID: op, RequestSHA256: sha, InstanceID: t.InstanceID, Status: "succeeded"}, nil
}
func (r *publicVMRPC) SendStorage(_ context.Context, raw []byte, sha string) (nodeproto.StorageResult, error) {
	t, e := nodeproto.DecodeStorageTask(raw)
	if e != nil || nodeproto.Digest(raw) != sha {
		return nodeproto.StorageResult{}, ErrInput
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.storage == nil {
		r.storage = map[string]nodeproto.TypedStorageTask{}
	}
	r.storage[t.OperationID] = t
	if r.posts == nil {
		r.posts = map[string]int{}
	}
	r.posts[t.OperationID]++
	if r.drop {
		return nodeproto.StorageResult{}, ErrUnavailable
	}
	status := r.status
	if status == "" {
		status = "succeeded"
	}
	return publicVMStorageResult(t, sha, status), nil
}
func (r *publicVMRPC) LookupStorage(_ context.Context, op, sha string) (nodeproto.StorageResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.storage[op]
	if !ok {
		return nodeproto.StorageResult{}, ErrNotFound
	}
	return publicVMStorageResult(t, sha, "succeeded"), nil
}
func publicVMStorageResult(t nodeproto.TypedStorageTask, sha, status string) nodeproto.StorageResult {
	v := nodeproto.StorageResult{Protocol: t.Protocol, OperationID: t.OperationID, RequestSHA256: sha, Status: status, InstanceID: t.InstanceID, ArtifactID: t.ArtifactID, ManifestSHA256: t.ManifestSHA256, FenceToken: t.FenceToken, SourceNodeID: t.SourceNodeID, TargetNodeID: t.TargetNodeID, Items: []nodeproto.StorageArtifact{}}
	if t.Action == "migrate_prepare" {
		v.ManifestSHA256 = strings.Repeat("a", 64)
		v.FenceToken = strings.Repeat("b", 64)
		v.SourceNodeID = t.NodeID
	}
	return v
}

type publicVMFixture struct {
	store        *SQLStore
	config       Config
	node         NodeProfile
	actor, owner string
	now          time.Time
	pool         PublicIPPool
	resource     PublicIPResource
	rpc          *publicVMRPC
}

func mysqlPublicVMFixture(t *testing.T) publicVMFixture {
	t.Helper()
	s := consoleHTTPStore(t)
	p, now := mysqlNode(t, s)
	c := testConfig(p)
	c.Presets = []Preset{{ID: "direct-preset", NodeID: p.ID, Resources: testResources(p)}}
	root := DirectPublicProfile{ClusterID: "public-direct", NodeID: p.ID, ProfileID: nodeproto.DirectPublicProfile, ProfileSHA256: strings.Repeat("c", 64), CIDR: "8.8.4.0/24", GatewayIPv4: "8.8.4.1", PublicIPv4s: []string{"8.8.4.3", "8.8.4.4"}}
	c.DirectPublicProfiles = []DirectPublicProfile{root}
	if !c.Valid() {
		t.Fatal("invalid direct root")
	}
	caps := testCapabilities(p, now)
	caps.NetworkProfiles = append(caps.NetworkProfiles, nodeproto.DirectPublicCapability)
	caps.DirectPublicNetwork = &nodeproto.DirectPublicApproval{ProfileID: root.ProfileID, ProfileSHA256: root.ProfileSHA256, CIDR: root.CIDR, Gateway: root.GatewayIPv4, Addresses: root.PublicIPv4s}
	if e := s.Heartbeat(context.Background(), p, caps, now, time.Minute); e != nil {
		t.Fatal(e)
	}
	f := publicVMFixture{store: s, config: c, node: p, actor: id(), owner: id(), now: now, rpc: &publicVMRPC{}}
	var e error
	f.pool, _, _, e = s.CreatePublicIPPool(context.Background(), c, f.actor, id(), PublicIPPoolInput{root.ClusterID, "direct pool", root.CIDR, root.PublicIPv4s, true}, now)
	if e != nil {
		t.Fatal("pool", e)
	}
	f.resource, _, _, e = s.AllocatePublicIPResource(context.Background(), c, f.actor, id(), f.input("8.8.4.3"), now)
	if e != nil {
		t.Fatal("resource", e)
	}
	return f
}
func (f publicVMFixture) input(address string) PublicIPResourceInput {
	return PublicIPResourceInput{PoolID: f.pool.ID, OwnerRef: f.owner, Mode: "direct", NodeID: f.node.ID, ProfileID: nodeproto.DirectPublicProfile, Address: address}
}
func (f publicVMFixture) worker() OperationWorker {
	return OperationWorker{Store: f.store, Config: f.config, Now: func() time.Time { return f.now }, RPC: func(context.Context, NodeProfile) (NodeRPC, error) { return f.rpc, nil }, StorageRPC: func(context.Context, NodeProfile) (StorageRPC, error) { return f.rpc, nil }}
}
func (f publicVMFixture) create(t *testing.T) Operation {
	t.Helper()
	o, _, e := f.store.CreateInstance(context.Background(), f.config, f.actor, id(), CreateInstanceInput{Hostname: "direct-vm", OwnerRef: f.owner, PresetID: "direct-preset", PublicIPResourceID: f.resource.ID, PublicIPExpectedGeneration: publicVMGeneration(0)}, f.now)
	if e != nil {
		t.Fatal("direct create", e)
	}
	return o
}
func (f publicVMFixture) power(t *testing.T, instance, action string) Operation {
	t.Helper()
	in := OperationInput{Action: action}
	if dangerous(action) {
		in.Confirmation = instance
	}
	o, _, e := f.store.CreateOperation(context.Background(), f.config, f.actor, instance, id(), in, f.now)
	if e != nil {
		t.Fatal(action, e)
	}
	w := f.worker()
	o, e = w.Dispatch(context.Background(), o.ID)
	if e != nil {
		t.Fatal("power dispatch", e)
	}
	return o
}
func TestMySQLPublicVMDirectCreateDetachReclaimAndLegacyBypass(t *testing.T) {
	f := mysqlPublicVMFixture(t)
	ctx := context.Background()
	if _, _, e := f.store.CreateInstance(ctx, f.config, f.actor, id(), CreateInstanceInput{Hostname: "unreserved", OwnerRef: f.owner, PresetID: "direct-preset"}, f.now); !errors.Is(e, ErrState) {
		t.Fatal("managed bridge admitted legacy", e)
	}
	wrong := CreateInstanceInput{Hostname: "wrong-owner", OwnerRef: id(), PresetID: "direct-preset", PublicIPResourceID: f.resource.ID, PublicIPExpectedGeneration: publicVMGeneration(0)}
	if _, _, e := f.store.CreateInstance(ctx, f.config, f.actor, id(), wrong, f.now); !errors.Is(e, ErrState) {
		t.Fatal("cross owner", e)
	}
	o := f.create(t)
	r, e := f.store.PublicIPResource(ctx, f.config, f.resource.ID)
	if e != nil || r.BindingState != "pending" || r.BindingGeneration != 1 || r.Releasable {
		t.Fatal("ack became bound", r, e)
	}
	if _, _, _, e = f.store.ReleasePublicIPResource(ctx, f.config, f.actor, id(), r.ID, 1, f.now); !errors.Is(e, ErrState) {
		t.Fatal("pending reclaimed", e)
	}
	w := f.worker()
	if _, e = w.Dispatch(ctx, o.ID); e != nil {
		t.Fatal(e)
	}
	r, e = f.store.PublicIPResource(ctx, f.config, r.ID)
	if e != nil || r.BindingState != "bound" || r.InstanceID != o.InstanceID {
		t.Fatal(r, e)
	}
	f.power(t, o.InstanceID, "shutdown")
	r, op, replay, e := f.store.BindPublicIPResource(ctx, f.config, f.actor, id(), r.ID, "", true, 1, f.now)
	if e != nil || replay || r.BindingGeneration != 2 || r.BindingState != "pending" {
		t.Fatal("detach plan", r, e)
	}
	if _, e = w.Dispatch(ctx, op.ID); e != nil {
		t.Fatal(e)
	}
	r, e = f.store.PublicIPResource(ctx, f.config, r.ID)
	if e != nil || !r.Releasable || r.BindingState != "unbound" {
		t.Fatal("detach did not confirm", r, e)
	}
	released, _, _, e := f.store.ReleasePublicIPResource(ctx, f.config, f.actor, id(), r.ID, 2, f.now)
	if e != nil || released.State != "released" {
		t.Fatal(e)
	}
	if _, _, e = f.store.CreateOperation(ctx, f.config, f.actor, o.InstanceID, id(), OperationInput{Action: "start"}, f.now); !errors.Is(e, ErrState) {
		t.Fatal("node1 start resurrected detached address", e)
	}
	allocated, _, _, e := f.store.AllocatePublicIPResource(ctx, f.config, f.actor, id(), f.input(r.Address), f.now)
	if e != nil || allocated.ID == r.ID {
		t.Fatal("reclaim/reallocate", e)
	}
}
func TestMySQLPublicVMUnknownCreateOnlyGETCanResolve(t *testing.T) {
	f := mysqlPublicVMFixture(t)
	ctx := context.Background()
	o := f.create(t)
	f.rpc.drop = true
	w := f.worker()
	got, e := w.Dispatch(ctx, o.ID)
	if !errors.Is(e, ErrUnavailable) || got.State != "uncertain" {
		t.Fatal(got, e)
	}
	r, e := f.store.PublicIPResource(ctx, f.config, f.resource.ID)
	if e != nil || r.BindingState != "blocked" || r.Releasable {
		t.Fatal(r, e)
	}
	if _, _, _, e = f.store.ReleasePublicIPResource(ctx, f.config, f.actor, id(), r.ID, r.BindingGeneration, f.now); !errors.Is(e, ErrState) {
		t.Fatal("unknown released", e)
	}
	if _, e = w.Dispatch(ctx, o.ID); !errors.Is(e, ErrState) {
		t.Fatal("unknown POST replay", e)
	}
	if f.rpc.posts[o.ID] != 1 {
		t.Fatal("POST repeated")
	}
	if _, e = w.Reconcile(ctx, o.ID); e != nil {
		t.Fatal(e)
	}
	r, e = f.store.PublicIPResource(ctx, f.config, r.ID)
	if e != nil || r.BindingState != "bound" || f.rpc.posts[o.ID] != 1 {
		t.Fatal(r, e)
	}
}
func TestMySQLPublicVMFloatingMoveStaleGenerationAndCompleteRelease(t *testing.T) {
	f, g, policies, in := mysqlPublicIPFixture(t)
	ctx := context.Background()
	f.config.OverlayClusters[0].NATProfiles[0].AllowFloatingIP = true
	pool, _, _, e := f.store.CreatePublicIPPool(ctx, f.config, f.actor, id(), in, f.now)
	if e != nil {
		t.Fatal(e)
	}
	initial, _, e := f.store.PlanOverlayEpoch(ctx, f.config, f.actor, id(), OverlayEpochInput{ClusterID: f.vpc.ClusterID, Members: f.members, Gateways: []overlayproto.Gateway{g}, NATPolicies: &policies}, f.now)
	if e != nil {
		t.Fatal(e)
	}
	w := f.worker(&overlayFakeRPC{})
	advanceOverlayFixture(t, w, initial.ID)
	root := f.config.OverlayClusters[0].NATProfiles[0]
	input := PublicIPResourceInput{PoolID: pool.ID, OwnerRef: f.vpc.OwnerRef, Mode: "floating", NodeID: root.NodeID, ProfileID: root.ProfileID, VPCID: f.vpc.ID, Address: "8.8.8.9"}
	r, allocation, _, e := f.store.AllocatePublicIPResource(ctx, f.config, f.actor, id(), input, f.now)
	if e != nil {
		t.Fatal(e)
	}
	opID := id()
	r, binding, _, e := f.store.BindPublicIPResource(ctx, f.config, f.actor, opID, r.ID, f.members[0].InstanceID, false, 0, f.now)
	if e != nil || r.BindingGeneration != 1 || r.EpochID == "" {
		t.Fatal("bind", r, e)
	}
	if _, _, _, e = f.store.ReleasePublicIPResource(ctx, f.config, f.actor, id(), r.ID, 1, f.now); !errors.Is(e, ErrState) {
		t.Fatal("pending reclaimed", e)
	}
	advanceOverlayFixture(t, w, r.EpochID)
	r, e = f.store.PublicIPResource(ctx, f.config, r.ID)
	if e != nil || r.BindingState != "bound" {
		t.Fatal(r, e)
	}
	if _, _, _, e = f.store.BindPublicIPResource(ctx, f.config, f.actor, id(), r.ID, f.members[1].InstanceID, false, 0, f.now); !errors.Is(e, ErrState) {
		t.Fatal("stale editor moved address", e)
	}
	r, _, _, e = f.store.BindPublicIPResource(ctx, f.config, f.actor, id(), r.ID, f.members[1].InstanceID, false, 1, f.now)
	if e != nil || r.BindingGeneration != 2 {
		t.Fatal("cross-node move", e)
	}
	advanceOverlayFixture(t, w, r.EpochID)
	r, e = f.store.PublicIPResource(ctx, f.config, r.ID)
	if e != nil || r.InstanceID != f.members[1].InstanceID || r.BindingState != "bound" {
		t.Fatal(r, e)
	}
	replayed, again, replay, e := f.store.BindPublicIPResource(ctx, f.config, f.actor, opID, r.ID, f.members[0].InstanceID, false, 0, f.now)
	if e != nil || !replay || !reflect.DeepEqual(again, binding) || replayed.InstanceID != f.members[0].InstanceID {
		t.Fatal("fixed original result changed", e)
	}
	r, _, _, e = f.store.BindPublicIPResource(ctx, f.config, f.actor, id(), r.ID, "", true, 2, f.now)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 5; i++ {
		if _, e = w.Advance(ctx, r.EpochID); e != nil {
			t.Fatal(e)
		}
	}
	if _, _, _, e = f.store.ReleasePublicIPResource(ctx, f.config, f.actor, id(), r.ID, 3, f.now); !errors.Is(e, ErrState) {
		t.Fatal("partial detach reclaimed", e)
	}
	if _, e = w.Advance(ctx, r.EpochID); e != nil {
		t.Fatal(e)
	}
	if _, _, _, e = f.store.ReleasePublicIPResource(ctx, f.config, f.actor, id(), r.ID, 3, f.now); e != nil {
		t.Fatal(e)
	}
	fixed, e := f.store.PublicIPResourceOperation(ctx, f.actor, allocation.ID)
	if e != nil || fixed.Result.Resource.BindingGeneration != 0 || fixed.Result.Resource.BindingState != "unbound" {
		t.Fatal("allocation history rewritten", e)
	}
}
func TestMySQLPublicVMGlobalNATCollisionConcurrentLastAddressAndAuditRollback(t *testing.T) {
	f, g, policies, in := mysqlPublicIPFixture(t)
	_ = g
	_ = policies
	ctx := context.Background()
	f.config.OverlayClusters[0].NATProfiles[0].AllowFloatingIP = true
	in.Addresses = []string{"8.8.8.9"}
	pool, _, _, e := f.store.CreatePublicIPPool(ctx, f.config, f.actor, id(), in, f.now)
	if e != nil {
		t.Fatal(e)
	}
	root := f.config.OverlayClusters[0].NATProfiles[0]
	input := PublicIPResourceInput{PoolID: pool.ID, OwnerRef: f.vpc.OwnerRef, Mode: "floating", NodeID: root.NodeID, ProfileID: root.ProfileID, VPCID: f.vpc.ID}
	var wg sync.WaitGroup
	success := 0
	var mu sync.Mutex
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _, e := f.store.AllocatePublicIPResource(ctx, f.config, f.actor, id(), input, f.now)
			mu.Lock()
			defer mu.Unlock()
			if e == nil {
				success++
			} else if !errors.Is(e, ErrPublicIPCapacity) {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if success != 1 {
		t.Fatal("last IP allocated", success)
	}
	if _, _, _, e = f.store.AllocatePublicIP(ctx, f.config, f.actor, id(), publicLeaseFixtureInput(f, pool, "8.8.8.9"), f.now); !errors.Is(e, ErrConflict) {
		t.Fatal("NAT stole VM resource", e)
	}
	if _, e = f.store.DB.Exec("DELETE FROM controller_public_ip_active WHERE address='8.8.8.9'"); e != nil {
		t.Fatal(e)
	}
	if _, _, _, e = f.store.AllocatePublicIP(ctx, f.config, f.actor, id(), publicLeaseFixtureInput(f, pool, "8.8.8.9"), f.now); !errors.Is(e, ErrState) {
		t.Fatal("active corruption freed reserved VM", e)
	}
}
func TestMySQLPublicVMResourceAuditFailureRollsBackEveryClaim(t *testing.T) {
	f := mysqlPublicVMFixture(t)
	ctx := context.Background()
	if _, e := f.store.DB.Exec("CREATE TRIGGER public_vm_audit_refusal BEFORE INSERT ON controller_audit FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='fixture refusal'"); e != nil {
		t.Fatal(e)
	}
	key := id()
	if _, _, _, e := f.store.AllocatePublicIPResource(ctx, f.config, f.actor, key, f.input("8.8.4.4"), f.now); e == nil {
		t.Fatal("audit failure admitted")
	}
	for _, q := range []string{"SELECT COUNT(*) FROM controller_public_ip_resources WHERE id=?", "SELECT COUNT(*) FROM controller_public_ip_resource_operations WHERE id=?", "SELECT COUNT(*) FROM controller_public_ip_active WHERE lease_id=?"} {
		var n int
		if e := f.store.DB.QueryRow(q, key).Scan(&n); e != nil || n != 0 {
			t.Fatal("partial resource mutation", q, e, n)
		}
	}
}
func TestMySQLPublicVMResourceSchemaReentryAndDrift(t *testing.T) {
	f := mysqlPublicVMFixture(t)
	ctx := context.Background()
	if e := f.store.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	if _, e := f.store.DB.Exec("DROP INDEX controller_public_binding_revision ON controller_public_ip_bindings"); e != nil {
		t.Fatal(e)
	}
	if e := f.store.Check(ctx); e == nil {
		t.Fatal("missing unique binding history index accepted")
	}
	raw, _ := json.Marshal(f.resource)
	if !strings.Contains(string(raw), `"binding_generation":0`) {
		t.Fatal(string(raw))
	}
}

func (f *publicVMFixture) addTarget(t *testing.T) NodeProfile {
	t.Helper()
	p := f.node
	p.ID = "direct-target-" + id()[:12]
	p.Endpoint = "https://target.example.invalid"
	if e := f.store.RegisterNode(context.Background(), p); e != nil {
		t.Fatal(e)
	}
	root := f.config.DirectPublicProfiles[0]
	root.NodeID = p.ID
	f.config.Nodes = append(f.config.Nodes, p)
	f.config.DirectPublicProfiles = append(f.config.DirectPublicProfiles, root)
	caps := testCapabilities(p, f.now)
	caps.NetworkProfiles = append(caps.NetworkProfiles, nodeproto.DirectPublicCapability)
	caps.DirectPublicNetwork = &nodeproto.DirectPublicApproval{ProfileID: root.ProfileID, ProfileSHA256: root.ProfileSHA256, CIDR: root.CIDR, Gateway: root.GatewayIPv4, Addresses: root.PublicIPv4s}
	if e := f.store.Heartbeat(context.Background(), p, caps, f.now, time.Minute); e != nil {
		t.Fatal(e)
	}
	// Registration is fail closed: a healthy heartbeat alone must never open
	// admission. The fixture must perform the same explicit operator release
	// required by real nodes, rather than weakening the migration capacity gate.
	if e := f.store.Maintenance(context.Background(), p.ID, false); e != nil {
		t.Fatal(e)
	}
	if !f.config.Valid() {
		t.Fatal("target config")
	}
	return p
}

func TestMySQLPublicVMDirectMigrationRequiresExplicitTargetMaintenanceRelease(t *testing.T) {
	f := mysqlPublicVMFixture(t)
	target := f.addTarget(t)
	ctx := context.Background()
	created := f.create(t)
	w := f.worker()
	if _, e := w.Dispatch(ctx, created.ID); e != nil {
		t.Fatal(e)
	}
	f.power(t, created.InstanceID, "shutdown")
	if e := f.store.Maintenance(ctx, target.ID, true); e != nil {
		t.Fatal(e)
	}
	root := f.config.DirectPublicProfiles[1]
	caps := testCapabilities(target, f.now)
	caps.NetworkProfiles = append(caps.NetworkProfiles, nodeproto.DirectPublicCapability)
	caps.DirectPublicNetwork = &nodeproto.DirectPublicApproval{ProfileID: root.ProfileID, ProfileSHA256: root.ProfileSHA256, CIDR: root.CIDR, Gateway: root.GatewayIPv4, Addresses: root.PublicIPv4s}
	if e := f.store.Heartbeat(ctx, target, caps, f.now, time.Minute); e != nil {
		t.Fatal(e)
	}
	input := OperationInput{Action: "migrate_prepare", Confirmation: created.InstanceID, TargetNodeID: target.ID}
	key := id()
	if _, _, e := f.store.CreateOperation(ctx, f.config, f.actor, created.InstanceID, key, input, f.now); !errors.Is(e, ErrCapacity) {
		t.Fatal("heartbeat silently released target maintenance", e)
	}
	var intents int
	if e := f.store.DB.QueryRow("SELECT COUNT(*) FROM controller_public_ip_bindings WHERE id=?", key).Scan(&intents); e != nil || intents != 0 {
		t.Fatal("closed target left a migration intent", intents, e)
	}
	if e := f.store.Maintenance(ctx, target.ID, false); e != nil {
		t.Fatal(e)
	}
	if _, _, e := f.store.CreateOperation(ctx, f.config, f.actor, created.InstanceID, key, input, f.now); e != nil {
		t.Fatal("explicit healthy target release did not open admission", e)
	}
}

func TestMySQLPublicVMDirectMigrationFrozenGenerationBoundaries(t *testing.T) {
	for _, kind := range []string{"rejected_prepare_retry", "old_prepare_on_new_generation", "unknown_source_no_new_key"} {
		t.Run(kind, func(t *testing.T) {
			f := mysqlPublicVMFixture(t)
			target := f.addTarget(t)
			ctx := context.Background()
			created := f.create(t)
			w := f.worker()
			if _, e := w.Dispatch(ctx, created.ID); e != nil {
				t.Fatal(e)
			}
			f.power(t, created.InstanceID, "shutdown")
			input := OperationInput{Action: "migrate_prepare", Confirmation: created.InstanceID, TargetNodeID: target.ID}
			first, _, e := f.store.CreateOperation(ctx, f.config, f.actor, created.InstanceID, id(), input, f.now)
			if e != nil {
				t.Fatal("prepare plan", e)
			}
			if kind == "unknown_source_no_new_key" {
				f.rpc.drop = true
				if _, e = w.Dispatch(ctx, first.ID); !errors.Is(e, ErrUnavailable) {
					t.Fatal(e)
				}
				if _, _, e = f.store.CreateOperation(ctx, f.config, f.actor, created.InstanceID, id(), input, f.now); !errors.Is(e, ErrState) {
					t.Fatal("unknown source changed key", e)
				}
				if _, _, _, e = f.store.ReleasePublicIPResource(ctx, f.config, f.actor, id(), f.resource.ID, 2, f.now); !errors.Is(e, ErrState) {
					t.Fatal("unknown source freed address", e)
				}
				return
			}
			f.rpc.status = "rejected"
			if _, e = w.Dispatch(ctx, first.ID); e != nil {
				t.Fatal("known rejected proof", e)
			}
			r, e := f.store.PublicIPResource(ctx, f.config, f.resource.ID)
			if e != nil || r.BindingState != "bound" || r.BindingGeneration != 2 {
				t.Fatal("rejection changed incarnation or trapped retry", r, e)
			}
			second, _, e := f.store.CreateOperation(ctx, f.config, f.actor, created.InstanceID, id(), input, f.now)
			if e != nil {
				t.Fatal("known rejected prepare prevented new intent", e)
			}
			r, e = f.store.PublicIPResource(ctx, f.config, r.ID)
			if e != nil || r.BindingGeneration != 3 {
				t.Fatal(r, e)
			}
			if kind == "old_prepare_on_new_generation" {
				if _, e = f.store.DB.Exec("UPDATE controller_operations SET state='accepted' WHERE id=?", first.ID); e != nil {
					t.Fatal(e)
				}
				if _, e = f.store.ClaimOperation(ctx, first.ID, f.config, f.now); !errors.Is(e, ErrState) {
					t.Fatal("old prepare claimed new version", e)
				}
				if f.rpc.posts[first.ID] != 1 {
					t.Fatal("old request sent")
				}
				return
			}
			f.rpc.status = ""
			if _, e = w.Dispatch(ctx, second.ID); e != nil {
				t.Fatal("new prepare could not execute", e)
			}
			for _, action := range []string{"migrate_import", "migrate_activate"} {
				in := OperationInput{Action: action, ArtifactID: second.ArtifactID}
				if dangerous(action) {
					in.Confirmation = created.InstanceID
				}
				o, _, e := f.store.CreateOperation(ctx, f.config, f.actor, created.InstanceID, id(), in, f.now)
				if e != nil {
					t.Fatal(action, e)
				}
				task, e := nodeproto.DecodeStorageTask(o.Request)
				if e != nil || task.DirectPublic.Generation != 2 || task.DirectPublic.MAC != nodeproto.NetworkMAC(f.node.ID, created.InstanceID) {
					t.Fatal("guest incarnation was confused with UI version", task, e)
				}
				if _, e = w.Dispatch(ctx, o.ID); e != nil {
					t.Fatal(action, e)
				}
			}
			r, e = f.store.PublicIPResource(ctx, f.config, r.ID)
			if e != nil || r.BindingState != "bound" || r.BindingGeneration != 3 || r.NodeID != target.ID {
				t.Fatal("placement/intent mismatch", r, e)
			}
		})
	}
}
func TestMySQLPublicVMDirectAdoptAndReAdoptPreserveGuestIdentity(t *testing.T) {
	f := mysqlPublicVMFixture(t)
	ctx := context.Background()
	legacy := f.config
	legacy.DirectPublicProfiles = nil
	created, _, e := f.store.CreateInstance(ctx, legacy, f.actor, id(), CreateInstanceInput{Hostname: "legacy-adopt", OwnerRef: f.owner, PresetID: "direct-preset"}, f.now)
	if e != nil {
		t.Fatal(e)
	}
	w := f.worker()
	legacyWorker := w
	legacyWorker.Config = legacy
	if _, e = legacyWorker.Dispatch(ctx, created.ID); e != nil {
		t.Fatal(e)
	}
	shutdown, _, e := f.store.CreateOperation(ctx, legacy, f.actor, created.InstanceID, id(), OperationInput{Action: "shutdown"}, f.now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = legacyWorker.Dispatch(ctx, shutdown.ID); e != nil {
		t.Fatal(e)
	}
	r, o, _, e := f.store.BindPublicIPResource(ctx, f.config, f.actor, id(), f.resource.ID, created.InstanceID, false, 0, f.now)
	if e != nil {
		t.Fatal("adopt", e)
	}
	task, e := nodeproto.DecodeTask(mustOperation(t, f.store, o.ID).Request)
	if e != nil || task.Action != "public_adopt" || task.DirectPublic.MAC != nodeproto.NetworkMAC(f.node.ID, created.InstanceID) {
		t.Fatal(task, e)
	}
	if _, e = w.Dispatch(ctx, o.ID); e != nil {
		t.Fatal(e)
	}
	r, o, _, e = f.store.BindPublicIPResource(ctx, f.config, f.actor, id(), r.ID, "", true, 1, f.now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = w.Dispatch(ctx, o.ID); e != nil {
		t.Fatal(e)
	}
	r, o, _, e = f.store.BindPublicIPResource(ctx, f.config, f.actor, id(), r.ID, created.InstanceID, false, 2, f.now)
	if e != nil {
		t.Fatal("re-adopt", e)
	}
	again := mustOperation(t, f.store, o.ID)
	typed, e := nodeproto.DecodeTask(again.Request)
	if e != nil || typed.DirectPublic.MAC != task.DirectPublic.MAC || typed.DirectPublic.Generation <= task.DirectPublic.Generation {
		t.Fatal("re-adopt guessed guest identity", typed, e)
	}
	if _, e = w.Dispatch(ctx, o.ID); e != nil {
		t.Fatal(e)
	}
	r, e = f.store.PublicIPResource(ctx, f.config, r.ID)
	if e != nil || r.BindingState != "bound" || r.BindingGeneration != 3 {
		t.Fatal(r, e)
	}
}
func mustOperation(t *testing.T, s *SQLStore, id string) Operation {
	t.Helper()
	o, e := s.Operation(context.Background(), id)
	if e != nil {
		t.Fatal(e)
	}
	return o
}
func TestMySQLPublicVMOverlayRawInputCannotBypassResourceGeneration(t *testing.T) {
	f := mysqlOverlayFixture(t)
	ctx := context.Background()
	floats := []overlayproto.FloatingIP{}
	input := OverlayEpochInput{ClusterID: f.vpc.ClusterID, Members: f.members, Gateways: []overlayproto.Gateway{}, FloatingIPs: &floats}
	if _, _, e := f.store.PlanOverlayEpoch(ctx, f.config, f.actor, id(), input, f.now); !errors.Is(e, ErrInput) {
		t.Fatal("raw planning bypassed resource CAS", e)
	}
	recovery := OverlayRecoveryInput{ExpectedSnapshotSHA256: strings.Repeat("a", 64), Replacement: &OverlayReplacementInput{Members: f.members, Gateways: []overlayproto.Gateway{}, FloatingIPs: &floats}}
	if _, e := canonicalOverlayRecoveryInput(recovery); !errors.Is(e, ErrInput) {
		t.Fatal("raw recovery bypassed CAS", e)
	}
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	ident, e := identity.New(f.store.DB, identity.Config{Origin: server.URL})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ident.Bootstrap(ctx, "floating-cas-admin@example.invalid", "fixture", []byte(consoleHTTPPassword)); e != nil {
		t.Fatal(e)
	}
	mux.Handle("/", (Console{Store: f.store, Config: f.config, Identity: ident}).Handler())
	browser := newConsoleHTTPBrowser(t, server)
	browser.login(t, "floating-cas-admin@example.invalid")
	if status, _ := browser.request(t, "POST", "/console/v1/overlays/epochs", consoleHTTPJSON(t, input), consoleHTTPOptions{idempotency: id()}); status != 400 {
		t.Fatal("raw HTTP floating CAS bypass", status)
	}
	input.FloatingIPs = nil
	if status, _ := browser.request(t, "POST", "/console/v1/overlays/epochs", consoleHTTPJSON(t, input), consoleHTTPOptions{idempotency: id()}); status != 202 {
		t.Fatal("ordinary omitted floating compatibility", status)
	}

}

func TestMySQLPublicVMWithdrawnRootAllowsOnlyExactCleanup(t *testing.T) {
	f := mysqlPublicVMFixture(t)
	ctx := context.Background()
	created := f.create(t)
	w := f.worker()
	if _, e := w.Dispatch(ctx, created.ID); e != nil {
		t.Fatal(e)
	}
	f.config.DirectPublicProfiles = nil
	w = f.worker()
	shutdown, _, e := f.store.CreateOperation(ctx, f.config, f.actor, created.InstanceID, id(), OperationInput{Action: "shutdown"}, f.now)
	if e != nil {
		t.Fatal("withdrawal blocked stop", e)
	}
	if _, e = w.Dispatch(ctx, shutdown.ID); e != nil {
		t.Fatal(e)
	}
	if _, _, e = f.store.CreateOperation(ctx, f.config, f.actor, created.InstanceID, id(), OperationInput{Action: "start"}, f.now); !errors.Is(e, ErrState) {
		t.Fatal("withdrawn root started old address", e)
	}
	r, op, _, e := f.store.BindPublicIPResource(ctx, f.config, f.actor, id(), f.resource.ID, "", true, 1, f.now)
	if e != nil {
		t.Fatal("withdrawal trapped detach", e)
	}
	if _, e = w.Dispatch(ctx, op.ID); e != nil {
		t.Fatal(e)
	}
	r, e = f.store.PublicIPResource(ctx, f.config, r.ID)
	if e != nil || !r.Releasable {
		t.Fatal(r, e)
	}
	if _, _, _, e = f.store.ReleasePublicIPResource(ctx, f.config, f.actor, id(), r.ID, 2, f.now); e != nil {
		t.Fatal("withdrawal trapped reclaim", e)
	}
	if _, _, _, e = f.store.AllocatePublicIPResource(ctx, f.config, f.actor, id(), f.input(r.Address), f.now); !errors.Is(e, ErrState) {
		t.Fatal("withdrawn address reallocated", e)
	}
	if _, _, e = f.store.CreateOperation(ctx, f.config, f.actor, created.InstanceID, id(), OperationInput{Action: "start"}, f.now); !errors.Is(e, ErrState) {
		t.Fatal("node1 resurrected retired primary", e)
	}
}
func TestMySQLPublicVMRetireRequiresExactRealTargetReceipt(t *testing.T) {
	f := mysqlPublicVMFixture(t)
	target := f.addTarget(t)
	ctx := context.Background()
	created := f.create(t)
	w := f.worker()
	if _, e := w.Dispatch(ctx, created.ID); e != nil {
		t.Fatal(e)
	}
	f.power(t, created.InstanceID, "shutdown")
	prepare, _, e := f.store.CreateOperation(ctx, f.config, f.actor, created.InstanceID, id(), OperationInput{Action: "migrate_prepare", Confirmation: created.InstanceID, TargetNodeID: target.ID}, f.now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = w.Dispatch(ctx, prepare.ID); e != nil {
		t.Fatal(e)
	}
	for _, action := range []string{"migrate_import", "migrate_activate"} {
		input := OperationInput{Action: action, ArtifactID: prepare.ID}
		if dangerous(action) {
			input.Confirmation = created.ID
		}
		o, _, e := f.store.CreateOperation(ctx, f.config, f.actor, created.ID, id(), input, f.now)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = w.Dispatch(ctx, o.ID); e != nil {
			t.Fatal(e)
		}
	}
	migration, e := scanMigration(f.store.DB.QueryRowContext(ctx, "SELECT "+migrationColumns+" FROM controller_migrations WHERE id=?", prepare.ID))
	if e != nil {
		t.Fatal(e)
	}
	console := Console{Store: f.store}
	if e = console.retirementView(ctx, &migration); e != nil || migration.SourceRetirementState != "required" || migration.SourceRetirementOperationID != "" {
		t.Fatal("storage/2 retirement requirement was hidden", migration, e)
	}
	input := OperationInput{Action: "migrate_retire_source", Confirmation: created.ID, ArtifactID: prepare.ID}
	if _, _, e = f.store.CreateOperation(ctx, f.config, f.actor, created.ID, id(), input, f.now); !errors.Is(e, ErrState) {
		t.Fatal("browser bool/fake proof admitted", e)
	}
	retire, _, e := w.CreateRetireSource(ctx, f.actor, created.ID, id(), input)
	if e != nil {
		t.Fatal("verified target planning", e)
	}
	if e = console.retirementView(ctx, &migration); e != nil || migration.SourceRetirementState != "pending" || migration.SourceRetirementOperationID != retire.ID {
		t.Fatal("retirement ACK became success", migration, e)
	}
	typed, e := nodeproto.DecodeStorageTask(retire.Request)
	if e != nil || typed.RetireProof.IsZero() || typed.DirectPublic.NodeID != f.node.ID || typed.DirectPublic.Generation != 1 {
		t.Fatal(typed, e)
	}
	if _, e = f.store.ClaimOperation(ctx, retire.ID, f.config, f.now); e != nil {
		t.Fatal(e)
	}
	good := publicVMStorageResult(typed, retire.RequestSHA, "succeeded")
	bad := good
	bad.FenceToken = strings.Repeat("f", 64)
	if _, e = f.store.CompleteOperation(ctx, f.config, retire.ID, "succeeded", &bad, f.now); !errors.Is(e, ErrState) {
		t.Fatal("wrong fence released source", e)
	}
	var released bool
	if e = f.store.DB.QueryRow("SELECT released FROM controller_reservations WHERE operation_id=?", created.ID).Scan(&released); e != nil || released {
		t.Fatal("wrong receipt freed capacity", released, e)
	}
	if _, e = f.store.CompleteOperation(ctx, f.config, retire.ID, "succeeded", &good, f.now); e != nil {
		t.Fatal(e)
	}
	if e = f.store.DB.QueryRow("SELECT released FROM controller_reservations WHERE operation_id=?", created.ID).Scan(&released); e != nil || !released {
		t.Fatal("exact retirement failed", released, e)
	}
	if e = console.retirementView(ctx, &migration); e != nil || migration.SourceRetirementState != "succeeded" || migration.SourceRetirementOperationID != retire.ID {
		t.Fatal("exact retirement receipt was not projected", migration, e)
	}
}

func TestMySQLPublicVMConsoleGrantsCSRFOriginAndImmutableACK(t *testing.T) {
	f := mysqlPublicVMFixture(t)
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	ident, e := identity.New(f.store.DB, identity.Config{Origin: server.URL})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ident.Bootstrap(context.Background(), "vm-public-admin@example.invalid", "public VM fixture", []byte(consoleHTTPPassword)); e != nil {
		t.Fatal(e)
	}
	mux.Handle("/", (Console{Store: f.store, Config: f.config, Identity: ident}).Handler())
	admin := newConsoleHTTPBrowser(t, server)
	admin.login(t, "vm-public-admin@example.invalid")
	admin.createUser(t, "vm-public-read@example.invalid", "custom", []string{"nodes.read"})
	admin.createUser(t, "vm-public-network@example.invalid", "custom", []string{"nodes.read", "nodes.manage"})
	reader := newConsoleHTTPBrowser(t, server)
	reader.login(t, "vm-public-read@example.invalid")
	manager := newConsoleHTTPBrowser(t, server)
	manager.login(t, "vm-public-network@example.invalid")
	path := "/console/v1/public-ips/resources"
	key := id()
	body := consoleHTTPJSON(t, f.input("8.8.4.4"))
	for name, b := range map[string]*consoleHTTPBrowser{"reader": reader, "network_only": manager} {
		if status, _ := b.request(t, "POST", path, body, consoleHTTPOptions{idempotency: key}); status != 403 {
			t.Fatal(name, status)
		}
	}
	for name, options := range map[string]consoleHTTPOptions{"csrf": {idempotency: key, csrf: ptr("")}, "origin": {idempotency: key, origin: ptr("https://evil.invalid")}} {
		if status, _ := admin.request(t, "POST", path, body, options); status != 403 {
			t.Fatal(name, status)
		}
	}
	status, raw := admin.request(t, "POST", path, body, consoleHTTPOptions{idempotency: key})
	var accepted struct {
		Resource  PublicIPResource          `json:"resource"`
		Operation PublicIPResourceOperation `json:"operation"`
	}
	if status != 201 || json.Unmarshal(raw, &accepted) != nil || accepted.Resource.BindingGeneration != 0 || accepted.Resource.ID != key {
		t.Fatal(status, string(raw))
	}
	status, raw = admin.request(t, "GET", "/console/v1/public-ips/resource-operations/"+key, "", consoleHTTPOptions{})
	var ack struct {
		Operation PublicIPResourceOperation `json:"operation"`
	}
	if status != 200 || json.Unmarshal(raw, &ack) != nil || !reflect.DeepEqual(ack.Operation, accepted.Operation) {
		t.Fatal("ACK changed", status, string(raw))
	}
	if status, _ = reader.request(t, "GET", "/console/v1/public-ips/resource-operations/"+key, "", consoleHTTPOptions{}); status != 404 {
		t.Fatal("cross actor ACK leak", status)
	}
	for _, bad := range []string{`{}`, `{"expected_generation":null}`, `{"expected_generation":0,"Expected_Generation":1}`, `{"expected_generation":0,"expected_generation":1}`, `{"expected_generation":0,"node_id":"attacker"}`} {
		if status, _ = admin.request(t, "POST", path+"/"+key+"/release", bad, consoleHTTPOptions{idempotency: id()}); status != 400 {
			t.Fatal("loose release JSON", bad, status)
		}
	}
	if status, _ = admin.request(t, "POST", path+"/"+key+"/release", `{"expected_generation":1}`, consoleHTTPOptions{idempotency: id()}); status != 409 {
		t.Fatal("stale resource reclaim", status)
	}
	if status, _ = admin.request(t, "GET", path+"?owner_ref="+f.owner+"&instance_id="+id(), "", consoleHTTPOptions{}); status != 200 {
		t.Fatal("server-side filter unavailable", status)
	}
	for _, query := range []string{"?owner_ref=", "?pool_id=bad", "?cursor=", "?instance_id=" + id() + "&instance_id=" + id()} {
		if status, _ = admin.request(t, "GET", path+query, "", consoleHTTPOptions{}); status != 400 {
			t.Fatal("loose resource query", query, status)
		}
	}
}

func publicVMGeneration(n uint64) *uint64 { return &n }
func TestMySQLPublicVMCreationDraftGenerationCannotFollowAnotherBinding(t *testing.T) {
	f := mysqlPublicVMFixture(t)
	ctx := context.Background()
	draft := CreateInstanceInput{Hostname: "stale-draft", OwnerRef: f.owner, PresetID: "direct-preset", PublicIPResourceID: f.resource.ID, PublicIPExpectedGeneration: publicVMGeneration(0)}
	created := f.create(t)
	w := f.worker()
	if _, e := w.Dispatch(ctx, created.ID); e != nil {
		t.Fatal(e)
	}
	f.power(t, created.ID, "shutdown")
	r, detached, _, e := f.store.BindPublicIPResource(ctx, f.config, f.actor, id(), f.resource.ID, "", true, 1, f.now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = w.Dispatch(ctx, detached.ID); e != nil {
		t.Fatal(e)
	}
	staleID := id()
	if _, _, e = f.store.CreateInstance(ctx, f.config, f.actor, staleID, draft, f.now); !errors.Is(e, ErrState) {
		t.Fatal("stale creation stole rebound resource", e)
	}
	var n int
	if e = f.store.DB.QueryRow("SELECT COUNT(*) FROM controller_instances WHERE id=?", staleID).Scan(&n); e != nil || n != 0 {
		t.Fatal("stale draft left partial instance", e, n)
	}
	draft.PublicIPExpectedGeneration = publicVMGeneration(2)
	fresh, _, e := f.store.CreateInstance(ctx, f.config, f.actor, id(), draft, f.now)
	if e != nil {
		t.Fatal("fresh explicit choice rejected", e)
	}
	changed := draft
	changed.PublicIPExpectedGeneration = publicVMGeneration(r.BindingGeneration + 2)
	if _, _, e = f.store.CreateInstance(ctx, f.config, f.actor, fresh.ID, changed, f.now); !errors.Is(e, ErrConflict) {
		t.Fatal("same key silently changed creation generation", e)
	}
}

func TestMySQLPublicVMBindingAuditFailureRollsBackIntentAndGeneration(t *testing.T) {
	f := mysqlPublicVMFixture(t)
	ctx := context.Background()
	created := f.create(t)
	w := f.worker()
	if _, e := w.Dispatch(ctx, created.ID); e != nil {
		t.Fatal(e)
	}
	f.power(t, created.ID, "shutdown")
	if _, e := f.store.DB.Exec("CREATE TRIGGER public_vm_bind_refusal BEFORE INSERT ON controller_audit FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='fixture audit refusal'"); e != nil {
		t.Fatal(e)
	}
	key := id()
	if _, _, _, e := f.store.BindPublicIPResource(ctx, f.config, f.actor, key, f.resource.ID, "", true, 1, f.now); e == nil {
		t.Fatal("audit failure committed binding")
	}
	for _, q := range []string{"SELECT COUNT(*) FROM controller_public_ip_bindings WHERE id=?", "SELECT COUNT(*) FROM controller_public_ip_resource_operations WHERE id=?", "SELECT COUNT(*) FROM controller_operations WHERE id=?"} {
		var n int
		if e := f.store.DB.QueryRow(q, key).Scan(&n); e != nil || n != 0 {
			t.Fatal("partial binding committed", q, n, e)
		}
	}
	r, e := f.store.PublicIPResource(ctx, f.config, f.resource.ID)
	if e != nil || r.BindingState != "bound" || r.BindingGeneration != 1 || r.Releasable {
		t.Fatal("binding edit version changed on rollback", r, e)
	}
}

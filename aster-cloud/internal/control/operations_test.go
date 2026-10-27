package control

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestConsoleInputsNeverGuessDangerOrAcceptAmbiguousJSON(t *testing.T) {
	instance := strings.Repeat("1", 32)
	for _, a := range []string{"reboot", "force_off", "delete", "snapshot_restore", "snapshot_delete", "backup_restore", "backup_delete", "migrate_prepare", "migrate_transfer", "migrate_activate"} {
		in := OperationInput{Action: a}
		if strings.Contains(a, "restore") || strings.Contains(a, "delete") && a != "delete" || (a == "migrate_activate" || a == "migrate_transfer") {
			in.ArtifactID = strings.Repeat("2", 32)
		}
		if a == "migrate_prepare" {
			in.TargetNodeID = "target"
		}
		if in.valid(instance) {
			t.Fatal("danger did not require exact instance", a)
		}
		in.Confirmation = instance
		if !in.valid(instance) {
			t.Fatal("explicit confirmation rejected", a)
		}
	}
	for _, raw := range []string{`{"enabled":null}`, `{}`, `{"Enabled":false}`, `{"enabled":false,"Enabled":true}`, `{"enabled":false,"enabled":true}`, `{"enabled":false,"extra":1}`} {
		var in struct {
			Enabled bool `json:"enabled"`
		}
		if strict([]byte(raw), &in) {
			t.Fatal("ambiguous maintenance accepted", raw)
		}
	}
	for _, raw := range []string{`{"Action":"start","confirmation":""}`, `{"action":"start","Action":"delete","confirmation":""}`, `{"action":"start","confirmation":null}`, `{"action":"start"}`} {
		var in OperationInput
		if strict([]byte(raw), &in) {
			t.Fatal("ambiguous operation accepted", raw)
		}
	}
	for _, raw := range []string{`{"action":"start","confirmation":""}`, `{"action":"snapshot_restore","confirmation":"` + instance + `","artifact_id":"` + strings.Repeat("2", 32) + `"}`} {
		var in OperationInput
		if !strict([]byte(raw), &in) || !in.valid(instance) {
			t.Fatal("legitimate operation rejected", raw)
		}
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "https://console.invalid/console/v1/instances", nil)
	(Console{}).Handler().ServeHTTP(rr, req)
	if rr.Code != 503 {
		t.Fatal("missing identity must fail closed")
	}
}
func TestOperationDTOHasNoPrivateBindings(t *testing.T) {
	raw, _ := json.Marshal(Operation{ID: strings.Repeat("1", 32), Request: []byte("DO_NOT_LEAK"), RequestSHA: "SECRET_SHA", IntentSHA: "SECRET_INTENT", ProfileSHA: "SECRET_PROFILE", Protocol: "PRIVATE_PROTOCOL"})
	for _, secret := range []string{"DO_NOT_LEAK", "SECRET_", "PRIVATE_PROTOCOL", "request_json", "profile_sha256"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("private task leaked", string(raw))
		}
	}
}

type consoleRPC struct {
	posts, gets atomic.Int32
	mu          sync.Mutex
	tasks       map[string]nodeproto.NodeTask
	Drop        bool
	Status      string
}

func (r *consoleRPC) Send(_ context.Context, raw []byte, sha string) (nodeproto.NodeResult, error) {
	t, e := nodeproto.DecodeTask(raw)
	if e != nil || nodeproto.Digest(raw) != sha {
		return nodeproto.NodeResult{}, ErrInput
	}
	r.posts.Add(1)
	r.mu.Lock()
	if r.tasks == nil {
		r.tasks = map[string]nodeproto.NodeTask{}
	}
	r.tasks[t.OperationID] = t
	r.mu.Unlock()
	if r.Drop {
		return nodeproto.NodeResult{}, ErrUnavailable
	}
	status := r.Status
	if status == "" {
		status = "accepted"
	}
	return nodeproto.NodeResult{Protocol: nodeproto.Protocol, OperationID: t.OperationID, RequestSHA256: sha, Status: status, InstanceID: t.InstanceID}, nil
}
func (r *consoleRPC) Lookup(_ context.Context, op, sha string) (nodeproto.NodeResult, error) {
	r.gets.Add(1)
	r.mu.Lock()
	t, ok := r.tasks[op]
	r.mu.Unlock()
	if !ok {
		return nodeproto.NodeResult{}, ErrNotFound
	}
	return nodeproto.NodeResult{Protocol: nodeproto.Protocol, OperationID: op, RequestSHA256: sha, Status: "succeeded", InstanceID: t.InstanceID}, nil
}
func (r *consoleRPC) Capabilities(context.Context) (Capability, error) {
	return Capability{}, ErrUnavailable
}

type consoleStorageRPC struct {
	posts, gets atomic.Int32
	mu          sync.Mutex
	tasks       map[string]nodeproto.TypedStorageTask
	BadFence    bool
}

func (r *consoleStorageRPC) result(t nodeproto.TypedStorageTask, sha, status string) nodeproto.StorageResult {
	v := nodeproto.StorageResult{Protocol: nodeproto.StorageProtocol, OperationID: t.OperationID, RequestSHA256: sha, Status: status, InstanceID: t.InstanceID, ArtifactID: t.ArtifactID, Items: []nodeproto.StorageArtifact{}, ManifestSHA256: strings.Repeat("c", 64), SourceNodeID: t.SourceNodeID, TargetNodeID: t.TargetNodeID, FenceToken: t.FenceToken}
	if t.Action == "migrate_prepare" {
		v.SourceNodeID = t.NodeID
		v.FenceToken = strings.Repeat("d", 64)
	}
	if r.BadFence {
		v.FenceToken = ""
	}
	return v
}
func (r *consoleStorageRPC) SendStorage(_ context.Context, raw []byte, sha string) (nodeproto.StorageResult, error) {
	t, e := nodeproto.DecodeStorageTask(raw)
	if e != nil || nodeproto.Digest(raw) != sha {
		return nodeproto.StorageResult{}, ErrInput
	}
	r.posts.Add(1)
	r.mu.Lock()
	if r.tasks == nil {
		r.tasks = map[string]nodeproto.TypedStorageTask{}
	}
	r.tasks[t.OperationID] = t
	r.mu.Unlock()
	return r.result(t, sha, "accepted"), nil
}
func (r *consoleStorageRPC) LookupStorage(_ context.Context, op, sha string) (nodeproto.StorageResult, error) {
	r.gets.Add(1)
	r.mu.Lock()
	t, ok := r.tasks[op]
	r.mu.Unlock()
	if !ok {
		return nodeproto.StorageResult{}, ErrNotFound
	}
	return r.result(t, sha, "succeeded"), nil
}
func readyConsoleInstance(t *testing.T, s *SQLStore) (Config, NodeProfile, Instance, time.Time) {
	t.Helper()
	p, now := mysqlNode(t, s)
	c := testConfig(p)
	r := testRequest(p)
	j, _, e := s.Admit(context.Background(), r, c.Candidates(r), now, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Claim(context.Background(), j.OperationID, p.Digest(), now, time.Minute); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Complete(context.Background(), j.OperationID, "succeeded", now); e != nil {
		t.Fatal(e)
	}
	v, e := s.Instance(context.Background(), j.InstanceID)
	if e != nil {
		t.Fatal(e)
	}
	return c, p, v, now
}
func TestMySQLConsoleOperationsAreDurableAndDoNotFabricateFinancialOrders(t *testing.T) {
	s, _ := mysqlTestStore(t)
	ctx := context.Background()
	t.Run("admin_create_replay_and_shared_capacity", func(t *testing.T) {
		p, now := mysqlNode(t, s)
		c := testConfig(p)
		c.Presets = []Preset{{ID: "approved", NodeID: p.ID, Resources: testResources(p)}}
		actor, op := id(), id()
		in := CreateInstanceInput{Hostname: "manual-vm", OwnerRef: id(), PresetID: "approved"}
		o, replay, e := s.CreateInstance(ctx, c, actor, op, in, now)
		if e != nil || replay || o.InstanceID != op {
			t.Fatal("admin resource admission", e)
		}
		again, replay, e := s.CreateInstance(ctx, c, actor, op, in, now)
		if e != nil || !replay || again.RequestSHA != o.RequestSHA {
			t.Fatal("admin replay mutated intent", e)
		}
		changed := in
		changed.Hostname = "changed"
		if _, _, e = s.CreateInstance(ctx, c, actor, op, changed, now); !errors.Is(e, ErrConflict) {
			t.Fatal("changed intent accepted", e)
		}
		var count int
		s.DB.QueryRow("SELECT COUNT(*) FROM controller_jobs WHERE operation_id=? OR order_id=?", op, op).Scan(&count)
		if count != 0 {
			t.Fatal("admin created fictional financial job")
		}
		rpc := &consoleRPC{Status: "succeeded"}
		w := OperationWorker{Store: s, Config: c, RPC: func(context.Context, NodeProfile) (NodeRPC, error) { return rpc, nil }, Now: func() time.Time { return now }}
		result, e := w.Dispatch(ctx, op)
		if e != nil || result.State != "succeeded" || rpc.posts.Load() != 1 {
			t.Fatal("dispatch create", e, result.State)
		}
		v, e := s.Instance(ctx, op)
		if e != nil || v.State != "running" {
			t.Fatal("instance not confirmed", e)
		}
		req := testRequest(p)
		req.OperationID = op
		if _, _, e = s.Admit(ctx, req, c.Candidates(req), now, time.Minute); !errors.Is(e, ErrConflict) {
			t.Fatal("billing reused console namespace", e)
		}
		deleted := id()
		if _, _, e = s.CreateOperation(ctx, c, actor, op, deleted, OperationInput{Action: "delete", Confirmation: op}, now); e != nil {
			t.Fatal("delete staff-created resource admission", e)
		}
		if result, e = w.Dispatch(ctx, deleted); e != nil || result.State != "succeeded" {
			t.Fatal("delete staff-created resource confirmation", e, result.State)
		}
		var released bool
		if e = s.DB.QueryRow("SELECT released FROM controller_reservations WHERE operation_id=? AND node_id=?", op, p.ID).Scan(&released); e != nil || !released {
			t.Fatal("confirmed staff delete retained its reservation", e)
		}
	})
	t.Run("concurrent_dispatch_once_lost_reply_only_GET_and_node_queue", func(t *testing.T) {
		c, p, v, now := readyConsoleInstance(t, s)
		actor, op := id(), id()
		o, _, e := s.CreateOperation(ctx, c, actor, v.ID, op, OperationInput{Action: "shutdown", Confirmation: ""}, now)
		if e != nil {
			t.Fatal(e)
		}
		rpc := &consoleRPC{Drop: true}
		w := OperationWorker{Store: s, Config: c, RPC: func(context.Context, NodeProfile) (NodeRPC, error) { return rpc, nil }, Now: func() time.Time { return now }}
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() { defer wg.Done(); _, _ = w.Dispatch(ctx, o.ID) }()
		}
		wg.Wait()
		if rpc.posts.Load() != 1 {
			t.Fatal("duplicate POST", rpc.posts.Load())
		}
		o, e = s.Operation(ctx, o.ID)
		if e != nil || o.State != "uncertain" {
			t.Fatal("lost result not retained", e, o.State)
		}
		if _, _, e = s.CreateOperation(ctx, c, actor, v.ID, id(), OperationInput{Action: "start", Confirmation: ""}, now); !errors.Is(e, ErrState) {
			t.Fatal("unknown admitted competing mutation", e)
		}
		pending := testRequest(p)
		j, _, e := s.Admit(ctx, pending, c.Candidates(pending), now, time.Minute)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = s.Claim(ctx, j.OperationID, p.Digest(), now, time.Minute); !errors.Is(e, ErrState) {
			t.Fatal("legacy dispatcher ignored console worker", e)
		}
		if _, e = w.Dispatch(ctx, o.ID); !errors.Is(e, ErrState) {
			t.Fatal("unknown resent", e)
		}
		o, e = w.Reconcile(ctx, o.ID)
		if e != nil || o.State != "succeeded" || rpc.posts.Load() != 1 || rpc.gets.Load() != 1 {
			t.Fatal("not GET-only", e)
		}
		v, e = s.Instance(ctx, v.ID)
		if e != nil || v.State != "shutoff" {
			t.Fatal("power state stale", e)
		}
	})
	t.Run("offline_snapshot_bound_artifact_restore_and_delete", func(t *testing.T) {
		c, _, v, now := readyConsoleInstance(t, s)
		actor := id()
		if _, _, e := s.CreateOperation(ctx, c, actor, v.ID, id(), OperationInput{Action: "snapshot_create", Confirmation: ""}, now); !errors.Is(e, ErrState) {
			t.Fatal("snapshot of unconfirmed running disk", e)
		}
		if _, e := s.DB.Exec("UPDATE controller_instances SET state='shutoff' WHERE id=?", v.ID); e != nil {
			t.Fatal(e)
		}
		rpc := &consoleStorageRPC{}
		w := OperationWorker{Store: s, Config: c, StorageRPC: func(context.Context, NodeProfile) (StorageRPC, error) { return rpc, nil }, Now: func() time.Time { return now }}
		op := id()
		o, _, e := s.CreateOperation(ctx, c, actor, v.ID, op, OperationInput{Action: "snapshot_create", Confirmation: ""}, now)
		if e != nil || o.ArtifactID != op {
			t.Fatal("snapshot intent", e)
		}
		if _, e = w.Dispatch(ctx, op); e != nil {
			t.Fatal(e)
		}
		if _, e = w.Reconcile(ctx, op); e != nil {
			t.Fatal(e)
		}
		var state string
		if e = s.DB.QueryRow("SELECT state FROM controller_artifacts WHERE id=?", op).Scan(&state); e != nil || state != "ready" {
			t.Fatal("artifact not confirmed", e, state)
		}
		for _, action := range []string{"snapshot_restore", "snapshot_delete"} {
			next := id()
			if _, _, e = s.CreateOperation(ctx, c, actor, v.ID, next, OperationInput{Action: action, Confirmation: v.ID, ArtifactID: op}, now); e != nil {
				t.Fatal(action, e)
			}
			if _, e = w.Dispatch(ctx, next); e != nil {
				t.Fatal(e)
			}
			if _, e = w.Reconcile(ctx, next); e != nil {
				t.Fatal(e)
			}
		}
		if _, _, e = s.CreateOperation(ctx, c, actor, v.ID, id(), OperationInput{Action: "snapshot_restore", Confirmation: v.ID, ArtifactID: op}, now); !errors.Is(e, ErrState) {
			t.Fatal("deleted artifact restored", e)
		}
	})
	t.Run("cold_migration_fence_then_import_then_activate_and_target_reservation", func(t *testing.T) {
		c, source, v, now := readyConsoleInstance(t, s)
		target, _ := mysqlNode(t, s)
		c.Nodes = append(c.Nodes, target)
		if _, e := s.DB.Exec("UPDATE controller_instances SET state='shutoff' WHERE id=?", v.ID); e != nil {
			t.Fatal(e)
		}
		rpc := &consoleStorageRPC{}
		w := OperationWorker{Store: s, Config: c, StorageRPC: func(context.Context, NodeProfile) (StorageRPC, error) { return rpc, nil }, Now: func() time.Time { return now }}
		actor, prepare := id(), id()
		if _, _, e := s.CreateOperation(ctx, c, actor, v.ID, prepare, OperationInput{Action: "migrate_prepare", Confirmation: v.ID, TargetNodeID: target.ID}, now); e != nil {
			t.Fatal(e)
		}
		if _, _, e := s.CreateOperation(ctx, c, actor, v.ID, id(), OperationInput{Action: "migrate_activate", Confirmation: v.ID, ArtifactID: prepare}, now); !errors.Is(e, ErrState) {
			t.Fatal("activated without source fence", e)
		}
		if _, e := w.Dispatch(ctx, prepare); e != nil {
			t.Fatal(e)
		}
		if _, e := w.Reconcile(ctx, prepare); e != nil {
			t.Fatal(e)
		}
		transfer := id()
		input := OperationInput{Action: "migrate_transfer", Confirmation: v.ID, ArtifactID: prepare}
		bound, replay, e := s.CreateOperation(ctx, c, actor, v.ID, transfer, input, now)
		if e != nil || replay || bound.Protocol != TransferProtocol || bound.NodeID != target.ID {
			t.Fatal("transfer did not bind target", e, bound)
		}
		intent, e := DecodeTransferIntent(bound.Request)
		if e != nil || intent.SourceProfileSHA != source.Digest() || intent.Approval.TransferID != transfer || intent.Approval.SourceNodeID != source.ID || intent.Approval.SourceOperationID != prepare || intent.Approval.FenceToken != strings.Repeat("d", 64) {
			t.Fatal("transfer lost immutable source/fence binding", e)
		}
		if _, again, e := s.CreateOperation(ctx, c, actor, v.ID, transfer, input, now); e != nil || !again {
			t.Fatal("transfer replay changed intent", e)
		}
		if e = s.Maintenance(ctx, source.ID, true); e != nil {
			t.Fatal(e)
		}
		if _, e = s.ClaimOperation(ctx, transfer, c, now); !errors.Is(e, ErrCapacity) {
			t.Fatal("transfer ignored source maintenance", e)
		}
		if e = s.Maintenance(ctx, source.ID, false); e != nil {
			t.Fatal(e)
		}
		if _, e = s.DB.Exec("UPDATE controller_nodes SET heartbeat_at=? WHERE id=?", now.Add(-10*time.Minute), source.ID); e != nil {
			t.Fatal(e)
		}
		if _, e = s.ClaimOperation(ctx, transfer, c, now); !errors.Is(e, ErrCapacity) {
			t.Fatal("transfer ignored stale source", e)
		}
		if _, e = s.DB.Exec("UPDATE controller_nodes SET heartbeat_at=? WHERE id=?", now, source.ID); e != nil {
			t.Fatal(e)
		}
		if _, e = s.ClaimOperation(ctx, transfer, c, now); e != nil {
			t.Fatal("transfer claim", e)
		}
		// Both legacy billing and staff queues share the transfer's two-node slot.
		for _, node := range []NodeProfile{source, target} {
			request := testRequest(node)
			job, _, e := s.Admit(ctx, request, c.Candidates(request), now, time.Minute)
			if e != nil {
				t.Fatal("queue admission", e)
			}
			if _, e = s.Claim(ctx, job.OperationID, node.Digest(), now, time.Minute); !errors.Is(e, ErrState) {
				t.Fatal("transfer did not occupy both nodes", node.ID, e)
			}
		}
		// This test isolates SQL coordination. Real signed streams/receipts are
		// independently required by the relay's mTLS fault-injection tests.
		if _, e = s.CompleteOperation(ctx, c, transfer, "succeeded", nil, now); e != nil {
			t.Fatal("confirmed relay result", e)
		}
		migration, e := scanMigration(s.DB.QueryRowContext(ctx, "SELECT "+migrationColumns+" FROM controller_migrations WHERE id=?", prepare))
		if e != nil || migration.Phase != "transferred" {
			t.Fatal("transfer did not advance durable phase", e, migration.Phase)
		}
		for _, action := range []string{"migrate_import", "migrate_activate"} {
			op := id()
			in := OperationInput{Action: action, Confirmation: "", ArtifactID: prepare}
			if action == "migrate_activate" {
				in.Confirmation = v.ID
			}
			o, _, e := s.CreateOperation(ctx, c, actor, v.ID, op, in, now)
			if e != nil || o.NodeID != target.ID {
				t.Fatal(action, e)
			}
			if _, e = w.Dispatch(ctx, op); e != nil {
				t.Fatal(e)
			}
			if _, e = w.Reconcile(ctx, op); e != nil {
				t.Fatal(e)
			}
		}
		got, e := s.Instance(ctx, v.ID)
		if e != nil || got.NodeID != target.ID || got.Resources.ComputeNodeID != target.ID || got.State != "running" {
			t.Fatal("target not committed", e, got)
		}
		var retained int
		if e = s.DB.QueryRow("SELECT COUNT(*) FROM controller_reservations WHERE operation_id=? AND node_id=? AND released=FALSE", prepare, target.ID).Scan(&retained); e != nil || retained != 1 {
			t.Fatal("target capacity prematurely released", e)
		}
	})
}

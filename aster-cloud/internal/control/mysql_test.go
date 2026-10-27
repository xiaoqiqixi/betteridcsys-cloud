package control

import (
	"aster/billing/controllerapi"
	"aster/cloud/internal/nodeproto"
	"context"
	"database/sql"
	"errors"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

func mysqlTestStore(t *testing.T) (*SQLStore, string) {
	t.Helper()
	dsn := os.Getenv("ASTER_CLOUD_TEST_DSN")
	if dsn == "" {
		fallback := os.Getenv("ASTER_MYSQL_TEST_DSN")
		if fallback == "" {
			t.Skip("ASTER_CLOUD_TEST_DSN unset: real MySQL controller tests not run")
		}
		c, e := mysql.ParseDSN(fallback)
		if e != nil || c.DBName != "aster_ci_test" {
			t.Fatal("CI fallback requires exact isolated aster_ci_test database")
		}
		c.MultiStatements = false
		admin, e := sql.Open("mysql", c.FormatDSN())
		if e != nil {
			t.Fatal("CI MySQL connection unavailable")
		}
		name := "aster_cloud_test_" + id()[:16]
		if _, e = admin.Exec("CREATE DATABASE `" + name + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin"); e != nil {
			admin.Close()
			t.Fatal("cannot create independent controller test database")
		}
		t.Cleanup(func() { admin.Exec("DROP DATABASE `" + name + "`"); admin.Close() })
		c.DBName = name
		dsn = c.FormatDSN()
	}
	c, e := mysql.ParseDSN(dsn)
	if e != nil || !strings.Contains(c.DBName, "_test") {
		t.Fatal("refuse non-test controller database")
	}
	s, e := OpenDSN(dsn)
	if e != nil {
		t.Fatal("invalid isolated MySQL controller DSN")
	}
	t.Cleanup(func() { s.DB.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if e = s.Migrate(ctx); e != nil {
		t.Fatal("controller migration failed", e)
	}
	return s, dsn
}
func mysqlNode(t *testing.T, s *SQLStore) (NodeProfile, time.Time) {
	t.Helper()
	p := testProfile()
	p.ID = "node-" + id()[:16]
	now := time.Now().UTC().Truncate(time.Microsecond)
	ctx := context.Background()
	if e := s.RegisterNode(ctx, p); e != nil {
		t.Fatal(e)
	}
	if e := s.Heartbeat(ctx, p, testCapabilities(p, now), now, time.Minute); e != nil {
		t.Fatal(e)
	}
	if e := s.Maintenance(ctx, p.ID, false); e != nil {
		t.Fatal(e)
	}
	return p, now
}

func TestMySQLControllerPersistenceAndFailureBoundaries(t *testing.T) {
	s, dsn := mysqlTestStore(t)
	ctx := context.Background()
	t.Run("persistent_replay_order_binding_and_audit", func(t *testing.T) {
		p, now := mysqlNode(t, s)
		r := testRequest(p)
		j, replay, e := s.Admit(ctx, r, testConfig(p).Candidates(r), now, time.Minute)
		if e != nil || replay || j.State != "accepted" {
			t.Fatal("initial acceptance", e, j.State)
		}
		again, replay, e := s.Admit(ctx, r, testConfig(p).Candidates(r), now, time.Minute)
		if e != nil || !replay || again.InstanceID != j.InstanceID || again.RequestSHA != j.RequestSHA {
			t.Fatal("replay changed binding", e)
		}
		changed := r
		changed.Hostname = "different"
		if _, _, e = s.Admit(ctx, changed, testConfig(p).Candidates(changed), now, time.Minute); !errors.Is(e, ErrConflict) {
			t.Fatal("different request accepted")
		}
		changed = r
		changed.OperationID = id()
		if _, _, e = s.Admit(ctx, changed, testConfig(p).Candidates(changed), now, time.Minute); !errors.Is(e, ErrConflict) {
			t.Fatal("same order second operation accepted")
		}
		reopened, e := OpenDSN(dsn)
		if e != nil {
			t.Fatal(e)
		}
		defer reopened.DB.Close()
		saved, e := reopened.Lookup(ctx, r.OperationID)
		if e != nil || saved.InstanceID != j.InstanceID || !saved.Result().Matches(r) {
			t.Fatal("restart lost result", e)
		}
		var jobs, reservations, audits int
		s.DB.QueryRow("SELECT COUNT(*) FROM controller_jobs WHERE operation_id=?", r.OperationID).Scan(&jobs)
		s.DB.QueryRow("SELECT COUNT(*) FROM controller_reservations WHERE operation_id=?", r.OperationID).Scan(&reservations)
		s.DB.QueryRow("SELECT COUNT(*) FROM controller_audit WHERE action='provisioning.accepted' AND target=?", r.OperationID).Scan(&audits)
		if jobs != 1 || reservations != 1 || audits != 1 {
			t.Fatal("non-atomic/duplicate persistence", jobs, reservations, audits)
		}
	})
	t.Run("parallel_capacity_is_atomic", func(t *testing.T) {
		p, now := mysqlNode(t, s)
		var accepted atomic.Int32
		var failures atomic.Int32
		var wg sync.WaitGroup
		for range 16 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r := testRequest(p)
				j, _, e := s.Admit(ctx, r, testConfig(p).Candidates(r), now, time.Minute)
				if e == nil && j.State == "accepted" {
					accepted.Add(1)
				} else if !errors.Is(e, ErrCapacity) {
					failures.Add(1)
				}
			}()
		}
		wg.Wait()
		if accepted.Load() != 4 || failures.Load() != 0 {
			t.Fatal("capacity oversold or atomic admission failed", accepted.Load(), failures.Load())
		}
		var cpu int
		s.DB.QueryRow("SELECT SUM(cpu) FROM controller_reservations WHERE node_id=? AND released=FALSE", p.ID).Scan(&cpu)
		if cpu != 8 {
			t.Fatal("wrong reserved CPU", cpu)
		}
	})
	t.Run("maintenance_expired_heartbeat_and_absence_refuse", func(t *testing.T) {
		p, now := mysqlNode(t, s)
		r := testRequest(p)
		if e := s.Maintenance(ctx, p.ID, true); e != nil {
			t.Fatal(e)
		}
		if _, _, e := s.Admit(ctx, r, testConfig(p).Candidates(r), now, time.Minute); !errors.Is(e, ErrCapacity) {
			t.Fatal("maintenance accepted")
		}
		if e := s.Maintenance(ctx, p.ID, false); e != nil {
			t.Fatal(e)
		}
		if _, _, e := s.Admit(ctx, r, testConfig(p).Candidates(r), now.Add(61*time.Second), time.Minute); !errors.Is(e, ErrCapacity) {
			t.Fatal("expired heartbeat accepted")
		}
		never := p
		never.ID = "node-" + id()[:16]
		if e := s.RegisterNode(ctx, never); e != nil {
			t.Fatal(e)
		}
		req := testRequest(never)
		if _, _, e := s.Admit(ctx, req, testConfig(never).Candidates(req), now, time.Minute); !errors.Is(e, ErrCapacity) {
			t.Fatal("never observed node accepted")
		}
	})
	t.Run("unsupported_custom_is_bound_durable_rejection", func(t *testing.T) {
		p, now := mysqlNode(t, s)
		r := testRequest(p)
		r.Product.Resources.BandwidthMbps = 1
		r.ConfigurationSHA256, _ = r.Product.Digest()
		j, replay, e := s.Admit(ctx, r, testConfig(p).Candidates(r), now, time.Minute)
		if e != nil || replay || j.State != "rejected" || j.Result().ResourceID != "" || !j.Result().Matches(r) {
			t.Fatal("unsupported value ignored", e)
		}
		var n int
		s.DB.QueryRow("SELECT COUNT(*) FROM controller_reservations WHERE operation_id=?", r.OperationID).Scan(&n)
		if n != 0 {
			t.Fatal("rejected request reserved capacity")
		}
		reloaded, e := s.Lookup(ctx, r.OperationID)
		if e != nil || reloaded.State != "rejected" {
			t.Fatal("rejection not durable")
		}
	})
	t.Run("only_one_dispatch_and_lost_result_only_GET", func(t *testing.T) {
		p, now := mysqlNode(t, s)
		r := testRequest(p)
		j, _, e := s.Admit(ctx, r, testConfig(p).Candidates(r), now, time.Minute)
		if e != nil {
			t.Fatal(e)
		}
		rpc := &fakeRPC{lost: true}
		w := Worker{Store: s, Config: testConfig(p), RPC: func(context.Context, NodeProfile) (NodeRPC, error) { return rpc, nil }, Now: func() time.Time { return now }}
		var wg sync.WaitGroup
		for range 12 {
			wg.Add(1)
			go func() { defer wg.Done(); _, _ = w.Dispatch(ctx, r.OperationID) }()
		}
		wg.Wait()
		if rpc.sends != 1 {
			t.Fatal("duplicate node mutation", rpc.sends)
		}
		j, e = s.Lookup(ctx, r.OperationID)
		if e != nil || j.State != "uncertain" {
			t.Fatal("loss missing", j.State, e)
		}
		w.Store = &SQLStore{DB: s.DB}
		j, e = w.Reconcile(ctx, r.OperationID)
		if e != nil || j.State != "succeeded" || rpc.sends != 1 || rpc.gets != 1 || !j.Result().Matches(r) {
			t.Fatal("reconcile lost binding", j.State, e, rpc.sends, rpc.gets)
		}
		if _, e = s.Complete(ctx, r.OperationID, "rejected", now); !errors.Is(e, ErrConflict) {
			t.Fatal("terminal result regressed")
		}
	})
	t.Run("success_plus_new_heartbeat_remains_conservative", func(t *testing.T) {
		p, now := mysqlNode(t, s)
		r := testRequest(p)
		j, _, e := s.Admit(ctx, r, testConfig(p).Candidates(r), now, time.Minute)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = s.Claim(ctx, j.OperationID, p.Digest(), now, time.Minute); e != nil {
			t.Fatal(e)
		}
		if _, e = s.Complete(ctx, j.OperationID, "succeeded", now); e != nil {
			t.Fatal(e)
		}
		caps := testCapabilities(p, now)
		caps.Capacity.CPUCoresAllocated = 2
		caps.Capacity.MemoryAllocatedMiB = 512
		caps.Capacity.MemoryAvailableMiB -= 512
		caps.Capacity.StorageAllocatedGiB = 5
		caps.Capacity.StorageAvailableGiB -= 5
		if e = s.Heartbeat(ctx, p, caps, now, time.Minute); e != nil {
			t.Fatal(e)
		}
		count := 0
		for range 8 {
			next := testRequest(p)
			j, _, e = s.Admit(ctx, next, testConfig(p).Candidates(next), now, time.Minute)
			if e == nil && j.State == "accepted" {
				count++
			} else if !errors.Is(e, ErrCapacity) {
				t.Fatal(e)
			}
		}
		if count != 2 {
			t.Fatal("conservative reservations changed or capacity oversold", count)
		}
		var active int
		s.DB.QueryRow("SELECT COUNT(*) FROM controller_reservations WHERE operation_id=? AND released=FALSE", r.OperationID).Scan(&active)
		if active != 1 {
			t.Fatal("success released before heartbeat ownership proof")
		}
	})
	t.Run("node_rejection_releases_only_confirmed_reservation", func(t *testing.T) {
		p, now := mysqlNode(t, s)
		r := testRequest(p)
		j, _, e := s.Admit(ctx, r, testConfig(p).Candidates(r), now, time.Minute)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = s.Claim(ctx, j.OperationID, p.Digest(), now, time.Minute); e != nil {
			t.Fatal(e)
		}
		if _, e = s.Complete(ctx, j.OperationID, "uncertain", now); e != nil {
			t.Fatal(e)
		}
		var released bool
		s.DB.QueryRow("SELECT released FROM controller_reservations WHERE operation_id=?", j.OperationID).Scan(&released)
		if released {
			t.Fatal("uncertain released reservation")
		}
		if _, e = s.Complete(ctx, j.OperationID, "rejected", now); e != nil {
			t.Fatal(e)
		}
		s.DB.QueryRow("SELECT released FROM controller_reservations WHERE operation_id=?", j.OperationID).Scan(&released)
		if !released {
			t.Fatal("confirmed rejection retained reservation")
		}
	})
	t.Run("changed_root_profile_and_crash_sending_never_resend", func(t *testing.T) {
		p, now := mysqlNode(t, s)
		r := testRequest(p)
		j, _, e := s.Admit(ctx, r, testConfig(p).Candidates(r), now, time.Minute)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = s.Claim(ctx, j.OperationID, p.Digest(), now, time.Minute); e != nil {
			t.Fatal(e)
		}
		rpc := &fakeRPC{}
		w := Worker{Store: s, Config: testConfig(p), RPC: func(context.Context, NodeProfile) (NodeRPC, error) { return rpc, nil }, Now: func() time.Time { return now }}
		if _, e = w.Dispatch(ctx, j.OperationID); !errors.Is(e, ErrState) {
			t.Fatal("sending became dispatchable")
		}
		if rpc.sends != 0 {
			t.Fatal("crash window resent")
		}
		if _, e = w.Reconcile(ctx, j.OperationID); e == nil || rpc.sends != 0 || rpc.gets != 1 {
			t.Fatal("not found treated as authority to POST")
		}
		changed := p
		changed.Endpoint = "https://different.invalid:9444"
		w.Config = testConfig(changed)
		if _, e = w.Reconcile(ctx, j.OperationID); !errors.Is(e, ErrState) {
			t.Fatal("changed node endpoint accepted")
		}
	})
	t.Run("single_node_worker_keeps_other_orders_queued_without_POST_or_audit", func(t *testing.T) {
		p, now := mysqlNode(t, s)
		requests := []controllerapi.Request{testRequest(p), testRequest(p)}
		jobs := make([]Job, 2)
		for i, request := range requests {
			var e error
			jobs[i], _, e = s.Admit(ctx, request, testConfig(p).Candidates(request), now, time.Minute)
			if e != nil || jobs[i].State != "accepted" {
				t.Fatal("queue admission failed", e)
			}
		}
		rpc := &acceptingNodeRPC{}
		worker := Worker{Store: s, Config: testConfig(p), RPC: func(context.Context, NodeProfile) (NodeRPC, error) { return rpc, nil }, Now: func() time.Time { return now.Add(time.Second) }}
		start := make(chan struct{})
		results := make([]Job, 2)
		errorsOut := make([]error, 2)
		var wg sync.WaitGroup
		for i := range jobs {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				results[i], errorsOut[i] = worker.Dispatch(ctx, jobs[i].OperationID)
			}(i)
		}
		close(start)
		wg.Wait()
		winner, pending := -1, -1
		for i, e := range errorsOut {
			if e == nil && results[i].State == "dispatched" {
				if winner != -1 {
					t.Fatal("two node workers claimed")
				}
				winner = i
			} else if errors.Is(e, ErrState) {
				pending = i
			} else {
				t.Fatal("unexpected claim result", e)
			}
		}
		if winner < 0 || pending < 0 || rpc.posts.Load() != 1 {
			t.Fatal("concurrent orders did not retain one queued job", winner, pending, rpc.posts.Load())
		}
		assertQueuedUntouched := func() {
			t.Helper()
			stored, e := s.Lookup(ctx, jobs[pending].OperationID)
			if e != nil || !reflect.DeepEqual(stored, jobs[pending]) {
				t.Fatal("blocked queue state or request binding changed", e, stored.State)
			}
			var claims, reservations, rejected int
			if e = s.DB.QueryRow("SELECT COUNT(*) FROM controller_audit WHERE target=? AND action='node.dispatch_claimed'", jobs[pending].OperationID).Scan(&claims); e != nil {
				t.Fatal(e)
			}
			if e = s.DB.QueryRow("SELECT COUNT(*) FROM controller_reservations WHERE operation_id=? AND released=FALSE", jobs[pending].OperationID).Scan(&reservations); e != nil {
				t.Fatal(e)
			}
			if e = s.DB.QueryRow("SELECT COUNT(*) FROM controller_audit WHERE target=? AND action LIKE '%rejected%'", jobs[pending].OperationID).Scan(&rejected); e != nil {
				t.Fatal(e)
			}
			if claims != 0 || reservations != 1 || rejected != 0 || rpc.posts.Load() != 1 {
				t.Fatal("blocked order had a POST/state/audit side effect", claims, reservations, rejected, rpc.posts.Load())
			}
		}
		assertQueuedUntouched()
		// accepted node response leaves the first job dispatched, not free.
		if _, e := worker.Dispatch(ctx, jobs[pending].OperationID); !errors.Is(e, ErrState) {
			t.Fatal("accepted response freed node", e)
		}
		assertQueuedUntouched()
		if _, e := s.Complete(ctx, jobs[winner].OperationID, "uncertain", now.Add(2*time.Second)); e != nil {
			t.Fatal(e)
		}
		if _, e := worker.Dispatch(ctx, jobs[pending].OperationID); !errors.Is(e, ErrState) {
			t.Fatal("unknown outcome freed node", e)
		}
		assertQueuedUntouched()
		if _, e := s.Complete(ctx, jobs[winner].OperationID, "succeeded", now.Add(3*time.Second)); e != nil {
			t.Fatal(e)
		}
		second, e := worker.Dispatch(ctx, jobs[pending].OperationID)
		if e != nil || second.State != "dispatched" || rpc.posts.Load() != 2 {
			t.Fatal("proven terminal did not release node for next queued order", e, second.State, rpc.posts.Load())
		}
		for _, job := range jobs {
			var count int
			if e = s.DB.QueryRow("SELECT COUNT(*) FROM controller_audit WHERE target=? AND action='node.dispatch_claimed'", job.OperationID).Scan(&count); e != nil || count != 1 {
				t.Fatal("claim audit count is not exactly one per order", e, count)
			}
		}
	})
	t.Run("schema_checksum_fail_closed", func(t *testing.T) {
		var hash string
		if e := s.DB.QueryRow("SELECT sha256 FROM controller_schema WHERE version=1").Scan(&hash); e != nil {
			t.Fatal(e)
		}
		if _, e := s.DB.Exec("UPDATE controller_schema SET sha256=? WHERE version=1", strings.Repeat("0", 64)); e != nil {
			t.Fatal(e)
		}
		defer s.DB.Exec("UPDATE controller_schema SET sha256=? WHERE version=1", hash)
		if e := s.Check(ctx); !errors.Is(e, ErrConflict) {
			t.Fatal("modified migration accepted")
		}
	})
}

// A node's durable accepted acknowledgement does not release its single worker.
type acceptingNodeRPC struct{ posts atomic.Int32 }

func (r *acceptingNodeRPC) Send(_ context.Context, raw []byte, digest string) (nodeproto.NodeResult, error) {
	task, e := nodeproto.DecodeTask(raw)
	if e != nil || nodeproto.Digest(raw) != digest {
		return nodeproto.NodeResult{}, ErrInput
	}
	r.posts.Add(1)
	return nodeproto.NodeResult{Protocol: nodeproto.Protocol, OperationID: task.OperationID, RequestSHA256: digest, Status: "accepted", InstanceID: task.InstanceID}, nil
}
func (*acceptingNodeRPC) Lookup(context.Context, string, string) (nodeproto.NodeResult, error) {
	return nodeproto.NodeResult{}, ErrUnavailable
}
func (*acceptingNodeRPC) Capabilities(context.Context) (Capability, error) {
	return Capability{}, ErrUnavailable
}

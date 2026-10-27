package control

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// This driver exercises SQLStore.Claim's actual fail-closed branch without a
// local database. Real InnoDB concurrency/audit assertions remain in mysql_test.
var claimFixtures sync.Map

func init() { sql.Register("aster-claim-boundary-test", claimDriver{}) }

type claimDriver struct{}

func (claimDriver) Open(key string) (driver.Conn, error) {
	v, ok := claimFixtures.Load(key)
	if !ok {
		return nil, ErrInput
	}
	return &claimConn{v.(*claimFixture)}, nil
}

type claimFixture struct {
	job                            Job
	instance                       Instance
	otherState                     string
	executions, commits, rollbacks int
}
type claimConn struct{ s *claimFixture }

func (c *claimConn) Prepare(string) (driver.Stmt, error)                          { return nil, ErrInput }
func (c *claimConn) Close() error                                                 { return nil }
func (c *claimConn) Begin() (driver.Tx, error)                                    { return &claimTx{c.s}, nil }
func (c *claimConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) { return c.Begin() }
func (c *claimConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	switch {
	case strings.Contains(q, "FROM controller_lock"):
		return &claimRows{columns: []string{"id"}, values: []driver.Value{int64(1)}}, nil
	case strings.Contains(q, "SELECT COUNT(*) FROM controller_operations o JOIN controller_migrations"):
		return &claimRows{columns: []string{"count"}, values: []driver.Value{int64(0)}}, nil
	case strings.Contains(q, "SELECT COUNT(*) FROM controller_operations"):
		return &claimRows{columns: []string{"count"}, values: []driver.Value{int64(0)}}, nil
	case strings.Contains(q, "SELECT COUNT(*) FROM controller_jobs"):
		if !strings.Contains(q, "node_id=? AND operation_id<>? AND CAST(state AS BINARY) NOT IN ('accepted','succeeded','rejected')") || len(args) != 2 || args[0].Value != c.s.job.NodeID || args[1].Value != c.s.job.OperationID {
			return nil, ErrInput
		}
		count := int64(1)
		switch c.s.otherState {
		case "<no-peer>", "accepted", "succeeded", "rejected":
			count = 0
		}
		return &claimRows{columns: []string{"count"}, values: []driver.Value{count}}, nil
	case strings.Contains(q, "FROM controller_jobs WHERE operation_id=?"):
		j := c.s.job
		return &claimRows{columns: strings.Split(jobColumns, ","), values: []driver.Value{j.OperationID, j.OrderID, j.ControllerID, j.RequestSHA, j.RequestJSON, j.InstanceID, j.NodeID, j.NodeProfileSHA, j.NodeRequestSHA, j.NodeRequest, j.State, j.CreatedAt, j.UpdatedAt}}, nil
	case strings.Contains(q, "FROM controller_nodes"):
		return &claimRows{columns: []string{"maintenance", "heartbeat_at", "profile_sha256"}, values: []driver.Value{false, c.s.job.CreatedAt, c.s.job.NodeProfileSHA}}, nil
	case strings.Contains(q, "FROM controller_instances WHERE id=?"):
		v := c.s.instance
		raw, _ := json.Marshal(v.Resources)
		return &claimRows{columns: []string{"id", "owner_ref", "node_id", "hostname", "state", "resources", "created_at", "updated_at"}, values: []driver.Value{v.ID, v.OwnerRef, v.NodeID, v.Hostname, v.State, raw, v.CreatedAt, v.UpdatedAt}}, nil
	case strings.Contains(q, "FROM controller_public_ip_resources WHERE owner_ref=?"):
		return &claimRows{columns: strings.Split(publicResourceColumns, ","), empty: true}, nil
	case strings.Contains(q, "FROM controller_instance_networks WHERE instance_id=?"):
		return &claimRows{columns: []string{"operation_id", "node_id", "request_sha256", "network_sha256", "binding"}, empty: true}, nil
	}
	return nil, ErrInput
}
func (c *claimConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	c.s.executions++
	return driver.RowsAffected(1), nil
}

type claimTx struct{ s *claimFixture }

func (t *claimTx) Commit() error   { t.s.commits++; return nil }
func (t *claimTx) Rollback() error { t.s.rollbacks++; return nil }

type claimRows struct {
	columns []string
	values  []driver.Value
	read    bool
	empty   bool
}

func (r *claimRows) Columns() []string { return r.columns }
func (r *claimRows) Close() error      { return nil }
func (r *claimRows) Next(dest []driver.Value) error {
	if r.read || r.empty {
		return io.EOF
	}
	copy(dest, r.values)
	r.read = true
	return nil
}
func TestSQLClaimPreservesQueueForEveryUnprovenNodeState(t *testing.T) {
	for _, state := range []string{"sending", "dispatched", "uncertain", "failed", "unknown", "future-state", "SUCCEEDED", "Rejected", "accepted", "succeeded", "rejected", "", "<no-peer>"} {
		t.Run(state, func(t *testing.T) {
			now := time.Now().UTC()
			fixture := &claimFixture{job: Job{OperationID: id(), OrderID: id(), ControllerID: "main", RequestSHA: strings.Repeat("a", 64), RequestJSON: []byte("{}"), InstanceID: id(), NodeID: "approved-node", NodeProfileSHA: strings.Repeat("b", 64), NodeRequestSHA: strings.Repeat("c", 64), NodeRequest: []byte("{}"), State: "accepted", CreatedAt: now, UpdatedAt: now}, otherState: state}
			p := testProfile()
			p.ID = fixture.job.NodeID
			fixture.instance = Instance{ID: fixture.job.InstanceID, OwnerRef: id(), NodeID: p.ID, Hostname: "claim-fixture", State: "reserved", Resources: testResources(p), CreatedAt: now, UpdatedAt: now}
			task := nodeproto.NodeTask{Protocol: nodeproto.Protocol, OperationID: fixture.job.OperationID, NodeID: p.ID, Action: "create", InstanceID: fixture.instance.ID, OwnerRef: fixture.instance.OwnerRef, Hostname: fixture.instance.Hostname, Resources: fixture.instance.Resources}
			var bindErr error
			fixture.job.NodeRequest, fixture.job.NodeRequestSHA, bindErr = task.BytesAndDigest()
			if bindErr != nil {
				t.Fatal(bindErr)
			}
			key := id()
			claimFixtures.Store(key, fixture)
			defer claimFixtures.Delete(key)
			db, e := sql.Open("aster-claim-boundary-test", key)
			if e != nil {
				t.Fatal(e)
			}
			defer db.Close()
			s := SQLStore{DB: db}
			result, e := s.Claim(context.Background(), fixture.job.OperationID, fixture.job.NodeProfileSHA, now, time.Minute)
			free := state == "<no-peer>" || state == "accepted" || state == "succeeded" || state == "rejected"
			if !free {
				if !errors.Is(e, ErrState) || fixture.executions != 0 || fixture.commits != 0 || fixture.rollbacks != 1 {
					t.Fatal("occupied node changed state/audit", e, fixture)
				}
				return
			}
			if e != nil || result.State != "sending" || fixture.executions != 2 || fixture.commits != 1 || fixture.rollbacks != 0 {
				t.Fatal("terminal/queued peer incorrectly blocks claim", e, fixture)
			}
		})
	}
}

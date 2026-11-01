package control

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

var stateMachineFixtures sync.Map

func init() { sql.Register("aster-state-machine-test", stateMachineDriver{}) }

type stateMachineDriver struct{}

func (stateMachineDriver) Open(key string) (driver.Conn, error) {
	v, ok := stateMachineFixtures.Load(key)
	if !ok {
		return nil, ErrInput
	}
	return &stateMachineConn{v.(*stateMachineFixture)}, nil
}

type stateMachineNode struct {
	profile                        NodeProfile
	seen                           time.Time
	unsupported, full, maintenance bool
}
type stateMachineFixture struct {
	job             *Job
	op              Operation
	instance        Instance
	nodes           map[string]stateMachineNode
	now             time.Time
	writes, commits int
	audits          []string
}
type stateMachineConn struct{ f *stateMachineFixture }

func (c *stateMachineConn) Prepare(string) (driver.Stmt, error) { return nil, ErrInput }
func (c *stateMachineConn) Close() error                        { return nil }
func (c *stateMachineConn) Begin() (driver.Tx, error)           { return c, nil }
func (c *stateMachineConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return c, nil
}
func (c *stateMachineConn) Commit() error   { c.f.commits++; return nil }
func (c *stateMachineConn) Rollback() error { return nil }
func stateMachineRows(columns string, values ...driver.Value) driver.Rows {
	return &claimRows{columns: strings.Split(columns, ","), values: values, empty: len(values) == 0}
}
func (c *stateMachineConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	f := c.f
	switch {
	case strings.Contains(q, "FROM controller_lock"):
		return stateMachineRows("id", int64(1)), nil
	case strings.Contains(q, "SELECT COUNT(*)"):
		count := int64(0)
		if strings.Contains(q, "controller_operations WHERE instance_id") && f.op.ID != "" {
			if !strings.Contains(q, "'resolved'") {
				return nil, errors.New("resolved operations still quarantine instance")
			}
			if f.op.State != "resolved" && f.op.State != "succeeded" && f.op.State != "rejected" {
				count = 1
			}
		}
		if strings.Contains(q, "controller_operations WHERE node_id") && f.op.ID != "" {
			if !strings.Contains(q, "'resolved'") {
				return nil, errors.New("resolved operations still occupy node")
			}
			if f.op.State != "resolved" && f.op.State != "succeeded" && f.op.State != "rejected" && f.op.State != "accepted" {
				count = 1
			}
		}
		return stateMachineRows("count", count), nil
	case strings.Contains(q, "FROM controller_jobs WHERE operation_id"):
		if f.job == nil {
			return stateMachineRows(jobColumns), nil
		}
		j := *f.job
		return stateMachineRows(jobColumns, j.OperationID, j.OrderID, j.ControllerID, j.RequestSHA, j.RequestJSON, j.InstanceID, j.NodeID, j.NodeProfileSHA, j.NodeRequestSHA, j.NodeRequest, j.State, j.CreatedAt, j.UpdatedAt), nil
	case strings.Contains(q, "FROM controller_jobs WHERE order_id"):
		return stateMachineRows("operation_id"), nil
	case strings.Contains(q, "FROM controller_nodes"):
		n, ok := f.nodes[args[0].Value.(string)]
		if !ok {
			return stateMachineRows("profile,maintenance,seen,cpu,memory,disk,caps"), nil
		}
		caps := testCapabilities(n.profile, f.now)
		if n.unsupported {
			caps.Actions = []string{"start"}
		}
		raw, _ := json.Marshal(caps)
		cpu := int64(64)
		if n.full {
			cpu = 0
		}
		return stateMachineRows("profile,maintenance,seen,cpu,memory,disk,caps", n.profile.Digest(), n.maintenance, n.seen, cpu, int64(65536), int64(1000), raw), nil
	case strings.Contains(q, "SUM(cpu)"):
		return stateMachineRows("cpu,memory,disk", int64(0), int64(0), int64(0)), nil
	case strings.Contains(q, "FROM controller_operations WHERE id"):
		o := f.op
		if o.ID == "" || args[0].Value != o.ID {
			return stateMachineRows(operationColumns), nil
		}
		return stateMachineRows(operationColumns, o.ID, o.ActorID, o.InstanceID, o.NodeID, o.ProfileSHA, o.Action, o.ArtifactID, o.TargetNodeID, o.IntentSHA, o.Protocol, o.Request, o.RequestSHA, o.State, o.CreatedAt, o.UpdatedAt, o.Seq), nil
	case strings.Contains(q, "FROM controller_instances WHERE id"):
		v := f.instance
		raw, _ := json.Marshal(v.Resources)
		return stateMachineRows("id,owner,node,hostname,state,resources,created,updated", v.ID, v.OwnerRef, v.NodeID, v.Hostname, v.State, raw, v.CreatedAt, v.UpdatedAt), nil
	case strings.Contains(q, "FROM controller_public_ip_resources WHERE owner_ref"):
		return stateMachineRows(publicResourceColumns), nil
	case strings.Contains(q, "FROM controller_public_ip_bindings"):
		return stateMachineRows("id"), nil
	case strings.Contains(q, "FROM controller_instance_networks"):
		return stateMachineRows("operation_id,node_id,request_sha256,network_sha256,binding"), nil
	}
	return nil, fmt.Errorf("unexpected SQL: %s", q)
}
func (c *stateMachineConn) ExecContext(_ context.Context, q string, a []driver.NamedValue) (driver.Result, error) {
	f := c.f
	f.writes++
	switch {
	case strings.HasPrefix(q, "INSERT INTO controller_jobs("):
		f.job = &Job{OperationID: a[0].Value.(string), OrderID: a[1].Value.(string), ControllerID: a[2].Value.(string), RequestSHA: a[3].Value.(string), RequestJSON: a[4].Value.([]byte), InstanceID: a[5].Value.(string), NodeID: a[6].Value.(string), NodeProfileSHA: a[7].Value.(string), NodeRequestSHA: a[8].Value.(string), NodeRequest: a[9].Value.([]byte), State: a[10].Value.(string), CreatedAt: a[11].Value.(time.Time), UpdatedAt: a[12].Value.(time.Time)}
	case strings.HasPrefix(q, "INSERT INTO controller_audit"):
		f.audits = append(f.audits, a[1].Value.(string))
	case strings.HasPrefix(q, "UPDATE controller_instances SET state=?"):
		f.instance.State = a[0].Value.(string)
	case strings.HasPrefix(q, "UPDATE controller_operations SET state='resolved'"):
		f.op.State = "resolved"
	case strings.HasPrefix(q, "INSERT INTO controller_operations("):
	default:
		return nil, fmt.Errorf("unexpected write: %s", q)
	}
	return driver.RowsAffected(1), nil
}
func stateMachineStore(t *testing.T, f *stateMachineFixture) *SQLStore {
	t.Helper()
	key := id()
	stateMachineFixtures.Store(key, f)
	db, e := sql.Open("aster-state-machine-test", key)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close(); stateMachineFixtures.Delete(key) })
	return &SQLStore{DB: db}
}
func TestBillingPermanentMismatchPersistsWhileShortagesRemainRetryable(t *testing.T) {
	for _, name := range []string{"direct_only", "unsupported", "missing", "stale", "maintenance", "full", "direct_plus_stale", "unsupported_plus_stale"} {
		t.Run(name, func(t *testing.T) {
			p := testProfile()
			now := time.Now().UTC()
			r := testRequest(p)
			c := testConfig(p)
			candidates := c.Candidates(r)
			f := &stateMachineFixture{now: now, nodes: map[string]stateMachineNode{p.ID: {profile: p, seen: now}}}
			n := f.nodes[p.ID]
			switch name {
			case "direct_only":
				candidates[0].DirectPublicRequired = true
			case "unsupported":
				n.unsupported = true
			case "missing":
				delete(f.nodes, p.ID)
			case "stale", "direct_plus_stale":
				n.seen = now.Add(-2 * time.Minute)
			case "maintenance":
				n.maintenance = true
			case "full":
				n.full = true
			case "unsupported_plus_stale":
				n.unsupported = true
			}
			if name != "missing" {
				f.nodes[p.ID] = n
			}
			if name == "direct_plus_stale" {
				direct := candidates[0]
				direct.DirectPublicRequired = true
				candidates = append([]Candidate{direct}, candidates...)
			}
			if name == "unsupported_plus_stale" {
				other := p
				other.ID = "second"
				f.nodes[other.ID] = stateMachineNode{profile: other, seen: now.Add(-2 * time.Minute)}
				extra := candidates[0]
				extra.Node = other
				extra.ProfileSHA = other.Digest()
				extra.Resources.ComputeNodeID = other.ID
				candidates = append(candidates, extra)
			}
			s := stateMachineStore(t, f)
			j, replay, err := s.Admit(context.Background(), r, candidates, now, time.Minute)
			permanent := name == "direct_only" || name == "unsupported"
			if !permanent {
				if !errors.Is(err, ErrCapacity) || f.job != nil || f.writes != 0 || f.commits != 0 {
					t.Fatal(j, err, f)
				}
				return
			}
			code := "UNSUPPORTED_PRODUCT"
			if name == "direct_only" {
				code = "DIRECT_PUBLIC_LEASE_REQUIRED"
			}
			if err != nil || replay || j.State != "rejected" || j.RejectionCode() != code || f.job == nil || j.InstanceID != "" {
				t.Fatal(j, err)
			}
			writes := f.writes
			// The same sold request must retain its rejection even after capacity changes.
			f.nodes[p.ID] = stateMachineNode{profile: p, seen: now}
			got, replay, err := s.Admit(context.Background(), r, c.Candidates(r), now, time.Minute)
			if err != nil || !replay || got.RejectionCode() != code || f.writes != writes {
				t.Fatal(got, err)
			}
			r.Hostname = "changed"
			if _, _, err = s.Admit(context.Background(), r, nil, now, time.Minute); !errors.Is(err, ErrConflict) {
				t.Fatal("replay changed intent", err)
			}
		})
	}
}

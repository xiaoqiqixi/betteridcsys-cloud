package hypervisor

import (
	"aster/cloud/internal/control"
	"aster/cloud/internal/nodeproto"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Exercise the node journal, its GET handler, the operation-reconcile worker,
// and controller admission together. Libvirt and SQL use in-memory adapters;
// the root-only CLI's resolver is invoked with effective UID 0 so this test also
// runs on developer hosts without root or libvirt. CLI flag validation and the
// refusal of non-root resolution are covered separately.
func TestOperatorResolutionUnblocksControllerAfterUncertainReboot(t *testing.T) {
	m, runner, task := uncertainReboot(t)
	ctx := context.Background()
	now := time.Now().UTC()
	p := control.NodeProfile{ID: task.NodeID, DatacenterID: task.Resources.DatacenterID, GroupID: task.Resources.NodeGroupID}
	cfg := control.Config{Nodes: []control.NodeProfile{p}}
	raw, sha, err := task.BytesAndDigest()
	if err != nil {
		t.Fatal(err)
	}
	op := control.Operation{ID: task.OperationID, ActorID: strings.Repeat("a", 32), InstanceID: task.InstanceID, NodeID: task.NodeID, ProfileSHA: p.Digest(), Action: task.Action, Protocol: task.Protocol, Request: raw, RequestSHA: sha, State: "dispatched", CreatedAt: now, UpdatedAt: now}
	state := &resolutionControllerDB{
		operations: map[string]control.Operation{op.ID: op},
		instance:   control.Instance{ID: task.InstanceID, OwnerRef: task.OwnerRef, NodeID: task.NodeID, Hostname: task.Hostname, Resources: task.Resources, State: "running", CreatedAt: now, UpdatedAt: now},
	}
	db := sql.OpenDB(state)
	t.Cleanup(func() { db.Close() })
	store := &control.SQLStore{DB: db}
	cert := &x509.Certificate{Raw: []byte("verified controller test certificate")}
	m.Config.ExpectedControllerCertificateSHA256 = nodeproto.Digest(cert.Raw)
	rpc := &resolutionNodeRPC{manager: m, cert: cert}
	worker := control.OperationWorker{Store: store, Config: cfg, RPC: func(context.Context, control.NodeProfile) (control.NodeRPC, error) { return rpc, nil }, Now: func() time.Time { return now }}
	if out, err := worker.Reconcile(ctx, op.ID); err != nil || out.State != "uncertain" {
		t.Fatal("unknown reboot was not quarantined by controller", out, err)
	}
	nextID := strings.Repeat("b", 32)
	if _, _, err := store.CreateOperation(ctx, cfg, op.ActorID, task.InstanceID, nextID, control.OperationInput{Action: "start"}, now); !errors.Is(err, control.ErrState) {
		t.Fatal("controller accepted a new action before resolution", err)
	}

	// Stop the node, run the engine behind `aster-node --resolve-instance ID
	// --reason TEXT` as root, then reopen the journal as the restarted service.
	m.Shutdown()
	runner.states["aster-"+task.InstanceID] = "shut off"
	before := len(runner.commands)
	const reason = "Checked original guest after interrupted reboot"
	if _, err := m.resolveInstance(ctx, task.InstanceID, reason, 0); err != nil {
		t.Fatal(err)
	}
	if err := m.Ledger.Close(); err != nil {
		t.Fatal(err)
	}
	ledger, err := OpenLedger(m.Config.StateDirectory, m.Config.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	m = &Manager{Config: m.Config, Ledger: ledger, Runner: runner, bridgeReady: m.bridgeReady, capacityRead: m.capacityRead}
	t.Cleanup(func() { m.Shutdown(); ledger.Close() })
	rpc.manager = m
	if out, err := worker.Reconcile(ctx, op.ID); err != nil || out.State != "resolved" || state.instance.State != "shutoff" {
		t.Fatal("controller did not consume durable root resolution", out, state.instance, err)
	}
	for _, cmd := range runner.commands[before:] {
		if !strings.Contains(cmd, " dumpxml ") && !strings.Contains(cmd, " domstate ") {
			t.Fatal("operator resolution or reconcile mutated libvirt", cmd)
		}
	}
	old, _ := ledger.Query(task.OperationID)
	if old.Result.Status != "uncertain" || old.Result.Resolved == nil || old.Result.Resolved.Who != "uid:0" || old.Result.Resolved.Reason != reason {
		t.Fatal("resolution rewrote original unknown outcome", old)
	}
	if strings.Join(state.audits, ",") != "operation.uncertain,operation.resolved,operation.resolution_receipt" {
		t.Fatal("missing uncertainty or resolution audit", state.audits)
	}
	created, replay, err := store.CreateOperation(ctx, cfg, op.ActorID, task.InstanceID, nextID, control.OperationInput{Action: "start"}, now)
	if err != nil || replay || created.State != "accepted" {
		t.Fatal("resolved operation still blocks controller admission", created, err)
	}
	next, err := nodeproto.DecodeTask(created.Request)
	if err != nil {
		t.Fatal(err)
	}
	if result := submit(t, m, next); result.Status != "succeeded" {
		t.Fatal("node still quarantines resolved instance", result)
	}
	state.instance.State = "running" // A later controller observation must survive replay.
	lookups, writes := rpc.lookups, state.writes
	if out, err := worker.Reconcile(ctx, op.ID); err != nil || out.State != "resolved" || state.instance.State != "running" || rpc.lookups != lookups || state.writes != writes {
		t.Fatal("terminal resolution replay touched newer state", out, err)
	}
}

type resolutionNodeRPC struct {
	control.NodeRPC
	manager *Manager
	cert    *x509.Certificate
	lookups int
}

func (r *resolutionNodeRPC) Send(context.Context, []byte, string) (nodeproto.NodeResult, error) {
	return nodeproto.NodeResult{}, errors.New("reconciliation must never POST")
}
func (r *resolutionNodeRPC) Lookup(ctx context.Context, id, sha string) (nodeproto.NodeResult, error) {
	r.lookups++
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/v1/tasks/"+id, nil)
	req.Header.Set("X-Request-SHA256", sha)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{r.cert}, VerifiedChains: [][]*x509.Certificate{{r.cert}}}
	response := httptest.NewRecorder()
	r.manager.Handler().ServeHTTP(response, req)
	var result nodeproto.NodeResult
	if response.Code != http.StatusOK {
		return result, fmt.Errorf("node lookup: HTTP %d", response.Code)
	}
	err := json.Unmarshal(response.Body.Bytes(), &result)
	return result, err
}

// A narrow SQL driver for the public controller store APIs used above. Unknown
// queries/writes fail, including any attempt to release customer reservations.
type resolutionControllerDB struct {
	operations map[string]control.Operation
	instance   control.Instance
	audits     []string
	writes     int
}

func (s *resolutionControllerDB) Connect(context.Context) (driver.Conn, error) { return s, nil }
func (s *resolutionControllerDB) Driver() driver.Driver                        { return resolutionControllerDriver{s} }

type resolutionControllerDriver struct{ s *resolutionControllerDB }

func (d resolutionControllerDriver) Open(string) (driver.Conn, error) { return d.s, nil }
func (s *resolutionControllerDB) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (s *resolutionControllerDB) Close() error              { return nil }
func (s *resolutionControllerDB) Begin() (driver.Tx, error) { return s, nil }
func (s *resolutionControllerDB) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return s, nil
}
func (s *resolutionControllerDB) Commit() error   { return nil }
func (s *resolutionControllerDB) Rollback() error { return nil }
func (s *resolutionControllerDB) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	rows := func(values ...driver.Value) (driver.Rows, error) {
		columns := strings.Split(strings.Split(strings.TrimPrefix(q, "SELECT "), " FROM ")[0], ",")
		return &resolutionRows{columns: columns, values: values}, nil
	}
	switch {
	case strings.Contains(q, "FROM controller_lock"):
		return rows(int64(1))
	case strings.HasPrefix(q, "SELECT COUNT(*)"):
		count := int64(0)
		if strings.Contains(q, "FROM controller_operations WHERE instance_id") {
			for _, o := range s.operations {
				if o.InstanceID == args[0].Value && !strings.Contains(q, "'"+o.State+"'") {
					count++
				}
			}
		}
		return rows(count)
	case strings.Contains(q, "FROM controller_operations WHERE id"):
		o, ok := s.operations[args[0].Value.(string)]
		if !ok {
			return rows()
		}
		return rows(o.ID, o.ActorID, o.InstanceID, o.NodeID, o.ProfileSHA, o.Action, o.ArtifactID, o.TargetNodeID, o.IntentSHA, o.Protocol, o.Request, o.RequestSHA, o.State, o.CreatedAt, o.UpdatedAt, o.Seq)
	case strings.Contains(q, "FROM controller_instances WHERE id"):
		v := s.instance
		raw, _ := json.Marshal(v.Resources)
		return rows(v.ID, v.OwnerRef, v.NodeID, v.Hostname, v.State, raw, v.CreatedAt, v.UpdatedAt)
	case strings.Contains(q, "FROM controller_public_ip_resources WHERE owner_ref"), strings.Contains(q, "FROM controller_public_ip_bindings"), strings.Contains(q, "FROM controller_instance_networks"):
		return rows()
	}
	return nil, fmt.Errorf("unexpected recovery query: %s", q)
}
func (s *resolutionControllerDB) ExecContext(_ context.Context, q string, a []driver.NamedValue) (driver.Result, error) {
	s.writes++
	switch {
	case strings.HasPrefix(q, "UPDATE controller_operations SET state=?,"):
		id := a[2].Value.(string)
		o := s.operations[id]
		o.State, o.UpdatedAt = a[0].Value.(string), a[1].Value.(time.Time)
		s.operations[id] = o
	case strings.HasPrefix(q, "UPDATE controller_operations SET state='resolved',"):
		id := a[1].Value.(string)
		o := s.operations[id]
		o.State, o.UpdatedAt = "resolved", a[0].Value.(time.Time)
		s.operations[id] = o
	case strings.HasPrefix(q, "UPDATE controller_instances SET state=?,"):
		s.instance.State = a[0].Value.(string)
	case strings.HasPrefix(q, "INSERT INTO controller_audit"):
		s.audits = append(s.audits, a[1].Value.(string))
	case strings.HasPrefix(q, "INSERT INTO controller_operations("):
		o := control.Operation{ID: a[0].Value.(string), ActorID: a[1].Value.(string), InstanceID: a[2].Value.(string), NodeID: a[3].Value.(string), ProfileSHA: a[4].Value.(string), Action: a[5].Value.(string), ArtifactID: a[6].Value.(string), TargetNodeID: a[7].Value.(string), IntentSHA: a[8].Value.(string), Protocol: a[9].Value.(string), Request: a[10].Value.([]byte), RequestSHA: a[11].Value.(string), State: a[12].Value.(string), CreatedAt: a[13].Value.(time.Time), UpdatedAt: a[14].Value.(time.Time)}
		s.operations[o.ID] = o
	default:
		return nil, fmt.Errorf("unexpected recovery write: %s", q)
	}
	return driver.RowsAffected(1), nil
}

type resolutionRows struct {
	columns []string
	values  []driver.Value
}

func (r *resolutionRows) Columns() []string { return r.columns }
func (r *resolutionRows) Close() error      { return nil }
func (r *resolutionRows) Next(out []driver.Value) error {
	if r.values == nil {
		return io.EOF
	}
	copy(out, r.values)
	r.values = nil
	return nil
}

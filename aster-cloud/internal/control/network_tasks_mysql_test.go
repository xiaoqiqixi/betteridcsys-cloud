package control

import (
	"aster/billing/controllerapi"
	"aster/cloud/internal/networking"
	"aster/cloud/internal/nodeproto"
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func mysqlVPCConfig(t *testing.T, s *SQLStore, p NodeProfile, owner string, now time.Time) Config {
	t.Helper()
	ctx := context.Background()
	n := &networking.Store{DB: s.DB}
	actor := id()
	v, _, e := n.CreateVPC(ctx, actor, id(), networking.CreateVPCInput{OwnerRef: owner, NodeID: p.ID, Name: "Private fixture", CIDR: "10.25.0.0/24", VLANID: 25}, now)
	if e != nil {
		t.Fatal(e)
	}
	pool, _, e := n.CreatePool(ctx, actor, id(), networking.CreatePoolInput{NodeID: p.ID, VPCID: v.ID, Name: "Private pool", CIDR: v.CIDR, Gateway: "10.25.0.1", Addresses: []string{"10.25.0.10", "10.25.0.11", "10.25.0.12"}, Enabled: true}, now)
	if e != nil {
		t.Fatal(e)
	}
	c := vpcTestConfig(p, pool.ID)
	c.NetworkProfiles[0].OwnerRef = owner
	if e = s.Heartbeat(ctx, p, vpcTestCapabilities(p, now), now, time.Minute); e != nil {
		t.Fatal(e)
	}
	return c
}
func mysqlVPCRequest(p NodeProfile, owner string) controllerapi.Request {
	r := testRequest(p)
	r.OwnerRef = owner
	*r.Product.Resources = vpcTestResources(p)
	r.ConfigurationSHA256, _ = r.Product.Digest()
	return r
}
func TestMySQLVPCAdmissionFreezesSeparateFinancialAndNetworkContracts(t *testing.T) {
	s := consoleHTTPStore(t)
	ctx := context.Background()
	p, now := mysqlNode(t, s)
	owner := id()
	c := mysqlVPCConfig(t, s, p, owner, now)
	r := mysqlVPCRequest(p, owner)
	c.NetworkProfiles[0].ConfigurationSHA256 = r.ConfigurationSHA256
	before, financialSHA, e := r.BytesAndDigest()
	if e != nil {
		t.Fatal(e)
	}
	j, replay, e := s.Admit(ctx, r, c.Candidates(r), now, time.Minute)
	if e != nil || replay || j.State != "accepted" || j.RequestSHA != financialSHA || string(j.RequestJSON) != string(before) || !j.Result().Matches(r) {
		t.Fatal("financial contract changed", j, e)
	}
	task, e := nodeproto.DecodeTask(j.NodeRequest)
	if e != nil || task.Protocol != nodeproto.NetworkProtocol || task.Resources != *r.Product.Resources || task.Network.ProfileSHA256 != c.NetworkProfiles[0].ProfileSHA256 || task.Network.IPv4 != "10.25.0.10" || task.Network.LeaseID != r.OperationID {
		t.Fatal("network binding not frozen", task, e)
	}
	if strings.Contains(string(j.NodeRequest), `"gateway"`) {
		t.Fatal("L2 private task invented a default gateway")
	}
	again, replay, e := s.Admit(ctx, r, c.Candidates(r), now, time.Minute)
	if e != nil || !replay || again.NodeRequestSHA != j.NodeRequestSHA || string(again.NodeRequest) != string(j.NodeRequest) {
		t.Fatal("replay changed reservation", e)
	}
	for _, q := range []string{
		"SELECT COUNT(*) FROM controller_network_leases WHERE instance_id=?",
		"SELECT COUNT(*) FROM controller_instance_networks WHERE instance_id=?",
		"SELECT COUNT(*) FROM controller_jobs WHERE instance_id=?",
	} {
		var n int
		if e = s.DB.QueryRow(q, j.InstanceID).Scan(&n); e != nil || n != 1 {
			t.Fatal("non-atomic/duplicate network admission", q, n, e)
		}
	}
	if _, e = s.Claim(ctx, j.OperationID, p.Digest(), now, time.Minute); e != nil {
		t.Fatal("bound VPC task cannot claim", e)
	}
	if _, e = s.Complete(ctx, j.OperationID, "succeeded", now); e != nil {
		t.Fatal(e)
	}
	// A synthetic acknowledged node result changes no financial order or amount.
	if _, e = s.DB.Exec("UPDATE controller_instances SET state='shutoff' WHERE id=?", j.InstanceID); e != nil {
		t.Fatal(e)
	}
	for _, action := range []string{"reboot", "snapshot_create", "backup_create", "migrate_prepare"} {
		in := OperationInput{Action: action, Confirmation: j.InstanceID}
		if action == "migrate_prepare" {
			in.TargetNodeID = "other"
		}
		if _, _, e = s.CreateOperation(ctx, c, id(), j.InstanceID, id(), in, now); !errors.Is(e, ErrState) {
			t.Fatal("VPC used unbound legacy storage/migration", action, e)
		}
	}
	c.Presets[0].Resources.BandwidthMbps = 999
	op, _, e := s.CreateOperation(ctx, c, id(), j.InstanceID, id(), OperationInput{Action: "start"}, now)
	if e != nil {
		t.Fatal(e)
	}
	power, e := nodeproto.DecodeTask(op.Request)
	if e != nil || power.Protocol != nodeproto.NetworkProtocol || power.Network != task.Network || power.Resources != task.Resources {
		t.Fatal("power reread mutable product/profile instead of original binding", e)
	}

	if _, e = s.ClaimOperation(ctx, op.ID, c, now); e != nil {
		t.Fatal(e)
	}
	if _, e = s.CompleteOperation(ctx, c, op.ID, "succeeded", nil, now); e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec("UPDATE controller_network_pools SET enabled=FALSE WHERE id=?", c.NetworkProfiles[0].PoolID); e != nil {
		t.Fatal(e)
	}
	stop, _, e := s.CreateOperation(ctx, c, id(), j.InstanceID, id(), OperationInput{Action: "shutdown"}, now)
	if e != nil {
		t.Fatal("disabled pool prevented safe shutdown admission", e)
	}
	if _, e = s.ClaimOperation(ctx, stop.ID, c, now); e != nil {
		t.Fatal("disabled pool prevented safe shutdown dispatch", e)
	}
}
func TestMySQLVPCStaffCreateAndFailedReservationRollBackEntireAdmission(t *testing.T) {
	s := consoleHTTPStore(t)
	ctx := context.Background()
	t.Run("staff_create", func(t *testing.T) {
		p, now := mysqlNode(t, s)
		owner := id()
		c := mysqlVPCConfig(t, s, p, owner, now)
		opID := id()
		actor := id()
		in := CreateInstanceInput{Hostname: "private-vm", OwnerRef: owner, PresetID: c.Presets[0].ID}
		op, replay, e := s.CreateInstance(ctx, c, actor, opID, in, now)
		if e != nil || replay || op.Protocol != nodeproto.NetworkProtocol {
			t.Fatal(op, e)
		}
		task, e := nodeproto.DecodeTask(op.Request)
		if e != nil || task.Network.InstanceID != opID {
			t.Fatal(task, e)
		}
		again, replay, e := s.CreateInstance(ctx, c, actor, opID, in, now)
		if e != nil || !replay || again.RequestSHA != op.RequestSHA {
			t.Fatal("staff replay changed network", e)
		}
	})
	for _, cause := range []string{"wrong_owner", "disabled_pool", "network_audit_failure", "binding_insert_failure"} {
		t.Run(cause, func(t *testing.T) {
			p, now := mysqlNode(t, s)
			owner := id()
			c := mysqlVPCConfig(t, s, p, owner, now)
			r := mysqlVPCRequest(p, owner)
			switch cause {
			case "wrong_owner":
				r.OwnerRef = id()
				c.NetworkProfiles[0].OwnerRef = r.OwnerRef
			case "disabled_pool":
				if _, e := s.DB.Exec("UPDATE controller_network_pools SET enabled=FALSE WHERE id=?", c.NetworkProfiles[0].PoolID); e != nil {
					t.Fatal(e)
				}
			case "network_audit_failure":
				if _, e := s.DB.Exec("CREATE TRIGGER vpc_reject_audit BEFORE INSERT ON controller_audit FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='fixture refusal'"); e != nil {
					t.Fatal(e)
				}
				defer s.DB.Exec("DROP TRIGGER vpc_reject_audit")
			case "binding_insert_failure":
				if _, e := s.DB.Exec("CREATE TRIGGER vpc_reject_binding BEFORE INSERT ON controller_instance_networks FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='fixture refusal'"); e != nil {
					t.Fatal(e)
				}
				defer s.DB.Exec("DROP TRIGGER vpc_reject_binding")
			}
			c.NetworkProfiles[0].ConfigurationSHA256 = r.ConfigurationSHA256
			if _, _, e := s.Admit(ctx, r, c.Candidates(r), now, time.Minute); e == nil {
				t.Fatal("unsafe admission succeeded")
			}
			for _, q := range []string{
				"SELECT COUNT(*) FROM controller_jobs WHERE operation_id=?",
				"SELECT COUNT(*) FROM controller_reservations WHERE operation_id=?",
				"SELECT COUNT(*) FROM controller_network_leases WHERE id=?",
				"SELECT COUNT(*) FROM controller_instance_networks WHERE operation_id=?",
				"SELECT COUNT(*) FROM controller_audit WHERE target=?",
			} {
				var n int
				if e := s.DB.QueryRow(q, r.OperationID).Scan(&n); e != nil || n != 0 {
					t.Fatal("partial admission persisted", q, n, e)
				}
			}
			var instances int
			if e := s.DB.QueryRow("SELECT COUNT(*) FROM controller_instances WHERE node_id=?", p.ID).Scan(&instances); e != nil || instances != 0 {
				t.Fatal("orphan instance persisted", instances, e)
			}
		})
	}
}
func TestMySQLVPCParallelAllocationAndBindingDriftFailClosed(t *testing.T) {
	s := consoleHTTPStore(t)
	ctx := context.Background()
	p, now := mysqlNode(t, s)
	owner := id()
	c := mysqlVPCConfig(t, s, p, owner, now)
	seed := mysqlVPCRequest(p, owner)
	c.NetworkProfiles[0].ConfigurationSHA256 = seed.ConfigurationSHA256
	var accepted, bad atomic.Int32
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := mysqlVPCRequest(p, owner)
			j, _, e := s.Admit(ctx, r, c.Candidates(r), now, time.Minute)
			if e == nil && j.State == "accepted" {
				accepted.Add(1)
			} else if !errors.Is(e, ErrCapacity) {
				bad.Add(1)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 3 || bad.Load() != 0 {
		t.Fatal("IP/capacity reservation oversold or leaked", accepted.Load(), bad.Load())
	}
	for _, q := range []string{
		"SELECT COUNT(*) FROM controller_instances WHERE node_id=?",
		"SELECT COUNT(*) FROM controller_reservations WHERE node_id=?",
		"SELECT COUNT(*) FROM controller_instance_networks WHERE node_id=?",
		"SELECT COUNT(DISTINCT address) FROM controller_network_leases WHERE node_id=?",
	} {
		var n int
		if e := s.DB.QueryRow(q, p.ID).Scan(&n); e != nil || n != 3 {
			t.Fatal("parallel bindings disagree", q, n, e)
		}
	}
	var operation string
	if e := s.DB.QueryRow("SELECT operation_id FROM controller_jobs WHERE node_id=? LIMIT 1", p.ID).Scan(&operation); e != nil {
		t.Fatal(e)
	}
	if _, e := s.DB.Exec("UPDATE controller_network_pools SET enabled=FALSE WHERE id=?", c.NetworkProfiles[0].PoolID); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Claim(ctx, operation, p.Digest(), now, time.Minute); !errors.Is(e, ErrState) {
		t.Fatal("disabled pool permitted dispatch", e)
	}
	j, e := s.Lookup(ctx, operation)
	if e != nil || j.State != "accepted" {
		t.Fatal("failed validation consumed dispatch", j, e)
	}
	if _, e = s.DB.Exec("UPDATE controller_network_pools SET enabled=TRUE WHERE id=?", c.NetworkProfiles[0].PoolID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec("UPDATE controller_instance_networks SET network_sha256=? WHERE operation_id=?", strings.Repeat("f", 64), operation); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Claim(ctx, operation, p.Digest(), now, time.Minute); !errors.Is(e, ErrState) {
		t.Fatal("tampered immutable binding permitted dispatch", e)
	}
}

func TestMySQLVPCBindingMigrationReentryAndConflictingShape(t *testing.T) {
	s := consoleHTTPStore(t)
	ctx := context.Background()
	if _, e := s.DB.Exec("DELETE FROM controller_schema WHERE version=6"); e != nil {
		t.Fatal(e)
	}
	if e := s.Migrate(ctx); e != nil {
		t.Fatal("correct partial migration could not reenter", e)
	}
	if _, e := s.DB.Exec("DELETE FROM controller_schema WHERE version=6"); e != nil {
		t.Fatal(e)
	}
	if _, e := s.DB.Exec("DROP TABLE controller_instance_networks"); e != nil {
		t.Fatal(e)
	}
	if _, e := s.DB.Exec("CREATE VIEW controller_instance_networks AS SELECT id AS instance_id FROM controller_instances"); e != nil {
		t.Fatal(e)
	}
	if e := s.Migrate(ctx); !errors.Is(e, networking.ErrConflict) {
		t.Fatal("migration did not classify conflicting view as schema conflict", e)
	}
	var n int
	if e := s.DB.QueryRow("SELECT COUNT(*) FROM controller_schema WHERE version=6").Scan(&n); e != nil || n != 0 {
		t.Fatal("failed migration recorded success", n, e)
	}
	if _, e := s.DB.Exec("DROP VIEW controller_instance_networks"); e != nil {
		t.Fatal(e)
	}
	if e := s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	if _, e := s.DB.Exec("DROP INDEX controller_instance_network_operation ON controller_instance_networks"); e != nil {
		t.Fatal(e)
	}
	if _, e := s.DB.Exec("CREATE INDEX controller_instance_network_operation ON controller_instance_networks(operation_id)"); e != nil {
		t.Fatal(e)
	}
	if e := s.Check(ctx); !errors.Is(e, networking.ErrConflict) {
		t.Fatal("binding operation uniqueness silently lost", e)
	}
}

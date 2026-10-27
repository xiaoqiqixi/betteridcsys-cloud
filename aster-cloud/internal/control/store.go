package control

import (
	"aster/billing/controllerapi"
	"aster/cloud/internal/identity"
	"aster/cloud/internal/networking"
	"aster/cloud/internal/nodeproto"
	"aster/cloud/migrations"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
)

type SQLStore struct{ DB *sql.DB }

func OpenDSN(raw string) (*SQLStore, error) {
	c, e := mysql.ParseDSN(strings.TrimSpace(raw))
	if e != nil || c.DBName == "" || !(c.DBName == "aster_controller" || strings.HasPrefix(c.DBName, "aster_controller_") || c.DBName == "aster_cloud" || strings.HasPrefix(c.DBName, "aster_cloud_")) || c.MultiStatements || c.AllowAllFiles || c.AllowCleartextPasswords || c.AllowOldPasswords || c.TLSConfig == "skip-verify" || c.TLSConfig == "preferred" {
		return nil, ErrInput
	}
	if c.Net != "unix" && !(c.Net == "tcp" && (strings.HasPrefix(c.Addr, "127.0.0.1:") || strings.HasPrefix(c.Addr, "[::1]:"))) {
		return nil, ErrInput
	}
	c.ParseTime = true
	c.Loc = time.UTC
	c.Timeout = 5 * time.Second
	c.ReadTimeout = 10 * time.Second
	c.WriteTimeout = 10 * time.Second
	c.MultiStatements = false
	db, e := sql.Open("mysql", c.FormatDSN())
	if e != nil {
		return nil, ErrUnavailable
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(5 * time.Minute)
	return &SQLStore{db}, nil
}
func (s *SQLStore) Ping(c context.Context) error { return s.DB.PingContext(c) }
func (s *SQLStore) Migrate(ctx context.Context) error {
	conn, e := s.DB.Conn(ctx)
	if e != nil {
		return e
	}
	defer conn.Close()
	var locked int
	if e = conn.QueryRowContext(ctx, "SELECT GET_LOCK('aster_controller_schema_v1',5)").Scan(&locked); e != nil || locked != 1 {
		return ErrUnavailable
	}
	defer conn.ExecContext(context.Background(), "DO RELEASE_LOCK('aster_controller_schema_v1')")
	// Existing prefixes are immutable. Apply only new numbered files; a partial
	// InnoDB DDL migration is re-entered via idempotent CREATE, never fake-marked.
	if _, e = conn.ExecContext(ctx, strings.TrimSpace(strings.Split(migrations.SQL, ";")[0])); e != nil {
		return e
	}
	for _, migration := range migrations.All() {
		h := sha256.Sum256([]byte(migration.SQL))
		want := hex.EncodeToString(h[:])
		var have string
		e = conn.QueryRowContext(ctx, "SELECT sha256 FROM controller_schema WHERE version=?", migration.Version).Scan(&have)
		if e == nil {
			if have != want {
				return ErrConflict
			}
			continue
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		var existingIndexes map[string]bool
		if migration.Version == 5 {
			if e = networking.CheckMigration(ctx, conn, true); e != nil {
				return e
			}
		}
		if migration.Version == 6 {
			if e = networking.CheckTaskBindingMigration(ctx, conn, true); e != nil {
				return e
			}
		}
		if migration.Version == 7 {
			if e = networking.CheckOverlayMigration(ctx, conn, true); e != nil {
				return e
			}
		}
		if migration.Version == 8 {
			if e = networking.CheckPublicIPMigration(ctx, conn, true); e != nil {
				return e
			}
		}
		if migration.Version == 9 {
			if e = networking.CheckPublicIPResourceMigration(ctx, conn, true); e != nil {
				return e
			}
		}
		if migration.Version == 10 {
			if e = networking.CheckPublicIngressMigration(ctx, conn, true); e != nil {
				return e
			}
		}
		if migration.Version == 4 {
			existingIndexes, e = auditIndexMigrationPlan(ctx, conn, migration.SQL)
			if e != nil {
				return e
			}
		}
		if migration.Version == 11 {
			existingIndexes, e = usersPaginationMigrationPlan(ctx, conn, migration.SQL)
			if e != nil {
				return e
			}
		}
		if migration.Version == 12 {
			existingIndexes, e = identity.IdentityMigrationPlan(ctx, conn, migration.SQL)
			if errors.Is(e, identity.ErrConflict) {
				return ErrConflict
			}
			if e != nil {
				return e
			}
		}
		for _, statement := range strings.Split(migration.SQL, ";") {
			if q := strings.TrimSpace(statement); q != "" {
				if existingIndexes[q] {
					continue
				}
				if _, e = conn.ExecContext(ctx, q); e != nil {
					return e
				}
			}
		}
		if migration.Version == 4 {
			if e = checkAuditQueryIndexes(ctx, conn); e != nil {
				return e
			}
		}
		if migration.Version == 11 {
			if e = checkUsersPaginationIndex(ctx, conn); e != nil {
				return e
			}
		}
		if migration.Version == 12 {
			if e = identity.CheckOperationsSchema(ctx, conn); errors.Is(e, identity.ErrConflict) {
				return ErrConflict
			}
			if e != nil {
				return e
			}
		}
		if migration.Version == 5 {
			if e = networking.CheckMigration(ctx, conn, false); e != nil {
				return e
			}
		}
		if migration.Version == 6 {
			if e = networking.CheckTaskBindingMigration(ctx, conn, false); e != nil {
				return e
			}
		}
		if migration.Version == 7 {
			if e = networking.CheckOverlayMigration(ctx, conn, false); e != nil {
				return e
			}
		}
		if migration.Version == 8 {
			if e = networking.CheckPublicIPMigration(ctx, conn, false); e != nil {
				return e
			}
		}
		if migration.Version == 9 {
			if e = networking.CheckPublicIPResourceMigration(ctx, conn, false); e != nil {
				return e
			}
		}
		if migration.Version == 10 {
			if e = networking.CheckPublicIngressMigration(ctx, conn, false); e != nil {
				return e
			}
		}
		if _, e = conn.ExecContext(ctx, "INSERT INTO controller_schema(version,sha256,applied_at) VALUES(?,?,?)", migration.Version, want, time.Now().UTC()); e != nil {
			return e
		}
	}
	return s.Check(ctx)
}
func (s *SQLStore) Check(ctx context.Context) error {
	all := migrations.All()
	var n int
	if e := s.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM controller_schema").Scan(&n); e != nil || n != len(all) {
		return ErrConflict
	}
	for _, m := range all {
		h := sha256.Sum256([]byte(m.SQL))
		var have string
		if e := s.DB.QueryRowContext(ctx, "SELECT sha256 FROM controller_schema WHERE version=?", m.Version).Scan(&have); e != nil {
			return e
		}
		if have != hex.EncodeToString(h[:]) {
			return ErrConflict
		}
	}
	for _, query := range []string{"SELECT id FROM controller_lock WHERE id=1", "SELECT id,profile_sha256,datacenter_id,maintenance,heartbeat_at,free_cpu,free_memory_mib,free_disk_gib,capabilities,updated_at FROM controller_nodes LIMIT 0", "SELECT " + jobColumns + " FROM controller_jobs LIMIT 0", "SELECT id,owner_ref,node_id,hostname,state,resources,created_at,updated_at FROM controller_instances LIMIT 0", "SELECT operation_id,node_id,cpu,memory_mib,disk_gib,released,created_at FROM controller_reservations LIMIT 0", "SELECT id,actor,action,target,created_at FROM controller_audit LIMIT 0", "SELECT id,state,request_json FROM controller_operations LIMIT 0", "SELECT id,instance_id FROM controller_artifacts LIMIT 0", "SELECT id,phase FROM controller_migrations LIMIT 0"} {
		rows, e := s.DB.QueryContext(ctx, query)
		if e != nil {
			return e
		}
		rows.Close()
	}
	if err := checkAuditQueryIndexes(ctx, s.DB); err != nil {
		return err
	}
	if err := checkUsersPaginationIndex(ctx, s.DB); err != nil {
		return err
	}
	if err := identity.CheckOperationsSchema(ctx, s.DB); errors.Is(err, identity.ErrConflict) {
		return ErrConflict
	} else if err != nil {
		return err
	}
	if e := (&networking.Store{DB: s.DB}).Check(ctx); e != nil {
		return e
	}
	if e := networking.CheckTaskBindingMigration(ctx, s.DB, false); e != nil {
		return e
	}
	if e := networking.CheckOverlayMigration(ctx, s.DB, false); e != nil {
		return e
	}
	if e := networking.CheckPublicIPMigration(ctx, s.DB, false); e != nil {
		return e
	}
	if e := networking.CheckPublicIPResourceMigration(ctx, s.DB, false); e != nil {
		return e
	}
	return networking.CheckPublicIngressMigration(ctx, s.DB, false)
}
func (s *SQLStore) locked(ctx context.Context) (*sql.Tx, error) {
	// ponytail: one database gate serializes mutations; replace with ordered node/
	// operation row locking only after measured scheduler throughput needs it.
	tx, e := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if e != nil {
		return nil, e
	}
	var n int
	if e = tx.QueryRowContext(ctx, "SELECT id FROM controller_lock WHERE id=1 FOR UPDATE").Scan(&n); e != nil {
		tx.Rollback()
		return nil, e
	}
	return tx, nil
}

const jobColumns = "operation_id,order_id,controller_id,request_sha256,request_json,instance_id,node_id,node_profile_sha256,node_request_sha256,node_request,state,created_at,updated_at"

func scanJob(row interface{ Scan(...any) error }) (Job, error) {
	var j Job
	e := row.Scan(&j.OperationID, &j.OrderID, &j.ControllerID, &j.RequestSHA, &j.RequestJSON, &j.InstanceID, &j.NodeID, &j.NodeProfileSHA, &j.NodeRequestSHA, &j.NodeRequest, &j.State, &j.CreatedAt, &j.UpdatedAt)
	if errors.Is(e, sql.ErrNoRows) {
		return Job{}, ErrNotFound
	}
	return j, e
}
func (s *SQLStore) Lookup(ctx context.Context, op string) (Job, error) {
	return scanJob(s.DB.QueryRowContext(ctx, "SELECT "+jobColumns+" FROM controller_jobs WHERE operation_id=?", op))
}
func audit(ctx context.Context, tx *sql.Tx, actor, action, target string, now time.Time) error {
	_, e := tx.ExecContext(ctx, "INSERT INTO controller_audit(actor,action,target,created_at) VALUES(?,?,?,?)", actor, action, target, now)
	return e
}
func (s *SQLStore) Admit(ctx context.Context, r controllerapi.Request, candidates []Candidate, now time.Time, ttl time.Duration) (Job, bool, error) {
	raw, digest, e := r.BytesAndDigest()
	if e != nil {
		return Job{}, false, ErrInput
	}
	tx, e := s.locked(ctx)
	if e != nil {
		return Job{}, false, e
	}
	defer tx.Rollback()
	if e = publicIngressOperationIDUnusedTx(ctx, tx, r.OperationID); e != nil {
		return Job{}, false, e
	}
	prior, e := scanJob(tx.QueryRowContext(ctx, "SELECT "+jobColumns+" FROM controller_jobs WHERE operation_id=?", r.OperationID))
	if e == nil {
		if prior.ControllerID != r.Product.ControllerID || prior.RequestSHA != digest {
			return Job{}, false, ErrConflict
		}
		return prior, true, tx.Commit()
	}
	if !errors.Is(e, ErrNotFound) {
		return Job{}, false, e
	}
	var namespaceCount int
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM controller_operations WHERE id=?", r.OperationID).Scan(&namespaceCount); e != nil {
		return Job{}, false, e
	}
	if namespaceCount != 0 {
		return Job{}, false, ErrConflict
	}
	var other string
	e = tx.QueryRowContext(ctx, "SELECT operation_id FROM controller_jobs WHERE order_id=?", r.OrderID).Scan(&other)
	if e == nil {
		return Job{}, false, ErrConflict
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return Job{}, false, e
	}
	j := Job{OperationID: r.OperationID, OrderID: r.OrderID, ControllerID: r.Product.ControllerID, RequestSHA: digest, RequestJSON: raw, NodeRequest: []byte{}, State: "rejected", CreatedAt: now, UpdatedAt: now}
	supported := false
	fresh := false
	for _, candidate := range candidates {
		if candidate.DirectPublicRequired {
			continue
		}
		n := candidate.Node
		var profile string
		var maintenance bool
		var seen sql.NullTime
		var cpu, mem, disk int64
		var caps []byte
		e = tx.QueryRowContext(ctx, "SELECT profile_sha256,maintenance,heartbeat_at,free_cpu,free_memory_mib,free_disk_gib,capabilities FROM controller_nodes WHERE id=?", n.ID).Scan(&profile, &maintenance, &seen, &cpu, &mem, &disk, &caps)
		if errors.Is(e, sql.ErrNoRows) {
			continue
		}
		if e != nil {
			return Job{}, false, e
		}
		var at *time.Time
		if seen.Valid {
			at = &seen.Time
		}
		if profile != candidate.ProfileSHA || maintenance || !heartbeatFresh(at, now, ttl) {
			continue
		}
		fresh = true
		var capability Capability
		if !strict(caps, &capability) {
			return Job{}, false, ErrUnavailable
		}
		if !capability.SupportsNetwork(candidate.Resources, n, candidate.NetworkProfileID) {
			continue
		}
		supported = true
		var rc, rm, rd int64
		e = tx.QueryRowContext(ctx, "SELECT COALESCE(SUM(cpu),0),COALESCE(SUM(memory_mib),0),COALESCE(SUM(disk_gib),0) FROM controller_reservations WHERE node_id=? AND released=FALSE", n.ID).Scan(&rc, &rm, &rd)
		if e != nil {
			return Job{}, false, e
		}
		rsc := candidate.Resources
		// Reservations remain conservative after heartbeat (including existing VMs),
		// so externally consumed capacity can never be sold as a fresh reservation.
		if int64(rsc.CPUCores) > cpu-rc || int64(rsc.MemoryMiB) > mem-rm || int64(rsc.SystemDiskGiB) > disk-rd {
			continue
		}
		j.InstanceID = id()
		j.NodeID = n.ID
		j.NodeProfileSHA = candidate.ProfileSHA
		j.State = "accepted"
		task := nodeproto.NodeTask{Protocol: nodeproto.Protocol, OperationID: j.OperationID, NodeID: n.ID, Action: "create", InstanceID: j.InstanceID, OwnerRef: r.OwnerRef, Hostname: r.Hostname, Resources: rsc}
		resourceRaw, _ := json.Marshal(rsc)
		if _, e = tx.ExecContext(ctx, "INSERT INTO controller_instances(id,owner_ref,node_id,hostname,state,resources,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)", j.InstanceID, r.OwnerRef, n.ID, r.Hostname, "reserved", resourceRaw, now, now); e != nil {
			return Job{}, false, e
		}
		task, e = bindCreateNetwork(ctx, tx, task, candidate, now)
		if e != nil {
			return Job{}, false, e
		}
		j.NodeRequest, j.NodeRequestSHA, e = task.BytesAndDigest()
		if e != nil {
			return Job{}, false, e
		}
		if e = insertNetworkBinding(ctx, tx, task, j.NodeRequestSHA, now); e != nil {
			return Job{}, false, e
		}
		if e = reserveOverlayCreation(ctx, tx, candidate, task, now); e != nil {
			return Job{}, false, e
		}
		if _, e = tx.ExecContext(ctx, "INSERT INTO controller_reservations(operation_id,node_id,cpu,memory_mib,disk_gib,released,created_at) VALUES(?,?,?,?,?,FALSE,?)", j.OperationID, n.ID, rsc.CPUCores, rsc.MemoryMiB, rsc.SystemDiskGiB, now); e != nil {
			return Job{}, false, e
		}
		break
	}
	if j.State == "rejected" && len(candidates) > 0 && (!fresh || supported) {
		return Job{}, false, ErrCapacity
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO controller_jobs("+jobColumns+") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", j.OperationID, j.OrderID, j.ControllerID, j.RequestSHA, j.RequestJSON, j.InstanceID, j.NodeID, j.NodeProfileSHA, j.NodeRequestSHA, j.NodeRequest, j.State, now, now); e != nil {
		return Job{}, false, e
	}
	if e = audit(ctx, tx, "billing:"+r.Product.ControllerID, "provisioning."+j.State, j.OperationID, now); e != nil {
		return Job{}, false, e
	}
	return j, false, tx.Commit()
}
func (s *SQLStore) Claim(ctx context.Context, op, profile string, now time.Time, ttl time.Duration) (Job, error) {
	tx, e := s.locked(ctx)
	if e != nil {
		return Job{}, e
	}
	defer tx.Rollback()
	j, e := scanJob(tx.QueryRowContext(ctx, "SELECT "+jobColumns+" FROM controller_jobs WHERE operation_id=?", op))
	if e != nil {
		return Job{}, e
	}
	if j.State != "accepted" || profile != j.NodeProfileSHA {
		return Job{}, ErrState
	}
	task, e := nodeproto.DecodeTask(j.NodeRequest)
	if e != nil || nodeproto.Digest(j.NodeRequest) != j.NodeRequestSHA || task.OperationID != j.OperationID || task.InstanceID != j.InstanceID || task.NodeID != j.NodeID || task.Action != "create" {
		return Job{}, ErrState
	}
	if e = validateTaskNetwork(ctx, tx, task); e != nil {
		return Job{}, e
	}
	// Nodes execute one operation at a time and reject, rather than queue, a
	// second POST. Keep accepted jobs here until the prior operation is proven
	// terminal; unknown future states must never accidentally free the node.
	var occupied int
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM controller_jobs WHERE node_id=? AND operation_id<>? AND CAST(state AS BINARY) NOT IN ('accepted','succeeded','rejected')", j.NodeID, op).Scan(&occupied); e != nil {
		return Job{}, e
	}
	if occupied != 0 {
		return Job{}, ErrState
	}
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM controller_operations WHERE node_id=? AND CAST(state AS BINARY) NOT IN ('accepted','succeeded','rejected')", j.NodeID).Scan(&occupied); e != nil {
		return Job{}, e
	}
	if occupied != 0 {
		return Job{}, ErrState
	}
	if e = transferOccupancy(ctx, tx, j.NodeID).Scan(&occupied); e != nil {
		return Job{}, e
	}
	if occupied != 0 {
		return Job{}, ErrState
	}
	var maintenance bool
	var seen sql.NullTime
	var stored string
	e = tx.QueryRowContext(ctx, "SELECT maintenance,heartbeat_at,profile_sha256 FROM controller_nodes WHERE id=?", j.NodeID).Scan(&maintenance, &seen, &stored)
	if e != nil {
		return Job{}, e
	}
	if maintenance || !seen.Valid || stored != profile || !heartbeatFresh(&seen.Time, now, ttl) {
		return Job{}, ErrCapacity
	}
	if _, e = tx.ExecContext(ctx, "UPDATE controller_jobs SET state='sending',updated_at=? WHERE operation_id=?", now, op); e != nil {
		return Job{}, e
	}
	if e = audit(ctx, tx, "host-operator", "node.dispatch_claimed", op, now); e != nil {
		return Job{}, e
	}
	j.State = "sending"
	j.UpdatedAt = now
	return j, tx.Commit()
}
func (s *SQLStore) Complete(ctx context.Context, op, status string, now time.Time) (Job, error) {
	next, instance := "uncertain", "unknown"
	switch status {
	case "accepted":
		next, instance = "dispatched", "creating"
	case "succeeded":
		next, instance = "succeeded", "created"
	case "rejected":
		next, instance = "rejected", "rejected"
	case "uncertain":
	default:
		return Job{}, ErrInput
	}
	tx, e := s.locked(ctx)
	if e != nil {
		return Job{}, e
	}
	defer tx.Rollback()
	j, e := scanJob(tx.QueryRowContext(ctx, "SELECT "+jobColumns+" FROM controller_jobs WHERE operation_id=?", op))
	if e != nil {
		return Job{}, e
	}
	if j.State == "succeeded" || j.State == "rejected" {
		if j.State != next {
			return Job{}, ErrConflict
		}
		return j, tx.Commit()
	}
	if j.State != "sending" && j.State != "uncertain" && j.State != "dispatched" {
		return Job{}, ErrState
	}
	if _, e = tx.ExecContext(ctx, "UPDATE controller_jobs SET state=?,updated_at=? WHERE operation_id=?", next, now, op); e != nil {
		return Job{}, e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE controller_instances SET state=?,updated_at=? WHERE id=?", instance, now, j.InstanceID); e != nil {
		return Job{}, e
	}
	if next == "rejected" {
		if _, e = tx.ExecContext(ctx, "UPDATE controller_reservations SET released=TRUE WHERE operation_id=?", op); e != nil {
			return Job{}, e
		}
	}
	if e = audit(ctx, tx, "host-operator", "node.result_"+next, op, now); e != nil {
		return Job{}, e
	}
	j.State = next
	j.UpdatedAt = now
	return j, tx.Commit()
}
func (s *SQLStore) RegisterNode(ctx context.Context, p NodeProfile) error {
	if !p.Valid() {
		return ErrInput
	}
	tx, e := s.locked(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	// Registering/replacing host policy always closes admission until an actual
	// authenticated heartbeat and explicit maintenance release occur.
	if _, e = tx.ExecContext(ctx, "INSERT INTO controller_nodes(id,profile_sha256,datacenter_id,maintenance,capabilities,updated_at) VALUES(?,?,?,TRUE,?,?) ON DUPLICATE KEY UPDATE profile_sha256=VALUES(profile_sha256),datacenter_id=VALUES(datacenter_id),maintenance=TRUE,heartbeat_at=NULL,capabilities=VALUES(capabilities),updated_at=VALUES(updated_at)", p.ID, p.Digest(), p.DatacenterID, []byte("{}"), now); e != nil {
		return e
	}
	if e = audit(ctx, tx, "host-operator", "node.registered", p.ID, now); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *SQLStore) Heartbeat(ctx context.Context, p NodeProfile, c Capability, now time.Time, ttl time.Duration) error {
	at, e := time.Parse(time.RFC3339Nano, c.ObservedAt)
	if e != nil || !heartbeatFresh(&at, now, ttl) || c.Protocol != nodeproto.Protocol || c.NodeID != p.ID || c.Hypervisor != "libvirt-kvm" || !c.validNetworkCapabilities() {
		return ErrInput
	}
	v := c.Capacity
	if v.CPUCoresTotal < 0 || v.CPUCoresAllocated < 0 || v.CPUCoresAllocated > v.CPUCoresTotal || v.MemoryTotalMiB < 0 || v.MemoryAllocatedMiB < 0 || v.MemoryAllocatedMiB > v.MemoryTotalMiB || v.MemoryAvailableMiB < 0 || v.MemoryAvailableMiB > v.MemoryTotalMiB || v.StorageTotalGiB < 0 || v.StorageAllocatedGiB < 0 || v.StorageAllocatedGiB > v.StorageTotalGiB || v.StorageAvailableGiB < 0 || v.StorageAvailableGiB > v.StorageTotalGiB {
		return ErrInput
	}
	freeCPU := v.CPUCoresTotal - v.CPUCoresAllocated
	freeMem := min(v.MemoryAvailableMiB, v.MemoryTotalMiB-v.MemoryAllocatedMiB)
	freeDisk := min(v.StorageAvailableGiB, v.StorageTotalGiB-v.StorageAllocatedGiB)
	raw, _ := json.Marshal(c)
	tx, e := s.locked(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	result, e := tx.ExecContext(ctx, "UPDATE controller_nodes SET heartbeat_at=?,free_cpu=?,free_memory_mib=?,free_disk_gib=?,capabilities=?,maintenance=(maintenance OR ?),updated_at=? WHERE id=? AND profile_sha256=?", at, freeCPU, freeMem, freeDisk, raw, c.Maintenance, now, p.ID, p.Digest())
	if e != nil {
		return e
	}
	n, e := result.RowsAffected()
	if e != nil || n != 1 {
		return ErrConflict
	}
	if e = audit(ctx, tx, "host-operator", "node.heartbeat", p.ID, now); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *SQLStore) Maintenance(ctx context.Context, node string, on bool) error {
	tx, e := s.locked(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var raw []byte
	if e = tx.QueryRowContext(ctx, "SELECT capabilities FROM controller_nodes WHERE id=?", node).Scan(&raw); e != nil {
		return e
	}
	var caps Capability
	if !on && (!strict(raw, &caps) || caps.Maintenance) {
		return ErrState
	}
	if _, e = tx.ExecContext(ctx, "UPDATE controller_nodes SET maintenance=?,updated_at=? WHERE id=?", on, time.Now().UTC(), node); e != nil {
		return e
	}
	action := "node.maintenance_off"
	if on {
		action = "node.maintenance_on"
	}
	if e = audit(ctx, tx, "host-operator", action, node, time.Now().UTC()); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *SQLStore) Nodes(ctx context.Context) ([]NodeView, error) {
	rows, e := s.DB.QueryContext(ctx, "SELECT n.id,n.datacenter_id,n.maintenance,n.heartbeat_at,n.free_cpu,n.free_memory_mib,n.free_disk_gib,COALESCE(SUM(CASE WHEN r.released=FALSE THEN r.cpu ELSE 0 END),0),COALESCE(SUM(CASE WHEN r.released=FALSE THEN r.memory_mib ELSE 0 END),0),COALESCE(SUM(CASE WHEN r.released=FALSE THEN r.disk_gib ELSE 0 END),0) FROM controller_nodes n LEFT JOIN controller_reservations r ON r.node_id=n.id GROUP BY n.id ORDER BY n.id LIMIT 100")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []NodeView{}
	for rows.Next() {
		var n NodeView
		if e = rows.Scan(&n.ID, &n.DatacenterID, &n.Maintenance, &n.HeartbeatAt, &n.FreeCPU, &n.FreeMemoryMiB, &n.FreeDiskGiB, &n.ReservedCPU, &n.ReservedMemoryMiB, &n.ReservedDiskGiB); e != nil {
			return nil, e
		}
		out = append(out, n)
	}
	return out, rows.Err()
}
func (s *SQLStore) Instances(ctx context.Context) ([]Instance, error) {
	rows, e := s.DB.QueryContext(ctx, "SELECT id,owner_ref,node_id,hostname,state,resources,created_at,updated_at FROM controller_instances ORDER BY created_at DESC,id DESC LIMIT 100")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Instance{}
	for rows.Next() {
		var v Instance
		var raw []byte
		if e = rows.Scan(&v.ID, &v.OwnerRef, &v.NodeID, &v.Hostname, &v.State, &raw, &v.CreatedAt, &v.UpdatedAt); e != nil {
			return nil, e
		}
		if !strict(raw, &v.Resources) {
			return nil, ErrUnavailable
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *SQLStore) Jobs(ctx context.Context) ([]Job, error) {
	rows, e := s.DB.QueryContext(ctx, "SELECT "+jobColumns+" FROM controller_jobs ORDER BY created_at DESC,operation_id DESC LIMIT 100")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Job{}
	for rows.Next() {
		j, e := scanJob(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, j)
	}
	return out, rows.Err()
}
func (s *SQLStore) Audits(ctx context.Context) ([]Audit, error) {
	rows, e := s.DB.QueryContext(ctx, "SELECT id,actor,action,target,created_at FROM controller_audit ORDER BY id DESC LIMIT 100")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Audit{}
	for rows.Next() {
		var a Audit
		if e = rows.Scan(&a.ID, &a.Actor, &a.Action, &a.Target, &a.CreatedAt); e != nil {
			return nil, e
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

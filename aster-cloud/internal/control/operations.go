package control

import (
	"aster/billing/controllerapi"
	"aster/cloud/internal/nodeproto"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type OperationInput struct {
	Action       string `json:"action"`
	Confirmation string `json:"confirmation"`
	ArtifactID   string `json:"artifact_id,omitempty"`
	TargetNodeID string `json:"target_node_id,omitempty"`
}
type Operation struct {
	ID           string    `json:"id"`
	ActorID      string    `json:"actor_id"`
	InstanceID   string    `json:"instance_id"`
	NodeID       string    `json:"node_id"`
	Action       string    `json:"action"`
	ArtifactID   string    `json:"artifact_id"`
	TargetNodeID string    `json:"target_node_id"`
	State        string    `json:"state"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	ProfileSHA   string    `json:"-"`
	IntentSHA    string    `json:"-"`
	Protocol     string    `json:"-"`
	Request      []byte    `json:"-"`
	RequestSHA   string    `json:"-"`
	Seq          int64     `json:"-"`
}
type Artifact struct {
	ID          string    `json:"id"`
	InstanceID  string    `json:"instance_id"`
	NodeID      string    `json:"node_id"`
	Kind        string    `json:"kind"`
	State       string    `json:"state"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	ManifestSHA string    `json:"-"`
}
type Migration struct {
	SourceRetirementState       string                  `json:"source_retirement_state,omitempty"`
	SourceRetirementOperationID string                  `json:"source_retirement_operation_id,omitempty"`
	ID                          string                  `json:"id"`
	InstanceID                  string                  `json:"instance_id"`
	SourceNodeID                string                  `json:"source_node_id"`
	TargetNodeID                string                  `json:"target_node_id"`
	Phase                       string                  `json:"phase"`
	CreatedAt                   time.Time               `json:"created_at"`
	UpdatedAt                   time.Time               `json:"updated_at"`
	TargetProfileSHA            string                  `json:"-"`
	SourceOperationID           string                  `json:"-"`
	ManifestSHA                 string                  `json:"-"`
	FenceToken                  string                  `json:"-"`
	Resources                   controllerapi.Resources `json:"-"`
}

func OperationPermission(action string) string {
	switch action {
	case "create", "start", "shutdown", "public_adopt", "public_detach":
		return "instances.manage"
	case "reboot", "force_off", "delete":
		return "instances.dangerous"
	case "snapshot_create", "snapshot_delete", "backup_create", "backup_verify", "backup_delete":
		return "storage.manage"
	case "snapshot_restore", "backup_restore":
		return "storage.restore"
	case "migrate_prepare", "migrate_transfer", "migrate_import", "migrate_activate", "migrate_retire_source":
		return "migration.manage"
	}
	return ""
}

// Binding tasks are planned only by the resource API's locked version/CAS
// transaction. Their execution still uses the ordinary explicit task endpoints.
func publicIPBindingAction(action string) bool {
	return action == "public_adopt" || action == "public_detach"
}

func dangerous(action string) bool {
	switch action {
	case "reboot", "force_off", "delete", "snapshot_restore", "snapshot_delete", "backup_restore", "backup_delete", "migrate_prepare", "migrate_transfer", "migrate_activate", "migrate_retire_source":
		return true
	}
	return false
}
func (in OperationInput) valid(instance string) bool {
	if publicIPBindingAction(in.Action) || OperationPermission(in.Action) == "" || (in.Confirmation != "" && in.Confirmation != instance) || dangerous(in.Action) && in.Confirmation != instance {
		return false
	}
	switch in.Action {
	case "snapshot_create", "backup_create":
		return in.ArtifactID == "" && in.TargetNodeID == ""
	case "snapshot_restore", "snapshot_delete", "backup_verify", "backup_restore", "backup_delete", "migrate_transfer", "migrate_import", "migrate_activate", "migrate_retire_source":
		return nodeproto.ValidID(in.ArtifactID) && in.TargetNodeID == ""
	case "migrate_prepare":
		return in.ArtifactID == "" && nodeproto.ValidNodeID(in.TargetNodeID)
	default:
		return in.ArtifactID == "" && in.TargetNodeID == ""
	}
}

const operationColumns = "id,actor_id,instance_id,node_id,profile_sha256,action,artifact_id,target_node_id,intent_sha256,request_protocol,request_json,request_sha256,state,created_at,updated_at,seq"

func scanOperation(row interface{ Scan(...any) error }) (Operation, error) {
	var o Operation
	e := row.Scan(&o.ID, &o.ActorID, &o.InstanceID, &o.NodeID, &o.ProfileSHA, &o.Action, &o.ArtifactID, &o.TargetNodeID, &o.IntentSHA, &o.Protocol, &o.Request, &o.RequestSHA, &o.State, &o.CreatedAt, &o.UpdatedAt, &o.Seq)
	if errors.Is(e, sql.ErrNoRows) {
		e = ErrNotFound
	}
	return o, e
}
func (s *SQLStore) Operation(ctx context.Context, op string) (Operation, error) {
	return scanOperation(s.DB.QueryRowContext(ctx, "SELECT "+operationColumns+" FROM controller_operations WHERE id=?", op))
}
func scanInstance(row interface{ Scan(...any) error }) (Instance, error) {
	var v Instance
	var raw []byte
	e := row.Scan(&v.ID, &v.OwnerRef, &v.NodeID, &v.Hostname, &v.State, &raw, &v.CreatedAt, &v.UpdatedAt)
	if errors.Is(e, sql.ErrNoRows) {
		return v, ErrNotFound
	}
	if e == nil && !strict(raw, &v.Resources) {
		e = ErrUnavailable
	}
	return v, e
}
func (s *SQLStore) Instance(ctx context.Context, instance string) (Instance, error) {
	return scanInstance(s.DB.QueryRowContext(ctx, "SELECT id,owner_ref,node_id,hostname,state,resources,created_at,updated_at FROM controller_instances WHERE id=?", instance))
}
func scanMigration(row interface{ Scan(...any) error }) (Migration, error) {
	var m Migration
	var raw []byte
	e := row.Scan(&m.ID, &m.InstanceID, &m.SourceNodeID, &m.TargetNodeID, &m.TargetProfileSHA, &m.SourceOperationID, &raw, &m.ManifestSHA, &m.FenceToken, &m.Phase, &m.CreatedAt, &m.UpdatedAt)
	if errors.Is(e, sql.ErrNoRows) {
		e = ErrNotFound
	}
	if e == nil && !strict(raw, &m.Resources) {
		e = ErrUnavailable
	}
	return m, e
}

const migrationColumns = "id,instance_id,source_node_id,target_node_id,target_profile_sha256,source_operation_id,target_resources,manifest_sha256,fence_token,phase,created_at,updated_at"

func (s *SQLStore) CreateOperation(ctx context.Context, c Config, actor, instance, op string, in OperationInput, now time.Time) (Operation, bool, error) {
	return s.createOperation(ctx, c, actor, instance, op, in, now, nil)
}
func (s *SQLStore) createOperation(ctx context.Context, c Config, actor, instance, op string, in OperationInput, now time.Time, retire *nodeproto.StorageResult) (Operation, bool, error) {
	if !nodeproto.ValidID(actor) || !nodeproto.ValidID(instance) || !nodeproto.ValidID(op) || !in.valid(instance) {
		return Operation{}, false, ErrInput
	}
	intent, _ := json.Marshal(struct {
		Actor, Instance string
		Input           OperationInput
	}{actor, instance, in})
	fingerprint := nodeproto.Digest(intent)
	tx, e := s.locked(ctx)
	if e != nil {
		return Operation{}, false, e
	}
	defer tx.Rollback()
	if e = publicResourceIDUnusedTx(ctx, tx, op); e != nil {
		return Operation{}, false, e
	}
	prior, e := scanOperation(tx.QueryRowContext(ctx, "SELECT "+operationColumns+" FROM controller_operations WHERE id=?", op))
	if e == nil {
		if prior.ActorID != actor || prior.IntentSHA != fingerprint {
			return Operation{}, false, ErrConflict
		}
		return prior, true, tx.Commit()
	}
	if !errors.Is(e, ErrNotFound) {
		return Operation{}, false, e
	}
	// The node has a single namespace across original provisioning and console jobs.
	var used int
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM controller_jobs WHERE operation_id=?", op).Scan(&used); e != nil {
		return Operation{}, false, e
	}
	if used != 0 {
		return Operation{}, false, ErrConflict
	}
	v, e := scanInstance(tx.QueryRowContext(ctx, "SELECT id,owner_ref,node_id,hostname,state,resources,created_at,updated_at FROM controller_instances WHERE id=?", instance))
	if e != nil {
		return Operation{}, false, e
	}
	if v.State != "created" && v.State != "running" && v.State != "shutoff" {
		return Operation{}, false, ErrState
	}
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM controller_operations WHERE instance_id=? AND CAST(state AS BINARY) NOT IN ('succeeded','rejected')", instance).Scan(&used); e != nil {
		return Operation{}, false, e
	}
	if used != 0 {
		return Operation{}, false, ErrState
	}
	var moving int
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM controller_migrations WHERE instance_id=? AND CAST(phase AS BINARY) NOT IN ('active','rejected')", instance).Scan(&moving); e != nil {
		return Operation{}, false, e
	}
	if moving != 0 && in.Action != "migrate_transfer" && in.Action != "migrate_import" && in.Action != "migrate_activate" {
		return Operation{}, false, ErrState
	}
	o := Operation{ID: op, ActorID: actor, InstanceID: instance, NodeID: v.NodeID, Action: in.Action, ArtifactID: in.ArtifactID, TargetNodeID: in.TargetNodeID, IntentSHA: fingerprint, State: "accepted", CreatedAt: now, UpdatedAt: now}
	if !strings.HasPrefix(in.Action, "migrate_") || in.Action == "migrate_prepare" {
		if e = directPublicInstanceGateTx(ctx, tx, c, v); e != nil {
			return Operation{}, false, e
		}
	}
	direct, e := instanceDirectPublicTx(ctx, tx, v)
	if e != nil {
		return Operation{}, false, e
	}
	if direct.IsZero() && (in.Action == "start" || in.Action == "reboot" || strings.HasPrefix(in.Action, "migrate_")) {
		known, err := instanceHadDirectPublicTx(ctx, tx, v.ID)
		if err != nil {
			return Operation{}, false, err
		}
		if known {
			return Operation{}, false, ErrState
		}
	}
	if c.directRequired(v.NodeID) && direct.IsZero() && strings.HasPrefix(in.Action, "migrate_") {
		return Operation{}, false, ErrState
	}
	network, e := instanceNetworkBinding(ctx, tx, v)
	if e != nil {
		return Operation{}, false, e
	}
	if !network.IsZero() {
		if e = overlayLifecycleGate(ctx, tx, instance); e != nil {
			return Operation{}, false, e
		}
	}
	if !network.IsZero() && !networkActionSupported(in.Action) {
		return Operation{}, false, ErrState
	}
	st := nodeproto.TypedStorageTask{Protocol: nodeproto.StorageProtocol, OperationID: op, NodeID: v.NodeID, Action: in.Action, InstanceID: v.ID, OwnerRef: v.OwnerRef, ArtifactID: in.ArtifactID}
	if !direct.IsZero() {
		st.Protocol = nodeproto.StorageDirectProtocol
		st.DirectPublic = direct
	}
	switch in.Action {
	case "start", "shutdown", "reboot", "force_off", "delete":
		t := nodeproto.NodeTask{Protocol: nodeproto.Protocol, OperationID: op, NodeID: v.NodeID, Action: in.Action, InstanceID: v.ID, OwnerRef: v.OwnerRef, Hostname: v.Hostname, Resources: v.Resources}
		if !network.IsZero() {
			t.Protocol, t.Network = nodeproto.NetworkProtocol, network
		}
		if !direct.IsZero() {
			t.Protocol = nodeproto.DirectPublicProtocol
			t.DirectPublic = direct
		}
		if in.Action == "delete" {
			t.ConfirmInstanceID = v.ID
		}
		if !c.approvesTaskNetwork(t) {
			return Operation{}, false, ErrState
		}
		o.Protocol = t.Protocol
		o.Request, o.RequestSHA, e = t.BytesAndDigest()
	case "snapshot_create", "backup_create":
		if v.State != "shutoff" {
			return Operation{}, false, ErrState
		}
		o.ArtifactID = op
		st.ArtifactID = op
		kind := strings.TrimSuffix(in.Action, "_create")
		if _, e = tx.ExecContext(ctx, "INSERT INTO controller_artifacts(id,instance_id,node_id,kind,state,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", op, v.ID, v.NodeID, kind, "pending", now, now); e != nil {
			return Operation{}, false, e
		}
	case "snapshot_restore", "snapshot_delete", "backup_verify", "backup_restore", "backup_delete":
		var a Artifact
		e = tx.QueryRowContext(ctx, "SELECT id,instance_id,node_id,kind,state,manifest_sha256 FROM controller_artifacts WHERE id=?", in.ArtifactID).Scan(&a.ID, &a.InstanceID, &a.NodeID, &a.Kind, &a.State, &a.ManifestSHA)
		if errors.Is(e, sql.ErrNoRows) {
			return Operation{}, false, ErrNotFound
		}
		if e != nil {
			return Operation{}, false, e
		}
		if a.InstanceID != v.ID || a.NodeID != v.NodeID || a.State != "ready" || !strings.HasPrefix(in.Action, a.Kind+"_") {
			return Operation{}, false, ErrState
		}
		if in.Action != "backup_verify" && v.State != "shutoff" {
			return Operation{}, false, ErrState
		}
		if dangerous(in.Action) {
			st.ConfirmArtifactID = in.ArtifactID
		}
	case "migrate_prepare":
		if v.State != "shutoff" || moving != 0 || in.TargetNodeID == v.NodeID {
			return Operation{}, false, ErrState
		}
		if !direct.IsZero() {
			if _, err := directResourcePlacementTx(ctx, tx, c, v.ID, in.TargetNodeID); err != nil {
				return Operation{}, false, err
			}
		}
		target, ok := c.Node(in.TargetNodeID)
		if !ok {
			return Operation{}, false, ErrInput
		}
		resources := v.Resources
		resources.ComputeNodeID = target.ID
		resources.DatacenterID = target.DatacenterID
		resources.NodeGroupID = target.GroupID
		var maintenance bool
		var seen sql.NullTime
		var profile string
		var capsRaw []byte
		var cpu, mem, disk, rc, rm, rd int64
		e = tx.QueryRowContext(ctx, "SELECT profile_sha256,maintenance,heartbeat_at,free_cpu,free_memory_mib,free_disk_gib,capabilities FROM controller_nodes WHERE id=?", target.ID).Scan(&profile, &maintenance, &seen, &cpu, &mem, &disk, &capsRaw)
		if e != nil {
			return Operation{}, false, ErrCapacity
		}
		var caps Capability
		if !strict(capsRaw, &caps) || len(caps.StorageIDs) != 1 {
			return Operation{}, false, ErrCapacity
		}
		resources.SystemStorageID = caps.StorageIDs[0]
		if !direct.IsZero() {
			targetBinding := direct
			targetBinding.NodeID = target.ID
			targetBinding.Generation++
			if !directCapabilityMatches(caps, targetBinding) {
				return Operation{}, false, ErrCapacity
			}
		}
		if maintenance || !seen.Valid || !heartbeatFresh(&seen.Time, now, time.Duration(c.HeartbeatTTLSeconds)*time.Second) || profile != target.Digest() || !strict(capsRaw, &caps) || !caps.Supports(resources, target) {
			return Operation{}, false, ErrCapacity
		}
		e = tx.QueryRowContext(ctx, "SELECT COALESCE(SUM(cpu),0),COALESCE(SUM(memory_mib),0),COALESCE(SUM(disk_gib),0) FROM controller_reservations WHERE node_id=? AND released=FALSE", target.ID).Scan(&rc, &rm, &rd)
		if e != nil {
			return Operation{}, false, e
		}
		if int64(resources.CPUCores) > cpu-rc || int64(resources.MemoryMiB) > mem-rm || int64(resources.SystemDiskGiB) > disk-rd {
			return Operation{}, false, ErrCapacity
		}
		if _, e = tx.ExecContext(ctx, "INSERT INTO controller_reservations(operation_id,node_id,cpu,memory_mib,disk_gib,released,created_at) VALUES(?,?,?,?,?,FALSE,?)", op, target.ID, resources.CPUCores, resources.MemoryMiB, resources.SystemDiskGiB, now); e != nil {
			return Operation{}, false, e
		}
		o.ArtifactID = op
		st.ArtifactID = op
		st.TargetNodeID = target.ID
		if _, e = tx.ExecContext(ctx, "INSERT INTO controller_migrations("+migrationColumns+") VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", op, v.ID, v.NodeID, target.ID, target.Digest(), op, mustJSON(resources), "", "", "preparing", now, now); e != nil {
			return Operation{}, false, e
		}
	case "migrate_transfer":
		migration, e := scanMigration(tx.QueryRowContext(ctx, "SELECT "+migrationColumns+" FROM controller_migrations WHERE id=?", in.ArtifactID))
		if e != nil {
			return Operation{}, false, e
		}
		if migration.InstanceID != v.ID || migration.SourceNodeID != v.NodeID || migration.Phase != "prepared" || !shaRE.MatchString(migration.ManifestSHA) || !shaRE.MatchString(migration.FenceToken) {
			return Operation{}, false, ErrState
		}
		source, ok := c.Node(migration.SourceNodeID)
		if !ok {
			return Operation{}, false, ErrState
		}
		target, ok := c.Node(migration.TargetNodeID)
		if !ok || target.Digest() != migration.TargetProfileSHA {
			return Operation{}, false, ErrState
		}
		prepare, e := scanOperation(tx.QueryRowContext(ctx, "SELECT "+operationColumns+" FROM controller_operations WHERE id=?", migration.SourceOperationID))
		if e != nil || prepare.ProfileSHA != source.Digest() || prepare.State != "succeeded" {
			return Operation{}, false, ErrState
		}
		intent := TransferIntent{Protocol: TransferProtocol, SourceProfileSHA: source.Digest(), Approval: nodeproto.StorageInboxApprovalTask{Protocol: nodeproto.StorageProtocol, TransferID: op, ArtifactID: migration.ID, NodeID: target.ID, InstanceID: v.ID, OwnerRef: v.OwnerRef, SourceNodeID: source.ID, SourceOperationID: migration.SourceOperationID, TargetNodeID: target.ID, ManifestSHA256: migration.ManifestSHA, FenceToken: migration.FenceToken}}
		o.NodeID = target.ID
		o.TargetNodeID = target.ID
		o.Protocol = TransferProtocol
		o.Request, o.RequestSHA, e = intent.BytesAndDigest()
		if e != nil {
			return Operation{}, false, ErrInput
		}
	case "migrate_retire_source":
		st, e = buildRetireSourceTx(ctx, tx, c, o, v, retire)
		if e != nil {
			return Operation{}, false, e
		}
		o.NodeID = st.NodeID
		o.TargetNodeID = st.TargetNodeID
	case "migrate_import", "migrate_activate":
		m, e := scanMigration(tx.QueryRowContext(ctx, "SELECT "+migrationColumns+" FROM controller_migrations WHERE id=?", in.ArtifactID))
		if e != nil {
			return Operation{}, false, e
		}
		if m.InstanceID != v.ID || !shaRE.MatchString(m.ManifestSHA) || !shaRE.MatchString(m.FenceToken) {
			return Operation{}, false, ErrState
		}
		if in.Action == "migrate_import" && m.Phase != "prepared" && m.Phase != "transferred" || in.Action == "migrate_activate" && m.Phase != "imported" {
			return Operation{}, false, ErrState
		}
		target, ok := c.Node(m.TargetNodeID)
		if !ok || target.Digest() != m.TargetProfileSHA {
			return Operation{}, false, ErrState
		}
		o.NodeID = target.ID
		o.TargetNodeID = target.ID
		st.NodeID = target.ID
		if !direct.IsZero() {
			st.DirectPublic.NodeID = target.ID
			st.DirectPublic.Generation++
			if !c.approvesDirectPublic(st.DirectPublic) {
				return Operation{}, false, ErrState
			}
		}
		st.SourceNodeID = m.SourceNodeID
		st.TargetNodeID = target.ID
		st.SourceOperationID = m.SourceOperationID
		st.ManifestSHA256 = m.ManifestSHA
		st.FenceToken = m.FenceToken
		if in.Action == "migrate_activate" {
			st.ConfirmArtifactID = in.ArtifactID
		}
	default:
		return Operation{}, false, ErrInput
	}
	if e != nil {
		return Operation{}, false, e
	}
	if o.Protocol == "" {
		o.Protocol = st.Protocol
		o.Request, o.RequestSHA, e = st.BytesAndDigest()
		if e != nil {
			return Operation{}, false, ErrInput
		}
	}
	if in.Action == "migrate_prepare" && !direct.IsZero() {
		if e = freezeDirectMigrationTx(ctx, tx, o, direct, now); e != nil {
			return Operation{}, false, e
		}
	}
	p, ok := c.Node(o.NodeID)
	if !ok {
		return Operation{}, false, ErrState
	}
	o.ProfileSHA = p.Digest()
	_, e = tx.ExecContext(ctx, "INSERT INTO controller_operations("+strings.TrimSuffix(operationColumns, ",seq")+") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", o.ID, o.ActorID, o.InstanceID, o.NodeID, o.ProfileSHA, o.Action, o.ArtifactID, o.TargetNodeID, o.IntentSHA, o.Protocol, o.Request, o.RequestSHA, o.State, o.CreatedAt, o.UpdatedAt)
	if e != nil {
		return Operation{}, false, e
	}
	if e = audit(ctx, tx, "user:"+actor, "operation."+in.Action, op, now); e != nil {
		return Operation{}, false, e
	}
	return o, false, tx.Commit()
}
func (s *SQLStore) ClaimOperation(ctx context.Context, op string, c Config, now time.Time) (Operation, error) {
	tx, e := s.locked(ctx)
	if e != nil {
		return Operation{}, e
	}
	defer tx.Rollback()
	o, e := scanOperation(tx.QueryRowContext(ctx, "SELECT "+operationColumns+" FROM controller_operations WHERE id=?", op))
	if e != nil {
		return Operation{}, e
	}
	p, ok := c.Node(o.NodeID)
	if !ok || p.Digest() != o.ProfileSHA || o.State != "accepted" {
		return Operation{}, ErrState
	}
	if o.Protocol == nodeproto.Protocol || o.Protocol == nodeproto.NetworkProtocol || o.Protocol == nodeproto.DirectPublicProtocol {
		task, err := nodeproto.DecodeTask(o.Request)
		if err != nil || nodeproto.Digest(o.Request) != o.RequestSHA || task.Protocol != o.Protocol || task.OperationID != o.ID || task.InstanceID != o.InstanceID || task.Action != o.Action {
			return Operation{}, ErrState
		}
		if !c.approvesTaskNetwork(task) {
			return Operation{}, ErrState
		}
		if err = validateTaskNetwork(ctx, tx, task); err != nil {
			return Operation{}, err
		}
	} else {
		if e = validateDirectStorageTx(ctx, tx, c, o); e != nil {
			return Operation{}, e
		}
		var networked int
		if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM controller_instance_networks WHERE instance_id=?", o.InstanceID).Scan(&networked); e != nil {
			return Operation{}, e
		}
		if networked != 0 {
			return Operation{}, ErrState
		}
	}
	var occupied int
	for _, q := range []string{"SELECT COUNT(*) FROM controller_jobs WHERE node_id=? AND CAST(state AS BINARY) NOT IN ('accepted','succeeded','rejected')", "SELECT COUNT(*) FROM controller_operations WHERE node_id=? AND CAST(state AS BINARY) NOT IN ('accepted','succeeded','rejected')"} {
		if e = tx.QueryRowContext(ctx, q, o.NodeID).Scan(&occupied); e != nil {
			return Operation{}, e
		}
		if occupied != 0 {
			return Operation{}, ErrState
		}
	}
	if e = transferOccupancy(ctx, tx, o.NodeID).Scan(&occupied); e != nil {
		return Operation{}, e
	}
	if occupied != 0 {
		return Operation{}, ErrState
	}
	if o.Protocol == TransferProtocol {
		intent, e := DecodeTransferIntent(o.Request)
		if e != nil {
			return Operation{}, ErrState
		}
		source, ok := c.Node(intent.Approval.SourceNodeID)
		if !ok || source.Digest() != intent.SourceProfileSHA {
			return Operation{}, ErrState
		}
		var sourceMaintenance bool
		var sourceSeen sql.NullTime
		var sourceProfile string
		if e = tx.QueryRowContext(ctx, "SELECT maintenance,heartbeat_at,profile_sha256 FROM controller_nodes WHERE id=?", source.ID).Scan(&sourceMaintenance, &sourceSeen, &sourceProfile); e != nil {
			return Operation{}, e
		}
		if sourceMaintenance || !sourceSeen.Valid || sourceProfile != intent.SourceProfileSHA || !heartbeatFresh(&sourceSeen.Time, now, time.Duration(c.HeartbeatTTLSeconds)*time.Second) {
			return Operation{}, ErrCapacity
		}
		for _, q := range []string{"SELECT COUNT(*) FROM controller_jobs WHERE node_id=? AND CAST(state AS BINARY) NOT IN ('accepted','succeeded','rejected')", "SELECT COUNT(*) FROM controller_operations WHERE node_id=? AND CAST(state AS BINARY) NOT IN ('accepted','succeeded','rejected')"} {
			if e = tx.QueryRowContext(ctx, q, source.ID).Scan(&occupied); e != nil {
				return Operation{}, e
			}
			if occupied != 0 {
				return Operation{}, ErrState
			}
		}
		if e = transferOccupancy(ctx, tx, source.ID).Scan(&occupied); e != nil {
			return Operation{}, e
		}
		if occupied != 0 {
			return Operation{}, ErrState
		}
	}
	var maintenance bool
	var seen sql.NullTime
	var profile string
	if e = tx.QueryRowContext(ctx, "SELECT maintenance,heartbeat_at,profile_sha256 FROM controller_nodes WHERE id=?", o.NodeID).Scan(&maintenance, &seen, &profile); e != nil {
		return Operation{}, e
	}
	if maintenance || !seen.Valid || profile != o.ProfileSHA || !heartbeatFresh(&seen.Time, now, time.Duration(c.HeartbeatTTLSeconds)*time.Second) {
		return Operation{}, ErrCapacity
	}
	if _, e = tx.ExecContext(ctx, "UPDATE controller_operations SET state='sending',updated_at=? WHERE id=?", now, op); e != nil {
		return Operation{}, e
	}
	if e = audit(ctx, tx, "controller", "operation.dispatch_committed", op, now); e != nil {
		return Operation{}, e
	}
	o.State = "sending"
	o.UpdatedAt = now
	return o, tx.Commit()
}
func (s *SQLStore) CompleteOperation(ctx context.Context, c Config, op, status string, storage *nodeproto.StorageResult, now time.Time) (Operation, error) {
	next := map[string]string{"accepted": "dispatched", "succeeded": "succeeded", "rejected": "rejected", "uncertain": "uncertain"}[status]
	if next == "" {
		return Operation{}, ErrInput
	}
	tx, e := s.locked(ctx)
	if e != nil {
		return Operation{}, e
	}
	defer tx.Rollback()
	o, e := scanOperation(tx.QueryRowContext(ctx, "SELECT "+operationColumns+" FROM controller_operations WHERE id=?", op))
	if e != nil {
		return Operation{}, e
	}
	if o.State == "succeeded" || o.State == "rejected" {
		if o.State != next {
			return Operation{}, ErrConflict
		}
		return o, tx.Commit()
	}
	if o.State != "sending" && o.State != "dispatched" && o.State != "uncertain" {
		return Operation{}, ErrState
	}
	if status == "succeeded" && (o.Protocol == nodeproto.StorageProtocol || o.Protocol == nodeproto.StorageDirectProtocol) {
		task, e := nodeproto.DecodeStorageTask(o.Request)
		if e != nil || storage == nil || !storage.Matches(task, o.RequestSHA) {
			return Operation{}, ErrState
		}
		if strings.HasSuffix(o.Action, "_create") || o.Action == "migrate_prepare" {
			if !shaRE.MatchString(storage.ManifestSHA256) {
				return Operation{}, ErrState
			}
		}
		if o.Action == "migrate_prepare" && (storage.SourceNodeID != o.NodeID || storage.TargetNodeID != o.TargetNodeID || !shaRE.MatchString(storage.FenceToken)) {
			return Operation{}, ErrState
		}
		if o.Action == "migrate_import" || o.Action == "migrate_activate" || o.Action == "migrate_retire_source" {
			if storage.ManifestSHA256 != task.ManifestSHA256 || storage.SourceNodeID != task.SourceNodeID || storage.TargetNodeID != task.TargetNodeID || storage.FenceToken != task.FenceToken {
				return Operation{}, ErrState
			}
			if o.Action == "migrate_retire_source" && (storage.Items == nil || len(storage.Items) != 0) {
				return Operation{}, ErrState
			}
		}
	}
	if _, e = tx.ExecContext(ctx, "UPDATE controller_operations SET state=?,updated_at=? WHERE id=?", next, now, op); e != nil {
		return Operation{}, e
	}
	if status == "succeeded" {
		state := ""
		switch o.Action {
		case "create", "start", "reboot":
			state = "running"
		case "shutdown", "force_off":
			state = "shutoff"
		case "delete":
			state = "deleted"
		case "snapshot_create", "backup_create":
			_, e = tx.ExecContext(ctx, "UPDATE controller_artifacts SET state='ready',manifest_sha256=?,updated_at=? WHERE id=?", storage.ManifestSHA256, now, o.ArtifactID)
		case "snapshot_delete", "backup_delete":
			_, e = tx.ExecContext(ctx, "UPDATE controller_artifacts SET state='deleted',updated_at=? WHERE id=?", now, o.ArtifactID)
		case "migrate_retire_source":
			e = completeRetireSourceTx(ctx, tx, o, now)
		case "migrate_prepare":
			_, e = tx.ExecContext(ctx, "UPDATE controller_migrations SET phase='prepared',manifest_sha256=?,fence_token=?,updated_at=? WHERE id=?", storage.ManifestSHA256, storage.FenceToken, now, o.ArtifactID)
		case "migrate_transfer":
			_, e = tx.ExecContext(ctx, "UPDATE controller_migrations SET phase='transferred',updated_at=? WHERE id=?", now, o.ArtifactID)
		case "migrate_import":
			_, e = tx.ExecContext(ctx, "UPDATE controller_migrations SET phase='imported',updated_at=? WHERE id=?", now, o.ArtifactID)
		case "migrate_activate":
			v, err := scanInstance(tx.QueryRowContext(ctx, "SELECT id,owner_ref,node_id,hostname,state,resources,created_at,updated_at FROM controller_instances WHERE id=?", o.InstanceID))
			if err != nil {
				return Operation{}, err
			}
			migration, err := scanMigration(tx.QueryRowContext(ctx, "SELECT "+migrationColumns+" FROM controller_migrations WHERE id=?", o.ArtifactID))
			if err != nil {
				return Operation{}, err
			}
			target, ok := c.Node(o.NodeID)
			if !ok || target.Digest() != o.ProfileSHA || migration.TargetProfileSHA != o.ProfileSHA {
				return Operation{}, ErrState
			}
			if o.Protocol == nodeproto.StorageDirectProtocol {
				task, err := nodeproto.DecodeStorageTask(o.Request)
				if err != nil {
					return Operation{}, ErrState
				}
				if err = completeDirectMigrationTx(ctx, tx, c, o, task, now); err != nil {
					return Operation{}, err
				}
			}
			v.Resources = migration.Resources
			raw, _ := json.Marshal(v.Resources)
			if _, e = tx.ExecContext(ctx, "UPDATE controller_instances SET node_id=?,resources=?,state='running',updated_at=? WHERE id=?", o.NodeID, raw, now, o.InstanceID); e != nil {
				return Operation{}, e
			}
			_, e = tx.ExecContext(ctx, "UPDATE controller_migrations SET phase='active',updated_at=? WHERE id=?", now, o.ArtifactID)
		}
		if e != nil {
			return Operation{}, e
		}
		if state != "" {
			if _, e = tx.ExecContext(ctx, "UPDATE controller_instances SET state=?,updated_at=? WHERE id=?", state, now, o.InstanceID); e != nil {
				return Operation{}, e
			}
		}
		if o.Action == "delete" {
			if _, e = tx.ExecContext(ctx, "UPDATE controller_reservations SET released=TRUE WHERE node_id=? AND (operation_id IN (SELECT operation_id FROM controller_jobs WHERE instance_id=?) OR operation_id IN (SELECT id FROM controller_operations WHERE instance_id=? AND node_id=? AND action='create' AND state='succeeded') OR operation_id IN (SELECT source_operation_id FROM controller_migrations WHERE instance_id=? AND target_node_id=?))", o.NodeID, o.InstanceID, o.InstanceID, o.NodeID, o.InstanceID, o.NodeID); e != nil {
				return Operation{}, e
			}
		}
	}
	if status == "rejected" {
		if o.Action == "create" {
			if _, e = tx.ExecContext(ctx, "UPDATE controller_instances SET state='rejected',updated_at=? WHERE id=?", now, o.InstanceID); e != nil {
				return Operation{}, e
			}
			if _, e = tx.ExecContext(ctx, "UPDATE controller_reservations SET released=TRUE WHERE operation_id=?", o.ID); e != nil {
				return Operation{}, e
			}
		}
		if o.Action == "snapshot_create" || o.Action == "backup_create" {
			_, e = tx.ExecContext(ctx, "UPDATE controller_artifacts SET state='rejected',updated_at=? WHERE id=?", now, o.ArtifactID)
		}
		if o.Action == "migrate_prepare" {
			_, e = tx.ExecContext(ctx, "UPDATE controller_migrations SET phase='rejected',updated_at=? WHERE id=?", now, o.ArtifactID)
			if e == nil {
				_, e = tx.ExecContext(ctx, "UPDATE controller_reservations SET released=TRUE WHERE operation_id=?", o.ID)
			}
		}
		if e != nil {
			return Operation{}, e
		}
	}
	if e = audit(ctx, tx, "node:"+o.NodeID, "operation."+next, op, now); e != nil {
		return Operation{}, e
	}
	o.State = next
	o.UpdatedAt = now
	return o, tx.Commit()
}

func mustJSON(v any) []byte {
	raw, e := json.Marshal(v)
	if e != nil {
		panic("invalid internal serializable value")
	}
	return raw
}

func transferOccupancy(ctx context.Context, tx *sql.Tx, node string) *sql.Row {
	return tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM controller_operations o JOIN controller_migrations m ON o.artifact_id=m.id WHERE o.action='migrate_transfer' AND CAST(o.state AS BINARY) NOT IN ('accepted','succeeded','rejected') AND (m.source_node_id=? OR m.target_node_id=?)", node, node)
}

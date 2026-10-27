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

type CreateInstanceInput struct {
	Hostname                   string  `json:"hostname"`
	OwnerRef                   string  `json:"owner_ref"`
	PresetID                   string  `json:"preset_id"`
	PublicIPResourceID         string  `json:"public_ip_resource_id,omitempty"`
	PublicIPExpectedGeneration *uint64 `json:"public_ip_expected_generation,omitempty"`
}

// CreateInstance is explicitly a staff resource action. It never creates a fake
// financial order or changes a payment/financial snapshot to authorize it.
func (s *SQLStore) CreateInstance(ctx context.Context, c Config, actor, op string, in CreateInstanceInput, now time.Time) (Operation, bool, error) {
	if !nodeproto.ValidID(actor) || !nodeproto.ValidID(op) || !nodeproto.ValidID(in.OwnerRef) || (in.PublicIPResourceID != "") != (in.PublicIPExpectedGeneration != nil) {
		return Operation{}, false, ErrInput
	}
	intent, _ := json.Marshal(struct {
		Actor string
		Input CreateInstanceInput
	}{actor, in})
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
	var used int
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM controller_jobs WHERE operation_id=?", op).Scan(&used); e != nil {
		return Operation{}, false, e
	}
	if used != 0 {
		return Operation{}, false, ErrConflict
	}
	candidates := c.Candidates(controllerapi.Request{OwnerRef: in.OwnerRef, Product: controllerapi.ProductSpec{Mode: "preset", ControllerID: c.ControllerID, RemoteProductID: in.PresetID}})
	if len(candidates) != 1 {
		return Operation{}, false, ErrInput
	}
	candidate := candidates[0]
	r := candidate.Resources
	p := candidate.Node
	task := nodeproto.NodeTask{Protocol: nodeproto.Protocol, OperationID: op, NodeID: p.ID, Action: "create", InstanceID: op, OwnerRef: in.OwnerRef, Hostname: in.Hostname, Resources: r}
	var raw []byte
	var sha string
	var maintenance bool
	var seen sql.NullTime
	var profile string
	var capsRaw []byte
	var cpu, mem, disk, rc, rm, rd int64
	e = tx.QueryRowContext(ctx, "SELECT profile_sha256,maintenance,heartbeat_at,free_cpu,free_memory_mib,free_disk_gib,capabilities FROM controller_nodes WHERE id=?", p.ID).Scan(&profile, &maintenance, &seen, &cpu, &mem, &disk, &capsRaw)
	if e != nil {
		return Operation{}, false, ErrCapacity
	}
	var caps Capability
	if maintenance || !seen.Valid || !heartbeatFresh(&seen.Time, now, time.Duration(c.HeartbeatTTLSeconds)*time.Second) || profile != candidate.ProfileSHA || !strict(capsRaw, &caps) || !caps.SupportsNetwork(r, p, candidate.NetworkProfileID) {
		return Operation{}, false, ErrCapacity
	}
	if in.PublicIPResourceID != "" {
		resource, e := scanPublicResource(tx.QueryRowContext(ctx, "SELECT "+publicResourceColumns+" FROM controller_public_ip_resources WHERE id=?", in.PublicIPResourceID))
		if e != nil {
			return Operation{}, false, e
		}
		root, ok := directPublicProfile(c, resource.ClusterID, resource.NodeID, resource.ProfileID)
		if !ok || !directCapabilityMatches(caps, directPublicBinding(resource, root, op)) {
			return Operation{}, false, ErrCapacity
		}
	}
	if e = tx.QueryRowContext(ctx, "SELECT COALESCE(SUM(cpu),0),COALESCE(SUM(memory_mib),0),COALESCE(SUM(disk_gib),0) FROM controller_reservations WHERE node_id=? AND released=FALSE", p.ID).Scan(&rc, &rm, &rd); e != nil {
		return Operation{}, false, e
	}
	if int64(r.CPUCores) > cpu-rc || int64(r.MemoryMiB) > mem-rm || int64(r.SystemDiskGiB) > disk-rd {
		return Operation{}, false, ErrCapacity
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO controller_instances(id,owner_ref,node_id,hostname,state,resources,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)", op, in.OwnerRef, p.ID, in.Hostname, "reserved", mustJSON(r), now, now); e != nil {
		return Operation{}, false, e
	}
	task, e = bindCreateNetwork(ctx, tx, task, candidate, now)
	if e != nil {
		return Operation{}, false, e
	}
	task, e = bindCreateDirectPublicTx(ctx, tx, c, task, in.PublicIPResourceID, in.PublicIPExpectedGeneration, now)
	if e != nil {
		return Operation{}, false, e
	}
	raw, sha, e = task.BytesAndDigest()
	if e != nil {
		return Operation{}, false, ErrInput
	}
	if e = insertNetworkBinding(ctx, tx, task, sha, now); e != nil {
		return Operation{}, false, e
	}
	if e = reserveOverlayCreation(ctx, tx, candidate, task, now); e != nil {
		return Operation{}, false, e
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO controller_reservations(operation_id,node_id,cpu,memory_mib,disk_gib,released,created_at) VALUES(?,?,?,?,?,FALSE,?)", op, p.ID, r.CPUCores, r.MemoryMiB, r.SystemDiskGiB, now); e != nil {
		return Operation{}, false, e
	}
	o := Operation{ID: op, ActorID: actor, InstanceID: op, NodeID: p.ID, Action: "create", State: "accepted", CreatedAt: now, UpdatedAt: now, ProfileSHA: p.Digest(), IntentSHA: fingerprint, Protocol: task.Protocol, Request: raw, RequestSHA: sha}
	if _, e = tx.ExecContext(ctx, "INSERT INTO controller_operations("+strings.TrimSuffix(operationColumns, ",seq")+") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", o.ID, o.ActorID, o.InstanceID, o.NodeID, o.ProfileSHA, o.Action, o.ArtifactID, o.TargetNodeID, o.IntentSHA, o.Protocol, o.Request, o.RequestSHA, o.State, o.CreatedAt, o.UpdatedAt); e != nil {
		return Operation{}, false, e
	}
	if e = audit(ctx, tx, "user:"+actor, "instance.create_requested", op, now); e != nil {
		return Operation{}, false, e
	}
	return o, false, tx.Commit()
}

package control

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

const publicResourceColumns = "id,cluster_id,pool_id,owner_ref,mode,node_id,profile_id,vpc_id,address,state,binding_generation,created_at,updated_at"
const publicResourceOperationColumns = "id,actor_id,action,target_resource_id,resource_id,request_sha256,request,result,created_at"
const publicBindingColumns = "id,resource_id,revision,binding_generation,action,instance_id,previous_instance_id,epoch_id,request_sha256,binding,created_at"

func scanPublicResource(row interface{ Scan(...any) error }) (PublicIPResource, error) {
	var r PublicIPResource
	e := row.Scan(&r.ID, &r.ClusterID, &r.PoolID, &r.OwnerRef, &r.Mode, &r.NodeID, &r.ProfileID, &r.VPCID, &r.Address, &r.State, &r.BindingGeneration, &r.CreatedAt, &r.UpdatedAt)
	if errors.Is(e, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	if e != nil {
		return r, e
	}
	if !nodeproto.ValidID(r.ID) || r.BindingGeneration >= 1<<63 || !nodeproto.ValidNodeID(r.ClusterID) || !publicResourceInputValid(PublicIPResourceInput{r.PoolID, r.OwnerRef, r.Mode, r.NodeID, r.ProfileID, r.VPCID, r.Address}) || r.Address == "" || (r.State != "reserved" && r.State != "released") || !validOverlayTime(r.CreatedAt) || !validOverlayTime(r.UpdatedAt) || r.UpdatedAt.Before(r.CreatedAt) {
		return r, ErrState
	}
	return r, nil
}
func scanPublicBinding(row interface{ Scan(...any) error }) (PublicIPBindingIntent, error) {
	var b PublicIPBindingIntent
	e := row.Scan(&b.ID, &b.ResourceID, &b.Revision, &b.Generation, &b.Action, &b.InstanceID, &b.PreviousInstanceID, &b.EpochID, &b.RequestSHA256, &b.Binding, &b.CreatedAt)
	if errors.Is(e, sql.ErrNoRows) {
		return b, ErrNotFound
	}
	if e != nil {
		return b, e
	}
	if !nodeproto.ValidID(b.ID) || !nodeproto.ValidID(b.ResourceID) || b.Revision < 1 || b.Generation < 1 || b.Generation >= 1<<63 || b.InstanceID != "" && !nodeproto.ValidID(b.InstanceID) || b.PreviousInstanceID != "" && !nodeproto.ValidID(b.PreviousInstanceID) || b.EpochID != "" && !nodeproto.ValidID(b.EpochID) || !shaRE.MatchString(b.RequestSHA256) || !json.Valid(b.Binding) || !validOverlayTime(b.CreatedAt) {
		return b, ErrState
	}
	return b, nil
}
func latestPublicBindingTx(ctx context.Context, tx *sql.Tx, id string) (PublicIPBindingIntent, error) {
	return scanPublicBinding(tx.QueryRowContext(ctx, "SELECT "+publicBindingColumns+" FROM controller_public_ip_bindings WHERE resource_id=? ORDER BY revision DESC LIMIT 1", id))
}
func scanPublicResourceOperation(row interface{ Scan(...any) error }) (PublicIPResourceOperation, error) {
	var o PublicIPResourceOperation
	var raw []byte
	e := row.Scan(&o.ID, &o.ActorID, &o.Action, &o.TargetResourceID, &o.ResourceID, &o.RequestSHA256, &o.Request, &raw, &o.CreatedAt)
	if errors.Is(e, sql.ErrNoRows) {
		return o, ErrNotFound
	}
	if e != nil {
		return o, e
	}
	if !nodeproto.ValidID(o.ID) || !nodeproto.ValidID(o.ActorID) || !nodeproto.ValidID(o.ResourceID) || o.TargetResourceID != "" && !nodeproto.ValidID(o.TargetResourceID) || !strictPublicIP(raw, &o.Result) || o.Result.Resource.ID != o.ResourceID || !validOverlayTime(o.CreatedAt) || o.RequestSHA256 != publicOperationDigest(o.Action, o.TargetResourceID, o.Request) || !resourceOperationResultValid(o) {
		return o, ErrState
	}
	return o, nil
}
func resourceOperationResultValid(o PublicIPResourceOperation) bool {
	r := o.Result.Resource
	if !publicResourceInputValid(PublicIPResourceInput{r.PoolID, r.OwnerRef, r.Mode, r.NodeID, r.ProfileID, r.VPCID, r.Address}) || r.Address == "" || !nodeproto.ValidNodeID(r.ClusterID) || r.BindingGeneration >= 1<<63 || !validOverlayTime(r.CreatedAt) || !validOverlayTime(r.UpdatedAt) || r.UpdatedAt.Before(r.CreatedAt) || r.UpdatedAt.After(o.CreatedAt) {
		return false
	}
	switch o.Action {
	case "resource.allocate":
		var in PublicIPResourceInput
		return o.TargetResourceID == "" && o.ResourceID == o.ID && strictPublicIP(o.Request, &in) && in.PoolID == r.PoolID && in.OwnerRef == r.OwnerRef && in.Mode == r.Mode && in.NodeID == r.NodeID && in.ProfileID == r.ProfileID && in.VPCID == r.VPCID && (in.Address == "" || in.Address == r.Address) && r.State == "reserved" && r.BindingState == "unbound" && r.BindingGeneration == 0 && r.OperationID == ""
	case "resource.release":
		var in struct {
			ExpectedGeneration uint64 `json:"expected_generation"`
		}
		return strictPublicIP(o.Request, &in) && in.ExpectedGeneration == r.BindingGeneration && o.TargetResourceID == r.ID && r.State == "released" && r.BindingState == "released"
	case "resource.bind":
		var in publicResourceBindingInput
		return o.TargetResourceID == r.ID && strictPublicIP(o.Request, &in) && nodeproto.ValidID(in.InstanceID) && in.InstanceID == r.InstanceID && in.ExpectedGeneration != nil && *in.ExpectedGeneration < 1<<63-1 && (in.ExpectedIngressRevision == nil || r.Mode == "floating" && *in.ExpectedIngressRevision <= maxPublicIngressRevision) && r.BindingGeneration == *in.ExpectedGeneration+1 && r.State == "reserved" && r.BindingState == "pending" && r.OperationID == o.ID
	case "resource.recover":
		var in struct {
			ExpectedGeneration     uint64 `json:"expected_generation"`
			ExpectedSnapshotSHA256 string `json:"expected_snapshot_sha256"`
		}
		return strictPublicIP(o.Request, &in) && shaRE.MatchString(in.ExpectedSnapshotSHA256) && in.ExpectedGeneration < 1<<63-1 && r.BindingGeneration == in.ExpectedGeneration+1 && o.TargetResourceID == r.ID && r.State == "reserved" && r.BindingState == "pending" && r.InstanceID == "" && r.OperationID == o.ID && nodeproto.ValidID(r.EpochID)
	case "resource.unbind":
		var in struct {
			ExpectedGeneration uint64 `json:"expected_generation"`
		}
		return strictPublicIP(o.Request, &in) && in.ExpectedGeneration < 1<<63-1 && r.BindingGeneration == in.ExpectedGeneration+1 && o.TargetResourceID == r.ID && r.State == "reserved" && r.BindingState == "pending" && r.InstanceID == ""
	}
	return false
}
func publicResourceReplay(ctx context.Context, tx *sql.Tx, actor, op, action, target string, raw json.RawMessage) (PublicIPResourceOperation, bool, error) {
	o, e := scanPublicResourceOperation(tx.QueryRowContext(ctx, "SELECT "+publicResourceOperationColumns+" FROM controller_public_ip_resource_operations WHERE id=?", op))
	if e == nil {
		if o.ActorID != actor || o.Action != action || o.TargetResourceID != target || o.RequestSHA256 != publicOperationDigest(action, target, raw) {
			return o, false, ErrConflict
		}
		return o, true, nil
	}
	if !errors.Is(e, ErrNotFound) {
		return o, false, e
	}
	// A new operation cannot shadow an original NAT or instance/job intent.
	if e := publicIngressOperationIDUnusedTx(ctx, tx, op); e != nil {
		return o, false, e
	}
	for _, q := range []string{"SELECT COUNT(*) FROM controller_public_ip_operations WHERE id=?", "SELECT COUNT(*) FROM controller_operations WHERE id=?", "SELECT COUNT(*) FROM controller_jobs WHERE operation_id=?", "SELECT COUNT(*) FROM controller_overlay_epochs WHERE id=?"} {
		var n int
		if e = tx.QueryRowContext(ctx, q, op).Scan(&n); e != nil {
			return o, false, e
		}
		if n != 0 {
			return o, false, ErrConflict
		}
	}
	return o, false, nil
}
func insertPublicResourceOperation(ctx context.Context, tx *sql.Tx, actor, op, action, target string, r PublicIPResource, raw json.RawMessage, now time.Time) (PublicIPResourceOperation, error) {
	o := PublicIPResourceOperation{op, actor, action, target, r.ID, publicOperationDigest(action, target, raw), raw, PublicIPResourceResult{r}, now}
	result, _ := json.Marshal(o.Result)
	if !resourceOperationResultValid(o) {
		return o, ErrState
	}
	_, e := tx.ExecContext(ctx, "INSERT INTO controller_public_ip_resource_operations("+publicResourceOperationColumns+") VALUES(?,?,?,?,?,?,?,?,?)", o.ID, o.ActorID, o.Action, o.TargetResourceID, o.ResourceID, o.RequestSHA256, []byte(raw), result, now)
	if e != nil {
		return o, e
	}
	e = audit(ctx, tx, "user:"+actor, "public_ip."+action, r.ID, now)
	return o, e
}
func (s *SQLStore) AllocatePublicIPResource(ctx context.Context, c Config, actor, op string, in PublicIPResourceInput, now time.Time) (PublicIPResource, PublicIPResourceOperation, bool, error) {
	if !publicMutationValid(actor, op, now) || !publicResourceInputValid(in) {
		return PublicIPResource{}, PublicIPResourceOperation{}, false, ErrInput
	}
	raw, _ := json.Marshal(in)
	tx, e := s.locked(ctx)
	if e != nil {
		return PublicIPResource{}, PublicIPResourceOperation{}, false, e
	}
	defer tx.Rollback()
	o, replay, e := publicResourceReplay(ctx, tx, actor, op, "resource.allocate", "", raw)
	if e != nil {
		return PublicIPResource{}, o, false, e
	}
	if replay {
		return o.Result.Resource, o, true, nil
	}
	pool, e := scanPublicPool(tx.QueryRowContext(ctx, "SELECT "+publicPoolColumns+" FROM controller_public_ip_pools WHERE id=?", in.PoolID))
	if e != nil {
		return PublicIPResource{}, o, false, e
	}
	if !pool.Enabled {
		return PublicIPResource{}, o, false, ErrState
	}
	now = now.UTC().Truncate(time.Microsecond)
	r := PublicIPResource{ID: op, ClusterID: pool.ClusterID, PoolID: pool.ID, OwnerRef: in.OwnerRef, Mode: in.Mode, NodeID: in.NodeID, ProfileID: in.ProfileID, VPCID: in.VPCID, State: "reserved", BindingState: "unbound", Releasable: true, CreatedAt: now, UpdatedAt: now}
	active, e := publicIPActiveMapTx(ctx, tx)
	if e != nil {
		return r, o, false, e
	}
	proof, e := readPublicIPReleaseProofTx(ctx, tx, c)
	if e != nil {
		return r, o, false, e
	}
	eligible := false
	for _, address := range pool.Addresses {
		if in.Address != "" && address != in.Address {
			continue
		}
		if !publicResourceApprovedTx(ctx, tx, c, r, address) {
			continue
		}
		eligible = true
		if active[address] != "" {
			if in.Address != "" {
				return r, o, false, ErrConflict
			}
			continue
		}
		if e = proof.detached(ctx, tx, address, ""); e != nil {
			if in.Address != "" || !errors.Is(e, ErrState) {
				return r, o, false, e
			}
			continue
		}
		r.Address = address
		break
	}
	if r.Address == "" {
		if !eligible {
			return r, o, false, ErrState
		}
		return r, o, false, ErrPublicIPCapacity
	}
	if e = resourcePoolInventoryTx(ctx, tx, r); e != nil {
		return r, o, false, e
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO controller_public_ip_active(address,lease_id) VALUES(?,?)", r.Address, r.ID); e != nil {
		return r, o, false, ErrConflict
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO controller_public_ip_resources("+publicResourceColumns+") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", r.ID, r.ClusterID, r.PoolID, r.OwnerRef, r.Mode, r.NodeID, r.ProfileID, r.VPCID, r.Address, r.State, r.BindingGeneration, r.CreatedAt, r.UpdatedAt); e != nil {
		return r, o, false, e
	}
	o, e = insertPublicResourceOperation(ctx, tx, actor, op, "resource.allocate", "", r, raw, now)
	if e != nil {
		return r, o, false, e
	}
	return r, o, false, tx.Commit()
}
func publicResourceActiveTx(ctx context.Context, tx *sql.Tx, r PublicIPResource) error {
	if r.State != "reserved" {
		return ErrState
	}
	if e := resourcePoolInventoryTx(ctx, tx, r); e != nil {
		return e
	}
	var id string
	if e := tx.QueryRowContext(ctx, "SELECT lease_id FROM controller_public_ip_active WHERE address=?", r.Address).Scan(&id); e != nil || id != r.ID {
		return ErrState
	}
	return nil
}
func (s *SQLStore) ReleasePublicIPResource(ctx context.Context, c Config, actor, op, resource string, expected uint64, now time.Time) (PublicIPResource, PublicIPResourceOperation, bool, error) {
	if !publicMutationValid(actor, op, now) || !nodeproto.ValidID(resource) {
		return PublicIPResource{}, PublicIPResourceOperation{}, false, ErrInput
	}
	tx, e := s.locked(ctx)
	if e != nil {
		return PublicIPResource{}, PublicIPResourceOperation{}, false, e
	}
	defer tx.Rollback()
	raw := marshalPublicBinding(struct {
		ExpectedGeneration uint64 `json:"expected_generation"`
	}{expected})
	o, replay, e := publicResourceReplay(ctx, tx, actor, op, "resource.release", resource, raw)
	if e != nil {
		return PublicIPResource{}, o, false, e
	}
	if replay {
		return o.Result.Resource, o, true, nil
	}
	r, e := scanPublicResource(tx.QueryRowContext(ctx, "SELECT "+publicResourceColumns+" FROM controller_public_ip_resources WHERE id=?", resource))
	if e != nil {
		return r, o, false, e
	}
	if r.BindingGeneration != expected {
		return r, o, false, ErrState
	}
	if e = publicResourceActiveTx(ctx, tx, r); e != nil {
		return r, o, false, e
	}
	if e = decoratePublicResourceTx(ctx, tx, c, &r); e != nil {
		return r, o, false, e
	}
	if !r.Releasable {
		return r, o, false, ErrState
	}
	if e = publicAddressDetachedTx(ctx, tx, c, r.Address); e != nil {
		return r, o, false, e
	}
	result, e := tx.ExecContext(ctx, "DELETE FROM controller_public_ip_active WHERE address=? AND lease_id=?", r.Address, r.ID)
	if e != nil {
		return r, o, false, e
	}
	n, e := result.RowsAffected()
	if e != nil || n != 1 {
		return r, o, false, ErrState
	}
	now = now.UTC().Truncate(time.Microsecond)
	r.State = "released"
	r.BindingState = "released"
	r.Releasable = false
	r.ReleaseReason = ""
	r.UpdatedAt = now
	if _, e = tx.ExecContext(ctx, "UPDATE controller_public_ip_resources SET state='released',updated_at=? WHERE id=?", now, r.ID); e != nil {
		return r, o, false, e
	}
	o, e = insertPublicResourceOperation(ctx, tx, actor, op, "resource.release", r.ID, r, raw, now)
	if e != nil {
		return r, o, false, e
	}
	return r, o, false, tx.Commit()
}

func publicResourceIDUnusedTx(ctx context.Context, tx *sql.Tx, op string) error {
	if e := publicIngressOperationIDUnusedTx(ctx, tx, op); e != nil {
		return e
	}
	var n int
	e := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM controller_public_ip_resource_operations WHERE id=?", op).Scan(&n)
	if e != nil {
		return e
	}
	if n != 0 {
		return ErrConflict
	}
	return nil
}

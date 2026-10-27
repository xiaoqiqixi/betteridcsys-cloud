package control

import (
	"aster/cloud/internal/nodeproto"
	"aster/cloud/internal/overlayproto"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"time"
)

func publicIngressResultValid(o PublicIngressOperation) bool {
	if o.Action != "public_ingress.update" || !nodeproto.ValidID(o.ID) || !nodeproto.ValidID(o.ActorID) || !nodeproto.ValidID(o.TargetInstanceID) || !validOverlayTime(o.CreatedAt) {
		return false
	}
	var in PublicIngressInput
	if !strict(o.Request, &in) || in.ExpectedRevision == nil || *in.ExpectedRevision >= maxPublicIngressRevision {
		return false
	}
	p, e := overlayproto.CanonicalPublicIngress(publicIngressWire(o.Result.Policy))
	if e != nil || !reflect.DeepEqual(p, publicIngressWire(o.Result.Policy)) || p.InstanceID != o.TargetInstanceID || p.Revision != *in.ExpectedRevision+1 || !reflect.DeepEqual(p.Rules, in.Rules) {
		return false
	}
	v := o.Result.Policy
	if v.Supported && v.UnsupportedReason != "" || !v.Supported && v.UnsupportedReason != "UPGRADE_REQUIRED" && v.UnsupportedReason != "NODE_NOT_READY" || v.State == "active" && v.LegacyUnrestricted || v.State == "pending" && !v.Supported {
		return false
	}
	return v.OperationID == o.ID && v.UpdatedAt != nil && v.UpdatedAt.Equal(o.CreatedAt) && ((v.State == "active" && v.EffectiveRevision != nil && *v.EffectiveRevision == v.Revision && v.EpochID == "" && v.BoundResourceID == "") || (v.State == "pending" && v.EffectiveRevision == nil && nodeproto.ValidID(v.EpochID) && nodeproto.ValidID(v.BoundResourceID))) && o.RequestSHA256 == publicOperationDigest(o.Action, o.TargetInstanceID, o.Request)
}
func scanPublicIngressOperation(row interface{ Scan(...any) error }) (PublicIngressOperation, error) {
	var o PublicIngressOperation
	var result []byte
	e := row.Scan(&o.ID, &o.ActorID, &o.Action, &o.TargetInstanceID, &o.RequestSHA256, &o.Request, &result, &o.CreatedAt)
	if errors.Is(e, sql.ErrNoRows) {
		return o, ErrNotFound
	}
	if e != nil {
		return o, e
	}
	if !strictPublicIP(result, &o.Result) || !publicIngressResultValid(o) {
		return o, ErrState
	}
	return o, nil
}
func (s *SQLStore) PublicIngressOperation(ctx context.Context, actor, op string) (PublicIngressOperation, error) {
	if !nodeproto.ValidID(actor) || !nodeproto.ValidID(op) {
		return PublicIngressOperation{}, ErrInput
	}
	return scanPublicIngressOperation(s.DB.QueryRowContext(ctx, "SELECT "+publicIngressOperationColumns+" FROM controller_public_ingress_operations WHERE id=? AND actor_id=?", op, actor))
}
func publicIngressOperationIDUnusedTx(ctx context.Context, tx *sql.Tx, id string) error {
	var n int
	e := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM controller_public_ingress_operations WHERE id=?", id).Scan(&n)
	if e != nil {
		return e
	}
	if n != 0 {
		return ErrConflict
	}
	return nil
}
func publicIngressOldIDUnusedTx(ctx context.Context, tx *sql.Tx, id string) error {
	for _, q := range []string{
		"SELECT COUNT(*) FROM controller_jobs WHERE operation_id=?",
		"SELECT COUNT(*) FROM controller_operations WHERE id=?",
		"SELECT COUNT(*) FROM controller_overlay_epochs WHERE id=?",
		"SELECT COUNT(*) FROM controller_overlay_tasks WHERE operation_id=?",
		"SELECT COUNT(*) FROM controller_overlay_vpcs WHERE id=?",
		"SELECT COUNT(*) FROM controller_public_ip_operations WHERE id=?",
		"SELECT COUNT(*) FROM controller_public_ip_resource_operations WHERE id=?",
		"SELECT COUNT(*) FROM controller_public_ip_bindings WHERE id=?",
		"SELECT COUNT(*) FROM controller_network_vpcs WHERE id=?",
		"SELECT COUNT(*) FROM controller_network_pools WHERE id=?",
		"SELECT COUNT(*) FROM controller_network_leases WHERE id=?",
	} {
		var n int
		if e := tx.QueryRowContext(ctx, q, id).Scan(&n); e != nil {
			return e
		}
		if n != 0 {
			return ErrConflict
		}
	}
	return nil
}
func (s *SQLStore) SetPublicIngress(ctx context.Context, c Config, actor, instance, op string, in PublicIngressInput, now time.Time) (PublicIngressView, PublicIngressOperation, bool, error) {
	if !publicMutationValid(actor, op, now) || !nodeproto.ValidID(instance) || in.ExpectedRevision == nil || *in.ExpectedRevision >= maxPublicIngressRevision || in.Rules == nil {
		return PublicIngressView{}, PublicIngressOperation{}, false, ErrInput
	}
	// Canonicalize rules before replay checks without accepting an owner supplied
	// by the browser. The real owner is pinned from the instance under the lock.
	check, e := overlayproto.CanonicalPublicIngress(overlayproto.PublicIngressPolicy{Schema: 1, InstanceID: instance, OwnerRef: actor, Revision: *in.ExpectedRevision + 1, Rules: in.Rules})
	if e != nil {
		return PublicIngressView{}, PublicIngressOperation{}, false, ErrInput
	}
	in.Rules = check.Rules
	raw, _ := json.Marshal(in)
	tx, e := s.locked(ctx)
	if e != nil {
		return PublicIngressView{}, PublicIngressOperation{}, false, e
	}
	defer tx.Rollback()
	old, e := scanPublicIngressOperation(tx.QueryRowContext(ctx, "SELECT "+publicIngressOperationColumns+" FROM controller_public_ingress_operations WHERE id=?", op))
	if e == nil {
		if old.ActorID != actor || old.TargetInstanceID != instance || old.RequestSHA256 != publicOperationDigest("public_ingress.update", instance, raw) {
			return PublicIngressView{}, old, false, ErrConflict
		}
		return old.Result.Policy, old, true, nil
	}
	if !errors.Is(e, ErrNotFound) {
		return PublicIngressView{}, old, false, e
	}
	if e = publicIngressOldIDUnusedTx(ctx, tx, op); e != nil {
		return PublicIngressView{}, old, false, e
	}
	v, e := ingressInstanceTx(ctx, tx, instance)
	if e != nil {
		return PublicIngressView{}, old, false, e
	}
	current, e := publicIngressViewTx(ctx, tx, c, v, now)
	if e != nil {
		return current, old, false, e
	}
	if current.Revision != *in.ExpectedRevision || current.State == "pending" || current.State == "blocked" {
		return current, old, false, ErrState
	}
	if e = publicInstanceIdleTx(ctx, tx, v.ID); e != nil {
		return current, old, false, e
	}
	policy, e := overlayproto.CanonicalPublicIngress(overlayproto.PublicIngressPolicy{Schema: 1, InstanceID: v.ID, OwnerRef: v.OwnerRef, Revision: *in.ExpectedRevision + 1, Rules: in.Rules})
	if e != nil {
		return current, old, false, ErrInput
	}
	now = now.UTC().Truncate(time.Microsecond)
	next := publicIngressView(policy)
	next.OperationID = op
	next.UpdatedAt = &now
	next.Supported = current.Supported
	next.UnsupportedReason = current.UnsupportedReason
	resource, e := relatedFloatingResourceTx(ctx, tx, c, v)
	if e != nil {
		return next, old, false, e
	}
	epochID := ""
	if resource != nil {
		if resource.BindingState != "bound" || resource.InstanceID != v.ID {
			return next, old, false, ErrState
		}
		epochID = overlayproto.Digest([]byte("aster.public-ingress.epoch/1:" + op))[:32]
		next.BoundResourceID = resource.ID
		next.EpochID = epochID
		next.State = "pending"
		next.LegacyUnrestricted = current.LegacyUnrestricted
	} else {
		revision := policy.Revision
		next.State = "active"
		next.EffectiveRevision = &revision
	}
	encoded, _ := json.Marshal(policy)
	if _, e = tx.ExecContext(ctx, "INSERT INTO controller_public_ingress_versions("+publicIngressVersionColumns+") VALUES(?,?,?,?,?,?,?)", v.ID, policy.Revision, v.OwnerRef, encoded, op, epochID, now); e != nil {
		return next, old, false, e
	}
	if resource != nil {
		if e = planPublicIngressEpochTx(ctx, tx, c, actor, op, epochID, v, *resource, policy, now); e != nil {
			return next, old, false, e
		}
	}
	result := PublicIngressOperation{ID: op, ActorID: actor, Action: "public_ingress.update", TargetInstanceID: v.ID, RequestSHA256: publicOperationDigest("public_ingress.update", v.ID, raw), Request: raw, Result: PublicIngressResult{Policy: next}, CreatedAt: now}
	if !publicIngressResultValid(result) {
		return next, result, false, ErrState
	}
	out, _ := json.Marshal(result.Result)
	if _, e = tx.ExecContext(ctx, "INSERT INTO controller_public_ingress_operations("+publicIngressOperationColumns+") VALUES(?,?,?,?,?,?,?,?)", result.ID, result.ActorID, result.Action, result.TargetInstanceID, result.RequestSHA256, []byte(raw), out, now); e != nil {
		return next, result, false, e
	}
	if e = audit(ctx, tx, "user:"+actor, "public_ingress.updated", v.ID, now); e != nil {
		return next, result, false, e
	}
	return next, result, false, tx.Commit()
}

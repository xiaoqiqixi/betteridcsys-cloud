package control

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"database/sql"
	"strings"
	"time"
)

func freezeDirectMigrationTx(ctx context.Context, tx *sql.Tx, o Operation, b nodeproto.DirectPublicBinding, now time.Time) error {
	if b.IsZero() {
		return nil
	}
	r, e := scanPublicResource(tx.QueryRowContext(ctx, "SELECT "+publicResourceColumns+" FROM controller_public_ip_resources WHERE id=?", b.LeaseID))
	if e != nil || r.BindingGeneration >= 1<<63-1 || b.Generation >= 1<<63-1 {
		return ErrState
	}
	previous, e := latestPublicBindingTx(ctx, tx, r.ID)
	if e != nil || previous.Generation != r.BindingGeneration {
		return ErrState
	}
	var original nodeproto.DirectPublicBinding
	if !strictPublicIP(previous.Binding, &original) || original != b {
		return ErrState
	}
	return insertPublicBindingTx(ctx, tx, PublicIPBindingIntent{ID: o.ID, ResourceID: b.LeaseID, Action: "direct.migrating", InstanceID: o.InstanceID, RequestSHA256: o.RequestSHA, Binding: marshalPublicBinding(b), CreatedAt: now})
}
func validateDirectStorageTx(ctx context.Context, tx *sql.Tx, c Config, o Operation) error {
	if o.Protocol == TransferProtocol {
		return validateDirectTransferTx(ctx, tx, c, o)
	}
	t, e := nodeproto.DecodeStorageTask(o.Request)
	if e != nil || t.OperationID != o.ID || t.InstanceID != o.InstanceID || t.Action != o.Action || t.Protocol != o.Protocol || nodeproto.Digest(o.Request) != o.RequestSHA {
		return ErrState
	}
	v, e := scanInstance(tx.QueryRowContext(ctx, "SELECT id,owner_ref,node_id,hostname,state,resources,created_at,updated_at FROM controller_instances WHERE id=?", o.InstanceID))
	if e != nil || v.OwnerRef != t.OwnerRef {
		return ErrState
	}
	b, e := instanceDirectPublicTx(ctx, tx, v)
	if e != nil {
		return e
	}
	if b.IsZero() {
		if c.directRequired(v.NodeID) && strings.HasPrefix(o.Action, "migrate_") {
			return ErrState
		}
		if !t.DirectPublic.IsZero() {
			return ErrState
		}
		return nil
	}
	if o.Action == "migrate_retire_source" {
		r, e := scanPublicResource(tx.QueryRowContext(ctx, "SELECT "+publicResourceColumns+" FROM controller_public_ip_resources WHERE id=?", b.LeaseID))
		if e != nil {
			return e
		}
		if e = publicResourceActiveTx(ctx, tx, r); e != nil {
			return e
		}
		return validateRetireStorageTx(ctx, tx, c, o, t)
	}
	if t.Protocol != nodeproto.StorageDirectProtocol || !c.approvesDirectPublic(t.DirectPublic) {
		return ErrState
	}
	r, e := scanPublicResource(tx.QueryRowContext(ctx, "SELECT "+publicResourceColumns+" FROM controller_public_ip_resources WHERE id=?", b.LeaseID))
	if e != nil {
		return e
	}
	if !resourceDirectTargetApproved(c, r, t.DirectPublic) {
		return ErrState
	}
	if e = directCapabilityTx(ctx, tx, t.DirectPublic); e != nil {
		return e
	}
	if e = publicResourceActiveTx(ctx, tx, r); e != nil {
		return e
	}
	if o.Action == "migrate_prepare" {
		frozen, e := scanPublicBinding(tx.QueryRowContext(ctx, "SELECT "+publicBindingColumns+" FROM controller_public_ip_bindings WHERE id=?", o.ID))
		if e != nil || frozen.ResourceID != r.ID || frozen.Generation != r.BindingGeneration || frozen.RequestSHA256 != o.RequestSHA {
			return ErrState
		}
	}
	want := b
	if o.Action == "migrate_import" || o.Action == "migrate_activate" {
		want.NodeID = o.NodeID
		want.Generation++
		// The resource edit version and guest incarnation are distinct counters.
		// Bind to the exact immutable prepare version rather than equating them.
		prepare, e := scanPublicBinding(tx.QueryRowContext(ctx, "SELECT "+publicBindingColumns+" FROM controller_public_ip_bindings WHERE id=?", t.SourceOperationID))
		if e != nil || prepare.Action != "direct.migrating" || prepare.ResourceID != r.ID || prepare.Generation != r.BindingGeneration {
			return ErrState
		}
		var source nodeproto.DirectPublicBinding
		if !strictPublicIP(prepare.Binding, &source) || source != b || want.Generation != source.Generation+1 {
			return ErrState
		}
	}
	if o.Action == "migrate_retire_source" {
		return validateRetireStorageTx(ctx, tx, c, o, t)
	}
	if want != t.DirectPublic {
		return ErrState
	}
	if strings.HasPrefix(o.Action, "migrate_") {
		return nil
	}
	return directPublicInstanceGateTx(ctx, tx, c, v)
}

func validateDirectTransferTx(ctx context.Context, tx *sql.Tx, c Config, o Operation) error {
	intent, e := DecodeTransferIntent(o.Request)
	if e != nil {
		return e
	}
	prepare, e := scanOperation(tx.QueryRowContext(ctx, "SELECT "+operationColumns+" FROM controller_operations WHERE id=?", intent.Approval.SourceOperationID))
	if e != nil {
		return e
	}
	task, e := nodeproto.DecodeStorageTask(prepare.Request)
	if e != nil {
		return e
	}
	if task.DirectPublic.IsZero() {
		if c.directRequired(task.NodeID) {
			return ErrState
		}
		return nil
	}
	frozen, e := scanPublicBinding(tx.QueryRowContext(ctx, "SELECT "+publicBindingColumns+" FROM controller_public_ip_bindings WHERE id=?", prepare.ID))
	if e != nil || frozen.Action != "direct.migrating" || frozen.RequestSHA256 != prepare.RequestSHA {
		return ErrState
	}
	r, e := scanPublicResource(tx.QueryRowContext(ctx, "SELECT "+publicResourceColumns+" FROM controller_public_ip_resources WHERE id=?", task.DirectPublic.LeaseID))
	if e != nil || r.BindingGeneration != frozen.Generation {
		return ErrState
	}
	if e = publicResourceActiveTx(ctx, tx, r); e != nil {
		return e
	}
	target := task.DirectPublic
	target.NodeID = intent.Approval.TargetNodeID
	target.Generation++
	if !resourceDirectTargetApproved(c, r, target) {
		return ErrState
	}
	return directCapabilityTx(ctx, tx, target)
}

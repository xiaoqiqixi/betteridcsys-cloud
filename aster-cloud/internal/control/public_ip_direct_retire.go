package control

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// Retirement is a separately confirmed operation. The target receipt is fetched
// read-only before the admission lock; no HTTP body can supply a target_active bool.
func (w OperationWorker) CreateRetireSource(ctx context.Context, actor, instance, op string, in OperationInput) (Operation, bool, error) {
	if in.Action != "migrate_retire_source" || !in.valid(instance) {
		return Operation{}, false, ErrInput
	}
	if _, e := w.Store.Operation(ctx, op); e == nil {
		return w.Store.CreateOperation(ctx, w.Config, actor, instance, op, in, w.now())
	} else if !errors.Is(e, ErrNotFound) {
		return Operation{}, false, e
	}
	activation, e := scanOperation(w.Store.DB.QueryRowContext(ctx, "SELECT "+operationColumns+" FROM controller_operations WHERE artifact_id=? AND instance_id=? AND action='migrate_activate' AND state='succeeded' ORDER BY seq DESC LIMIT 1", in.ArtifactID, instance))
	if e != nil {
		return Operation{}, false, e
	}
	task, e := nodeproto.DecodeStorageTask(activation.Request)
	if e != nil || task.Protocol != nodeproto.StorageDirectProtocol {
		return Operation{}, false, ErrState
	}
	p, ok := w.Config.Node(activation.NodeID)
	if !ok || p.Digest() != activation.ProfileSHA {
		return Operation{}, false, ErrState
	}
	rpc, e := w.storage(ctx, p)
	if e != nil {
		return Operation{}, false, e
	}
	receipt, e := rpc.LookupStorage(ctx, activation.ID, activation.RequestSHA)
	if e != nil || !receipt.Matches(task, activation.RequestSHA) || receipt.Status != "succeeded" || receipt.Items == nil || len(receipt.Items) != 0 || receipt.ManifestSHA256 != task.ManifestSHA256 || receipt.FenceToken != task.FenceToken || receipt.SourceNodeID != task.SourceNodeID || receipt.TargetNodeID != task.TargetNodeID {
		return Operation{}, false, ErrUnavailable
	}
	return w.Store.createOperation(ctx, w.Config, actor, instance, op, in, w.now(), &receipt)
}
func buildRetireSourceTx(ctx context.Context, tx *sql.Tx, c Config, o Operation, v Instance, receipt *nodeproto.StorageResult) (nodeproto.TypedStorageTask, error) {
	fail := func() (nodeproto.TypedStorageTask, error) { return nodeproto.TypedStorageTask{}, ErrState }
	if receipt == nil {
		return fail()
	}
	m, e := scanMigration(tx.QueryRowContext(ctx, "SELECT "+migrationColumns+" FROM controller_migrations WHERE id=?", o.ArtifactID))
	if e != nil || m.Phase != "active" || m.InstanceID != v.ID || m.TargetNodeID != v.NodeID {
		return fail()
	}
	activation, e := scanOperation(tx.QueryRowContext(ctx, "SELECT "+operationColumns+" FROM controller_operations WHERE id=?", receipt.OperationID))
	if e != nil || activation.State != "succeeded" || activation.Action != "migrate_activate" || activation.ArtifactID != m.ID || activation.InstanceID != v.ID || activation.NodeID != m.TargetNodeID || activation.ProfileSHA != m.TargetProfileSHA {
		return fail()
	}
	activate, e := nodeproto.DecodeStorageTask(activation.Request)
	if e != nil || activate.Protocol != nodeproto.StorageDirectProtocol || !receipt.Matches(activate, activation.RequestSHA) || receipt.Status != "succeeded" || receipt.Items == nil || len(receipt.Items) != 0 {
		return fail()
	}
	var occupied int
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM controller_operations WHERE artifact_id=? AND instance_id=? AND action='migrate_retire_source' AND id<>? AND state<>'rejected'", m.ID, v.ID, o.ID).Scan(&occupied); e != nil || occupied != 0 {
		return fail()
	}
	prepare, e := scanOperation(tx.QueryRowContext(ctx, "SELECT "+operationColumns+" FROM controller_operations WHERE id=?", m.SourceOperationID))
	if e != nil || prepare.State != "succeeded" || prepare.NodeID != m.SourceNodeID {
		return fail()
	}
	source, e := nodeproto.DecodeStorageTask(prepare.Request)
	if e != nil || source.Protocol != nodeproto.StorageDirectProtocol || source.Action != "migrate_prepare" || source.InstanceID != v.ID || source.ArtifactID != m.ID || source.OwnerRef != v.OwnerRef || !nodeproto.SameDirectAddress(source.DirectPublic, activate.DirectPublic) || activate.DirectPublic.Generation != source.DirectPublic.Generation+1 {
		return fail()
	}
	root, ok := c.Node(source.NodeID)
	if !ok || root.Digest() != prepare.ProfileSHA {
		return fail()
	}
	raw, _ := json.Marshal(receipt)
	task := nodeproto.TypedStorageTask{Protocol: nodeproto.StorageDirectProtocol, OperationID: o.ID, NodeID: m.SourceNodeID, Action: "migrate_retire_source", InstanceID: v.ID, OwnerRef: v.OwnerRef, ArtifactID: m.ID, TargetNodeID: m.TargetNodeID, SourceNodeID: m.SourceNodeID, SourceOperationID: m.SourceOperationID, ManifestSHA256: m.ManifestSHA, FenceToken: m.FenceToken, ConfirmArtifactID: m.ID, DirectPublic: source.DirectPublic, RetireProof: nodeproto.PublicRetireProof{ActivateOperationID: activation.ID, ActivateRequestSHA256: activation.RequestSHA, ActivateReceiptSHA256: nodeproto.Digest(raw), TargetProfileSHA256: activate.DirectPublic.ProfileSHA256, TargetGeneration: activate.DirectPublic.Generation, ConfirmInstanceID: v.ID}}
	if _, _, e = task.BytesAndDigest(); e != nil {
		return fail()
	}
	return task, nil
}
func validateRetireStorageTx(ctx context.Context, tx *sql.Tx, c Config, o Operation, t nodeproto.TypedStorageTask) error {
	activation, e := scanOperation(tx.QueryRowContext(ctx, "SELECT "+operationColumns+" FROM controller_operations WHERE id=?", t.RetireProof.ActivateOperationID))
	if e != nil {
		return e
	}
	a, e := nodeproto.DecodeStorageTask(activation.Request)
	if e != nil {
		return e
	}
	receipt := nodeproto.StorageResult{Protocol: nodeproto.StorageDirectProtocol, OperationID: activation.ID, RequestSHA256: activation.RequestSHA, Status: "succeeded", InstanceID: a.InstanceID, ArtifactID: a.ArtifactID, ManifestSHA256: a.ManifestSHA256, FenceToken: a.FenceToken, SourceNodeID: a.SourceNodeID, TargetNodeID: a.TargetNodeID, Items: []nodeproto.StorageArtifact{}}
	v, e := scanInstance(tx.QueryRowContext(ctx, "SELECT id,owner_ref,node_id,hostname,state,resources,created_at,updated_at FROM controller_instances WHERE id=?", o.InstanceID))
	if e != nil {
		return e
	}
	wanted, e := buildRetireSourceTx(ctx, tx, c, o, v, &receipt)
	if e != nil || wanted != t {
		return ErrState
	}
	return nil
}
func completeRetireSourceTx(ctx context.Context, tx *sql.Tx, o Operation, now time.Time) error {
	t, e := nodeproto.DecodeStorageTask(o.Request)
	if e != nil || t.Action != "migrate_retire_source" {
		return ErrState
	}
	// The source is permanently retired, not a new permission to start its old generation.
	_, e = tx.ExecContext(ctx, "UPDATE controller_reservations SET released=TRUE WHERE node_id=? AND (operation_id IN (SELECT operation_id FROM controller_jobs WHERE instance_id=?) OR operation_id IN (SELECT id FROM controller_operations WHERE instance_id=? AND node_id=? AND action='create' AND state='succeeded') OR operation_id IN (SELECT source_operation_id FROM controller_migrations WHERE instance_id=? AND target_node_id=?))", t.NodeID, t.InstanceID, t.InstanceID, t.NodeID, t.InstanceID, t.NodeID)
	return e
}

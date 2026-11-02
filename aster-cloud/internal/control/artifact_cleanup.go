package control

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"database/sql"
)

func artifactDelete(action string) bool {
	return action == "snapshot_delete" || action == "backup_delete"
}

// A deleted instance no longer owns a live IP binding. Its successful delete
// task is the immutable node binding for subsequent, explicitly confirmed
// artifact cleanup, even after that address has been released or reassigned.
func deletedArtifactBindingTx(ctx context.Context, tx *sql.Tx, v Instance) (nodeproto.DirectPublicBinding, error) {
	if v.State != "deleted" || v.Resources.NetworkType != "normal" {
		return nodeproto.DirectPublicBinding{}, ErrState
	}
	o, err := scanOperation(tx.QueryRowContext(ctx, "SELECT "+operationColumns+" FROM controller_operations WHERE instance_id=? AND node_id=? AND action='delete' AND state='succeeded' ORDER BY seq DESC LIMIT 1", v.ID, v.NodeID))
	if err != nil {
		return nodeproto.DirectPublicBinding{}, err
	}
	t, err := nodeproto.DecodeTask(o.Request)
	if err != nil || nodeproto.Digest(o.Request) != o.RequestSHA || t.Protocol != o.Protocol || t.OperationID != o.ID || t.Action != "delete" || t.NodeID != v.NodeID || t.InstanceID != v.ID || t.OwnerRef != v.OwnerRef || t.Hostname != v.Hostname || t.Resources != v.Resources || !t.Network.IsZero() {
		return nodeproto.DirectPublicBinding{}, ErrState
	}
	return t.DirectPublic, nil
}

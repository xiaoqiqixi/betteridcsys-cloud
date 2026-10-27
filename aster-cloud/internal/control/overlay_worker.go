package control

import (
	"aster/cloud/internal/nodeproto"
	"aster/cloud/internal/overlayproto"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// OverlayRPC is deliberately separate from legacy node/1 and node/2 RPCs.
type OverlayRPC interface {
	SendOverlay(context.Context, overlayproto.Task) (overlayproto.Receipt, error)
	LookupOverlay(context.Context, overlayproto.Task) (overlayproto.Receipt, error)
}

func (c *NodeClient) SendOverlay(ctx context.Context, t overlayproto.Task) (overlayproto.Receipt, error) {
	raw, sha, e := t.BytesAndDigest()
	if e != nil || t.NodeID != c.profile.ID {
		return overlayproto.Receipt{}, ErrInput
	}
	out, status, e := c.callStatusTimed(ctx, http.MethodPost, "/v1/overlay/tasks", raw, sha, 110*time.Second, 100*time.Second)
	if e != nil {
		return overlayproto.Receipt{}, e
	}
	r, e := overlayproto.DecodeReceipt(out)
	if e != nil || !r.Matches(t, sha) || status != http.StatusOK {
		return overlayproto.Receipt{}, ErrUnavailable
	}
	return r, nil
}
func (c *NodeClient) LookupOverlay(ctx context.Context, t overlayproto.Task) (overlayproto.Receipt, error) {
	_, sha, e := t.BytesAndDigest()
	if e != nil || t.NodeID != c.profile.ID {
		return overlayproto.Receipt{}, ErrInput
	}
	out, e := c.call(ctx, http.MethodGet, "/v1/overlay/tasks/"+t.OperationID, nil, sha)
	if e != nil {
		return overlayproto.Receipt{}, e
	}
	r, e := overlayproto.DecodeReceipt(out)
	if e != nil || !r.Matches(t, sha) {
		return overlayproto.Receipt{}, ErrUnavailable
	}
	return r, nil
}

type OverlayWorker struct {
	Store  *SQLStore
	Config Config
	RPC    func(context.Context, NodeProfile) (OverlayRPC, error)
	Now    func() time.Time
}

func (w OverlayWorker) now() time.Time {
	if w.Now != nil {
		return w.Now().UTC()
	}
	return time.Now().UTC()
}
func (w OverlayWorker) rpc(ctx context.Context, p NodeProfile) (OverlayRPC, error) {
	if w.RPC != nil {
		return w.RPC(ctx, p)
	}
	return NewNodeClient(ctx, p)
}
func overlayPinsMatch(c Config, e OverlayEpoch) bool {
	cluster, ok := c.OverlayCluster(e.ClusterID)
	if !ok || len(cluster.Profiles) != len(e.Snapshot.Profiles) {
		return false
	}
	pins := map[string]overlayproto.ProfilePin{}
	for _, p := range cluster.Profiles {
		pins[p.NodeID] = p
	}
	for _, p := range e.Snapshot.Profiles {
		if pins[p.NodeID] != p {
			return false
		}
	}
	return true
}

// A new full root configuration is never silently adopted by ordinary edits.
// Only recovery may cross an explicitly listed old pin while preserving the old
// snapshot and observed heads. HTTP callers cannot supply this approval.
func overlayRecoveryPinsApproved(c Config, e OverlayEpoch) bool {
	cluster, ok := c.OverlayCluster(e.ClusterID)
	if !ok || len(cluster.Profiles) != len(e.Snapshot.Profiles) {
		return false
	}
	for _, old := range e.Snapshot.Profiles {
		approved := false
		for _, current := range cluster.Profiles {
			if old == current {
				approved = true
			}
		}
		for _, previous := range cluster.PreviousProfiles {
			if old == previous {
				approved = true
			}
		}
		if !approved {
			return false
		}
	}
	return true
}
func validateOverlayBindings(ctx context.Context, tx *sql.Tx, e OverlayEpoch) error {
	for _, m := range e.Snapshot.Members {
		v, err := scanInstance(tx.QueryRowContext(ctx, "SELECT id,owner_ref,node_id,hostname,state,resources,created_at,updated_at FROM controller_instances WHERE id=?", m.InstanceID))
		if err != nil || v.NodeID != m.NodeID || v.OwnerRef != m.OwnerRef || v.State == "deleted" {
			return ErrState
		}
		n, err := instanceNetworkBinding(ctx, tx, v)
		if err != nil || n.Digest() != m.NetworkSHA256 || n.LeaseID != m.LeaseID || n.PoolID != m.PoolID || n.VPCID != m.LocalVPCID {
			return ErrState
		}
	}
	return overlayCompleteInventory(ctx, tx, e.Snapshot)
}
func (s *SQLStore) claimOverlayTask(ctx context.Context, c Config, id, taskID string, now time.Time) (OverlayEpoch, OverlayNodeTask, error) {
	tx, e := s.locked(ctx)
	if e != nil {
		return OverlayEpoch{}, OverlayNodeTask{}, e
	}
	defer tx.Rollback()
	epoch, e := scanOverlayEpoch(tx.QueryRowContext(ctx, "SELECT "+overlayEpochColumns+" FROM controller_overlay_epochs WHERE id=?", id))
	if e != nil {
		return epoch, OverlayNodeTask{}, e
	}
	task, e := scanOverlayTask(tx.QueryRowContext(ctx, "SELECT "+overlayTaskColumns+" FROM controller_overlay_tasks WHERE operation_id=?", taskID))
	if e != nil {
		return epoch, task, e
	}
	p, ok := c.Node(task.NodeID)
	wire := overlayTask(epoch, task.NodeID, task.Phase)
	_, sha, err := wire.BytesAndDigest()
	if err != nil || !ok || task.EpochID != epoch.ID || epoch.State != "pending" || task.Phase != epoch.Phase || task.State != "pending" || task.NodeProfileSHA256 != p.Digest() || task.RequestSHA256 != sha || !overlayPinsMatch(c, epoch) {
		return epoch, task, ErrState
	}
	cluster, _ := c.OverlayCluster(epoch.ClusterID)
	if !overlayPoliciesApproved(cluster, epoch.Snapshot) {
		return epoch, task, ErrState
	}
	if e = validatePublicIPSnapshotTx(ctx, tx, c, epoch.Snapshot, now); e != nil {
		return epoch, task, e
	}
	if e = validateOverlayBindings(ctx, tx, epoch); e != nil {
		return epoch, task, e
	}
	// A corrupted phase field must not bypass the all-participants barrier.
	for _, phase := range []string{"prepare", "program", "release"} {
		if phase == epoch.Phase {
			break
		}
		var count int
		if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM controller_overlay_tasks WHERE epoch_id=? AND phase=? AND state='succeeded'", id, phase).Scan(&count); e != nil || count != len(epoch.Snapshot.Profiles) {
			return epoch, task, ErrState
		}
	}
	if _, e = tx.ExecContext(ctx, "UPDATE controller_overlay_tasks SET state='sending',updated_at=? WHERE operation_id=?", now, taskID); e != nil {
		return epoch, task, e
	}
	if e = audit(ctx, tx, "overlay-worker", "overlay."+task.Phase+".sending", taskID, now); e != nil {
		return epoch, task, e
	}
	task.State = "sending"
	task.UpdatedAt = now
	return epoch, task, tx.Commit()
}
func (s *SQLStore) completeOverlayTask(ctx context.Context, id, taskID string, result *overlayproto.Receipt, now time.Time) (OverlayEpoch, error) {
	tx, e := s.locked(ctx)
	if e != nil {
		return OverlayEpoch{}, e
	}
	defer tx.Rollback()
	epoch, e := scanOverlayEpoch(tx.QueryRowContext(ctx, "SELECT "+overlayEpochColumns+" FROM controller_overlay_epochs WHERE id=?", id))
	if e != nil {
		return epoch, e
	}
	task, e := scanOverlayTask(tx.QueryRowContext(ctx, "SELECT "+overlayTaskColumns+" FROM controller_overlay_tasks WHERE operation_id=?", taskID))
	if e != nil {
		return epoch, e
	}
	if epoch.State == "superseded" {
		return epoch, ErrState
	}
	wire := overlayTask(epoch, task.NodeID, task.Phase)
	_, sha, err := wire.BytesAndDigest()
	if err != nil || task.EpochID != id || task.RequestSHA256 != sha {
		return epoch, ErrState
	}
	state := "uncertain"
	raw := []byte{}
	if result != nil {
		if !result.Matches(wire, sha) {
			return epoch, ErrState
		}
		state = result.Status
		raw, _ = json.Marshal(result)
	}
	if task.State == "succeeded" || task.State == "rejected" {
		if state != task.State || string(raw) != string(task.Receipt) {
			return epoch, ErrConflict
		}
		return epoch, nil
	}
	if task.State != "sending" && task.State != "uncertain" {
		return epoch, ErrState
	}
	if task.Phase != epoch.Phase {
		return epoch, ErrState
	}
	if _, e = tx.ExecContext(ctx, "UPDATE controller_overlay_tasks SET state=?,receipt=?,updated_at=? WHERE operation_id=?", state, raw, now, taskID); e != nil {
		return epoch, e
	}
	if e = audit(ctx, tx, "overlay-worker", "overlay."+task.Phase+"."+state, taskID, now); e != nil {
		return epoch, e
	}
	rows, e := tx.QueryContext(ctx, "SELECT state FROM controller_overlay_tasks WHERE epoch_id=? AND phase=?", id, epoch.Phase)
	if e != nil {
		return epoch, e
	}
	states := []string{}
	for rows.Next() {
		var state string
		if e = rows.Scan(&state); e != nil {
			rows.Close()
			return epoch, e
		}
		states = append(states, state)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return epoch, e
	}
	if len(states) != len(epoch.Snapshot.Profiles) {
		return epoch, ErrState
	}
	phase, state, e := overlayBarrier(epoch.Phase, states)
	if e != nil {
		return epoch, e
	}
	epoch.Phase = phase
	epoch.State = state
	epoch.UpdatedAt = now
	if _, e = tx.ExecContext(ctx, "UPDATE controller_overlay_epochs SET phase=?,state=?,updated_at=? WHERE id=?", phase, state, now, id); e != nil {
		return epoch, e
	}
	return epoch, tx.Commit()
}

// This transition is intentionally conservative: no majority/quorum can release
// VMs. Every approved participant must acknowledge precisely the same snapshot.
func overlayBarrier(phase string, states []string) (string, string, error) {
	if !overlayproto.ValidPhase(phase) || len(states) < 1 || len(states) > 32 {
		return "", "", ErrState
	}
	all := true
	uncertain, rejected := false, false
	for _, s := range states {
		switch s {
		case "succeeded":
		case "pending", "sending":
			all = false
		case "uncertain":
			all = false
			uncertain = true
		case "rejected":
			all = false
			rejected = true
		default:
			return "", "", ErrState
		}
	}
	if rejected {
		return phase, "rejected", nil
	}
	if uncertain {
		return phase, "uncertain", nil
	}
	if !all {
		return phase, "pending", nil
	}
	switch phase {
	case "prepare":
		return "program", "pending", nil
	case "program":
		return "release", "pending", nil
	default:
		return "release", "succeeded", nil
	}
}

// Advance performs at most one new node POST. Repeat calls select only pending
// tasks; sending/uncertain tasks are never retransmitted, even after restart.
func (w OverlayWorker) Advance(ctx context.Context, id string) (OverlayEpoch, error) {
	e, err := w.Store.OverlayEpoch(ctx, id)
	if err != nil {
		return e, err
	}
	if e.State == "succeeded" {
		return e, nil
	}
	if e.State != "pending" || !overlayPinsMatch(w.Config, e) {
		return e, ErrState
	}
	tasks, err := w.Store.OverlayTasks(ctx, id)
	if err != nil {
		return e, err
	}
	for _, t := range tasks {
		if t.Phase != e.Phase {
			continue
		}
		if t.State == "sending" || t.State == "uncertain" {
			return e, ErrState
		}
	}
	for _, t := range tasks {
		if t.Phase != e.Phase || t.State != "pending" {
			continue
		}
		p, ok := w.Config.Node(t.NodeID)
		if !ok || p.Digest() != t.NodeProfileSHA256 {
			return e, ErrState
		}
		rpc, err := w.rpc(ctx, p)
		if err != nil {
			return e, err
		}
		e, t, err = w.Store.claimOverlayTask(ctx, w.Config, id, t.OperationID, w.now())
		if err != nil {
			return e, err
		}
		result, callErr := rpc.SendOverlay(ctx, overlayTask(e, t.NodeID, t.Phase))
		var receipt *overlayproto.Receipt
		if callErr == nil && result.Matches(overlayTask(e, t.NodeID, t.Phase), t.RequestSHA256) {
			receipt = &result
		} else {
			callErr = ErrUnavailable
		}
		finish, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		saved, saveErr := w.Store.completeOverlayTask(finish, id, t.OperationID, receipt, w.now())
		if saveErr != nil {
			return e, saveErr
		}
		if callErr != nil {
			return saved, callErr
		}
		return saved, nil
	}
	return e, ErrState
}

// Reconcile is read-only on nodes and checks the exact historical transport pin.
// It is allowed if root removed the current overlay profile, but never sends.
func (w OverlayWorker) Reconcile(ctx context.Context, id string) (OverlayEpoch, error) {
	e, err := w.Store.OverlayEpoch(ctx, id)
	if err != nil {
		return e, err
	}
	tasks, err := w.Store.OverlayTasks(ctx, id)
	if err != nil {
		return e, err
	}
	for _, t := range tasks {
		if t.Phase != e.Phase || t.State != "sending" && t.State != "uncertain" {
			continue
		}
		p, ok := w.Config.Node(t.NodeID)
		if !ok || p.Digest() != t.NodeProfileSHA256 {
			return e, ErrState
		}
		rpc, err := w.rpc(ctx, p)
		if err != nil {
			return e, err
		}
		r, err := rpc.LookupOverlay(ctx, overlayTask(e, t.NodeID, t.Phase))
		if err != nil || !r.Matches(overlayTask(e, t.NodeID, t.Phase), t.RequestSHA256) {
			return e, ErrUnavailable
		}
		return w.Store.completeOverlayTask(ctx, id, t.OperationID, &r, w.now())
	}
	if e.State == "succeeded" {
		return e, nil
	}
	return e, ErrState
}

// An in-flight cluster epoch owns all member lifecycle mutations. Old API
// operations cannot race a prepare/program/release transition on the same VM.
func overlayLifecycleGate(ctx context.Context, tx *sql.Tx, instance string) error {
	var cluster string
	e := tx.QueryRowContext(ctx, "SELECT cluster_id FROM controller_overlay_members WHERE instance_id=?", instance).Scan(&cluster)
	if errors.Is(e, sql.ErrNoRows) {
		return nil
	}
	if e != nil {
		return e
	}
	var state string
	e = tx.QueryRowContext(ctx, "SELECT state FROM controller_overlay_epochs WHERE cluster_id=? ORDER BY epoch DESC LIMIT 1", cluster).Scan(&state)
	if e != nil || state != "succeeded" {
		return ErrState
	}
	return nil
}

// Include every nondeleted immutable binding on a selected dedicated profile.
// A snapshot omitting a disabled/offline peer cannot silently widen or forget it.
func overlayCompleteInventory(ctx context.Context, tx *sql.Tx, snapshot overlayproto.Snapshot) error {
	members := map[string]bool{}
	for _, m := range snapshot.Members {
		members[m.InstanceID] = true
	}
	for _, pin := range snapshot.Profiles {
		rows, e := tx.QueryContext(ctx, "SELECT n.instance_id,n.binding FROM controller_instance_networks n JOIN controller_instances i ON i.id=n.instance_id WHERE n.node_id=? AND CAST(i.state AS BINARY)<>'deleted'", pin.NodeID)
		if e != nil {
			return e
		}
		for rows.Next() {
			var instance string
			var raw []byte
			if rows.Scan(&instance, &raw) != nil {
				rows.Close()
				return ErrState
			}
			var binding nodeproto.NetworkBinding
			if !strict(raw, &binding) || binding.InstanceID != instance || binding.NodeID != pin.NodeID {
				rows.Close()
				return ErrState
			}
			if binding.ProfileID == pin.ProfileID && !members[instance] {
				rows.Close()
				return ErrState
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
	}
	return nil
}

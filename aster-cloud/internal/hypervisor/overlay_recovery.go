package hypervisor

import (
	"aster/cloud/internal/fabric"
	"aster/cloud/internal/nodeproto"
	"aster/cloud/internal/overlayproto"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
)

const overlayNodeRecoveryProtocol = "aster.node-overlay-recovery/1"

// One immutable inventory spans all three cluster barriers. Desired is power
// intent, Release is power intent intersected with the new network authorization.
// A disabled peer is never resumed just because its ledger says "running".
type overlayRecoveryEvidence struct {
	Protocol   string            `json:"protocol"`
	RecoveryID string            `json:"recovery_id"`
	ProfileID  string            `json:"profile_id"`
	Prepare    overlayproto.Task `json:"prepare"`
	Operations []Operation       `json:"operations"`
	Instances  []Instance        `json:"instances"`
	Desired    map[string]bool   `json:"desired"`
	Release    map[string]bool   `json:"release"`
}

type overlayRecoveryResult struct {
	Protocol     string               `json:"protocol"`
	Release      overlayproto.Task    `json:"release"`
	IntentSHA256 string               `json:"intent_sha256"`
	Receipt      overlayproto.Receipt `json:"receipt"`
}

func (m *Manager) overlayNodeTaskPath(id string) string {
	return filepath.Join(m.Ledger.directory, "overlay-node-task-"+id+".json")
}
func (m *Manager) readOverlayNodeTask(id string) (overlayproto.Task, error) {
	raw, e := readApproved(m.overlayNodeTaskPath(id), true, overlayproto.MaxBytes)
	if e != nil {
		return overlayproto.Task{}, e
	}
	return overlayproto.DecodeTask(raw)
}
func (m *Manager) saveOverlayNodeTask(t overlayproto.Task) error {
	raw, _, e := t.BytesAndDigest()
	if e != nil {
		return e
	}
	path := m.overlayNodeTaskPath(t.OperationID)
	old, e := readApproved(path, true, overlayproto.MaxBytes)
	if e == nil {
		if !bytes.Equal(raw, old) {
			return ErrConflict
		}
		return nil
	}
	if !os.IsNotExist(e) {
		return e
	}
	return writeRecoveryEvidence(path, raw)
}
func (m *Manager) overlayRecoveryPath(sha, suffix string) string {
	return filepath.Join(m.Ledger.directory, "overlay-recovery-"+sha+"."+suffix+".json")
}
func overlayRecoveryID(t overlayproto.Task) string {
	return nodeproto.Digest([]byte(overlayNodeRecoveryProtocol + ":" + t.NodeID + ":" + t.SnapshotSHA256))[:32]
}
func decodeOverlayEvidence(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(out); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrOwnership
	}
	canonical, e := json.Marshal(out)
	if e != nil || !bytes.Equal(raw, canonical) {
		return ErrOwnership
	}
	return nil
}
func (m *Manager) readOverlayRecovery(t overlayproto.Task) (overlayRecoveryEvidence, []byte, error) {
	var ev overlayRecoveryEvidence
	raw, e := readApproved(m.overlayRecoveryPath(t.SnapshotSHA256, "intent"), true, 4<<20)
	if e != nil {
		return ev, nil, e
	}
	if e = decodeOverlayEvidence(raw, &ev); e != nil {
		return ev, nil, e
	}
	_, _, e = ev.Prepare.BytesAndDigest()
	if e != nil || ev.Protocol != overlayNodeRecoveryProtocol || ev.RecoveryID != overlayRecoveryID(t) || ev.Prepare.Phase != "prepare" || ev.Prepare.NodeID != t.NodeID || ev.Prepare.Recovery == nil || !reflect.DeepEqual(ev.Prepare.Recovery, t.Recovery) || !reflect.DeepEqual(ev.Prepare.Snapshot, t.Snapshot) || ev.Prepare.SnapshotSHA256 != t.SnapshotSHA256 || !nodeproto.ValidNodeID(ev.ProfileID) || ev.Operations == nil || ev.Instances == nil || ev.Desired == nil || ev.Release == nil {
		return ev, nil, ErrOwnership
	}
	return ev, raw, nil
}

// Capture every pending lifecycle operation on the bridge, not merely the first
// failed guest. No pending operation is adopted unless its original complete
// frozen binding matches the node-owned instance and its outcome is observable.
func (m *Manager) freezeOverlayRecovery(profile string, t overlayproto.Task) (overlayRecoveryEvidence, error) {
	ev := overlayRecoveryEvidence{Protocol: overlayNodeRecoveryProtocol, RecoveryID: overlayRecoveryID(t), ProfileID: profile, Prepare: t, Operations: []Operation{}, Instances: []Instance{}, Desired: map[string]bool{}, Release: map[string]bool{}}
	instances, _, e := m.overlayInventoryMode(profile, t.Snapshot, true)
	if e != nil {
		return ev, e
	}
	ev.Instances = append(ev.Instances, instances...)
	members := map[string]Instance{}
	for _, i := range instances {
		members[i.ID] = i
		ev.Desired[i.ID] = i.State == "running"
	}
	l := m.Ledger
	l.mu.Lock()
	if l.closed || l.poisoned {
		l.mu.Unlock()
		return ev, errors.New("journal unavailable")
	}
	for _, op := range l.state.Operations {
		_, member := members[op.Task.InstanceID]
		if pendingNetworkOperation(op) && (member || !op.Task.Network.IsZero() && op.Task.Network.ProfileID == profile) {
			if op.Task.Network.IsZero() || op.Task.Network.ProfileID != profile {
				l.mu.Unlock()
				return ev, ErrOwnership
			}
			if _, ok := members[op.Task.InstanceID]; !ok {
				l.mu.Unlock()
				return ev, ErrOwnership
			}
			state, ok := recoveryDesiredState(op.Task.Action)
			if !ok {
				l.mu.Unlock()
				return ev, ErrUnsupported
			}
			ev.Desired[op.Task.InstanceID] = state == "running"
			ev.Operations = append(ev.Operations, op)
		}
	}
	l.mu.Unlock()
	sort.Slice(ev.Operations, func(a, b int) bool { return ev.Operations[a].Task.OperationID < ev.Operations[b].Task.OperationID })
	for _, member := range t.Snapshot.Members {
		if member.NodeID != m.Config.NodeID {
			continue
		}
		if _, exists := members[member.InstanceID]; exists {
			ev.Release[member.InstanceID] = member.Enabled && ev.Desired[member.InstanceID]
		}
	}
	// An original create/start cannot be reported complete while the requested
	// guest is deliberately network-disabled and kept paused by this epoch.
	for _, op := range ev.Operations {
		if ev.Desired[op.Task.InstanceID] && !ev.Release[op.Task.InstanceID] {
			return ev, errors.New("OVERLAY_RECOVERY_TARGET_DISABLED")
		}
	}
	if e = m.checkOverlayRecoveryInventory(ev); e != nil {
		return ev, e
	}
	return ev, nil
}

func (m *Manager) checkOverlayRecoveryInventory(ev overlayRecoveryEvidence) error {
	instances, _, e := m.overlayInventoryMode(ev.ProfileID, ev.Prepare.Snapshot, true)
	if e != nil || len(instances) != len(ev.Instances) {
		return ErrConflict
	}
	for n := range instances {
		if !reflect.DeepEqual(instances[n], ev.Instances[n]) {
			return ErrConflict
		}
	}
	if len(ev.Desired) != len(instances) || len(ev.Release) != len(instances) {
		return ErrOwnership
	}
	authorized := map[string]bool{}
	for _, member := range ev.Prepare.Snapshot.Members {
		if member.NodeID == m.Config.NodeID {
			authorized[member.InstanceID] = member.Enabled
		}
	}
	for _, i := range instances {
		desired, haveDesired := ev.Desired[i.ID]
		release, haveRelease := ev.Release[i.ID]
		if !haveDesired || !haveRelease || release != (desired && authorized[i.ID]) {
			return ErrOwnership
		}
	}
	if len(ev.Operations) != 0 {
		ops, all, e := m.prepareRecoveryGroup(ev.ProfileID, ev.Operations[0], ev.Desired)
		if e != nil {
			return e
		}
		if !reflect.DeepEqual(ops, ev.Operations) || !reflect.DeepEqual(all, ev.Instances) {
			return ErrConflict
		}
		return nil
	}
	// Drift-only recovery still freezes the complete inventory and must not
	// bypass a new pending lifecycle/storage operation between cluster barriers.
	l := m.Ledger
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.poisoned {
		return ErrOwnership
	}
	for _, op := range l.state.Operations {
		_, member := ev.Desired[op.Task.InstanceID]
		if (member || !op.Task.Network.IsZero() && op.Task.Network.ProfileID == ev.ProfileID) && pendingNetworkOperation(op) {
			return ErrConflict
		}
	}
	for _, i := range instances {
		if i.State != "running" && i.State != "shut off" || ev.Desired[i.ID] != (i.State == "running") {
			return ErrOwnership
		}
		for _, op := range l.state.StorageOperations {
			if op.Task.InstanceID == i.ID && (op.Result.Status == "accepted" || op.Result.Status == "uncertain") {
				return ErrConflict
			}
		}
	}
	return nil
}

func (m *Manager) checkOverlayRecoveryReleased(ctx context.Context, ev overlayRecoveryEvidence) error {
	if e := m.checkOverlayRecoveryInventory(ev); e != nil {
		return e
	}
	for _, i := range ev.Instances {
		if e := m.assertOwned(ctx, i); e != nil {
			return e
		}
		if e := m.ovsBootPolicy(ctx, i); e != nil {
			return e
		}
		state, e := m.state(ctx, i.Domain)
		if e != nil {
			return e
		}
		want, link := "shut off", "down"
		if ev.Release[i.ID] {
			want, link = "running", "up"
		} else if ev.Desired[i.ID] {
			want = "paused"
		}
		if state != want {
			return ErrOwnership
		}
		if state != "shut off" {
			if e = m.assertOVSLink(ctx, i, link); e != nil {
				return e
			}
		}
	}
	return nil
}

func uncertainOverlayReceipt(r overlayproto.Receipt, code string) overlayproto.Receipt {
	if r.Status == "succeeded" {
		r.Status, r.Code = "uncertain", code
	}
	return r
}

// This is only a projection. The original fabric receipt and evidence remain
// immutable. Missing node completion must never become a successful cluster ACK.
func (m *Manager) visibleOverlayReceipt(t overlayproto.Task, r overlayproto.Receipt) overlayproto.Receipt {
	if t.Recovery == nil || t.Phase != "release" || r.Status != "succeeded" {
		return r
	}
	ev, intent, e := m.readOverlayRecovery(t)
	if e != nil {
		return uncertainOverlayReceipt(r, "NODE_RECOVERY_COMPLETION_UNCONFIRMED")
	}
	raw, e := readApproved(m.overlayRecoveryPath(t.SnapshotSHA256, "result"), true, 4<<20)
	var result overlayRecoveryResult
	if e != nil || decodeOverlayEvidence(raw, &result) != nil || result.Protocol != overlayNodeRecoveryProtocol || !reflect.DeepEqual(result.Release, t) || result.IntentSHA256 != nodeproto.Digest(intent) || result.Receipt != r {
		return uncertainOverlayReceipt(r, "NODE_RECOVERY_COMPLETION_UNCONFIRMED")
	}
	_, sha, _ := t.BytesAndDigest()
	commit := NetworkRecoveryCommit{OperationID: ev.RecoveryID, ProfileID: ev.ProfileID, RequestSHA256: sha, IntentSHA256: nodeproto.Digest(intent), ResultSHA256: nodeproto.Digest(raw)}
	if !m.Ledger.NetworkRecoveryCommitted(commit) {
		return uncertainOverlayReceipt(r, "NODE_RECOVERY_COMPLETION_UNCONFIRMED")
	}
	return r
}

func (m *Manager) applyOverlayRecovery(ctx context.Context, profile string, cfg fabric.OverlayConfig, g overlayGate, t overlayproto.Task) (overlayproto.Receipt, []Instance, error) {
	var r overlayproto.Receipt
	var ev overlayRecoveryEvidence
	var intent []byte
	var e error
	if t.Phase == "prepare" {
		if e = m.Ledger.networkRecoveryIDAvailable(overlayRecoveryID(t)); e != nil {
			return r, nil, e
		}
		// A prior interrupted attempt without a fabric receipt is not permission
		// to repeat callbacks. The controller must authorize another recovery epoch.
		if _, e = readApproved(m.overlayRecoveryPath(t.SnapshotSHA256, "intent"), true, 4<<20); !os.IsNotExist(e) {
			return r, nil, errors.New("OVERLAY_RECOVERY_PREPARE_ALREADY_ATTEMPTED")
		}
		ev, e = m.freezeOverlayRecovery(profile, t)
		if e != nil {
			return r, ev.Instances, e
		}
		intent, e = json.Marshal(ev)
		if e == nil {
			e = writeRecoveryEvidence(m.overlayRecoveryPath(t.SnapshotSHA256, "intent"), intent)
		}
	} else {
		ev, intent, e = m.readOverlayRecovery(t)
	}
	if e != nil || ev.ProfileID != profile {
		if e == nil {
			e = ErrOwnership
		}
		return r, ev.Instances, e
	}
	validate := func(ctx context.Context, fenced bool) error {
		if e := m.checkOverlayRecoveryInventory(ev); e != nil {
			return e
		}
		if e := m.verifyRecoveryGroup(ctx, ev.Operations, ev.Instances, ev.Desired); e != nil {
			return e
		}
		if fenced {
			return m.checkFencedInventory(ctx, ev.Instances, ev.Release)
		}
		return nil
	}
	switch t.Phase {
	case "prepare":
		r, e = g.PrepareOverlay(ctx, cfg, t, func(ctx context.Context) error {
			if e := validate(ctx, false); e != nil {
				return e
			}
			return m.fenceOVSInventory(ctx, ev.Instances, ev.Release)
		})
	case "program":
		if e = validate(ctx, true); e == nil {
			r, e = g.ProgramOverlay(ctx, cfg, t)
		}
	case "release":
		r, e = g.ReleaseOverlay(ctx, cfg, t, func(ctx context.Context) error {
			if e := validate(ctx, true); e != nil {
				return e
			}
			return m.releaseOVSInventory(ctx, ev.Instances, ev.Release)
		})
		_, sha, _ := t.BytesAndDigest()
		if e == nil && r.Matches(t, sha) && r.Status == "succeeded" {
			// Fabric has freshly re-read the whole data plane after release. Only
			// now may original pending node outcomes and the completion marker be
			// committed together in ONE atomic journal write, with exact CAS.
			e = m.checkOverlayRecoveryReleased(ctx, ev)
			result := overlayRecoveryResult{Protocol: overlayNodeRecoveryProtocol, Release: t, IntentSHA256: nodeproto.Digest(intent), Receipt: r}
			var raw []byte
			if e == nil {
				raw, e = json.Marshal(result)
			}
			if e == nil {
				e = writeRecoveryEvidence(m.overlayRecoveryPath(t.SnapshotSHA256, "result"), raw)
			}
			if e == nil {
				_, e = m.Ledger.FinishNetworkRecovery(ev.RecoveryID, ev.Operations, ev.Instances, NetworkRecoveryCommit{OperationID: ev.RecoveryID, ProfileID: profile, RequestSHA256: sha, IntentSHA256: nodeproto.Digest(intent), ResultSHA256: nodeproto.Digest(raw)})
			}
			if e != nil {
				r = uncertainOverlayReceipt(r, "NODE_RECOVERY_COMPLETION_UNCONFIRMED")
			}
		}
	default:
		e = overlayproto.ErrInput
	}
	return r, ev.Instances, e
}

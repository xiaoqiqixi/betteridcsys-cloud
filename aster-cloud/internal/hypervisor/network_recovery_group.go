package hypervisor

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"time"
)

func pendingNetworkOperation(op Operation) bool {
	return op.Result.Status == "accepted" || op.Result.Status == "uncertain"
}
func recoveryDesiredState(action string) (string, bool) {
	switch action {
	case "create", "start":
		return "running", true
	case "shutdown", "force_off":
		return "shut off", true
	}
	return "", false
}
func recoveryTaskMatchesInstance(op Operation, i Instance) bool {
	return op.Task.InstanceID == i.ID && op.Task.OwnerRef == i.OwnerRef && op.Task.Resources == i.Resources && op.Task.Hostname == i.Hostname && op.Task.Network == i.Network && !i.Network.IsZero() && i.SourceFence == nil && i.TargetBinding == nil && i.State != "deleted"
}

// prepareRecoveryGroup snapshots ALL original pending operations for one bridge.
// It does not claim a host outcome, issue a command, or silently complete peers.
// The caller must preserve returned Operations in its immutable approval evidence,
// verifyRecoveryGroup under fabric DROP, and finish once after fresh live proof.
func (m *Manager) prepareRecoveryGroup(profile string, original Operation, enabled map[string]bool) ([]Operation, []Instance, error) {
	l := m.Ledger
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.poisoned {
		return nil, nil, errors.New("journal unavailable")
	}
	current, ok := l.state.Operations[original.Task.OperationID]
	if !ok || current != original || original.Task.Network.ProfileID != profile || original.Task.Network.IsZero() {
		return nil, nil, ErrOwnership
	}
	members := map[string]Instance{}
	for id, i := range l.state.Instances {
		if i.State == "deleted" || i.Network.IsZero() || i.Network.ProfileID != profile {
			continue
		}
		if i.SourceFence != nil || i.TargetBinding != nil || i.Network.ProfileSHA256 != original.Task.Network.ProfileSHA256 {
			return nil, nil, ErrOwnership
		}
		members[id] = cloneInstance(i)
	}
	if len(members) == 0 || len(members) > 128 {
		return nil, nil, ErrOwnership
	}
	for id := range enabled {
		if _, ok := members[id]; !ok {
			return nil, nil, ErrOwnership
		}
	}
	for _, op := range l.state.StorageOperations {
		if _, ok := members[op.Task.InstanceID]; ok && (op.Result.Status == "accepted" || op.Result.Status == "uncertain") {
			return nil, nil, errors.New("NETWORK_RECOVERY_STORAGE_UNRESOLVED")
		}
	}
	selected := map[string]Operation{original.Task.OperationID: original}
	for id, op := range l.state.Operations {
		_, member := members[op.Task.InstanceID]
		if (member || op.Task.Network.ProfileID == profile) && pendingNetworkOperation(op) {
			selected[id] = op
		}
	}
	if len(selected) > 128 {
		return nil, nil, ErrOwnership
	}
	seenInstances := map[string]bool{}
	for _, op := range selected {
		i, ok := members[op.Task.InstanceID]
		desired, supported := recoveryDesiredState(op.Task.Action)
		if !ok || !supported || !recoveryTaskMatchesInstance(op, i) || !pendingNetworkOperation(op) && op.Result.Status != "succeeded" || seenInstances[i.ID] {
			return nil, nil, ErrOwnership
		}
		if enabled[i.ID] != (desired == "running") {
			return nil, nil, errors.New("NETWORK_RECOVERY_CONFLICTING_DESIRED_STATE")
		}
		if op.Result.Status == "succeeded" && i.State != desired {
			return nil, nil, ErrOwnership
		}
		seenInstances[i.ID] = true
	}
	// Unaffected peers retain their already-known desired power state. An
	// uncertain instance with no associated pending operation is not adopted.
	for id, i := range members {
		if !seenInstances[id] {
			if i.State != "running" && i.State != "shut off" || enabled[id] != (i.State == "running") {
				return nil, nil, ErrOwnership
			}
		}
	}
	ops := make([]Operation, 0, len(selected))
	instances := make([]Instance, 0, len(members))
	for _, op := range selected {
		ops = append(ops, op)
	}
	for _, i := range members {
		instances = append(instances, i)
	}
	sort.Slice(ops, func(a, b int) bool { return ops[a].Task.OperationID < ops[b].Task.OperationID })
	sort.Slice(instances, func(a, b int) bool { return instances[a].ID < instances[b].ID })
	return ops, instances, nil
}

// Call only after fabric isolation and before its fence/release callbacks. A
// stopped requested start is NOT retried; an unfinished shutdown is NOT repeated.
// Merely pausing a shutdown target cannot prove that shutdown has completed.
func (m *Manager) verifyRecoveryGroup(ctx context.Context, ops []Operation, instances []Instance, enabled map[string]bool) error {
	desired := map[string]string{}
	for _, op := range ops {
		state, ok := recoveryDesiredState(op.Task.Action)
		if !ok {
			return ErrUnsupported
		}
		desired[op.Task.InstanceID] = state
	}
	for _, i := range instances {
		if err := m.assertOwned(ctx, i); err != nil {
			return err
		}
		if err := m.ovsBootPolicy(ctx, i); err != nil {
			return err
		}
		state, err := m.state(ctx, i.Domain)
		if err != nil {
			return err
		}
		want := desired[i.ID]
		if want == "" {
			want = i.State
		}
		if enabled[i.ID] != (want == "running") {
			return ErrOwnership
		}
		if want == "running" {
			if state != "running" && state != "paused" {
				return errors.New("NETWORK_RECOVERY_START_NOT_OBSERVED")
			}
		} else if want == "shut off" {
			if state != "shut off" {
				return errors.New("NETWORK_RECOVERY_STOP_NOT_OBSERVED")
			}
		} else {
			return ErrOwnership
		}
	}
	return nil
}

// FinishNetworkRecovery commits the proven bridge group in ONE node journal save.
// The exact pre-recovery operation and inventory snapshots are CAS preconditions;
// the caller must first preserve them durably and obtain a NEW fabric live proof.
// Already-succeeded operations are byte-for-byte unchanged. A failed save poisons
// the ledger and restores its pre-commit in-memory maps: no partial successes are
// visible to in-process queries. Disk rename/fsync uncertainty still requires a
// new explicit operator recovery, not automatic repetition of old VM mutations.
func (l *Ledger) FinishNetworkRecovery(recoveryID string, ops []Operation, instances []Instance, commit NetworkRecoveryCommit) (map[string]nodeproto.NodeResult, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.poisoned || !nodeproto.ValidID(recoveryID) || len(ops) > 128 || len(instances) > 128 {
		return nil, ErrOwnership
	}
	if !commit.valid() || commit.OperationID != recoveryID {
		return nil, ErrOwnership
	}
	if _, exists := l.state.NetworkRecoveries[recoveryID]; exists {
		return nil, ErrConflict
	}
	if _, exists := l.state.Operations[recoveryID]; exists {
		return nil, ErrConflict
	}
	if _, exists := l.state.StorageOperations[recoveryID]; exists {
		return nil, ErrConflict
	}
	expected := map[string]Operation{}
	members := map[string]Instance{}
	desired := map[string]string{}
	profile := commit.ProfileID
	for _, i := range instances {
		if _, dup := members[i.ID]; dup || i.Network.IsZero() || i.State == "deleted" || i.SourceFence != nil || i.TargetBinding != nil {
			return nil, ErrOwnership
		}
		if i.Network.ProfileID != profile {
			return nil, ErrOwnership
		}
		now, ok := l.state.Instances[i.ID]
		if !ok || !reflect.DeepEqual(now, i) {
			return nil, ErrConflict
		}
		members[i.ID] = i
	}
	for _, op := range ops {
		id := op.Task.OperationID
		if id == recoveryID {
			return nil, ErrConflict
		}
		if _, dup := expected[id]; dup {
			return nil, ErrOwnership
		}
		now, ok := l.state.Operations[id]
		if !ok || now != op {
			return nil, ErrConflict
		}
		i, ok := members[op.Task.InstanceID]
		state, supported := recoveryDesiredState(op.Task.Action)
		if !ok || !supported || !recoveryTaskMatchesInstance(op, i) || !pendingNetworkOperation(op) && op.Result.Status != "succeeded" {
			return nil, ErrOwnership
		}
		if _, dup := desired[i.ID]; dup {
			return nil, ErrOwnership
		}
		if op.Result.Status == "succeeded" && i.State != state {
			return nil, ErrOwnership
		}
		desired[i.ID] = state
		expected[id] = op
	}
	for id, i := range members {
		if _, selected := desired[id]; !selected && i.State != "running" && i.State != "shut off" {
			return nil, ErrOwnership
		}
	}
	// Reject partial inventories or newly introduced unresolved work since approval.
	for id, i := range l.state.Instances {
		if !i.Network.IsZero() && i.Network.ProfileID == profile && i.State != "deleted" {
			if _, ok := members[id]; !ok {
				return nil, ErrConflict
			}
		}
	}
	for id, op := range l.state.Operations {
		_, member := members[op.Task.InstanceID]
		if (member || op.Task.Network.ProfileID == profile) && pendingNetworkOperation(op) {
			if _, included := expected[id]; !included {
				return nil, ErrConflict
			}
		}
	}
	for _, op := range l.state.StorageOperations {
		if _, ok := members[op.Task.InstanceID]; ok && (op.Result.Status == "accepted" || op.Result.Status == "uncertain") {
			return nil, ErrConflict
		}
	}
	oldOps, oldInstances := l.state.Operations, l.state.Instances
	nextOps := make(map[string]Operation, len(oldOps))
	for id, op := range oldOps {
		nextOps[id] = op
	}
	nextInstances := make(map[string]Instance, len(oldInstances))
	for id, i := range oldInstances {
		nextInstances[id] = cloneInstance(i)
	}
	results := map[string]nodeproto.NodeResult{}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for id, op := range expected {
		if pendingNetworkOperation(op) {
			op.Result.Status = "succeeded"
			op.ErrorCode = "EXPLICIT_NETWORK_RECOVERY_" + recoveryID
			op.UpdatedAt = now
			nextOps[id] = op
			i := nextInstances[op.Task.InstanceID]
			i.State = desired[i.ID]
			nextInstances[i.ID] = i
		}
		results[id] = op.Result
	}
	// A distinct receipt is mandatory even when every original operation had
	// already succeeded. It commits atomically with this new recovery's group;
	// old success and a pre-commit result file cannot manufacture this receipt.
	originals := append([]Operation{}, ops...)
	sort.Slice(originals, func(a, b int) bool { return originals[a].Task.OperationID < originals[b].Task.OperationID })
	originalRaw, _ := json.Marshal(originals)
	outcomes := make([]nodeproto.NodeResult, 0, len(results))
	for _, op := range originals {
		outcomes = append(outcomes, results[op.Task.OperationID])
	}
	oldRecoveries, oldSchema := l.state.NetworkRecoveries, l.state.Schema
	nextRecoveries := make(map[string]networkRecoveryRecord, len(oldRecoveries)+1)
	for id, record := range oldRecoveries {
		nextRecoveries[id] = record
	}
	nextRecoveries[recoveryID] = networkRecoveryRecord{Commit: commit, OriginalOperationsSHA256: nodeproto.Digest(originalRaw), Outcomes: outcomes}
	l.state.NetworkRecoveries = nextRecoveries
	if l.state.Schema < 4 {
		l.state.Schema = 4
	}
	l.state.Operations, l.state.Instances = nextOps, nextInstances
	if err := l.save(); err != nil {
		l.state.Operations, l.state.Instances = oldOps, oldInstances
		l.state.NetworkRecoveries, l.state.Schema = oldRecoveries, oldSchema
		l.poisoned = true
		return nil, err
	}
	return results, nil
}

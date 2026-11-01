package hypervisor

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"errors"
	"os"
	"time"
)

// ResolveInstance is an offline root operation under the exclusive journal
// lock. It observes libvirt and never starts, stops, retries or removes a disk.
func (m *Manager) ResolveInstance(ctx context.Context, id, reason string) ([]nodeproto.NodeResult, error) {
	return m.resolveInstance(ctx, id, reason, os.Geteuid())
}

func (m *Manager) resolveInstance(ctx context.Context, id, reason string, uid int) ([]nodeproto.NodeResult, error) {
	if uid != 0 {
		return nil, errors.New("instance resolution requires root")
	}
	if !nodeproto.ValidID(id) || !nodeproto.ValidResolutionReason(reason) {
		return nil, nodeproto.ErrInvalid
	}
	m.admission.Lock()
	defer m.admission.Unlock()
	if m.active {
		return nil, errors.New("worker active; resolution refused")
	}
	i, ok := m.Ledger.Instance(id)
	if !ok {
		return nil, ErrNotFound
	}
	if !m.Ledger.HasPendingInstance(id, "") || !i.Network.IsZero() || i.SourceFence != nil || i.TargetBinding != nil && !i.TargetBinding.Activated || i.PublicRetired {
		return nil, errors.New("instance requires its network/storage recovery procedure")
	}
	if err := m.assertOwned(ctx, i); err != nil {
		return nil, err
	}
	state, err := m.state(ctx, i.Domain)
	if err != nil {
		return nil, err
	}
	resolution := nodeproto.InstanceResolution{Who: "uid:0", When: time.Now().UTC().Format(time.RFC3339Nano), ObservedState: state, Reason: reason}
	if !resolution.Valid() {
		return nil, errors.New("unsupported live domain state")
	}
	return m.Ledger.resolveInstance(i, resolution)
}

func (l *Ledger) resolveInstance(i Instance, resolution nodeproto.InstanceResolution) ([]nodeproto.NodeResult, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.poisoned {
		return nil, errors.New("journal unavailable")
	}
	for _, op := range l.state.StorageOperations {
		if op.Task.InstanceID == i.ID && (op.Result.Status == "accepted" || op.Result.Status == "uncertain") {
			return nil, errors.New("storage operation requires independent recovery")
		}
	}
	var ids []string
	for id, op := range l.state.Operations {
		if op.Task.InstanceID != i.ID || op.Result.Resolved != nil || op.Result.Status != "accepted" && op.Result.Status != "uncertain" {
			continue
		}
		t := op.Task
		if op.Result.Status != "uncertain" || t.Action == "public_adopt" || t.Action == "public_detach" || t.OwnerRef != i.OwnerRef || t.Resources != i.Resources || t.Hostname != i.Hostname || t.Network != i.Network || !directTaskMatches(i, t) {
			return nil, ErrOwnership
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return nil, errors.New("no unresolved operation")
	}
	// The annotation and observed instance state share one fsynced journal save.
	l.state.Schema = 6
	i.State = resolution.ObservedState
	l.state.Instances[i.ID] = cloneInstance(i)
	var results []nodeproto.NodeResult
	for _, id := range ids {
		op := l.state.Operations[id]
		r := resolution
		op.Result.Resolved = &r
		op.UpdatedAt = resolution.When
		l.state.Operations[id] = op
		results = append(results, cloneNodeResult(op.Result))
	}
	if err := l.save(); err != nil {
		// Do not expose uncommitted clearance from a poisoned process.
		i.State = "uncertain"
		l.state.Instances[i.ID] = i
		for _, id := range ids {
			op := l.state.Operations[id]
			op.Result.Resolved = nil
			l.state.Operations[id] = op
		}
		return nil, err
	}
	return results, nil
}

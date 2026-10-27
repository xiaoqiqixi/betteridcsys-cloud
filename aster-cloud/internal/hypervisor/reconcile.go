package hypervisor

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"errors"
)

// Reconcile only observes the original domain; it never repeats a libvirt write.
// Intended for the root-only CLI while the service is stopped (exclusive journal).
func (m *Manager) Reconcile(ctx context.Context, id string) (nodeproto.NodeResult, error) {
	if !nodeproto.ValidID(id) {
		return nodeproto.NodeResult{}, nodeproto.ErrInvalid
	}
	m.admission.Lock()
	defer m.admission.Unlock()
	if m.active {
		return nodeproto.NodeResult{}, errors.New("worker active; reconciliation refused")
	}
	op, ok := m.Ledger.Query(id)
	if !ok {
		return nodeproto.NodeResult{}, ErrNotFound
	}
	if op.Result.Status != "accepted" && op.Result.Status != "uncertain" {
		return op.Result, errors.New("only accepted/uncertain operations can be reconciled")
	}
	instance, ok := m.Ledger.Instance(op.Task.InstanceID)
	if ok && (op.Task.Action == "public_adopt" || op.Task.Action == "public_detach") {
		return m.reconcileDirect(ctx, op, instance)
	}
	if !ok || instance.OwnerRef != op.Task.OwnerRef || instance.Resources != op.Task.Resources || instance.Hostname != op.Task.Hostname || instance.Network != op.Task.Network || !directTaskMatches(instance, op.Task) {
		return op.Result, ErrOwnership
	}
	// A running VM is not evidence of a completed fabric activation. The old
	// read-only power reconciler must not turn a dropped/unknown OVS guest into
	// a successful opening. Network reconciliation needs its own live proof.
	if !instance.Network.IsZero() {
		return op.Result, errors.New("OVS_NEEDS_NETWORK_GATE_RECONCILIATION")
	}
	if op.Task.Action == "reboot" || op.Task.Action == "delete" {
		return op.Result, errors.New("read-only observation cannot prove reboot/delete completion")
	}
	if err := m.assertOwned(ctx, instance); err != nil {
		return op.Result, err
	}
	state, err := m.state(ctx, instance.Domain)
	if err != nil {
		return op.Result, err
	}
	desired := "running"
	switch op.Task.Action {
	case "create", "start":
	case "shutdown", "force_off":
		desired = "shut off"
	default:
		return op.Result, ErrUnsupported
	}
	if state != desired {
		return op.Result, errors.New("observed state does not prove requested outcome")
	}
	instance.State = desired
	return m.Ledger.Finish(id, "succeeded", "READONLY_RECONCILED_FROM_"+op.Result.Status, &instance)
}

// A stopped domain with the exact frozen direct NIC metadata and explicit link
// state can prove completion after a crash between libvirt define and journal
// save. It does not rerun define, mutate a guest or infer success from power alone.
func (m *Manager) reconcileDirect(ctx context.Context, op Operation, i Instance) (nodeproto.NodeResult, error) {
	t := op.Task
	if t.Protocol != nodeproto.DirectPublicProtocol || !i.Network.IsZero() || i.SourceFence != nil || i.TargetBinding != nil || i.ID != t.InstanceID || i.OwnerRef != t.OwnerRef || i.Resources != t.Resources || i.Hostname != t.Hostname || i.IPv4 != t.DirectPublic.IPv4 || i.MAC != t.DirectPublic.MAC || t.Action == "public_adopt" && m.approvedDirect(t.DirectPublic) != nil {
		return op.Result, ErrOwnership
	}
	i.DirectPublic = t.DirectPublic
	i.DirectPublicDetached = t.Action == "public_detach"
	if e := m.assertOwned(ctx, i); e != nil {
		return op.Result, e
	}
	state, e := m.state(ctx, i.Domain)
	if e != nil || state != "shut off" {
		return op.Result, errors.New("DIRECT_PUBLIC_READBACK_UNCONFIRMED")
	}
	if !i.DirectPublicDetached {
		for _, other := range m.Ledger.Instances() {
			if other.ID != i.ID && other.State != "deleted" && !other.DirectPublicDetached && (other.IPv4 == i.IPv4 || other.DirectPublic.LeaseID == i.DirectPublic.LeaseID) {
				return op.Result, ErrConflict
			}
		}
	}
	i.State = "shut off"
	return m.Ledger.Finish(t.OperationID, "succeeded", "DIRECT_PUBLIC_READONLY_RECONCILED", &i)
}

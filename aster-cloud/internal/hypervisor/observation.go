package hypervisor

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"time"
)

// ObserveInstance never converts a journal cache into a live observation. It
// serializes against both VM workers and inbox I/O, requires complete ownership
// XML and fresh libvirt state, and never resolves a pending operation.
func (m *Manager) ObserveInstance(ctx context.Context, id string) (nodeproto.InstanceObservation, error) {
	if !nodeproto.ValidID(id) {
		return nodeproto.InstanceObservation{}, ErrNotFound
	}
	m.admission.Lock()
	defer m.admission.Unlock()
	if m.active || m.stopping {
		return nodeproto.InstanceObservation{}, ErrConflict
	}
	i, ok := m.Ledger.Instance(id)
	if !ok || i.State == "deleted" || i.PublicRetired {
		return nodeproto.InstanceObservation{}, ErrNotFound
	}
	if i.State == "uncertain" || i.State == "reserved" || m.Ledger.HasPendingInstance(id, "") {
		return nodeproto.InstanceObservation{}, ErrConflict
	}
	if e := m.assertOwned(ctx, i); e != nil {
		return nodeproto.InstanceObservation{}, e
	}
	state, e := m.state(ctx, i.Domain)
	if e != nil {
		return nodeproto.InstanceObservation{}, e
	}
	return nodeproto.InstanceObservation{DirectPublic: i.DirectPublic, DirectPublicDetached: i.DirectPublicDetached, Protocol: nodeproto.InstanceProtocol, NodeID: m.Config.NodeID, InstanceID: id, OwnerRef: i.OwnerRef, Hostname: i.Hostname, State: state, IPv4: i.IPv4, MAC: i.MAC, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), SourceFenced: i.SourceFence != nil, TargetPending: i.TargetBinding != nil && !i.TargetBinding.Activated}, nil
}

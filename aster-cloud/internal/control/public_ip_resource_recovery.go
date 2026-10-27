package control

import (
	"aster/cloud/internal/nodeproto"
	"aster/cloud/internal/overlayproto"
	"context"
	"errors"
	"math"
)

// RecoverPublicIPResource can only detach this resource. It cannot publish a new
// target, overwrite an old receipt, or bypass the all-node recovery barrier.
func (w OverlayWorker) RecoverPublicIPResource(ctx context.Context, actor, op, resource string, expected uint64, expectedSnapshot string) (PublicIPResource, PublicIPResourceOperation, bool, error) {
	if !nodeproto.ValidID(actor) || !nodeproto.ValidID(op) || !nodeproto.ValidID(resource) || expected >= 1<<63-1 || !overlayproto.ValidSHA(expectedSnapshot) {
		return PublicIPResource{}, PublicIPResourceOperation{}, false, ErrInput
	}
	raw := marshalPublicBinding(struct {
		ExpectedGeneration     uint64 `json:"expected_generation"`
		ExpectedSnapshotSHA256 string `json:"expected_snapshot_sha256"`
	}{expected, expectedSnapshot})
	prior, e := w.Store.PublicIPResourceOperation(ctx, actor, op)
	if e == nil {
		if prior.Action != "resource.recover" || prior.TargetResourceID != resource || prior.RequestSHA256 != publicOperationDigest("resource.recover", resource, raw) {
			return PublicIPResource{}, prior, false, ErrConflict
		}
		return prior.Result.Resource, prior, true, nil
	}
	if !errors.Is(e, ErrNotFound) {
		return PublicIPResource{}, prior, false, e
	}

	// No writes precede these probes. The latest epoch and edit version are
	// rechecked under controller_lock afterwards, including the original digest.
	r, e := scanPublicResource(w.Store.DB.QueryRowContext(ctx, "SELECT "+publicResourceColumns+" FROM controller_public_ip_resources WHERE id=?", resource))
	if e != nil {
		return r, prior, false, e
	}
	if r.Mode != "floating" || r.State != "reserved" || r.BindingGeneration != expected {
		return r, prior, false, ErrState
	}
	old, e := scanOverlayEpoch(w.Store.DB.QueryRowContext(ctx, "SELECT "+overlayEpochColumns+" FROM controller_overlay_epochs WHERE cluster_id=? ORDER BY epoch DESC LIMIT 1", r.ClusterID))
	if e != nil {
		return r, prior, false, e
	}
	if old.SnapshotSHA256 != expectedSnapshot || old.State == "superseded" || old.Epoch == math.MaxInt64 || !w.Config.validOverlayClusters() || !overlayRecoveryPinsApproved(w.Config, old) {
		return r, prior, false, ErrState
	}
	heads, e := w.readOverlayRecoveryHeads(ctx, old)
	if e != nil {
		return r, prior, false, e
	}
	tx, e := w.Store.locked(ctx)
	if e != nil {
		return r, prior, false, e
	}
	defer tx.Rollback()
	prior, replay, e := publicResourceReplay(ctx, tx, actor, op, "resource.recover", resource, raw)
	if e != nil {
		return r, prior, false, e
	}
	if replay {
		return prior.Result.Resource, prior, true, nil
	}
	r, e = scanPublicResource(tx.QueryRowContext(ctx, "SELECT "+publicResourceColumns+" FROM controller_public_ip_resources WHERE id=?", resource))
	if e != nil {
		return r, prior, false, e
	}
	if r.Mode != "floating" || r.State != "reserved" || r.BindingGeneration != expected {
		return r, prior, false, ErrState
	}
	if e = publicResourceActiveTx(ctx, tx, r); e != nil {
		return r, prior, false, e
	}
	binding, e := latestPublicBindingTx(ctx, tx, r.ID)
	if e != nil {
		return r, prior, false, e
	}
	if binding.Generation != expected || binding.EpochID == "" || binding.Action != "floating.bind" && binding.Action != "floating.unbind" && binding.Action != "floating.policy" {
		return r, prior, false, ErrState
	}
	// The resource may already be absent from an unconfirmed unbind snapshot;
	// recovery must still prove all nodes have crossed the new fencing epoch.
	original, e := scanOverlayEpoch(tx.QueryRowContext(ctx, "SELECT "+overlayEpochColumns+" FROM controller_overlay_epochs WHERE id=?", binding.EpochID))
	if e != nil {
		return r, prior, false, e
	}
	if original.ClusterID != r.ClusterID || original.Epoch > old.Epoch || original.SnapshotSHA256 != binding.RequestSHA256 {
		return r, prior, false, ErrState
	}
	members := []OverlayMemberInput{}
	for _, m := range old.Snapshot.Members {
		members = append(members, OverlayMemberInput{InstanceID: m.InstanceID, VPCID: m.VPCID, Enabled: m.Enabled, Reserved: m.Reserved})
	}
	floats := []overlayproto.FloatingIP{}
	for _, f := range old.Snapshot.FloatingIPs {
		if f.ResourceID != r.ID {
			floats = append(floats, f)
		}
	}
	cluster, _ := w.Config.OverlayCluster(r.ClusterID)
	floats = recoveryFloatingPins(cluster, floats)
	nat := append([]overlayproto.NATPolicy{}, old.Snapshot.NATPolicies...)
	for i, policy := range nat {
		for _, root := range cluster.NATProfiles {
			if root.NodeID == policy.NodeID && root.ProfileID == policy.ProfileID && root.VPCID == policy.VPCID && root.GatewayInstanceID == policy.GatewayInstanceID && policy.PublicIPv4 != "" {
				nat[i].ProfileSHA256 = root.ProfileSHA256
			}
		}
	}
	// Preserve every unrelated target/address/port. Only an explicit selected
	// NAT address can cross a root pin here: an old implicit default must not
	// silently adopt a changed root primary. Full approval is checked below.
	in := OverlayRecoveryInput{ExpectedSnapshotSHA256: expectedSnapshot, Replacement: &OverlayReplacementInput{Members: members, Gateways: old.Snapshot.Gateways, NATPolicies: &nat, FloatingIPs: &floats}}
	epochID := overlayproto.Digest([]byte("aster.public-ip.recovery/1:" + op))[:32]
	digest := overlayRecoveryDigest(old.ID, in)
	now := w.now()
	epoch, replayed, e := planOverlayRecoveryTx(ctx, tx, w.Config, actor, old.ID, epochID, digest, in, heads, now)
	if e != nil {
		return r, prior, false, e
	}
	if replayed {
		return r, prior, false, ErrState
	}
	previous := binding.InstanceID
	if previous == "" {
		previous = binding.PreviousInstanceID
	}
	if e = insertPublicBindingTx(ctx, tx, PublicIPBindingIntent{ID: op, ResourceID: r.ID, Action: "floating.unbind", PreviousInstanceID: previous, EpochID: epoch.ID, RequestSHA256: epoch.SnapshotSHA256, Binding: marshalPublicBinding(overlayproto.FloatingIP{}), CreatedAt: epoch.CreatedAt}); e != nil {
		return r, prior, false, e
	}
	r.BindingGeneration++
	r.BindingState = "pending"
	r.InstanceID = ""
	r.OperationID = op
	r.EpochID = epoch.ID
	r.Releasable = false
	r.ReleaseReason = "NETWORK_OPERATION_PENDING"
	r.UpdatedAt = epoch.CreatedAt
	if _, e = tx.ExecContext(ctx, "UPDATE controller_public_ip_resources SET updated_at=? WHERE id=?", r.UpdatedAt, r.ID); e != nil {
		return r, prior, false, e
	}
	result, e := insertPublicResourceOperation(ctx, tx, actor, op, "resource.recover", r.ID, r, raw, r.UpdatedAt)
	if e != nil {
		return r, result, false, e
	}
	return r, result, false, tx.Commit()
}

// A recovery may adopt a newly approved root digest for exactly the same
// floating target and address. It cannot grant a withdrawn address or route.
func recoveryFloatingPins(cluster OverlayCluster, previous []overlayproto.FloatingIP) []overlayproto.FloatingIP {
	out := append([]overlayproto.FloatingIP{}, previous...)
	for i, f := range out {
		for _, p := range cluster.NATProfiles {
			if p.NodeID == f.NodeID && p.ProfileID == f.ProfileID && p.VPCID == f.VPCID && p.GatewayInstanceID == f.GatewayInstanceID && p.AllowFloatingIP && p.AllowInternetEgress && approvedPublicIPAddress(p, f.PublicIPv4) {
				out[i].ProfileSHA256 = p.ProfileSHA256
			}
		}
	}
	return out
}

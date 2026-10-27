package control

import (
	"aster/cloud/internal/overlayproto"
	"context"
	"database/sql"
	"errors"
	"math"
	"time"
)

func bindFloatingResourceTx(ctx context.Context, tx *sql.Tx, c Config, actor, op string, r *PublicIPResource, v Instance, previous string, unbind bool, ingressRevision *uint64, now time.Time) error {
	cluster, ok := c.OverlayCluster(r.ClusterID)
	if !ok || !c.validOverlayClusters() {
		return ErrState
	}
	latest, e := scanOverlayEpoch(tx.QueryRowContext(ctx, "SELECT "+overlayEpochColumns+" FROM controller_overlay_epochs WHERE cluster_id=? ORDER BY epoch DESC LIMIT 1", r.ClusterID))
	if e != nil || latest.State != "succeeded" || latest.Epoch == math.MaxInt64 || !overlayPinsMatch(c, latest) || publicReleaseCompleteTx(ctx, tx, latest) != nil {
		return ErrState
	}
	if !unbind && !publicResourceApprovedTx(ctx, tx, c, *r, r.Address) {
		return ErrState
	}
	floats := []overlayproto.FloatingIP{}
	for _, f := range latest.Snapshot.FloatingIPs {
		if f.ResourceID != r.ID {
			floats = append(floats, f)
		}
	}
	var selected overlayproto.FloatingIP
	if !unbind {
		var member overlayproto.Member
		for _, m := range latest.Snapshot.Members {
			if m.InstanceID == v.ID {
				member = m
			}
		}
		if member.InstanceID == "" || member.NodeID != v.NodeID || member.OwnerRef != r.OwnerRef || member.VPCID != r.VPCID || !member.Enabled || member.Reserved {
			return ErrState
		}
		lease := PublicIPLease{ClusterID: r.ClusterID, OwnerRef: r.OwnerRef, VPCID: r.VPCID, NodeID: r.NodeID, ProfileID: r.ProfileID}
		root, e := publicLeaseRootProfileTx(ctx, tx, c, lease)
		if e != nil {
			return e
		}
		policy, err := desiredPublicIngressTx(ctx, tx, v)
		if err != nil {
			return err
		}
		if ingressRevision == nil && policy.Policy.Revision != 0 || ingressRevision != nil && *ingressRevision != policy.Policy.Revision {
			return ErrState
		}
		selected = overlayproto.FloatingIP{ResourceID: r.ID, NodeID: r.NodeID, VPCID: r.VPCID, OwnerRef: r.OwnerRef, ProfileID: r.ProfileID, ProfileSHA256: root.ProfileSHA256, GatewayInstanceID: root.GatewayInstanceID, InstanceID: v.ID, TargetIPv4: member.IPv4, PublicIPv4: r.Address, Ingress: &policy.Policy}
		floats = append(floats, selected)
	}
	members := []OverlayMemberInput{}
	for _, m := range latest.Snapshot.Members {
		members = append(members, OverlayMemberInput{InstanceID: m.InstanceID, VPCID: m.VPCID, Enabled: m.Enabled, Reserved: m.Reserved})
	}
	input := OverlayEpochInput{ClusterID: r.ClusterID, ExpectedEpoch: latest.Epoch, Members: members, Gateways: latest.Snapshot.Gateways, FloatingIPs: &floats}
	snapshot, sha, e := buildOverlaySnapshot(ctx, tx, c, cluster, latest, input, now, false)
	if e != nil {
		return e
	}
	if e = validatePublicIPSnapshotTx(ctx, tx, c, snapshot, now); e != nil {
		return e
	}
	epochID := overlayproto.Digest([]byte("aster.public-ip.binding/1:" + op))[:32]
	r.EpochID = epochID
	epoch := OverlayEpoch{ID: epochID, ClusterID: r.ClusterID, Epoch: snapshot.Epoch, SnapshotSHA256: sha, Snapshot: snapshot, ActorID: actor, RequestSHA256: overlayproto.Digest(marshalPublicBinding(input)), Phase: "prepare", State: "pending", CreatedAt: now, UpdatedAt: now}
	if e = insertPublicResourceEpochTx(ctx, tx, c, epoch); e != nil {
		return e
	}
	action := "floating.bind"
	instance := v.ID
	if unbind {
		action = "floating.unbind"
		instance = ""
	}
	if e = insertPublicBindingTx(ctx, tx, PublicIPBindingIntent{ID: op, ResourceID: r.ID, Action: action, InstanceID: instance, PreviousInstanceID: previous, EpochID: epochID, RequestSHA256: sha, Binding: marshalPublicBinding(selected), CreatedAt: now}); e != nil {
		return e
	}
	return audit(ctx, tx, "user:"+actor, "public_ip.network_epoch_planned", epochID, now)
}
func insertPublicResourceEpochTx(ctx context.Context, tx *sql.Tx, c Config, e OverlayEpoch) error {
	_, err := tx.ExecContext(ctx, "INSERT INTO controller_overlay_epochs("+overlayEpochColumns+") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", e.ID, e.ClusterID, e.Epoch, e.ActorID, e.RequestSHA256, e.SnapshotSHA256, mustJSON(e.Snapshot), []byte{}, "", e.Phase, e.State, e.CreatedAt, e.UpdatedAt)
	if err != nil {
		return err
	}
	for _, phase := range []string{"prepare", "program", "release"} {
		for _, pin := range e.Snapshot.Profiles {
			p, ok := c.Node(pin.NodeID)
			if !ok {
				return ErrState
			}
			task := overlayTask(e, pin.NodeID, phase)
			_, sha, err := task.BytesAndDigest()
			if err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, "INSERT INTO controller_overlay_tasks("+overlayTaskColumns+") VALUES(?,?,?,?,?,?,?,?,?)", task.OperationID, e.ID, pin.NodeID, phase, p.Digest(), sha, "pending", []byte{}, e.CreatedAt); err != nil {
				return err
			}
		}
	}
	return nil
}
func decorateFloatingResourceTx(ctx context.Context, tx *sql.Tx, c Config, r *PublicIPResource, b PublicIPBindingIntent) error {
	original, e := scanOverlayEpoch(tx.QueryRowContext(ctx, "SELECT "+overlayEpochColumns+" FROM controller_overlay_epochs WHERE id=?", b.EpochID))
	if e != nil {
		return e
	}
	if original.ClusterID != r.ClusterID || original.SnapshotSHA256 != b.RequestSHA256 {
		return ErrState
	}
	latest, e := scanOverlayEpoch(tx.QueryRowContext(ctx, "SELECT "+overlayEpochColumns+" FROM controller_overlay_epochs WHERE cluster_id=? ORDER BY epoch DESC LIMIT 1", r.ClusterID))
	if e != nil {
		return e
	}
	if latest.Epoch < original.Epoch {
		return ErrState
	}
	r.EpochID = latest.ID
	if publicReleaseCompleteTx(ctx, tx, latest) != nil {
		if latest.State != "pending" {
			r.BindingState = "blocked"
			r.ReleaseReason = "NETWORK_RELEASE_UNCONFIRMED"
		}
		return nil
	}
	for _, f := range latest.Snapshot.FloatingIPs {
		if f.ResourceID == r.ID {
			if f.PublicIPv4 != r.Address || f.OwnerRef != r.OwnerRef || f.VPCID != r.VPCID || f.NodeID != r.NodeID || f.ProfileID != r.ProfileID {
				return ErrState
			}
			r.InstanceID = f.InstanceID
			r.BindingState = "bound"
			r.ReleaseReason = "VM_PUBLIC_IP_BOUND"
			return nil
		}
	}
	if e = publicAddressDetachedTx(ctx, tx, c, r.Address); e != nil {
		if !errors.Is(e, ErrState) {
			return e
		}
		r.BindingState = "blocked"
		r.ReleaseReason = "NETWORK_RELEASE_UNCONFIRMED"
		return nil
	}
	r.InstanceID = ""
	r.BindingState = "unbound"
	r.ReleaseReason = ""
	r.Releasable = true
	return nil
}
func validateFloatingPublicResourcesTx(ctx context.Context, tx *sql.Tx, c Config, snapshot overlayproto.Snapshot, seen map[string]bool) error {
	for _, f := range snapshot.FloatingIPs {
		if seen[f.PublicIPv4] {
			return ErrState
		}
		seen[f.PublicIPv4] = true
		r, e := scanPublicResource(tx.QueryRowContext(ctx, "SELECT "+publicResourceColumns+" FROM controller_public_ip_resources WHERE id=?", f.ResourceID))
		if e != nil || r.Mode != "floating" || r.ClusterID != snapshot.ClusterID || r.OwnerRef != f.OwnerRef || r.VPCID != f.VPCID || r.NodeID != f.NodeID || r.ProfileID != f.ProfileID || r.Address != f.PublicIPv4 {
			return ErrState
		}
		if e = publicResourceActiveTx(ctx, tx, r); e != nil {
			return e
		}
		if !publicResourceApprovedTx(ctx, tx, c, r, r.Address) {
			return ErrState
		}
		found := false
		for _, m := range snapshot.Members {
			if m.InstanceID == f.InstanceID && m.OwnerRef == r.OwnerRef && m.VPCID == r.VPCID && m.IPv4 == f.TargetIPv4 && m.Enabled && !m.Reserved {
				found = true
			}
		}
		if !found {
			return ErrState
		}
		if e = publicAddressDetachedExceptTx(ctx, tx, c, r.Address, snapshot.ClusterID); e != nil {
			return e
		}
	}
	return nil
}

package control

import (
	"aster/cloud/internal/overlayproto"
	"context"
	"database/sql"
	"math"
	"reflect"
	"time"
)

func planPublicIngressEpochTx(ctx context.Context, tx *sql.Tx, c Config, actor, op, epochID string, v Instance, r PublicIPResource, policy overlayproto.PublicIngressPolicy, now time.Time) error {
	cluster, ok := c.OverlayCluster(r.ClusterID)
	if !ok || !c.validOverlayClusters() {
		return ErrState
	}
	latest, e := scanOverlayEpoch(tx.QueryRowContext(ctx, "SELECT "+overlayEpochColumns+" FROM controller_overlay_epochs WHERE cluster_id=? ORDER BY epoch DESC LIMIT 1", r.ClusterID))
	if e != nil || latest.Epoch == math.MaxInt64 || !overlayPinsMatch(c, latest) || publicReleaseCompleteTx(ctx, tx, latest) != nil {
		return ErrState
	}
	floats := append([]overlayproto.FloatingIP{}, latest.Snapshot.FloatingIPs...)
	found := false
	var selected overlayproto.FloatingIP
	for i, f := range floats {
		if f.ResourceID == r.ID {
			if f.InstanceID != v.ID || f.OwnerRef != v.OwnerRef || f.PublicIPv4 != r.Address {
				return ErrState
			}
			p := policy
			floats[i].Ingress = &p
			selected = floats[i]
			found = true
		}
	}
	if !found {
		return ErrState
	}
	members := []OverlayMemberInput{}
	for _, m := range latest.Snapshot.Members {
		members = append(members, OverlayMemberInput{InstanceID: m.InstanceID, VPCID: m.VPCID, Enabled: m.Enabled, Reserved: m.Reserved})
	}
	in := OverlayEpochInput{ClusterID: r.ClusterID, ExpectedEpoch: latest.Epoch, Members: members, Gateways: latest.Snapshot.Gateways, FloatingIPs: &floats}
	snapshot, sha, e := buildOverlaySnapshot(ctx, tx, c, cluster, latest, in, now, false)
	if e != nil {
		return e
	}
	if e = validatePublicIPSnapshotTx(ctx, tx, c, snapshot, now); e != nil {
		return e
	}
	epoch := OverlayEpoch{ID: epochID, ClusterID: r.ClusterID, Epoch: snapshot.Epoch, ActorID: actor, RequestSHA256: overlayproto.Digest(marshalPublicBinding(in)), SnapshotSHA256: sha, Snapshot: snapshot, Phase: "prepare", State: "pending", CreatedAt: now, UpdatedAt: now}
	if e = insertPublicResourceEpochTx(ctx, tx, c, epoch); e != nil {
		return e
	}
	if e = insertPublicBindingTx(ctx, tx, PublicIPBindingIntent{ID: op, ResourceID: r.ID, Action: "floating.policy", InstanceID: v.ID, PreviousInstanceID: v.ID, EpochID: epoch.ID, RequestSHA256: sha, Binding: marshalPublicBinding(selected), CreatedAt: now}); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE controller_public_ip_resources SET updated_at=? WHERE id=?", now, r.ID); e != nil {
		return e
	}
	return audit(ctx, tx, "user:"+actor, "public_ingress.epoch_planned", epoch.ID, now)
}
func validatePublicIngressSnapshotTx(ctx context.Context, tx *sql.Tx, c Config, s overlayproto.Snapshot, now time.Time) error {
	explicit := false
	for _, f := range s.FloatingIPs {
		if f.Ingress == nil {
			continue
		}
		explicit = true
		v, e := ingressInstanceTx(ctx, tx, f.InstanceID)
		if e != nil || v.OwnerRef != f.OwnerRef {
			return ErrState
		}
		desired, e := desiredPublicIngressTx(ctx, tx, v)
		if e != nil {
			return e
		}
		if !reflect.DeepEqual(desired.Policy, *f.Ingress) {
			return ErrState
		}
	}
	if explicit {
		supported, _, e := publicIngressCapabilityTx(ctx, tx, c, s.Profiles, now)
		if e != nil {
			return e
		}
		if !supported {
			return ErrState
		}
	}
	return nil
}

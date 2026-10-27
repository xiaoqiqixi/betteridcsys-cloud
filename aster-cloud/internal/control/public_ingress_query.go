package control

import (
	"aster/cloud/internal/nodeproto"
	"aster/cloud/internal/overlayproto"
	"context"
	"database/sql"
	"errors"
	"reflect"
	"time"
)

const publicIngressVersionColumns = "instance_id,revision,owner_ref,policy,operation_id,epoch_id,created_at"
const publicIngressOperationColumns = "id,actor_id,action,target_instance_id,request_sha256,request,result,created_at"

func scanPublicIngressVersion(row interface{ Scan(...any) error }) (publicIngressVersion, error) {
	var v publicIngressVersion
	var instance, owner string
	var revision uint64
	var raw []byte
	e := row.Scan(&instance, &revision, &owner, &raw, &v.OperationID, &v.EpochID, &v.CreatedAt)
	if errors.Is(e, sql.ErrNoRows) {
		return v, ErrNotFound
	}
	if e != nil {
		return v, e
	}
	if !strict(raw, &v.Policy) || !nodeproto.ValidID(instance) || !nodeproto.ValidID(owner) || !nodeproto.ValidID(v.OperationID) || v.EpochID != "" && !nodeproto.ValidID(v.EpochID) || !validOverlayTime(v.CreatedAt) || revision < 1 || revision > maxPublicIngressRevision || v.Policy.Revision != revision || v.Policy.InstanceID != instance || v.Policy.OwnerRef != owner {
		return v, ErrState
	}
	canonical, e := overlayproto.CanonicalPublicIngress(v.Policy)
	if e != nil || !reflect.DeepEqual(canonical, v.Policy) {
		return v, ErrState
	}
	return v, nil
}
func desiredPublicIngressTx(ctx context.Context, tx *sql.Tx, v Instance) (publicIngressVersion, error) {
	p, e := scanPublicIngressVersion(tx.QueryRowContext(ctx, "SELECT "+publicIngressVersionColumns+" FROM controller_public_ingress_versions WHERE instance_id=? ORDER BY revision DESC LIMIT 1", v.ID))
	if errors.Is(e, ErrNotFound) {
		return publicIngressVersion{Policy: overlayproto.DefaultPublicIngress(v.ID, v.OwnerRef)}, nil
	}
	if e != nil {
		return p, e
	}
	if p.Policy.OwnerRef != v.OwnerRef {
		return p, ErrState
	}
	return p, nil
}
func ingressInstanceTx(ctx context.Context, tx *sql.Tx, id string) (Instance, error) {
	v, e := scanInstance(tx.QueryRowContext(ctx, "SELECT id,owner_ref,node_id,hostname,state,resources,created_at,updated_at FROM controller_instances WHERE id=?", id))
	if e != nil {
		return v, e
	}
	if v.Resources.NetworkType != "vpc" || v.State == "deleted" {
		return v, ErrState
	}
	return v, nil
}

// Every participating node is independently required to understand and enforce
// the frozen rules. A healthy gateway does not upgrade an old remote node.
func publicIngressCapabilityTx(ctx context.Context, tx *sql.Tx, c Config, profiles []overlayproto.ProfilePin, now time.Time) (bool, string, error) {
	if len(profiles) == 0 {
		return false, "NODE_NOT_READY", nil
	}
	for _, pin := range profiles {
		p, ok := c.Node(pin.NodeID)
		if !ok {
			return false, "NODE_NOT_READY", nil
		}
		var digest string
		var maintenance bool
		var seen sql.NullTime
		var raw []byte
		e := tx.QueryRowContext(ctx, "SELECT profile_sha256,maintenance,heartbeat_at,capabilities FROM controller_nodes WHERE id=?", pin.NodeID).Scan(&digest, &maintenance, &seen, &raw)
		if errors.Is(e, sql.ErrNoRows) {
			return false, "NODE_NOT_READY", nil
		}
		if e != nil {
			return false, "", e
		}
		var caps Capability
		if !strict(raw, &caps) || caps.NodeID != pin.NodeID || !caps.validNetworkCapabilities() {
			return false, "NODE_NOT_READY", nil
		}
		if digest != p.Digest() || maintenance || caps.Maintenance || !seen.Valid || !heartbeatFresh(&seen.Time, now, time.Duration(c.HeartbeatTTLSeconds)*time.Second) {
			return false, "NODE_NOT_READY", nil
		}
		if !contains(caps.NetworkProfiles, nodeproto.PublicIngressCapability) {
			return false, "UPGRADE_REQUIRED", nil
		}
		if !contains(caps.OVSNetworkProfiles, pin.ProfileID) {
			return false, "NODE_NOT_READY", nil
		}
	}
	return true, "", nil
}
func publicIngressClusterTx(ctx context.Context, tx *sql.Tx, c Config, instance string) (OverlayCluster, bool, error) {
	var id string
	e := tx.QueryRowContext(ctx, "SELECT cluster_id FROM controller_overlay_members WHERE instance_id=?", instance).Scan(&id)
	if errors.Is(e, sql.ErrNoRows) {
		return OverlayCluster{}, false, nil
	}
	if e != nil {
		return OverlayCluster{}, false, e
	}
	cluster, ok := c.OverlayCluster(id)
	if !ok {
		return cluster, false, ErrState
	}
	return cluster, true, nil
}
func relatedFloatingResourceTx(ctx context.Context, tx *sql.Tx, c Config, v Instance) (*PublicIPResource, error) {
	rows, e := tx.QueryContext(ctx, "SELECT "+publicResourceColumns+" FROM controller_public_ip_resources r WHERE owner_ref=? AND mode='floating' AND state='reserved' AND EXISTS(SELECT 1 FROM controller_public_ip_bindings b WHERE b.resource_id=r.id AND (b.instance_id=? OR b.previous_instance_id=?) AND NOT EXISTS(SELECT 1 FROM controller_public_ip_bindings newer WHERE newer.resource_id=b.resource_id AND newer.revision>b.revision)) ORDER BY id LIMIT 4097", v.OwnerRef, v.ID, v.ID)
	if e != nil {
		return nil, e
	}
	items := []PublicIPResource{}
	for rows.Next() {
		r, x := scanPublicResource(rows)
		if x != nil {
			rows.Close()
			return nil, x
		}
		items = append(items, r)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	if len(items) > 4096 {
		return nil, ErrCapacity
	}
	var found *PublicIPResource
	for _, r := range items {
		if e = decoratePublicResourceTx(ctx, tx, c, &r); e != nil {
			return nil, e
		}
		if r.BindingState == "unbound" || r.BindingState == "released" || r.BindingState == "bound" && r.InstanceID != v.ID {
			continue
		}
		if found != nil {
			return nil, ErrState
		}
		copy := r
		found = &copy
	}
	return found, nil
}
func floatingForInstance(s overlayproto.Snapshot, instance string) *overlayproto.FloatingIP {
	for _, f := range s.FloatingIPs {
		if f.InstanceID == instance {
			copy := f
			return &copy
		}
	}
	return nil
}
func publicIngressViewTx(ctx context.Context, tx *sql.Tx, c Config, v Instance, now time.Time) (PublicIngressView, error) {
	desired, e := desiredPublicIngressTx(ctx, tx, v)
	if e != nil {
		return PublicIngressView{}, e
	}
	out := publicIngressView(desired.Policy)
	out.OperationID = desired.OperationID
	if !desired.CreatedAt.IsZero() {
		at := desired.CreatedAt
		out.UpdatedAt = &at
	}
	cluster, joined, e := publicIngressClusterTx(ctx, tx, c, v.ID)
	if e != nil {
		return out, e
	}
	out.UnsupportedReason = "NODE_NOT_READY"
	if joined {
		out.Supported, out.UnsupportedReason, e = publicIngressCapabilityTx(ctx, tx, c, cluster.Profiles, now)
		if e != nil {
			return out, e
		}
	}
	resource, e := relatedFloatingResourceTx(ctx, tx, c, v)
	if e != nil {
		return out, e
	}
	if resource == nil {
		// A policy without an associated public resource is stored, not a claim that
		// any network interface is currently reachable or filtered.
		revision := out.Revision
		out.EffectiveRevision = &revision
		if revision > 0 {
			out.State = "active"
		}
		// A previous policy update may have failed partway before a recovery removed
		// its mapping. No new key is accepted until that recovery fully releases.
		if desired.EpochID != "" {
			original, x := scanOverlayEpoch(tx.QueryRowContext(ctx, "SELECT "+overlayEpochColumns+" FROM controller_overlay_epochs WHERE id=?", desired.EpochID))
			if x != nil {
				return out, x
			}
			latest, x := scanOverlayEpoch(tx.QueryRowContext(ctx, "SELECT "+overlayEpochColumns+" FROM controller_overlay_epochs WHERE cluster_id=? ORDER BY epoch DESC LIMIT 1", original.ClusterID))
			if x != nil {
				return out, x
			}
			if publicReleaseCompleteTx(ctx, tx, latest) != nil {
				out.State = "blocked"
				if latest.State == "pending" {
					out.State = "pending"
				}
				out.EffectiveRevision = nil
				out.EpochID = latest.ID
			}
		}
		return out, nil
	}
	out.BoundResourceID = resource.ID
	out.EpochID = resource.EpochID
	latest, e := scanOverlayEpoch(tx.QueryRowContext(ctx, "SELECT "+overlayEpochColumns+" FROM controller_overlay_epochs WHERE cluster_id=? ORDER BY epoch DESC LIMIT 1", resource.ClusterID))
	if e != nil {
		return out, e
	}
	// Historical release receipts prove what was installed, not whether the
	// current root still approves that exact profile and public mapping. The
	// desired policy and immutable ACK stay intact when current approval drifts.
	if !overlayPinsMatch(c, latest) || !overlayPoliciesApproved(cluster, latest.Snapshot) {
		out.Supported = false
		out.UnsupportedReason = "NODE_NOT_READY"
	}
	out.EpochID = latest.ID
	if publicReleaseCompleteTx(ctx, tx, latest) != nil {
		out.State = "blocked"
		if latest.State == "pending" {
			out.State = "pending"
		}
		prior, x := scanOverlayEpoch(tx.QueryRowContext(ctx, "SELECT "+overlayEpochColumns+" FROM controller_overlay_epochs WHERE cluster_id=? AND epoch<? AND state='succeeded' AND phase='release' ORDER BY epoch DESC LIMIT 1", latest.ClusterID, latest.Epoch))
		if x == nil && publicReleaseCompleteTx(ctx, tx, prior) == nil {
			if f := floatingForInstance(prior.Snapshot, v.ID); f != nil && f.Ingress == nil {
				out.LegacyUnrestricted = true
			}
		} else if x != nil && !errors.Is(x, ErrNotFound) {
			return out, x
		}
		return out, nil
	}
	f := floatingForInstance(latest.Snapshot, v.ID)
	if f == nil {
		return out, ErrState
	}
	if f.Ingress == nil {
		out.LegacyUnrestricted = true
		out.State = "default"
		if !out.Supported {
			out.State = "blocked"
		}
		return out, nil
	}
	if !out.Supported || !reflect.DeepEqual(*f.Ingress, desired.Policy) {
		out.State = "blocked"
		return out, nil
	}
	revision := out.Revision
	out.EffectiveRevision = &revision
	out.State = "active"
	return out, nil
}
func (s *SQLStore) PublicIngress(ctx context.Context, c Config, instance string, now time.Time) (PublicIngressView, error) {
	if !nodeproto.ValidID(instance) {
		return PublicIngressView{}, ErrInput
	}
	tx, e := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return PublicIngressView{}, e
	}
	defer tx.Rollback()
	v, e := ingressInstanceTx(ctx, tx, instance)
	if e != nil {
		return PublicIngressView{}, e
	}
	out, e := publicIngressViewTx(ctx, tx, c, v, now)
	if e != nil {
		return out, e
	}
	return out, tx.Commit()
}

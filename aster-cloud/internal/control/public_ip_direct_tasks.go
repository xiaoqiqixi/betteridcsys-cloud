package control

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"database/sql"
	"time"
)

func (c Config) directRequired(node string) bool {
	for _, p := range c.DirectPublicProfiles {
		if p.NodeID == node {
			return true
		}
	}
	return false
}
func (c Config) approvesDirectPublic(b nodeproto.DirectPublicBinding) bool {
	if !b.ValidIdentity() {
		return false
	}
	for _, p := range c.DirectPublicProfiles {
		if p.NodeID == b.NodeID && p.ProfileID == b.ProfileID && p.ProfileSHA256 == b.ProfileSHA256 && p.CIDR == b.CIDR && p.GatewayIPv4 == b.Gateway && directPublicAddressApproved(p, b.IPv4) {
			return true
		}
	}
	return false
}
func bindCreateDirectPublicTx(ctx context.Context, tx *sql.Tx, c Config, t nodeproto.NodeTask, resource string, expected *uint64, now time.Time) (nodeproto.NodeTask, error) {
	if resource == "" {
		if c.directRequired(t.NodeID) && t.Resources.NetworkType == "normal" {
			return t, ErrState
		}
		return t, nil
	}
	if !nodeproto.ValidID(resource) || expected == nil || t.Resources.NetworkType != "normal" {
		return t, ErrInput
	}
	r, e := scanPublicResource(tx.QueryRowContext(ctx, "SELECT "+publicResourceColumns+" FROM controller_public_ip_resources WHERE id=?", resource))
	if e != nil {
		return t, e
	}
	if r.BindingGeneration != *expected {
		return t, ErrState
	}
	if r.Mode != "direct" || r.NodeID != t.NodeID || r.OwnerRef != t.OwnerRef || publicResourceActiveTx(ctx, tx, r) != nil {
		return t, ErrState
	}
	if e = decoratePublicResourceTx(ctx, tx, c, &r); e != nil || r.BindingState != "unbound" || !r.Releasable {
		return t, ErrState
	}
	p, ok := directPublicProfile(c, r.ClusterID, r.NodeID, r.ProfileID)
	if !ok || !directPublicAddressApproved(p, r.Address) {
		return t, ErrState
	}
	t.Protocol = nodeproto.DirectPublicProtocol
	t.DirectPublic = directPublicBinding(r, p, t.InstanceID)
	raw, sha, e := t.BytesAndDigest()
	_ = raw
	if e != nil {
		return t, e
	}
	if e = insertPublicBindingTx(ctx, tx, PublicIPBindingIntent{ID: t.OperationID, ResourceID: r.ID, Action: "direct.create", InstanceID: t.InstanceID, RequestSHA256: sha, Binding: marshalPublicBinding(t.DirectPublic), CreatedAt: now.UTC().Truncate(time.Microsecond)}); e != nil {
		return t, e
	}
	return t, nil
}
func validateDirectTaskTx(ctx context.Context, tx *sql.Tx, t nodeproto.NodeTask, v Instance) error {
	n, e := instanceDirectPublicTx(ctx, tx, v)
	if e != nil {
		return e
	}
	if t.Protocol == nodeproto.DirectPublicProtocol {
		if n.IsZero() || n != t.DirectPublic {
			return ErrState
		}
		r, e := scanPublicResource(tx.QueryRowContext(ctx, "SELECT "+publicResourceColumns+" FROM controller_public_ip_resources WHERE id=?", n.LeaseID))
		if e != nil || r.OwnerRef != v.OwnerRef || r.NodeID != v.NodeID || r.Address != n.IPv4 {
			return ErrState
		}
		if !directCleanupAction(t.Action) {
			if e = directCapabilityTx(ctx, tx, n); e != nil {
				return e
			}
		}
		return publicResourceActiveTx(ctx, tx, r)
	}
	if !n.IsZero() {
		return ErrState
	}
	if t.Action == "start" || t.Action == "reboot" {
		known, e := instanceHadDirectPublicTx(ctx, tx, v.ID)
		if e != nil {
			return e
		}
		if known {
			return ErrState
		}
	}
	return nil
}
func directPublicInstanceGateTx(ctx context.Context, tx *sql.Tx, c Config, v Instance) error {
	n, e := instanceDirectPublicTx(ctx, tx, v)
	if e != nil || n.IsZero() {
		return e
	}
	r, e := scanPublicResource(tx.QueryRowContext(ctx, "SELECT "+publicResourceColumns+" FROM controller_public_ip_resources WHERE id=?", n.LeaseID))
	if e != nil {
		return e
	}
	if e = decoratePublicResourceTx(ctx, tx, c, &r); e != nil {
		return e
	}
	if r.BindingState != "bound" || r.InstanceID != v.ID {
		return ErrState
	}
	return nil
}
func directResourcePlacementTx(ctx context.Context, tx *sql.Tx, c Config, instance, target string) (nodeproto.DirectPublicBinding, error) {
	v, e := scanInstance(tx.QueryRowContext(ctx, "SELECT id,owner_ref,node_id,hostname,state,resources,created_at,updated_at FROM controller_instances WHERE id=?", instance))
	if e != nil {
		return nodeproto.DirectPublicBinding{}, e
	}
	b, e := instanceDirectPublicTx(ctx, tx, v)
	if e != nil || b.IsZero() {
		return b, e
	}
	if e = directPublicInstanceGateTx(ctx, tx, c, v); e != nil {
		return b, e
	}
	r, e := scanPublicResource(tx.QueryRowContext(ctx, "SELECT "+publicResourceColumns+" FROM controller_public_ip_resources WHERE id=?", b.LeaseID))
	if e != nil {
		return b, e
	}
	b.NodeID = target
	if !resourceDirectTargetApproved(c, r, b) {
		return b, ErrState
	}
	return b, nil
}

// Called only after the exact storage/2 activation receipt was validated.
func completeDirectMigrationTx(ctx context.Context, tx *sql.Tx, c Config, o Operation, task nodeproto.TypedStorageTask, now time.Time) error {
	if task.DirectPublic.IsZero() {
		return nil
	}
	b := task.DirectPublic
	if !c.approvesDirectPublic(b) || b.NodeID != o.NodeID || b.InstanceID != o.InstanceID {
		return ErrState
	}
	r, e := scanPublicResource(tx.QueryRowContext(ctx, "SELECT "+publicResourceColumns+" FROM controller_public_ip_resources WHERE id=?", b.LeaseID))
	if e != nil || r.State != "reserved" || r.Mode != "direct" || r.OwnerRef != b.OwnerRef || r.Address != b.IPv4 || r.PoolID != b.PoolID {
		return ErrState
	}
	if e = publicResourceActiveTx(ctx, tx, r); e != nil {
		return e
	}
	if !resourceDirectTargetApproved(c, r, b) {
		return ErrState
	}
	frozen, e := scanPublicBinding(tx.QueryRowContext(ctx, "SELECT "+publicBindingColumns+" FROM controller_public_ip_bindings WHERE id=?", task.SourceOperationID))
	if e != nil || frozen.ResourceID != r.ID || frozen.Generation != r.BindingGeneration || frozen.Action != "direct.migrating" {
		return ErrState
	}
	var source nodeproto.DirectPublicBinding
	if !strictPublicIP(frozen.Binding, &source) || !nodeproto.SameDirectAddress(source, b) || b.Generation != source.Generation+1 {
		return ErrState
	}
	if _, e = tx.ExecContext(ctx, "UPDATE controller_public_ip_resources SET node_id=?,updated_at=? WHERE id=?", b.NodeID, now, r.ID); e != nil {
		return e
	}
	return insertPublicBindingTx(ctx, tx, PublicIPBindingIntent{ID: o.ID, ResourceID: r.ID, Action: "direct.migrate", InstanceID: o.InstanceID, RequestSHA256: o.RequestSHA, Binding: marshalPublicBinding(b), CreatedAt: now})
}

func resourceDirectTargetApproved(c Config, r PublicIPResource, b nodeproto.DirectPublicBinding) bool {
	p, ok := directPublicProfile(c, r.ClusterID, b.NodeID, b.ProfileID)
	return ok && p.ProfileSHA256 == b.ProfileSHA256 && p.CIDR == b.CIDR && p.GatewayIPv4 == b.Gateway && directPublicAddressApproved(p, b.IPv4)
}
func directCapabilityTx(ctx context.Context, tx *sql.Tx, b nodeproto.DirectPublicBinding) error {
	var raw []byte
	if e := tx.QueryRowContext(ctx, "SELECT capabilities FROM controller_nodes WHERE id=?", b.NodeID).Scan(&raw); e != nil {
		return e
	}
	var caps Capability
	if !strict(raw, &caps) || caps.NodeID != b.NodeID || !caps.validNetworkCapabilities() || !directCapabilityMatches(caps, b) {
		return ErrState
	}
	return nil
}

func directCleanupAction(action string) bool {
	return action == "public_detach" || action == "shutdown" || action == "force_off" || action == "delete"
}
func instanceHadDirectPublicTx(ctx context.Context, tx *sql.Tx, instance string) (bool, error) {
	var n int
	e := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM controller_public_ip_bindings WHERE epoch_id='' AND (instance_id=? OR previous_instance_id=?)", instance, instance).Scan(&n)
	return n > 0, e
}

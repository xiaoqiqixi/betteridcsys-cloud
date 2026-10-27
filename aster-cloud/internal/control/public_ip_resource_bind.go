package control

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"database/sql"
	"strings"
	"time"
)

func publicInstanceIdleTx(ctx context.Context, tx *sql.Tx, instance string) error {
	for _, q := range []string{"SELECT COUNT(*) FROM controller_jobs WHERE instance_id=? AND state NOT IN ('succeeded','rejected')", "SELECT COUNT(*) FROM controller_operations WHERE instance_id=? AND state NOT IN ('succeeded','rejected')", "SELECT COUNT(*) FROM controller_migrations WHERE instance_id=? AND phase NOT IN ('active','rejected')"} {
		var n int
		if e := tx.QueryRowContext(ctx, q, instance).Scan(&n); e != nil {
			return e
		}
		if n != 0 {
			return ErrState
		}
	}
	return overlayLifecycleGate(ctx, tx, instance)
}
func (s *SQLStore) BindPublicIPResource(ctx context.Context, c Config, actor, op, resource, instance string, unbind bool, expected uint64, now time.Time) (PublicIPResource, PublicIPResourceOperation, bool, error) {
	return s.BindPublicIPResourceWithIngress(ctx, c, actor, op, resource, instance, unbind, expected, nil, now)
}
func (s *SQLStore) BindPublicIPResourceWithIngress(ctx context.Context, c Config, actor, op, resource, instance string, unbind bool, expected uint64, ingressRevision *uint64, now time.Time) (PublicIPResource, PublicIPResourceOperation, bool, error) {
	if !publicMutationValid(actor, op, now) || !nodeproto.ValidID(resource) || !unbind && !nodeproto.ValidID(instance) || unbind && (instance != "" || ingressRevision != nil) || ingressRevision != nil && *ingressRevision > maxPublicIngressRevision {
		return PublicIPResource{}, PublicIPResourceOperation{}, false, ErrInput
	}
	action := "resource.bind"
	raw := marshalPublicBinding(struct {
		ExpectedGeneration uint64 `json:"expected_generation"`
	}{expected})
	if !unbind {
		raw = marshalPublicBinding(publicResourceBindingInput{InstanceID: instance, ExpectedGeneration: &expected, ExpectedIngressRevision: ingressRevision})
	} else {
		action = "resource.unbind"
	}
	tx, e := s.locked(ctx)
	if e != nil {
		return PublicIPResource{}, PublicIPResourceOperation{}, false, e
	}
	defer tx.Rollback()
	o, replay, e := publicResourceReplay(ctx, tx, actor, op, action, resource, raw)
	if e != nil {
		return PublicIPResource{}, o, false, e
	}
	if replay {
		return o.Result.Resource, o, true, nil
	}
	r, e := scanPublicResource(tx.QueryRowContext(ctx, "SELECT "+publicResourceColumns+" FROM controller_public_ip_resources WHERE id=?", resource))
	if e != nil {
		return r, o, false, e
	}
	if ingressRevision != nil && r.Mode != "floating" {
		return r, o, false, ErrInput
	}
	if r.BindingGeneration != expected || expected >= 1<<63-1 {
		return r, o, false, ErrState
	}
	if e = publicResourceActiveTx(ctx, tx, r); e != nil {
		return r, o, false, e
	}
	if e = decoratePublicResourceTx(ctx, tx, c, &r); e != nil {
		return r, o, false, e
	}
	previous := r.InstanceID
	if r.BindingState != "unbound" && r.BindingState != "bound" || unbind && r.BindingState != "bound" || !unbind && r.Mode == "direct" && r.BindingState != "unbound" || !unbind && instance == previous {
		return r, o, false, ErrState
	}
	if previous != "" {
		if e = publicInstanceIdleTx(ctx, tx, previous); e != nil {
			return r, o, false, e
		}
	}
	target := instance
	if unbind {
		target = previous
	}
	v, e := scanInstance(tx.QueryRowContext(ctx, "SELECT id,owner_ref,node_id,hostname,state,resources,created_at,updated_at FROM controller_instances WHERE id=?", target))
	if e != nil {
		return r, o, false, e
	}
	if v.OwnerRef != r.OwnerRef || v.State != "running" && v.State != "shutoff" && v.State != "created" {
		return r, o, false, ErrState
	}
	if e = publicInstanceIdleTx(ctx, tx, target); e != nil {
		return r, o, false, e
	}
	now = now.UTC().Truncate(time.Microsecond)
	if r.Mode == "floating" {
		e = bindFloatingResourceTx(ctx, tx, c, actor, op, &r, v, previous, unbind, ingressRevision, now)
	} else {
		e = s.bindDirectResourceTx(ctx, tx, c, actor, op, &r, v, previous, unbind, now)
	}
	if e != nil {
		return r, o, false, e
	}
	r.BindingGeneration++
	r.OperationID = op
	r.BindingState = "pending"
	r.Releasable = false
	r.ReleaseReason = "NETWORK_OPERATION_PENDING"
	r.InstanceID = instance
	r.UpdatedAt = now
	if _, e = tx.ExecContext(ctx, "UPDATE controller_public_ip_resources SET updated_at=? WHERE id=?", now, r.ID); e != nil {
		return r, o, false, e
	}
	o, e = insertPublicResourceOperation(ctx, tx, actor, op, action, r.ID, r, raw, now)
	if e != nil {
		return r, o, false, e
	}
	return r, o, false, tx.Commit()
}
func (s *SQLStore) bindDirectResourceTx(ctx context.Context, tx *sql.Tx, c Config, actor, op string, r *PublicIPResource, v Instance, previous string, unbind bool, now time.Time) error {
	p, ok := directPublicProfile(c, r.ClusterID, r.NodeID, r.ProfileID)
	if v.NodeID != r.NodeID || v.Resources.NetworkType != "normal" || !unbind && (!ok || !directPublicAddressApproved(p, r.Address)) {
		return ErrState
	}
	t := nodeproto.NodeTask{Protocol: nodeproto.DirectPublicProtocol, OperationID: op, NodeID: v.NodeID, Action: "public_adopt", InstanceID: v.ID, OwnerRef: v.OwnerRef, Hostname: v.Hostname, Resources: v.Resources, ConfirmInstanceID: v.ID, DirectPublic: directPublicBinding(*r, p, v.ID)}
	bAction := "direct.bind"
	bindingInstance := v.ID
	if unbind {
		if v.State != "shutoff" {
			return ErrState
		}
		prior, e := instanceDirectPublicTx(ctx, tx, v)
		if e != nil || prior.IsZero() || prior.LeaseID != r.ID {
			return ErrState
		}
		t.DirectPublic = prior
		t.Action = "public_detach"
		bAction = "direct.unbind"
		bindingInstance = ""
	} else {
		if v.State != "shutoff" {
			return ErrState
		}
		var err error
		t.DirectPublic, err = directAdoptionIdentityTx(ctx, tx, v, *r, t.DirectPublic)
		if err != nil {
			return err
		}
		existing, e := instanceDirectPublicTx(ctx, tx, v)
		if e != nil || !existing.IsZero() {
			return ErrState
		}
		// The immutable adopt task performs exact live IP/MAC proof at dispatch.
		// Planning never makes a network RPC while holding controller_lock.
	}
	raw, sha, e := t.BytesAndDigest()
	if e != nil {
		return ErrInput
	}
	o := Operation{ID: op, ActorID: actor, InstanceID: v.ID, NodeID: v.NodeID, Action: t.Action, Protocol: t.Protocol, State: "accepted", ProfileSHA: mustNode(c, v.NodeID).Digest(), IntentSHA: sha, Request: raw, RequestSHA: sha, CreatedAt: now, UpdatedAt: now}
	_, e = tx.ExecContext(ctx, "INSERT INTO controller_operations("+strings.TrimSuffix(operationColumns, ",seq")+") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", o.ID, o.ActorID, o.InstanceID, o.NodeID, o.ProfileSHA, o.Action, o.ArtifactID, o.TargetNodeID, o.IntentSHA, o.Protocol, o.Request, o.RequestSHA, o.State, now, now)
	if e != nil {
		return e
	}
	return insertPublicBindingTx(ctx, tx, PublicIPBindingIntent{ID: op, ResourceID: r.ID, Action: bAction, InstanceID: bindingInstance, PreviousInstanceID: previous, RequestSHA256: sha, Binding: marshalPublicBinding(t.DirectPublic), CreatedAt: now})
}
func mustNode(c Config, id string) NodeProfile { p, _ := c.Node(id); return p }

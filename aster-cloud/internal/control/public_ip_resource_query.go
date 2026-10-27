package control

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

// Every read is a coherent database snapshot; unknown evidence never becomes free.
func (s *SQLStore) PublicIPResource(ctx context.Context, c Config, id string) (PublicIPResource, error) {
	if !nodeproto.ValidID(id) {
		return PublicIPResource{}, ErrInput
	}
	tx, e := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return PublicIPResource{}, e
	}
	defer tx.Rollback()
	r, e := scanPublicResource(tx.QueryRowContext(ctx, "SELECT "+publicResourceColumns+" FROM controller_public_ip_resources WHERE id=?", id))
	if e != nil {
		return r, e
	}
	if e = decoratePublicResourceTx(ctx, tx, c, &r); e != nil {
		return r, e
	}
	return r, tx.Commit()
}
func (s *SQLStore) PublicIPResources(ctx context.Context, c Config, cluster, pool, cursor string) ([]PublicIPResource, string, error) {
	return s.PublicIPResourcesFor(ctx, c, cluster, pool, "", "", cursor)
}
func (s *SQLStore) PublicIPResourcesFor(ctx context.Context, c Config, cluster, pool, owner, instance, cursor string) ([]PublicIPResource, string, error) {
	if owner != "" && !nodeproto.ValidID(owner) || instance != "" && !nodeproto.ValidID(instance) || cluster != "" && !nodeproto.ValidNodeID(cluster) || pool != "" && !nodeproto.ValidID(pool) || cursor != "" && !nodeproto.ValidID(cursor) {
		return nil, "", ErrInput
	}
	tx, e := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return nil, "", e
	}
	defer tx.Rollback()
	q := "SELECT " + publicResourceColumns + " FROM controller_public_ip_resources WHERE id>?"
	args := []any{cursor}
	if cluster != "" {
		q += " AND cluster_id=?"
		args = append(args, cluster)
	}
	if pool != "" {
		q += " AND pool_id=?"
		args = append(args, pool)
	}
	if owner != "" {
		q += " AND owner_ref=?"
		args = append(args, owner)
	}
	if instance != "" {
		q += " AND EXISTS (SELECT 1 FROM controller_public_ip_bindings b WHERE b.resource_id=controller_public_ip_resources.id AND (b.instance_id=? OR b.previous_instance_id=?) AND NOT EXISTS (SELECT 1 FROM controller_public_ip_bindings newer WHERE newer.resource_id=b.resource_id AND newer.revision>b.revision))"
		args = append(args, instance, instance)
	}
	q += " ORDER BY id LIMIT 101"
	rows, e := tx.QueryContext(ctx, q, args...)
	if e != nil {
		return nil, "", e
	}
	items := []PublicIPResource{}
	for rows.Next() {
		r, x := scanPublicResource(rows)
		if x != nil {
			rows.Close()
			return nil, "", x
		}
		items = append(items, r)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, "", e
	}
	for i := range items {
		if e = decoratePublicResourceTx(ctx, tx, c, &items[i]); e != nil {
			return nil, "", e
		}
	}
	items, next, e := publicIPBudgetPage(items, func(r PublicIPResource) string { return r.ID })
	if e != nil {
		return nil, "", e
	}
	return items, next, tx.Commit()
}
func (s *SQLStore) PublicIPResourceOperation(ctx context.Context, actor, id string) (PublicIPResourceOperation, error) {
	if !nodeproto.ValidID(actor) || !nodeproto.ValidID(id) {
		return PublicIPResourceOperation{}, ErrInput
	}
	return scanPublicResourceOperation(s.DB.QueryRowContext(ctx, "SELECT "+publicResourceOperationColumns+" FROM controller_public_ip_resource_operations WHERE id=? AND actor_id=?", id, actor))
}
func (s *SQLStore) PublicIPResourceOperations(ctx context.Context, actor, cursor string) ([]PublicIPResourceOperation, string, error) {
	if !nodeproto.ValidID(actor) || cursor != "" && !nodeproto.ValidID(cursor) {
		return nil, "", ErrInput
	}
	rows, e := s.DB.QueryContext(ctx, "SELECT "+publicResourceOperationColumns+" FROM controller_public_ip_resource_operations WHERE actor_id=? AND id>? ORDER BY id LIMIT 101", actor, cursor)
	if e != nil {
		return nil, "", e
	}
	defer rows.Close()
	items := []PublicIPResourceOperation{}
	for rows.Next() {
		o, e := scanPublicResourceOperation(rows)
		if e != nil {
			return nil, "", e
		}
		items = append(items, o)
	}
	if e = rows.Err(); e != nil {
		return nil, "", e
	}
	return publicIPBudgetPage(items, func(o PublicIPResourceOperation) string { return o.ID })
}
func decoratePublicResourceTx(ctx context.Context, tx *sql.Tx, c Config, r *PublicIPResource) error {
	r.InstanceID = ""
	r.EpochID = ""
	r.OperationID = ""
	r.Releasable = false
	r.ReleaseReason = ""
	if r.State == "released" {
		r.BindingState = "released"
		return nil
	}
	if e := publicResourceActiveTx(ctx, tx, *r); e != nil {
		r.BindingState = "blocked"
		r.ReleaseReason = "PUBLIC_IP_CLAIM_UNCONFIRMED"
		return nil
	}
	b, e := latestPublicBindingTx(ctx, tx, r.ID)
	if errors.Is(e, ErrNotFound) {
		if e = publicAddressDetachedTx(ctx, tx, c, r.Address); e != nil {
			r.BindingState = "blocked"
			r.ReleaseReason = "NETWORK_RELEASE_UNCONFIRMED"
		} else {
			r.BindingState = "unbound"
			r.Releasable = true
		}
		return nil
	}
	if e != nil {
		return e
	}
	r.InstanceID = b.InstanceID
	r.EpochID = b.EpochID
	r.OperationID = b.ID
	r.BindingState = "pending"
	r.ReleaseReason = "NETWORK_OPERATION_PENDING"
	if b.Action == "direct.migrating" {
		prepare, e := scanOperation(tx.QueryRowContext(ctx, "SELECT "+operationColumns+" FROM controller_operations WHERE id=?", b.ID))
		if e != nil {
			return e
		}
		if prepare.RequestSHA != b.RequestSHA256 || b.Generation != r.BindingGeneration {
			return ErrState
		}
		if prepare.State == "rejected" {
			r.BindingState = "bound"
			r.ReleaseReason = "VM_PUBLIC_IP_BOUND"
		} else {
			r.BindingState = "pending"
			r.ReleaseReason = "INSTANCE_MIGRATION_PENDING"
		}
		return nil
	}
	if b.EpochID != "" {
		return decorateFloatingResourceTx(ctx, tx, c, r, b)
	}
	o, e := scanOperation(tx.QueryRowContext(ctx, "SELECT "+operationColumns+" FROM controller_operations WHERE id=?", b.ID))
	if e != nil {
		return e
	}
	if o.RequestSHA != b.RequestSHA256 || o.InstanceID != b.InstanceID && o.InstanceID != b.PreviousInstanceID {
		return ErrState
	}
	task, e := nodeproto.DecodeTask(o.Request)
	if b.Action == "direct.migrate" {
		stored, x := nodeproto.DecodeStorageTask(o.Request)
		if x != nil || stored.Protocol != nodeproto.StorageDirectProtocol || stored.Action != "migrate_activate" || o.State != "succeeded" {
			return ErrState
		}
		task = nodeproto.NodeTask{Protocol: nodeproto.DirectPublicProtocol, DirectPublic: stored.DirectPublic, OwnerRef: stored.OwnerRef}
		e = nil
	}
	if e != nil || task.Protocol != nodeproto.DirectPublicProtocol || task.DirectPublic.LeaseID != r.ID || task.DirectPublic.IPv4 != r.Address || task.OwnerRef != r.OwnerRef {
		return ErrState
	}
	if o.State == "rejected" && (b.Action == "direct.create" || b.Action == "direct.bind") {
		r.InstanceID = ""
		r.BindingState = "unbound"
		r.Releasable = true
		r.ReleaseReason = ""
		return nil
	}
	if o.State != "succeeded" {
		if o.State != "accepted" {
			r.BindingState = "blocked"
			r.ReleaseReason = "NODE_OPERATION_UNCONFIRMED"
		}
		return nil
	}
	if b.Action == "direct.unbind" {
		r.InstanceID = ""
		r.BindingState = "unbound"
		r.Releasable = true
		r.ReleaseReason = ""
		return nil
	}
	v, e := scanInstance(tx.QueryRowContext(ctx, "SELECT id,owner_ref,node_id,hostname,state,resources,created_at,updated_at FROM controller_instances WHERE id=?", b.InstanceID))
	if e != nil {
		return e
	}
	if v.OwnerRef != r.OwnerRef {
		return ErrState
	}
	if v.State == "deleted" {
		// Only a complete exact node/3 delete receipt permits the old address to return.
		rows, e := tx.QueryContext(ctx, "SELECT "+operationColumns+" FROM controller_operations WHERE instance_id=? AND action='delete' AND state='succeeded' ORDER BY seq DESC", v.ID)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			deleted, e := scanOperation(rows)
			if e != nil {
				return e
			}
			t, e := nodeproto.DecodeTask(deleted.Request)
			if e == nil && t.Protocol == nodeproto.DirectPublicProtocol && t.DirectPublic == task.DirectPublic {
				r.InstanceID = ""
				r.BindingState = "unbound"
				r.Releasable = true
				r.ReleaseReason = ""
				return nil
			}
		}
		if e = rows.Err(); e != nil {
			return e
		}
		r.BindingState = "blocked"
		r.ReleaseReason = "NODE_DELETE_UNCONFIRMED"
		return nil
	}
	r.BindingState = "bound"
	r.ReleaseReason = "VM_PUBLIC_IP_BOUND"
	return nil
}

// A direct binding is reconstructed only from its original immutable node task.
func instanceDirectPublicTx(ctx context.Context, tx *sql.Tx, v Instance) (nodeproto.DirectPublicBinding, error) {
	rows, e := tx.QueryContext(ctx, "SELECT "+publicResourceColumns+" FROM controller_public_ip_resources WHERE owner_ref=? AND mode='direct' AND state='reserved' ORDER BY id", v.OwnerRef)
	if e != nil {
		return nodeproto.DirectPublicBinding{}, e
	}
	resources := []PublicIPResource{}
	for rows.Next() {
		r, e := scanPublicResource(rows)
		if e != nil {
			rows.Close()
			return nodeproto.DirectPublicBinding{}, e
		}
		resources = append(resources, r)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nodeproto.DirectPublicBinding{}, e
	}
	var result nodeproto.DirectPublicBinding
	for _, r := range resources {
		b, e := latestPublicBindingTx(ctx, tx, r.ID)
		if errors.Is(e, ErrNotFound) {
			continue
		}
		if e != nil {
			return result, e
		}
		if b.EpochID != "" || b.InstanceID != v.ID && b.PreviousInstanceID != v.ID {
			continue
		}
		var n nodeproto.DirectPublicBinding
		if !strictPublicIP(b.Binding, &n) || !n.ValidIdentity() || n.LeaseID != r.ID || n.PoolID != r.PoolID || n.IPv4 != r.Address || n.OwnerRef != v.OwnerRef || n.InstanceID != v.ID {
			return result, ErrState
		}
		if b.Action == "direct.bind" || b.Action == "direct.create" {
			o, e := scanOperation(tx.QueryRowContext(ctx, "SELECT "+operationColumns+" FROM controller_operations WHERE id=?", b.ID))
			if e != nil {
				return result, e
			}
			if o.State == "rejected" {
				continue
			}
		}
		if b.Action == "direct.unbind" {
			o, e := scanOperation(tx.QueryRowContext(ctx, "SELECT "+operationColumns+" FROM controller_operations WHERE id=?", b.ID))
			if e != nil {
				return result, e
			}
			if o.State == "succeeded" {
				continue
			}
		}
		if !result.IsZero() {
			return result, ErrState
		}
		result = n
	}
	return result, nil
}
func insertPublicBindingTx(ctx context.Context, tx *sql.Tx, b PublicIPBindingIntent) error {
	var revision int64
	if e := tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(revision),0) FROM controller_public_ip_bindings WHERE resource_id=?", b.ResourceID).Scan(&revision); e != nil {
		return e
	}
	var generation uint64
	if e := tx.QueryRowContext(ctx, "SELECT binding_generation FROM controller_public_ip_resources WHERE id=?", b.ResourceID).Scan(&generation); e != nil {
		return e
	}
	oldGeneration := generation
	if b.Action != "direct.migrate" {
		generation++
	}
	if generation >= 1<<63 || revision == int64(^uint64(0)>>1) {
		return ErrState
	}
	b.Revision = revision + 1
	b.Generation = generation
	_, e := tx.ExecContext(ctx, "INSERT INTO controller_public_ip_bindings("+publicBindingColumns+") VALUES(?,?,?,?,?,?,?,?,?,?,?)", b.ID, b.ResourceID, b.Revision, b.Generation, b.Action, b.InstanceID, b.PreviousInstanceID, b.EpochID, b.RequestSHA256, []byte(b.Binding), b.CreatedAt)
	if e != nil {
		return e
	}
	if generation == oldGeneration {
		return nil
	}
	result, e := tx.ExecContext(ctx, "UPDATE controller_public_ip_resources SET binding_generation=? WHERE id=? AND binding_generation=?", generation, b.ResourceID, oldGeneration)
	if e != nil {
		return e
	}
	n, e := result.RowsAffected()
	if e != nil || n != 1 {
		return ErrState
	}
	return nil
}
func directPublicBinding(r PublicIPResource, p DirectPublicProfile, instance string) nodeproto.DirectPublicBinding {
	return nodeproto.DirectPublicBinding{Schema: 1, LeaseID: r.ID, PoolID: r.PoolID, NodeID: r.NodeID, OwnerRef: r.OwnerRef, InstanceID: instance, ProfileID: p.ProfileID, ProfileSHA256: p.ProfileSHA256, CIDR: p.CIDR, Gateway: p.GatewayIPv4, IPv4: r.Address, MAC: nodeproto.NetworkMAC(r.NodeID, instance), Generation: int64(r.BindingGeneration + 1)}
}
func marshalPublicBinding(v any) json.RawMessage { raw, _ := json.Marshal(v); return raw }

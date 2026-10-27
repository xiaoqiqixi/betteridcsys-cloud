package control

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"database/sql"
)

func (s *SQLStore) PublicIPPool(ctx context.Context, id string) (PublicIPPool, error) {
	if !nodeproto.ValidID(id) {
		return PublicIPPool{}, ErrInput
	}
	return scanPublicPool(s.DB.QueryRowContext(ctx, "SELECT "+publicPoolColumns+" FROM controller_public_ip_pools WHERE id=?", id))
}
func (s *SQLStore) PublicIPPools(ctx context.Context, cluster, cursor string) ([]PublicIPPool, string, error) {
	if cluster != "" && !nodeproto.ValidNodeID(cluster) || cursor != "" && !nodeproto.ValidID(cursor) {
		return nil, "", ErrInput
	}
	q := "SELECT " + publicPoolColumns + " FROM controller_public_ip_pools WHERE id>?"
	args := []any{cursor}
	if cluster != "" {
		q += " AND cluster_id=?"
		args = append(args, cluster)
	}
	q += " ORDER BY id LIMIT 101"
	rows, e := s.DB.QueryContext(ctx, q, args...)
	if e != nil {
		return nil, "", e
	}
	defer rows.Close()
	items := []PublicIPPool{}
	for rows.Next() {
		v, err := scanPublicPool(rows)
		if err != nil {
			return nil, "", err
		}
		items = append(items, v)
	}
	if e = rows.Err(); e != nil {
		return nil, "", e
	}
	return publicIPBudgetPage(items, func(v PublicIPPool) string { return v.ID })
}
func (s *SQLStore) PublicIPLease(ctx context.Context, c Config, id string) (PublicIPLease, error) {
	if !nodeproto.ValidID(id) {
		return PublicIPLease{}, ErrInput
	}
	tx, e := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return PublicIPLease{}, e
	}
	defer tx.Rollback()
	v, e := scanPublicLease(tx.QueryRowContext(ctx, "SELECT "+publicLeaseColumns+" FROM controller_public_ip_leases WHERE id=?", id))
	if e != nil {
		return v, e
	}
	decoratePublicIPLeaseTx(ctx, tx, c, &v)
	return v, tx.Commit()
}
func publicIPLeasesTx(ctx context.Context, tx *sql.Tx, c Config, cluster, pool, cursor string, onlyReserved bool, limit int) ([]PublicIPLease, error) {
	q := "SELECT " + publicLeaseColumns + " FROM controller_public_ip_leases WHERE id>?"
	args := []any{cursor}
	if cluster != "" {
		q += " AND cluster_id=?"
		args = append(args, cluster)
	}
	if pool != "" {
		q += " AND pool_id=?"
		args = append(args, pool)
	}
	if onlyReserved {
		q += " AND state='reserved'"
	}
	q += " ORDER BY id LIMIT ?"
	args = append(args, limit)
	rows, e := tx.QueryContext(ctx, q, args...)
	if e != nil {
		return nil, e
	}
	items := []PublicIPLease{}
	for rows.Next() {
		v, err := scanPublicLease(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		items = append(items, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	if e = decoratePublicIPLeasesTx(ctx, tx, c, items); e != nil {
		return nil, e
	}
	return items, nil
}
func (s *SQLStore) PublicIPLeases(ctx context.Context, c Config, cluster, pool, cursor string) ([]PublicIPLease, string, error) {
	if cluster != "" && !nodeproto.ValidNodeID(cluster) || pool != "" && !nodeproto.ValidID(pool) || cursor != "" && !nodeproto.ValidID(cursor) {
		return nil, "", ErrInput
	}
	tx, e := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return nil, "", e
	}
	defer tx.Rollback()
	items, e := publicIPLeasesTx(ctx, tx, c, cluster, pool, cursor, false, 101)
	if e != nil {
		return nil, "", e
	}
	items, next, e := publicIPBudgetPage(items, func(v PublicIPLease) string { return v.ID })
	if e != nil {
		return nil, "", e
	}
	return items, next, tx.Commit()
}
func (s *SQLStore) PublicIPOperation(ctx context.Context, actor, id string) (PublicIPOperation, error) {
	if !nodeproto.ValidID(actor) || !nodeproto.ValidID(id) {
		return PublicIPOperation{}, ErrInput
	}
	v, e := scanPublicOperation(s.DB.QueryRowContext(ctx, "SELECT "+publicOperationColumns+" FROM controller_public_ip_operations WHERE id=? AND actor_id=?", id, actor))
	return v, e
}
func (s *SQLStore) PublicIPOperations(ctx context.Context, actor, cursor string) ([]PublicIPOperation, string, error) {
	if !nodeproto.ValidID(actor) || cursor != "" && !nodeproto.ValidID(cursor) {
		return nil, "", ErrInput
	}
	rows, e := s.DB.QueryContext(ctx, "SELECT "+publicOperationColumns+" FROM controller_public_ip_operations WHERE actor_id=? AND id>? ORDER BY id LIMIT 101", actor, cursor)
	if e != nil {
		return nil, "", e
	}
	defer rows.Close()
	items := []PublicIPOperation{}
	for rows.Next() {
		v, err := scanPublicOperation(rows)
		if err != nil {
			return nil, "", err
		}
		items = append(items, v)
	}
	if e = rows.Err(); e != nil {
		return nil, "", e
	}
	return publicIPBudgetPage(items, func(v PublicIPOperation) string { return v.ID })
}
func (s *SQLStore) PublicIPOptions(ctx context.Context, c Config) (PublicIPOptions, error) {
	out := PublicIPOptions{DirectApprovals: append([]DirectPublicProfile{}, c.DirectPublicProfiles...), Clusters: []PublicIPClusterOption{}, Approvals: []PublicIPApproval{}, VPCs: []OverlayVPC{}, Complete: true}
	if !c.validOverlayClusters() || !c.validDirectPublicProfiles() {
		return out, ErrState
	}
	tx, e := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	seenClusters := map[string]bool{}
	for _, p := range c.DirectPublicProfiles {
		if !seenClusters[p.ClusterID] {
			out.Clusters = append(out.Clusters, PublicIPClusterOption{p.ClusterID})
			seenClusters[p.ClusterID] = true
		}
	}
	for _, cluster := range c.OverlayClusters {
		if !seenClusters[cluster.ClusterID] {
			seenClusters[cluster.ClusterID] = true
			out.Clusters = append(out.Clusters, PublicIPClusterOption{cluster.ClusterID})
		}
		for _, p := range cluster.NATProfiles {
			addresses := []string{}
			if approvedPublicIPAddress(p, p.PublicIPv4) {
				addresses = append(addresses, p.PublicIPv4)
			}
			addresses = append(addresses, p.PublicIPv4s...)
			owner := ""
			for _, g := range cluster.Gateways {
				if g.VPCID == p.VPCID && g.InstanceID == p.GatewayInstanceID && g.NodeID == p.NodeID {
					owner = g.OwnerRef
				}
			}
			if owner == "" {
				return out, ErrState
			}
			out.Approvals = append(out.Approvals, PublicIPApproval{cluster.ClusterID, p.NodeID, p.VPCID, owner, p.ProfileID, p.ProfileSHA256, addresses, p.AllowInternetEgress, p.AllowFloatingIP})
		}
		rows, err := tx.QueryContext(ctx, "SELECT "+overlayVPCColumns+" FROM controller_overlay_vpcs WHERE cluster_id=? ORDER BY id LIMIT 33", cluster.ClusterID)
		if err != nil {
			return out, err
		}
		count := 0
		for rows.Next() {
			v, x := scanOverlayVPC(rows)
			if x != nil {
				rows.Close()
				return out, x
			}
			out.VPCs = append(out.VPCs, v)
			count++
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return out, err
		}
		if count > 32 {
			return out, ErrCapacity
		}
	}
	out.ResourceTargets, e = publicResourceTargetsTx(ctx, tx, c)
	if e != nil {
		return out, e
	}
	if !publicIPProjectionFits(out) {
		return out, ErrCapacity
	}
	return out, tx.Commit()
}

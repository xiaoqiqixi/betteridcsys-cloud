package control

import (
	"context"
	"database/sql"
)

type publicIPClusterProof struct {
	latest         OverlayEpoch
	references     map[string]bool
	unknownHistory bool
	current        map[string]bool
	unknownCurrent bool
	checked        bool
	releaseError   error
}
type publicIPReleaseProof struct {
	clusters map[string]*publicIPClusterProof
}

// The complete immutable history is read once per transaction. No fixed epoch
// count truncation is permitted; callers reuse this proof across all leases.
func readPublicIPReleaseProofTx(ctx context.Context, tx *sql.Tx, c Config) (*publicIPReleaseProof, error) {
	rows, err := tx.QueryContext(ctx, "SELECT "+overlayEpochColumns+" FROM controller_overlay_epochs ORDER BY cluster_id,epoch")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	proof := &publicIPReleaseProof{clusters: map[string]*publicIPClusterProof{}}
	for rows.Next() {
		e, x := scanOverlayEpoch(rows)
		if x != nil {
			return nil, x
		}
		entry := proof.clusters[e.ClusterID]
		if entry == nil {
			entry = &publicIPClusterProof{references: map[string]bool{}}
			proof.clusters[e.ClusterID] = entry
		}
		entry.latest = e
		entry.current = map[string]bool{}
		entry.unknownCurrent = false
		for _, f := range e.Snapshot.FloatingIPs {
			entry.references[f.PublicIPv4] = true
			entry.current[f.PublicIPv4] = true
		}
		for _, p := range e.Snapshot.NATPolicies {
			address, known := publicEpochAddress(c, e, p)
			if known {
				entry.references[address] = true
				entry.current[address] = true
			} else {
				entry.unknownHistory = true
				entry.unknownCurrent = true
			}
		}
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return proof, nil
}
func (p *publicIPReleaseProof) detached(ctx context.Context, tx *sql.Tx, address, exceptCluster string) error {
	for cluster, entry := range p.clusters {
		if cluster == exceptCluster || !entry.unknownHistory && !entry.references[address] {
			continue
		}
		if !entry.checked {
			entry.releaseError = publicReleaseCompleteTx(ctx, tx, entry.latest)
			entry.checked = true
		}
		if entry.releaseError != nil {
			return entry.releaseError
		}
		if entry.unknownCurrent || entry.current[address] {
			return ErrState
		}
	}
	return nil
}
func (p *publicIPReleaseProof) decorate(ctx context.Context, tx *sql.Tx, c Config, v *PublicIPLease, safe bool) {
	if v.State == "released" {
		v.BindingState = "released"
		v.Releasable = false
		v.ReleaseReason = ""
		return
	}
	v.BindingState = "reserved"
	v.Releasable = safe
	v.ReleaseReason = ""
	if safe {
		return
	}
	v.BindingState = "release_blocked"
	v.ReleaseReason = "NETWORK_RELEASE_UNCONFIRMED"
	entry := p.clusters[v.ClusterID]
	if entry == nil {
		return
	}
	for _, policy := range entry.latest.Snapshot.NATPolicies {
		address, known := publicEpochAddress(c, entry.latest, policy)
		if known && address == v.Address && policy.NodeID == v.NodeID && policy.VPCID == v.VPCID && policy.ProfileID == v.ProfileID {
			if !entry.checked {
				entry.releaseError = publicReleaseCompleteTx(ctx, tx, entry.latest)
				entry.checked = true
			}
			if entry.releaseError == nil {
				v.BindingState = "bound"
				v.ReleaseReason = "NAT_ADDRESS_BOUND"
			} else {
				v.BindingState = "pending"
				v.ReleaseReason = "NETWORK_OPERATION_PENDING"
			}
		}
	}
}
func decoratePublicIPLeasesTx(ctx context.Context, tx *sql.Tx, c Config, items []PublicIPLease) error {
	if len(items) == 0 {
		return nil
	}
	proof, err := readPublicIPReleaseProofTx(ctx, tx, c)
	if err != nil {
		return err
	}
	inventory := map[string]string{}
	active := map[string]string{}
	poolAddresses := map[string]map[string]bool{}
	poolClusters := map[string]string{}
	rows, err := tx.QueryContext(ctx, "SELECT address,pool_id FROM controller_public_ip_inventory ORDER BY address")
	if err != nil {
		return err
	}
	for rows.Next() {
		var a, p string
		if err = rows.Scan(&a, &p); err != nil {
			rows.Close()
			return err
		}
		inventory[a] = p
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	rows, err = tx.QueryContext(ctx, "SELECT address,lease_id FROM controller_public_ip_active ORDER BY address")
	if err != nil {
		return err
	}
	for rows.Next() {
		var a, l string
		if err = rows.Scan(&a, &l); err != nil {
			rows.Close()
			return err
		}
		active[a] = l
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	rows, err = tx.QueryContext(ctx, "SELECT "+publicPoolColumns+" FROM controller_public_ip_pools ORDER BY id")
	if err != nil {
		return err
	}
	for rows.Next() {
		pool, x := scanPublicPool(rows)
		if x != nil {
			rows.Close()
			return x
		}
		poolClusters[pool.ID] = pool.ClusterID
		addresses := map[string]bool{}
		for _, a := range pool.Addresses {
			addresses[a] = true
		}
		poolAddresses[pool.ID] = addresses
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for i := range items {
		v := &items[i]
		safe := v.State == "reserved" && inventory[v.Address] == v.PoolID && active[v.Address] == v.ID && poolClusters[v.PoolID] == v.ClusterID && poolAddresses[v.PoolID][v.Address] && proof.detached(ctx, tx, v.Address, "") == nil
		proof.decorate(ctx, tx, c, v, safe)
	}
	return nil
}

// The active index is a claim, not a substitute for history. An accidentally
// missing/recreated or orphaned active row must not free a reserved historical
// lease for allocation; reject corruption instead of repairing it by guessing.
func publicIPActiveMapTx(ctx context.Context, tx *sql.Tx) (map[string]string, error) {
	active := map[string]string{}
	rows, err := tx.QueryContext(ctx, "SELECT address,lease_id FROM controller_public_ip_active ORDER BY address")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var a, l string
		if err = rows.Scan(&a, &l); err != nil {
			rows.Close()
			return nil, err
		}
		active[a] = l
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	rows, err = tx.QueryContext(ctx, "SELECT address,id FROM controller_public_ip_leases WHERE state='reserved' UNION ALL SELECT address,id FROM controller_public_ip_resources WHERE state='reserved' ORDER BY address,id")
	if err != nil {
		return nil, err
	}
	count := 0
	seen := map[string]bool{}
	for rows.Next() {
		var a, l string
		if err = rows.Scan(&a, &l); err != nil {
			rows.Close()
			return nil, err
		}
		if active[a] != l || seen[a] {
			rows.Close()
			return nil, ErrState
		}
		seen[a] = true
		count++
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if count != len(active) {
		return nil, ErrState
	}
	return active, nil
}

package control

import (
	"aster/cloud/internal/overlayproto"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// publicEpochAddress returns a conservative reference. Old default selections
// are resolved only through the exact current root NAT pin. A historical pin
// that is no longer reconstructible is unknown, never an invented free IP.
func publicEpochAddress(c Config, e OverlayEpoch, p overlayproto.NATPolicy) (string, bool) {
	if p.PublicIPv4 != "" {
		return p.PublicIPv4, true
	}
	cluster, ok := c.OverlayCluster(e.ClusterID)
	if !ok {
		return "", false
	}
	for _, root := range cluster.NATProfiles {
		if root.NodeID == p.NodeID && root.VPCID == p.VPCID && root.ProfileID == p.ProfileID && root.ProfileSHA256 == p.ProfileSHA256 {
			return root.PublicIPv4, true
		}
	}
	return "", false
}
func publicReleaseCompleteTx(ctx context.Context, tx *sql.Tx, e OverlayEpoch) error {
	if e.State != "succeeded" || e.Phase != "release" {
		return ErrState
	}
	rows, err := tx.QueryContext(ctx, "SELECT "+overlayTaskColumns+" FROM controller_overlay_tasks WHERE epoch_id=? ORDER BY phase,node_id", e.ID)
	if err != nil {
		return err
	}
	tasks := []OverlayNodeTask{}
	for rows.Next() {
		task, x := scanOverlayTask(rows)
		if x != nil {
			rows.Close()
			return x
		}
		tasks = append(tasks, task)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(tasks) != 3*len(e.Snapshot.Profiles) {
		return ErrState
	}
	seen := map[string]bool{}
	for _, task := range tasks {
		if task.State != "succeeded" || task.Result == nil {
			return ErrState
		}
		wire := overlayTask(e, task.NodeID, task.Phase)
		_, want, x := wire.BytesAndDigest()
		if x != nil || task.RequestSHA256 != want || task.Result.SnapshotSHA256 != e.SnapshotSHA256 || task.Result.Epoch != e.Epoch || task.Result.ClusterID != e.ClusterID {
			return ErrState
		}
		found := false
		for _, p := range e.Snapshot.Profiles {
			if p.NodeID == task.NodeID {
				found = true
			}
		}
		key := task.NodeID + ":" + task.Phase
		if !found || seen[key] {
			return ErrState
		}
		seen[key] = true
	}
	return nil
}

// A later complete fencing/release epoch proves older (including rejected or
// unknown) intents detached. Merely seeing an absent address in a pending or
// superseding snapshot does not. There is no 64-epoch history scan limit.
func publicAddressDetachedExceptTx(ctx context.Context, tx *sql.Tx, c Config, address, exceptCluster string) error {
	proof, err := readPublicIPReleaseProofTx(ctx, tx, c)
	if err != nil {
		return err
	}
	return proof.detached(ctx, tx, address, exceptCluster)
}

func publicAddressDetachedTx(ctx context.Context, tx *sql.Tx, c Config, address string) error {
	return publicAddressDetachedExceptTx(ctx, tx, c, address, "")
}
func PublicIPSafeToReleaseTx(ctx context.Context, tx *sql.Tx, c Config, lease PublicIPLease) error {
	if err := publicLeaseInventoryTx(ctx, tx, lease); err != nil {
		return err
	}
	if lease.State != "reserved" {
		return ErrState
	}
	var active string
	if err := tx.QueryRowContext(ctx, "SELECT lease_id FROM controller_public_ip_active WHERE address=?", lease.Address).Scan(&active); err != nil || active != lease.ID {
		return ErrState
	}
	return publicAddressDetachedTx(ctx, tx, c, lease.Address)
}

// All planning paths and the last dispatch gate run this under controller_lock.
// Explicit address selection is never authorized by a database row alone: the
// independent root projection, exact VPC owner and active unique lease all bind.
func validatePublicIPSnapshotTx(ctx context.Context, tx *sql.Tx, c Config, snapshot overlayproto.Snapshot, now time.Time) error {
	proof, err := readPublicIPReleaseProofTx(ctx, tx, c)
	if err != nil {
		return err
	}
	epoch := OverlayEpoch{ClusterID: snapshot.ClusterID, Snapshot: snapshot}
	seen := map[string]bool{}
	for _, p := range snapshot.NATPolicies {
		address, known := publicEpochAddress(c, epoch, p)
		if !known {
			return ErrState
		}
		// Old explicit-prefix profiles may use documentation/private primary
		// addresses. They cannot enter public inventory and retain their old
		// node-local namespace, rather than gaining new global IPAM semantics.
		if p.PublicIPv4 == "" && !overlayproto.PublicInternetIPv4(address) {
			continue
		}
		if seen[address] {
			return ErrState
		}
		seen[address] = true
		var leaseID string
		err := tx.QueryRowContext(ctx, "SELECT lease_id FROM controller_public_ip_active WHERE address=?", address).Scan(&leaseID)
		if p.PublicIPv4 == "" {
			if err == nil {
				return ErrState
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			if err = publicLegacyInventoryAllowedTx(ctx, tx, snapshot, p, address); err != nil {
				return err
			}
		} else {
			if err != nil {
				return ErrState
			}
			lease, x := scanPublicLease(tx.QueryRowContext(ctx, "SELECT "+publicLeaseColumns+" FROM controller_public_ip_leases WHERE id=?", leaseID))
			if x != nil || lease.State != "reserved" || lease.Address != address || lease.ClusterID != snapshot.ClusterID || lease.VPCID != p.VPCID || lease.NodeID != p.NodeID || lease.ProfileID != p.ProfileID {
				return ErrState
			}
			if x = publicLeaseApprovedTx(ctx, tx, c, lease); x != nil {
				return x
			}
			found := false
			for _, v := range snapshot.VPCs {
				if v.ID == lease.VPCID && v.OwnerRef == lease.OwnerRef {
					found = true
				}
			}
			if !found {
				return ErrState
			}
		}
		if err = proof.detached(ctx, tx, address, snapshot.ClusterID); err != nil {
			return err
		}
	}
	if e := validateFloatingPublicResourcesTx(ctx, tx, c, snapshot, seen); e != nil {
		return e
	}
	return validatePublicIngressSnapshotTx(ctx, tx, c, snapshot, now)
}
func decoratePublicIPLeaseTx(ctx context.Context, tx *sql.Tx, c Config, v *PublicIPLease) {
	if v.State == "released" {
		v.BindingState = "released"
		v.Releasable = false
		v.ReleaseReason = ""
		return
	}
	v.BindingState = "reserved"
	v.Releasable = true
	v.ReleaseReason = ""
	if err := PublicIPSafeToReleaseTx(ctx, tx, c, *v); err != nil {
		v.BindingState = "release_blocked"
		v.Releasable = false
		v.ReleaseReason = "NETWORK_RELEASE_UNCONFIRMED"
		latest, e := scanOverlayEpoch(tx.QueryRowContext(ctx, "SELECT "+overlayEpochColumns+" FROM controller_overlay_epochs WHERE cluster_id=? ORDER BY epoch DESC LIMIT 1", v.ClusterID))
		if e == nil {
			for _, p := range latest.Snapshot.NATPolicies {
				address, known := publicEpochAddress(c, latest, p)
				if known && address == v.Address && p.NodeID == v.NodeID && p.VPCID == v.VPCID && p.ProfileID == v.ProfileID {
					if latest.State == "succeeded" && publicReleaseCompleteTx(ctx, tx, latest) == nil {
						v.BindingState = "bound"
						v.ReleaseReason = "NAT_ADDRESS_BOUND"
					} else {
						v.BindingState = "pending"
						v.ReleaseReason = "NETWORK_OPERATION_PENDING"
					}
				}
			}
		}

	}
}

// Capture only pre-existing legacy occupancy at pool creation. This immutable
// inventory fact is not user input and never changes an old network snapshot.
func publicLegacyBaselinesTx(ctx context.Context, tx *sql.Tx, c Config) (map[string]string, error) {
	rows, err := tx.QueryContext(ctx, "SELECT "+overlayEpochColumns+" FROM controller_overlay_epochs e WHERE NOT EXISTS (SELECT 1 FROM controller_overlay_epochs n WHERE n.cluster_id=e.cluster_id AND n.epoch>e.epoch) ORDER BY cluster_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	baselines := map[string]string{}
	for rows.Next() {
		e, x := scanOverlayEpoch(rows)
		if x != nil {
			return nil, x
		}
		for _, p := range e.Snapshot.NATPolicies {
			if p.PublicIPv4 != "" {
				continue
			}
			a, known := publicEpochAddress(c, e, p)
			if !known {
				return nil, ErrState
			}
			if !overlayproto.PublicInternetIPv4(a) {
				continue
			}
			if baselines[a] != "" {
				return nil, ErrState
			}
			baselines[a] = e.ID
		}
	}
	return baselines, rows.Err()
}

func publicLegacyInventoryAllowedTx(ctx context.Context, tx *sql.Tx, snapshot overlayproto.Snapshot, policy overlayproto.NATPolicy, address string) error {
	var baselineID string
	err := tx.QueryRowContext(ctx, "SELECT legacy_epoch_id FROM controller_public_ip_inventory WHERE address=?", address).Scan(&baselineID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if baselineID == "" {
		return ErrState
	}
	baseline, err := scanOverlayEpoch(tx.QueryRowContext(ctx, "SELECT "+overlayEpochColumns+" FROM controller_overlay_epochs WHERE id=?", baselineID))
	if err != nil || baseline.ClusterID != snapshot.ClusterID || baseline.Epoch > snapshot.Epoch {
		return ErrState
	}
	rows, err := tx.QueryContext(ctx, "SELECT "+overlayEpochColumns+" FROM controller_overlay_epochs WHERE cluster_id=? AND epoch>=? AND epoch<=? ORDER BY epoch", snapshot.ClusterID, baseline.Epoch, snapshot.Epoch)
	if err != nil {
		return err
	}
	defer rows.Close()
	want, _ := json.Marshal(policy)
	count := 0
	for rows.Next() {
		e, x := scanOverlayEpoch(rows)
		if x != nil {
			return x
		}
		found := false
		for _, p := range e.Snapshot.NATPolicies {
			raw, _ := json.Marshal(p)
			if bytes.Equal(raw, want) {
				found = true
			}
		}
		if !found {
			return ErrState
		}
		count++
	}
	if err = rows.Err(); err != nil {
		return err
	}
	if count == 0 {
		return ErrState
	}
	return nil
}

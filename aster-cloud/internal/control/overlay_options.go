package control

import (
	"aster/cloud/internal/nodeproto"
	"aster/cloud/internal/overlayproto"
	"context"
	"database/sql"
	"errors"
	"sort"
)

// OverlayOptions is a safe projection of root approval and current immutable
// instance bindings. It is not an instruction to edit host files or devices.
type OverlayOptions struct {
	PublicIPLeases           []PublicIPLease           `json:"public_ip_leases"`
	ClusterID                string                    `json:"cluster_id"`
	Profiles                 []overlayproto.ProfilePin `json:"profiles"`
	Mappings                 []OverlayMapping          `json:"mappings"`
	Gateways                 []overlayproto.Gateway    `json:"gateways"`
	NATProfiles              []OverlayNATProfile       `json:"nat_profiles"`
	Instances                []OverlayInstanceOption   `json:"instances"`
	LatestEpoch              *OverlayEpoch             `json:"latest_epoch"`
	ProfileMigrationRequired bool                      `json:"profile_migration_required"`
	ProfileMigrationApproved bool                      `json:"profile_migration_approved"`
}

type OverlayInstanceOption struct {
	InstanceID string `json:"instance_id"`
	NodeID     string `json:"node_id"`
	OwnerRef   string `json:"owner_ref"`
	Hostname   string `json:"hostname"`
	State      string `json:"state"`
	VPCID      string `json:"vpc_id"`
	LocalVPCID string `json:"local_vpc_id"`
	IPv4       string `json:"ipv4"`
	Enabled    bool   `json:"enabled"`
	Reserved   bool   `json:"reserved"`
	Eligible   bool   `json:"eligible"`
	Reason     string `json:"reason"`
}

func (s *SQLStore) OverlayVPC(ctx context.Context, id string) (OverlayVPC, error) {
	if !nodeproto.ValidID(id) {
		return OverlayVPC{}, ErrInput
	}
	return scanOverlayVPC(s.DB.QueryRowContext(ctx, "SELECT "+overlayVPCColumns+" FROM controller_overlay_vpcs WHERE id=?", id))
}

func (s *SQLStore) OverlayOptions(ctx context.Context, c Config, clusterID string) (OverlayOptions, error) {
	cluster, ok := c.OverlayCluster(clusterID)
	if !ok || !c.validOverlayClusters() {
		return OverlayOptions{}, ErrInput
	}
	out := OverlayOptions{ClusterID: clusterID, Profiles: append([]overlayproto.ProfilePin{}, cluster.Profiles...), Mappings: append([]OverlayMapping{}, cluster.Mappings...), Gateways: append([]overlayproto.Gateway{}, cluster.Gateways...), NATProfiles: append([]OverlayNATProfile{}, cluster.NATProfiles...), Instances: []OverlayInstanceOption{}}
	// A single read-only repeatable snapshot prevents a list assembled from
	// mutually inconsistent epoch, instance and reservation observations.
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	latest, err := scanOverlayEpoch(tx.QueryRowContext(ctx, "SELECT "+overlayEpochColumns+" FROM controller_overlay_epochs WHERE cluster_id=? ORDER BY epoch DESC LIMIT 1", clusterID))
	if err != nil && !errors.Is(err, ErrNotFound) {
		return out, err
	}
	retained := map[string]overlayproto.Member{}
	if err == nil {
		out.LatestEpoch = &latest
		out.ProfileMigrationRequired = !overlayPinsMatch(c, latest)
		out.ProfileMigrationApproved = overlayRecoveryPinsApproved(c, latest)
		for _, member := range latest.Snapshot.Members {
			retained[member.InstanceID] = member
		}
	}
	liveCount := 0
	for _, pin := range cluster.Profiles {
		rows, err := tx.QueryContext(ctx, "SELECT i.id,i.owner_ref,i.node_id,i.hostname,i.state,i.resources,i.created_at,i.updated_at FROM controller_instances i JOIN controller_instance_networks n ON n.instance_id=i.id WHERE i.node_id=? AND CAST(i.state AS BINARY)<>'deleted' AND JSON_UNQUOTE(JSON_EXTRACT(CONVERT(n.binding USING utf8mb4),'$.profile_id'))=? ORDER BY i.id LIMIT 129", pin.NodeID, pin.ProfileID)
		if err != nil {
			return out, err
		}
		instances := []Instance{}
		for rows.Next() {
			v, err := scanInstance(rows)
			if err != nil {
				rows.Close()
				return out, err
			}
			instances = append(instances, v)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return out, err
		}
		liveCount += len(instances)
		if liveCount > 128 {
			return out, ErrCapacity
		}
		// The latest immutable snapshot may still contain a now-deleted guest.
		// Include its exact retained identity so the UI can explicitly remove it,
		// rather than guessing deletion from absence or becoming permanently stuck.
		present := map[string]bool{}
		for _, instance := range instances {
			present[instance.ID] = true
		}
		for _, member := range latest.Snapshot.Members {
			if member.NodeID != pin.NodeID || present[member.InstanceID] {
				continue
			}
			v, e := scanInstance(tx.QueryRowContext(ctx, "SELECT id,owner_ref,node_id,hostname,state,resources,created_at,updated_at FROM controller_instances WHERE id=?", member.InstanceID))
			if e != nil || v.State != "deleted" {
				return out, ErrState
			}
			instances = append(instances, v)
		}
		for _, instance := range instances {
			n, err := instanceNetworkBinding(ctx, tx, instance)
			if err != nil {
				return out, err
			}
			if n.ProfileID != pin.ProfileID {
				continue
			}
			if len(out.Instances) == 256 {
				return out, ErrCapacity
			}
			v := OverlayInstanceOption{InstanceID: instance.ID, NodeID: instance.NodeID, OwnerRef: instance.OwnerRef, Hostname: instance.Hostname, State: instance.State, LocalVPCID: n.VPCID, IPv4: n.IPv4, Enabled: true}
			for _, mapping := range cluster.Mappings {
				if mapping.NodeID == instance.NodeID && mapping.LocalVPCID == n.VPCID {
					v.VPCID = mapping.VPCID
				}
			}
			old, wasMember := retained[instance.ID]
			if wasMember {
				v.Enabled, v.Reserved = old.Enabled, old.Reserved
			}
			v.Eligible = instance.State == "created" || instance.State == "running" || instance.State == "shutoff" || v.Reserved && instance.State == "reserved"
			if !v.Eligible {
				v.Reason = "INSTANCE_STATE_UNCONFIRMED"
			}
			var occupied int
			if err = tx.QueryRowContext(ctx, "SELECT (SELECT COUNT(*) FROM controller_jobs WHERE instance_id=? AND state NOT IN ('succeeded','rejected') AND NOT (?=TRUE AND state='accepted'))+(SELECT COUNT(*) FROM controller_operations WHERE instance_id=? AND state NOT IN ('succeeded','rejected') AND NOT (?=TRUE AND action='create' AND state='accepted'))", instance.ID, v.Reserved, instance.ID, v.Reserved).Scan(&occupied); err != nil {
				return out, err
			}
			if occupied != 0 {
				v.Eligible, v.Reason = false, "INSTANCE_OPERATION_PENDING"
			}
			if v.VPCID == "" {
				v.Eligible, v.Reason = false, "ROOT_MAPPING_REQUIRED"
			} else {
				global, e := scanOverlayVPC(tx.QueryRowContext(ctx, "SELECT "+overlayVPCColumns+" FROM controller_overlay_vpcs WHERE id=?", v.VPCID))
				if errors.Is(e, ErrNotFound) {
					v.Eligible, v.Reason = false, "VPC_REQUIRED"
				} else if e != nil {
					return out, e
				} else if global.ClusterID != clusterID || global.OwnerRef != instance.OwnerRef || global.CIDR != n.CIDR {
					v.Eligible, v.Reason = false, "VPC_BINDING_MISMATCH"
				}
			}
			if instance.State == "deleted" {
				v.Eligible, v.Reason = false, "INSTANCE_DELETED"
			}
			out.Instances = append(out.Instances, v)
		}
	}
	out.PublicIPLeases, err = publicIPLeasesTx(ctx, tx, c, clusterID, "", "", true, 4097)
	if err != nil {
		return out, err
	}
	if len(out.PublicIPLeases) > 4096 {
		return out, ErrCapacity
	}
	sort.Slice(out.Instances, func(i, j int) bool { return out.Instances[i].InstanceID < out.Instances[j].InstanceID })
	if !publicIPProjectionFits(out) {
		return out, ErrCapacity
	}
	return out, tx.Commit()
}

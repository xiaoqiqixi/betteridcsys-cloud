package control

import (
	"aster/cloud/internal/nodeproto"
	"aster/cloud/internal/overlayproto"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// reserveOverlayCreation is part of the original instance/IPAM/capacity
// transaction. A future VM receives no launch permit until every peer releases
// this separately versioned reservation epoch. Financial bytes remain original.
func reserveOverlayCreation(ctx context.Context, tx *sql.Tx, candidate Candidate, t nodeproto.NodeTask, now time.Time) error {
	if candidate.Overlay == nil {
		return nil
	}
	if t.Protocol != nodeproto.NetworkProtocol {
		return ErrState
	}
	approval := candidate.Overlay
	c := Config{ControllerID: approval.ControllerID, Nodes: approval.Nodes, OverlayClusters: approval.RootClusters, HeartbeatTTLSeconds: approval.HeartbeatTTLSeconds}
	cluster, ok := c.OverlayCluster(approval.Cluster.ClusterID)
	if !ok || !c.validOverlayClusters() {
		return ErrState
	}
	globalID := ""
	for _, mapping := range cluster.Mappings {
		if mapping.NodeID == t.NodeID && mapping.LocalVPCID == t.Network.VPCID {
			globalID = mapping.VPCID
		}
	}
	if globalID == "" {
		return ErrState
	}
	previous, e := scanOverlayEpoch(tx.QueryRowContext(ctx, "SELECT "+overlayEpochColumns+" FROM controller_overlay_epochs WHERE cluster_id=? ORDER BY epoch DESC LIMIT 1", cluster.ClusterID))
	if e != nil && !errors.Is(e, ErrNotFound) {
		return e
	}
	if previous.Epoch > 0 && (previous.State != "succeeded" || !overlayPinsMatch(c, previous)) {
		return ErrState
	}
	snapshot := overlayproto.Snapshot{Protocol: overlayproto.Protocol, ClusterID: cluster.ClusterID, Epoch: previous.Epoch + 1, PreviousSHA256: previous.SnapshotSHA256, Profiles: append([]overlayproto.ProfilePin{}, cluster.Profiles...), VPCs: []overlayproto.VPC{}, Members: []overlayproto.Member{}, Gateways: append([]overlayproto.Gateway{}, previous.Snapshot.Gateways...)}
	snapshot.NATPolicies = previous.Snapshot.NATPolicies
	snapshot.FloatingIPs = previous.Snapshot.FloatingIPs
	if !overlayPoliciesApproved(cluster, snapshot) {
		return ErrState
	}
	// Confirmed deleted instances leave only the next active snapshot. Their
	// original epoch, immutable binding and unique lease reservation are retained.
	for _, old := range previous.Snapshot.Members {
		v, err := scanInstance(tx.QueryRowContext(ctx, "SELECT id,owner_ref,node_id,hostname,state,resources,created_at,updated_at FROM controller_instances WHERE id=?", old.InstanceID))
		if err != nil {
			return err
		}
		if v.State == "deleted" {
			continue
		}
		if v.State != "created" && v.State != "running" && v.State != "shutoff" && !(v.State == "reserved" && old.Reserved) {
			return ErrState
		}
		binding, err := instanceNetworkBinding(ctx, tx, v)
		if err != nil || binding.Digest() != old.NetworkSHA256 {
			return ErrState
		}
		var occupied int
		if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM controller_jobs WHERE instance_id=? AND state NOT IN ('succeeded','rejected') AND NOT (?=TRUE AND state='accepted')", v.ID, old.Reserved).Scan(&occupied); err != nil || occupied != 0 {
			return ErrState
		}
		if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM controller_operations WHERE instance_id=? AND state NOT IN ('succeeded','rejected') AND NOT (?=TRUE AND action='create' AND state='accepted')", v.ID, old.Reserved).Scan(&occupied); err != nil || occupied != 0 {
			return ErrState
		}
		snapshot.Members = append(snapshot.Members, old)
	}
	rows, e := tx.QueryContext(ctx, "SELECT "+overlayVPCColumns+" FROM controller_overlay_vpcs WHERE cluster_id=? ORDER BY id LIMIT 33", cluster.ClusterID)
	if e != nil {
		return e
	}
	var global overlayproto.VPC
	for rows.Next() {
		v, e := scanOverlayVPC(rows)
		if e != nil {
			rows.Close()
			return e
		}
		w := overlayproto.VPC{ID: v.ID, OwnerRef: v.OwnerRef, CIDR: v.CIDR, VNI: v.VNI}
		snapshot.VPCs = append(snapshot.VPCs, w)
		if v.ID == globalID {
			global = w
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	if global.ID == "" || global.OwnerRef != t.OwnerRef || global.CIDR != t.Network.CIDR {
		return ErrState
	}
	n := t.Network
	snapshot.Members = append(snapshot.Members, overlayproto.Member{NodeID: t.NodeID, InstanceID: t.InstanceID, InterfaceID: n.InterfaceID, OwnerRef: t.OwnerRef, VPCID: globalID, LocalVPCID: n.VPCID, LeaseID: n.LeaseID, PoolID: n.PoolID, NetworkSHA256: n.Digest(), IPv4: n.IPv4, MAC: n.MAC, InboundMbps: n.InboundMbps, OutboundMbps: n.OutboundMbps, Enabled: true, Reserved: true})
	snapshot, sha, e := overlayproto.CanonicalSnapshot(snapshot)
	if e != nil {
		return ErrConflict
	}
	if e = validatePublicIPSnapshotTx(ctx, tx, c, snapshot, now); e != nil {
		return e
	}
	if e = overlayCompleteInventory(ctx, tx, snapshot); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO controller_overlay_members(instance_id,cluster_id,vpc_id,address,lease_id,network_sha256,created_at) VALUES(?,?,?,?,?,?,?)", t.InstanceID, cluster.ClusterID, globalID, n.IPv4, n.LeaseID, n.Digest(), now); e != nil {
		return ErrConflict
	}
	epochID := overlayproto.Digest([]byte("aster.overlay.admission/1:" + t.OperationID))[:32]
	actor := overlayproto.Digest([]byte("aster.overlay.system/1:" + approval.ControllerID))[:32]
	raw, _ := json.Marshal(snapshot)
	intent := overlayproto.Digest([]byte("aster.overlay.admission/1:" + t.Network.Digest() + ":" + sha))
	epoch := OverlayEpoch{ID: epochID, ClusterID: cluster.ClusterID, Epoch: snapshot.Epoch, SnapshotSHA256: sha, Snapshot: snapshot, Phase: "prepare", State: "pending", ActorID: actor, RequestSHA256: intent, CreatedAt: now, UpdatedAt: now}
	if _, e = tx.ExecContext(ctx, "INSERT INTO controller_overlay_epochs("+overlayEpochColumns+") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", epochID, cluster.ClusterID, epoch.Epoch, actor, intent, sha, raw, []byte{}, "", epoch.Phase, epoch.State, now, now); e != nil {
		return e
	}
	for _, phase := range []string{"prepare", "program", "release"} {
		for _, pin := range snapshot.Profiles {
			p, ok := c.Node(pin.NodeID)
			if !ok {
				return ErrState
			}
			var registered string
			if e = tx.QueryRowContext(ctx, "SELECT profile_sha256 FROM controller_nodes WHERE id=?", pin.NodeID).Scan(&registered); e != nil || registered != p.Digest() {
				return ErrState
			}
			task := overlayTask(epoch, pin.NodeID, phase)
			_, taskSHA, e := task.BytesAndDigest()
			if e != nil {
				return ErrInput
			}
			if _, e = tx.ExecContext(ctx, "INSERT INTO controller_overlay_tasks("+overlayTaskColumns+") VALUES(?,?,?,?,?,?,?,?,?)", task.OperationID, epochID, pin.NodeID, phase, p.Digest(), taskSHA, "pending", []byte{}, now); e != nil {
				return e
			}
		}
	}
	return audit(ctx, tx, "overlay-admission", "overlay.member.reserved", epochID, now)
}

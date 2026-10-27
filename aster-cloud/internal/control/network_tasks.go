package control

import (
	"aster/cloud/internal/networking"
	"aster/cloud/internal/nodeproto"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// bindCreateNetwork runs inside the instance/capacity/task admission transaction.
// The financial request and its digest remain untouched; only the independent
// node/2 request gains an exact, root-selected IPAM reservation.
func bindCreateNetwork(ctx context.Context, tx *sql.Tx, task nodeproto.NodeTask, candidate Candidate, now time.Time) (nodeproto.NodeTask, error) {
	if task.Resources.NetworkType != "vpc" {
		if candidate.NetworkProfileID != "" || candidate.NetworkPoolID != "" || candidate.NetworkProfileSHA != "" || candidate.NetworkOwnerRef != "" {
			return nodeproto.NodeTask{}, ErrInput
		}
		return task, nil
	}
	if !vpcResources(task.Resources) || !nodeproto.ValidNodeID(candidate.NetworkProfileID) || !nodeproto.ValidID(candidate.NetworkPoolID) || !shaRE.MatchString(candidate.NetworkProfileSHA) || task.OwnerRef != candidate.NetworkOwnerRef {
		return nodeproto.NodeTask{}, ErrInput
	}
	lease, pool, vpc, e := (&networking.Store{}).ReserveTaskTx(ctx, tx, task.OperationID, networking.ReserveInput{PoolID: candidate.NetworkPoolID, InstanceID: task.InstanceID, OwnerRef: task.OwnerRef}, now)
	if e != nil {
		return nodeproto.NodeTask{}, networkError(e)
	}
	task.Protocol = nodeproto.NetworkProtocol
	task.Network = nodeproto.NetworkBinding{Schema: 1, ProfileID: candidate.NetworkProfileID, ProfileSHA256: candidate.NetworkProfileSHA, LeaseID: lease.ID, PoolID: pool.ID, VPCID: vpc.ID, NodeID: lease.NodeID, OwnerRef: lease.OwnerRef, InstanceID: lease.InstanceID, CIDR: vpc.CIDR, IPv4: lease.Address, MAC: nodeproto.NetworkMAC(task.NodeID, task.InstanceID), InterfaceID: nodeproto.NetworkInterfaceID(task.InstanceID), VLANID: vpc.VLANID, InboundMbps: task.Resources.InboundBandwidthMbps, OutboundMbps: task.Resources.BandwidthMbps}
	if !task.Valid() {
		return nodeproto.NodeTask{}, ErrInput
	}
	return task, nil
}

func networkError(e error) error {
	switch {
	case errors.Is(e, networking.ErrInput):
		return ErrInput
	case errors.Is(e, networking.ErrCapacity):
		return ErrCapacity
	case errors.Is(e, networking.ErrNotFound), errors.Is(e, networking.ErrForbidden), errors.Is(e, networking.ErrConflict), errors.Is(e, networking.ErrState):
		return ErrState
	default:
		return ErrUnavailable
	}
}

func networkActionSupported(action string) bool {
	switch action {
	case "start", "shutdown", "force_off", "delete":
		return true
	}
	return false
}

func insertNetworkBinding(ctx context.Context, tx *sql.Tx, task nodeproto.NodeTask, requestSHA string, now time.Time) error {
	if task.Protocol != nodeproto.NetworkProtocol {
		return nil
	}
	if !task.Valid() || task.Action != "create" || !shaRE.MatchString(requestSHA) {
		return ErrInput
	}
	raw, _ := json.Marshal(task.Network)
	_, e := tx.ExecContext(ctx, "INSERT INTO controller_instance_networks(instance_id,operation_id,node_id,request_sha256,network_sha256,binding,created_at) VALUES(?,?,?,?,?,?,?)", task.InstanceID, task.OperationID, task.NodeID, requestSHA, task.Network.Digest(), raw, now)
	return e
}

// The creation binding is immutable. Power requests reuse it, never today's
// preset, pool allocation order, or root profile selection.
func instanceNetworkBinding(ctx context.Context, tx *sql.Tx, v Instance) (nodeproto.NetworkBinding, error) {
	var operation, node, requestSHA, networkSHA string
	var raw []byte
	e := tx.QueryRowContext(ctx, "SELECT operation_id,node_id,request_sha256,network_sha256,binding FROM controller_instance_networks WHERE instance_id=?", v.ID).Scan(&operation, &node, &requestSHA, &networkSHA, &raw)
	if errors.Is(e, sql.ErrNoRows) {
		if v.Resources.NetworkType == "vpc" {
			return nodeproto.NetworkBinding{}, ErrState
		}
		return nodeproto.NetworkBinding{}, nil
	}
	if e != nil {
		return nodeproto.NetworkBinding{}, e
	}
	var n nodeproto.NetworkBinding
	if len(raw) > 4096 || !strict(raw, &n) || node != v.NodeID || n.Digest() != networkSHA || v.Resources.NetworkType != "vpc" {
		return nodeproto.NetworkBinding{}, ErrState
	}
	t := nodeproto.NodeTask{Protocol: nodeproto.NetworkProtocol, OperationID: operation, NodeID: v.NodeID, Action: "create", InstanceID: v.ID, OwnerRef: v.OwnerRef, Hostname: v.Hostname, Resources: v.Resources, Network: n}
	_, sha, e := t.BytesAndDigest()
	if e != nil || sha != requestSHA {
		return nodeproto.NetworkBinding{}, ErrState
	}
	if e = (&networking.Store{}).CheckTaskReservationTx(ctx, tx, n, false); e != nil {
		return nodeproto.NetworkBinding{}, networkError(e)
	}
	return n, nil
}

func validateTaskNetwork(ctx context.Context, tx *sql.Tx, task nodeproto.NodeTask) error {
	v, e := scanInstance(tx.QueryRowContext(ctx, "SELECT id,owner_ref,node_id,hostname,state,resources,created_at,updated_at FROM controller_instances WHERE id=?", task.InstanceID))
	if e != nil {
		return e
	}
	if v.NodeID != task.NodeID || v.OwnerRef != task.OwnerRef || v.Hostname != task.Hostname || v.Resources != task.Resources {
		return ErrState
	}
	if e = validateDirectTaskTx(ctx, tx, task, v); e != nil {
		return e
	}
	if task.Protocol == nodeproto.DirectPublicProtocol {
		return nil
	}
	n, e := instanceNetworkBinding(ctx, tx, v)
	if e != nil {
		return e
	}
	if n != task.Network || n.IsZero() && task.Protocol != nodeproto.Protocol || !n.IsZero() && task.Protocol != nodeproto.NetworkProtocol {
		return ErrState
	}
	if !n.IsZero() && (task.Action == "create" || task.Action == "start" || task.Action == "reboot") {
		if e = (&networking.Store{}).CheckTaskReservationTx(ctx, tx, n, true); e != nil {
			return networkError(e)
		}
	}
	if !n.IsZero() {
		return overlayLifecycleGate(ctx, tx, task.InstanceID)
	}
	return nil
}

package control

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"time"
)

type StorageRPC interface {
	SendStorage(context.Context, []byte, string) (nodeproto.StorageResult, error)
	LookupStorage(context.Context, string, string) (nodeproto.StorageResult, error)
}

func (c *NodeClient) SendStorage(ctx context.Context, raw []byte, sha string) (nodeproto.StorageResult, error) {
	t, e := nodeproto.DecodeStorageTask(raw)
	if e != nil || nodeproto.Digest(raw) != sha || t.NodeID != c.profile.ID {
		return nodeproto.StorageResult{}, ErrInput
	}
	out, e := c.call(ctx, "POST", "/v1/storage-tasks", raw, sha)
	if e != nil {
		return nodeproto.StorageResult{}, e
	}
	var result nodeproto.StorageResult
	if !strict(out, &result) || !result.Matches(t, sha) {
		return result, ErrUnavailable
	}
	return result, nil
}
func (c *NodeClient) LookupStorage(ctx context.Context, op, sha string) (nodeproto.StorageResult, error) {
	if !nodeproto.ValidID(op) || !shaRE.MatchString(sha) {
		return nodeproto.StorageResult{}, ErrInput
	}
	raw, e := c.call(ctx, "GET", "/v1/storage-tasks/"+op, nil, sha)
	if e != nil {
		return nodeproto.StorageResult{}, e
	}
	var result nodeproto.StorageResult
	if !strict(raw, &result) || result.OperationID != op || result.RequestSHA256 != sha {
		return result, ErrUnavailable
	}
	return result, nil
}

type OperationWorker struct {
	Store      *SQLStore
	Config     Config
	RPC        func(context.Context, NodeProfile) (NodeRPC, error)
	StorageRPC func(context.Context, NodeProfile) (StorageRPC, error)
	Now        func() time.Time
}

func (w OperationWorker) now() time.Time {
	if w.Now != nil {
		return w.Now().UTC()
	}
	return time.Now().UTC()
}
func (w OperationWorker) binding(ctx context.Context, op string) (Operation, NodeProfile, error) {
	o, e := w.Store.Operation(ctx, op)
	if e != nil {
		return o, NodeProfile{}, e
	}
	p, ok := w.Config.Node(o.NodeID)
	if !ok || p.Digest() != o.ProfileSHA || nodeproto.Digest(o.Request) != o.RequestSHA {
		return o, p, ErrState
	}
	switch o.Protocol {
	case TransferProtocol:
		intent, e := DecodeTransferIntent(o.Request)
		if e != nil || intent.Approval.TransferID != o.ID || intent.Approval.ArtifactID != o.ArtifactID || intent.Approval.NodeID != o.NodeID || intent.Approval.InstanceID != o.InstanceID {
			return o, p, ErrState
		}
	case nodeproto.Protocol, nodeproto.NetworkProtocol, nodeproto.DirectPublicProtocol:
		t, e := nodeproto.DecodeTask(o.Request)
		if e != nil || t.OperationID != o.ID || t.InstanceID != o.InstanceID || t.NodeID != o.NodeID || t.Action != o.Action || t.Protocol != o.Protocol {
			return o, p, ErrState
		}
	case nodeproto.StorageProtocol, nodeproto.StorageDirectProtocol:
		t, e := nodeproto.DecodeStorageTask(o.Request)
		if e != nil || t.OperationID != o.ID || t.InstanceID != o.InstanceID || t.NodeID != o.NodeID || t.Action != o.Action || t.ArtifactID != o.ArtifactID {
			return o, p, ErrState
		}
	default:
		return o, p, ErrState
	}
	return o, p, nil
}
func (w OperationWorker) power(ctx context.Context, p NodeProfile) (NodeRPC, error) {
	if w.RPC != nil {
		return w.RPC(ctx, p)
	}
	return NewNodeClient(ctx, p)
}
func (w OperationWorker) storage(ctx context.Context, p NodeProfile) (StorageRPC, error) {
	if w.StorageRPC != nil {
		return w.StorageRPC(ctx, p)
	}
	return NewNodeClient(ctx, p)
}
func (w OperationWorker) Dispatch(ctx context.Context, op string) (out Operation, err error) {
	defer func() { logWorkerOutcome(ctx, "aster_controller_operation", "dispatch", op, out.State, err) }()
	o, p, e := w.binding(ctx, op)
	if e != nil {
		return o, e
	}
	if o.Protocol == TransferProtocol {
		return w.dispatchTransfer(ctx, o)
	}
	if o.Protocol == nodeproto.NetworkProtocol || o.Protocol == nodeproto.DirectPublicProtocol {
		task, e := nodeproto.DecodeTask(o.Request)
		if e != nil || !w.Config.approvesTaskNetwork(task) {
			return o, ErrState
		}
	}
	// Resolve/configure TLS before claim. Once sending is committed, never POST again.
	var rpc NodeRPC
	var srpc StorageRPC
	if o.Protocol == nodeproto.Protocol || o.Protocol == nodeproto.NetworkProtocol || o.Protocol == nodeproto.DirectPublicProtocol {
		rpc, e = w.power(ctx, p)
	} else {
		srpc, e = w.storage(ctx, p)
	}
	if e != nil {
		return o, e
	}
	o, e = w.Store.ClaimOperation(ctx, op, w.Config, w.now())
	if e != nil {
		return o, e
	}
	status := "uncertain"
	var storage *nodeproto.StorageResult
	var callErr error
	if rpc != nil {
		t, _ := nodeproto.DecodeTask(o.Request)
		r, e := rpc.Send(ctx, o.Request, o.RequestSHA)
		callErr = e
		if e == nil && r.Matches(t, o.RequestSHA) {
			status = r.Status
		}
	} else {
		t, _ := nodeproto.DecodeStorageTask(o.Request)
		r, e := srpc.SendStorage(ctx, o.Request, o.RequestSHA)
		callErr = e
		if e == nil && r.Matches(t, o.RequestSHA) {
			status = r.Status
			storage = &r
		}
	}
	finish, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	result, e := w.Store.CompleteOperation(finish, w.Config, op, status, storage, w.now())
	if e != nil {
		return o, e
	}
	if callErr != nil {
		return result, ErrUnavailable
	}
	return result, nil
}
func (w OperationWorker) Reconcile(ctx context.Context, op string) (out Operation, err error) {
	defer func() { logWorkerOutcome(ctx, "aster_controller_operation", "reconcile", op, out.State, err) }()
	o, p, e := w.binding(ctx, op)
	if e != nil {
		return o, e
	}
	if o.State == "succeeded" || o.State == "rejected" {
		return o, nil
	}
	if o.State != "sending" && o.State != "dispatched" && o.State != "uncertain" {
		return o, ErrState
	}
	if o.Protocol == TransferProtocol {
		return w.reconcileTransfer(ctx, o)
	}
	var status string
	var storage *nodeproto.StorageResult
	if o.Protocol == nodeproto.Protocol || o.Protocol == nodeproto.NetworkProtocol || o.Protocol == nodeproto.DirectPublicProtocol {
		rpc, e := w.power(ctx, p)
		if e != nil {
			return o, e
		}
		r, e := rpc.Lookup(ctx, o.ID, o.RequestSHA)
		t, _ := nodeproto.DecodeTask(o.Request)
		if e != nil || !r.Matches(t, o.RequestSHA) {
			return o, ErrUnavailable
		}
		status = r.Status
	} else {
		rpc, e := w.storage(ctx, p)
		if e != nil {
			return o, e
		}
		r, e := rpc.LookupStorage(ctx, o.ID, o.RequestSHA)
		t, _ := nodeproto.DecodeStorageTask(o.Request)
		if e != nil || !r.Matches(t, o.RequestSHA) {
			return o, ErrUnavailable
		}
		status = r.Status
		storage = &r
	}
	return w.Store.CompleteOperation(ctx, w.Config, o.ID, status, storage, w.now())
}

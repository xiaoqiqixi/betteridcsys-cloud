package control

import (
	"aster/billing/serviceapi"
	"aster/cloud/internal/nodeproto"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestMySQLTerminatedServiceRetainsExplicitSnapshotCleanup(t *testing.T) {
	s, c, p, v, now := readyService(t)
	ctx := context.Background()
	if _, e := s.DB.ExecContext(ctx, "UPDATE controller_instances SET state='shutoff' WHERE id=?", v.ID); e != nil {
		t.Fatal(e)
	}
	r := serviceapi.ActionRequest{Protocol: serviceapi.Protocol, OperationID: id(), OwnerRef: v.OwnerRef, Action: "snapshot_create", Params: serviceapi.Params{Name: "retained"}}
	if receipt, _, e := s.AdmitService(ctx, c, v.ID, r, now); e != nil || receipt.Status != "accepted" {
		t.Fatal(receipt, e)
	}
	op, e := s.ClaimOperation(ctx, r.OperationID, c, now)
	if e != nil {
		t.Fatal(e)
	}
	task, e := nodeproto.DecodeStorageTask(op.Request)
	if e != nil {
		t.Fatal(e)
	}
	proof := nodeproto.StorageResult{Protocol: task.Protocol, OperationID: task.OperationID, RequestSHA256: op.RequestSHA, InstanceID: task.InstanceID, ArtifactID: task.ArtifactID, Status: "succeeded", ManifestSHA256: strings.Repeat("a", 64), Items: []nodeproto.StorageArtifact{}}
	if _, e = s.CompleteOperation(ctx, c, op.ID, "succeeded", &proof, now); e != nil {
		t.Fatal(e)
	}
	termination, _, e := s.CreateOperation(ctx, c, v.OwnerRef, v.ID, id(), OperationInput{Action: "delete", Confirmation: v.ID}, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.ClaimOperation(ctx, termination.ID, c, now); e != nil {
		t.Fatal(e)
	}
	if _, e = s.CompleteOperation(ctx, c, termination.ID, "succeeded", nil, now); e != nil {
		t.Fatal(e)
	}
	assertNodeReservation(t, s, p.ID, 0, 0, 0)
	r = serviceapi.ActionRequest{Protocol: serviceapi.Protocol, OperationID: id(), OwnerRef: v.OwnerRef, Action: "snapshot_delete", Params: serviceapi.Params{SnapshotID: task.ArtifactID}}
	if receipt, _, e := s.AdmitService(ctx, c, v.ID, r, now); e != nil || receipt.Status != "accepted" {
		t.Fatal(receipt, e)
	}
	cleanup, e := s.ClaimOperation(ctx, r.OperationID, c, now)
	if e != nil {
		t.Fatal(e)
	}
	proof.OperationID, proof.RequestSHA256 = cleanup.ID, cleanup.RequestSHA
	for range 2 {
		if _, e = s.CompleteOperation(ctx, c, cleanup.ID, "succeeded", &proof, now); e != nil {
			t.Fatal(e)
		}
		assertNodeReservation(t, s, p.ID, 0, 0, 0)
	}
	items, e := s.ServiceSnapshots(ctx, v.ID, 1)
	if e != nil || len(items.Items) != 0 {
		t.Fatal(items, e)
	}
	if got, e := s.Instance(ctx, v.ID); e != nil || got.State != "deleted" {
		t.Fatal("cleanup resurrected instance", got, e)
	}
	if _, _, e := s.CreateOperation(ctx, c, v.OwnerRef, v.ID, id(), OperationInput{Action: "start"}, now); !errors.Is(e, ErrState) {
		t.Fatal("cleanup enabled start after termination", e)
	}
}

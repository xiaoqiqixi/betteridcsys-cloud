package control

import (
	"aster/billing/serviceapi"
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func assertNodeReservation(t *testing.T, s *SQLStore, node string, cpu, mem, disk int) {
	t.Helper()
	var gotCPU, gotMem, gotDisk int
	err := s.DB.QueryRow("SELECT COALESCE(SUM(cpu),0),COALESCE(SUM(memory_mib),0),COALESCE(SUM(disk_gib),0) FROM controller_reservations WHERE node_id=? AND released=FALSE", node).Scan(&gotCPU, &gotMem, &gotDisk)
	if err != nil || gotCPU != cpu || gotMem != mem || gotDisk != disk {
		t.Fatalf("reservation=(%d,%d,%d), want=(%d,%d,%d): %v", gotCPU, gotMem, gotDisk, cpu, mem, disk, err)
	}
}

func TestMySQLResizeReservationOutcomesAndTerminate(t *testing.T) {
	for _, outcome := range []string{"succeeded", "rejected", "uncertain"} {
		t.Run(outcome, func(t *testing.T) {
			s, c, p, v, now := readyService(t)
			ctx := context.Background()
			params := serviceapi.Params{CPUCores: 8, MemoryMB: 1024, DiskGB: 15}
			r := serviceapi.ActionRequest{Protocol: serviceapi.Protocol, OperationID: id(), OwnerRef: v.OwnerRef, Action: "resize", Params: params}
			first, replay, e := s.AdmitService(ctx, c, v.ID, r, now)
			if e != nil || replay || first.Status != "accepted" {
				t.Fatal(first, replay, e)
			}
			assertNodeReservation(t, s, p.ID, 8, 1024, 15)
			again, replay, e := s.AdmitService(ctx, c, v.ID, r, now)
			if e != nil || !replay || first.Result() != again.Result() {
				t.Fatal(again, replay, e)
			}
			assertNodeReservation(t, s, p.ID, 8, 1024, 15)
			if _, e = s.ClaimOperation(ctx, r.OperationID, c, now); e != nil {
				t.Fatal(e)
			}
			// The original worker can disappear here; completion only reads the
			// durable intent and reservation, with no in-memory resize bookkeeping.
			restarted := &SQLStore{DB: s.DB}
			for range 2 {
				if o, e := restarted.CompleteOperation(ctx, c, r.OperationID, outcome, nil, now); e != nil || o.State != outcome {
					t.Fatal(o, e)
				}
			}
			if outcome == "rejected" {
				assertNodeReservation(t, s, p.ID, v.Resources.CPUCores, v.Resources.MemoryMiB, v.Resources.SystemDiskGiB)
				return
			}
			assertNodeReservation(t, s, p.ID, 8, 1024, 15)
			request := testRequest(p)
			if _, _, e = s.Admit(ctx, request, c.Candidates(request), now, time.Minute); !errors.Is(e, ErrCapacity) {
				t.Fatal("create oversubscribed resized node", e)
			}
			if outcome == "uncertain" {
				if _, _, e = s.CreateOperation(ctx, c, v.OwnerRef, v.ID, id(), OperationInput{Action: "delete", Confirmation: v.ID}, now); !errors.Is(e, ErrState) {
					t.Fatal("uncertain resize allowed deletion", e)
				}
				return
			}
			// Successful shrink releases CPU/RAM only after confirmation, and
			// termination releases the current allocation, not just initial create.
			r.OperationID = id()
			r.Params.CPUCores, r.Params.MemoryMB = 1, 512
			if receipt, _, e := s.AdmitService(ctx, c, v.ID, r, now); e != nil || receipt.Status != "accepted" {
				t.Fatal(receipt, e)
			}
			assertNodeReservation(t, s, p.ID, 8, 1024, 15)
			if _, e = s.ClaimOperation(ctx, r.OperationID, c, now); e != nil {
				t.Fatal(e)
			}
			if _, e = s.CompleteOperation(ctx, c, r.OperationID, "succeeded", nil, now); e != nil {
				t.Fatal(e)
			}
			assertNodeReservation(t, s, p.ID, 1, 512, 15)
			deleted, _, e := s.CreateOperation(ctx, c, v.OwnerRef, v.ID, id(), OperationInput{Action: "delete", Confirmation: v.ID}, now)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = s.ClaimOperation(ctx, deleted.ID, c, now); e != nil {
				t.Fatal(e)
			}
			for range 2 {
				if _, e = s.CompleteOperation(ctx, c, deleted.ID, "succeeded", nil, now); e != nil {
					t.Fatal(e)
				}
				assertNodeReservation(t, s, p.ID, 0, 0, 0)
			}
		})
	}
}

func TestMySQLResizeAndCreateShareCapacityLock(t *testing.T) {
	s, c, p, v, now := readyService(t)
	ctx := context.Background()
	resize := serviceapi.ActionRequest{Protocol: serviceapi.Protocol, OperationID: id(), OwnerRef: v.OwnerRef, Action: "resize", Params: serviceapi.Params{CPUCores: 8, MemoryMB: 1024, DiskGB: 15}}
	create := testRequest(p)
	start := make(chan struct{})
	var wg sync.WaitGroup
	var receipt ServiceReceipt
	var resizeErr, createErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		receipt, _, resizeErr = s.AdmitService(ctx, c, v.ID, resize, now)
	}()
	go func() {
		defer wg.Done()
		<-start
		_, _, createErr = s.Admit(ctx, create, c.Candidates(create), now, time.Minute)
	}()
	close(start)
	wg.Wait()
	if resizeErr != nil {
		t.Fatal(resizeErr)
	}
	if receipt.Status == "accepted" {
		if !errors.Is(createErr, ErrCapacity) {
			t.Fatal("create ignored resize reservation", createErr)
		}
		assertNodeReservation(t, s, p.ID, 8, 1024, 15)
	} else {
		if receipt.Code != "NODE_NOT_READY" || createErr != nil {
			t.Fatal(receipt, createErr)
		}
		assertNodeReservation(t, s, p.ID, 4, 1024, 10)
	}
}

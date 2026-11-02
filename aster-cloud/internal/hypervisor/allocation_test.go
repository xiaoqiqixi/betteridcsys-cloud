package hypervisor

import (
	"aster/billing/serviceapi"
	"context"
	"strings"
	"testing"
)

func TestResizeUncertaintyRetainsBothAllocationsAcrossRestart(t *testing.T) {
	for _, stage := range []string{"claim", "grow", "shrink"} {
		t.Run(stage, func(t *testing.T) {
			m, f, task := guestFixture(t)
			if r := submit(t, m, next(task, "3", "force_off")); r.Status != "succeeded" {
				t.Fatal(r)
			}
			params := serviceapi.Params{CPUCores: 4, MemoryMB: 2048, DiskGB: 20}
			if stage == "shrink" {
				if r := submit(t, m, guestTask(m, task, "4", "resize", params)); r.Status != "succeeded" {
					t.Fatal(r)
				}
				params.CPUCores, params.MemoryMB = 1, 512
				f.fail = "define"
			} else {
				f.fail = "resize"
			}
			resize := guestTask(m, task, "5", "resize", params)
			if stage == "claim" {
				_, sha, _ := resize.BytesAndDigest()
				if _, _, e := m.Ledger.Claim(resize, sha); e != nil {
					t.Fatal(e)
				}
			} else if r := submit(t, m, resize); r.Status != "uncertain" {
				t.Fatal(r)
			}
			m.Shutdown()
			if e := m.Ledger.Close(); e != nil {
				t.Fatal(e)
			}
			ledger, e := OpenLedger(m.Config.StateDirectory, m.Config.NodeID)
			if e != nil {
				t.Fatal(e)
			}
			defer ledger.Close()
			m.Ledger = ledger
			cpu, mem, disk := ledger.allocation("")
			if cpu != 4 || mem != 2048 || disk != 20 {
				t.Fatalf("lost resize reservation: %d CPU, %d MiB, %d GiB", cpu, mem, disk)
			}
			caps := m.Capabilities(context.Background()).Capacity
			if caps.CPUCoresAllocated != cpu || caps.MemoryAllocatedMiB != int64(mem) || caps.StorageAllocatedGiB != int64(disk) {
				t.Fatal("heartbeat lost reservation", caps)
			}
			create := task
			create.InstanceID, create.OperationID = strings.Repeat("b", 32), strings.Repeat("c", 32)
			m.Config.CPUAllocationLimit = cpu
			if _, e := m.prepare(create); e == nil {
				t.Fatal("create reused uncertain resize CPU")
			}
			m.Config.CPUAllocationLimit = 16
			m.Config.DiskAllocationLimitGiB = disk
			if _, e := m.prepare(create); e == nil {
				t.Fatal("create reused uncertain resize disk")
			}
			commands := len(f.commands)
			if r := submit(t, m, resize); r.Status != "uncertain" || len(f.commands) != commands {
				t.Fatal("restart replay executed resize", r)
			}
		})
	}
}

func TestResizeTerminalResultsReleaseOnlyUnusedAllocation(t *testing.T) {
	m, _, task := guestFixture(t)
	params := serviceapi.Params{CPUCores: 4, MemoryMB: 2048, DiskGB: 20}
	if r := submit(t, m, guestTask(m, task, "3", "resize", params)); r.Status != "rejected" {
		t.Fatal(r)
	}
	cpu, mem, disk := m.Ledger.allocation("")
	if cpu != task.Resources.CPUCores || mem != task.Resources.MemoryMiB || disk != task.Resources.SystemDiskGiB {
		t.Fatal("rejected resize leaked allocation", cpu, mem, disk)
	}
	if r := submit(t, m, next(task, "4", "force_off")); r.Status != "succeeded" {
		t.Fatal(r)
	}
	if r := submit(t, m, guestTask(m, task, "5", "resize", params)); r.Status != "succeeded" {
		t.Fatal(r)
	}
	params.CPUCores, params.MemoryMB = 1, 512
	if r := submit(t, m, guestTask(m, task, "6", "resize", params)); r.Status != "succeeded" {
		t.Fatal(r)
	}
	cpu, mem, disk = m.Ledger.allocation("")
	if cpu != 1 || mem != 512 || disk != 20 {
		t.Fatal("successful shrink retained obsolete allocation", cpu, mem, disk)
	}
}

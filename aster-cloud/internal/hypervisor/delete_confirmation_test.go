package hypervisor

import (
	"context"
	"errors"
	"os"
	"testing"
)

type unconfirmedDeleteRunner struct {
	*fakeRunner
	retainDomain bool
	undefined    bool
}

func (r *unconfirmedDeleteRunner) Run(ctx context.Context, binary string, args ...string) ([]byte, error) {
	if binary == Virsh && len(args) > 2 {
		if args[2] == "undefine" {
			r.undefined = true
			if r.retainDomain {
				// Model a guest that started after the stopped preflight. Libvirt
				// removes its persistent definition but keeps the live guest.
				r.fakeRunner.mu.Lock()
				r.states[args[3]] = "running"
				r.fakeRunner.mu.Unlock()
				return nil, nil
			}
		}
		if args[2] == "list" && r.undefined && !r.retainDomain {
			return nil, errors.New("domain inventory unavailable after undefine")
		}
	}
	return r.fakeRunner.Run(ctx, binary, args...)
}

func TestDeletePreservesDisksUntilDomainAbsenceIsConfirmed(t *testing.T) {
	for _, retain := range []bool{true, false} {
		t.Run(map[bool]string{true: "transient_guest", false: "inventory_unavailable"}[retain], func(t *testing.T) {
			m, f, task := newFixture(t)
			if r := submit(t, m, task); r.Status != "succeeded" {
				t.Fatal(r)
			}
			if r := submit(t, m, next(task, "3", "force_off")); r.Status != "succeeded" {
				t.Fatal(r)
			}
			i, _ := m.Ledger.Instance(task.InstanceID)
			before, e := os.Stat(i.Disk)
			if e != nil {
				t.Fatal(e)
			}
			m.Config.AllowDelete = true
			m.Runner = &unconfirmedDeleteRunner{fakeRunner: f, retainDomain: retain}
			del := next(task, "4", "delete")
			if r := submit(t, m, del); r.Status != "uncertain" {
				t.Fatal("delete succeeded without proving guest absent", r)
			}
			after, e := os.Stat(i.Disk)
			if e != nil || !os.SameFile(before, after) {
				t.Fatal("unconfirmed deletion removed customer disk", e)
			}
			op, _ := m.Ledger.Query(del.OperationID)
			if op.ErrorCode != "DELETE_DOMAIN_ABSENCE_UNCONFIRMED" {
				t.Fatal(op.ErrorCode)
			}
			m.Shutdown()
			m.Ledger.Close()
			l, e := OpenLedger(m.Config.StateDirectory, m.Config.NodeID)
			if e != nil {
				t.Fatal(e)
			}
			defer l.Close()
			m.Ledger = l
			commands := len(f.commands)
			if r := submit(t, m, del); r.Status != "uncertain" || len(f.commands) != commands {
				t.Fatal("restart repeated delete", r)
			}
			i, _ = l.Instance(i.ID)
			cpu, mem, disk := l.allocation("")
			if i.State != "uncertain" || cpu == 0 || mem == 0 || disk == 0 {
				t.Fatal("uncertain delete released reservation", i.State, cpu, mem, disk)
			}
		})
	}
}

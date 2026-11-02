package hypervisor

import (
	"aster/billing/serviceapi"
	"aster/cloud/internal/nodeproto"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExplicitArtifactCleanupAfterTerminationAndResize(t *testing.T) {
	for _, variant := range []string{"snapshot", "backup", "direct", "resized", "inventory_failure"} {
		t.Run(variant, func(t *testing.T) {
			m, f, task := newStorageFixture(t, "node-a")
			if variant == "direct" {
				task = configureDirect(t, m, task)
			}
			createOff(t, m, task)
			kind := "snapshot"
			if variant == "backup" {
				kind = "backup"
			}
			create := storageTask(task, 20, kind+"_create", 20)
			if variant == "direct" {
				create.Protocol, create.DirectPublic = nodeproto.StorageDirectProtocol, task.DirectPublic
			}
			assertStorageStatus(t, m, create, "succeeded")
			if variant == "resized" {
				m.Config.Guest = GuestConfig{Enabled: true, Families: map[string]string{"ubuntu22": "linux"}}
				m.Runner = &guestRunner{fakeRunner: f}
				if r := submit(t, m, guestTask(m, task, "7", "resize", serviceapi.Params{CPUCores: 2, MemoryMB: 1024, DiskGB: 20})); r.Status != "succeeded" {
					t.Fatal(r)
				}
				i, _ := m.Ledger.Instance(task.InstanceID)
				task.Resources = i.Resources
			}
			m.Config.AllowDelete = true
			if r := submit(t, m, next(task, "8", "delete")); r.Status != "succeeded" {
				t.Fatal(r)
			}
			m.Shutdown()
			m.Ledger.Close()
			l, e := OpenLedger(m.Config.StateDirectory, m.Config.NodeID)
			if e != nil {
				t.Fatal(e)
			}
			defer l.Close()
			m = &Manager{Config: m.Config, Ledger: l, Runner: m.Runner}
			defer m.Shutdown()
			cleanup := create
			cleanup.OperationID = strings.Repeat("9", 32)
			cleanup.Action, cleanup.ConfirmArtifactID = kind+"_delete", create.ArtifactID
			foreign := cleanup
			foreign.OperationID, foreign.OwnerRef = strings.Repeat("a", 32), strings.Repeat("b", 32)
			if !foreign.DirectPublic.IsZero() {
				foreign.DirectPublic.OwnerRef = foreign.OwnerRef
			}
			assertStorageStatus(t, m, foreign, "rejected")
			want := "succeeded"
			if variant == "inventory_failure" {
				f.fail, want = "list", "uncertain"
			}
			assertStorageStatus(t, m, cleanup, want)
			commands := len(f.commands)
			m.Shutdown()
			l.Close()
			l, e = OpenLedger(m.Config.StateDirectory, m.Config.NodeID)
			if e != nil {
				t.Fatal(e)
			}
			defer l.Close()
			m = &Manager{Config: m.Config, Ledger: l, Runner: m.Runner}
			assertStorageStatus(t, m, cleanup, want)
			if len(f.commands) != commands {
				t.Fatal("artifact cleanup replay repeated commands")
			}
			i, _ := l.Instance(task.InstanceID)
			cpu, mem, disk := l.allocation("")
			if i.State != "deleted" || cpu != 0 || mem != 0 || disk != 0 {
				t.Fatal("artifact cleanup resurrected instance allocation", i.State, cpu, mem, disk)
			}
			reserved, e := l.StorageReservedBytes()
			if e != nil || want == "succeeded" && reserved != 0 || want == "uncertain" && reserved == 0 {
				t.Fatal("artifact reservation disagrees with outcome", reserved, e)
			}
			_, e = os.Stat(filepath.Join(m.Config.Storage.Directory, create.ArtifactID, "disk.qcow2"))
			if want == "succeeded" && !os.IsNotExist(e) || want == "uncertain" && e != nil {
				t.Fatal("artifact disk disagrees with outcome", e)
			}
		})
	}
}

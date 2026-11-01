package hypervisor

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Exercise each rejection after Accept has written quarantine, including the
// duplicate admission guards that can be reached before a detached worker runs.
func TestExecuteRejectionsRestorePreparedInstance(t *testing.T) {
	for _, name := range []string{"maintenance", "ownership", "direct_approval", "direct_detached", "direct_ownership", "direct_running", "delete_disabled", "live_ownership", "ovs_paused", "ovs_crashed", "direct_network", "start_paused", "shutdown_paused", "reboot_off", "force_paused", "delete_running", "delete_files", "unsupported"} {
		t.Run(name, func(t *testing.T) {
			m, f, task := newFixture(t)
			if name == "ovs_paused" || name == "ovs_crashed" {
				var r *ovsRunner
				m, r, _, task = newOVSFixture(t)
				f = r.fakeRunner
			}
			if len(name) >= 7 && name[:7] == "direct_" {
				task = configureDirect(t, m, task)
			}
			if r := submit(t, m, task); r.Status != "succeeded" {
				t.Fatal(r)
			}
			task = next(task, "a", "start")
			prepared, _ := m.Ledger.Instance(task.InstanceID)
			wantCode := "DOMAIN_STATE_REJECTED"
			switch name {
			case "maintenance":
				m.Config.Maintenance = true
				wantCode = "MAINTENANCE"
			case "ownership":
				task.Hostname = "different"
				wantCode = "OWNERSHIP_OR_STATE_REJECTED"
			case "direct_approval":
				m.Config.Network.Gateway = "8.8.8.2"
				wantCode = "DIRECT_PUBLIC_APPROVAL_REJECTED"
			case "direct_detached":
				prepared.DirectPublicDetached = true
				wantCode = "DIRECT_PUBLIC_DETACHED"
			case "direct_ownership", "direct_running":
				task.Action = "public_detach"
				task.ConfirmInstanceID = task.InstanceID
				wantCode = "DIRECT_PUBLIC_REQUIRES_SHUT_OFF"
				if name == "direct_ownership" {
					f.fail = "dumpxml"
					wantCode = "LIVE_OWNERSHIP_UNCONFIRMED"
				}
			case "delete_disabled":
				task.Action = "delete"
				wantCode = "DELETE_DISABLED_OR_UNCONFIRMED"
			case "live_ownership":
				f.fail = "dumpxml"
				wantCode = "LIVE_OWNERSHIP_UNCONFIRMED"
			case "ovs_paused", "start_paused":
				f.states[prepared.Domain] = "paused"
			case "ovs_crashed":
				f.states[prepared.Domain] = "crashed"
			case "direct_network":
				f.fail = "nwfilter-dumpxml"
				wantCode = "DIRECT_PUBLIC_LIVE_NETWORK_UNCONFIRMED"
			case "shutdown_paused":
				task.Action = "shutdown"
				f.states[prepared.Domain] = "paused"
			case "reboot_off":
				task.Action = "reboot"
				f.states[prepared.Domain] = "shut off"
			case "force_paused":
				task.Action = "force_off"
				f.states[prepared.Domain] = "paused"
			case "delete_running", "delete_files":
				task.Action = "delete"
				task.ConfirmInstanceID = task.InstanceID
				m.Config.AllowDelete = true
				wantCode = "DELETE_REQUIRES_POWER_OFF"
				if name == "delete_files" {
					f.states[prepared.Domain] = "shut off"
					wantCode = "DELETE_MANAGED_FILES_UNCONFIRMED"
					if e := os.WriteFile(filepath.Join(prepared.Directory, "customer-data"), []byte("retain"), 0600); e != nil {
						t.Fatal(e)
					}
				}
			case "unsupported":
				task.Action = "unsupported"
				wantCode = "UNSUPPORTED_ACTION"
			}
			result, _, e := m.Ledger.Claim(task, nodeproto.Digest([]byte(name)))
			if e != nil {
				t.Fatal(e)
			}
			quarantine := prepared
			quarantine.State = "uncertain"
			if _, e = m.Ledger.Finish(task.OperationID, "accepted", "MUTATION_IN_FLIGHT", &quarantine); e != nil {
				t.Fatal(e)
			}
			before := len(f.commands)
			result, e = m.execute(context.Background(), task, result, &prepared)
			op, _ := m.Ledger.Query(task.OperationID)
			restored, _ := m.Ledger.Instance(task.InstanceID)
			if e != nil || result.Status != "rejected" || op.ErrorCode != wantCode || !reflect.DeepEqual(restored, prepared) {
				t.Fatalf("result=%+v code=%s restored=%+v error=%v", result, op.ErrorCode, restored, e)
			}
			for _, cmd := range f.commands[before:] {
				for _, verb := range []string{" start ", " shutdown ", " destroy ", " undefine ", " define "} {
					if strings.Contains(cmd, verb) {
						t.Fatal("rejection mutated libvirt", cmd)
					}
				}
			}
		})
	}
}

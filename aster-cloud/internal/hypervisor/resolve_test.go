package hypervisor

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func uncertainReboot(t *testing.T) (*Manager, *fakeRunner, nodeproto.NodeTask) {
	t.Helper()
	m, f, task := newFixture(t)
	if r := submit(t, m, task); r.Status != "succeeded" {
		t.Fatal(r)
	}
	task = next(task, "4", "reboot")
	f.fail = "shutdown"
	if r := submit(t, m, task); r.Status != "uncertain" {
		t.Fatal(r)
	}
	f.fail = ""
	return m, f, task
}
func TestResolvePreservesUnknownHistoryAndSurvivesRestart(t *testing.T) {
	for _, state := range []string{"running", "shut off", "paused", "crashed", "pmsuspended", "blocked"} {
		t.Run(state, func(t *testing.T) {
			m, f, task := uncertainReboot(t)
			f.states["aster-"+task.InstanceID] = state
			old, _ := m.Ledger.Query(task.OperationID)
			before := len(f.commands)
			results, err := m.resolveInstance(context.Background(), task.InstanceID, "Checked original guest console", 0)
			if err != nil || len(results) != 1 {
				t.Fatal(results, err)
			}
			for _, cmd := range f.commands[before:] {
				if !strings.Contains(cmd, " dumpxml ") && !strings.Contains(cmd, " domstate ") {
					t.Fatal("resolution mutated host", cmd)
				}
			}
			op, _ := m.Ledger.Query(task.OperationID)
			if op.Result.Status != "uncertain" || op.ErrorCode != old.ErrorCode || op.Task != old.Task || op.Result.RequestSHA256 != old.Result.RequestSHA256 || op.Result.Resolved == nil || op.Result.Resolved.ObservedState != state || !op.Result.Resolved.Valid() {
				t.Fatal(op)
			}
			// Returned pointers must not mutate persisted history.
			results[0].Resolved.Reason = "changed"
			op.Result.Resolved.Reason = "changed"
			if err = m.Ledger.Close(); err != nil {
				t.Fatal(err)
			}
			ledger, err := OpenLedger(m.Config.StateDirectory, m.Config.NodeID)
			if err != nil {
				t.Fatal(err)
			}
			defer ledger.Close()
			m.Ledger = ledger
			op, _ = ledger.Query(task.OperationID)
			i, _ := ledger.Instance(task.InstanceID)
			if ledger.state.Schema != 6 || op.Result.Resolved.Reason != "Checked original guest console" || i.State != state || ledger.HasPendingInstance(i.ID, "") {
				t.Fatal(op, i)
			}
			before = len(f.commands)
			r, err := m.Reconcile(context.Background(), task.OperationID)
			if err != nil || r.Status != "uncertain" || r.Resolved == nil || len(f.commands) != before {
				t.Fatal("reconciliation rewrote history", r, err)
			}
			if state == "running" {
				if r := submit(t, m, next(task, "5", "force_off")); r.Status != "succeeded" {
					t.Fatal("resolution failed to release admission", r)
				}
			}
		})
	}
}
func TestResolveFailsClosed(t *testing.T) {
	for _, failure := range []string{"nonroot", "reason", "ownership", "state_read", "unknown_state", "active", "storage_pending", "journal_failure"} {
		t.Run(failure, func(t *testing.T) {
			m, f, task := uncertainReboot(t)
			uid := 0
			reason := "Operator reviewed guest"
			switch failure {
			case "nonroot":
				uid = 1000
			case "reason":
				reason = " "
			case "ownership":
				f.domains["aster-"+task.InstanceID] = []byte("<domain/>")
			case "state_read":
				f.fail = "domstate"
			case "unknown_state":
				f.states["aster-"+task.InstanceID] = "unknown"
			case "active":
				m.active = true
				defer func() { m.active = false }()
			case "storage_pending":
				m.Ledger.state.StorageOperations["other"] = StorageOperation{Task: nodeproto.TypedStorageTask{InstanceID: task.InstanceID}, Result: nodeproto.StorageResult{Status: "uncertain"}}
			case "journal_failure":
				m.Ledger.directory = filepath.Join(m.Ledger.directory, "missing")
			}
			if _, err := m.resolveInstance(context.Background(), task.InstanceID, reason, uid); err == nil {
				t.Fatal("unsafe resolution accepted")
			}
			op, _ := m.Ledger.Query(task.OperationID)
			i, _ := m.Ledger.Instance(task.InstanceID)
			if op.Result.Resolved != nil || i.State != "uncertain" {
				t.Fatal("failed resolution cleared quarantine", op, i)
			}
		})
	}
}
func TestResolvedJournalCannotBeDowngradedOrOpenedAsFutureSchema(t *testing.T) {
	for _, schema := range []int{5, 7} {
		t.Run(string(rune('0'+schema)), func(t *testing.T) {
			m, _, task := uncertainReboot(t)
			if _, err := m.resolveInstance(context.Background(), task.InstanceID, "Verified original VM", 0); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(m.Config.StateDirectory, "journal.json")
			if err := m.Ledger.Close(); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var j journal
			if err = json.Unmarshal(raw, &j); err != nil {
				t.Fatal(err)
			}
			j.Schema = schema
			raw, _ = json.Marshal(j)
			if err = os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if l, err := OpenLedger(m.Config.StateDirectory, m.Config.NodeID); err == nil {
				l.Close()
				t.Fatal("unsupported schema accepted")
			}
		})
	}
}

func TestResolveClaimInterruptedBeforeQuarantineWrite(t *testing.T) {
	m, _, task := newFixture(t)
	if r := submit(t, m, task); r.Status != "succeeded" {
		t.Fatal(r)
	}
	task = next(task, "a", "reboot")
	_, sha, _ := task.BytesAndDigest()
	if _, _, err := m.Ledger.Claim(task, sha); err != nil {
		t.Fatal(err)
	}
	// Crash between the initial durable claim and the quarantine update.
	if err := m.Ledger.Close(); err != nil {
		t.Fatal(err)
	}
	l, err := OpenLedger(m.Config.StateDirectory, m.Config.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	m.Ledger = l
	if _, err = m.resolveInstance(context.Background(), task.InstanceID, "Reviewed claim interruption", 0); err != nil {
		t.Fatal(err)
	}
	if m.Ledger.HasPendingInstance(task.InstanceID, "") {
		t.Fatal("claim-only crash cannot be cleared")
	}
}

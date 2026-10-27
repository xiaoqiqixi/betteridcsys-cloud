package hypervisor

import (
	"aster/cloud/internal/nodeproto"
	"aster/cloud/internal/overlayproto"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func overlayRecoveryFixture(t *testing.T, action string) (*Manager, *ovsRunner, *fakeOverlayGate, overlayproto.Task, Operation) {
	t.Helper()
	m, r, g, task := newOverlayFixture(t)
	var old Operation
	for _, op := range m.Ledger.state.Operations {
		old = op
	}
	if action != "" {
		old.Task.Action = action
		if action == "delete" {
			old.Task.ConfirmInstanceID = old.Task.InstanceID
		}
		_, sha, e := old.Task.BytesAndDigest()
		if e != nil {
			t.Fatal(e)
		}
		old.Result.RequestSHA256 = sha
		old.Result.Status = "uncertain"
		old.ErrorCode = "OVS_FINAL_ACK_LOST"
		m.Ledger.mu.Lock()
		m.Ledger.state.Operations[old.Task.OperationID] = old
		i := m.Ledger.state.Instances[old.Task.InstanceID]
		i.State = "uncertain"
		m.Ledger.state.Instances[i.ID] = i
		if e := m.Ledger.save(); e != nil {
			t.Fatal(e)
		}
		m.Ledger.mu.Unlock()
		r.states[i.Domain], r.links[i.Domain] = "paused", "down"
		if action == "shutdown" || action == "force_off" {
			r.states[i.Domain] = "shut off"
		}
	}
	priorSHA := task.SnapshotSHA256
	task.Recovery = &overlayproto.Recovery{Epoch: task.Snapshot.Epoch, SnapshotSHA256: priorSHA, Heads: []overlayproto.Head{{NodeID: task.NodeID, ClusterID: task.Snapshot.ClusterID, Epoch: task.Snapshot.Epoch, SnapshotSHA256: priorSHA}}}
	task.Snapshot.Epoch++
	task.Snapshot.PreviousSHA256 = priorSHA
	var e error
	task.Snapshot, task.SnapshotSHA256, e = overlayproto.CanonicalSnapshot(task.Snapshot)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = task.BytesAndDigest(); e != nil {
		t.Fatal(e)
	}
	return m, r, g, task, old
}

func prepareAndProgramRecovery(t *testing.T, m *Manager, task overlayproto.Task) {
	t.Helper()
	for _, phase := range []string{"prepare", "program"} {
		if got, e := m.ApplyOverlay(context.Background(), phaseTask(task, phase)); e != nil || got.Status != "succeeded" {
			t.Fatalf("%s: %v %v", phase, got, e)
		}
	}
}

func TestOverlayRecoveryCompletesObservedPendingWithoutRepeatingLifecycle(t *testing.T) {
	for _, action := range []string{"create", "start", "shutdown", "force_off", ""} {
		t.Run("action_"+action, func(t *testing.T) {
			m, r, g, task, old := overlayRecoveryFixture(t, action)
			starts, defines := r.count(" start "), r.count(" define ")
			stops := r.count(" shutdown ") + r.count(" destroy ")
			prepareAndProgramRecovery(t, m, task)
			if current, _ := m.Ledger.Query(old.Task.OperationID); current != old {
				t.Fatal("prepare/program completed node result before release")
			}
			release := phaseTask(task, "release")
			got, e := m.ApplyOverlay(context.Background(), release)
			if e != nil || got.Status != "succeeded" {
				t.Fatal(got, e)
			}
			current, _ := m.Ledger.Query(old.Task.OperationID)
			i, _ := m.Ledger.Instance(old.Task.InstanceID)
			want := "running"
			if action == "shutdown" || action == "force_off" {
				want = "shut off"
			}
			if current.Result.Status != "succeeded" || current.Task != old.Task || current.Result.RequestSHA256 != old.Result.RequestSHA256 || i.State != want || r.states[i.Domain] != want || i.Network != old.Task.Network || m.Ledger.HasPendingNetworkProfile(i.Network.ProfileID, "") {
				t.Fatal("original binding/result not converged exactly", current, i.State)
			}
			if action == "" && current != old {
				t.Fatal("drift recovery rewrote old completed operation")
			}
			if starts != r.count(" start ") || defines != r.count(" define ") || stops != r.count(" shutdown ")+r.count(" destroy ") {
				t.Fatal("recovery repeated original VM lifecycle")
			}
			ev, raw, e := m.readOverlayRecovery(release)
			if e != nil || len(raw) == 0 || len(ev.Instances) != 1 || action != "" && (len(ev.Operations) != 1 || ev.Operations[0] != old) {
				t.Fatal("old uncertainty evidence lost", e)
			}
			info, e := os.Stat(m.overlayRecoveryPath(task.SnapshotSHA256, "intent"))
			if e != nil || info.Mode().Perm() != 0600 {
				t.Fatal("recovery evidence not private", e)
			}
			commands, calls := len(r.commands), len(g.calls)
			_, sha, _ := release.BytesAndDigest()
			if replay, e := m.ApplyOverlay(context.Background(), release); e != nil || replay != got {
				t.Fatal("historical POST changed", replay, e)
			}
			if replay, e := m.LookupOverlay(context.Background(), release.OperationID, sha); e != nil || replay != got {
				t.Fatal("historical GET changed", replay, e)
			}
			if len(r.commands) != commands || len(g.calls) != calls {
				t.Fatal("historical replay reran recovery")
			}
			// Atomic original outcomes plus completion survive a process restart.
			directory := m.Ledger.directory
			if e = m.Ledger.Close(); e != nil {
				t.Fatal(e)
			}
			m.Ledger, e = OpenLedger(directory, m.Config.NodeID)
			if e != nil {
				t.Fatal(e)
			}
			defer m.Ledger.Close()
			if replay, e := m.LookupOverlay(context.Background(), release.OperationID, sha); e != nil || replay != got || len(r.commands) != commands {
				t.Fatal("restart did not preserve exact completion", replay, e)
			}
		})
	}
}

func TestOverlayRecoveryRejectsUnobservedOrUnsupportedOriginalOutcome(t *testing.T) {
	for _, action := range []string{"create", "start", "shutdown", "force_off", "delete", "reboot"} {
		t.Run(action, func(t *testing.T) {
			m, r, _, task, old := overlayRecoveryFixture(t, action)
			i, _ := m.Ledger.Instance(old.Task.InstanceID)
			if action == "create" || action == "start" {
				r.states[i.Domain] = "shut off"
			} else {
				r.states[i.Domain] = "paused"
			}
			starts, stops := r.count(" start "), r.count(" destroy ")+r.count(" shutdown ")
			if got, e := m.ApplyOverlay(context.Background(), task); e == nil || got.Status == "succeeded" {
				t.Fatal("unobserved lifecycle adopted", got, e)
			}
			current, _ := m.Ledger.Query(old.Task.OperationID)
			if current != old || r.count(" start ") != starts || r.count(" destroy ")+r.count(" shutdown ") != stops {
				t.Fatal("verification mutated original operation")
			}
		})
	}
}

func TestOverlayRecoveryOrdinaryEpochCannotAdoptPending(t *testing.T) {
	m, _, _, task, old := overlayRecoveryFixture(t, "create")
	task.Recovery = nil
	if got, e := m.ApplyOverlay(context.Background(), task); e == nil || got.Status == "succeeded" {
		t.Fatal("ordinary epoch adopted uncertainty", got, e)
	}
	if current, _ := m.Ledger.Query(old.Task.OperationID); current != old {
		t.Fatal("ordinary epoch completed pending")
	}
}

func TestOverlayRecoveryAllBarriersUseFrozenInventoryCAS(t *testing.T) {
	for _, change := range []string{"instance", "operation", "new_pending", "storage", "resume", "desired", "release"} {
		for _, phase := range []string{"program", "release"} {
			t.Run(change+"_"+phase, func(t *testing.T) {
				m, r, _, task, old := overlayRecoveryFixture(t, "create")
				if _, e := m.ApplyOverlay(context.Background(), phaseTask(task, "prepare")); e != nil {
					t.Fatal(e)
				}
				if phase == "release" {
					if _, e := m.ApplyOverlay(context.Background(), phaseTask(task, "program")); e != nil {
						t.Fatal(e)
					}
				}
				i, _ := m.Ledger.Instance(old.Task.InstanceID)
				m.Ledger.mu.Lock()
				switch change {
				case "instance":
					i.Hostname = "changed"
					m.Ledger.state.Instances[i.ID] = i
				case "operation":
					op := old
					op.ErrorCode = "changed"
					m.Ledger.state.Operations[op.Task.OperationID] = op
				case "new_pending":
					op := old
					op.Task.OperationID = strings.Repeat("e", 32)
					m.Ledger.state.Operations[op.Task.OperationID] = op
				case "storage":
					m.Ledger.state.StorageOperations[strings.Repeat("e", 32)] = StorageOperation{Task: nodeproto.TypedStorageTask{InstanceID: i.ID}, Result: nodeproto.StorageResult{Status: "uncertain"}}
				case "resume":
					r.states[i.Domain], r.links[i.Domain] = "running", "up"
				}
				m.Ledger.mu.Unlock()
				if change == "desired" || change == "release" {
					ev, _, e := m.readOverlayRecovery(phaseTask(task, "release"))
					if e != nil {
						t.Fatal(e)
					}
					if change == "desired" {
						ev.Desired[i.ID] = false
					} else {
						ev.Release[i.ID] = false
					}
					raw, _ := json.Marshal(ev)
					if e = os.WriteFile(m.overlayRecoveryPath(task.SnapshotSHA256, "intent"), raw, 0600); e != nil {
						t.Fatal(e)
					}
				}
				if got, e := m.ApplyOverlay(context.Background(), phaseTask(task, phase)); e == nil || got.Status == "succeeded" {
					t.Fatal("changed phase inventory accepted", got, e)
				}
				if current, _ := m.Ledger.Query(old.Task.OperationID); current.Result.Status != "uncertain" {
					t.Fatal("CAS failure completed original")
				}
				if change == "resume" && (r.states[i.Domain] != "paused" || r.links[i.Domain] != "down") {
					t.Fatal("failed program/release bypassed common fence")
				}
			})
		}
	}
}

func TestOverlayRecoveryFabricReceiptCannotBypassNodeDurableCompletion(t *testing.T) {
	for _, pending := range []bool{true, false} {
		for _, fault := range []string{"result_evidence", "journal_save", "lost_fabric_ack", "missing_intent", "missing_result", "missing_commit", "missing_task"} {
			t.Run(fault+"_pending_"+map[bool]string{true: "yes", false: "no"}[pending], func(t *testing.T) {
				action := ""
				if pending {
					action = "create"
				}
				m, r, g, task, old := overlayRecoveryFixture(t, action)
				prepareAndProgramRecovery(t, m, task)
				release := phaseTask(task, "release")
				switch fault {
				case "result_evidence":
					if e := os.Mkdir(m.overlayRecoveryPath(task.SnapshotSHA256, "result"), 0700); e != nil {
						t.Fatal(e)
					}
				case "journal_save":
					path := filepath.Join(m.Ledger.directory, "journal.json")
					if e := os.Rename(path, path+".prior"); e != nil {
						t.Fatal(e)
					}
					if e := os.Mkdir(path, 0700); e != nil {
						t.Fatal(e)
					}
				case "lost_fabric_ack":
					g.fail = "release"
				}
				got, e := m.ApplyOverlay(context.Background(), release)
				failed := fault == "result_evidence" || fault == "journal_save" || fault == "lost_fabric_ack"
				if failed {
					if e == nil || got.Status != "uncertain" {
						t.Fatal("node failure advertised success", got, e)
					}
					if current, _ := m.Ledger.Query(old.Task.OperationID); current != old {
						t.Fatal("failed commit changed original result")
					}
					i, _ := m.Ledger.Instance(old.Task.InstanceID)
					if r.states[i.Domain] != "paused" || r.links[i.Domain] != "down" {
						t.Fatal("completion failure left guest released")
					}
				} else if e != nil || got.Status != "succeeded" {
					t.Fatal(got, e)
				}
				originalFabric := g.receipts[release.OperationID]
				switch fault {
				case "missing_intent", "missing_result":
					suffix := strings.TrimPrefix(fault, "missing_")
					if e := os.Remove(m.overlayRecoveryPath(task.SnapshotSHA256, suffix)); e != nil {
						t.Fatal(e)
					}
				case "missing_commit":
					m.Ledger.mu.Lock()
					delete(m.Ledger.state.NetworkRecoveries, overlayRecoveryID(task))
					m.Ledger.mu.Unlock()
				case "missing_task":
					if e := os.Remove(m.overlayNodeTaskPath(release.OperationID)); e != nil {
						t.Fatal(e)
					}
				}
				commands, calls := len(r.commands), len(g.calls)
				_, sha, _ := release.BytesAndDigest()
				if visible, e := m.LookupOverlay(context.Background(), release.OperationID, sha); e != nil || visible.Status != "uncertain" {
					t.Fatal("GET manufactured success from fabric receipt", visible, e)
				}
				if fault != "missing_task" {
					if visible, e := m.ApplyOverlay(context.Background(), release); e != nil || visible.Status != "uncertain" {
						t.Fatal("POST replay manufactured success", visible, e)
					}
				}
				if len(r.commands) != commands || len(g.calls) != calls || g.receipts[release.OperationID] != originalFabric {
					t.Fatal("replay mutated host or historical fabric receipt")
				}
			})
		}
	}
}

func TestOverlayRecoveryEvidenceCannotChangeBetweenPhases(t *testing.T) {
	m, _, _, task, _ := overlayRecoveryFixture(t, "create")
	if _, e := m.ApplyOverlay(context.Background(), phaseTask(task, "prepare")); e != nil {
		t.Fatal(e)
	}
	program := phaseTask(task, "program")
	program.Recovery = &overlayproto.Recovery{Epoch: task.Recovery.Epoch, SnapshotSHA256: task.Recovery.SnapshotSHA256, Heads: append([]overlayproto.Head{}, task.Recovery.Heads...)}
	program.Recovery.Heads[0].SnapshotSHA256 = strings.Repeat("f", 64)
	if got, e := m.ApplyOverlay(context.Background(), program); e == nil || got.Status == "succeeded" {
		t.Fatal("changed recovery head accepted", got, e)
	}
}

func TestOverlayRecoveryStoppedOrDisabledEligiblePeerDoesNotResume(t *testing.T) {
	for _, kind := range []string{"stopped", "disabled"} {
		t.Run(kind, func(t *testing.T) {
			m, r, _, task, old := overlayRecoveryFixture(t, "")
			i, _ := m.Ledger.Instance(old.Task.InstanceID)
			if kind == "stopped" {
				m.Ledger.mu.Lock()
				i.State = "shut off"
				m.Ledger.state.Instances[i.ID] = i
				m.Ledger.mu.Unlock()
				r.states[i.Domain] = "shut off"
			} else {
				task.Snapshot.Members[0].Enabled = false
				var e error
				task.Snapshot, task.SnapshotSHA256, e = overlayproto.CanonicalSnapshot(task.Snapshot)
				if e != nil {
					t.Fatal(e)
				}
			}
			prepareAndProgramRecovery(t, m, task)
			if got, e := m.ApplyOverlay(context.Background(), phaseTask(task, "release")); e != nil || got.Status != "succeeded" {
				t.Fatal(got, e)
			}
			want := "shut off"
			if kind == "disabled" {
				want = "paused"
			}
			if r.states[i.Domain] != want {
				t.Fatal("peer was incorrectly resumed", r.states[i.Domain])
			}
			current, _ := m.Ledger.Instance(i.ID)
			if !reflect.DeepEqual(current, i) {
				t.Fatal("drift repair rewrote original ledger state")
			}
		})
	}
}

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

func recoveryGroupFixture(t *testing.T) (*Manager, *ovsRunner, []Operation, map[string]bool) {
	t.Helper()
	m, r, _, a := newOVSFixture(t)
	if got := submit(t, m, a); got.Status != "succeeded" {
		t.Fatal(got)
	}
	b := a
	b.OperationID = strings.Repeat("7", 32)
	b.InstanceID = strings.Repeat("8", 32)
	b.Hostname = "vm-b"
	b.Network.InstanceID = b.InstanceID
	b.Network.LeaseID = strings.Repeat("9", 32)
	b.Network.IPv4 = "10.20.0.11"
	b.Network.MAC = nodeproto.NetworkMAC(b.NodeID, b.InstanceID)
	b.Network.InterfaceID = nodeproto.NetworkInterfaceID(b.InstanceID)
	if got := submit(t, m, b); got.Status != "succeeded" {
		t.Fatal(got)
	}
	// Model an existing two-operation crash journal, not two new admissions.
	// New admissions are separately fenced by the manager's per-profile guard.
	for _, task := range []nodeproto.NodeTask{a, b} {
		i, _ := m.Ledger.Instance(task.InstanceID)
		i.State = "uncertain"
		if _, err := m.Ledger.Finish(task.OperationID, "uncertain", "INTERRUPTED_AFTER_CLAIM", &i); err != nil {
			t.Fatal(err)
		}
		r.states[i.Domain] = "paused"
		r.links[i.Domain] = "down"
	}
	aa, _ := m.Ledger.Query(a.OperationID)
	bb, _ := m.Ledger.Query(b.OperationID)
	return m, r, []Operation{aa, bb}, map[string]bool{a.InstanceID: true, b.InstanceID: true}
}
func TestRecoveryGroupConvergesAllPendingOnceAndPreservesOriginalEvidence(t *testing.T) {
	m, r, old, enabled := recoveryGroupFixture(t)
	ops, instances, err := m.prepareRecoveryGroup(old[0].Task.Network.ProfileID, old[0], enabled)
	if err != nil || len(ops) != 2 || len(instances) != 2 {
		t.Fatal(len(ops), len(instances), err)
	}
	// Both sides used to block each other; recovery uses a single complete group.
	if err = m.verifyRecoveryGroup(context.Background(), ops, instances, enabled); err != nil {
		t.Fatal(err)
	}
	starts := r.count(" start ")
	if err = m.fenceOVSInventory(context.Background(), instances, enabled); err != nil {
		t.Fatal(err)
	}
	if err = m.releaseOVSInventory(context.Background(), instances, enabled); err != nil {
		t.Fatal(err)
	}
	got, err := m.Ledger.FinishNetworkRecovery(strings.Repeat("d", 32), ops, instances, groupTestCommit(strings.Repeat("d", 32), old[0].Task.Network.ProfileID))
	if err != nil || len(got) != 2 {
		t.Fatal(got, err)
	}
	for _, prior := range old {
		current, _ := m.Ledger.Query(prior.Task.OperationID)
		i, _ := m.Ledger.Instance(prior.Task.InstanceID)
		if prior.Result.Status != "uncertain" || current.Task != prior.Task || current.Result.RequestSHA256 != prior.Result.RequestSHA256 || current.Result.Status != "succeeded" || i.State != "running" || i.Network != prior.Task.Network || m.Ledger.HasPendingInstance(i.ID, "") {
			t.Fatal("group result rewrote inputs or left pending", current)
		}
	}
	if r.count(" start ") != starts {
		t.Fatal("original start repeated")
	}
	if _, err = m.Ledger.FinishNetworkRecovery(strings.Repeat("d", 32), ops, instances, groupTestCommit(strings.Repeat("d", 32), old[0].Task.Network.ProfileID)); err == nil {
		t.Fatal("stale group CAS accepted")
	}
	directory, node := m.Ledger.directory, m.Config.NodeID
	if err = m.Ledger.Close(); err != nil {
		t.Fatal(err)
	}
	reloaded, err := OpenLedger(directory, node)
	if err != nil {
		t.Fatal(err)
	}
	defer reloaded.Close()
	for _, prior := range old {
		op, _ := reloaded.Query(prior.Task.OperationID)
		if op.Result.Status != "succeeded" {
			t.Fatal("partial durable commit", op)
		}
	}
}
func TestRecoveryGroupRejectsUnprovableLifecycleStorageAndPartialInventory(t *testing.T) {
	for _, kind := range []string{"reboot", "delete", "storage", "wrong_owner", "wrong_network", "missing_enabled", "unknown_enabled", "peer_untracked_uncertain"} {
		t.Run(kind, func(t *testing.T) {
			m, _, old, enabled := recoveryGroupFixture(t)
			m.Ledger.mu.Lock()
			peer := m.Ledger.state.Operations[old[1].Task.OperationID]
			switch kind {
			case "reboot", "delete":
				peer.Task.Action = kind
				m.Ledger.state.Operations[peer.Task.OperationID] = peer
			case "storage":
				m.Ledger.state.StorageOperations[strings.Repeat("f", 32)] = StorageOperation{Task: nodeproto.TypedStorageTask{InstanceID: peer.Task.InstanceID}, Result: nodeproto.StorageResult{Status: "uncertain"}}
			case "wrong_owner":
				peer.Task.OwnerRef = strings.Repeat("e", 32)
				m.Ledger.state.Operations[peer.Task.OperationID] = peer
			case "wrong_network":
				peer.Task.Network.IPv4 = "10.20.0.12"
				m.Ledger.state.Operations[peer.Task.OperationID] = peer
			case "missing_enabled":
				delete(enabled, peer.Task.InstanceID)
			case "unknown_enabled":
				enabled[strings.Repeat("e", 32)] = true
			case "peer_untracked_uncertain":
				delete(m.Ledger.state.Operations, peer.Task.OperationID)
			}
			m.Ledger.mu.Unlock()
			if _, _, err := m.prepareRecoveryGroup(old[0].Task.Network.ProfileID, old[0], enabled); err == nil {
				t.Fatal("unprovable group accepted", kind)
			}
		})
	}
	m, _, old, enabled := recoveryGroupFixture(t)
	ops, instances, err := m.prepareRecoveryGroup(old[0].Task.Network.ProfileID, old[0], enabled)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Ledger.FinishNetworkRecovery(strings.Repeat("d", 32), ops[:1], instances, groupTestCommit(strings.Repeat("d", 32), old[0].Task.Network.ProfileID)); err == nil {
		t.Fatal("partial operations accepted")
	}
	if _, err = m.Ledger.FinishNetworkRecovery(strings.Repeat("d", 32), ops, instances[:1], groupTestCommit(strings.Repeat("d", 32), old[0].Task.Network.ProfileID)); err == nil {
		t.Fatal("partial inventory accepted")
	}
}
func TestRecoveryGroupDoesNotPretendPausedStopOrStoppedStartCompleted(t *testing.T) {
	for _, action := range []string{"create", "shutdown", "force_off"} {
		t.Run(action, func(t *testing.T) {
			m, r, old, enabled := recoveryGroupFixture(t)
			peer := old[1]
			if action != "create" {
				peer.Task.Action = action
				_, sha, err := peer.Task.BytesAndDigest()
				if err != nil {
					t.Fatal(err)
				}
				peer.Result.RequestSHA256 = sha
				m.Ledger.mu.Lock()
				m.Ledger.state.Operations[peer.Task.OperationID] = peer
				m.Ledger.mu.Unlock()
				delete(enabled, peer.Task.InstanceID)
			} else {
				r.states["aster-"+peer.Task.InstanceID] = "shut off"
			}
			ops, instances, err := m.prepareRecoveryGroup(old[0].Task.Network.ProfileID, old[0], enabled)
			if err != nil {
				t.Fatal(err)
			}
			starts, stops := r.count(" start "), r.count(" shutdown ")+r.count(" destroy ")
			if err = m.verifyRecoveryGroup(context.Background(), ops, instances, enabled); err == nil {
				t.Fatal("wrong actual power state proved")
			}
			if r.count(" start ") != starts || r.count(" shutdown ")+r.count(" destroy ") != stops {
				t.Fatal("verification replayed lifecycle")
			}
			if action != "create" {
				r.states["aster-"+peer.Task.InstanceID] = "shut off"
				if err = m.verifyRecoveryGroup(context.Background(), ops, instances, enabled); err != nil {
					t.Fatal("actual stopped target rejected", err)
				}
			}
		})
	}
}
func TestRecoveryGroupCASAndFailedSaveCannotExposePartialSuccess(t *testing.T) {
	for _, kind := range []string{"changed_operation", "changed_instance", "new_pending", "disk_failure"} {
		t.Run(kind, func(t *testing.T) {
			m, _, old, enabled := recoveryGroupFixture(t)
			ops, instances, err := m.prepareRecoveryGroup(old[0].Task.Network.ProfileID, old[0], enabled)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "disk_failure" {
				path := filepath.Join(m.Ledger.directory, "journal.json")
				if err = os.Rename(path, path+".original"); err != nil {
					t.Fatal(err)
				}
				if err = os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			} else {
				m.Ledger.mu.Lock()
				switch kind {
				case "changed_operation":
					op := m.Ledger.state.Operations[ops[0].Task.OperationID]
					op.ErrorCode = "changed"
					m.Ledger.state.Operations[op.Task.OperationID] = op
				case "changed_instance":
					i := m.Ledger.state.Instances[instances[0].ID]
					i.Hostname = "changed"
					m.Ledger.state.Instances[i.ID] = i
				case "new_pending":
					op := ops[0]
					op.Task.OperationID = strings.Repeat("f", 32)
					op.Result.OperationID = op.Task.OperationID
					m.Ledger.state.Operations[op.Task.OperationID] = op
				}
				m.Ledger.mu.Unlock()
			}
			if _, err = m.Ledger.FinishNetworkRecovery(strings.Repeat("d", 32), ops, instances, groupTestCommit(strings.Repeat("d", 32), old[0].Task.Network.ProfileID)); err == nil {
				t.Fatal("changed/failed group committed")
			}
			for _, op := range ops {
				current, _ := m.Ledger.Query(op.Task.OperationID)
				if current.Result.Status != "uncertain" {
					t.Fatal("partial success visible", current)
				}
			}
			if kind == "disk_failure" && !m.Ledger.poisoned {
				t.Fatal("disk uncertainty not fenced")
			}
		})
	}
}
func TestRecoveryGroupPreservesAlreadySucceededSelectedOperation(t *testing.T) {
	m, _, old, enabled := recoveryGroupFixture(t)
	originalInstance, _ := m.Ledger.Instance(old[0].Task.InstanceID)
	originalInstance.State = "running"
	if _, err := m.Ledger.Finish(old[0].Task.OperationID, "succeeded", "ORIGINAL_SUCCESS", &originalInstance); err != nil {
		t.Fatal(err)
	}
	original, _ := m.Ledger.Query(old[0].Task.OperationID)
	ops, instances, err := m.prepareRecoveryGroup(original.Task.Network.ProfileID, original, enabled)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Ledger.FinishNetworkRecovery(strings.Repeat("d", 32), ops, instances, groupTestCommit(strings.Repeat("d", 32), old[0].Task.Network.ProfileID)); err != nil {
		t.Fatal(err)
	}
	after, _ := m.Ledger.Query(original.Task.OperationID)
	if !reflect.DeepEqual(after, original) {
		t.Fatal("old success rewritten")
	}
}

func groupTestCommit(id, profile string) NetworkRecoveryCommit {
	return NetworkRecoveryCommit{OperationID: id, ProfileID: profile, RequestSHA256: strings.Repeat("a", 64), IntentSHA256: strings.Repeat("b", 64), ResultSHA256: strings.Repeat("c", 64)}
}

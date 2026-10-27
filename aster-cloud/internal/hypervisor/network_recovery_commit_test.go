package hypervisor

import (
	"aster/cloud/internal/nodeproto"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNetworkRecoveryOldSuccessCannotAcknowledgeFailedNewCommit(t *testing.T) {
	for _, oldSuccess := range []bool{true, false} {
		t.Run(map[bool]string{true: "old_success", false: "old_uncertain"}[oldSuccess], func(t *testing.T) {
			m, runner, gate, task, req := recoveryFixture(t, oldSuccess)
			prior, _ := m.Ledger.Query(task.OperationID)
			path := filepath.Join(m.Ledger.directory, "journal.json")
			if err := os.Rename(path, path+".before"); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			if out, err := m.RecoverNetwork(context.Background(), req); err == nil || out != (NetworkRecoveryResult{}) {
				t.Fatal("failed new commit returned success", out, err)
			}
			current, _ := m.Ledger.Query(task.OperationID)
			if current != prior || len(m.Ledger.state.NetworkRecoveries) != 0 || m.Ledger.state.Schema != 3 || !m.Ledger.poisoned {
				t.Fatal("partial recovery state escaped failed atomic save")
			}
			resultPath := filepath.Join(m.Ledger.directory, "network-recovery-"+req.OperationID+".result.json")
			if _, err := os.Stat(resultPath); err != nil {
				t.Fatal("test must have pre-commit result evidence", err)
			}
			i, _ := m.Ledger.Instance(task.InstanceID)
			if runner.states[i.Domain] != "paused" || runner.links[i.Domain] != "down" {
				t.Fatal("failed recovery guest not fenced")
			}
			calls := len(runner.commands)
			if _, err := m.RecoverNetwork(context.Background(), req); err == nil || gate.callsRecovery != 1 || len(runner.commands) != calls {
				t.Fatal("old success/result evidence acknowledged failed new commit or repeated writes", err)
			}
			// A clean reopen of the unchanged old journal cannot turn the orphaned
			// result document into a receipt either.
			dir, node := m.Ledger.directory, m.Config.NodeID
			if err := m.Ledger.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(path+".before", path); err != nil {
				t.Fatal(err)
			}
			fresh, err := OpenLedger(dir, node)
			if err != nil {
				t.Fatal(err)
			}
			defer fresh.Close()
			m.Ledger = fresh
			if _, err = m.RecoverNetwork(context.Background(), req); err == nil || gate.callsRecovery != 1 || len(runner.commands) != calls {
				t.Fatal("reopen manufactured recovery completion", err)
			}
		})
	}
}

func TestNetworkRecoveryAtomicCommitSurvivesRestartAndCannotBeReused(t *testing.T) {
	m, runner, gate, task, req := recoveryFixture(t, false)
	out, err := m.RecoverNetwork(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	commit := m.Ledger.state.NetworkRecoveries[req.OperationID].Commit
	if m.Ledger.state.Schema != 4 || !m.Ledger.NetworkRecoveryCommitted(commit) {
		t.Fatal("missing schema 4 receipt")
	}
	encoded, _ := json.Marshal(m.Ledger.state)
	// The previous OpenLedger gate accepted exactly schemas 1, 2 and 3. Even
	// though encoding/json ignores unknown fields, schema 4 prevents downgrade.
	var oldReader struct {
		Schema int `json:"schema"`
	}
	if json.Unmarshal(encoded, &oldReader) != nil || oldReader.Schema == 1 || oldReader.Schema == 2 || oldReader.Schema == 3 {
		t.Fatal("old binary could accept and erase the new completion map")
	}
	for _, field := range []string{"operation", "profile", "request", "intent", "result"} {
		bad := commit
		switch field {
		case "operation":
			bad.OperationID = strings.Repeat("e", 32)
		case "profile":
			bad.ProfileID = "other"
		case "request":
			bad.RequestSHA256 = strings.Repeat("e", 64)
		case "intent":
			bad.IntentSHA256 = strings.Repeat("e", 64)
		case "result":
			bad.ResultSHA256 = strings.Repeat("e", 64)
		}
		if m.Ledger.NetworkRecoveryCommitted(bad) {
			t.Fatal("receipt accepted changed", field)
		}
	}
	reused := task
	reused.OperationID = req.OperationID
	if _, _, err := m.Ledger.Claim(reused, strings.Repeat("a", 64)); !errors.Is(err, ErrConflict) {
		t.Fatal("node task reused recovery ID", err)
	}
	if _, _, err := m.Ledger.ClaimStorage(nodeproto.TypedStorageTask{OperationID: req.OperationID}, strings.Repeat("a", 64)); !errors.Is(err, ErrConflict) {
		t.Fatal("storage task reused recovery ID", err)
	}
	calls := len(runner.commands)
	dir, node := m.Ledger.directory, m.Config.NodeID
	if err = m.Ledger.Close(); err != nil {
		t.Fatal(err)
	}
	fresh, err := OpenLedger(dir, node)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	m.Ledger = fresh
	if !fresh.NetworkRecoveryCommitted(commit) {
		t.Fatal("receipt lost on restart")
	}
	replay, err := m.RecoverNetwork(context.Background(), req)
	if err != nil || replay != out || gate.callsRecovery != 1 || len(runner.commands) != calls {
		t.Fatal("historical replay changed/wrote", err)
	}
	// A subsequent ordinary network claim must not downgrade and erase schema 4.
	reused.OperationID = strings.Repeat("e", 32)
	_, sha, _ := reused.BytesAndDigest()
	if _, _, err = fresh.Claim(reused, sha); err != nil || fresh.state.Schema != 4 {
		t.Fatal("claim downgraded recovery journal", err)
	}
}

func TestNetworkRecoveryReplayRequiresUntamperedCompleteDocuments(t *testing.T) {
	for _, kind := range []string{"intent_missing", "result_missing", "intent_changed", "result_changed", "result_unknown", "result_duplicate", "result_null", "result_trailing", "receipt_missing"} {
		t.Run(kind, func(t *testing.T) {
			m, runner, gate, _, req := recoveryFixture(t, true)
			if _, err := m.RecoverNetwork(context.Background(), req); err != nil {
				t.Fatal(err)
			}
			intent := filepath.Join(m.Ledger.directory, "network-recovery-"+req.OperationID+".intent.json")
			result := filepath.Join(m.Ledger.directory, "network-recovery-"+req.OperationID+".result.json")
			raw, err := os.ReadFile(result)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "intent_missing":
				// A reused committed ID without its original intent must be rejected
				// before any fabric or libvirt operation, not considered a fresh try.
				if err = os.Remove(intent); err != nil {
					t.Fatal(err)
				}
			case "result_missing":
				if err = os.Remove(result); err != nil {
					t.Fatal(err)
				}
			case "intent_changed":
				b, _ := os.ReadFile(intent)
				var evidence networkRecoveryEvidence
				_ = json.Unmarshal(b, &evidence)
				evidence.Original.ErrorCode = "CHANGED"
				b, _ = json.Marshal(evidence)
				err = os.WriteFile(intent, b, 0600)
			case "result_changed":
				raw = bytes.Replace(raw, []byte(`"revision":0`), []byte(`"revision":1`), 1)
			case "result_unknown":
				raw = append([]byte(`{"unknown":true,`), raw[1:]...)
			case "result_duplicate":
				raw = bytes.Replace(raw, []byte(`"operation_id":`), []byte(`"operation_id":"`+req.OperationID+`","operation_id":`), 1)
			case "result_null":
				raw = []byte("null")
			case "result_trailing":
				raw = append(raw, []byte("{}")...)
			case "receipt_missing":
				delete(m.Ledger.state.NetworkRecoveries, req.OperationID)
			}
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(kind, "result_") && kind != "result_missing" {
				if err = os.WriteFile(result, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			calls := len(runner.commands)
			if _, err = m.RecoverNetwork(context.Background(), req); err == nil || gate.callsRecovery != 1 || len(runner.commands) != calls {
				t.Fatal("changed evidence accepted or replayed host commands", err)
			}
		})
	}
}

func TestNetworkRecoveryJournalSchema4RejectsLostAmbiguousOrInvalidReceipts(t *testing.T) {
	m, _, _, _, req := recoveryFixture(t, false)
	if _, err := m.RecoverNetwork(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	valid, err := os.ReadFile(filepath.Join(m.Ledger.directory, "journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"downgrade", "missing", "null", "empty", "unknown", "duplicate", "bad_id", "bad_sha", "missing_commit", "null_outcomes", "too_many_outcomes", "duplicate_outcomes", "failed_outcome", "changed_outcome", "wrong_profile", "node_collision", "storage_collision", "lost_original_reference"} {
		t.Run(kind, func(t *testing.T) {
			var state journal
			if err := json.Unmarshal(valid, &state); err != nil {
				t.Fatal(err)
			}
			record := state.NetworkRecoveries[req.OperationID]
			switch kind {
			case "downgrade":
				state.Schema = 3
			case "missing", "null", "empty":
				state.NetworkRecoveries = nil
			case "bad_id":
				record.Commit.OperationID = strings.Repeat("e", 32)
			case "bad_sha":
				record.Commit.IntentSHA256 = "bad"
			case "missing_commit":
				record.Commit = NetworkRecoveryCommit{}
			case "null_outcomes":
				record.Outcomes = nil
			case "too_many_outcomes":
				for len(record.Outcomes) < 129 {
					record.Outcomes = append(record.Outcomes, record.Outcomes[0])
				}
			case "duplicate_outcomes":
				record.Outcomes = append(record.Outcomes, record.Outcomes[0])
			case "failed_outcome":
				record.Outcomes[0].Status = "uncertain"
			case "changed_outcome":
				record.Outcomes[0].RequestSHA256 = strings.Repeat("e", 64)
			case "wrong_profile":
				record.Commit.ProfileID = "other"
			case "node_collision":
				op := state.Operations[req.OriginalOperationID]
				op.Task.OperationID, op.Result.OperationID = req.OperationID, req.OperationID
				state.Operations[req.OperationID] = op
			case "storage_collision":
				state.StorageOperations = map[string]StorageOperation{req.OperationID: {}}
			case "lost_original_reference":
				op := state.Operations[req.OriginalOperationID]
				op.ErrorCode = "EXPLICIT_NETWORK_RECOVERY_" + strings.Repeat("e", 32)
				state.Operations[req.OriginalOperationID] = op
			}
			if state.NetworkRecoveries != nil {
				state.NetworkRecoveries[req.OperationID] = record
			}
			raw, _ := json.Marshal(state)
			switch kind {
			case "null":
				raw = append([]byte(`{"network_recoveries":null,`), raw[1:]...)
			case "empty":
				raw = append([]byte(`{"network_recoveries":{},`), raw[1:]...)
			case "unknown":
				raw = append([]byte(`{"unknown":true,`), raw[1:]...)
			case "duplicate":
				raw = bytes.Replace(raw, []byte(`"schema":4`), []byte(`"schema":4,"schema":4`), 1)
			}
			dir := privateDir(t)
			if err = os.WriteFile(filepath.Join(dir, "journal.json"), raw, 0600); err != nil {
				t.Fatal(err)
			}
			loaded, err := OpenLedger(dir, m.Config.NodeID)
			if err == nil {
				loaded.Close()
				t.Fatal("invalid schema 4 journal accepted", kind)
			}
		})
	}
}

func TestRecoveryGroupEmptyCommitRequiresCompleteKnownProfile(t *testing.T) {
	m, _, _, task := newOVSFixture(t)
	commit := groupTestCommit(strings.Repeat("d", 32), task.Network.ProfileID)
	if _, err := m.Ledger.FinishNetworkRecovery(commit.OperationID, nil, nil, commit); err != nil || !m.Ledger.NetworkRecoveryCommitted(commit) {
		t.Fatal("empty bridge receipt failed", err)
	}
	if got := submit(t, m, task); got.Status != "succeeded" {
		t.Fatal(got)
	}
	if m.Ledger.state.Schema != 4 {
		t.Fatal("reserve/claim downgraded schema 4")
	}
	commit.OperationID = strings.Repeat("e", 32)
	if _, err := m.Ledger.FinishNetworkRecovery(commit.OperationID, nil, nil, commit); err == nil {
		t.Fatal("omitted bridge member accepted")
	}
	instances := m.Ledger.Instances()
	if _, err := m.Ledger.FinishNetworkRecovery(commit.OperationID, nil, instances, commit); err != nil {
		t.Fatal("known full inventory commit failed", err)
	}
	commit.OperationID = strings.Repeat("f", 32)
	m.Ledger.mu.Lock()
	i := m.Ledger.state.Instances[task.InstanceID]
	i.State = "uncertain"
	m.Ledger.state.Instances[i.ID] = i
	m.Ledger.mu.Unlock()
	if _, err := m.Ledger.FinishNetworkRecovery(commit.OperationID, nil, m.Ledger.Instances(), commit); err == nil {
		t.Fatal("unknown inventory falsely completed")
	}
}

func TestRecoveryGroupMissingPendingInstanceCannotBeOmittedAsEmptyBridge(t *testing.T) {
	m, _, old, enabled := recoveryGroupFixture(t)
	m.Ledger.mu.Lock()
	delete(m.Ledger.state.Instances, old[1].Task.InstanceID)
	m.Ledger.mu.Unlock()
	delete(enabled, old[1].Task.InstanceID)
	if _, _, err := m.prepareRecoveryGroup(old[0].Task.Network.ProfileID, old[0], enabled); err == nil {
		t.Fatal("pending peer without inventory silently omitted")
	}
	m.Ledger.mu.Lock()
	delete(m.Ledger.state.Instances, old[0].Task.InstanceID)
	m.Ledger.mu.Unlock()
	commit := groupTestCommit(strings.Repeat("d", 32), old[0].Task.Network.ProfileID)
	if _, err := m.Ledger.FinishNetworkRecovery(commit.OperationID, nil, nil, commit); err == nil {
		t.Fatal("empty bridge ignored unresolved profile operations")
	}
}

func TestNetworkRecoveryNewIDCollisionRejectedBeforeHostMutation(t *testing.T) {
	for _, kind := range []string{"node", "storage", "orphan_result"} {
		t.Run(kind, func(t *testing.T) {
			m, runner, gate, task, req := recoveryFixture(t, true)
			switch kind {
			case "node":
				other := task
				other.OperationID = req.OperationID
				_, sha, _ := other.BytesAndDigest()
				if _, _, err := m.Ledger.Claim(other, sha); err != nil {
					t.Fatal(err)
				}
			case "storage":
				m.Ledger.mu.Lock()
				m.Ledger.state.StorageOperations[req.OperationID] = StorageOperation{}
				m.Ledger.mu.Unlock()
			case "orphan_result":
				path := filepath.Join(m.Ledger.directory, "network-recovery-"+req.OperationID+".result.json")
				if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			calls := len(runner.commands)
			if _, err := m.RecoverNetwork(context.Background(), req); err == nil || gate.callsRecovery != 0 || len(runner.commands) != calls {
				t.Fatal("ID/evidence collision issued host mutation", err)
			}
		})
	}
}

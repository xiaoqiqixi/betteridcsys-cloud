package hypervisor

import (
	"aster/cloud/internal/nodeproto"
	"path/filepath"
	"testing"
)

func TestJournalTemporaryFileFailureFencesAllMutationAdmission(t *testing.T) {
	for _, stage := range []string{"claim", "finish"} {
		t.Run(stage, func(t *testing.T) {
			m, f, task := newFixture(t)
			_, sha, err := task.BytesAndDigest()
			if err != nil {
				t.Fatal(err)
			}
			if stage == "finish" {
				if _, _, err = m.Ledger.Claim(task, sha); err != nil {
					t.Fatal(err)
				}
			}
			directory := m.Ledger.directory
			m.Ledger.directory = filepath.Join(directory, "missing-parent")
			if stage == "claim" {
				_, _, err = m.Ledger.Claim(task, sha)
			} else {
				_, err = m.Ledger.Finish(task.OperationID, "succeeded", "", nil)
			}
			m.Ledger.directory = directory
			if err == nil || !m.Ledger.poisoned {
				t.Fatal("early journal failure did not fence the node", err)
			}
			// Restoring filesystem availability must not publish uncommitted
			// state or authorize another power/storage command in this process.
			fresh := next(task, "9", "create")
			raw, _, _ := fresh.BytesAndDigest()
			if _, err = m.Accept(fresh, raw); err == nil {
				t.Fatal("power admission survived journal failure")
			}
			storage := nodeproto.TypedStorageTask{Protocol: nodeproto.StorageProtocol, OperationID: fresh.OperationID, NodeID: task.NodeID, Action: "snapshot_create", InstanceID: task.InstanceID, OwnerRef: task.OwnerRef, ArtifactID: fresh.OperationID}
			raw, _, err = storage.BytesAndDigest()
			if err != nil {
				t.Fatal(err)
			}
			if _, err = m.AcceptStorage(storage, raw); err == nil {
				t.Fatal("storage admission survived journal failure")
			}
			if len(f.commands) != 0 {
				t.Fatal("uncommitted intent executed host commands")
			}
			if err = m.Ledger.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := OpenLedger(directory, m.Config.NodeID)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			op, exists := reopened.Query(task.OperationID)
			if stage == "claim" && exists || stage == "finish" && (!exists || op.Result.Status != "uncertain") {
				t.Fatal("restart did not recover last durable intent", exists, op.Result)
			}
		})
	}
}

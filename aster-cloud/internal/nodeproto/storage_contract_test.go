package nodeproto

import (
	"encoding/json"
	"strings"
	"testing"
)

func storageFixture() TypedStorageTask {
	return TypedStorageTask{Protocol: StorageProtocol, OperationID: strings.Repeat("4", 32), NodeID: "node-a", Action: "backup_create", InstanceID: strings.Repeat("2", 32), OwnerRef: strings.Repeat("3", 32), ArtifactID: strings.Repeat("5", 32)}
}
func TestStorageProtocolStrictIndependentWire(t *testing.T) {
	task := storageFixture()
	raw, sha, e := task.BytesAndDigest()
	if e != nil {
		t.Fatal(e)
	}
	decoded, e := DecodeStorageTask(raw)
	if e != nil || decoded != task {
		t.Fatal(e)
	}
	if _, e := DecodeTask(raw); e == nil {
		t.Fatal("storage accepted as old power protocol")
	}
	r := StorageResult{Protocol: StorageProtocol, OperationID: task.OperationID, RequestSHA256: sha, Status: "accepted", InstanceID: task.InstanceID, ArtifactID: task.ArtifactID, Items: []StorageArtifact{}}
	if !r.Matches(task, sha) {
		t.Fatal(r)
	}
	s := string(raw)
	for name, bad := range map[string]string{"unknown_url": strings.TrimSuffix(s, "}") + `,"url":"https://evil.invalid"}`, "wrongcase": strings.Replace(s, `"artifact_id"`, `"Artifact_ID"`, 1), "duplicate": strings.Replace(s, `"artifact_id":`, `"artifact_id":"`+task.ArtifactID+`","artifact_id":`, 1), "null": strings.Replace(s, `"fence_token":""`, `"fence_token":null`, 1), "missing": strings.Replace(s, `,"source_node_id":""`, "", 1), "trailing": s + "{}", "oversize": s + strings.Repeat(" ", 65536)} {
		t.Run(name, func(t *testing.T) {
			if _, e := DecodeStorageTask([]byte(bad)); e == nil {
				t.Fatal("ambiguous storage task accepted")
			}
		})
	}
}
func TestStorageActionBindingsNoPathsOrBooleanFencing(t *testing.T) {
	for name, mutate := range map[string]func(*TypedStorageTask){"path": func(t *TypedStorageTask) { t.ArtifactID = "../../disk" }, "VM0": func(t *TypedStorageTask) { t.InstanceID = "0" }, "irrelevant_target": func(t *TypedStorageTask) { t.TargetNodeID = "node-b" }, "restore_no_confirm": func(t *TypedStorageTask) { t.Action = "backup_restore" }, "remote_command": func(t *TypedStorageTask) { t.Action = "scp" }} {
		t.Run(name, func(t *testing.T) {
			x := storageFixture()
			mutate(&x)
			if x.Valid() {
				t.Fatal("unsafe task")
			}
		})
	}
	x := storageFixture()
	x.Action = "migrate_prepare"
	x.TargetNodeID = "node-b"
	if !x.Valid() {
		t.Fatal(x)
	}
	x.Action = "migrate_import"
	x.NodeID = "node-b"
	x.SourceNodeID = "node-a"
	x.SourceOperationID = strings.Repeat("6", 32)
	x.ManifestSHA256 = strings.Repeat("a", 64)
	x.FenceToken = strings.Repeat("b", 64)
	if !x.Valid() {
		t.Fatal(x)
	}
	x.Action = "migrate_activate"
	if x.Valid() {
		t.Fatal("unconfirmed activate")
	}
	x.ConfirmArtifactID = x.ArtifactID
	if !x.Valid() {
		t.Fatal(x)
	}
	raw, _ := json.Marshal(x)
	raw = []byte(strings.TrimSuffix(string(raw), "}") + `,"source_fenced":true}`)
	if _, e := DecodeStorageTask(raw); e == nil {
		t.Fatal("user source_fenced bool trusted")
	}
}

package nodeproto

import (
	"encoding/json"
	"strings"
	"testing"
)

func directFixture() NodeTask {
	t := fixture()
	t.Protocol = DirectPublicProtocol
	t.DirectPublic = DirectPublicBinding{Generation: 1, Schema: 1, LeaseID: strings.Repeat("4", 32), PoolID: strings.Repeat("5", 32), NodeID: t.NodeID, OwnerRef: t.OwnerRef, InstanceID: t.InstanceID, ProfileID: DirectPublicProfile, ProfileSHA256: strings.Repeat("a", 64), CIDR: "8.8.8.0/24", Gateway: "8.8.8.1", IPv4: "8.8.8.8", MAC: "52:54:00:12:34:56"}
	return t
}
func TestDirectPublicExplicitProtocolAndOldBytes(t *testing.T) {
	tsk := directFixture()
	raw, _, e := tsk.BytesAndDigest()
	if e != nil {
		t.Fatal(e)
	}
	out, e := DecodeTask(raw)
	if e != nil || out != tsk {
		t.Fatal(e, string(raw))
	}
	for _, version := range []string{Protocol, NetworkProtocol} {
		bad := tsk
		bad.Protocol = version
		if bad.Valid() {
			t.Fatal("old protocol silently accepted direct binding")
		}
	}
	old := fixture()
	raw, _, _ = old.BytesAndDigest()
	if strings.Contains(string(raw), "direct_public") {
		t.Fatal("old canonical bytes changed")
	}
	for _, action := range []string{"public_adopt", "public_detach"} {
		tsk.Action = action
		if tsk.Valid() {
			t.Fatal("missing typed instance confirmation")
		}
		tsk.ConfirmInstanceID = tsk.InstanceID
		if !tsk.Valid() {
			t.Fatal(action)
		}
		tsk.ConfirmInstanceID = ""
	}
}
func TestDirectPublicRejectsEveryChangedBoundary(t *testing.T) {
	for name, edit := range map[string]func(*DirectPublicBinding){"private": func(b *DirectPublicBinding) { b.IPv4 = "10.0.0.1" }, "metadata": func(b *DirectPublicBinding) { b.IPv4 = "169.254.169.254" }, "documentation": func(b *DirectPublicBinding) { b.IPv4 = "192.0.2.8" }, "outside": func(b *DirectPublicBinding) { b.IPv4 = "9.9.9.9" }, "gateway": func(b *DirectPublicBinding) { b.IPv4 = b.Gateway }, "broadcast": func(b *DirectPublicBinding) { b.IPv4 = "8.8.8.255" }, "owner": func(b *DirectPublicBinding) { b.OwnerRef = strings.Repeat("6", 32) }, "node": func(b *DirectPublicBinding) { b.NodeID = "node-b" }, "multicast_mac": func(b *DirectPublicBinding) { b.MAC = "53:54:00:00:00:01" }, "global_mac": func(b *DirectPublicBinding) { b.MAC = "50:54:00:00:00:01" }, "wrong_profile": func(b *DirectPublicBinding) { b.ProfileID = "shell" }, "host_cidr": func(b *DirectPublicBinding) { b.CIDR = "8.8.8.8/24" }} {
		t.Run(name, func(t *testing.T) {
			task := directFixture()
			edit(&task.DirectPublic)
			if task.Valid() {
				t.Fatal("accepted changed boundary")
			}
		})
	}
	task := directFixture()
	raw, _, _ := task.BytesAndDigest()
	for _, bad := range []string{strings.Replace(string(raw), `"schema":1`, `"schema":1,"schema":1`, 1), strings.Replace(string(raw), `"gateway":`, `"Gateway":`, 1), strings.Replace(string(raw), `"gateway":`, `"command":"id","gateway":`, 1), strings.Replace(string(raw), `"schema":1`, `"schema":null`, 1)} {
		if _, e := DecodeTask([]byte(bad)); e == nil {
			t.Fatal("ambiguous direct binding accepted", bad)
		}
	}
}
func TestDirectStorageExplicitBindingAndStableIdentity(t *testing.T) {
	n := directFixture()
	task := TypedStorageTask{Protocol: StorageDirectProtocol, OperationID: n.OperationID, NodeID: n.NodeID, Action: "migrate_prepare", InstanceID: n.InstanceID, OwnerRef: n.OwnerRef, ArtifactID: strings.Repeat("6", 32), TargetNodeID: "node-b", DirectPublic: n.DirectPublic}
	raw, sha, e := task.BytesAndDigest()
	if e != nil {
		t.Fatal(e)
	}
	out, e := DecodeStorageTask(raw)
	if e != nil || out != task {
		t.Fatal(e, string(raw))
	}
	r := StorageResult{Protocol: StorageDirectProtocol, OperationID: task.OperationID, InstanceID: task.InstanceID, ArtifactID: task.ArtifactID, RequestSHA256: sha, Status: "succeeded", SourceNodeID: task.NodeID, TargetNodeID: task.TargetNodeID, ManifestSHA256: strings.Repeat("a", 64), FenceToken: strings.Repeat("b", 64), Items: []StorageArtifact{}}
	if !r.Matches(task, sha) {
		t.Fatal("storage2 receipt mismatch")
	}
	r.Protocol = StorageProtocol
	if r.Matches(task, sha) {
		t.Fatal("storage1 receipt upgraded")
	}
	target := n.DirectPublic
	target.NodeID = "node-b"
	if !SameDirectAddress(n.DirectPublic, target) {
		t.Fatal("placement-only relocation rejected")
	}
	target.IPv4 = "8.8.8.9"
	if SameDirectAddress(n.DirectPublic, target) {
		t.Fatal("silent IP rotation")
	}
	old := task
	old.Protocol = StorageProtocol
	old.DirectPublic = DirectPublicBinding{}
	raw, _ = json.Marshal(old)
	if strings.Contains(string(raw), "direct_public") {
		t.Fatal("legacy storage bytes changed")
	}
}

func TestDirectStorageReceiptBindsEveryMigrationPlacementAndFence(t *testing.T) {
	n := directFixture()
	for _, action := range []string{"migrate_import", "migrate_activate", "migrate_retire_source"} {
		t.Run(action, func(t *testing.T) {
			task := TypedStorageTask{Protocol: StorageDirectProtocol, OperationID: n.OperationID, NodeID: n.NodeID, Action: action, InstanceID: n.InstanceID, OwnerRef: n.OwnerRef, ArtifactID: strings.Repeat("6", 32), TargetNodeID: n.NodeID, SourceNodeID: "node-b", SourceOperationID: strings.Repeat("7", 32), ManifestSHA256: strings.Repeat("a", 64), FenceToken: strings.Repeat("b", 64), DirectPublic: n.DirectPublic}
			if action == "migrate_activate" {
				task.ConfirmArtifactID = task.ArtifactID
			}
			if action == "migrate_retire_source" {
				task.SourceNodeID = n.NodeID
				task.TargetNodeID = "node-b"
				task.ConfirmArtifactID = task.ArtifactID
				task.RetireProof = PublicRetireProof{ActivateOperationID: strings.Repeat("8", 32), ActivateRequestSHA256: strings.Repeat("c", 64), TargetProfileSHA256: task.DirectPublic.ProfileSHA256, TargetGeneration: task.DirectPublic.Generation + 1, ConfirmInstanceID: task.InstanceID}
				proofReceipt := StorageResult{Protocol: StorageDirectProtocol, OperationID: task.RetireProof.ActivateOperationID, RequestSHA256: task.RetireProof.ActivateRequestSHA256, Status: "succeeded", InstanceID: task.InstanceID, ArtifactID: task.ArtifactID, ManifestSHA256: task.ManifestSHA256, FenceToken: task.FenceToken, SourceNodeID: task.NodeID, TargetNodeID: task.TargetNodeID, Items: []StorageArtifact{}}
				raw, _ := json.Marshal(proofReceipt)
				task.RetireProof.ActivateReceiptSHA256 = Digest(raw)
			}
			_, sha, e := task.BytesAndDigest()
			if e != nil {
				t.Fatal(e)
			}
			result := StorageResult{Protocol: task.Protocol, OperationID: task.OperationID, RequestSHA256: sha, Status: "succeeded", InstanceID: task.InstanceID, ArtifactID: task.ArtifactID, SourceNodeID: task.SourceNodeID, TargetNodeID: task.TargetNodeID, ManifestSHA256: task.ManifestSHA256, FenceToken: task.FenceToken, Items: []StorageArtifact{}}
			if !result.Matches(task, sha) {
				t.Fatal("correct frozen receipt rejected")
			}
			for name, edit := range map[string]func(*StorageResult){"source": func(r *StorageResult) { r.SourceNodeID = "foreign-node" }, "target": func(r *StorageResult) { r.TargetNodeID = "foreign-node" }, "manifest": func(r *StorageResult) { r.ManifestSHA256 = strings.Repeat("f", 64) }, "fence": func(r *StorageResult) { r.FenceToken = strings.Repeat("f", 64) }, "null_items": func(r *StorageResult) { r.Items = nil }, "artifact_items": func(r *StorageResult) { r.Items = []StorageArtifact{{ArtifactID: task.ArtifactID}} }, "unknown_status": func(r *StorageResult) { r.Status = "paid" }} {
				t.Run(name, func(t *testing.T) {
					bad := result
					edit(&bad)
					if bad.Matches(task, sha) {
						t.Fatal("unbound migration receipt accepted")
					}
				})
			}
			legacy := task
			legacy.Protocol = StorageProtocol
			legacy.DirectPublic = DirectPublicBinding{}
			legacy.RetireProof = PublicRetireProof{}
			if action != "migrate_retire_source" {
				bad := result
				bad.Protocol = StorageProtocol
				bad.FenceToken = "legacy-placeholder"
				if !bad.Matches(legacy, sha) {
					t.Fatal("legacy storage1 matching semantics silently changed")
				}
			}
		})
	}
}

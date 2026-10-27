package hypervisor

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func newStorageFixture(t *testing.T, node string) (*Manager, *fakeRunner, nodeproto.NodeTask) {
	t.Helper()
	m, f, task := newFixture(t)
	if node != m.Config.NodeID {
		_ = m.Ledger.Close()
		m.Config.NodeID = node
		m.Config.StateDirectory = filepath.Join(filepath.Dir(m.Config.StateDirectory), "state-"+node)
		l, e := OpenLedger(m.Config.StateDirectory, node)
		if e != nil {
			t.Fatal(e)
		}
		m.Ledger = l
		t.Cleanup(func() { m.Shutdown(); l.Close() })
		task.NodeID = node
		task.Resources.ComputeNodeID = node
	}
	root := privateDir(t)
	m.Config.Storage = StorageConfig{Enabled: true, Directory: filepath.Join(root, "artifacts"), InboxDirectory: filepath.Join(root, "inbox"), MaxArtifactBytes: 32 << 30, MaxTotalBytes: 128 << 30, AllowMigration: true, SourceCertificatePins: map[string]string{}}
	for _, p := range []string{m.Config.Storage.Directory, m.Config.Storage.InboxDirectory} {
		if e := os.Mkdir(p, 0700); e != nil {
			t.Fatal(e)
		}
	}
	certs := certificates(t)
	for p, raw := range map[string][]byte{m.Config.Certificate: certs.serverCert, m.Config.PrivateKey: certs.serverKey, m.Config.ControllerCA: certs.ca} {
		if e := os.WriteFile(p, raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := m.Config.Validate(); e != nil {
		t.Fatal(e)
	}
	return m, f, task
}
func storageTask(task nodeproto.NodeTask, op int, action string, artifact int) nodeproto.TypedStorageTask {
	id := ""
	if artifact != 0 {
		id = fmt.Sprintf("%032x", artifact)
	}
	s := nodeproto.TypedStorageTask{Protocol: nodeproto.StorageProtocol, OperationID: fmt.Sprintf("%032x", op), NodeID: task.NodeID, Action: action, InstanceID: task.InstanceID, OwnerRef: task.OwnerRef, ArtifactID: id}
	if strings.HasSuffix(action, "_restore") || strings.HasSuffix(action, "_delete") {
		s.ConfirmArtifactID = id
	}
	return s
}
func waitStorage(t *testing.T, m *Manager, task nodeproto.TypedStorageTask) nodeproto.StorageResult {
	t.Helper()
	raw, _, e := task.BytesAndDigest()
	if e != nil {
		t.Fatal(task, e)
	}
	r, e := m.AcceptStorage(task, raw)
	if e != nil {
		t.Fatal(e)
	}
	deadline := time.After(5 * time.Second)
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for r.Status == "accepted" {
		select {
		case <-deadline:
			t.Fatal("storage result timeout", task)
		case <-tick.C:
			r, _ = m.LookupStorage(task.OperationID)
		}
	}
	return r
}
func createOff(t *testing.T, m *Manager, task nodeproto.NodeTask) {
	t.Helper()
	if r := submit(t, m, task); r.Status != "succeeded" {
		t.Fatal(r)
	}
	if r := submit(t, m, next(task, "4", "force_off")); r.Status != "succeeded" {
		t.Fatal(r)
	}
}
func assertStorageStatus(t *testing.T, m *Manager, task nodeproto.TypedStorageTask, want string) nodeproto.StorageResult {
	t.Helper()
	r := waitStorage(t, m, task)
	if r.Status != want {
		op, _ := m.Ledger.QueryStorage(task.OperationID)
		t.Fatalf("action=%s result=%+v code=%s want=%s", task.Action, r, op.ErrorCode, want)
	}
	return r
}
func TestOfflineSnapshotBackupRestoreLifecycleAndPreservedOriginal(t *testing.T) {
	m, f, task := newStorageFixture(t, "node-a")
	createOff(t, m, task)
	i, _ := m.Ledger.Instance(task.InstanceID)
	original, e := os.ReadFile(i.Disk)
	if e != nil {
		t.Fatal(e)
	}
	snap := storageTask(task, 10, "snapshot_create", 100)
	s := assertStorageStatus(t, m, snap, "succeeded")
	if len(s.Items) != 1 || s.ManifestSHA256 == "" {
		t.Fatal(s)
	}
	backup := storageTask(task, 11, "backup_create", 101)
	assertStorageStatus(t, m, backup, "succeeded")
	assertStorageStatus(t, m, storageTask(task, 12, "backup_verify", 101), "succeeded")
	modified := []byte("synthetic changed guest data")
	if e = os.WriteFile(i.Disk, modified, 0600); e != nil {
		t.Fatal(e)
	}
	restore := storageTask(task, 13, "backup_restore", 101)
	assertStorageStatus(t, m, restore, "succeeded")
	after, e := os.ReadFile(i.Disk)
	if e != nil || string(after) != string(original) {
		t.Fatal("replacement disk bytes", e)
	}
	op, _ := m.Ledger.QueryStorage(restore.OperationID)
	if op.Recovery == nil {
		t.Fatal("no durable original preservation")
	}
	previous, e := os.ReadFile(filepath.Join(i.Directory, op.Recovery.PreviousDiskName))
	if e != nil || string(previous) != string(modified) || op.Recovery.PreviousDiskSHA256 != nodeproto.Digest(modified) {
		t.Fatal("old disk not retained", e)
	}
	listing := assertStorageStatus(t, m, storageTask(task, 14, "snapshot_list", 0), "succeeded")
	if len(listing.Items) != 1 || listing.Items[0].ArtifactID != snap.ArtifactID {
		t.Fatal(listing)
	}
	assertStorageStatus(t, m, storageTask(task, 15, "snapshot_restore", 100), "succeeded")
	assertStorageStatus(t, m, storageTask(task, 16, "snapshot_delete", 100), "succeeded")
	assertStorageStatus(t, m, storageTask(task, 17, "backup_delete", 101), "succeeded")
	if f.count(" convert ") != 2 || f.count(" start ") != 1 {
		t.Fatal("unexpected qemu/VM operations", f.commands)
	}
}
func TestStorageNeverInvokesQemuImgForRunningDomain(t *testing.T) {
	m, f, task := newStorageFixture(t, "node-a")
	if r := submit(t, m, task); r.Status != "succeeded" {
		t.Fatal(r)
	}
	before := f.count(QemuImg)
	assertStorageStatus(t, m, storageTask(task, 10, "backup_create", 100), "rejected")
	if f.count(QemuImg) != before {
		t.Fatal("qemu-img touched running guest")
	}
	i, _ := m.Ledger.Instance(task.InstanceID)
	if i.State != "running" {
		t.Fatal(i)
	}
}
func TestStorageClaimDurableBeforeDiskOperationAndSharesPowerSlot(t *testing.T) {
	m, f, task := newStorageFixture(t, "node-a")
	createOff(t, m, task)
	st := storageTask(task, 10, "snapshot_create", 100)
	var once sync.Once
	f.before = func(string) {
		once.Do(func() {
			raw, e := readApproved(filepath.Join(m.Config.StateDirectory, "journal.json"), true, maxJournalBytes)
			var state journal
			if e != nil || json.Unmarshal(raw, &state) != nil || state.StorageOperations[st.OperationID].Result.Status != "accepted" || state.Instances[task.InstanceID].State != "uncertain" {
				t.Error("storage claim not durable before exec", e)
			}
		})
	}
	gate := make(chan struct{})
	f.block = gate
	raw, _, _ := st.BytesAndDigest()
	r, e := m.AcceptStorage(st, raw)
	if e != nil || r.Status != "accepted" {
		t.Fatal(r, e)
	}
	power := next(task, "5", "start")
	if result := submit(t, m, power); result.Status != "rejected" {
		t.Fatal("power overlapped storage", result)
	}
	if _, e = m.AcceptStorage(st, append(raw, ' ')); !errors.Is(e, ErrConflict) {
		t.Fatal("different raw replay", e)
	}
	close(gate)
	assertStorageStatus(t, m, st, "succeeded")
	before := f.count(" convert ")
	assertStorageStatus(t, m, st, "succeeded")
	if f.count(" convert ") != before {
		t.Fatal("storage replay reran copy")
	}
}
func TestStorageRestoreFailurePreservesOriginalAndRemainsUnknown(t *testing.T) {
	for _, point := range []string{"restore_before_preserve", "restore_after_preserve", "restore_after_swap"} {
		t.Run(point, func(t *testing.T) {
			m, _, task := newStorageFixture(t, "node-a")
			createOff(t, m, task)
			assertStorageStatus(t, m, storageTask(task, 10, "backup_create", 100), "succeeded")
			i, _ := m.Ledger.Instance(task.InstanceID)
			modified := []byte("newer guest content")
			_ = os.WriteFile(i.Disk, modified, 0600)
			m.storageFS = func(stage string) error {
				if stage == point {
					return errors.New("injected fsync/rename boundary failure")
				}
				return nil
			}
			restore := storageTask(task, 11, "backup_restore", 100)
			assertStorageStatus(t, m, restore, "uncertain")
			i, _ = m.Ledger.Instance(task.InstanceID)
			if i.State != "uncertain" {
				t.Fatal(i)
			}
			op, _ := m.Ledger.QueryStorage(restore.OperationID)
			if op.Recovery == nil {
				t.Fatal("missing recovery intent")
			}
			if point != "restore_before_preserve" {
				data, e := os.ReadFile(filepath.Join(i.Directory, op.Recovery.PreviousDiskName))
				if e != nil || string(data) != string(modified) {
					t.Fatal("original disk lost", e)
				}
			}
			assertStorageStatus(t, m, restore, "uncertain")
			if result := submit(t, m, next(task, "5", "start")); result.Status != "rejected" {
				t.Fatal("unknown restore allowed start")
			}
		})
	}
}
func TestArtifactVerificationRejectsMissingTamperedLinkedOrBackingDisk(t *testing.T) {
	for _, kind := range []string{"missing_manifest", "manifest_tamper", "disk_tamper", "symlink", "hardlink", "external_backing", "qemu_check_error"} {
		t.Run(kind, func(t *testing.T) {
			m, f, task := newStorageFixture(t, "node-a")
			createOff(t, m, task)
			s := storageTask(task, 10, "backup_create", 100)
			assertStorageStatus(t, m, s, "succeeded")
			dir := filepath.Join(m.Config.Storage.Directory, s.ArtifactID)
			disk := filepath.Join(dir, "disk.qcow2")
			switch kind {
			case "missing_manifest":
				_ = os.Remove(filepath.Join(dir, "manifest.json"))
			case "manifest_tamper":
				raw, _ := os.ReadFile(filepath.Join(dir, "manifest.json"))
				_ = os.WriteFile(filepath.Join(dir, "manifest.json"), append(raw, ' '), 0600)
			case "disk_tamper":
				_ = os.WriteFile(disk, []byte("not approved bytes"), 0600)
			case "symlink":
				_ = os.Remove(disk)
				i, _ := m.Ledger.Instance(task.InstanceID)
				_ = os.Symlink(i.Disk, disk)
			case "hardlink":
				_ = os.Link(disk, filepath.Join(dir, "alias"))
			case "external_backing":
				f.info = `{"format":"qcow2","virtual-size":1073741824,"backing-filename":"/etc/passwd"}`
			case "qemu_check_error":
				f.fail = "check"
			}
			assertStorageStatus(t, m, storageTask(task, 11, "backup_verify", 100), "uncertain")
			if f.count(" start ") != 1 {
				t.Fatal("verification booted anything")
			}
		})
	}
}
func TestStorageForeignOwnerNeverTouchesDisk(t *testing.T) {
	m, f, task := newStorageFixture(t, "node-a")
	createOff(t, m, task)
	s := storageTask(task, 10, "backup_create", 100)
	s.OwnerRef = strings.Repeat("9", 32)
	before := len(f.commands)
	assertStorageStatus(t, m, s, "rejected")
	if len(f.commands) != before {
		t.Fatal("foreign owner reached host")
	}
}
func exportFixture(t *testing.T) (*Manager, *fakeRunner, nodeproto.NodeTask, nodeproto.TypedStorageTask, nodeproto.StorageResult) {
	t.Helper()
	m, f, task := newStorageFixture(t, "node-a")
	createOff(t, m, task)
	export := storageTask(task, 10, "migrate_prepare", 100)
	export.TargetNodeID = "node-b"
	r := assertStorageStatus(t, m, export, "succeeded")
	return m, f, task, export, r
}
func handoffFixture(t *testing.T, source, target *Manager, export nodeproto.TypedStorageTask, result nodeproto.StorageResult) nodeproto.TypedStorageTask {
	t.Helper()
	dir := filepath.Join(target.Config.Storage.InboxDirectory, export.ArtifactID)
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"disk.qcow2", "manifest.json"} {
		body, e := os.ReadFile(filepath.Join(source.Config.Storage.Directory, export.ArtifactID, name))
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, name), body, 0600); e != nil {
			t.Fatal(e)
		}
	}
	_, cert, e := source.nodeSigningKey()
	if e != nil {
		t.Fatal(e)
	}
	target.Config.Storage.SourceCertificatePins[source.Config.NodeID] = nodeproto.Digest(cert)
	return nodeproto.TypedStorageTask{Protocol: nodeproto.StorageProtocol, OperationID: fmt.Sprintf("%032x", 20), NodeID: target.Config.NodeID, Action: "migrate_import", InstanceID: export.InstanceID, OwnerRef: export.OwnerRef, ArtifactID: export.ArtifactID, TargetNodeID: target.Config.NodeID, SourceNodeID: source.Config.NodeID, SourceOperationID: export.OperationID, ManifestSHA256: result.ManifestSHA256, FenceToken: result.FenceToken}
}
func TestColdMigrationFencesSourceImportsInactiveAndActivatesApprovedTarget(t *testing.T) {
	source, sf, task, export, receipt := exportFixture(t)
	i, _ := source.Ledger.Instance(task.InstanceID)
	if i.SourceFence == nil || i.SourceFence.Token != receipt.FenceToken {
		t.Fatal("missing source fence")
	}
	if result := submit(t, source, next(task, "5", "start")); result.Status != "rejected" {
		t.Fatal("fenced source booted")
	}
	target, tf, _ := newStorageFixture(t, "node-b")
	target.Config.DatacenterID = "dc-b"
	target.Config.NodeGroupID = "group-b"
	imp := handoffFixture(t, source, target, export, receipt)
	// No upload/copy is sufficient to authorize any VM action.
	before := len(tf.commands)
	assertStorageStatus(t, target, imp, "rejected")
	if len(tf.commands) != before || len(target.Ledger.Instances()) != 0 {
		t.Fatal("unapproved inbox defined a VM")
	}
	if e := target.approveInbox(context.Background(), imp.ArtifactID, imp.FenceToken); e != nil {
		t.Fatal(e)
	}
	imp.OperationID = fmt.Sprintf("%032x", 21)
	assertStorageStatus(t, target, imp, "succeeded")
	i, _ = target.Ledger.Instance(task.InstanceID)
	if i.State != "imported" || i.TargetBinding == nil || i.TargetBinding.Activated || i.Resources.ComputeNodeID != "node-b" || i.Resources.DatacenterID != "dc-b" || i.Resources.NodeGroupID != "group-b" {
		t.Fatal("target ledger binding/placement", i)
	}
	if tf.count(" define ") != 1 || tf.count(" start ") != 0 {
		t.Fatal("import was not inactive")
	}
	power := task
	power.NodeID = target.Config.NodeID
	power.Resources = i.Resources
	power = next(power, "6", "start")
	if r := submit(t, target, power); r.Status != "rejected" {
		t.Fatal("unactivated target power bypass", r)
	}
	activate := imp
	activate.OperationID = fmt.Sprintf("%032x", 22)
	activate.Action = "migrate_activate"
	activate.ConfirmArtifactID = activate.ArtifactID
	assertStorageStatus(t, target, activate, "succeeded")
	i, _ = target.Ledger.Instance(task.InstanceID)
	if i.State != "running" || !i.TargetBinding.Activated || tf.count(" start ") != 1 || sf.count(" start ") != 1 {
		t.Fatal("migration double-start or false target activation", i)
	}
	power.OperationID = strings.Repeat("7", 32)
	power.Action = "force_off"
	if r := submit(t, target, power); r.Status != "succeeded" {
		t.Fatal("post-migration power resources incompatible", r)
	}
}
func TestSourceFenceSurvivesCopyFailureAndRestartWithoutReplay(t *testing.T) {
	m, f, task := newStorageFixture(t, "node-a")
	createOff(t, m, task)
	f.fail = "convert"
	export := storageTask(task, 10, "migrate_prepare", 100)
	export.TargetNodeID = "node-b"
	assertStorageStatus(t, m, export, "uncertain")
	i, _ := m.Ledger.Instance(task.InstanceID)
	if i.SourceFence == nil {
		t.Fatal("failed export cleared fence")
	}
	a, ok := m.Ledger.Artifact(export.ArtifactID)
	reserved := (int64(task.Resources.SystemDiskGiB) + 1) << 30
	if used, e := m.Ledger.StorageReservedBytes(); !ok || a.Artifact.State != "uncertain" || a.ReservedBytes != reserved || e != nil || used != reserved {
		t.Fatal("fenced uncertain export released conservative budget", a, used, e)
	}
	before := f.count(" convert ")
	_ = m.Ledger.Close()
	l, e := OpenLedger(m.Config.StateDirectory, m.Config.NodeID)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	m.Ledger = l
	assertStorageStatus(t, m, export, "uncertain")
	if f.count(" convert ") != before {
		t.Fatal("uncertain export repeated")
	}
	if r := submit(t, m, next(task, "5", "start")); r.Status != "rejected" {
		t.Fatal("restarted fenced source booted")
	}
}
func TestMigrationRejectsWrongSourceTargetManifestFenceOrProtectedInbox(t *testing.T) {
	for _, kind := range []string{"source_pin", "target", "fence", "manifest", "owner", "symlink_inbox", "altered_approval"} {
		t.Run(kind, func(t *testing.T) {
			source, _, _, export, receipt := exportFixture(t)
			target, tf, _ := newStorageFixture(t, "node-b")
			imp := handoffFixture(t, source, target, export, receipt)
			if e := target.approveInbox(context.Background(), imp.ArtifactID, imp.FenceToken); e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "source_pin":
				target.Config.Storage.SourceCertificatePins[source.Config.NodeID] = strings.Repeat("0", 64)
			case "target":
				imp.TargetNodeID = "node-a"
			case "fence":
				imp.FenceToken = strings.Repeat("a", 64)
			case "manifest":
				imp.ManifestSHA256 = strings.Repeat("b", 64)
			case "owner":
				imp.OwnerRef = strings.Repeat("9", 32)
			case "symlink_inbox":
				dir := filepath.Join(target.Config.Storage.InboxDirectory, imp.ArtifactID)
				_ = os.Rename(dir, dir+"-hidden")
				_ = os.Symlink(dir+"-hidden", dir)
			case "altered_approval":
				p := filepath.Join(target.Config.Storage.InboxDirectory, imp.ArtifactID, "approval.json")
				raw, _ := os.ReadFile(p)
				_ = os.WriteFile(p, append(raw, ' '), 0600)
			}
			if !imp.Valid() {
				raw, _ := json.Marshal(imp)
				if _, e := target.AcceptStorage(imp, raw); e == nil {
					t.Fatal("invalid target accepted")
				}
				return
			}
			beforeDefine := tf.count(" define ")
			assertStorageStatus(t, target, imp, "rejected")
			if tf.count(" define ") != beforeDefine || tf.count(" start ") != 0 {
				t.Fatal("invalid handoff affected VM")
			}
		})
	}
}
func TestImportedActivationUnknownNeverAutomaticallyDoubleStarts(t *testing.T) {
	source, _, _, export, receipt := exportFixture(t)
	target, tf, _ := newStorageFixture(t, "node-b")
	imp := handoffFixture(t, source, target, export, receipt)
	if e := target.approveInbox(context.Background(), imp.ArtifactID, imp.FenceToken); e != nil {
		t.Fatal(e)
	}
	assertStorageStatus(t, target, imp, "succeeded")
	activate := imp
	activate.OperationID = fmt.Sprintf("%032x", 21)
	activate.Action = "migrate_activate"
	activate.ConfirmArtifactID = activate.ArtifactID
	tf.fail = "start"
	assertStorageStatus(t, target, activate, "uncertain")
	before := tf.count(" start ")
	assertStorageStatus(t, target, activate, "uncertain")
	activate.OperationID = fmt.Sprintf("%032x", 22)
	assertStorageStatus(t, target, activate, "rejected")
	if tf.count(" start ") != before {
		t.Fatal("unknown target activation reran")
	}
}
func TestStorageAndLegacyOperationNamespaceCannotCollide(t *testing.T) {
	m, _, task := newStorageFixture(t, "node-a")
	createOff(t, m, task)
	st := storageTask(task, 10, "backup_create", 100)
	assertStorageStatus(t, m, st, "succeeded")
	power := next(task, "5", "start")
	power.OperationID = st.OperationID
	raw, _, _ := power.BytesAndDigest()
	if _, e := m.Accept(power, raw); !errors.Is(e, ErrConflict) {
		t.Fatal("storage op collided with power", e)
	}
	st.OperationID = task.OperationID
	raw, _, _ = st.BytesAndDigest()
	if _, e := m.AcceptStorage(st, raw); !errors.Is(e, ErrConflict) {
		t.Fatal("power op collided with storage", e)
	}
}

func TestStorageJournalUpgradeAndAcceptedRestartNeverExecutes(t *testing.T) {
	m, f, task := newStorageFixture(t, "node-a")
	st := storageTask(task, 10, "backup_create", 100)
	_, sha, _ := st.BytesAndDigest()
	if _, _, e := m.Ledger.ClaimStorage(st, sha); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join(m.Config.StateDirectory, "journal.json"))
	var state journal
	if e != nil || json.Unmarshal(raw, &state) != nil || state.Schema != 2 {
		t.Fatal("storage use did not reject downgrade to old schema1-only node", e)
	}
	_ = m.Ledger.Close()
	l, e := OpenLedger(m.Config.StateDirectory, m.Config.NodeID)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	m.Ledger = l
	assertStorageStatus(t, m, st, "uncertain")
	if len(f.commands) != 0 {
		t.Fatal("accepted storage task replayed after restart")
	}
}

func TestRegisteredRestoreCopiesAreVerifiedAndRemovedOnlyByOwnedVMDelete(t *testing.T) {
	m, f, task := newStorageFixture(t, "node-a")
	createOff(t, m, task)
	assertStorageStatus(t, m, storageTask(task, 10, "backup_create", 100), "succeeded")
	assertStorageStatus(t, m, storageTask(task, 11, "backup_restore", 100), "succeeded")
	i, _ := m.Ledger.Instance(task.InstanceID)
	if len(m.Ledger.Recoveries(i.ID)) != 1 {
		t.Fatal("missing registered retention")
	}
	m.Config.AllowDelete = true
	if r := submit(t, m, next(task, "5", "delete")); r.Status != "succeeded" {
		t.Fatal(r)
	}
	if _, e := os.Stat(i.Directory); !os.IsNotExist(e) {
		t.Fatal("managed retained copy not cleaned", e)
	}
	if len(m.Ledger.Recoveries(i.ID)) != 0 || f.count(" undefine ") != 1 {
		t.Fatal("retention not released")
	}
}
func TestDeleteUnknownDirectoryContentsDoesNotUndefineOrRemoveOwnedDisk(t *testing.T) {
	m, f, task := newStorageFixture(t, "node-a")
	createOff(t, m, task)
	i, _ := m.Ledger.Instance(task.InstanceID)
	_ = os.WriteFile(filepath.Join(i.Directory, "unknown-admin-file"), []byte("not ours"), 0600)
	m.Config.AllowDelete = true
	if r := submit(t, m, next(task, "5", "delete")); r.Status != "rejected" {
		t.Fatal(r)
	}
	if f.count(" undefine ") != 0 {
		t.Fatal("undefine happened before directory safety proof")
	}
	if _, e := os.Stat(i.Disk); e != nil {
		t.Fatal("customer disk touched", e)
	}
}
func TestImportedBindingPersistsAcrossRestartAndCannotUseLegacyStart(t *testing.T) {
	source, _, _, export, result := exportFixture(t)
	target, _, _ := newStorageFixture(t, "node-b")
	imp := handoffFixture(t, source, target, export, result)
	if e := target.approveInbox(context.Background(), imp.ArtifactID, imp.FenceToken); e != nil {
		t.Fatal(e)
	}
	assertStorageStatus(t, target, imp, "succeeded")
	_ = target.Ledger.Close()
	l, e := OpenLedger(target.Config.StateDirectory, target.Config.NodeID)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	target.Ledger = l
	i, _ := l.Instance(imp.InstanceID)
	if i.TargetBinding == nil || i.TargetBinding.Activated || i.TargetBinding.FenceToken != imp.FenceToken || i.State != "imported" {
		t.Fatal("target binding lost", i)
	}
	task := nodeproto.NodeTask{Protocol: nodeproto.Protocol, OperationID: strings.Repeat("6", 32), NodeID: target.Config.NodeID, Action: "start", InstanceID: i.ID, OwnerRef: i.OwnerRef, Hostname: i.Hostname, Resources: i.Resources}
	if r := submit(t, target, task); r.Status != "rejected" {
		t.Fatal("legacy startup bypass after restart", r)
	}
}
func TestStorageArtifactAndPreservedRestoreBudgetCannotBeSilentlyExceeded(t *testing.T) {
	m, f, task := newStorageFixture(t, "node-a")
	createOff(t, m, task)
	m.Config.Storage.MaxArtifactBytes = 11 << 30
	m.Config.Storage.MaxTotalBytes = 11 << 30
	assertStorageStatus(t, m, storageTask(task, 10, "backup_create", 100), "succeeded")
	before := f.count(" convert ")
	assertStorageStatus(t, m, storageTask(task, 11, "snapshot_create", 101), "rejected")
	if f.count(" convert ") != before {
		t.Fatal("artifact exceeded reserve")
	}
	assertStorageStatus(t, m, storageTask(task, 12, "backup_restore", 100), "uncertain")
	i, _ := m.Ledger.Instance(task.InstanceID)
	if i.State != "uncertain" {
		t.Fatal("restore budget failure did not retain conservative state")
	}
}

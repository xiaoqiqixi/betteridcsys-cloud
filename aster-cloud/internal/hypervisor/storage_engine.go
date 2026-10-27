package hypervisor

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func (m *Manager) LookupStorage(id string) (nodeproto.StorageResult, bool) {
	if !nodeproto.ValidID(id) {
		return nodeproto.StorageResult{}, false
	}
	m.admission.Lock()
	defer m.admission.Unlock()
	op, ok := m.Ledger.QueryStorage(id)
	if !ok {
		return nodeproto.StorageResult{}, false
	}
	r := op.Result
	if m.active && m.activeOperation == id {
		r.Status = "accepted"
	}
	return r, true
}
func (m *Manager) AcceptStorage(task nodeproto.TypedStorageTask, raw []byte) (nodeproto.StorageResult, error) {
	decoded, e := nodeproto.DecodeStorageTask(raw)
	if e != nil || decoded != task || task.NodeID != m.Config.NodeID {
		return nodeproto.StorageResult{}, nodeproto.ErrInvalid
	}
	m.admission.Lock()
	defer m.admission.Unlock()
	result, fresh, e := m.Ledger.ClaimStorage(task, nodeproto.Digest(raw))
	if e != nil {
		return result, e
	}
	if !fresh {
		if m.active && m.activeOperation == task.OperationID {
			result.Status = "accepted"
		}
		return result, nil
	}
	reject := func(code string) (nodeproto.StorageResult, error) {
		return m.Ledger.FinishStorage(task.OperationID, "rejected", code, result, nil, nil, nil)
	}
	if m.stopping || m.Config.Maintenance {
		return reject("MAINTENANCE")
	}
	if m.active {
		return reject("NODE_BUSY")
	}
	if task.Action != "snapshot_list" && task.Action != "backup_list" && m.Ledger.HasPendingInstance(task.InstanceID, task.OperationID) {
		return reject("UNRESOLVED_INSTANCE_OPERATION")
	}
	if !m.Config.Storage.Enabled || m.Config.validateStorage() != nil {
		return reject("STORAGE_NOT_APPROVED")
	}
	if e = ownedPath(m.Config.Storage.Directory, true, true); e != nil {
		return reject("PRIVATE_ARTIFACT_ROOT_REQUIRED")
	}
	var instance Instance
	if task.Action == "migrate_retire_source" {
		var ok bool
		instance, ok = m.Ledger.Instance(task.InstanceID)
		if !ok || m.validateRetireSource(task, instance) != nil {
			return reject("PUBLIC_SOURCE_RETIRE_PROOF_REJECTED")
		}
	} else if task.Action == "migrate_import" {
		manifest, _, err := m.readImport(task, true)
		if err != nil {
			return reject("AWAITING_PROTECTED_HANDOFF_OR_INVALID_BINDING")
		}
		resources := manifest.Resources
		// Relocation changes physical placement only. Keep CPU/RAM/disk and the
		// historical source configuration in the signed manifest; never money data.

		resources.ComputeNodeID = m.Config.NodeID
		resources.DatacenterID = m.Config.DatacenterID
		resources.NodeGroupID = m.Config.NodeGroupID
		resources.SystemStorageID = m.Config.StorageID
		t := nodeproto.NodeTask{Protocol: nodeproto.Protocol, OperationID: task.OperationID, NodeID: task.NodeID, Action: "create", InstanceID: task.InstanceID, OwnerRef: task.OwnerRef, Hostname: manifest.Hostname, Resources: resources}
		if task.Protocol == nodeproto.StorageDirectProtocol {
			t.Protocol = nodeproto.DirectPublicProtocol
			t.DirectPublic = task.DirectPublic
		}
		instance, e = m.prepareWithRetired(t, true)
		if e != nil {
			return reject(safeCode(e))
		}
		instance.TargetBinding = &TargetBinding{SourceNodeID: task.SourceNodeID, SourceOperationID: task.SourceOperationID, ArtifactID: task.ArtifactID, ManifestSHA256: task.ManifestSHA256, FenceToken: task.FenceToken}
		if e = m.Ledger.Reserve(instance); e != nil {
			return reject(safeCode(e))
		}
	} else {
		var ok bool
		instance, ok = m.Ledger.Instance(task.InstanceID)
		if !ok || instance.OwnerRef != task.OwnerRef {
			return reject("INSTANCE_OWNERSHIP_REJECTED")
		}
		if task.DirectPublic != instance.DirectPublic || instance.DirectPublicDetached || (!instance.DirectPublic.IsZero() && m.approvedDirect(instance.DirectPublic) != nil) {
			return reject("DIRECT_PUBLIC_STORAGE_BINDING_REJECTED")
		}
		if !instance.Network.IsZero() {
			return reject("OVS_STORAGE_CONTRACT_UNSUPPORTED")
		}
		if task.Action == "snapshot_list" || task.Action == "backup_list" {
			kind := "snapshot"
			if task.Action == "backup_list" {
				kind = "backup"
			}
			for _, a := range m.Ledger.Artifacts() {
				if a.Artifact.Kind == kind && a.Artifact.OwnerRef == task.OwnerRef && a.Artifact.InstanceID == task.InstanceID && a.Artifact.State != "deleted" {
					result.Items = append(result.Items, a.Artifact)
				}
			}
			sort.Slice(result.Items, func(i, j int) bool { return result.Items[i].ArtifactID < result.Items[j].ArtifactID })
			return m.Ledger.FinishStorage(task.OperationID, "succeeded", "", result, nil, nil, nil)
		}
		if instance.State == "reserved" || instance.State == "uncertain" || instance.State == "deleted" || instance.SourceFence != nil {
			return reject("INSTANCE_FENCED_OR_UNCERTAIN")
		}
		if task.Action == "migrate_activate" {
			b := instance.TargetBinding
			if b == nil || b.Activated || instance.State != "imported" || b.SourceNodeID != task.SourceNodeID || b.SourceOperationID != task.SourceOperationID || b.ArtifactID != task.ArtifactID || b.ManifestSHA256 != task.ManifestSHA256 || b.FenceToken != task.FenceToken {
				return reject("IMPORTED_TARGET_BINDING_REQUIRED")
			}
			if _, _, e = m.readImport(task, true); e != nil {
				return reject("ROOT_HANDOFF_APPROVAL_REQUIRED")
			}
		} else if instance.TargetBinding != nil && !instance.TargetBinding.Activated {
			return reject("TARGET_NOT_ACTIVATED")
		}
	}
	var artifact *ArtifactRecord
	if task.Action == "snapshot_create" || task.Action == "backup_create" || task.Action == "migrate_prepare" {
		if task.Action == "migrate_prepare" && !m.Config.Storage.AllowMigration {
			return reject("MIGRATION_NOT_APPROVED")
		}
		if _, ok := m.Ledger.Artifact(task.ArtifactID); ok {
			return reject("ARTIFACT_ID_ALREADY_RESERVED")
		}
		reserve := (int64(instance.Resources.SystemDiskGiB) + 1) << 30
		used, budgetErr := m.Ledger.StorageReservedBytes()
		if budgetErr != nil {
			return reject("STORAGE_BUDGET_UNAVAILABLE")
		}
		if reserve > m.Config.Storage.MaxArtifactBytes || reserve > m.Config.Storage.MaxTotalBytes-used {
			return reject("ARTIFACT_CAPACITY_EXHAUSTED")
		}
		kind := "snapshot"
		if task.Action == "backup_create" {
			kind = "backup"
		}
		if task.Action == "migrate_prepare" {
			kind = "migration"
		}
		a := ArtifactRecord{Artifact: nodeproto.StorageArtifact{ArtifactID: task.ArtifactID, Kind: kind, NodeID: m.Config.NodeID, InstanceID: task.InstanceID, OwnerRef: task.OwnerRef, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), State: "reserved"}, ReservedBytes: reserve}
		artifact = &a
	} else if task.Action != "migrate_import" && task.Action != "migrate_activate" && task.Action != "migrate_retire_source" {
		a, ok := m.Ledger.Artifact(task.ArtifactID)
		kind := "snapshot"
		if strings.HasPrefix(task.Action, "backup_") {
			kind = "backup"
		}
		if !ok || a.Artifact.OwnerRef != task.OwnerRef || a.Artifact.InstanceID != task.InstanceID || a.Artifact.NodeID != m.Config.NodeID || a.Artifact.Kind != kind || a.Artifact.State != "available" {
			return reject("ARTIFACT_OWNERSHIP_OR_STATE_REJECTED")
		}
		artifact = &a
	}
	quarantine := cloneInstance(instance)
	quarantine.State = "uncertain"
	if r, err := m.Ledger.FinishStorage(task.OperationID, "accepted", "DURABLE_STORAGE_CLAIM", result, &quarantine, artifact, nil); err != nil {
		return r, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	m.active = true
	m.activeOperation = task.OperationID
	m.cancel = cancel
	m.workers.Add(1)
	go func() {
		defer m.workers.Done()
		defer cancel()
		m.executeStorage(ctx, task, result, instance, artifact)
		if m.beforeRelease != nil {
			m.beforeRelease()
		}
		m.admission.Lock()
		m.active = false
		m.activeOperation = ""
		m.cancel = nil
		m.admission.Unlock()
	}()
	return result, nil
}
func (m *Manager) executeStorage(ctx context.Context, task nodeproto.TypedStorageTask, result nodeproto.StorageResult, instance Instance, artifact *ArtifactRecord) {
	finish := func(status, code string) {
		if status == "uncertain" {
			instance.State = "uncertain"
			if artifact != nil && artifact.Artifact.State != "deleted" {
				artifact.Artifact.State = "uncertain"
			}
		}
		_, e := m.Ledger.FinishStorage(task.OperationID, status, code, result, &instance, artifact, nil)
		m.logStorageOutcome(ctx, task, status, code, e == nil)
	}
	if ctx.Err() != nil {
		finish("uncertain", "CANCELLED_AFTER_CLAIM")
		return
	}
	if task.Action == "migrate_retire_source" {
		if changed, e := m.retirePublicSource(ctx, task, &instance); e != nil {
			if !changed {
				finish("rejected", "PUBLIC_SOURCE_RETIRE_PREFLIGHT_REJECTED")
				return
			}
			finish("uncertain", "PUBLIC_SOURCE_RETIRE_UNCONFIRMED")
			return
		}
		finish("succeeded", "")
		return
	}
	if task.Action == "migrate_import" {
		manifest, dir, e := m.readImport(task, true)
		if e == nil {
			e = m.importOwned(ctx, instance, manifest, dir)
		}
		if e != nil {
			finish("uncertain", "IMPORT_OUTCOME_UNCERTAIN")
			return
		}
		instance.State = "imported"
		finish("succeeded", "")
		return
	}
	if e := m.assertOwned(ctx, instance); e != nil {
		finish("uncertain", "LIVE_OWNERSHIP_UNCONFIRMED")
		return
	}
	state, e := m.state(ctx, instance.Domain)
	if e != nil {
		finish("uncertain", "DOMAIN_STATE_UNAVAILABLE")
		return
	}
	if state != "shut off" {
		instance.State = state
		if artifact != nil && artifact.Artifact.State == "reserved" {
			artifact.Artifact.State = "rejected"
			artifact.ReservedBytes = 0
		}
		finish("rejected", "OFFLINE_OPERATION_REQUIRES_SHUT_OFF")
		return
	}
	instance.State = "shut off"
	if task.Action == "migrate_activate" {
		manifest, dir, e := m.readImport(task, true)
		_ = dir
		if e == nil {
			e = m.verifyFlat(ctx, instance.Disk, manifest)
		}
		if e == nil && !instance.DirectPublic.IsZero() {
			e = m.approvedDirect(instance.DirectPublic)
		}
		if e == nil && instance.IPv4 != "" {
			e = m.verifyNetwork(ctx)
		}
		if e == nil {
			_, e = m.virsh(ctx, "start", instance.Domain)
		}
		if e == nil {
			state, e = m.state(ctx, instance.Domain)
			if state != "running" {
				e = errors.New("target running state unconfirmed")
			}
		}
		if e != nil {
			finish("uncertain", "ACTIVATION_OUTCOME_UNCERTAIN")
			return
		}
		instance.TargetBinding.Activated = true
		instance.State = "running"
		finish("succeeded", "")
		return
	}
	if task.Action == "snapshot_create" || task.Action == "backup_create" || task.Action == "migrate_prepare" {
		if task.Action == "migrate_prepare" {
			autostart, err := m.virsh(ctx, "list", "--all", "--autostart", "--name")
			if err != nil {
				finish("uncertain", "SOURCE_AUTOSTART_STATE_UNAVAILABLE")
				return
			}
			for _, name := range strings.Fields(string(autostart)) {
				if name == instance.Domain {
					// This is a confirmed pre-effect rejection: no fence or
					// artifact file has been created. Preserve the rejected ID
					// binding, but do not consume copy capacity indefinitely.
					artifact.Artifact.State = "rejected"
					artifact.ReservedBytes = 0
					finish("rejected", "SOURCE_AUTOSTART_MUST_BE_DISABLED")
					return
				}
			}
			token := make([]byte, 32)
			if _, e = rand.Read(token); e != nil {
				finish("uncertain", "FENCE_ENTROPY_UNAVAILABLE")
				return
			}
			instance.SourceFence = &SourceFence{Token: hex.EncodeToString(token), ArtifactID: task.ArtifactID, TargetNodeID: task.TargetNodeID, OperationID: task.OperationID, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
			result.FenceToken = instance.SourceFence.Token
			result.SourceNodeID = m.Config.NodeID
			result.TargetNodeID = task.TargetNodeID
			// Source fencing is permanent through the API, persisted BEFORE export. It
			// cannot be cleared by a target claim, a failed copy or an HTTP boolean.
			if _, e = m.Ledger.FinishStorage(task.OperationID, "accepted", "SOURCE_PERMANENTLY_FENCED", result, &instance, artifact, nil); e != nil {
				return
			}
			if !instance.DirectPublic.IsZero() {
				if e = m.defineDirectNetwork(ctx, instance, task.OperationID); e != nil {
					finish("uncertain", "DIRECT_SOURCE_LINK_FENCE_UNCONFIRMED")
					return
				}
			}
		}
		a, e := m.createArtifact(ctx, task, instance, *artifact)
		if e != nil {
			finish("uncertain", "ARTIFACT_CREATE_UNCERTAIN")
			return
		}
		*artifact = a
		result.ManifestSHA256 = a.Artifact.ManifestSHA256
		result.Items = []nodeproto.StorageArtifact{a.Artifact}
		finish("succeeded", "")
		return
	}
	signed, hash, e := m.readArtifact(ctx, *artifact, instance)
	if e != nil {
		finish("uncertain", "ARTIFACT_VERIFICATION_FAILED")
		return
	}
	result.ManifestSHA256 = hash
	result.Items = []nodeproto.StorageArtifact{artifact.Artifact}
	switch task.Action {
	case "backup_verify":
		finish("succeeded", "")
	case "snapshot_restore", "backup_restore":
		if e = m.restoreArtifact(ctx, task, instance, signed.Manifest, result); e != nil {
			finish("uncertain", "RESTORE_OUTCOME_UNCERTAIN")
			return
		}
		finish("succeeded", "")
	case "snapshot_delete", "backup_delete":
		directory := filepath.Join(m.Config.Storage.Directory, task.ArtifactID)
		for _, name := range []string{"disk.qcow2", "manifest.json"} {
			p := filepath.Join(directory, name)
			if e = ownedPath(p, true, false); e != nil {
				finish("uncertain", "DELETE_ARTIFACT_PATH_REJECTED")
				return
			}
			if e = os.Remove(p); e != nil {
				finish("uncertain", "DELETE_ARTIFACT_UNCERTAIN")
				return
			}
		}
		if e = os.Remove(directory); e != nil {
			finish("uncertain", "ARTIFACT_DIRECTORY_NOT_EMPTY")
			return
		}
		if e = syncDirectory(m.Config.Storage.Directory); e != nil {
			finish("uncertain", "ARTIFACT_DELETE_DURABILITY_UNCERTAIN")
			return
		}
		artifact.Artifact.State = "deleted"
		result.Items = []nodeproto.StorageArtifact{artifact.Artifact}
		finish("succeeded", "")
	default:
		finish("rejected", "UNSUPPORTED_STORAGE_ACTION")
	}
}

func (m *Manager) logStorageOutcome(ctx context.Context, task nodeproto.TypedStorageTask, status, code string, durable bool) {
	level := slog.LevelInfo
	if status == "uncertain" || !durable {
		level = slog.LevelWarn
	}
	if !durable {
		status, code = "uncertain", "JOURNAL_WRITE_UNCONFIRMED"
	}
	slog.Log(ctx, level, "aster_node_storage_operation", "node_id", m.Config.NodeID, "operation_id", task.OperationID, "instance_id", task.InstanceID, "action", task.Action, "status", status, "code", code, "journal_write_confirmed", durable)
}
func (m *Manager) readArtifact(ctx context.Context, a ArtifactRecord, i Instance) (nodeproto.SignedStorageManifest, string, error) {
	dir := filepath.Join(m.Config.Storage.Directory, a.Artifact.ArtifactID)
	if e := ownedPath(dir, true, true); e != nil {
		return nodeproto.SignedStorageManifest{}, "", e
	}
	s, hash, e := readSignedManifest(dir)
	if e != nil {
		return s, "", e
	}
	manifest := s.Manifest
	if hash != a.Artifact.ManifestSHA256 || manifest.ArtifactID != a.Artifact.ArtifactID || manifest.Kind != a.Artifact.Kind || manifest.NodeID != m.Config.NodeID || manifest.InstanceID != i.ID || manifest.OwnerRef != i.OwnerRef || manifest.Hostname != i.Hostname || manifest.Resources != i.Resources || manifest.DirectPublic != i.DirectPublic || manifest.DiskSHA256 != a.Artifact.DiskSHA256 || manifest.DiskBytes != a.Artifact.DiskBytes || manifest.VirtualBytes != a.Artifact.VirtualBytes {
		return s, "", errors.New("artifact metadata binding rejected")
	}
	return s, hash, m.verifyFlat(ctx, filepath.Join(dir, "disk.qcow2"), manifest)
}
func (m *Manager) createArtifact(ctx context.Context, task nodeproto.TypedStorageTask, i Instance, a ArtifactRecord) (ArtifactRecord, error) {
	image, ok := m.Config.Images[i.Resources.ImageID]
	if !ok {
		return a, ErrUnsupported
	}
	imageHash, _, e := m.hashApprovedDisk(ctx, image.Path, m.Config.Storage.MaxArtifactBytes, false)
	if e != nil || imageHash != image.SHA256 {
		return a, errors.New("approved base image changed")
	}
	info, e := m.qcowInfo(ctx, i.Disk, image.Path)
	if e != nil || info.VirtualSize > uint64(i.Resources.SystemDiskGiB)<<30 || info.VirtualSize == 0 || (info.Backing != "" && info.Backing != image.Path) {
		return a, errors.New("source disk chain rejected")
	}
	if _, e = m.Runner.Run(ctx, QemuImg, "check", "-f", "qcow2", i.Disk); e != nil {
		return a, e
	}
	reserve := a.ReservedBytes
	capacity, e := HostCapacity(m.Config.Storage.Directory)
	if m.capacityRead != nil {
		capacity, e = m.capacityRead(m.Config.Storage.Directory)
	}
	if e != nil || capacity.StorageAvailableGiB < (reserve+(1<<30)-1)>>30 {
		return a, errors.New("artifact free space unavailable")
	}
	dir := filepath.Join(m.Config.Storage.Directory, task.ArtifactID)
	if e = NoSymlinkPath(dir); e != nil {
		return a, e
	}
	if e = os.Mkdir(dir, 0700); e != nil {
		return a, e
	}
	disk := filepath.Join(dir, "disk.qcow2")
	if e = writeExclusive(disk, nil); e != nil {
		return a, e
	}
	if _, e = m.Runner.Run(ctx, QemuImg, "convert", "-f", "qcow2", "-O", "qcow2", i.Disk, disk); e != nil {
		return a, e
	}
	if e = os.Chmod(disk, 0600); e != nil {
		return a, e
	}
	sha, size, e := m.hashDisk(ctx, disk, m.Config.Storage.MaxArtifactBytes)
	if e != nil {
		return a, e
	}
	manifest := nodeproto.StorageManifest{DirectPublic: i.DirectPublic, Protocol: task.Protocol, ArtifactID: task.ArtifactID, Kind: a.Artifact.Kind, NodeID: m.Config.NodeID, InstanceID: i.ID, OwnerRef: i.OwnerRef, Hostname: i.Hostname, Resources: i.Resources, SourceDomain: i.Domain, ImageID: i.Resources.ImageID, ImageSHA256: image.SHA256, DiskSHA256: sha, DiskBytes: size, VirtualBytes: info.VirtualSize, CreatedAt: a.Artifact.CreatedAt}
	if i.SourceFence != nil && task.Action == "migrate_prepare" {
		manifest.ExportOperationID = task.OperationID
		manifest.TargetNodeID = task.TargetNodeID
		manifest.FenceToken = i.SourceFence.Token
	}
	if e = m.verifyFlat(ctx, disk, manifest); e != nil {
		return a, e
	}
	if e = syncApprovedDisk(disk); e != nil {
		return a, e
	}
	_, hash, e := m.writeManifest(dir, manifest)
	if e != nil {
		return a, e
	}
	if e = syncDirectory(m.Config.Storage.Directory); e != nil {
		return a, e
	}
	a.Artifact.ManifestSHA256 = hash
	a.Artifact.DiskSHA256 = sha
	a.Artifact.DiskBytes = size
	a.Artifact.VirtualBytes = info.VirtualSize
	a.Artifact.State = "available"
	return a, nil
}

type qcowInformation struct {
	Format      string          `json:"format"`
	VirtualSize uint64          `json:"virtual-size"`
	Backing     string          `json:"backing-filename"`
	Specific    json.RawMessage `json:"format-specific"`
}

func (m *Manager) qcowInfo(ctx context.Context, path string, backing ...string) (qcowInformation, error) {
	var info qcowInformation
	allowed := ""
	if len(backing) > 0 {
		allowed = backing[0]
	}
	if e := validateQcowHeader(path, allowed); e != nil {
		return info, e
	}
	if e := ownedPath(path, true, false); e != nil {
		return info, e
	}
	raw, e := m.Runner.Run(ctx, QemuImg, "info", "--output=json", "-f", "qcow2", path)
	if e != nil {
		return info, e
	}
	if len(raw) > 1<<20 || json.Unmarshal(raw, &info) != nil || info.Format != "qcow2" || info.VirtualSize < 1 || strings.Contains(string(info.Specific), "data-file") {
		return info, errors.New("qcow2 structure rejected")
	}
	return info, nil
}
func (m *Manager) hashDisk(ctx context.Context, path string, max int64) (string, int64, error) {
	return m.hashApprovedDisk(ctx, path, max, true)
}
func (m *Manager) hashApprovedDisk(ctx context.Context, path string, max int64, private bool) (string, int64, error) {
	f, e := openApproved(path, private)
	if e != nil {
		return "", 0, e
	}
	defer f.Close()
	before, e := f.Stat()
	if e != nil || before.Size() < 1 || before.Size() > max {
		return "", 0, errors.New("disk size rejected")
	}
	h := sha256.New()
	n, e := io.CopyBuffer(h, contextReader{ctx, io.LimitReader(f, max+1)}, make([]byte, 128<<10))
	after, se := f.Stat()
	atPath, pe := os.Stat(path)
	if e != nil || se != nil || pe != nil || n != before.Size() || n > max || !os.SameFile(before, atPath) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return "", 0, errors.New("disk changed or hash read failed")
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
func (m *Manager) verifyFlat(ctx context.Context, path string, manifest nodeproto.StorageManifest) error {
	if manifest.DiskBytes < 1 || manifest.DiskBytes > m.Config.Storage.MaxArtifactBytes {
		return errors.New("artifact exceeds approved limit")
	}
	hash, size, e := m.hashDisk(ctx, path, m.Config.Storage.MaxArtifactBytes)
	if e != nil || hash != manifest.DiskSHA256 || size != manifest.DiskBytes {
		return errors.New("artifact bytes do not match manifest")
	}
	info, e := m.qcowInfo(ctx, path)
	if e != nil || info.Backing != "" || info.VirtualSize != manifest.VirtualBytes || info.VirtualSize > uint64(manifest.Resources.SystemDiskGiB)<<30 {
		return errors.New("artifact is not an independent qcow2")
	}
	_, e = m.Runner.Run(ctx, QemuImg, "check", "-f", "qcow2", path)
	return e
}
func (m *Manager) storageCheckpoint(stage string) error {
	if m.storageFS != nil {
		return m.storageFS(stage)
	}
	return nil
}
func (m *Manager) restoreArtifact(ctx context.Context, t nodeproto.TypedStorageTask, i Instance, manifest nodeproto.StorageManifest, r nodeproto.StorageResult) error {
	if manifest.ImageID != i.Resources.ImageID {
		return ErrOwnership
	}
	previousHash, previousSize, e := m.hashDisk(ctx, i.Disk, m.Config.Storage.MaxArtifactBytes)
	if e != nil {
		return e
	}
	stage := filepath.Join(i.Directory, "system.qcow2.next-"+t.OperationID)
	previous := filepath.Join(i.Directory, "system.qcow2.before-"+t.OperationID)
	reserve := previousSize + manifest.DiskBytes
	used, budgetErr := m.Ledger.StorageReservedBytes()
	if budgetErr != nil || reserve > m.Config.Storage.MaxTotalBytes-used {
		return errors.New("restore preservation budget exhausted")
	}
	readCapacity := m.capacityRead
	if readCapacity == nil {
		readCapacity = HostCapacity
	}
	capacity, capErr := readCapacity(i.Directory)
	if capErr != nil || capacity.StorageAvailableGiB < (manifest.DiskBytes+(1<<30)-1)>>30 {
		return errors.New("restore staging capacity unavailable")
	}
	recovery := &RestoreRecovery{ReservedBytes: reserve, PreviousDiskName: filepath.Base(previous), PreviousDiskSHA256: previousHash, PreviousDiskBytes: previousSize, ReplacementSHA256: manifest.DiskSHA256}
	quarantine := cloneInstance(i)
	quarantine.State = "uncertain"
	if _, e = m.Ledger.FinishStorage(t.OperationID, "accepted", "RESTORE_INTENT_PERSISTED", r, &quarantine, nil, recovery); e != nil {
		return e
	}
	if e = m.copyExact(ctx, filepath.Join(m.Config.Storage.Directory, t.ArtifactID, "disk.qcow2"), stage, manifest); e != nil {
		return e
	}
	if e = m.storageCheckpoint("restore_before_preserve"); e != nil {
		return e
	}
	// A durable hardlink preserves the exact previous inode, then a single atomic
	// rename replaces the active path. There is no interval with a missing disk.
	if e = os.Link(i.Disk, previous); e != nil {
		return e
	}
	if e = syncDirectory(i.Directory); e != nil {
		return e
	}
	if e = m.storageCheckpoint("restore_after_preserve"); e != nil {
		return e
	}
	if e = os.Rename(stage, i.Disk); e != nil {
		return e
	}
	if e = syncDirectory(i.Directory); e != nil {
		return e
	}
	if e = m.storageCheckpoint("restore_after_swap"); e != nil {
		return e
	}
	if e = m.verifyFlat(ctx, i.Disk, manifest); e != nil {
		return e
	}
	return m.assertOwned(ctx, i)
}
func (m *Manager) copyExact(ctx context.Context, source, target string, manifest nodeproto.StorageManifest) error {
	if e := m.verifyFlat(ctx, source, manifest); e != nil {
		return e
	}
	input, e := openApproved(source, true)
	if e != nil {
		return e
	}
	defer input.Close()
	output, e := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = io.CopyBuffer(output, contextReader{ctx, io.LimitReader(input, manifest.DiskBytes+1)}, make([]byte, 128<<10))
	if e == nil {
		e = output.Sync()
	}
	closeErr := output.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	return m.verifyFlat(ctx, target, manifest)
}
func (m *Manager) importOwned(ctx context.Context, i Instance, manifest nodeproto.StorageManifest, inbox string) error {
	names, e := m.virsh(ctx, "list", "--all", "--name")
	if e != nil {
		return e
	}
	for _, n := range strings.Fields(string(names)) {
		if n == i.Domain {
			return errors.New("target domain already exists")
		}
	}
	if i.IPv4 != "" {
		if e = m.verifyNetwork(ctx); e != nil {
			return e
		}
	}
	if e = ownedPath(m.Config.StorageDirectory, false, true); e != nil {
		return e
	}
	if e = NoSymlinkPath(i.Directory); e != nil {
		return e
	}
	if e = os.Mkdir(i.Directory, 0755); e != nil {
		return e
	}
	if e = m.copyExact(ctx, filepath.Join(inbox, "disk.qcow2"), i.Disk, manifest); e != nil {
		return e
	}
	if i.Seed != "" {
		if e = m.seed(ctx, i); e != nil {
			return e
		}
	}
	definition, e := m.domainXML(i)
	if e != nil {
		return e
	}
	xmlPath := filepath.Join(i.Directory, "domain.xml")
	if e = writeExclusive(xmlPath, definition); e != nil {
		return e
	}
	if e = syncDirectory(i.Directory); e != nil {
		return e
	}
	if e = m.requireDomainAbsent(ctx, i.Domain); e != nil {
		return e
	}
	if _, e = m.virsh(ctx, "define", xmlPath); e != nil {
		return e
	}
	if e = m.assertOwned(ctx, i); e != nil {
		return e
	}
	state, e := m.state(ctx, i.Domain)
	if e != nil || state != "shut off" {
		return errors.New("imported domain is not confirmed inactive")
	}
	return nil
}

func syncApprovedDisk(path string) error {
	f, e := openApproved(path, true)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func (m *Manager) requireDomainAbsent(ctx context.Context, domain string) error {
	names, e := m.virsh(ctx, "list", "--all", "--name")
	if e != nil {
		return e
	}
	for _, name := range strings.Fields(string(names)) {
		if name == domain {
			return errors.New("domain inventory collision")
		}
	}
	return nil
}

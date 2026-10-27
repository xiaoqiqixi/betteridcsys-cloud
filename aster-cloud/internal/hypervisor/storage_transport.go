package hypervisor

import (
	"aster/cloud/internal/nodeproto"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type InboxFileRecord struct {
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
	Status string `json:"status"`
}
type InboxTransfer struct {
	ApprovalState  string                     `json:"approval_state"`
	TransferID     string                     `json:"transfer_id"`
	ArtifactID     string                     `json:"artifact_id"`
	ManifestSHA256 string                     `json:"manifest_sha256"`
	Manifest       nodeproto.StorageManifest  `json:"manifest"`
	Files          map[string]InboxFileRecord `json:"files"`
	ReservedBytes  int64                      `json:"reserved_bytes"`
}

func cloneInbox(t InboxTransfer) InboxTransfer {
	files := map[string]InboxFileRecord{}
	for k, v := range t.Files {
		files[k] = v
	}
	t.Files = files
	return t
}
func (l *Ledger) Inbox(id string) (InboxTransfer, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	t, ok := l.state.InboxTransfers[id]
	return cloneInbox(t), ok
}
func (l *Ledger) Inboxes() []InboxTransfer {
	l.mu.Lock()
	defer l.mu.Unlock()
	items := []InboxTransfer{}
	for _, t := range l.state.InboxTransfers {
		items = append(items, cloneInbox(t))
	}
	return items
}
func (l *Ledger) SaveInbox(t InboxTransfer) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if old, ok := l.state.InboxTransfers[t.ArtifactID]; ok && (old.TransferID != t.TransferID || old.ManifestSHA256 != t.ManifestSHA256) {
		return ErrConflict
	}
	if !t.Manifest.DirectPublic.IsZero() && l.state.Schema < 5 {
		l.state.Schema = 5
	}
	if l.state.Schema < 2 {
		l.state.Schema = 2
	}
	l.state.InboxTransfers[t.ArtifactID] = cloneInbox(t)
	return l.save()
}
func (m *Manager) acquireStorageIO(parent context.Context) (context.Context, func(), error) {
	m.admission.Lock()
	defer m.admission.Unlock()
	if m.active || m.stopping || m.Config.Maintenance {
		return nil, nil, ErrConflict
	}
	if !m.Config.Storage.Enabled || !m.Config.Storage.AllowMigration {
		return nil, nil, ErrUnsupported
	}
	ctx, cancel := context.WithTimeout(parent, 20*time.Minute)
	m.active = true
	m.activeOperation = ""
	m.cancel = cancel
	m.workers.Add(1)
	var once sync.Once
	return ctx, func() {
		once.Do(func() {
			m.admission.Lock()
			m.active = false
			m.cancel = nil
			m.admission.Unlock()
			cancel()
			m.workers.Done()
		})
	}, nil
}
func storageStreamDeadline(w http.ResponseWriter) error {
	c := http.NewResponseController(w)
	if e := c.SetReadDeadline(time.Now().Add(20 * time.Minute)); e != nil {
		return e
	}
	return c.SetWriteDeadline(time.Now().Add(20 * time.Minute))
}
func (m *Manager) serveStorageTransport(w http.ResponseWriter, r *http.Request) bool {
	prefix := ""
	source := false
	if strings.HasPrefix(r.URL.Path, "/v1/storage-artifacts/") {
		prefix = "/v1/storage-artifacts/"
		source = true
	} else if strings.HasPrefix(r.URL.Path, "/v1/storage-inbox/") {
		prefix = "/v1/storage-inbox/"
	} else {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, prefix), "/")
	if len(parts) != 2 || !nodeproto.ValidID(parts[0]) {
		respond(w, 404, errorBody("NOT_FOUND"))
		return true
	}
	id, file := parts[0], parts[1]
	if file == "approve" && !source && r.Method == "POST" {
		m.approveControllerInbox(w, r, id)
		return true
	}
	if file == "approval" && !source && r.Method == "GET" {
		m.getInboxApproval(w, r, id)
		return true
	}
	if file != "manifest" && file != "disk" {
		respond(w, 404, errorBody("NOT_FOUND"))
		return true
	}
	if source && r.Method == "GET" {
		m.streamExport(w, r, id, file)
		return true
	}
	if !source && r.Method == "GET" {
		transfer := r.Header.Get("X-Transfer-ID")
		record, ok := m.Ledger.Inbox(id)
		if !ok {
			respond(w, 404, errorBody("INBOX_NOT_FOUND"))
			return true
		}
		if !nodeproto.ValidID(transfer) || record.TransferID != transfer {
			respond(w, 409, errorBody("TRANSFER_BINDING_CONFLICT"))
			return true
		}
		if _, exists := record.Files[file]; !exists {
			respond(w, 404, errorBody("FILE_NOT_RECEIVED"))
			return true
		}
		receipt, e := m.inboxReceipt(r.Context(), record, file)
		if e != nil {
			respond(w, 200, receipt)
			return true
		}
		respond(w, 200, receipt)
		return true
	}
	if !source && r.Method == "PUT" {
		m.receiveInbox(w, r, id, file)
		return true
	}
	respond(w, 404, errorBody("NOT_FOUND"))
	return true
}
func (m *Manager) streamExport(w http.ResponseWriter, r *http.Request, id, file string) {
	if !m.Config.Storage.Enabled || !m.Config.Storage.AllowMigration {
		respond(w, 403, errorBody("MIGRATION_NOT_APPROVED"))
		return
	}
	a, ok := m.Ledger.Artifact(id)
	if !ok || a.Artifact.Kind != "migration" || a.Artifact.State != "available" {
		respond(w, 404, errorBody("EXPORT_NOT_AVAILABLE"))
		return
	}
	i, ok := m.Ledger.Instance(a.Artifact.InstanceID)
	if !ok || i.OwnerRef != a.Artifact.OwnerRef || i.SourceFence == nil || i.SourceFence.ArtifactID != id || i.State != "shut off" {
		respond(w, 409, errorBody("SOURCE_FENCE_UNCONFIRMED"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Minute)
	defer cancel()
	if e := m.assertOwned(ctx, i); e != nil {
		respond(w, 409, errorBody("SOURCE_OWNERSHIP_UNCONFIRMED"))
		return
	}
	state, e := m.state(ctx, i.Domain)
	if e != nil || state != "shut off" {
		respond(w, 409, errorBody("SOURCE_NOT_OFFLINE"))
		return
	}
	autostart, e := m.virsh(ctx, "list", "--all", "--autostart", "--name")
	if e != nil {
		respond(w, 409, errorBody("SOURCE_AUTOSTART_UNCONFIRMED"))
		return
	}
	for _, n := range strings.Fields(string(autostart)) {
		if n == i.Domain {
			respond(w, 409, errorBody("SOURCE_AUTOSTART_ENABLED"))
			return
		}
	}
	dir := filepath.Join(m.Config.Storage.Directory, id)
	signed, hash, e := readSignedManifest(dir)
	if e != nil || hash != a.Artifact.ManifestSHA256 || signed.Manifest.FenceToken != i.SourceFence.Token || signed.Manifest.ExportOperationID != i.SourceFence.OperationID || signed.Manifest.TargetNodeID != i.SourceFence.TargetNodeID {
		respond(w, 409, errorBody("EXPORT_MANIFEST_INVALID"))
		return
	}
	if e = storageStreamDeadline(w); e != nil {
		respond(w, 503, errorBody("STREAM_DEADLINES_UNAVAILABLE"))
		return
	}
	path := filepath.Join(dir, "manifest.json")
	max := int64(256 << 10)
	if file == "disk" {
		path = filepath.Join(dir, "disk.qcow2")
		max = m.Config.Storage.MaxArtifactBytes
		if e = m.verifyFlat(ctx, path, signed.Manifest); e != nil {
			respond(w, 409, errorBody("EXPORT_DISK_INVALID"))
			return
		}
	}
	digest, size, e := m.hashDisk(ctx, path, max)
	if e != nil {
		respond(w, 409, errorBody("EXPORT_FILE_INVALID"))
		return
	}
	f, e := openApproved(path, true)
	if e != nil {
		respond(w, 409, errorBody("EXPORT_FILE_INVALID"))
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.Header().Set("X-Content-SHA256", digest)
	w.Header().Set("X-Manifest-SHA256", hash)
	if file == "manifest" {
		w.Header().Set("Content-Type", "application/json")
	}
	h := sha256.New()
	n, e := io.Copy(w, io.TeeReader(contextReader{ctx, io.LimitReader(f, size+1)}, h))
	if e != nil || n != size || hex.EncodeToString(h.Sum(nil)) != digest {
		panic(http.ErrAbortHandler)
	}
}
func (m *Manager) validateIncomingManifest(raw []byte, id string) (nodeproto.StorageManifest, string, error) {
	signed, hash, e := decodeSignedManifest(raw)
	if e != nil {
		return signed.Manifest, "", e
	}
	a := signed.Manifest
	pin := m.Config.Storage.SourceCertificatePins[a.NodeID]
	data, _, _ := manifestBytes(signed)
	if pin == "" || verifyData(signed.CertificateDER, signed.Signature, exportSigningDomain, data, pin) != nil {
		return a, "", errors.New("source signature not approved")
	}
	task := nodeproto.TypedStorageTask{Protocol: nodeproto.StorageProtocol, OperationID: "11111111111111111111111111111111", NodeID: m.Config.NodeID, Action: "migrate_import", InstanceID: a.InstanceID, OwnerRef: a.OwnerRef, ArtifactID: id, TargetNodeID: a.TargetNodeID, SourceNodeID: a.NodeID, SourceOperationID: a.ExportOperationID, ManifestSHA256: hash, FenceToken: a.FenceToken}
	bindDirectImportTask(&task, a)
	if !task.DirectPublic.IsZero() && m.approvedDirect(task.DirectPublic) != nil {
		return a, "", errors.New("target public network not approved")
	}
	if !task.Valid() || a.ArtifactID != id || a.Kind != "migration" {
		return a, "", errors.New("target-bound migration manifest required")
	}
	image, ok := m.Config.Images[a.ImageID]
	if !ok || image.SHA256 != a.ImageSHA256 || a.DiskBytes > m.Config.Storage.MaxArtifactBytes {
		return a, "", errors.New("target approval or file limit rejected")
	}
	return a, hash, nil
}
func (m *Manager) receiveInbox(w http.ResponseWriter, r *http.Request, id, file string) {
	transfer, digest := r.Header.Get("X-Transfer-ID"), r.Header.Get("X-Content-SHA256")
	if !nodeproto.ValidID(transfer) || !hashString(digest) || r.ContentLength < 1 || len(r.TransferEncoding) != 0 {
		respond(w, 400, errorBody("EXACT_LENGTH_DIGEST_TRANSFER_REQUIRED"))
		return
	}
	if e := storageStreamDeadline(w); e != nil {
		respond(w, 503, errorBody("STREAM_DEADLINES_UNAVAILABLE"))
		return
	}
	ctx, release, e := m.acquireStorageIO(r.Context())
	if e != nil {
		respond(w, 409, errorBody("STORAGE_BUSY_OR_DISABLED"))
		return
	}
	defer release()
	w = &releaseResponseWriter{ResponseWriter: w, release: release}
	if e = ownedPath(m.Config.Storage.InboxDirectory, true, true); e != nil {
		respond(w, 403, errorBody("PRIVATE_INBOX_REQUIRED"))
		return
	}
	record, exists := m.Ledger.Inbox(id)
	if exists && record.TransferID != transfer {
		respond(w, 409, errorBody("TRANSFER_BINDING_CONFLICT"))
		return
	}
	var rawManifest []byte
	if file == "manifest" {
		if r.ContentLength > 256<<10 {
			respond(w, 413, errorBody("MANIFEST_TOO_LARGE"))
			return
		}
		rawManifest, e = io.ReadAll(io.LimitReader(contextReader{ctx, r.Body}, r.ContentLength+1))
		if e != nil || int64(len(rawManifest)) != r.ContentLength || nodeproto.Digest(rawManifest) != digest {
			respond(w, 400, errorBody("MANIFEST_LENGTH_OR_DIGEST_MISMATCH"))
			return
		}
		manifest, hash, err := m.validateIncomingManifest(rawManifest, id)
		if err != nil {
			respond(w, 400, errorBody("SOURCE_MANIFEST_NOT_APPROVED"))
			return
		}
		if !exists {
			if _, ok := m.Ledger.Artifact(id); ok {
				respond(w, 409, errorBody("ARTIFACT_ID_COLLISION"))
				return
			}
			record = InboxTransfer{TransferID: transfer, ArtifactID: id, ManifestSHA256: hash, Manifest: manifest, Files: map[string]InboxFileRecord{}, ReservedBytes: manifest.DiskBytes + (256 << 10)}
			used, budgetErr := m.Ledger.StorageReservedBytes()
			if budgetErr != nil {
				respond(w, 503, errorBody("INBOX_BUDGET_UNAVAILABLE"))
				return
			}
			if used > m.Config.Storage.MaxTotalBytes || record.ReservedBytes > m.Config.Storage.MaxTotalBytes-used {
				respond(w, 409, errorBody("INBOX_CAPACITY_EXHAUSTED"))
				return
			}
		}
		if record.ManifestSHA256 != hash || record.Manifest != manifest {
			respond(w, 409, errorBody("MANIFEST_BINDING_CONFLICT"))
			return
		}
	} else {
		if !exists || record.Files["manifest"].Status != "available" || r.ContentLength != record.Manifest.DiskBytes || digest != record.Manifest.DiskSHA256 {
			respond(w, 409, errorBody("APPROVED_MANIFEST_FIRST_REQUIRED"))
			return
		}
		if r.ContentLength > m.Config.Storage.MaxArtifactBytes {
			respond(w, 413, errorBody("DISK_TOO_LARGE"))
			return
		}
	}
	if prior, ok := record.Files[file]; ok {
		if prior.SHA256 != digest || prior.Bytes != r.ContentLength {
			respond(w, 409, errorBody("FILE_BINDING_CONFLICT"))
			return
		}
		receipt, _ := m.inboxReceipt(ctx, record, file)
		if receipt.Status == "available" {
			respond(w, 200, receipt)
		} else {
			respond(w, 409, errorBody("TRANSFER_UNCERTAIN_QUERY_RECEIPT"))
		}
		return
	}
	record.Files[file] = InboxFileRecord{SHA256: digest, Bytes: r.ContentLength, Status: "receiving"}
	if e = m.Ledger.SaveInbox(record); e != nil {
		respond(w, 503, errorBody("INBOX_JOURNAL_UNAVAILABLE"))
		return
	}
	dir := filepath.Join(m.Config.Storage.InboxDirectory, id)
	if !exists {
		if e = NoSymlinkPath(dir); e == nil {
			e = os.Mkdir(dir, 0700)
		}
		if e != nil {
			respond(w, 409, errorBody("PROTECTED_INBOX_ALREADY_EXISTS_OR_UNAVAILABLE"))
			return
		}
		if e = syncDirectory(m.Config.Storage.InboxDirectory); e != nil {
			respond(w, 503, errorBody("INBOX_DURABILITY_UNCERTAIN"))
			return
		}
	} else if e = ownedPath(dir, true, true); e != nil {
		respond(w, 403, errorBody("PRIVATE_INBOX_REQUIRED"))
		return
	}
	name := "manifest.json"
	if file == "disk" {
		name = "disk.qcow2"
	}
	temporary := filepath.Join(dir, "."+file+".partial-"+transfer)
	final := filepath.Join(dir, name)
	out, e := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		respond(w, 409, errorBody("PARTIAL_TRANSFER_REQUIRES_INSPECTION"))
		return
	}
	h := sha256.New()
	body := io.Reader(r.Body)
	if file == "manifest" {
		body = bytes.NewReader(rawManifest)
	}
	n, copyErr := io.Copy(io.MultiWriter(out, h), io.LimitReader(contextReader{ctx, body}, r.ContentLength+1))
	syncErr := out.Sync()
	closeErr := out.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil || n != r.ContentLength || hex.EncodeToString(h.Sum(nil)) != digest {
		record.Files[file] = InboxFileRecord{digest, r.ContentLength, "uncertain"}
		_ = m.Ledger.SaveInbox(record)
		respond(w, 409, errorBody("TRANSFER_UNCERTAIN_QUERY_RECEIPT"))
		return
	}
	if file == "disk" {
		if e = m.verifyFlat(ctx, temporary, record.Manifest); e != nil {
			record.Files[file] = InboxFileRecord{digest, r.ContentLength, "uncertain"}
			_ = m.Ledger.SaveInbox(record)
			respond(w, 409, errorBody("INBOX_DISK_VERIFICATION_FAILED"))
			return
		}
	}
	// Link commits the final name atomically without ever replacing another file.
	if e = os.Link(temporary, final); e == nil {
		e = syncDirectory(dir)
	}
	if e == nil {
		e = os.Remove(temporary)
	}
	if e == nil {
		e = syncDirectory(dir)
	}
	if e != nil {
		respond(w, 409, errorBody("TRANSFER_COMMIT_UNCERTAIN"))
		return
	}
	record.Files[file] = InboxFileRecord{digest, r.ContentLength, "available"}
	if e = m.Ledger.SaveInbox(record); e != nil {
		respond(w, 503, errorBody("TRANSFER_JOURNAL_UNCERTAIN_QUERY_RECEIPT"))
		return
	}
	receipt, _ := m.inboxReceipt(ctx, record, file)
	respond(w, 201, receipt)
}
func (m *Manager) inboxReceipt(ctx context.Context, t InboxTransfer, file string) (nodeproto.StorageFileReceipt, error) {
	a := t.Manifest
	f, ok := t.Files[file]
	r := nodeproto.StorageFileReceipt{Protocol: nodeproto.StorageProtocol, NodeID: m.Config.NodeID, TransferID: t.TransferID, ArtifactID: t.ArtifactID, File: file, SHA256: f.SHA256, Bytes: f.Bytes, Status: "uncertain", ManifestSHA256: t.ManifestSHA256, SourceNodeID: a.NodeID, SourceOperationID: a.ExportOperationID, InstanceID: a.InstanceID, OwnerRef: a.OwnerRef, FenceToken: a.FenceToken, TargetNodeID: a.TargetNodeID}
	if !ok {
		return r, ErrNotFound
	}
	name := "manifest.json"
	if file == "disk" {
		name = "disk.qcow2"
	}
	hash, n, e := m.hashDisk(ctx, filepath.Join(m.Config.Storage.InboxDirectory, t.ArtifactID, name), f.Bytes)
	if e != nil || hash != f.SHA256 || n != f.Bytes {
		return r, errors.New("file not fully committed or bytes mismatch")
	}
	r.Status = "available"
	return r, nil
}
func (m *Manager) approveControllerInbox(w http.ResponseWriter, r *http.Request, id string) {
	if !m.Config.Storage.AllowControllerInboxApproval {
		respond(w, 403, errorBody("ROOT_CONTROLLER_INBOX_APPROVAL_NOT_ENABLED"))
		return
	}
	media, _, mediaErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaErr != nil || media != "application/json" {
		respond(w, 415, errorBody("JSON_REQUIRED"))
		return
	}
	body, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 65536))
	var task nodeproto.StorageInboxApprovalTask
	if e != nil || canonicalDecode(body, &task) != nil || !task.Valid() || task.NodeID != m.Config.NodeID || task.ArtifactID != id {
		respond(w, 400, errorBody("INVALID_INBOX_APPROVAL_BINDING"))
		return
	}
	ctx, release, e := m.acquireStorageIO(r.Context())
	if e != nil {
		respond(w, 409, errorBody("STORAGE_BUSY_OR_DISABLED"))
		return
	}
	defer release()
	w = &releaseResponseWriter{ResponseWriter: w, release: release}
	record, ok := m.Ledger.Inbox(id)
	if !ok || record.TransferID != task.TransferID || record.ManifestSHA256 != task.ManifestSHA256 {
		respond(w, 409, errorBody("TRANSFER_BINDING_CONFLICT"))
		return
	}
	storage := nodeproto.TypedStorageTask{Protocol: nodeproto.StorageProtocol, OperationID: task.TransferID, NodeID: task.NodeID, Action: "migrate_import", InstanceID: task.InstanceID, OwnerRef: task.OwnerRef, ArtifactID: id, TargetNodeID: task.TargetNodeID, SourceNodeID: task.SourceNodeID, SourceOperationID: task.SourceOperationID, ManifestSHA256: task.ManifestSHA256, FenceToken: task.FenceToken}
	bindDirectImportTask(&storage, record.Manifest)
	if _, _, e = m.readImport(storage, false); e != nil {
		respond(w, 409, errorBody("SOURCE_FENCE_BINDING_REJECTED"))
		return
	}
	for _, file := range []string{"manifest", "disk"} {
		receipt, err := m.inboxReceipt(ctx, record, file)
		if err != nil || receipt.Status != "available" {
			respond(w, 409, errorBody("VERIFIED_COMPLETE_HANDOFF_REQUIRED"))
			return
		}
	}
	if _, _, e = m.readImport(storage, true); e != nil {
		approvalPath := filepath.Join(m.Config.Storage.InboxDirectory, id, "approval.json")
		if _, statErr := os.Lstat(approvalPath); !os.IsNotExist(statErr) || record.ApprovalState != "" {
			respond(w, 409, errorBody("APPROVAL_UNCERTAIN_QUERY_RECEIPT"))
			return
		}
		record.ApprovalState = "approving"
		if e = m.Ledger.SaveInbox(record); e != nil {
			respond(w, 503, errorBody("APPROVAL_JOURNAL_UNAVAILABLE"))
			return
		}
		if e = m.approveInboxWithAttestation(ctx, id, task.FenceToken, "controller-verified-signed-source-fence-and-preapproved-inbox"); e != nil {
			respond(w, 409, errorBody("TARGET_APPROVAL_VERIFICATION_FAILED"))
			return
		}
	}
	record.ApprovalState = "approved"
	if e = m.Ledger.SaveInbox(record); e != nil {
		respond(w, 503, errorBody("APPROVAL_COMMIT_UNCERTAIN_QUERY_RECEIPT"))
		return
	}

	receipt, e := m.inboxReceipt(ctx, record, "disk")
	if e != nil {
		respond(w, 409, errorBody("HANDOFF_CHANGED_DURING_APPROVAL"))
		return
	}
	receipt.Status = "approved"
	receipt.File = "approval"
	respond(w, 200, receipt)
}

// Release the I/O slot BEFORE a complete HTTP receipt can become visible. This
// mirrors operation-terminal publication and prevents relay->import NODE_BUSY.
type releaseResponseWriter struct {
	http.ResponseWriter
	release func()
}

func (w *releaseResponseWriter) WriteHeader(status int) {
	w.release()
	w.ResponseWriter.WriteHeader(status)
}
func (w *releaseResponseWriter) Write(p []byte) (int, error) {
	w.release()
	return w.ResponseWriter.Write(p)
}

func (m *Manager) getInboxApproval(w http.ResponseWriter, r *http.Request, id string) {
	record, ok := m.Ledger.Inbox(id)
	if !ok {
		respond(w, 404, errorBody("INBOX_NOT_FOUND"))
		return
	}
	if r.Header.Get("X-Transfer-ID") != record.TransferID {
		respond(w, 409, errorBody("TRANSFER_BINDING_CONFLICT"))
		return
	}
	path := filepath.Join(m.Config.Storage.InboxDirectory, id, "approval.json")
	if _, e := os.Lstat(path); os.IsNotExist(e) && record.ApprovalState == "" {
		respond(w, 404, errorBody("APPROVAL_NOT_REQUESTED"))
		return
	}
	a := record.Manifest
	t := nodeproto.TypedStorageTask{Protocol: nodeproto.StorageProtocol, OperationID: record.TransferID, NodeID: m.Config.NodeID, Action: "migrate_import", InstanceID: a.InstanceID, OwnerRef: a.OwnerRef, ArtifactID: id, TargetNodeID: a.TargetNodeID, SourceNodeID: a.NodeID, SourceOperationID: a.ExportOperationID, ManifestSHA256: record.ManifestSHA256, FenceToken: a.FenceToken}
	bindDirectImportTask(&t, a)
	receipt, _ := m.inboxReceipt(r.Context(), record, "disk")
	receipt.File = "approval"
	receipt.Status = "uncertain"
	if _, _, e := m.readImport(t, true); e != nil {
		respond(w, 200, receipt)
		return
	}
	for _, file := range []string{"manifest", "disk"} {
		if _, e := m.inboxReceipt(r.Context(), record, file); e != nil {
			respond(w, 200, receipt)
			return
		}
	}
	receipt.Status = "approved"
	respond(w, 200, receipt)
}

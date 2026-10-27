package hypervisor

import (
	"aster/cloud/internal/nodeproto"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type deadlineRecorder struct {
	*httptest.ResponseRecorder
	onHeader func()
}

func (w *deadlineRecorder) SetReadDeadline(time.Time) error  { return nil }
func (w *deadlineRecorder) SetWriteDeadline(time.Time) error { return nil }
func (w *deadlineRecorder) WriteHeader(status int) {
	if w.onHeader != nil {
		w.onHeader()
	}
	w.ResponseRecorder.WriteHeader(status)
}
func transportRequest(m *Manager, leaf *x509.Certificate, method, path string, body []byte, transfer string) *http.Request {
	r := authorizedRequest(m, method, path, body, leaf)
	r.Header.Set("X-Transfer-ID", transfer)
	r.Header.Set("X-Content-SHA256", nodeproto.Digest(body))
	return r
}
func doTransport(m *Manager, r *http.Request) *deadlineRecorder {
	w := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	m.Handler().ServeHTTP(w, r)
	return w
}
func newRelayFixture(t *testing.T) (*Manager, *Manager, *fakeRunner, nodeproto.TypedStorageTask, nodeproto.StorageResult, *x509.Certificate, string) {
	t.Helper()
	source, _, _, export, result := exportFixture(t)
	target, tf, _ := newStorageFixture(t, "node-b")
	_, cert, e := source.nodeSigningKey()
	if e != nil {
		t.Fatal(e)
	}
	target.Config.Storage.SourceCertificatePins[source.Config.NodeID] = nodeproto.Digest(cert)
	auth := certificates(t).goodLeaf
	source.Config.ExpectedControllerCertificateSHA256 = nodeproto.Digest(auth.Raw)
	target.Config.ExpectedControllerCertificateSHA256 = nodeproto.Digest(auth.Raw)
	return source, target, tf, export, result, auth, strings.Repeat("e", 32)
}
func relayFile(t *testing.T, source, target *Manager, leaf *x509.Certificate, id, file, transfer string) []byte {
	t.Helper()
	w := doTransport(source, transportRequest(source, leaf, "GET", "/v1/storage-artifacts/"+id+"/"+file, nil, ""))
	if w.Code != 200 {
		t.Fatal("export GET", w.Code, w.Body.String())
	}
	body := append([]byte{}, w.Body.Bytes()...)
	if w.Header().Get("X-Content-SHA256") != nodeproto.Digest(body) || w.Header().Get("Content-Length") == "" {
		t.Fatal("missing exact source stream headers")
	}
	request := transportRequest(target, leaf, "PUT", "/v1/storage-inbox/"+id+"/"+file, body, transfer)
	response := doTransport(target, request)
	if response.Code != 201 {
		t.Fatal("target PUT", response.Code, response.Body.String())
	}
	return body
}
func approvalTask(source, target *Manager, export nodeproto.TypedStorageTask, result nodeproto.StorageResult, transfer string) nodeproto.StorageInboxApprovalTask {
	return nodeproto.StorageInboxApprovalTask{Protocol: nodeproto.StorageProtocol, TransferID: transfer, ArtifactID: export.ArtifactID, NodeID: target.Config.NodeID, InstanceID: export.InstanceID, OwnerRef: export.OwnerRef, SourceNodeID: source.Config.NodeID, SourceOperationID: export.OperationID, TargetNodeID: target.Config.NodeID, ManifestSHA256: result.ManifestSHA256, FenceToken: result.FenceToken}
}
func TestControlledMTLSRelayApprovesButDoesNotImportOrStart(t *testing.T) {
	source, target, tf, export, result, leaf, transfer := newRelayFixture(t)
	id := export.ArtifactID
	for _, file := range []string{"manifest", "disk", "approval"} {
		w := doTransport(target, transportRequest(target, leaf, "GET", "/v1/storage-inbox/"+id+"/"+file, nil, transfer))
		if w.Code != 404 {
			t.Fatal("missing receipt not 404", w.Code, w.Body.String())
		}
	}
	manifest := relayFile(t, source, target, leaf, id, "manifest", transfer)
	w := doTransport(target, transportRequest(target, leaf, "GET", "/v1/storage-inbox/"+id+"/disk", nil, transfer))
	if w.Code != 404 {
		t.Fatal("first disk must be distinguishable from unknown", w.Code, w.Body.String())
	}
	disk := relayFile(t, source, target, leaf, id, "disk", transfer)
	for file, body := range map[string][]byte{"manifest": manifest, "disk": disk} {
		w = doTransport(target, transportRequest(target, leaf, "GET", "/v1/storage-inbox/"+id+"/"+file, nil, transfer))
		var receipt nodeproto.StorageFileReceipt
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &receipt) != nil || receipt.Status != "available" || receipt.SHA256 != nodeproto.Digest(body) || receipt.ManifestSHA256 != result.ManifestSHA256 {
			t.Fatal(w.Code, w.Body.String())
		}
		w = doTransport(target, transportRequest(target, leaf, "PUT", "/v1/storage-inbox/"+id+"/"+file, body, transfer))
		if w.Code != 200 {
			t.Fatal("same file replay", w.Code, w.Body.String())
		}
	}
	a := approvalTask(source, target, export, result, transfer)
	body, _ := json.Marshal(a)
	w = doTransport(target, transportRequest(target, leaf, "POST", "/v1/storage-inbox/"+id+"/approve", body, transfer))
	if w.Code != 403 {
		t.Fatal("default automatic approval enabled", w.Code, w.Body.String())
	}
	target.Config.Storage.AllowControllerInboxApproval = true
	recorder := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder(), onHeader: func() {
		target.admission.Lock()
		active := target.active
		target.admission.Unlock()
		if active {
			t.Error("receipt was exposed before I/O admission released")
		}
	}}
	target.Handler().ServeHTTP(recorder, transportRequest(target, leaf, "POST", "/v1/storage-inbox/"+id+"/approve", body, transfer))
	if recorder.Code != 200 {
		t.Fatal(recorder.Code, recorder.Body.String())
	}
	w = doTransport(target, transportRequest(target, leaf, "GET", "/v1/storage-inbox/"+id+"/approval", nil, transfer))
	var receipt nodeproto.StorageFileReceipt
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &receipt) != nil || receipt.File != "approval" || receipt.Status != "approved" || receipt.SHA256 != nodeproto.Digest(disk) {
		t.Fatal("approval GET", w.Code, w.Body.String())
	}
	if len(target.Ledger.Instances()) != 0 || tf.count(" define ") != 0 || tf.count(" start ") != 0 {
		t.Fatal("upload/approval performed VM actions")
	}
	imp := nodeproto.TypedStorageTask{Protocol: nodeproto.StorageProtocol, OperationID: strings.Repeat("f", 32), NodeID: target.Config.NodeID, Action: "migrate_import", InstanceID: a.InstanceID, OwnerRef: a.OwnerRef, ArtifactID: a.ArtifactID, TargetNodeID: a.TargetNodeID, SourceNodeID: a.SourceNodeID, SourceOperationID: a.SourceOperationID, ManifestSHA256: a.ManifestSHA256, FenceToken: a.FenceToken}
	assertStorageStatus(t, target, imp, "succeeded")
	if tf.count(" define ") != 1 || tf.count(" start ") != 0 {
		t.Fatal("import did not remain off")
	}
}
func TestRelayRejectsWrongLengthDigestTransferAndUnapprovedSource(t *testing.T) {
	for _, kind := range []string{"missing_length", "chunked", "wrong_hash", "wrong_target", "unapproved_source", "wrong_transfer"} {
		t.Run(kind, func(t *testing.T) {
			source, target, _, export, _, leaf, transfer := newRelayFixture(t)
			raw, _ := os.ReadFile(filepath.Join(source.Config.Storage.Directory, export.ArtifactID, "manifest.json"))
			if kind == "wrong_transfer" {
				relayFile(t, source, target, leaf, export.ArtifactID, "manifest", transfer)
			}
			r := transportRequest(target, leaf, "PUT", "/v1/storage-inbox/"+export.ArtifactID+"/manifest", raw, transfer)
			switch kind {
			case "missing_length":
				r.ContentLength = -1
			case "chunked":
				r.TransferEncoding = []string{"chunked"}
			case "wrong_hash":
				r.Header.Set("X-Content-SHA256", strings.Repeat("0", 64))
			case "wrong_target":
				target.Config.NodeID = "node-c"
			case "unapproved_source":
				target.Config.Storage.SourceCertificatePins = map[string]string{}
			case "wrong_transfer":
				r.Header.Set("X-Transfer-ID", strings.Repeat("d", 32))
			}
			w := doTransport(target, r)
			if w.Code < 400 {
				t.Fatal(w.Code, w.Body.String())
			}
			if kind == "wrong_transfer" {
				w = doTransport(target, transportRequest(target, leaf, "GET", "/v1/storage-inbox/"+export.ArtifactID+"/manifest", nil, strings.Repeat("d", 32)))
				if w.Code != 409 {
					t.Fatal("transfer mismatch disguised as absence", w.Code)
				}
			}
		})
	}
}
func TestPartialRelayAndApprovalMarkerStayUncertainNever404OrOverwrite(t *testing.T) {
	source, target, tf, export, _, leaf, transfer := newRelayFixture(t)
	id := export.ArtifactID
	relayFile(t, source, target, leaf, id, "manifest", transfer)
	disk, _ := os.ReadFile(filepath.Join(source.Config.Storage.Directory, id, "disk.qcow2"))
	r := transportRequest(target, leaf, "PUT", "/v1/storage-inbox/"+id+"/disk", disk[:len(disk)/2], transfer)
	r.ContentLength = int64(len(disk))
	r.Header.Set("X-Content-SHA256", nodeproto.Digest(disk))
	w := doTransport(target, r)
	if w.Code != 409 {
		t.Fatal(w.Code, w.Body.String())
	}
	w = doTransport(target, transportRequest(target, leaf, "GET", "/v1/storage-inbox/"+id+"/disk", nil, transfer))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"uncertain"`) {
		t.Fatal("partial upload reported absent or ready", w.Code, w.Body.String())
	}
	w = doTransport(target, transportRequest(target, leaf, "PUT", "/v1/storage-inbox/"+id+"/disk", disk, transfer))
	if w.Code != 409 {
		t.Fatal("partial silently overwritten", w.Code, w.Body.String())
	}
	if tf.count(" define ")+tf.count(" start ") != 0 {
		t.Fatal("partial acted on VM")
	}
	record, _ := target.Ledger.Inbox(id)
	record.ApprovalState = "approving"
	if e := target.Ledger.SaveInbox(record); e != nil {
		t.Fatal(e)
	}
	w = doTransport(target, transportRequest(target, leaf, "GET", "/v1/storage-inbox/"+id+"/approval", nil, transfer))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"uncertain"`) {
		t.Fatal("uncertain approval disguised as absence", w.Code, w.Body.String())
	}
}
func TestExportRequiresLiveOwnedOffAndPermanentFence(t *testing.T) {
	for _, kind := range []string{"running", "foreign_xml", "autostart", "no_fence"} {
		t.Run(kind, func(t *testing.T) {
			source, _, _, export, _, leaf, _ := newRelayFixture(t)
			i, _ := source.Ledger.Instance(export.InstanceID)
			f := source.Runner.(*fakeRunner)
			switch kind {
			case "running":
				f.states[i.Domain] = "running"
			case "foreign_xml":
				f.domains[i.Domain] = []byte(`<domain type="kvm"><name>foreign</name></domain>`)
			case "autostart":
				f.autostart = map[string]bool{i.Domain: true}
			case "no_fence":
				i.SourceFence = nil
				_, _ = source.Ledger.Finish(strings.Repeat("1", 32), "succeeded", "TEST_NO_FENCE", &i)
			}
			w := doTransport(source, transportRequest(source, leaf, "GET", "/v1/storage-artifacts/"+export.ArtifactID+"/disk", nil, ""))
			if w.Code != 409 {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
}
func TestSourcePrepareRefusesAutostartBeforeFencingOrCopy(t *testing.T) {
	m, f, task := newStorageFixture(t, "node-a")
	createOff(t, m, task)
	f.autostart = map[string]bool{"aster-" + task.InstanceID: true}
	// Each copy can consume the entire approved budget. Rejected pre-effect
	// attempts with fresh IDs must not eventually exhaust it.
	m.Config.Storage.MaxTotalBytes = (int64(task.Resources.SystemDiskGiB) + 1) << 30
	m.Config.Storage.MaxArtifactBytes = m.Config.Storage.MaxTotalBytes
	for n := 0; n < 3; n++ {
		s := storageTask(task, 10+n, "migrate_prepare", 100+n)
		s.TargetNodeID = "node-b"
		assertStorageStatus(t, m, s, "rejected")
		assertStorageStatus(t, m, s, "rejected") // No repeated host effect.
		a, ok := m.Ledger.Artifact(s.ArtifactID)
		used, e := m.Ledger.StorageReservedBytes()
		if !ok || a.Artifact.State != "rejected" || a.ReservedBytes != 0 || e != nil || used != 0 {
			t.Fatal("confirmed pre-effect rejection retained copy budget", a, used, e)
		}
		if _, e = os.Lstat(filepath.Join(m.Config.Storage.Directory, s.ArtifactID)); !os.IsNotExist(e) {
			t.Fatal("rejected source created an artifact directory", e)
		}
	}
	i, _ := m.Ledger.Instance(task.InstanceID)
	if i.SourceFence != nil || i.State != "shut off" || f.count(" convert ") != 0 {
		t.Fatal("autostart source fenced/exported incorrectly")
	}
	// The rejected binding and released reservation must survive reload too.
	_ = m.Ledger.Close()
	l, e := OpenLedger(m.Config.StateDirectory, m.Config.NodeID)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	m.Ledger = l
	if used, e := l.StorageReservedBytes(); e != nil || used != 0 {
		t.Fatal("released budget did not survive reload", used, e)
	}
	assertStorageStatus(t, m, storageTask(task, 20, "backup_create", 200), "succeeded")
}
func TestFlatHeaderBlocksExternalReferencesBeforeQemuParser(t *testing.T) {
	for _, kind := range []string{"backing_url", "external_data", "encryption", "unknown_feature", "dirty", "external_extension"} {
		t.Run(kind, func(t *testing.T) {
			m, f, task := newStorageFixture(t, "node-a")
			raw := fakeQcowBytes()
			switch kind {
			case "backing_url":
				binary.BigEndian.PutUint64(raw[8:16], 200)
				binary.BigEndian.PutUint32(raw[16:20], 20)
				copy(raw[200:], "https://evil.invalid/")
			case "external_data":
				binary.BigEndian.PutUint64(raw[72:80], 1<<2)
			case "encryption":
				binary.BigEndian.PutUint32(raw[32:36], 2)
			case "unknown_feature":
				binary.BigEndian.PutUint64(raw[72:80], 1<<63)
			case "dirty":
				binary.BigEndian.PutUint64(raw[72:80], 1)
			case "external_extension":
				binary.BigEndian.PutUint32(raw[104:108], 0x44415441)
			}
			path := filepath.Join(m.Config.Storage.InboxDirectory, "untrusted.qcow2")
			_ = os.WriteFile(path, raw, 0600)
			manifest := nodeproto.StorageManifest{DiskSHA256: nodeproto.Digest(raw), DiskBytes: int64(len(raw)), VirtualBytes: 1 << 30, Resources: task.Resources}
			before := f.count(QemuImg)
			if e := m.verifyFlat(context.Background(), path, manifest); e == nil {
				t.Fatal("external reference accepted")
			}
			if f.count(QemuImg) != before {
				t.Fatal("unsafe file reached qemu parser")
			}
		})
	}
}
func TestObservationRequiresFreshOwnershipAndNeverResolvesUncertainTask(t *testing.T) {
	m, f, task := newStorageFixture(t, "node-a")
	createOff(t, m, task)
	i, _ := m.Ledger.Instance(task.InstanceID)
	i.State = "running"
	_, _ = m.Ledger.Finish(task.OperationID, "succeeded", "TEST_STALE_CACHE", &i)
	observed, e := m.ObserveInstance(context.Background(), i.ID)
	if e != nil || observed.State != "shut off" || observed.IPv4 != i.IPv4 || observed.ObservedAt == "" {
		t.Fatal(observed, e)
	}
	stored, _ := m.Ledger.Instance(i.ID)
	if stored.State != "running" {
		t.Fatal("observation mutated operation/cache")
	}
	m.admission.Lock()
	m.active = true
	m.admission.Unlock()
	before := len(f.commands)
	if _, e = m.ObserveInstance(context.Background(), i.ID); e == nil {
		t.Fatal("busy observation confirmed")
	}
	m.admission.Lock()
	m.active = false
	m.admission.Unlock()
	if len(f.commands) != before {
		t.Fatal("busy observation touched libvirt")
	}
	i.State = "uncertain"
	_, _ = m.Ledger.Finish(task.OperationID, "succeeded", "TEST_PENDING", &i)
	if _, e = m.ObserveInstance(context.Background(), i.ID); e == nil {
		t.Fatal("unknown state presented as fresh")
	}
	i.State = "shut off"
	_, _ = m.Ledger.Finish(task.OperationID, "succeeded", "TEST_RESET", &i)
	f.domains[i.Domain] = bytes.ReplaceAll(f.domains[i.Domain], []byte(i.IPv4), []byte("192.0.2.199"))
	if _, e = m.ObserveInstance(context.Background(), i.ID); e == nil {
		t.Fatal("cached address returned without owned NIC")
	}
}

package control

import (
	"aster/cloud/internal/nodeproto"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

const TransferProtocol = "aster.migration.transfer/1"

type TransferIntent struct {
	Protocol         string                             `json:"protocol"`
	SourceProfileSHA string                             `json:"source_profile_sha256"`
	Approval         nodeproto.StorageInboxApprovalTask `json:"approval"`
}

func (t TransferIntent) Valid() bool {
	return t.Protocol == TransferProtocol && shaRE.MatchString(t.SourceProfileSHA) && t.Approval.Valid()
}
func (t TransferIntent) BytesAndDigest() ([]byte, string, error) {
	if !t.Valid() {
		return nil, "", ErrInput
	}
	raw, err := json.Marshal(t)
	return raw, nodeproto.Digest(raw), err
}
func DecodeTransferIntent(raw []byte) (TransferIntent, error) {
	var t TransferIntent
	if !strict(raw, &t) || !t.Valid() {
		return t, ErrInput
	}
	canonical, _, err := t.BytesAndDigest()
	if err != nil || !bytes.Equal(raw, canonical) {
		return TransferIntent{}, ErrInput
	}
	return t, nil
}

const transferSigningDomain = "aster.node.storage/1 signed-manifest\n"

type transferRelay struct {
	source, target *NodeClient
	intent         TransferIntent
	instance       Instance
	direct         nodeproto.DirectPublicBinding
}
type transferManifest struct {
	raw      []byte
	fileSHA  string
	manifest nodeproto.StorageManifest
}

func (r transferRelay) valid() bool {
	if r.source == nil || r.target == nil || !r.intent.Valid() {
		return false
	}
	a := r.intent.Approval
	return r.intent.SourceProfileSHA == r.source.profile.Digest() && a.SourceNodeID == r.source.profile.ID && a.TargetNodeID == r.target.profile.ID && a.NodeID == r.target.profile.ID && r.instance.ID == a.InstanceID && r.instance.OwnerRef == a.OwnerRef && r.instance.NodeID == a.SourceNodeID && r.instance.Resources.ComputeNodeID == a.SourceNodeID
}

func (w OperationWorker) transferBinding(ctx context.Context, o Operation) (TransferIntent, NodeProfile, NodeProfile, Instance, error) {
	fail := func() (TransferIntent, NodeProfile, NodeProfile, Instance, error) {
		return TransferIntent{}, NodeProfile{}, NodeProfile{}, Instance{}, ErrState
	}
	t, err := DecodeTransferIntent(o.Request)
	if err != nil || o.Protocol != TransferProtocol || o.Action != "migrate_transfer" || nodeproto.Digest(o.Request) != o.RequestSHA || t.Approval.TransferID != o.ID || t.Approval.ArtifactID != o.ArtifactID || t.Approval.InstanceID != o.InstanceID || t.Approval.NodeID != o.NodeID || o.TargetNodeID != o.NodeID {
		return fail()
	}
	a := t.Approval
	source, ok := w.Config.Node(a.SourceNodeID)
	if !ok || source.Digest() != t.SourceProfileSHA {
		return fail()
	}
	target, ok := w.Config.Node(a.TargetNodeID)
	if !ok || target.Digest() != o.ProfileSHA {
		return fail()
	}
	v, err := w.Store.Instance(ctx, o.InstanceID)
	if err != nil {
		return fail()
	}
	m, err := scanMigration(w.Store.DB.QueryRowContext(ctx, "SELECT "+migrationColumns+" FROM controller_migrations WHERE id=?", o.ArtifactID))
	if err != nil {
		return fail()
	}
	if v.OwnerRef != a.OwnerRef || v.NodeID != source.ID || v.Resources.ComputeNodeID != source.ID || m.InstanceID != v.ID || m.ID != a.ArtifactID || m.SourceNodeID != source.ID || m.TargetNodeID != target.ID || m.TargetProfileSHA != o.ProfileSHA || m.SourceOperationID != a.SourceOperationID || m.ManifestSHA != a.ManifestSHA256 || m.FenceToken != a.FenceToken || (m.Phase != "prepared" && m.Phase != "transferred") {
		return fail()
	}
	wanted := v.Resources
	wanted.ComputeNodeID = target.ID
	wanted.DatacenterID = target.DatacenterID
	wanted.NodeGroupID = target.GroupID
	// Storage is the explicit target mapping frozen by authenticated preparation,
	// not a source ID guessed or silently preserved across different hosts.
	if !identifier.MatchString(m.Resources.SystemStorageID) {
		return fail()
	}
	var capsRaw []byte
	if err = w.Store.DB.QueryRowContext(ctx, "SELECT capabilities FROM controller_nodes WHERE id=? AND profile_sha256=?", target.ID, target.Digest()).Scan(&capsRaw); err != nil {
		return fail()
	}
	var caps Capability
	if !strict(capsRaw, &caps) || caps.NodeID != target.ID || caps.Protocol != nodeproto.Protocol || !contains(caps.StorageIDs, m.Resources.SystemStorageID) {
		return fail()
	}
	wanted.SystemStorageID = m.Resources.SystemStorageID
	if wanted != m.Resources {
		return fail()
	}
	return t, source, target, v, nil
}
func (w OperationWorker) transferClients(ctx context.Context, o Operation) (transferRelay, error) {
	t, source, target, v, err := w.transferBinding(ctx, o)
	if err != nil {
		return transferRelay{}, err
	}
	s, err := NewNodeClient(ctx, source)
	if err != nil {
		return transferRelay{}, err
	}
	d, err := NewNodeClient(ctx, target)
	if err != nil {
		return transferRelay{}, err
	}
	var direct nodeproto.DirectPublicBinding
	prepare, e := w.Store.Operation(ctx, t.Approval.SourceOperationID)
	if e != nil {
		return transferRelay{}, e
	}
	stored, e := nodeproto.DecodeStorageTask(prepare.Request)
	if e != nil {
		return transferRelay{}, e
	}
	direct = stored.DirectPublic
	if !direct.IsZero() {
		targetBinding := direct
		targetBinding.NodeID = target.ID
		targetBinding.Generation++
		if !w.Config.approvesDirectPublic(targetBinding) {
			return transferRelay{}, ErrState
		}
	}
	return transferRelay{source: s, target: d, intent: t, instance: v, direct: direct}, nil
}
func (w OperationWorker) dispatchTransfer(ctx context.Context, o Operation) (Operation, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	if o.State != "accepted" {
		return o, ErrState
	}
	relay, err := w.transferClients(ctx, o)
	if err != nil {
		return o, err
	}
	o, err = w.Store.ClaimOperation(ctx, o.ID, w.Config, w.now())
	if err != nil {
		return o, err
	}
	// Nothing is sent before durable sending. Any later failure is unknown, not
	// permission to repeat a PUT/POST or to advance import/activation.
	err = relay.dispatch(ctx)
	status := "uncertain"
	if err == nil {
		status = "succeeded"
	}
	finish, stop := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer stop()
	saved, saveErr := w.Store.CompleteOperation(finish, w.Config, o.ID, status, nil, w.now())
	if saveErr != nil {
		return o, saveErr
	}
	if err != nil {
		return saved, ErrUnavailable
	}
	return saved, nil
}
func (w OperationWorker) reconcileTransfer(ctx context.Context, o Operation) (Operation, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	if o.State != "sending" && o.State != "dispatched" && o.State != "uncertain" {
		return o, ErrState
	}
	relay, err := w.transferClients(ctx, o)
	if err != nil {
		return o, err
	}
	if err = relay.reconcile(ctx); err != nil {
		return o, ErrUnavailable
	}
	return w.Store.CompleteOperation(ctx, w.Config, o.ID, "succeeded", nil, w.now())
}

// Each call owns exactly one connection attempt. There is no proxy, redirect,
// HTTP/2, pool reuse, GetBody or implicit replay, including for streamed PUTs.
// NodeClient already froze DNS/CIDR, CA, hostname and exact leaf certificate pin.
func (c *NodeClient) transferRequest(ctx context.Context, method, path string, body io.Reader, length int64, sha, transfer string) (*http.Response, func(), error) {
	req, err := http.NewRequestWithContext(ctx, method, c.profile.Endpoint+path, body)
	if err != nil {
		return nil, func() {}, ErrInput
	}
	req.GetBody = nil
	req.Close = true
	req.ContentLength = length
	req.Header.Set("Accept", "application/json")
	if transfer != "" {
		req.Header.Set("X-Transfer-ID", transfer)
	}
	if sha != "" {
		req.Header.Set("X-Content-SHA256", sha)
	}
	if method == "PUT" {
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	if method == "POST" {
		req.Header.Set("Content-Type", "application/json")
	}
	var dials atomic.Int32
	dialer := net.Dialer{Timeout: 5 * time.Second, KeepAlive: -1}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DisableCompression: true, ForceAttemptHTTP2: false, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}, TLSClientConfig: c.tls.Clone(), TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 20 * time.Minute, MaxResponseHeaderBytes: 16 << 10, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		if !dials.CompareAndSwap(0, 1) {
			return nil, ErrUnavailable
		}
		return dialer.DialContext(ctx, network, c.address)
	}}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		transport.CloseIdleConnections()
		return nil, func() {}, ErrUnavailable
	}
	cleanup := func() { response.Body.Close(); transport.CloseIdleConnections() }
	if response.Header.Get("Content-Encoding") != "" {
		cleanup()
		return nil, func() {}, ErrUnavailable
	}
	return response, cleanup, nil
}
func receiptBody(response *http.Response) ([]byte, error) {
	media, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return nil, ErrUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(raw) > 65536 {
		return nil, ErrUnavailable
	}
	return raw, nil
}
func (r transferRelay) receiptMatches(v nodeproto.StorageFileReceipt, file, sha string, length int64) bool {
	a := r.intent.Approval
	status := "available"
	if file == "approval" {
		status = "approved"
	}
	return v.Protocol == nodeproto.StorageProtocol && v.NodeID == a.NodeID && v.TransferID == a.TransferID && v.ArtifactID == a.ArtifactID && v.File == file && v.SHA256 == sha && v.Bytes == length && v.Status == status && v.ManifestSHA256 == a.ManifestSHA256 && v.SourceNodeID == a.SourceNodeID && v.SourceOperationID == a.SourceOperationID && v.InstanceID == a.InstanceID && v.OwnerRef == a.OwnerRef && v.FenceToken == a.FenceToken && v.TargetNodeID == a.TargetNodeID
}
func (r transferRelay) getReceipt(ctx context.Context, file, sha string, length int64) (bool, error) {
	path := "/v1/storage-inbox/" + r.intent.Approval.ArtifactID + "/" + file
	response, close, err := r.target.transferRequest(ctx, "GET", path, nil, 0, "", r.intent.Approval.TransferID)
	if err != nil {
		return false, err
	}
	defer close()
	raw, err := receiptBody(response)
	if err != nil {
		return false, err
	}
	if response.StatusCode == 404 {
		var missing struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if !strict(raw, &missing) {
			return false, ErrUnavailable
		}
		if missing.Error.Code == "INBOX_NOT_FOUND" || missing.Error.Code == "FILE_NOT_RECEIVED" && file != "approval" || missing.Error.Code == "APPROVAL_NOT_REQUESTED" && file == "approval" {
			return false, nil
		}
		return false, ErrUnavailable
	}
	var receipt nodeproto.StorageFileReceipt
	if response.StatusCode != 200 || !strict(raw, &receipt) || !r.receiptMatches(receipt, file, sha, length) {
		return false, ErrUnavailable
	}
	return true, nil
}
func (r transferRelay) verifyWriteReceipt(response *http.Response, file, sha string, length int64) error {
	raw, err := receiptBody(response)
	if err != nil {
		return err
	}
	var receipt nodeproto.StorageFileReceipt
	if response.StatusCode != 200 && response.StatusCode != 201 || !strict(raw, &receipt) || !r.receiptMatches(receipt, file, sha, length) {
		return ErrUnavailable
	}
	return nil
}
func (r transferRelay) readManifest(ctx context.Context) (transferManifest, error) {
	a := r.intent.Approval
	response, close, err := r.source.transferRequest(ctx, "GET", "/v1/storage-artifacts/"+a.ArtifactID+"/manifest", nil, 0, "", a.TransferID)
	if err != nil {
		return transferManifest{}, err
	}
	defer close()
	media, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || response.StatusCode != 200 || response.ContentLength < 1 || response.ContentLength > 65536 || len(response.TransferEncoding) != 0 || response.Header.Get("X-Manifest-SHA256") != a.ManifestSHA256 {
		return transferManifest{}, ErrUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || int64(len(raw)) != response.ContentLength || nodeproto.Digest(raw) != response.Header.Get("X-Content-SHA256") {
		return transferManifest{}, ErrUnavailable
	}
	var signed nodeproto.SignedStorageManifest
	if !strict(raw, &signed) {
		return transferManifest{}, ErrUnavailable
	}
	canonical, err := json.Marshal(signed)
	if err != nil || !bytes.Equal(canonical, raw) {
		return transferManifest{}, ErrUnavailable
	}
	m := signed.Manifest
	inner, _ := json.Marshal(m)
	if nodeproto.Digest(inner) != a.ManifestSHA256 || (m.Protocol != nodeproto.StorageProtocol || !m.DirectPublic.IsZero()) && r.direct.IsZero() || !r.direct.IsZero() && (m.Protocol != nodeproto.StorageDirectProtocol || m.DirectPublic != r.direct) || m.Kind != "migration" || m.ArtifactID != a.ArtifactID || m.NodeID != a.SourceNodeID || m.InstanceID != a.InstanceID || m.OwnerRef != a.OwnerRef || m.TargetNodeID != a.TargetNodeID || m.ExportOperationID != a.SourceOperationID || m.FenceToken != a.FenceToken || m.SourceDomain != "aster-"+m.InstanceID || m.Hostname != r.instance.Hostname || m.Resources != r.instance.Resources || m.ImageID != m.Resources.ImageID || !shaRE.MatchString(m.ImageSHA256) || !shaRE.MatchString(m.DiskSHA256) || m.Resources.SystemDiskGiB < 1 || m.Resources.SystemDiskGiB > (1<<20) || m.DiskBytes < 1 || m.DiskBytes > ((int64(m.Resources.SystemDiskGiB)+1)<<30) || m.VirtualBytes < 1 || m.VirtualBytes > uint64(m.Resources.SystemDiskGiB)<<30 {
		return transferManifest{}, ErrState
	}
	if _, err = time.Parse(time.RFC3339Nano, m.CreatedAt); err != nil {
		return transferManifest{}, ErrState
	}
	der, err := base64.StdEncoding.DecodeString(signed.CertificateDER)
	if err != nil || len(der) > 65536 || nodeproto.Digest(der) != r.source.profile.ServerCertificateSHA256 {
		return transferManifest{}, ErrState
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return transferManifest{}, ErrState
	}
	sig, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil || len(sig) > 16384 {
		return transferManifest{}, ErrState
	}
	message := append([]byte(transferSigningDomain), inner...)
	hash := sha256.Sum256(message)
	valid := false
	switch key := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		valid = ecdsa.VerifyASN1(key, hash[:], sig)
	case *rsa.PublicKey:
		valid = rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], sig) == nil
	case ed25519.PublicKey:
		valid = ed25519.Verify(key, message, sig)
	}
	if !valid {
		return transferManifest{}, ErrState
	}
	return transferManifest{raw, nodeproto.Digest(raw), m}, nil
}
func (r transferRelay) putManifest(ctx context.Context, m transferManifest) error {
	response, close, err := r.target.transferRequest(ctx, "PUT", "/v1/storage-inbox/"+r.intent.Approval.ArtifactID+"/manifest", bytes.NewReader(m.raw), int64(len(m.raw)), m.fileSHA, r.intent.Approval.TransferID)
	if err != nil {
		return err
	}
	defer close()
	return r.verifyWriteReceipt(response, "manifest", m.fileSHA, int64(len(m.raw)))
}
func (r transferRelay) putDisk(ctx context.Context, m transferManifest) error {
	source, closeSource, err := r.source.transferRequest(ctx, "GET", "/v1/storage-artifacts/"+r.intent.Approval.ArtifactID+"/disk", nil, 0, "", r.intent.Approval.TransferID)
	if err != nil {
		return err
	}
	defer closeSource()
	if source.StatusCode != 200 || source.ContentLength != m.manifest.DiskBytes || len(source.TransferEncoding) != 0 || source.Header.Get("X-Content-SHA256") != m.manifest.DiskSHA256 || source.Header.Get("X-Manifest-SHA256") != r.intent.Approval.ManifestSHA256 {
		return ErrUnavailable
	}
	media, _, err := mime.ParseMediaType(source.Header.Get("Content-Type"))
	if err != nil || media != "application/octet-stream" {
		return ErrUnavailable
	}
	reader, writer := io.Pipe()
	defer reader.Close()
	done := make(chan error, 1)
	go func() {
		h := sha256.New()
		n, copyErr := io.CopyBuffer(io.MultiWriter(writer, h), io.LimitReader(source.Body, m.manifest.DiskBytes+1), make([]byte, 64<<10))
		if copyErr == nil && (n != m.manifest.DiskBytes || hex.EncodeToString(h.Sum(nil)) != m.manifest.DiskSHA256) {
			copyErr = ErrUnavailable
		}
		writer.CloseWithError(copyErr)
		done <- copyErr
	}()
	response, closeTarget, err := r.target.transferRequest(ctx, "PUT", "/v1/storage-inbox/"+r.intent.Approval.ArtifactID+"/disk", reader, m.manifest.DiskBytes, m.manifest.DiskSHA256, r.intent.Approval.TransferID)
	if err != nil {
		reader.CloseWithError(err)
		source.Body.Close()
		<-done
		return err
	}
	defer closeTarget()
	if err = r.verifyWriteReceipt(response, "disk", m.manifest.DiskSHA256, m.manifest.DiskBytes); err != nil {
		reader.CloseWithError(err)
		source.Body.Close()
		<-done
		return err
	}
	select {
	case copyErr := <-done:
		return copyErr
	case <-ctx.Done():
		reader.CloseWithError(ctx.Err())
		source.Body.Close()
		<-done
		return ErrUnavailable
	}
}
func (r transferRelay) approve(ctx context.Context, m transferManifest) error {
	raw, _ := json.Marshal(r.intent.Approval)
	response, close, err := r.target.transferRequest(ctx, "POST", "/v1/storage-inbox/"+r.intent.Approval.ArtifactID+"/approve", bytes.NewReader(raw), int64(len(raw)), nodeproto.Digest(raw), r.intent.Approval.TransferID)
	if err != nil {
		return err
	}
	defer close()
	return r.verifyWriteReceipt(response, "approval", m.manifest.DiskSHA256, m.manifest.DiskBytes)
}
func (r transferRelay) dispatch(ctx context.Context) error {
	if !r.valid() {
		return ErrState
	}
	m, err := r.readManifest(ctx)
	if err != nil {
		return err
	}
	for _, file := range []string{"manifest", "disk", "approval"} {
		sha, length := m.fileSHA, int64(len(m.raw))
		if file != "manifest" {
			sha, length = m.manifest.DiskSHA256, m.manifest.DiskBytes
		}
		present, err := r.getReceipt(ctx, file, sha, length)
		if err != nil {
			return err
		}
		if present {
			continue
		}
		switch file {
		case "manifest":
			err = r.putManifest(ctx, m)
		case "disk":
			err = r.putDisk(ctx, m)
		case "approval":
			err = r.approve(ctx, m)
		}
		if err != nil {
			return err
		}
	}
	return nil
}
func (r transferRelay) reconcile(ctx context.Context) error {
	if !r.valid() {
		return ErrState
	}
	// Even recovery re-verifies the exact pinned, signed source proof. An offline
	// source is conservatively unknown; no subset of receipts authorizes import.
	m, err := r.readManifest(ctx)
	if err != nil {
		return err
	}
	for _, file := range []string{"manifest", "disk", "approval"} {
		sha, length := m.fileSHA, int64(len(m.raw))
		if file != "manifest" {
			sha, length = m.manifest.DiskSHA256, m.manifest.DiskBytes
		}
		present, err := r.getReceipt(ctx, file, sha, length)
		if err != nil || !present {
			return ErrUnavailable
		}
	}
	return nil
}

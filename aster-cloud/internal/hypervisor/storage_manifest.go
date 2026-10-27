package hypervisor

import (
	"aster/cloud/internal/nodeproto"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

const exportSigningDomain = "aster.node.storage/1 signed-manifest\n"
const approvalSigningDomain = "aster.node.storage/1 root-import-approval\n"

type importApproval struct {
	Protocol          string `json:"protocol"`
	TargetNodeID      string `json:"target_node_id"`
	SourceNodeID      string `json:"source_node_id"`
	SourceOperationID string `json:"source_operation_id"`
	ArtifactID        string `json:"artifact_id"`
	InstanceID        string `json:"instance_id"`
	OwnerRef          string `json:"owner_ref"`
	ManifestSHA256    string `json:"manifest_sha256"`
	FenceToken        string `json:"fence_token"`
	Attestation       string `json:"attestation"`
	ApprovedAt        string `json:"approved_at"`
}
type signedApproval struct {
	Approval       importApproval `json:"approval"`
	CertificateDER string         `json:"certificate_der"`
	Signature      string         `json:"signature"`
}

func (m *Manager) nodeSigningKey() (crypto.Signer, []byte, error) {
	cert, e := readApproved(m.Config.Certificate, false, 1<<20)
	if e != nil {
		return nil, nil, e
	}
	key, e := readApproved(m.Config.PrivateKey, true, 1<<20)
	if e != nil {
		return nil, nil, e
	}
	pair, e := tls.X509KeyPair(cert, key)
	if e != nil || len(pair.Certificate) == 0 {
		return nil, nil, errors.New("node signing identity unavailable")
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, nil, errors.New("unsupported node signing key")
	}
	return signer, pair.Certificate[0], nil
}
func signData(key crypto.Signer, domain string, data []byte) (string, error) {
	message := append([]byte(domain), data...)
	var payload []byte
	var opts crypto.SignerOpts = crypto.SHA256
	if _, ok := key.Public().(ed25519.PublicKey); ok {
		payload = message
		opts = crypto.Hash(0)
	} else {
		h := sha256.Sum256(message)
		payload = h[:]
	}
	signature, e := key.Sign(rand.Reader, payload, opts)
	if e != nil {
		return "", e
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}
func verifyData(certDER, signature, domain string, data []byte, pin string) error {
	der, e := base64.StdEncoding.DecodeString(certDER)
	if e != nil || len(der) > 65536 {
		return errors.New("invalid manifest signer")
	}
	if pin != "" && nodeproto.Digest(der) != pin {
		return errors.New("manifest signer not approved")
	}
	cert, e := x509.ParseCertificate(der)
	if e != nil {
		return e
	}
	sig, e := base64.StdEncoding.DecodeString(signature)
	if e != nil || len(sig) > 16384 {
		return errors.New("invalid signature")
	}
	message := append([]byte(domain), data...)
	hash := sha256.Sum256(message)
	switch key := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if ecdsa.VerifyASN1(key, hash[:], sig) {
			return nil
		}
	case *rsa.PublicKey:
		if e = rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], sig); e == nil {
			return nil
		}
	case ed25519.PublicKey:
		if ed25519.Verify(key, message, sig) {
			return nil
		}
	}
	return errors.New("manifest signature rejected")
}
func canonicalDecode(raw []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(target); e != nil {
		return e
	}
	canonical, e := json.Marshal(target)
	if e != nil || !bytes.Equal(canonical, raw) {
		return errors.New("noncanonical or ambiguous protected metadata")
	}
	return nil
}
func manifestBytes(s nodeproto.SignedStorageManifest) ([]byte, string, error) {
	raw, e := json.Marshal(s.Manifest)
	return raw, nodeproto.Digest(raw), e
}
func (m *Manager) writeManifest(directory string, manifest nodeproto.StorageManifest) (nodeproto.SignedStorageManifest, string, error) {
	key, cert, e := m.nodeSigningKey()
	if e != nil {
		return nodeproto.SignedStorageManifest{}, "", e
	}
	raw, e := json.Marshal(manifest)
	if e != nil {
		return nodeproto.SignedStorageManifest{}, "", e
	}
	signature, e := signData(key, exportSigningDomain, raw)
	if e != nil {
		return nodeproto.SignedStorageManifest{}, "", e
	}
	signed := nodeproto.SignedStorageManifest{Manifest: manifest, CertificateDER: base64.StdEncoding.EncodeToString(cert), Signature: signature}
	body, e := json.Marshal(signed)
	if e != nil {
		return signed, "", e
	}
	if e = writeExclusive(filepath.Join(directory, "manifest.json"), body); e != nil {
		return signed, "", e
	}
	return signed, nodeproto.Digest(raw), syncDirectory(directory)
}
func readSignedManifest(directory string) (nodeproto.SignedStorageManifest, string, error) {
	var s nodeproto.SignedStorageManifest
	raw, e := readApproved(filepath.Join(directory, "manifest.json"), true, 256<<10)
	if e != nil {
		return s, "", e
	}
	return decodeSignedManifest(raw)
}
func decodeSignedManifest(raw []byte) (nodeproto.SignedStorageManifest, string, error) {
	var s nodeproto.SignedStorageManifest
	e := error(nil)
	if e = canonicalDecode(raw, &s); e != nil {
		return s, "", e
	}
	manifest, hash, e := manifestBytes(s)
	if e != nil {
		return s, "", e
	}
	if e = verifyData(s.CertificateDER, s.Signature, exportSigningDomain, manifest, ""); e != nil {
		return s, "", e
	}
	m := s.Manifest
	if (m.Protocol != nodeproto.StorageProtocol && m.Protocol != nodeproto.StorageDirectProtocol) || !nodeproto.ValidID(m.ArtifactID) || !nodeproto.ValidID(m.InstanceID) || !nodeproto.ValidID(m.OwnerRef) || !nodeproto.ValidNodeID(m.NodeID) || m.SourceDomain != "aster-"+m.InstanceID || !hashString(m.DiskSHA256) || !hashString(m.ImageSHA256) || m.DiskBytes < 1 || m.DiskBytes > (int64(m.Resources.SystemDiskGiB)+1)<<30 || m.VirtualBytes < 1 || m.Resources.SystemDiskGiB < 1 || m.VirtualBytes > uint64(m.Resources.SystemDiskGiB)<<30 || m.ImageID != m.Resources.ImageID {
		return s, "", errors.New("invalid artifact manifest")
	}
	if m.Protocol == nodeproto.StorageProtocol && !m.DirectPublic.IsZero() || m.Protocol == nodeproto.StorageDirectProtocol && !m.DirectPublic.ValidFor(nodeproto.NodeTask{NodeID: m.NodeID, InstanceID: m.InstanceID, OwnerRef: m.OwnerRef, Resources: m.Resources}) {
		return s, "", errors.New("artifact direct network binding rejected")
	}
	task := nodeproto.NodeTask{Protocol: nodeproto.Protocol, NodeID: m.NodeID, OperationID: "11111111111111111111111111111111", Action: "create", InstanceID: m.InstanceID, OwnerRef: m.OwnerRef, Hostname: m.Hostname}
	if !task.Valid() {
		return s, "", errors.New("manifest identity rejected")
	}
	if _, e = time.Parse(time.RFC3339Nano, m.CreatedAt); e != nil {
		return s, "", e
	}
	return s, hash, nil
}
func (m *Manager) readImport(task nodeproto.TypedStorageTask, requireApproval bool) (nodeproto.StorageManifest, string, error) {
	if !m.Config.Storage.Enabled || !m.Config.Storage.AllowMigration {
		return nodeproto.StorageManifest{}, "", ErrUnsupported
	}
	dir := filepath.Join(m.Config.Storage.InboxDirectory, task.ArtifactID)
	if e := ownedPath(m.Config.Storage.InboxDirectory, true, true); e != nil {
		return nodeproto.StorageManifest{}, "", e
	}
	if e := ownedPath(dir, true, true); e != nil {
		return nodeproto.StorageManifest{}, "", e
	}
	signed, hash, e := readSignedManifest(dir)
	if e != nil {
		return nodeproto.StorageManifest{}, "", e
	}
	manifest := signed.Manifest
	pin := m.Config.Storage.SourceCertificatePins[manifest.NodeID]
	if pin == "" {
		return manifest, "", errors.New("source node is not approved")
	}
	raw, _, _ := manifestBytes(signed)
	if e = verifyData(signed.CertificateDER, signed.Signature, exportSigningDomain, raw, pin); e != nil {
		return manifest, "", e
	}
	if manifest.Kind != "migration" || manifest.NodeID != task.SourceNodeID || manifest.TargetNodeID != m.Config.NodeID || manifest.TargetNodeID != task.TargetNodeID || manifest.ArtifactID != task.ArtifactID || manifest.InstanceID != task.InstanceID || manifest.OwnerRef != task.OwnerRef || manifest.ExportOperationID != task.SourceOperationID || manifest.FenceToken != task.FenceToken || hash != task.ManifestSHA256 || !nodeproto.ValidID(manifest.ExportOperationID) || !hashString(manifest.FenceToken) {
		return manifest, "", errors.New("migration binding rejected")
	}
	if task.Protocol != manifest.Protocol || !nodeproto.SameDirectAddress(manifest.DirectPublic, task.DirectPublic) || !task.DirectPublic.IsZero() && task.DirectPublic.Generation != manifest.DirectPublic.Generation+1 {
		return manifest, "", errors.New("migration must preserve exact public guest identity")
	}
	if !task.DirectPublic.IsZero() && m.approvedDirect(task.DirectPublic) != nil {
		return manifest, "", errors.New("target public network not approved")
	}
	image, ok := m.Config.Images[manifest.ImageID]
	if !ok || image.SHA256 != manifest.ImageSHA256 {
		return manifest, "", errors.New("migration image approval mismatch")
	}
	if requireApproval {
		body, e := readApproved(filepath.Join(dir, "approval.json"), true, 256<<10)
		if e != nil {
			return manifest, "", errors.New("awaiting protected root import approval")
		}
		var approved signedApproval
		if e = canonicalDecode(body, &approved); e != nil {
			return manifest, "", e
		}
		a := approved.Approval
		if a.Protocol != nodeproto.StorageProtocol || a.TargetNodeID != m.Config.NodeID || a.SourceNodeID != task.SourceNodeID || a.SourceOperationID != task.SourceOperationID || a.ArtifactID != task.ArtifactID || a.InstanceID != task.InstanceID || a.OwnerRef != task.OwnerRef || a.ManifestSHA256 != hash || a.FenceToken != task.FenceToken || (a.Attestation != "operator-verified-source-off-and-permanently-fenced" && !(m.Config.Storage.AllowControllerInboxApproval && a.Attestation == "controller-verified-signed-source-fence-and-preapproved-inbox")) {
			return manifest, "", errors.New("root approval binding rejected")
		}
		_, cert, e := m.nodeSigningKey()
		if e != nil {
			return manifest, "", e
		}
		raw, _ := json.Marshal(a)
		if e = verifyData(approved.CertificateDER, approved.Signature, approvalSigningDomain, raw, nodeproto.Digest(cert)); e != nil {
			return manifest, "", e
		}
	}
	return manifest, dir, nil
}

// ApproveInbox is root CLI only, while the node process is stopped/exclusively
// locked. The operator must independently inspect the permanently fenced source.
// A caller-supplied boolean over HTTP can never create this signed approval.
func (m *Manager) ApproveInbox(ctx context.Context, artifactID, reviewedFenceToken string) error {
	if os.Geteuid() != 0 || !nodeproto.ValidID(artifactID) || !hashString(reviewedFenceToken) {
		return errors.New("root approval requires artifact ID and reviewed source fence token")
	}
	return m.approveInbox(ctx, artifactID, reviewedFenceToken)
}
func (m *Manager) approveInbox(ctx context.Context, artifactID, reviewedFenceToken string) error {
	if !nodeproto.ValidID(artifactID) || !hashString(reviewedFenceToken) {
		return nodeproto.ErrInvalid
	}
	return m.approveInboxWithAttestation(ctx, artifactID, reviewedFenceToken, "operator-verified-source-off-and-permanently-fenced")
}
func (m *Manager) approveInboxWithAttestation(ctx context.Context, artifactID, reviewedFenceToken, attestation string) error {
	dir := filepath.Join(m.Config.Storage.InboxDirectory, artifactID)
	signed, hash, e := readSignedManifest(dir)
	if e != nil {
		return e
	}
	a := signed.Manifest
	task := nodeproto.TypedStorageTask{Protocol: nodeproto.StorageProtocol, NodeID: m.Config.NodeID, OperationID: "11111111111111111111111111111111", Action: "migrate_import", InstanceID: a.InstanceID, OwnerRef: a.OwnerRef, ArtifactID: artifactID, TargetNodeID: m.Config.NodeID, SourceNodeID: a.NodeID, SourceOperationID: a.ExportOperationID, ManifestSHA256: hash, FenceToken: reviewedFenceToken}
	bindDirectImportTask(&task, a)
	if !task.Valid() {
		return nodeproto.ErrInvalid
	}
	manifest, dir, e := m.readImport(task, false)
	if e != nil {
		return e
	}
	if e = m.verifyFlat(ctx, filepath.Join(dir, "disk.qcow2"), manifest); e != nil {
		return e
	}
	approval := importApproval{Protocol: nodeproto.StorageProtocol, TargetNodeID: m.Config.NodeID, SourceNodeID: a.NodeID, SourceOperationID: a.ExportOperationID, ArtifactID: a.ArtifactID, InstanceID: a.InstanceID, OwnerRef: a.OwnerRef, ManifestSHA256: hash, FenceToken: reviewedFenceToken, Attestation: attestation, ApprovedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	key, cert, e := m.nodeSigningKey()
	if e != nil {
		return e
	}
	raw, _ := json.Marshal(approval)
	sig, e := signData(key, approvalSigningDomain, raw)
	if e != nil {
		return e
	}
	body, _ := json.Marshal(signedApproval{approval, base64.StdEncoding.EncodeToString(cert), sig})
	if e = writeExclusive(filepath.Join(dir, "approval.json"), body); e != nil {
		return e
	}
	return syncDirectory(dir)
}
func syncDirectory(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}

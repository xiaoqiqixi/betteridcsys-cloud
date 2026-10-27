package hypervisor

import (
	"aster/cloud/internal/fabric"
	"aster/cloud/internal/nodeproto"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
)

const NetworkRecoveryProtocol = "aster.node-network-recovery/1"

// Root-only recovery is a distinct, reviewed intent. It never replays an old VM
// creation, destruction or payment operation. The complete bridge inventory is
// derived locally, not supplied as host commands or arbitrary OVS port numbers.
type NetworkRecoveryRequest struct {
	Protocol            string                     `json:"protocol"`
	OperationID         string                     `json:"operation_id"`
	OriginalOperationID string                     `json:"original_operation_id"`
	ProfileID           string                     `json:"profile_id"`
	Expected            fabric.RecoveryExpectation `json:"expected"`
	EnabledInstances    []string                   `json:"enabled_instances"`
}
type NetworkRecoveryResult struct {
	Protocol          string                  `json:"protocol"`
	OperationID       string                  `json:"operation_id"`
	RequestSHA256     string                  `json:"request_sha256"`
	OriginalOperation nodeproto.NodeResult    `json:"original_operation"`
	Network           fabric.LiveVerification `json:"network"`
}
type networkRecoveryEvidence struct {
	Request            NetworkRecoveryRequest `json:"request"`
	RequestSHA256      string                 `json:"request_sha256"`
	Original           Operation              `json:"original"`
	OriginalOperations []Operation            `json:"original_operations"`
	Instances          []Instance             `json:"instances"`
}
type recoveryGate interface {
	Recover(context.Context, fabric.RecoveryIntent, func(context.Context) error, func(context.Context) error) (fabric.LiveVerification, error)
}

func DecodeNetworkRecovery(raw []byte) (NetworkRecoveryRequest, error) {
	var r NetworkRecoveryRequest
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF || !r.valid() {
		return r, nodeproto.ErrInvalid
	}
	// Require the exact canonical document. This rejects duplicate/case-folded
	// keys, missing/null fields and different JSON interpretation at a boundary.
	canonical, _ := json.Marshal(r)
	if !bytes.Equal(bytes.TrimSpace(raw), canonical) {
		return r, nodeproto.ErrInvalid
	}
	return r, nil
}
func (r NetworkRecoveryRequest) valid() bool {
	if r.Protocol != NetworkRecoveryProtocol || !nodeproto.ValidID(r.OperationID) || !nodeproto.ValidID(r.OriginalOperationID) || r.OperationID == r.OriginalOperationID || !nodeproto.ValidNodeID(r.ProfileID) || !hashString(r.Expected.ExpectedJournalSHA256) || r.EnabledInstances == nil || len(r.EnabledInstances) > 128 {
		return false
	}
	seen := map[string]bool{}
	for _, id := range r.EnabledInstances {
		if !nodeproto.ValidID(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}
func (m *Manager) NetworkRecoveryStatus(profile string) (fabric.RecoveryExpectation, error) {
	p, ok := m.Config.OVSProfiles[profile]
	if !ok || p.OverlayConfig != "" {
		return fabric.RecoveryExpectation{}, ErrUnsupported
	}
	load := m.loadOVSConfig
	if load == nil {
		load = fabric.LoadConfig
	}
	c, e := load(p.FabricConfig)
	if e != nil || c.NodeID != m.Config.NodeID {
		return fabric.RecoveryExpectation{}, ErrOwnership
	}
	return fabric.RecoveryStatus(c)
}
func (m *Manager) RecoverNetwork(ctx context.Context, r NetworkRecoveryRequest) (NetworkRecoveryResult, error) {
	var out NetworkRecoveryResult
	if !r.valid() {
		return out, nodeproto.ErrInvalid
	}
	m.admission.Lock()
	defer m.admission.Unlock()
	if m.active || m.stopping {
		return out, errors.New("NODE_BUSY")
	}
	raw, _ := json.Marshal(r)
	sha := nodeproto.Digest(raw)
	intentPath := filepath.Join(m.Ledger.directory, "network-recovery-"+r.OperationID+".intent.json")
	resultPath := filepath.Join(m.Ledger.directory, "network-recovery-"+r.OperationID+".result.json")
	if b, e := readApproved(intentPath, true, 1<<20); e == nil {
		var old networkRecoveryEvidence
		if decodeRecoveryDocument(b, &old) != nil || old.RequestSHA256 != sha || !old.Request.valid() || old.Original.Task.OperationID != r.OriginalOperationID || old.OriginalOperations == nil || len(old.OriginalOperations) == 0 {
			return out, ErrConflict
		}
		intentSHA := nodeproto.Digest(b)
		b, e = readApproved(resultPath, true, 1<<20)
		if e != nil || decodeRecoveryDocument(b, &out) != nil || out.Protocol != NetworkRecoveryProtocol || out.OperationID != r.OperationID || out.RequestSHA256 != sha || out.OriginalOperation.Status != "succeeded" || !out.OriginalOperation.Matches(old.Original.Task, old.Original.Result.RequestSHA256) {
			return NetworkRecoveryResult{}, errors.New("RECOVERY_INTERRUPTED_NEW_APPROVAL_REQUIRED")
		}
		commit := NetworkRecoveryCommit{OperationID: r.OperationID, ProfileID: r.ProfileID, RequestSHA256: sha, IntentSHA256: intentSHA, ResultSHA256: nodeproto.Digest(b)}
		if !m.Ledger.NetworkRecoveryCommitted(commit) {
			return NetworkRecoveryResult{}, errors.New("RECOVERY_COMPLETION_UNCONFIRMED_NEW_APPROVAL_REQUIRED")
		}
		completed, ok := m.Ledger.Query(r.OriginalOperationID)
		if !ok || completed.Result != out.OriginalOperation || (old.Original.Result.Status != "succeeded" && completed.ErrorCode != "EXPLICIT_NETWORK_RECOVERY_"+r.OperationID || old.Original.Result.Status == "succeeded" && completed.ErrorCode != old.Original.ErrorCode) {
			return NetworkRecoveryResult{}, errors.New("RECOVERY_COMPLETION_UNCONFIRMED")
		}
		for _, prior := range old.OriginalOperations {
			done, ok := m.Ledger.Query(prior.Task.OperationID)
			if !ok || done.Result.Status != "succeeded" || prior.Result.Status != "succeeded" && done.ErrorCode != "EXPLICIT_NETWORK_RECOVERY_"+r.OperationID {
				return NetworkRecoveryResult{}, errors.New("RECOVERY_GROUP_COMPLETION_UNCONFIRMED")
			}
		}
		return out, nil // exact historical result, not a live start permit
	} else if !os.IsNotExist(e) {
		return out, e
	}
	if err := m.Ledger.networkRecoveryIDAvailable(r.OperationID); err != nil {
		return out, err
	}
	// An orphan result without its immutable approval is interrupted evidence,
	// never permission to manufacture a new intent under the same operation ID.
	if _, err := os.Lstat(resultPath); err == nil {
		return out, errors.New("RECOVERY_INTENT_MISSING_NEW_APPROVAL_REQUIRED")
	} else if !os.IsNotExist(err) {
		return out, err
	}
	op, ok := m.Ledger.Query(r.OriginalOperationID)
	if !ok || op.Task.Network.IsZero() || op.Task.Network.ProfileID != r.ProfileID || op.Result.Status != "uncertain" && op.Result.Status != "accepted" && op.Result.Status != "succeeded" {
		return out, ErrOwnership
	}
	if m.Config.OVSProfiles[r.ProfileID].OverlayConfig != "" {
		return out, errors.New("OVERLAY_REQUIRES_CLUSTER_RECOVERY")
	}
	originalInstance, exists := m.Ledger.Instance(op.Task.InstanceID)
	if !exists || originalInstance.OwnerRef != op.Task.OwnerRef || originalInstance.Resources != op.Task.Resources || originalInstance.Hostname != op.Task.Hostname || originalInstance.Network != op.Task.Network {
		return out, ErrOwnership
	}
	targetActive := false
	switch op.Task.Action {
	case "create", "start":
		targetActive = true
	case "shutdown", "force_off":
	default:
		return out, ErrUnsupported
	}
	enabled := map[string]bool{}
	for _, id := range r.EnabledInstances {
		enabled[id] = true
	}
	if enabled[op.Task.InstanceID] != targetActive {
		return out, ErrOwnership
	}
	if op.Result.Status == "succeeded" && (targetActive && originalInstance.State != "running" || !targetActive && originalInstance.State != "shut off") {
		return out, ErrOwnership
	}
	operations, instances, err := m.prepareRecoveryGroup(r.ProfileID, op, enabled)
	if err != nil {
		return out, err
	}
	intent := fabric.ActivationIntent{OperationID: r.OperationID, RequestSHA256: sha, InstanceID: op.Task.InstanceID, VPCs: []fabric.VPC{}, Ports: []fabric.PortIntent{}}
	vpcs := map[string]fabric.VPC{}
	found := map[string]bool{}
	for _, i := range instances {
		n := i.Network
		if n.IsZero() || n.ProfileID != r.ProfileID || i.State == "deleted" {
			continue
		}
		if n.ProfileSHA256 != op.Task.Network.ProfileSHA256 || i.SourceFence != nil || i.TargetBinding != nil || !n.ValidFor(nodeproto.NodeTask{NodeID: m.Config.NodeID, InstanceID: i.ID, OwnerRef: i.OwnerRef, Resources: i.Resources}) {
			return out, ErrOwnership
		}
		if _, _, e := m.approvedOVS(n); e != nil {
			return out, e
		}
		v := fabric.VPC{ID: n.VPCID, OwnerRef: n.OwnerRef, CIDR: n.CIDR, VLANID: n.VLANID}
		if old, ok := vpcs[v.ID]; ok && old != v {
			return out, ErrOwnership
		}
		vpcs[v.ID] = v
		intent.Ports = append(intent.Ports, fabric.PortIntent{InstanceID: i.ID, InterfaceID: n.InterfaceID, OwnerRef: i.OwnerRef, VPCID: n.VPCID, IPv4: n.IPv4, MAC: n.MAC, InboundMbps: n.InboundMbps, OutboundMbps: n.OutboundMbps, Enabled: enabled[i.ID]})
		found[i.ID] = true
	}
	if !found[op.Task.InstanceID] {
		return out, ErrOwnership
	}
	for id := range enabled {
		if !found[id] {
			return out, ErrOwnership
		}
	}
	for _, v := range vpcs {
		intent.VPCs = append(intent.VPCs, v)
	}
	sort.Slice(intent.VPCs, func(i, j int) bool { return intent.VPCs[i].ID < intent.VPCs[j].ID })
	sort.Slice(intent.Ports, func(i, j int) bool { return intent.Ports[i].InstanceID < intent.Ports[j].InstanceID })
	sort.Slice(instances, func(i, j int) bool { return instances[i].ID < instances[j].ID })
	gate, e := m.gateFor(op.Task.Network)
	if e != nil {
		return out, e
	}
	recoverer, ok := gate.(recoveryGate)
	if !ok {
		return out, ErrUnsupported
	}
	evidence := networkRecoveryEvidence{Request: r, RequestSHA256: sha, Original: op, OriginalOperations: operations, Instances: instances}
	b, _ := json.Marshal(evidence)
	intentSHA := nodeproto.Digest(b)
	if e = writeRecoveryEvidence(intentPath, b); e != nil {
		return out, e
	}
	proof, e := recoverer.Recover(ctx, fabric.RecoveryIntent{OperationID: r.OperationID, RequestSHA256: sha, RecoveryExpectation: r.Expected, Intent: intent}, func(ctx context.Context) error {
		if e := m.verifyRecoveryGroup(ctx, operations, instances, enabled); e != nil {
			return e
		}
		return m.fenceOVSInventory(ctx, instances, enabled)
	}, func(ctx context.Context) error { return m.releaseOVSInventory(ctx, instances, enabled) })
	if e != nil {
		for _, i := range instances {
			m.fenceOVSGuest(i)
		}
		return out, e
	}
	// Preserve the complete pre-recovery operation in its immutable evidence file.
	// Only after a new live proof may the original requested final state converge.
	result := op.Result
	result.Status = "succeeded"
	out = NetworkRecoveryResult{NetworkRecoveryProtocol, r.OperationID, sha, result, proof}
	b, _ = json.Marshal(out)
	if e = writeRecoveryEvidence(resultPath, b); e != nil {
		for _, i := range instances {
			m.fenceOVSGuest(i)
		}
		return NetworkRecoveryResult{}, e
	}
	commit := NetworkRecoveryCommit{OperationID: r.OperationID, ProfileID: r.ProfileID, RequestSHA256: sha, IntentSHA256: intentSHA, ResultSHA256: nodeproto.Digest(b)}
	if _, e = m.Ledger.FinishNetworkRecovery(r.OperationID, operations, instances, commit); e != nil {
		for _, i := range instances {
			m.fenceOVSGuest(i)
		}
		return NetworkRecoveryResult{}, e
	}
	return out, nil
}

func writeRecoveryEvidence(path string, raw []byte) error {
	if err := writeExclusive(path, raw); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func LoadNetworkRecoveryRequest(path string) (NetworkRecoveryRequest, error) {
	raw, e := readApproved(path, true, 65536)
	if e != nil {
		return NetworkRecoveryRequest{}, e
	}
	return DecodeNetworkRecovery(raw)
}

// All new recovery evidence is emitted canonically. Reject ambiguity or missing
// fields instead of accepting whatever encoding/json happened to decode last.
func decodeRecoveryDocument(raw []byte, dst any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil || d.Decode(new(any)) != io.EOF {
		return nodeproto.ErrInvalid
	}
	canonical, err := json.Marshal(dst)
	if err != nil || !bytes.Equal(bytes.TrimSpace(raw), canonical) {
		return nodeproto.ErrInvalid
	}
	return nil
}

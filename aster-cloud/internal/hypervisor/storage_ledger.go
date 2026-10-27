package hypervisor

import (
	"aster/cloud/internal/nodeproto"
	"errors"
	"time"
)

type ArtifactRecord struct {
	Artifact      nodeproto.StorageArtifact `json:"artifact"`
	ReservedBytes int64                     `json:"reserved_bytes"`
}
type RestoreRecovery struct {
	ReservedBytes      int64  `json:"reserved_bytes"`
	Removed            bool   `json:"removed"`
	PreviousDiskName   string `json:"previous_disk_name"`
	PreviousDiskSHA256 string `json:"previous_disk_sha256"`
	PreviousDiskBytes  int64  `json:"previous_disk_bytes"`
	ReplacementSHA256  string `json:"replacement_sha256"`
}
type StorageOperation struct {
	Task      nodeproto.TypedStorageTask `json:"task"`
	Result    nodeproto.StorageResult    `json:"result"`
	CreatedAt string                     `json:"created_at"`
	UpdatedAt string                     `json:"updated_at"`
	ErrorCode string                     `json:"error_code"`
	Recovery  *RestoreRecovery           `json:"recovery,omitempty"`
}

func (l *Ledger) ClaimStorage(task nodeproto.TypedStorageTask, sha string) (nodeproto.StorageResult, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.poisoned {
		return nodeproto.StorageResult{}, false, errors.New("journal unavailable")
	}
	if _, ok := l.state.Operations[task.OperationID]; ok {
		return nodeproto.StorageResult{}, false, ErrConflict
	}
	if _, ok := l.state.NetworkRecoveries[task.OperationID]; ok {
		return nodeproto.StorageResult{}, false, ErrConflict
	}
	if op, ok := l.state.StorageOperations[task.OperationID]; ok {
		if op.Result.RequestSHA256 != sha {
			return nodeproto.StorageResult{}, false, ErrConflict
		}
		return copyStorageResult(op.Result), false, nil
	}
	result := nodeproto.StorageResult{Protocol: task.Protocol, OperationID: task.OperationID, RequestSHA256: sha, InstanceID: task.InstanceID, ArtifactID: task.ArtifactID, Status: "accepted", SourceNodeID: task.SourceNodeID, TargetNodeID: task.TargetNodeID, ManifestSHA256: task.ManifestSHA256, FenceToken: task.FenceToken, Items: []nodeproto.StorageArtifact{}}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if task.Protocol == nodeproto.StorageDirectProtocol && l.state.Schema < 5 {
		l.state.Schema = 5
	}
	if l.state.Schema < 2 {
		l.state.Schema = 2
	}
	l.state.StorageOperations[task.OperationID] = StorageOperation{Task: task, Result: result, CreatedAt: now, UpdatedAt: now}
	return result, true, l.save()
}
func copyStorageResult(r nodeproto.StorageResult) nodeproto.StorageResult {
	r.Items = append([]nodeproto.StorageArtifact{}, r.Items...)
	return r
}
func (l *Ledger) QueryStorage(id string) (StorageOperation, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	op, ok := l.state.StorageOperations[id]
	op.Result = copyStorageResult(op.Result)
	if op.Recovery != nil {
		x := *op.Recovery
		op.Recovery = &x
	}
	return op, ok
}
func (l *Ledger) Artifact(id string) (ArtifactRecord, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	a, ok := l.state.Artifacts[id]
	return a, ok
}
func (l *Ledger) Artifacts() []ArtifactRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	a := make([]ArtifactRecord, 0, len(l.state.Artifacts))
	for _, x := range l.state.Artifacts {
		a = append(a, x)
	}
	return a
}
func (l *Ledger) FinishStorage(id, status, code string, result nodeproto.StorageResult, instance *Instance, artifact *ArtifactRecord, recovery *RestoreRecovery) (nodeproto.StorageResult, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	op, ok := l.state.StorageOperations[id]
	if !ok {
		return nodeproto.StorageResult{}, ErrNotFound
	}
	if !result.Matches(op.Task, op.Result.RequestSHA256) {
		return nodeproto.StorageResult{}, nodeproto.ErrInvalid
	}
	result.Status = status
	result.Items = append([]nodeproto.StorageArtifact{}, result.Items...)
	op.Result = result
	op.ErrorCode = code
	op.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if recovery != nil {
		x := *recovery
		op.Recovery = &x
	}
	l.state.StorageOperations[id] = op
	if status == "succeeded" && op.Task.Action == "migrate_retire_source" && instance != nil && instance.PublicRetired && instance.State == "retired" {
		if l.state.PublicRetirements == nil {
			l.state.PublicRetirements = map[string]PublicRetirement{}
		}
		l.state.PublicRetirements[publicRetirementKey(instance.ID, instance.DirectPublic.Generation)] = PublicRetirement{Binding: instance.DirectPublic, OperationID: id, Proof: op.Task.RetireProof, Fence: *instance.SourceFence}
	}
	if instance != nil {
		l.state.Instances[instance.ID] = cloneInstance(*instance)
	}
	if artifact != nil {
		l.state.Artifacts[artifact.Artifact.ArtifactID] = *artifact
	}
	err := l.save()
	if err != nil {
		op.Result.Status = "uncertain"
		op.ErrorCode = "JOURNAL_WRITE_UNCERTAIN"
		l.state.StorageOperations[id] = op
	}
	return copyStorageResult(op.Result), err
}

func (l *Ledger) validateStorageState() error {
	for id, a := range l.state.Artifacts {
		v := a.Artifact
		if !nodeproto.ValidID(id) || v.ArtifactID != id || !nodeproto.ValidID(v.InstanceID) || !nodeproto.ValidID(v.OwnerRef) || v.NodeID != l.state.NodeID || a.ReservedBytes < 0 || a.ReservedBytes > 1<<48 {
			return errors.New("invalid artifact journal binding")
		}
		switch v.Kind {
		case "snapshot", "backup", "migration":
		default:
			return errors.New("invalid artifact kind")
		}
		switch v.State {
		case "reserved", "available", "uncertain", "deleted", "rejected":
		default:
			return errors.New("invalid artifact state")
		}
		if v.State == "available" && (!hashString(v.ManifestSHA256) || !hashString(v.DiskSHA256) || v.DiskBytes < 1 || v.VirtualBytes < 1) {
			return errors.New("invalid available artifact identity")
		}
	}
	for id, i := range l.state.Instances {
		if f := i.SourceFence; f != nil {
			if !hashString(f.Token) || !nodeproto.ValidID(f.ArtifactID) || !nodeproto.ValidID(f.OperationID) || !nodeproto.ValidNodeID(f.TargetNodeID) || f.TargetNodeID == l.state.NodeID {
				return errors.New("invalid persisted source fence")
			}
			op, ok := l.state.StorageOperations[f.OperationID]
			if !ok || op.Task.Action != "migrate_prepare" || op.Task.InstanceID != id || op.Task.OwnerRef != i.OwnerRef || op.Task.ArtifactID != f.ArtifactID || op.Task.TargetNodeID != f.TargetNodeID || op.Result.FenceToken != f.Token {
				return errors.New("source fence operation binding rejected")
			}
		}
		if b := i.TargetBinding; b != nil {
			if !nodeproto.ValidNodeID(b.SourceNodeID) || b.SourceNodeID == l.state.NodeID || !nodeproto.ValidID(b.SourceOperationID) || !nodeproto.ValidID(b.ArtifactID) || !hashString(b.ManifestSHA256) || !hashString(b.FenceToken) {
				return errors.New("invalid target migration binding")
			}
		}
	}
	for id, t := range l.state.InboxTransfers {
		if !nodeproto.ValidID(id) || t.ArtifactID != id || !nodeproto.ValidID(t.TransferID) || !hashString(t.ManifestSHA256) || t.Manifest.ArtifactID != id || t.Manifest.TargetNodeID != l.state.NodeID || t.Manifest.Kind != "migration" || t.ReservedBytes < 1 || t.ReservedBytes > 1<<48 {
			return errors.New("invalid protected inbox journal")
		}
		for name, f := range t.Files {
			if (name != "manifest" && name != "disk") || !hashString(f.SHA256) || f.Bytes < 1 || f.Bytes > 1<<44 {
				return errors.New("invalid inbox file binding")
			}
			switch f.Status {
			case "receiving", "available", "uncertain":
			default:
				return errors.New("invalid inbox state")
			}
		}
		switch t.ApprovalState {
		case "", "approving", "approved":
		default:
			return errors.New("invalid approval state")
		}
	}
	for id, op := range l.state.StorageOperations {
		if r := op.Recovery; r != nil {
			if r.PreviousDiskName != "system.qcow2.before-"+id || !hashString(r.PreviousDiskSHA256) || !hashString(r.ReplacementSHA256) || r.PreviousDiskBytes < 1 {
				return errors.New("invalid restore recovery binding")
			}
		}
	}
	return nil
}

func (l *Ledger) HasPendingInstance(id, except string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for opID, op := range l.state.Operations {
		if opID != except && op.Task.InstanceID == id && (op.Result.Status == "accepted" || op.Result.Status == "uncertain") {
			return true
		}
	}
	for opID, op := range l.state.StorageOperations {
		if opID != except && op.Task.InstanceID == id && (op.Result.Status == "accepted" || op.Result.Status == "uncertain") {
			return true
		}
	}
	return false
}
func (l *Ledger) StorageReservedBytes() (int64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	sum := int64(0)
	add := func(n int64) error {
		if n < 0 || n > 1<<48 || sum > (1<<60)-n {
			return errors.New("storage budget journal rejected")
		}
		sum += n
		return nil
	}
	for _, a := range l.state.Artifacts {
		if a.Artifact.State != "deleted" {
			if e := add(a.ReservedBytes); e != nil {
				return 0, e
			}
		}
	}
	for _, a := range l.state.InboxTransfers {
		if e := add(a.ReservedBytes); e != nil {
			return 0, e
		}
	}
	for _, op := range l.state.StorageOperations {
		if op.Recovery != nil && !op.Recovery.Removed {
			if e := add(op.Recovery.ReservedBytes); e != nil {
				return 0, e
			}
		}
	}
	return sum, nil
}
func (l *Ledger) Recoveries(id string) []RestoreRecovery {
	l.mu.Lock()
	defer l.mu.Unlock()
	items := []RestoreRecovery{}
	for _, op := range l.state.StorageOperations {
		if op.Task.InstanceID == id && op.Recovery != nil && !op.Recovery.Removed {
			items = append(items, *op.Recovery)
		}
	}
	return items
}

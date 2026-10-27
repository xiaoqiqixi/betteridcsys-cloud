package hypervisor

import (
	"aster/billing/controllerapi"
	"aster/cloud/internal/fabric"
	"aster/cloud/internal/nodeproto"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

type SourceFence struct {
	Token        string `json:"token"`
	ArtifactID   string `json:"artifact_id"`
	TargetNodeID string `json:"target_node_id"`
	OperationID  string `json:"operation_id"`
	CreatedAt    string `json:"created_at"`
}
type TargetBinding struct {
	SourceNodeID      string `json:"source_node_id"`
	SourceOperationID string `json:"source_operation_id"`
	ArtifactID        string `json:"artifact_id"`
	ManifestSHA256    string `json:"manifest_sha256"`
	FenceToken        string `json:"fence_token"`
	Activated         bool   `json:"activated"`
}
type Instance struct {
	PublicRetired        bool                          `json:"public_retired,omitempty"`
	DirectPublic         nodeproto.DirectPublicBinding `json:"direct_public,omitzero"`
	DirectPublicDetached bool                          `json:"direct_public_detached,omitempty"`
	Network              nodeproto.NetworkBinding      `json:"network,omitzero"`
	SourceFence          *SourceFence                  `json:"source_fence,omitempty"`
	TargetBinding        *TargetBinding                `json:"target_binding,omitempty"`
	ID                   string                        `json:"id"`
	OwnerRef             string                        `json:"owner_ref"`
	Hostname             string                        `json:"hostname"`
	Domain               string                        `json:"domain"`
	Directory            string                        `json:"directory"`
	Disk                 string                        `json:"disk"`
	Seed                 string                        `json:"seed"`
	IPv4                 string                        `json:"ipv4"`
	MAC                  string                        `json:"mac"`
	State                string                        `json:"state"`
	Resources            controllerapi.Resources       `json:"resources"`
}
type Operation struct {
	Task      nodeproto.NodeTask   `json:"task"`
	Result    nodeproto.NodeResult `json:"result"`
	CreatedAt string               `json:"created_at"`
	UpdatedAt string               `json:"updated_at"`
	ErrorCode string               `json:"error_code,omitempty"`
}

const maxJournalBytes = 64 << 20

type journal struct {
	PublicRetirements map[string]PublicRetirement      `json:"public_retirements,omitempty"`
	NetworkRecoveries map[string]networkRecoveryRecord `json:"network_recoveries,omitempty"`
	InboxTransfers    map[string]InboxTransfer         `json:"inbox_transfers,omitempty"`
	StorageOperations map[string]StorageOperation      `json:"storage_operations,omitempty"`
	Artifacts         map[string]ArtifactRecord        `json:"artifacts,omitempty"`
	Schema            int                              `json:"schema"`
	NodeID            string                           `json:"node_id"`
	Operations        map[string]Operation             `json:"operations"`
	Instances         map[string]Instance              `json:"instances"`
}
type Ledger struct {
	mu        sync.Mutex
	directory string
	lock      *os.File
	state     journal
	closed    bool
	poisoned  bool
}

func OpenLedger(directory, nodeID string) (*Ledger, error) {
	if err := NoSymlinkPath(directory); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	if err := ownedPath(directory, true, true); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(directory, "node.lock")
	if err := NoSymlinkPath(lockPath); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err = ownedPath(lockPath, true, false); err != nil {
		lock.Close()
		return nil, err
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, errors.New("node already locked")
	}
	l := &Ledger{directory: directory, lock: lock, state: journal{Schema: 1, NodeID: nodeID, Operations: map[string]Operation{}, Instances: map[string]Instance{}}}
	path := filepath.Join(directory, "journal.json")
	if _, err = os.Lstat(path); err == nil {
		if err = ownedPath(path, true, false); err != nil {
			l.Close()
			return nil, err
		}
		raw, e := readApproved(path, true, maxJournalBytes)
		if e != nil {
			l.Close()
			return nil, e
		}
		if len(raw) > maxJournalBytes || json.Unmarshal(raw, &l.state) != nil || (l.state.Schema != 1 && l.state.Schema != 2 && l.state.Schema != 3 && l.state.Schema != 4 && l.state.Schema != 5) || l.state.NodeID != nodeID || l.state.Operations == nil || l.state.Instances == nil {
			l.Close()
			return nil, errors.New("invalid journal")
		}
		if l.state.Schema >= 4 {
			canonical, e := json.Marshal(l.state)
			if e != nil || !bytes.Equal(bytes.TrimSpace(raw), canonical) {
				l.Close()
				return nil, errors.New("noncanonical recovery journal")
			}
		}
	} else if !os.IsNotExist(err) {
		l.Close()
		return nil, err
	}
	if err = l.validateLoaded(); err != nil {
		l.Close()
		return nil, err
	}
	if l.state.InboxTransfers == nil {
		l.state.InboxTransfers = map[string]InboxTransfer{}
	}
	if l.state.StorageOperations == nil {
		l.state.StorageOperations = map[string]StorageOperation{}
	}
	if l.state.Artifacts == nil {
		l.state.Artifacts = map[string]ArtifactRecord{}
	}
	if len(l.state.StorageOperations) > 0 || len(l.state.Artifacts) > 0 || len(l.state.InboxTransfers) > 0 {
		if l.state.Schema < 2 {
			l.state.Schema = 2
		}
	}
	if err = l.validateStorageState(); err != nil {
		l.Close()
		return nil, err
	}
	for id, op := range l.state.StorageOperations {
		if !op.Result.Matches(op.Task, op.Result.RequestSHA256) || op.Task.NodeID != nodeID || id != op.Task.OperationID || !op.Task.DirectPublic.IsZero() && l.state.Schema < 5 {
			l.Close()
			return nil, errors.New("invalid storage journal")
		}
		if op.Result.Status == "accepted" {
			op.Result.Status = "uncertain"
			op.ErrorCode = "INTERRUPTED_AFTER_CLAIM"
			l.state.StorageOperations[id] = op
		}
	}
	// A previous accepted claim might already have affected libvirt. Never rerun it.
	for id, op := range l.state.Operations {
		if op.Result.Status == "accepted" {
			op.Result.Status = "uncertain"
			op.ErrorCode = "INTERRUPTED_AFTER_CLAIM"
			op.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
			l.state.Operations[id] = op
		}
	}
	if err = l.save(); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}
func (l *Ledger) save() error {
	if l.closed || l.poisoned {
		return errors.New("journal unavailable")
	}
	raw, err := json.Marshal(l.state)
	if err != nil {
		return err
	}
	if len(raw) > maxJournalBytes {
		l.poisoned = true
		return errors.New("journal capacity reached; operator action required")
	}
	tmp, err := os.CreateTemp(l.directory, ".journal-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(raw)
	}
	if err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(name, filepath.Join(l.directory, "journal.json"))
	}
	if err == nil {
		d, e := os.Open(l.directory)
		if e != nil {
			err = e
		} else {
			err = d.Sync()
			d.Close()
		}
	}
	if err != nil {
		l.poisoned = true
	}
	return err
}
func (l *Ledger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	syscall.Flock(int(l.lock.Fd()), syscall.LOCK_UN)
	return l.lock.Close()
}
func (l *Ledger) Claim(task nodeproto.NodeTask, sha string) (nodeproto.NodeResult, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.poisoned {
		return nodeproto.NodeResult{}, false, errors.New("journal unavailable")
	}
	if _, ok := l.state.StorageOperations[task.OperationID]; ok {
		return nodeproto.NodeResult{}, false, ErrConflict
	}
	if _, ok := l.state.NetworkRecoveries[task.OperationID]; ok {
		return nodeproto.NodeResult{}, false, ErrConflict
	}
	if op, ok := l.state.Operations[task.OperationID]; ok {
		if op.Result.RequestSHA256 != sha {
			return nodeproto.NodeResult{}, false, ErrConflict
		}
		return op.Result, false, nil
	}
	result := nodeproto.NodeResult{Protocol: task.Protocol, OperationID: task.OperationID, RequestSHA256: sha, InstanceID: task.InstanceID, Status: "accepted"}
	if task.Protocol == nodeproto.DirectPublicProtocol && l.state.Schema < 5 {
		l.state.Schema = 5
	}
	if task.Protocol == nodeproto.NetworkProtocol && l.state.Schema < 3 {
		l.state.Schema = 3
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	l.state.Operations[task.OperationID] = Operation{Task: task, Result: result, CreatedAt: now, UpdatedAt: now}
	return result, true, l.save()
}
func (l *Ledger) Reserve(instance Instance) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if old, ok := l.state.Instances[instance.ID]; ok && (!old.PublicRetired || old.State != "retired" || instance.TargetBinding == nil || instance.DirectPublic.IsZero() || instance.DirectPublic.Generation <= old.DirectPublic.Generation) {
		return ErrConflict
	}
	if !instance.Network.IsZero() {
		if !instance.Network.ValidFor(nodeproto.NodeTask{NodeID: l.state.NodeID, InstanceID: instance.ID, OwnerRef: instance.OwnerRef, Resources: instance.Resources}) {
			return ErrOwnership
		}
		if l.state.Schema < 3 {
			l.state.Schema = 3
		}
	}
	if !instance.DirectPublic.IsZero() && (!instance.DirectPublic.ValidFor(nodeproto.NodeTask{NodeID: l.state.NodeID, InstanceID: instance.ID, OwnerRef: instance.OwnerRef, Resources: instance.Resources}) || !instance.Network.IsZero() || instance.IPv4 != instance.DirectPublic.IPv4 || instance.MAC != instance.DirectPublic.MAC) {
		return ErrOwnership
	}
	if !instance.DirectPublic.IsZero() && l.state.Schema < 5 {
		l.state.Schema = 5
	}
	for _, existing := range l.state.Instances {
		if existing.State != "deleted" && !existing.DirectPublicDetached && (instance.IPv4 != "" && existing.IPv4 == instance.IPv4 || instance.MAC != "" && existing.MAC == instance.MAC || !instance.DirectPublic.IsZero() && instance.DirectPublic.LeaseID == existing.DirectPublic.LeaseID || !instance.Network.IsZero() && instance.Network.LeaseID == existing.Network.LeaseID) {
			return ErrConflict
		}
	}
	l.state.Instances[instance.ID] = cloneInstance(instance)
	return l.save()
}
func (l *Ledger) Finish(id, status, code string, instance *Instance) (nodeproto.NodeResult, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	op, ok := l.state.Operations[id]
	if !ok {
		return nodeproto.NodeResult{}, ErrNotFound
	}
	op.Result.Status = status
	op.ErrorCode = code
	op.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	l.state.Operations[id] = op
	if instance != nil {
		l.state.Instances[instance.ID] = cloneInstance(*instance)
		if instance.State == "deleted" {
			for opID, storageOp := range l.state.StorageOperations {
				if storageOp.Task.InstanceID == instance.ID && storageOp.Recovery != nil {
					x := *storageOp.Recovery
					x.Removed = true
					storageOp.Recovery = &x
					l.state.StorageOperations[opID] = storageOp
				}
			}
		}
	}
	err := l.save()
	if err != nil {
		op.Result.Status = "uncertain"
		op.ErrorCode = "JOURNAL_WRITE_UNCERTAIN"
		l.state.Operations[id] = op
	}
	return op.Result, err
}
func (l *Ledger) Query(id string) (Operation, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	op, ok := l.state.Operations[id]
	return op, ok
}
func (l *Ledger) Instances() []Instance {
	l.mu.Lock()
	defer l.mu.Unlock()
	items := make([]Instance, 0, len(l.state.Instances))
	for _, item := range l.state.Instances {
		items = append(items, cloneInstance(item))
	}
	return items
}
func (l *Ledger) Instance(id string) (Instance, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	item, ok := l.state.Instances[id]
	return cloneInstance(item), ok
}

func (l *Ledger) validateLoaded() error {
	if err := l.validateNetworkRecoveries(); err != nil {
		return err
	}
	ips := map[string]bool{}
	leases, taps := map[string]bool{}, map[string]bool{}
	for id, op := range l.state.Operations {
		if id != op.Task.OperationID || !op.Result.Matches(op.Task, op.Result.RequestSHA256) || op.Task.NodeID != l.state.NodeID {
			return errors.New("invalid journal operation identity")
		}
		if !op.Task.DirectPublic.IsZero() && l.state.Schema < 5 {
			return errors.New("direct public task needs schema 5")
		}
		if !op.Task.Network.IsZero() && l.state.Schema < 3 {
			return errors.New("OVS task needs schema 3")
		}
		if _, e := time.Parse(time.RFC3339Nano, op.CreatedAt); e != nil {
			return errors.New("invalid journal timestamp")
		}
	}
	for id, i := range l.state.Instances {
		if !nodeproto.ValidID(id) || i.ID != id || !nodeproto.ValidID(i.OwnerRef) || i.Domain != "aster-"+id || filepath.Base(i.Directory) != i.Domain || !filepath.IsAbs(i.Directory) || i.Disk != filepath.Join(i.Directory, "system.qcow2") || (i.Seed != "" && i.Seed != filepath.Join(i.Directory, "seed.iso")) {
			return errors.New("invalid journal instance identity")
		}
		if !i.DirectPublic.IsZero() {
			if l.state.Schema < 5 || !i.Network.IsZero() || !i.DirectPublic.ValidFor(nodeproto.NodeTask{NodeID: l.state.NodeID, InstanceID: i.ID, OwnerRef: i.OwnerRef, Resources: i.Resources}) || i.IPv4 != i.DirectPublic.IPv4 || i.MAC != i.DirectPublic.MAC {
				return errors.New("invalid immutable direct public binding")
			}
			if i.State != "deleted" && !i.DirectPublicDetached {
				if leases[i.DirectPublic.LeaseID] {
					return errors.New("duplicate direct public lease")
				}
				leases[i.DirectPublic.LeaseID] = true
			}
		} else if i.DirectPublicDetached {
			return errors.New("detached public binding missing")
		}
		if !i.Network.IsZero() {
			if l.state.Schema < 3 || !i.Network.ValidFor(nodeproto.NodeTask{NodeID: l.state.NodeID, InstanceID: i.ID, OwnerRef: i.OwnerRef, Resources: i.Resources}) || i.IPv4 != i.Network.IPv4 || i.MAC != i.Network.MAC {
				return errors.New("invalid immutable OVS journal binding")
			}
			if i.State != "deleted" {
				tap := fabric.TAPName(i.ID)
				if leases[i.Network.LeaseID] || taps[tap] {
					return errors.New("duplicate OVS lease or TAP identity")
				}
				leases[i.Network.LeaseID], taps[tap] = true, true
			}
		} else if i.Resources.NetworkType == "vpc" {
			return errors.New("VPC binding missing")
		}
		switch i.State {
		case "reserved", "uncertain", "running", "shut off", "deleted", "imported", "retired":
		default:
			return errors.New("invalid journal instance state")
		}
		if i.State != "deleted" && !i.DirectPublicDetached && i.IPv4 != "" {
			if ips[i.IPv4] {
				return errors.New("duplicate journal IP reservation")
			}
			ips[i.IPv4] = true
		}
	}
	return l.validatePublicRetirements()
}

func cloneInstance(i Instance) Instance {
	if i.SourceFence != nil {
		f := *i.SourceFence
		i.SourceFence = &f
	}
	if i.TargetBinding != nil {
		b := *i.TargetBinding
		i.TargetBinding = &b
	}
	return i
}

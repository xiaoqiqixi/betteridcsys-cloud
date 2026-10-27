package hypervisor

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type PublicRetirement struct {
	Binding     nodeproto.DirectPublicBinding `json:"binding"`
	OperationID string                        `json:"operation_id"`
	Proof       nodeproto.PublicRetireProof   `json:"proof"`
	Fence       SourceFence                   `json:"fence"`
}

func publicRetirementKey(id string, generation int64) string {
	return fmt.Sprintf("%s:%d", id, generation)
}
func (l *Ledger) validatePublicRetirements() error {
	for key, r := range l.state.PublicRetirements {
		if l.state.Schema < 5 || !r.Binding.ValidIdentity() || key != publicRetirementKey(r.Binding.InstanceID, r.Binding.Generation) {
			return errors.New("invalid public retirement identity")
		}
		op, ok := l.state.StorageOperations[r.OperationID]
		if !ok || op.Task.Action != "migrate_retire_source" || op.Result.Status != "succeeded" || op.Task.DirectPublic != r.Binding || op.Task.RetireProof != r.Proof || op.Task.FenceToken != r.Fence.Token || op.Task.SourceOperationID != r.Fence.OperationID || op.Task.TargetNodeID != r.Fence.TargetNodeID {
			return errors.New("public retirement receipt binding rejected")
		}
	}
	for _, i := range l.state.Instances {
		if i.PublicRetired {
			if i.State != "retired" || !i.DirectPublicDetached || i.SourceFence == nil {
				return errors.New("invalid retired source state")
			}
			r, ok := l.state.PublicRetirements[publicRetirementKey(i.ID, i.DirectPublic.Generation)]
			if !ok || r.Binding != i.DirectPublic || r.Fence != *i.SourceFence {
				return errors.New("retired source tombstone missing")
			}
		}
	}
	return nil
}
func (m *Manager) validateRetireSource(t nodeproto.TypedStorageTask, i Instance) error {
	if !m.Config.AllowDelete || !t.Valid() || t.Action != "migrate_retire_source" || i.PublicRetired || i.OwnerRef != t.OwnerRef || i.DirectPublic != t.DirectPublic || !i.Network.IsZero() || i.SourceFence == nil || i.DirectPublicDetached || i.State != "shut off" && i.State != "uncertain" {
		return ErrOwnership
	}
	f := i.SourceFence
	if f.ArtifactID != t.ArtifactID || f.OperationID != t.SourceOperationID || f.TargetNodeID != t.TargetNodeID || f.Token != t.FenceToken {
		return ErrOwnership
	}
	export, ok := m.Ledger.QueryStorage(f.OperationID)
	if !ok || export.Result.Status != "succeeded" || export.Task.Action != "migrate_prepare" || export.Task.DirectPublic != i.DirectPublic || export.Result.ManifestSHA256 != t.ManifestSHA256 || export.Result.FenceToken != t.FenceToken {
		return ErrOwnership
	}
	return nil
}

// Retirement is a separate, explicitly confirmed destructive operation. The
// caller's pinned controller has queried and frozen the actual target activate
// result; this node additionally binds it to its own permanent source fence.
func (m *Manager) retirePublicSource(ctx context.Context, t nodeproto.TypedStorageTask, i *Instance) (changed bool, err error) {
	if e := m.validateRetireSource(t, *i); e != nil {
		return changed, e
	}
	if e := m.assertOwned(ctx, *i); e != nil {
		return changed, e
	}
	state, e := m.state(ctx, i.Domain)
	if e != nil || state != "shut off" {
		return changed, errors.New("retire source must remain off")
	}
	extra, e := m.deletePreflight(ctx, *i)
	if e != nil {
		return changed, e
	}
	changed = true
	if _, e = m.virsh(ctx, "undefine", i.Domain); e != nil {
		return changed, e
	}
	names, e := m.virsh(ctx, "list", "--all", "--name")
	if e != nil {
		return changed, e
	}
	for _, name := range strings.Fields(string(names)) {
		if name == i.Domain {
			return changed, errors.New("source undefine unconfirmed")
		}
	}
	paths := []string{i.Disk, i.Seed, filepath.Join(i.Directory, "user-data"), filepath.Join(i.Directory, "meta-data"), filepath.Join(i.Directory, "network-config"), filepath.Join(i.Directory, "domain.xml")}
	paths = append(paths, extra...)
	for _, p := range paths {
		if p == "" {
			continue
		}
		if _, e = os.Lstat(p); os.IsNotExist(e) {
			continue
		}
		if e = ownedPath(p, false, false); e != nil {
			return changed, e
		}
		if e = os.Remove(p); e != nil {
			return changed, e
		}
	}
	if e = os.Remove(i.Directory); e != nil {
		return changed, e
	}
	if e = syncDirectory(m.Config.StorageDirectory); e != nil {
		return changed, e
	}
	i.State = "retired"
	i.PublicRetired = true
	i.DirectPublicDetached = true
	return changed, nil
}

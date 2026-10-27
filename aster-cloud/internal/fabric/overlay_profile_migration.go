package fabric

import (
	"aster/cloud/internal/overlayproto"
	"encoding/json"
	"os"
	"path/filepath"
)

type overlayProfileMigration struct {
	NodeID                string            `json:"node_id"`
	PreviousProfileSHA256 string            `json:"previous_profile_sha256"`
	ProfileSHA256         string            `json:"profile_sha256"`
	OperationID           string            `json:"operation_id"`
	RequestSHA256         string            `json:"request_sha256"`
	PreviousHead          overlayproto.Head `json:"previous_head"`
}

func (l *ledger) authorizeOverlayPin(c OverlayConfig, t overlayproto.Task, h overlayState, sha string) error {
	if !l.overlayOwned() || l.state.OverlayProfileSHA256 == sha {
		return nil
	}
	if t.Phase != "prepare" || t.Recovery == nil || c.PreviousProfileSHA256 != l.state.OverlayProfileSHA256 || c.PreviousProfileSHA256 == sha || h.Snapshot.ClusterID == "" {
		return ErrConflict
	}
	head := overlayproto.Head{NodeID: c.Base.NodeID, ClusterID: h.Snapshot.ClusterID, Epoch: h.Snapshot.Epoch, SnapshotSHA256: h.Digest}
	found := false
	for _, expected := range t.Recovery.Heads {
		if expected == head {
			found = true
		}
	}
	// An intermediate failed upgrade may already hold the new snapshot with the
	// old journal pin; only the old-to-new explicit recovery authorization applies.
	if !found {
		return ErrConflict
	}
	return nil
}
func (l *ledger) migrateOverlayPin(c OverlayConfig, t overlayproto.Task, h overlayState, sha, requestSHA string) error {
	if err := l.authorizeOverlayPin(c, t, h, sha); err != nil {
		return err
	}
	if !l.overlayOwned() || l.state.OverlayProfileSHA256 == sha {
		return l.pinOverlay(sha)
	}
	evidence := overlayProfileMigration{NodeID: c.Base.NodeID, PreviousProfileSHA256: l.state.OverlayProfileSHA256, ProfileSHA256: sha, OperationID: t.OperationID, RequestSHA256: requestSHA, PreviousHead: overlayproto.Head{NodeID: c.Base.NodeID, ClusterID: h.Snapshot.ClusterID, Epoch: h.Snapshot.Epoch, SnapshotSHA256: h.Digest}}
	raw, _ := json.Marshal(evidence)
	name := "overlay-profile-migration-" + t.OperationID + ".json"
	path := filepath.Join(l.cfg.StateDirectory, name)
	if _, err := os.Lstat(path); err == nil {
		previous, err := readPrivate(path, uint32(os.Geteuid()), 4096)
		if err != nil || string(previous) != string(raw) {
			return ErrConflict
		}
	} else if !os.IsNotExist(err) {
		return ErrUnavailable
	} else if l.atomic(name, raw) != nil {
		return ErrUncertain
	}
	old := l.state.OverlayProfileSHA256
	l.state.OverlayProfileSHA256 = sha
	if err := l.save(); err != nil {
		l.state.OverlayProfileSHA256 = old
		return err
	}
	return nil
}

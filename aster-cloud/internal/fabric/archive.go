package fabric

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
)

// Journal pages stay bounded. Completed history is never pruned: immutable,
// content-addressed pages form a hash chain rooted in the atomic live journal.
// A crash before the live head switches leaves a harmless, reusable orphan;
// a crash after it switches cannot make a forgotten operation executable again.
const journalPageSize = 32

func journalBytes(j journal) ([]byte, string) {
	raw, _ := json.Marshal(j)
	sum := sha256.Sum256(raw)
	return raw, hex.EncodeToString(sum[:])
}
func validSHA(s string) bool {
	raw, err := hex.DecodeString(s)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == s
}
func (l *ledger) archive(j journal) (string, error) {
	raw, sha := journalBytes(j)
	name := "history-" + sha + ".json"
	path := filepath.Join(l.cfg.StateDirectory, name)
	if _, err := os.Lstat(path); err == nil {
		old, err := readPrivate(path, uint32(os.Geteuid()), 8<<20)
		if err != nil || !bytes.Equal(raw, old) {
			return "", ErrUnavailable
		}
		return sha, nil
	} else if !os.IsNotExist(err) {
		return "", ErrUnavailable
	}
	if err := l.atomic(name, raw); err != nil {
		return "", err
	}
	return sha, nil
}
func (l *ledger) loadArchives() error {
	next := l.state
	seen := map[string]bool{}
	for next.ArchiveHead != "" {
		head := next.ArchiveHead
		if !validSHA(head) || seen[head] {
			return ErrUnavailable
		}
		seen[head] = true
		raw, err := readPrivate(filepath.Join(l.cfg.StateDirectory, "history-"+head+".json"), uint32(os.Geteuid()), 8<<20)
		var j journal
		if err != nil || decodeJournal(raw, &j) != nil || j.NodeID != l.cfg.NodeID || j.Bridge != l.cfg.Bridge || l.validateState(j) != nil {
			return ErrUnavailable
		}
		canonical, sha := journalBytes(j)
		if sha != head || !bytes.Equal(canonical, raw) {
			return ErrUnavailable
		}
		// Unknown old outcomes are preserved, not called successful. Only an
		// explicit recovery referencing that exact journal may fence them off.
		if !settled(j) && (next.Recovery == nil || next.Recovery.Intent.ExpectedJournalSHA256 != head) {
			return ErrUnavailable
		}
		if next.Recovery != nil {
			prior := l.state
			l.state = j
			expect := l.recoveryExpectation()
			l.state = prior
			if next.Recovery.Intent.RecoveryExpectation != expect {
				return ErrUnavailable
			}
		}
		l.history = append(l.history, j)
		next = j
	}
	// No checkpoint may change a receipt or resurrect/reuse an operation ID.
	revisions := map[int64]string{}
	operations := map[string]bool{}
	highest := int64(0)
	pinned := ""
	all := append([]journal{l.state}, l.history...)
	for n := len(all) - 1; n >= 0; n-- {
		j := all[n]
		if pinned != "" && j.OverlayProfileSHA256 != pinned {
			return ErrUnavailable
		}
		if j.OverlayProfileSHA256 != "" {
			pinned = j.OverlayProfileSHA256
		}
		for _, r := range j.Records {
			raw, _ := json.Marshal(r)
			sum := sha256.Sum256(raw)
			sha := hex.EncodeToString(sum[:])
			old, exists := revisions[r.Receipt.Revision]
			if exists {
				if old != sha {
					return ErrUnavailable
				}
				continue
			}
			if r.Receipt.Revision <= highest {
				return ErrUnavailable
			}
			highest = r.Receipt.Revision
			revisions[highest] = sha
		}
		for _, a := range j.Activations {
			if operations[a.Intent.OperationID] {
				return ErrUnavailable
			}
			operations[a.Intent.OperationID] = true
		}
		if j.Recovery != nil {
			id := j.Recovery.Intent.OperationID
			if operations[id] {
				return ErrUnavailable
			}
			operations[id] = true
		}
	}
	if len(l.state.Records) > 0 {
		if l.state.Records[len(l.state.Records)-1].Receipt.Revision != highest {
			return ErrUnavailable
		}
	} else if highest > 0 && (l.state.Recovery == nil || l.state.Recovery.State == "completed") {
		return ErrUnavailable
	}
	return nil
}
func settled(j journal) bool {
	if j.Recovery != nil && j.Recovery.State != "completed" {
		return false
	}
	for _, a := range j.Activations {
		if a.State != "completed" {
			return false
		}
	}
	for _, r := range j.Records {
		if r.Receipt.State != "applied" {
			return false
		}
	}
	return true
}
func (l *ledger) compact() error {
	if len(l.state.Records) < journalPageSize && len(l.state.Activations) < journalPageSize {
		return nil
	}
	if !settled(l.state) {
		return ErrUncertain
	}
	old := l.state
	head, err := l.archive(old)
	if err != nil {
		return err
	}
	keep := []record{}
	if len(old.Records) > 0 {
		keep = append(keep, old.Records[len(old.Records)-1])
	}
	l.state = journal{NATProfileIDs: old.NATProfileIDs, OverlayProfileSHA256: old.OverlayProfileSHA256, Schema: 3, NodeID: l.cfg.NodeID, Bridge: l.cfg.Bridge, ArchiveHead: head, Records: keep, Activations: []activationRecord{}}
	if err = l.save(); err != nil {
		l.state = old
		return err
	}
	l.history = append([]journal{old}, l.history...)
	return nil
}
func (l *ledger) operationSeen(id string) bool {
	for _, j := range append([]journal{l.state}, l.history...) {
		if j.Recovery != nil && j.Recovery.Intent.OperationID == id {
			return true
		}
		for _, a := range j.Activations {
			if a.Intent.OperationID == id {
				return true
			}
		}
	}
	return false
}
func (l *ledger) allRecords() []record {
	out := append([]record{}, l.state.Records...)
	for _, j := range l.history {
		out = append(out, j.Records...)
	}
	return out
}
func (l *ledger) lastRevision() int64 {
	highest := int64(0)
	for _, r := range l.allRecords() {
		if r.Receipt.Revision > highest {
			highest = r.Receipt.Revision
		}
	}
	return highest
}

func (j journal) MarshalJSON() ([]byte, error) {
	type wire struct {
		NATProfileIDs        []string            `json:"nat_profile_ids,omitempty"`
		OverlayProfileSHA256 string              `json:"overlay_profile_sha256,omitempty"`
		ArchiveHead          string              `json:"archive_head,omitempty"`
		Recovery             *recoveryRecord     `json:"recovery,omitempty"`
		Activations          *[]activationRecord `json:"activations,omitempty"`
		Schema               int                 `json:"schema"`
		NodeID               string              `json:"node_id"`
		Bridge               string              `json:"bridge"`
		Records              []record            `json:"records"`
	}
	w := wire{NATProfileIDs: j.NATProfileIDs, OverlayProfileSHA256: j.OverlayProfileSHA256, ArchiveHead: j.ArchiveHead, Recovery: j.Recovery, Schema: j.Schema, NodeID: j.NodeID, Bridge: j.Bridge, Records: j.Records}
	if j.Schema >= 2 {
		a := j.Activations
		if a == nil {
			a = []activationRecord{}
		}
		w.Activations = &a
	}
	return json.Marshal(w)
}

// The current approval digest is also a permanent overlay-mode tombstone.
// Only explicit root-approved recovery can migrate the digest; no legacy
// single-host entrypoint can downgrade the mode or erase NAT ownership IDs.
func (l *ledger) overlayOwned() bool { return l.state.OverlayProfileSHA256 != "" }
func (l *ledger) legacyGuard() error {
	if l.overlayOwned() {
		return ErrConflict
	}
	return legacyOverlayGuard(l.cfg)
}
func (l *ledger) pinOverlay(sha string) error {
	if !validSHA(sha) {
		return ErrInvalid
	}
	if l.overlayOwned() {
		if l.state.OverlayProfileSHA256 != sha {
			return ErrConflict
		}
		return nil
	}
	if !settled(l.state) {
		return ErrUncertain
	}
	old := l.state
	head, err := l.archive(old)
	if err != nil {
		return err
	}
	records := []record{}
	if len(old.Records) > 0 {
		records = append(records, old.Records[len(old.Records)-1])
	}
	l.state = journal{Schema: 3, NodeID: l.cfg.NodeID, Bridge: l.cfg.Bridge, ArchiveHead: head, OverlayProfileSHA256: sha, Records: records, Activations: []activationRecord{}}
	if err = l.save(); err != nil {
		l.state = old
		return err
	}
	l.history = append([]journal{old}, l.history...)
	return nil
}

package fabric

import (
	"aster/cloud/internal/overlayproto"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type natOwnership struct {
	ProfileSHA256 string     `json:"profile_sha256"`
	NodeID        string     `json:"node_id"`
	Profile       NATProfile `json:"profile"`
}

func natOwnerName(p NATProfile) string { return "nat-owner-" + p.ID + ".json" }
func readNATOwner(l *ledger, p NATProfile) (natOwnership, error) {
	raw, err := readPrivate(filepath.Join(l.cfg.StateDirectory, natOwnerName(p)), uint32(os.Geteuid()), 65536)
	if err != nil {
		return natOwnership{}, err
	}
	var old natOwnership
	if object(raw, []string{"profile_sha256", "node_id", "profile"}, &old) != nil {
		return old, ErrUnavailable
	}
	sha, err := NATProfileSHA256(old.Profile)
	if err != nil || old.NodeID != l.cfg.NodeID || old.Profile.ID != p.ID || sha != old.ProfileSHA256 {
		return old, ErrUnavailable
	}
	return old, nil
}
func (l *ledger) checkNATInventory(c OverlayConfig) error {
	approved := map[string]bool{}
	for _, p := range c.NATProfiles {
		approved[p.ID] = true
	}
	for _, id := range l.state.NATProfileIDs {
		if !approved[id] {
			return ErrConflict
		}
		if _, err := readNATOwner(l, NATProfile{ID: id}); err != nil {
			return ErrUnavailable
		}
	}
	// A crash after the owner write but before the journal write may leave a
	// valid extra owner. Never silently forget it when the root profile vanishes.
	entries, err := os.ReadDir(l.cfg.StateDirectory)
	if err != nil {
		return ErrUnavailable
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "nat-owner-") {
			id := strings.TrimSuffix(strings.TrimPrefix(entry.Name(), "nat-owner-"), ".json")
			if !approved[id] || entry.Name() != "nat-owner-"+id+".json" {
				return ErrConflict
			}
			if _, err := readNATOwner(l, NATProfile{ID: id}); err != nil {
				return ErrUnavailable
			}
		}
	}
	return nil
}
func (l *ledger) pinNATOwner(p NATProfile) error {
	if l.state.Schema != 3 || !l.overlayOwned() {
		return ErrInvalid
	}
	for _, id := range l.state.NATProfileIDs {
		if id == p.ID {
			return nil
		}
	}
	old := l.state.NATProfileIDs
	l.state.NATProfileIDs = append(append([]string{}, old...), p.ID)
	sort.Strings(l.state.NATProfileIDs)
	if err := l.save(); err != nil {
		l.state.NATProfileIDs = old
		return err
	}
	return nil
}
func (e *Executor) natOwner(l *ledger, p NATProfile, create bool) error {
	sha, err := NATProfileSHA256(p)
	if err != nil {
		return err
	}
	path := filepath.Join(l.cfg.StateDirectory, natOwnerName(p))
	if _, err := os.Lstat(path); os.IsNotExist(err) && create {
		for _, id := range l.state.NATProfileIDs {
			if id == p.ID {
				return ErrUnavailable
			}
		}
		raw, _ := json.Marshal(natOwnership{sha, e.Config.NodeID, p})
		if l.atomic(natOwnerName(p), raw) != nil {
			return ErrUncertain
		}
		return l.pinNATOwner(p)
	}
	old, err := readNATOwner(l, p)
	if err != nil || old.ProfileSHA256 != sha {
		return ErrUnavailable
	}
	return nil
}
func (e *Executor) migrateNATOwner(ctx context.Context, c OverlayConfig, l *ledger, p NATProfile, t overlayproto.Task, exists bool) error {
	old, err := readNATOwner(l, p)
	if err != nil {
		return err
	}
	sha, err := NATProfileSHA256(p)
	if err != nil {
		return err
	}
	if old.ProfileSHA256 == sha {
		return l.pinNATOwner(p)
	}
	if t.Phase != "prepare" || t.Recovery == nil || !overlayproto.ValidSHA(c.PreviousProfileSHA256) || p.PreviousProfileSHA256 != old.ProfileSHA256 || old.Profile.ID != p.ID || old.Profile.Namespace != p.Namespace || old.Profile.VPCID != p.VPCID || old.Profile.VPCCIDR != p.VPCCIDR || old.Profile.GatewayInstanceID != p.GatewayInstanceID || old.Profile.InsideInterface != p.InsideInterface || old.Profile.OutsideInterface != p.OutsideInterface || old.Profile.OutsidePeer != p.OutsidePeer {
		return ErrConflict
	}
	changedNamespace := old.Profile.NamespaceDevice != p.NamespaceDevice || old.Profile.NamespaceInode != p.NamespaceInode
	// New namespace identity is independently proved before this function. A
	// replacement namespace cannot bring an unowned pre-existing nft table.
	if changedNamespace && exists {
		return ErrConflict
	}
	if !changedNamespace {
		if e.natForwarding(ctx, old.Profile, false, true) != nil {
			return ErrUncertain
		}
		if _, err = e.natRun(ctx, old.Profile, NATConntrack, "-F"); err != nil {
			return err
		}
	} else if !p.RetiredPreviousNamespaceAck {
		return ErrConflict
	}
	// Lost namespace identity is not proof of isolation. This narrowly scoped root
	// acknowledgement is an explicit operator assertion, never an HTTP option.
	if e.natForwarding(ctx, p, false, true) != nil {
		return ErrUncertain
	}
	_, requestSHA, err := t.BytesAndDigest()
	if err != nil {
		return err
	}
	evidence := struct {
		Old                   natOwnership `json:"old"`
		New                   natOwnership `json:"new"`
		OperationID           string       `json:"operation_id"`
		RequestSHA256         string       `json:"request_sha256"`
		PreviousOverlaySHA256 string       `json:"previous_overlay_sha256"`
	}{old, natOwnership{sha, e.Config.NodeID, p}, t.OperationID, requestSHA, c.PreviousProfileSHA256}
	raw, _ := json.Marshal(evidence)
	name := "nat-profile-migration-" + p.ID + "-" + t.OperationID + ".json"
	path := filepath.Join(l.cfg.StateDirectory, name)
	if _, err := os.Lstat(path); err == nil {
		existing, err := readPrivate(path, uint32(os.Geteuid()), 1<<20)
		if err != nil || string(existing) != string(raw) {
			return ErrConflict
		}
	} else if !os.IsNotExist(err) {
		return ErrUnavailable
	} else if l.atomic(name, raw) != nil {
		return ErrUncertain
	}
	raw, _ = json.Marshal(natOwnership{sha, e.Config.NodeID, p})
	if l.atomic(natOwnerName(p), raw) != nil {
		return ErrUncertain
	}
	return l.pinNATOwner(p)
}

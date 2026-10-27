package control

import (
	"aster/cloud/internal/nodeproto"
	"aster/cloud/internal/overlayproto"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"
)

type OverlayRecoveryInput struct {
	ExpectedSnapshotSHA256 string                   `json:"expected_snapshot_sha256"`
	Replacement            *OverlayReplacementInput `json:"replacement,omitempty"`
}

// Replacement is a full new desired membership/routes selection, not a patch.
// The expected original digest, cluster, root pins and observed heads stay fixed.
type OverlayReplacementInput struct {
	Members     []OverlayMemberInput       `json:"members"`
	Gateways    []overlayproto.Gateway     `json:"gateways"`
	NATPolicies *[]overlayproto.NATPolicy  `json:"nat_policies,omitempty"`
	FloatingIPs *[]overlayproto.FloatingIP `json:"floating_ips,omitempty"`
}

func (in *OverlayRecoveryInput) UnmarshalJSON(raw []byte) error {
	type wire OverlayRecoveryInput
	var value wire
	if !strict(raw, &value) {
		return ErrInput
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return ErrInput
	}
	if raw, ok := fields["replacement"]; ok && bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return ErrInput
	}
	*in = OverlayRecoveryInput(value)
	return nil
}
func canonicalOverlayRecoveryInput(in OverlayRecoveryInput) (OverlayRecoveryInput, error) {
	if !overlayproto.ValidSHA(in.ExpectedSnapshotSHA256) {
		return in, ErrInput
	}
	if in.Replacement != nil {
		if in.Replacement.FloatingIPs != nil {
			return in, ErrInput
		}
		selection, _, err := canonicalOverlayInput(OverlayEpochInput{ClusterID: "recovery", Members: in.Replacement.Members, Gateways: in.Replacement.Gateways, NATPolicies: in.Replacement.NATPolicies, FloatingIPs: in.Replacement.FloatingIPs})
		if err != nil {
			return in, err
		}
		in.Replacement = &OverlayReplacementInput{Members: selection.Members, Gateways: selection.Gateways, NATPolicies: selection.NATPolicies, FloatingIPs: selection.FloatingIPs}
	}
	return in, nil
}

type overlayHeadReader interface {
	OverlayHead(context.Context, string) (overlayproto.Head, error)
}

func (c *NodeClient) OverlayHead(ctx context.Context, profile string) (overlayproto.Head, error) {
	if !nodeproto.ValidNodeID(profile) {
		return overlayproto.Head{}, ErrInput
	}
	raw, e := c.call(ctx, http.MethodGet, "/v1/overlay/head?profile_id="+url.QueryEscape(profile), nil, "")
	if e != nil {
		return overlayproto.Head{}, e
	}
	h, e := overlayproto.DecodeHead(raw)
	if e != nil || h.NodeID != c.profile.ID {
		return overlayproto.Head{}, ErrUnavailable
	}
	return h, nil
}
func overlayRecoveryDigest(original string, in OverlayRecoveryInput) string {
	b, _ := json.Marshal(struct {
		Original string               `json:"original"`
		Input    OverlayRecoveryInput `json:"input"`
	}{original, in})
	return overlayproto.Digest(b)
}

// Recover creates a new immutable all-node fencing epoch. It never changes an
// original receipt or turns unknown into success; old epochs remain inspectable.
// A previously successful epoch is recoverable after later OVS/lifecycle drift.
func (w OverlayWorker) Recover(ctx context.Context, actor, original, newID string, in OverlayRecoveryInput) (OverlayEpoch, bool, error) {
	if !nodeproto.ValidID(actor) || !nodeproto.ValidID(original) || !nodeproto.ValidID(newID) || original == newID || !overlayproto.ValidSHA(in.ExpectedSnapshotSHA256) {
		return OverlayEpoch{}, false, ErrInput
	}
	var e error
	in, e = canonicalOverlayRecoveryInput(in)
	if e != nil {
		return OverlayEpoch{}, false, e
	}
	digest := overlayRecoveryDigest(original, in)
	prior, e := w.Store.OverlayEpoch(ctx, newID)
	if e == nil {
		if prior.ActorID != actor || prior.RequestSHA256 != digest || prior.Recovery == nil {
			return OverlayEpoch{}, false, ErrConflict
		}
		return prior, true, nil
	}
	if !errors.Is(e, ErrNotFound) {
		return OverlayEpoch{}, false, e
	}
	old, e := w.Store.OverlayEpoch(ctx, original)
	if e != nil {
		return old, false, e
	}
	if old.SnapshotSHA256 != in.ExpectedSnapshotSHA256 || old.State == "superseded" || old.Epoch == math.MaxInt64 || !w.Config.validOverlayClusters() || !overlayRecoveryPinsApproved(w.Config, old) {
		return old, false, ErrState
	}
	heads, e := w.readOverlayRecoveryHeads(ctx, old)
	if e != nil {
		return old, false, e
	}
	return w.Store.planOverlayRecovery(ctx, w.Config, actor, original, newID, digest, in, heads, w.now())
}

// All recovery entry points use the same bounded, pinned, read-only node probes.
func (w OverlayWorker) readOverlayRecoveryHeads(ctx context.Context, old OverlayEpoch) ([]overlayproto.Head, error) {
	heads := make([]overlayproto.Head, len(old.Snapshot.Profiles))
	var wg sync.WaitGroup
	var mu sync.Mutex
	var headErr error
	// Bounded by the root-approved maximum of 32 participants; parallel read-only
	// probes avoid multiplying the browser deadline by every unreachable node.
	for i, pin := range old.Snapshot.Profiles {
		wg.Add(1)
		go func(i int, pin overlayproto.ProfilePin) {
			defer wg.Done()
			p, ok := w.Config.Node(pin.NodeID)
			var head overlayproto.Head
			var err error
			if !ok {
				err = ErrState
			} else {
				var rpc OverlayRPC
				rpc, err = w.rpc(ctx, p)
				if err == nil {
					reader, ok := rpc.(overlayHeadReader)
					if !ok {
						err = ErrUnavailable
					} else {
						head, err = reader.OverlayHead(ctx, pin.ProfileID)
					}
				}
			}
			if err == nil && (!head.Valid() || head.NodeID != pin.NodeID || head.Epoch > old.Epoch || head.Epoch > 0 && head.ClusterID != old.ClusterID) {
				err = ErrUnavailable
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				headErr = ErrUnavailable
			} else {
				heads[i] = head
			}
		}(i, pin)
	}
	wg.Wait()
	if headErr != nil {
		return nil, headErr
	}
	sort.Slice(heads, func(i, j int) bool { return heads[i].NodeID < heads[j].NodeID })
	return heads, nil
}

func (s *SQLStore) planOverlayRecovery(ctx context.Context, c Config, actor, original, newID, digest string, in OverlayRecoveryInput, heads []overlayproto.Head, now time.Time) (OverlayEpoch, bool, error) {
	var e error
	in, e = canonicalOverlayRecoveryInput(in)
	if e != nil {
		return OverlayEpoch{}, false, e
	}
	tx, e := s.locked(ctx)
	if e != nil {
		return OverlayEpoch{}, false, e
	}
	defer tx.Rollback()
	epoch, replay, e := planOverlayRecoveryTx(ctx, tx, c, actor, original, newID, digest, in, heads, now)
	if e != nil {
		return epoch, replay, e
	}
	return epoch, replay, tx.Commit()
}

// The caller owns controller_lock and the final commit. Private resource
// recovery uses this helper to freeze its edit version and epoch atomically.
func planOverlayRecoveryTx(ctx context.Context, tx *sql.Tx, c Config, actor, original, newID, digest string, in OverlayRecoveryInput, heads []overlayproto.Head, now time.Time) (OverlayEpoch, bool, error) {
	if e := publicIngressOperationIDUnusedTx(ctx, tx, newID); e != nil {
		return OverlayEpoch{}, false, e
	}
	existing, e := scanOverlayEpoch(tx.QueryRowContext(ctx, "SELECT "+overlayEpochColumns+" FROM controller_overlay_epochs WHERE id=?", newID))
	if e == nil {
		if existing.ActorID != actor || existing.RequestSHA256 != digest || existing.Recovery == nil {
			return existing, false, ErrConflict
		}
		return existing, true, nil
	}
	if !errors.Is(e, ErrNotFound) {
		return existing, false, e
	}
	old, e := scanOverlayEpoch(tx.QueryRowContext(ctx, "SELECT "+overlayEpochColumns+" FROM controller_overlay_epochs WHERE id=?", original))
	if e != nil {
		return old, false, e
	}
	latest, e := scanOverlayEpoch(tx.QueryRowContext(ctx, "SELECT "+overlayEpochColumns+" FROM controller_overlay_epochs WHERE cluster_id=? ORDER BY epoch DESC LIMIT 1", old.ClusterID))
	if e != nil || latest.ID != old.ID || old.SnapshotSHA256 != in.ExpectedSnapshotSHA256 || old.State == "superseded" || old.Epoch == math.MaxInt64 || !c.validOverlayClusters() || !overlayRecoveryPinsApproved(c, old) {
		return old, false, ErrState
	}
	if in.Replacement == nil {
		cluster, _ := c.OverlayCluster(old.ClusterID)
		retained := old.Snapshot
		retained.FloatingIPs = recoveryFloatingPins(cluster, retained.FloatingIPs)
		if !overlayPoliciesApproved(cluster, retained) {
			return old, false, ErrState
		}
		if e = validateOverlayBindings(ctx, tx, old); e != nil {
			return old, false, e
		}
	}
	if len(heads) != len(old.Snapshot.Profiles) {
		return old, false, ErrState
	}
	expectedHeads := map[string]bool{}
	for _, p := range old.Snapshot.Profiles {
		expectedHeads[p.NodeID] = true
	}
	for _, h := range heads {
		if !expectedHeads[h.NodeID] {
			return old, false, ErrState
		}
		delete(expectedHeads, h.NodeID)
	}
	// Freeze observed heads only if their receipts belong to historical snapshots
	// in this cluster. A fabricated/ahead/foreign hash cannot authorize adoption.
	for _, h := range heads {
		if !h.Valid() || h.Epoch > old.Epoch || h.Epoch > 0 && h.ClusterID != old.ClusterID {
			return old, false, ErrState
		}
		if h.Epoch > 0 {
			var sha string
			if e = tx.QueryRowContext(ctx, "SELECT snapshot_sha256 FROM controller_overlay_epochs WHERE cluster_id=? AND epoch=?", old.ClusterID, h.Epoch).Scan(&sha); e != nil || sha != h.SnapshotSHA256 {
				return old, false, ErrState
			}
		}
	}
	snapshot := old.Snapshot
	snapshot.Epoch++
	snapshot.PreviousSHA256 = old.SnapshotSHA256
	cluster, _ := c.OverlayCluster(old.ClusterID)
	snapshot.Profiles = append([]overlayproto.ProfilePin{}, cluster.Profiles...)
	snapshot.FloatingIPs = recoveryFloatingPins(cluster, snapshot.FloatingIPs)
	var sha string
	if in.Replacement != nil {
		selection := OverlayEpochInput{ClusterID: old.ClusterID, ExpectedEpoch: old.Epoch, Members: in.Replacement.Members, Gateways: in.Replacement.Gateways, NATPolicies: in.Replacement.NATPolicies, FloatingIPs: in.Replacement.FloatingIPs}
		snapshot, sha, e = buildOverlaySnapshot(ctx, tx, c, cluster, old, selection, now, true)
	} else {
		snapshot, sha, e = overlayproto.CanonicalSnapshot(snapshot)
	}
	if e != nil {
		return old, false, e
	}
	if e = validatePublicIPSnapshotTx(ctx, tx, c, snapshot, now); e != nil {
		return old, false, e
	}
	recovery := &overlayproto.Recovery{Epoch: old.Epoch, SnapshotSHA256: old.SnapshotSHA256, Heads: append([]overlayproto.Head{}, heads...)}
	epoch := OverlayEpoch{ID: newID, ClusterID: old.ClusterID, Epoch: snapshot.Epoch, SnapshotSHA256: sha, Snapshot: snapshot, Recovery: recovery, Phase: "prepare", State: "pending", ActorID: actor, RequestSHA256: digest, CreatedAt: now.UTC().Truncate(time.Microsecond), UpdatedAt: now.UTC().Truncate(time.Microsecond)}
	raw, _ := json.Marshal(snapshot)
	rec, _ := json.Marshal(recovery)
	if _, e = tx.ExecContext(ctx, "INSERT INTO controller_overlay_epochs("+overlayEpochColumns+") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", epoch.ID, epoch.ClusterID, epoch.Epoch, actor, digest, sha, raw, rec, "", epoch.Phase, epoch.State, epoch.CreatedAt, epoch.UpdatedAt); e != nil {
		return old, false, e
	}
	for _, phase := range []string{"prepare", "program", "release"} {
		for _, pin := range snapshot.Profiles {
			p, _ := c.Node(pin.NodeID)
			wire := overlayTask(epoch, pin.NodeID, phase)
			_, requestSHA, e := wire.BytesAndDigest()
			if e != nil {
				return old, false, ErrInput
			}
			if _, e = tx.ExecContext(ctx, "INSERT INTO controller_overlay_tasks("+overlayTaskColumns+") VALUES(?,?,?,?,?,?,?,?,?)", wire.OperationID, newID, pin.NodeID, phase, p.Digest(), requestSHA, "pending", []byte{}, now); e != nil {
				return old, false, e
			}
		}
	}
	if _, e = tx.ExecContext(ctx, "UPDATE controller_overlay_epochs SET state='superseded',superseded_by=?,updated_at=? WHERE id=?", newID, now, original); e != nil {
		return old, false, e
	}
	if e = audit(ctx, tx, "user:"+actor, "overlay.recovery.planned", newID, now); e != nil {
		return old, false, e
	}
	if in.Replacement != nil {
		// The audit target binds the new operation to its exact canonical intent;
		// no original epoch, request, receipt or financial bytes are replaced.
		if e = audit(ctx, tx, "user:"+actor, "overlay.recovery.replacement", newID+":"+sha, now); e != nil {
			return old, false, e
		}
	}
	return epoch, false, nil
}

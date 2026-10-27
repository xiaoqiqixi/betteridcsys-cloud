package fabric

import (
	"aster/cloud/internal/overlayproto"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type overlayState struct {
	Meters   []Meter               `json:"meters"`
	Snapshot overlayproto.Snapshot `json:"snapshot"`
	Digest   string                `json:"digest"`
	State    string                `json:"state"`
	Ports    []overlayPort         `json:"ports"`
}
type overlayOperation struct {
	Task    overlayproto.Task    `json:"task"`
	Receipt overlayproto.Receipt `json:"receipt"`
}

func overlayHead(l *ledger) (overlayState, error) {
	raw, err := readPrivate(filepath.Join(l.cfg.StateDirectory, "overlay.owner"), uint32(os.Geteuid()), 1<<20)
	if err != nil {
		return overlayState{}, err
	}
	var h overlayState
	if object(raw, []string{"snapshot", "digest", "state", "ports", "meters"}, &h) != nil {
		return h, ErrUnavailable
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	s, err := overlayproto.DecodeSnapshot(fields["snapshot"])
	if err != nil {
		return h, ErrUnavailable
	}
	_, sha, err := overlayproto.CanonicalSnapshot(s)
	if err != nil || sha != h.Digest || h.Ports == nil || len(h.Ports) > 191 || h.Meters == nil || len(h.Meters) > 256 {
		return h, ErrUnavailable
	}
	if h.State != "preparing" && h.State != "prepared" && h.State != "programming" && h.State != "programmed" && h.State != "releasing" && h.State != "applied" && h.State != "uncertain" {
		return h, ErrUnavailable
	}
	var ports []json.RawMessage
	if json.Unmarshal(fields["ports"], &ports) != nil {
		return h, ErrUnavailable
	}
	names := map[string]bool{}
	numbers := map[int]bool{}
	for _, raw := range ports {
		var p overlayPort
		if object(raw, []string{"name", "uuid", "ofport", "kind", "identity"}, &p) != nil || !nameRE.MatchString(p.Name) || !ovsUUIDRE.MatchString(p.UUID) || p.OFPort < 1 || p.OFPort > 32767 || names[p.Name] || numbers[p.OFPort] || p.Kind != "member" && p.Kind != "tunnel" && p.Kind != "gateway" {
			return h, ErrUnavailable
		}
		names[p.Name] = true
		numbers[p.OFPort] = true
	}
	var meters []json.RawMessage
	_ = json.Unmarshal(fields["meters"], &meters)
	meterIDs := map[int]bool{}
	for _, raw := range meters {
		var m Meter
		if object(raw, []string{"ID", "Kbps"}, &m) != nil || m.ID < 1 || m.ID > 65535 || m.Kbps < 1000 || m.Kbps > 100000000 || meterIDs[m.ID] {
			return h, ErrUnavailable
		}
		meterIDs[m.ID] = true
	}
	return h, nil
}
func saveOverlayHead(l *ledger, h overlayState) error {
	raw, err := json.Marshal(h)
	if err != nil {
		return ErrUnavailable
	}
	return l.atomic("overlay.owner", raw)
}
func overlayOpName(id string) string { return "overlay-op-" + id + ".json" }
func readOverlayOperation(l *ledger, id string) (overlayOperation, error) {
	raw, err := readPrivate(filepath.Join(l.cfg.StateDirectory, overlayOpName(id)), uint32(os.Geteuid()), 1<<20)
	if err != nil {
		return overlayOperation{}, err
	}
	var o overlayOperation
	if object(raw, []string{"task", "receipt"}, &o) != nil {
		return o, ErrUnavailable
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	task, err := overlayproto.DecodeTask(fields["task"])
	if err != nil {
		return o, ErrUnavailable
	}
	receipt, err := overlayproto.DecodeReceipt(fields["receipt"])
	_, sha, te := task.BytesAndDigest()
	if err != nil || te != nil || task.OperationID != id || !receipt.Matches(task, sha) {
		return o, ErrUnavailable
	}
	return overlayOperation{task, receipt}, nil
}
func saveOverlayOperation(l *ledger, o overlayOperation) error {
	raw, err := json.Marshal(o)
	if err != nil {
		return ErrUnavailable
	}
	return l.atomic(overlayOpName(o.Task.OperationID), raw)
}
func overlayReceipt(t overlayproto.Task, sha, status, code string) overlayproto.Receipt {
	return overlayproto.Receipt{Protocol: overlayproto.Protocol, OperationID: t.OperationID, NodeID: t.NodeID, ClusterID: t.Snapshot.ClusterID, Epoch: t.Snapshot.Epoch, Phase: t.Phase, SnapshotSHA256: t.SnapshotSHA256, RequestSHA256: sha, Status: status, Code: code}
}
func overlayReceiptError(r overlayproto.Receipt) error {
	if r.Status == "succeeded" {
		return nil
	}
	if r.Status == "rejected" {
		return ErrConflict
	}
	return ErrUncertain
}
func ReadOverlaySnapshot(c OverlayConfig) (overlayproto.Snapshot, string, error) {
	if _, err := canonicalOverlayConfig(c); err != nil {
		return overlayproto.Snapshot{}, "", err
	}
	l, err := openLedger(c.Base, false, nil)
	if err != nil {
		return overlayproto.Snapshot{}, "", err
	}
	defer l.close()
	h, err := overlayHead(l)
	if err != nil {
		return overlayproto.Snapshot{}, "", err
	}
	if _, _, _, err = validateOverlayApproval(c, h.Snapshot); err != nil {
		return overlayproto.Snapshot{}, "", err
	}
	return h.Snapshot, h.State, nil
}
func (e *Executor) LookupOverlay(ctx context.Context, c OverlayConfig, id, sha string) (overlayproto.Receipt, error) {
	if e == nil || e.euid == nil || e.euid() != 0 || c.Base != e.Config || !idRE.MatchString(id) || !overlayproto.ValidSHA(sha) || ctx.Err() != nil {
		return overlayproto.Receipt{}, ErrInvalid
	}
	if _, err := canonicalOverlayConfig(c); err != nil {
		return overlayproto.Receipt{}, err
	}
	l, err := openLedger(e.Config, false, nil)
	if err != nil {
		return overlayproto.Receipt{}, err
	}
	defer l.close()
	o, err := readOverlayOperation(l, id)
	if err != nil {
		return overlayproto.Receipt{}, err
	}
	if o.Receipt.RequestSHA256 != sha || o.Receipt.NodeID != e.Config.NodeID {
		return overlayproto.Receipt{}, ErrConflict
	}
	return o.Receipt, overlayReceiptError(o.Receipt)
}
func (e *Executor) PrepareOverlay(ctx context.Context, c OverlayConfig, t overlayproto.Task, bootstrap func(context.Context) error) (overlayproto.Receipt, error) {
	return e.overlayPhase(ctx, c, t, "prepare", bootstrap)
}
func (e *Executor) ProgramOverlay(ctx context.Context, c OverlayConfig, t overlayproto.Task) (overlayproto.Receipt, error) {
	return e.overlayPhase(ctx, c, t, "program", nil)
}
func (e *Executor) ReleaseOverlay(ctx context.Context, c OverlayConfig, t overlayproto.Task, release func(context.Context) error) (overlayproto.Receipt, error) {
	return e.overlayPhase(ctx, c, t, "release", release)
}
func (e *Executor) overlayPhase(ctx context.Context, c OverlayConfig, t overlayproto.Task, phase string, callback func(context.Context) error) (overlayproto.Receipt, error) {
	if e == nil || e.euid == nil || e.euid() != 0 || e.Runner == nil || e.tap == nil || c.Base != e.Config || t.NodeID != c.Base.NodeID || t.Phase != phase || phase != "program" && callback == nil {
		return overlayproto.Receipt{}, ErrInvalid
	}
	var err error
	c, t.Snapshot, _, err = validateOverlayApproval(c, t.Snapshot)
	if err != nil {
		return overlayproto.Receipt{}, err
	}
	for _, p := range c.NATProfiles {
		if _, err := compileNAT(c, t.Snapshot, p, false); err != nil {
			return overlayproto.Receipt{}, err
		}
	}
	taskBytes, sha, err := t.BytesAndDigest()
	if err != nil {
		return overlayproto.Receipt{}, ErrInvalid
	}
	t, err = overlayproto.DecodeTask(taskBytes)
	if err != nil {
		return overlayproto.Receipt{}, ErrInvalid
	}
	l, err := openLedger(e.Config, true, e.fault)
	if err != nil {
		return overlayproto.Receipt{}, err
	}
	defer l.close()
	if _, stErr := os.Lstat(filepath.Join(e.Config.StateDirectory, "journal.json")); os.IsNotExist(stErr) {
		if l.save() != nil {
			return overlayproto.Receipt{}, ErrUncertain
		}
	} else if stErr != nil {
		return overlayproto.Receipt{}, ErrUnavailable
	}
	if l.activationPending() {
		return overlayproto.Receipt{}, ErrUncertain
	}
	for _, r := range l.state.Records {
		if r.Receipt.State != "applied" {
			return overlayproto.Receipt{}, ErrUncertain
		}
	}
	if _, err = os.Lstat(filepath.Join(e.Config.StateDirectory, overlayOpName(t.OperationID))); err == nil {
		o, err := readOverlayOperation(l, t.OperationID)
		if err != nil {
			return overlayproto.Receipt{}, err
		}
		if o.Receipt.RequestSHA256 != sha {
			return overlayproto.Receipt{}, ErrConflict
		}
		return o.Receipt, overlayReceiptError(o.Receipt)
	} else if !os.IsNotExist(err) {
		return overlayproto.Receipt{}, ErrUnavailable
	}
	wasOwned := l.overlayOwned()
	h, he := overlayHead(l)
	_, markerErr := os.Lstat(filepath.Join(e.Config.StateDirectory, "overlay.owner"))
	fresh := os.IsNotExist(markerErr)
	if markerErr != nil && !fresh {
		return overlayproto.Receipt{}, ErrUnavailable
	}
	if he != nil && (!fresh || wasOwned) {
		return overlayproto.Receipt{}, ErrUncertain
	}
	if phase == "prepare" {
		if t.Recovery != nil {
			expected := overlayproto.Head{NodeID: c.Base.NodeID}
			if !fresh {
				expected.ClusterID = h.Snapshot.ClusterID
				expected.Epoch = h.Snapshot.Epoch
				expected.SnapshotSHA256 = h.Digest
			}
			matched := false
			for _, head := range t.Recovery.Heads {
				if head.NodeID == c.Base.NodeID {
					matched = head == expected
				}
			}
			if !matched || t.Snapshot.Epoch <= expected.Epoch {
				return overlayproto.Receipt{}, ErrConflict
			}
		} else if fresh {
			if he == nil || t.Snapshot.Epoch != 1 {
				return overlayproto.Receipt{}, ErrConflict
			}
		} else if h.Snapshot.ClusterID != t.Snapshot.ClusterID || t.Snapshot.Epoch != h.Snapshot.Epoch+1 || t.Snapshot.PreviousSHA256 != h.Digest || h.State != "applied" {
			return overlayproto.Receipt{}, ErrConflict
		}
	} else if he != nil || h.Digest != t.SnapshotSHA256 || h.Snapshot.ClusterID != t.Snapshot.ClusterID || h.Snapshot.Epoch != t.Snapshot.Epoch || phase == "program" && h.State != "prepared" || phase == "release" && h.State != "programmed" {
		return overlayproto.Receipt{}, ErrConflict
	}

	profileSHA, _ := OverlayConfigSHA256(c)
	if l.checkNATInventory(c) != nil {
		return overlayproto.Receipt{}, ErrConflict
	}
	if err := l.authorizeOverlayPin(c, t, h, profileSHA); err != nil {
		return overlayproto.Receipt{}, err
	}
	op := overlayOperation{Task: t, Receipt: overlayReceipt(t, sha, "uncertain", "OVERLAY_PHASE_UNCONFIRMED")}
	if saveOverlayOperation(l, op) != nil {
		return op.Receipt, ErrUncertain
	}
	if err := l.migrateOverlayPin(c, t, h, profileSHA, sha); err != nil {
		return op.Receipt, ErrUncertain
	}
	if fresh {
		if l.save() != nil {
			return op.Receipt, ErrUncertain
		}
	}
	if phase == "prepare" {
		if !fresh {
			raw, _ := json.Marshal(h)
			if l.atomic("overlay-epoch-"+strconv.FormatInt(h.Snapshot.Epoch, 10)+".json", raw) != nil {
				return op.Receipt, ErrUncertain
			}
		}
		retained := append([]Meter{}, h.Meters...)
		if fresh && len(l.state.Records) > 0 {
			legacy, _ := Compile(l.state.Records[len(l.state.Records)-1].Topology)
			retained = append([]Meter{}, legacy.Meters...)
		}
		h = overlayState{Snapshot: t.Snapshot, Digest: t.SnapshotSHA256, State: "preparing", Ports: []overlayPort{}, Meters: retained}
	} else if phase == "program" {
		h.State = "programming"
	} else {
		h.State = "releasing"
	}
	if saveOverlayHead(l, h) != nil {
		return op.Receipt, ErrUncertain
	}
	owned := false
	fail := func(code string) (overlayproto.Receipt, error) {
		nctx, ncancel := context.WithTimeout(context.Background(), 5*time.Second)
		if e.isolateNAT(nctx, c) != nil {
			code = "NAT_ISOLATION_UNCONFIRMED"
		}
		ncancel()
		if owned {
			cctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if e.isolateOverlay(cctx, l) != nil {
				code = "OVERLAY_ISOLATION_UNCONFIRMED"
			}
			cancel()
		}
		h.State = "uncertain"
		_ = saveOverlayHead(l, h)
		op.Receipt = overlayReceipt(t, sha, "uncertain", code)
		_ = saveOverlayOperation(l, op)
		return op.Receipt, ErrUncertain
	}
	var ports []overlayPort
	ports, owned, err = e.probeOverlay(ctx, c, t.Snapshot, phase == "prepare")
	if err != nil {
		return fail("OVERLAY_IDENTITY_UNCONFIRMED")
	}
	if e.ownedFlows(ctx) != nil {
		return fail("OVERLAY_FOREIGN_FLOWS")
	}
	if phase == "prepare" {
		if e.prepareNAT(ctx, c, l, t.Snapshot, t) != nil {
			return fail("NAT_PREPARE_UNCONFIRMED")
		}
		if e.isolateOverlay(ctx, l) != nil {
			return fail("OVERLAY_ISOLATION_UNCONFIRMED")
		}
		if callOverlayCallback(ctx, callback) != nil {
			return fail("OVERLAY_BOOTSTRAP_UNCONFIRMED")
		}
		ports, owned, err = e.probeOverlay(ctx, c, t.Snapshot, true)
		if err != nil {
			return fail("OVERLAY_IDENTITY_UNCONFIRMED")
		}
		if e.createOverlayTunnels(ctx, c, t.Snapshot, ports) != nil {
			return fail("OVERLAY_TUNNELS_UNCONFIRMED")
		}
		ports, owned, err = e.probeOverlay(ctx, c, t.Snapshot, false)
		if err != nil {
			return fail("OVERLAY_TUNNELS_UNCONFIRMED")
		}
		if e.verifyOverlayIsolation(ctx, l) != nil {
			return fail("OVERLAY_ISOLATION_UNCONFIRMED")
		}
		h.Ports = ports
		h.State = "prepared"
	} else {
		if !sameOverlayPorts(ports, h.Ports) {
			return fail("OVERLAY_PORTS_CHANGED")
		}
		p, pe := compileOverlay(c, t.Snapshot, ports)
		if pe != nil {
			return fail("OVERLAY_PLAN_REJECTED")
		}
		if phase == "program" {
			if e.verifyOverlayIsolation(ctx, l) != nil {
				return fail("OVERLAY_ISOLATION_UNCONFIRMED")
			}
			if e.programNAT(ctx, c, l, t.Snapshot) != nil {
				return fail("NAT_PROGRAM_UNCONFIRMED")
			}
			if e.programOverlay(ctx, l, p, h.Meters) != nil {
				return fail("OVERLAY_PROGRAM_UNCONFIRMED")
			}
			h.State = "programmed"
			h.Meters = append([]Meter{}, p.Meters...)
		} else {
			if e.verifyOverlayPlan(ctx, l, p) != nil {
				return fail("OVERLAY_READBACK_UNCONFIRMED")
			}
			if e.releaseNAT(ctx, c, l, t.Snapshot) != nil {
				return fail("NAT_RELEASE_UNCONFIRMED")
			}
			if callOverlayCallback(ctx, callback) != nil {
				return fail("OVERLAY_RELEASE_UNCONFIRMED")
			}
			if e.verifyOverlayPlan(ctx, l, p) != nil {
				return fail("OVERLAY_READBACK_UNCONFIRMED")
			}
			if e.verifyNAT(ctx, c, l, t.Snapshot, true) != nil {
				return fail("NAT_READBACK_UNCONFIRMED")
			}
			h.State = "applied"
		}
		after, ok, pe := e.probeOverlay(ctx, c, t.Snapshot, false)
		owned = owned && ok
		if pe != nil || !sameOverlayPorts(ports, after) {
			return fail("OVERLAY_PORTS_CHANGED")
		}
	}
	if ctx.Err() != nil {
		return fail("OVERLAY_CANCELLED")
	}
	if saveOverlayHead(l, h) != nil {
		return fail("OVERLAY_RECEIPT_UNCONFIRMED")
	}
	op.Receipt = overlayReceipt(t, sha, "succeeded", "OVERLAY_"+strings.ToUpper(phase)+"_CONFIRMED")
	if saveOverlayOperation(l, op) != nil {
		return fail("OVERLAY_RECEIPT_UNCONFIRMED")
	}
	return op.Receipt, nil
}
func callOverlayCallback(ctx context.Context, f func(context.Context) error) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrUncertain
		}
	}()
	if ctx.Err() != nil || f == nil {
		return ErrUncertain
	}
	return f(ctx)
}
func (e *Executor) isolateOverlay(ctx context.Context, l *ledger) error {
	if l.atomic("overlay-isolation.flows", []byte(strings.Join(isolationFlows(), "\n")+"\n")) != nil {
		return ErrUncertain
	}
	if _, err := e.of(ctx, "--bundle", "replace-flows", e.Config.Bridge, filepath.Join(e.Config.StateDirectory, "overlay-isolation.flows")); err != nil {
		return err
	}
	return e.verifyOverlayIsolation(ctx, l)
}
func (e *Executor) verifyOverlayIsolation(ctx context.Context, l *ledger) error {
	path := filepath.Join(e.Config.StateDirectory, "overlay-isolation.flows")
	raw, err := readPrivate(path, uint32(os.Geteuid()), 1<<20)
	if err != nil || string(raw) != strings.Join(isolationFlows(), "\n")+"\n" {
		return ErrUncertain
	}
	_, err = e.of(ctx, "diff-flows", path, e.Config.Bridge)
	return err
}
func (e *Executor) programOverlay(ctx context.Context, l *ledger, p overlayPlan, previous []Meter) error {
	if e.checkMeters(ctx, append(append([]Meter{}, previous...), p.Meters...), false) != nil {
		return ErrUncertain
	}
	if l.atomic("overlay-desired.flows", []byte(strings.Join(p.Flows, "\n")+"\n")) != nil {
		return ErrUncertain
	}
	if _, err := e.of(ctx, "del-meters", e.Config.Bridge); err != nil {
		return err
	}
	for _, m := range p.Meters {
		if _, err := e.of(ctx, "add-meter", e.Config.Bridge, "meter="+strconv.Itoa(m.ID)+",kbps,stats,bands=type=drop,rate="+strconv.Itoa(m.Kbps)); err != nil {
			return err
		}
	}
	if e.checkMeters(ctx, p.Meters, true) != nil {
		return ErrUncertain
	}
	if _, err := e.of(ctx, "--bundle", "replace-flows", e.Config.Bridge, filepath.Join(e.Config.StateDirectory, "overlay-desired.flows")); err != nil {
		return err
	}
	return e.verifyOverlayPlan(ctx, l, p)
}
func (e *Executor) verifyOverlayPlan(ctx context.Context, l *ledger, p overlayPlan) error {
	path := filepath.Join(e.Config.StateDirectory, "overlay-desired.flows")
	raw, err := readPrivate(path, uint32(os.Geteuid()), 1<<20)
	if err != nil || string(raw) != strings.Join(p.Flows, "\n")+"\n" {
		return ErrUncertain
	}
	if _, err = e.of(ctx, "diff-flows", path, e.Config.Bridge); err != nil {
		return err
	}
	return e.checkMeters(ctx, p.Meters, true)
}
func (e *Executor) CheckOverlay(ctx context.Context, c OverlayConfig) (overlayproto.Snapshot, error) {
	if e == nil || e.euid == nil || e.euid() != 0 || c.Base != e.Config {
		return overlayproto.Snapshot{}, ErrInvalid
	}
	l, err := openLedger(e.Config, false, nil)
	if err != nil {
		return overlayproto.Snapshot{}, err
	}
	defer l.close()
	h, err := overlayHead(l)
	if err != nil || h.State != "applied" {
		return overlayproto.Snapshot{}, ErrUncertain
	}
	c, s, _, err := validateOverlayApproval(c, h.Snapshot)
	if err != nil {
		return overlayproto.Snapshot{}, err
	}
	reader := *e
	reader.readOnly = true
	reader.fault = nil
	ports, _, err := reader.probeOverlay(ctx, c, s, false)
	if err != nil || !sameOverlayPorts(ports, h.Ports) {
		return overlayproto.Snapshot{}, ErrUncertain
	}
	p, err := compileOverlay(c, s, ports)
	if err != nil || reader.verifyOverlayPlan(ctx, l, p) != nil || reader.verifyNAT(ctx, c, l, s, true) != nil {
		return overlayproto.Snapshot{}, ErrUncertain
	}
	after, _, err := reader.probeOverlay(ctx, c, s, false)
	if err != nil || !sameOverlayPorts(ports, after) || ctx.Err() != nil {
		return overlayproto.Snapshot{}, ErrUncertain
	}
	return s, nil
}

// ReadOverlayHead has no mkdir/lock creation. No existing fabric state means
// a genuine first participant; an existing lock with missing journal is error.
func ReadOverlayHead(c OverlayConfig) (overlayproto.Head, error) {
	if _, err := canonicalOverlayConfig(c); err != nil {
		return overlayproto.Head{}, err
	}
	empty := overlayproto.Head{NodeID: c.Base.NodeID}
	if err := securePath(c.Base.StateDirectory); err != nil {
		return overlayproto.Head{}, err
	}
	if _, err := os.Lstat(c.Base.StateDirectory); os.IsNotExist(err) {
		return empty, nil
	} else if err != nil {
		return overlayproto.Head{}, ErrUnavailable
	}
	if _, err := os.Lstat(filepath.Join(c.Base.StateDirectory, "fabric.lock")); os.IsNotExist(err) {
		entries, e := os.ReadDir(c.Base.StateDirectory)
		if e != nil || len(entries) != 0 {
			return overlayproto.Head{}, ErrUnavailable
		}
		return empty, nil
	}
	l, err := openLedger(c.Base, false, nil)
	if err != nil {
		return overlayproto.Head{}, err
	}
	defer l.close()
	if _, err := os.Lstat(filepath.Join(c.Base.StateDirectory, "overlay.owner")); os.IsNotExist(err) {
		if l.overlayOwned() {
			return overlayproto.Head{}, ErrUncertain
		}
		return empty, nil
	}
	h, err := overlayHead(l)
	if err != nil {
		return overlayproto.Head{}, err
	}
	return overlayproto.Head{NodeID: c.Base.NodeID, ClusterID: h.Snapshot.ClusterID, Epoch: h.Snapshot.Epoch, SnapshotSHA256: h.Digest}, nil
}

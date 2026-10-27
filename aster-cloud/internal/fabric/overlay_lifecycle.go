package fabric

import (
	"aster/cloud/internal/overlayproto"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type overlayLocalOperation struct {
	BindingSHA256  string           `json:"binding_sha256"`
	Intent         ActivationIntent `json:"intent"`
	IntentSHA256   string           `json:"intent_sha256"`
	SnapshotSHA256 string           `json:"snapshot_sha256"`
	Mode           string           `json:"mode"`
	State          string           `json:"state"`
	Proof          LiveVerification `json:"proof"`
}

func overlayLocalName(id string) string { return "overlay-local-op-" + id + ".json" }
func overlayProof(c OverlayConfig, h overlayState) LiveVerification {
	raw, _ := json.Marshal(h.Ports)
	return LiveVerification{Protocol: LiveProtocol, NodeID: c.Base.NodeID, Revision: h.Snapshot.Epoch, Digest: h.Digest, BindingsSHA256: overlayproto.Digest(raw), State: "verified", ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
}
func overlayAuthorizes(c OverlayConfig, s overlayproto.Snapshot, in ActivationIntent, enabled bool, bindingSHA string) bool {
	members := map[string]overlayproto.Member{}
	for _, m := range s.Members {
		if m.NodeID == c.Base.NodeID {
			members[m.InstanceID] = m
		}
	}
	found := false
	for _, p := range in.Ports {
		m, ok := members[p.InstanceID]
		if !ok {
			if p.Enabled {
				return false
			}
			continue
		}
		if p.InterfaceID != m.InterfaceID || p.OwnerRef != m.OwnerRef || p.VPCID != m.LocalVPCID || p.IPv4 != m.IPv4 || p.MAC != m.MAC || p.InboundMbps != m.InboundMbps || p.OutboundMbps != m.OutboundMbps {
			return false
		}
		if p.InstanceID == in.InstanceID {
			if p.Enabled != enabled || enabled && !m.Enabled || m.NetworkSHA256 != bindingSHA || !overlayproto.ValidSHA(bindingSHA) {
				return false
			}
			found = true
		}
	}
	return found
}
func (e *Executor) OverlayActivate(ctx context.Context, c OverlayConfig, in ActivationIntent, bindingSHA string, bootstrap, release func(context.Context) error) (LiveVerification, error) {
	return e.overlayLocal(ctx, c, in, bindingSHA, true, bootstrap, release)
}
func (e *Executor) OverlayDeactivate(ctx context.Context, c OverlayConfig, in ActivationIntent, bindingSHA string, stop func(context.Context) error) (LiveVerification, error) {
	return e.overlayLocal(ctx, c, in, bindingSHA, false, stop, nil)
}
func (e *Executor) overlayLocal(ctx context.Context, c OverlayConfig, in ActivationIntent, bindingSHA string, start bool, change, release func(context.Context) error) (LiveVerification, error) {
	if e == nil || e.euid == nil || e.euid() != 0 || c.Base != e.Config || change == nil || start && release == nil {
		return LiveVerification{}, ErrInvalid
	}
	in, intentSHA, err := canonicalActivation(c.Base, in)
	if err != nil {
		return LiveVerification{}, err
	}
	if _, err = canonicalOverlayConfig(c); err != nil {
		return LiveVerification{}, err
	}
	l, err := openLedger(c.Base, true, e.fault)
	if err != nil {
		return LiveVerification{}, err
	}
	defer l.close()
	h, err := overlayHead(l)
	if err != nil {
		return LiveVerification{}, err
	}
	c, s, _, err := validateOverlayApproval(c, h.Snapshot)
	if err != nil {
		return LiveVerification{}, err
	}
	if !overlayAuthorizes(c, s, in, start, bindingSHA) {
		return LiveVerification{}, ErrConflict
	}
	mode := "stop"
	if start {
		mode = "start"
	}
	name := overlayLocalName(in.OperationID)
	if _, err := os.Lstat(filepath.Join(c.Base.StateDirectory, name)); err == nil {
		raw, err := readPrivate(filepath.Join(c.Base.StateDirectory, name), uint32(os.Geteuid()), 1<<20)
		if err != nil {
			return LiveVerification{}, err
		}
		var old overlayLocalOperation
		if object(raw, []string{"intent", "intent_sha256", "binding_sha256", "snapshot_sha256", "mode", "state", "proof"}, &old) != nil {
			return LiveVerification{}, ErrUnavailable
		}
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(raw, &fields)
		wrapper := []byte(`{"intent":` + string(fields["intent"]) + `,"intent_sha256":"` + old.IntentSHA256 + `","state":"completed","stage":"completed","updated_at":"2000-01-01T00:00:00Z"}`)
		var proof LiveVerification
		if decodeActivationRecord(wrapper) != nil || object(fields["proof"], []string{"protocol", "node_id", "revision", "digest", "bindings_sha256", "state", "observed_at"}, &proof) != nil {
			return LiveVerification{}, ErrUnavailable
		}
		_, sha, err := canonicalActivation(c.Base, old.Intent)
		if err != nil || sha != old.IntentSHA256 {
			return LiveVerification{}, ErrUnavailable
		}
		if old.IntentSHA256 != intentSHA || old.Mode != mode || old.BindingSHA256 != bindingSHA {
			return LiveVerification{}, ErrConflict
		}
		if old.State != "completed" {
			return LiveVerification{}, ErrUncertain
		}
		if old.Proof.Revision < 1 || !overlayproto.ValidSHA(old.SnapshotSHA256) || old.Proof.Protocol != LiveProtocol || old.Proof.NodeID != c.Base.NodeID || old.Proof.Digest != old.SnapshotSHA256 || old.Proof.State != "verified" || !overlayproto.ValidSHA(old.Proof.BindingsSHA256) {
			return LiveVerification{}, ErrUnavailable
		}
		return old.Proof, nil
	} else if !os.IsNotExist(err) {
		return LiveVerification{}, ErrUnavailable
	}
	if h.State != "applied" {
		return LiveVerification{}, ErrUncertain
	}
	op := overlayLocalOperation{Intent: in, IntentSHA256: intentSHA, BindingSHA256: bindingSHA, SnapshotSHA256: h.Digest, Mode: mode, State: "uncertain"}
	save := func() error { raw, _ := json.Marshal(op); return l.atomic(name, raw) }
	if save() != nil {
		return LiveVerification{}, ErrUncertain
	}
	h.State = "preparing"
	if saveOverlayHead(l, h) != nil {
		return LiveVerification{}, ErrUncertain
	}
	owned := false
	fail := func() (LiveVerification, error) {
		nctx, ncancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = e.isolateNAT(nctx, c)
		ncancel()
		if owned {
			cctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = e.isolateOverlay(cctx, l)
			cancel()
		}
		h.State = "uncertain"
		_ = saveOverlayHead(l, h)
		return LiveVerification{}, ErrUncertain
	}
	before, owned, err := e.probeOverlay(ctx, c, s, false)
	if err != nil || !sameOverlayPorts(before, h.Ports) || e.ownedFlows(ctx) != nil || e.verifyNAT(ctx, c, l, s, true) != nil {
		return fail()
	}
	if e.isolateOverlay(ctx, l) != nil {
		return fail()
	}
	if callOverlayCallback(ctx, change) != nil {
		return fail()
	}
	admitID := ""
	if start {
		admitID = in.InstanceID
	}
	after, ok, err := e.probeOverlayAdmitting(ctx, c, s, false, admitID)
	owned = owned && ok
	if err != nil {
		return fail()
	}
	present := false
	for _, p := range after {
		if p.Kind == "member" && p.Identity == in.InstanceID {
			present = true
		}
	}
	if present != start {
		return fail()
	}
	if start {
		var target overlayproto.Member
		for _, member := range s.Members {
			if member.NodeID == c.Base.NodeID && member.InstanceID == in.InstanceID {
				target = member
			}
		}
		if _, err := e.run(ctx, Vsctl, "--timeout=3", "set", "Interface", TAPName(in.InstanceID), "external_ids:aster-node-id="+c.Base.NodeID, "external_ids:aster-owner="+target.OwnerRef, "external_ids:aster-instance="+target.InstanceID, "external_ids:aster-vpc="+target.LocalVPCID); err != nil {
			return fail()
		}
		checked, ok, err := e.probeOverlay(ctx, c, s, false)
		owned = owned && ok
		if err != nil || !sameOverlayPorts(after, checked) {
			return fail()
		}
		after = checked
	}
	p, err := compileOverlay(c, s, after)
	if err != nil || e.programOverlay(ctx, l, p, h.Meters) != nil {
		return fail()
	}
	if start && callOverlayCallback(ctx, release) != nil {
		return fail()
	}
	if e.verifyOverlayPlan(ctx, l, p) != nil || e.verifyNAT(ctx, c, l, s, true) != nil {
		return fail()
	}
	final, ok, err := e.probeOverlay(ctx, c, s, false)
	owned = owned && ok
	if err != nil || !sameOverlayPorts(after, final) || ctx.Err() != nil {
		return fail()
	}
	h.State = "applied"
	h.Ports = final
	h.Meters = append([]Meter{}, p.Meters...)
	if saveOverlayHead(l, h) != nil {
		return fail()
	}
	op.State = "completed"
	op.Proof = overlayProof(c, h)
	if save() != nil {
		op.State = "uncertain"
		_ = save()
		return fail()
	}
	return op.Proof, nil
}
func overlayReadOnlyCommand(c Config, binary string, args []string) bool {
	if binary == NATIP && len(args) == 6 && args[0] == "-j" && args[1] == "-d" && args[2] == "link" && args[3] == "show" && args[4] == "dev" && nameRE.MatchString(args[5]) {
		return true
	}

	if binary == Vsctl && len(args) == 5 && args[0] == "--timeout=3" && args[1] == "--format=json" && args[3] == "list" {
		return args[2] == "--columns=_uuid,name,ofport,type,external_ids,options,mtu" && args[4] == "Interface" || args[2] == "--columns=name,interfaces,tag,trunks,vlan_mode" && args[4] == "Port"
	}
	if binary == Ofctl && len(args) == 7 && args[0] == "-O" && args[1] == "OpenFlow14" && args[2] == "--no-names" && args[3] == "--read-only" && args[4] == "diff-flows" && args[6] == c.Bridge {
		return args[5] == filepath.Join(c.StateDirectory, "overlay-desired.flows") || args[5] == filepath.Join(c.StateDirectory, "overlay-isolation.flows")
	}
	return false
}

// Keep the permitted command surface explicit even though callbacks are trusted
// root components. NAT commands use a separately approved, descriptor-pinned
// namespace. Host nftables, forwarding and routes remain read-only/unmodified.

// OverlayCheck additionally proves the requested member is eligible and has its
// exact live TAP, rather than treating an unrelated applied epoch as VM proof.
func (e *Executor) OverlayCheck(ctx context.Context, c OverlayConfig, in ActivationIntent, bindingSHA string) (LiveVerification, error) {
	if e == nil || e.euid == nil || e.euid() != 0 || c.Base != e.Config {
		return LiveVerification{}, ErrInvalid
	}
	in, _, err := canonicalActivation(c.Base, in)
	if err != nil {
		return LiveVerification{}, err
	}
	l, err := openLedger(c.Base, false, nil)
	if err != nil {
		return LiveVerification{}, err
	}
	defer l.close()
	h, err := overlayHead(l)
	if err != nil || h.State != "applied" {
		return LiveVerification{}, ErrUncertain
	}
	c, s, _, err := validateOverlayApproval(c, h.Snapshot)
	if err != nil || !overlayAuthorizes(c, s, in, true, bindingSHA) {
		return LiveVerification{}, ErrConflict
	}
	reader := *e
	reader.readOnly = true
	reader.fault = nil
	ports, _, err := reader.probeOverlay(ctx, c, s, false)
	if err != nil || !sameOverlayPorts(ports, h.Ports) {
		return LiveVerification{}, ErrUncertain
	}
	found := false
	for _, p := range ports {
		if p.Kind == "member" && p.Identity == in.InstanceID {
			found = true
		}
	}
	if !found {
		return LiveVerification{}, ErrUncertain
	}
	p, err := compileOverlay(c, s, ports)
	if err != nil || reader.verifyOverlayPlan(ctx, l, p) != nil || reader.verifyNAT(ctx, c, l, s, true) != nil {
		return LiveVerification{}, ErrUncertain
	}
	after, _, err := reader.probeOverlay(ctx, c, s, false)
	if err != nil || !sameOverlayPorts(ports, after) || ctx.Err() != nil {
		return LiveVerification{}, ErrUncertain
	}
	return overlayProof(c, h), nil
}

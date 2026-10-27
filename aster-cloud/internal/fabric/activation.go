package fabric

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// PortIntent is immutable authorization, not a cached ofport. Disabled ports
// remain identity-checked if present, but receive no allow flows or meters.
type PortIntent struct {
	InstanceID   string `json:"instance_id"`
	InterfaceID  string `json:"interface_id"`
	OwnerRef     string `json:"owner_ref"`
	VPCID        string `json:"vpc_id"`
	IPv4         string `json:"ipv4"`
	MAC          string `json:"mac"`
	InboundMbps  int    `json:"inbound_mbps"`
	OutboundMbps int    `json:"outbound_mbps"`
	Enabled      bool   `json:"enabled"`
}

// ActivationIntent must be built from the node's durable, independently approved
// bindings. It describes ALL nondeleted OVS instances, not customer supplied ports.
// Activate/Check require the target enabled; Deactivate requires it disabled.
// Only independently confirmed running peers should be enabled. This object
// cannot approve a bridge, create a NIC or configure a tunnel.
type ActivationIntent struct {
	OperationID   string       `json:"operation_id"`
	RequestSHA256 string       `json:"request_sha256"`
	InstanceID    string       `json:"instance_id"`
	VPCs          []VPC        `json:"vpcs"`
	Ports         []PortIntent `json:"ports"`
}

func namedUUID(namespace, instance string) string {
	if !idRE.MatchString(instance) {
		return ""
	}
	h := sha256.Sum256([]byte(namespace + instance))
	h[6] = h[6]&15 | 0x80
	h[8] = h[8]&63 | 0x80
	s := hex.EncodeToString(h[:16])
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
}

// DomainID and TAPName must also be pinned in the independently verified domain
// XML. TAPName does not use libvirt's reserved vnet/vif/macvtap/macvlan prefixes.
func DomainID(instance string) string { return namedUUID("aster.fabric.domain/1:", instance) }
func TAPName(instance string) string {
	if !idRE.MatchString(instance) {
		return ""
	}
	return "ast" + instance[:12]
}

func (p PortIntent) port(ofport int) Port {
	return Port{p.InstanceID, p.InterfaceID, p.OwnerRef, p.VPCID, p.IPv4, p.MAC, ofport, p.InboundMbps, p.OutboundMbps}
}
func canonicalActivation(c Config, in ActivationIntent) (ActivationIntent, string, error) {
	if !idRE.MatchString(in.OperationID) || !idRE.MatchString(in.InstanceID) || len(in.RequestSHA256) != 64 {
		return ActivationIntent{}, "", ErrInvalid
	}
	if raw, e := hex.DecodeString(in.RequestSHA256); e != nil || len(raw) != 32 || strings.ToLower(in.RequestSHA256) != in.RequestSHA256 {
		return ActivationIntent{}, "", ErrInvalid
	}
	in.VPCs = append([]VPC{}, in.VPCs...)
	in.Ports = append([]PortIntent{}, in.Ports...)
	sort.Slice(in.VPCs, func(i, j int) bool { return in.VPCs[i].ID < in.VPCs[j].ID })
	sort.Slice(in.Ports, func(i, j int) bool { return in.Ports[i].InstanceID < in.Ports[j].InstanceID })
	t := Topology{Schema: 1, NodeID: c.NodeID, Revision: 1, VPCs: in.VPCs, Ports: []Port{}}
	names := map[string]bool{}
	found := false
	for j, p := range in.Ports {
		name := TAPName(p.InstanceID)
		if name == "" || names[name] {
			return ActivationIntent{}, "", ErrInvalid
		}
		names[name] = true
		t.Ports = append(t.Ports, p.port(j+1))
		if p.InstanceID == in.InstanceID {
			found = true
		}
	}
	if !found {
		return ActivationIntent{}, "", ErrInvalid
	}
	if _, e := Compile(t); e != nil {
		return ActivationIntent{}, "", e
	}
	raw, _ := json.Marshal(in)
	h := sha256.Sum256(raw)
	return in, hex.EncodeToString(h[:]), nil
}

type activationRecord struct {
	Intent       ActivationIntent `json:"intent"`
	IntentSHA256 string           `json:"intent_sha256"`
	State        string           `json:"state"`
	Stage        string           `json:"stage"`
	UpdatedAt    string           `json:"updated_at"`
}

func (l *ledger) activationPending() bool {
	if l.state.Recovery != nil && l.state.Recovery.State != "completed" {
		return true
	}
	for _, a := range l.state.Activations {
		if a.State != "completed" {
			return true
		}
	}
	return false
}
func (l *ledger) validateActivations() error {
	if l.state.Schema == 1 {
		if len(l.state.Activations) != 0 {
			return ErrUnavailable
		}
		return nil
	}
	if (l.state.Schema != 2 && l.state.Schema != 3) || l.state.Activations == nil || len(l.state.Activations) > 64 {
		return ErrUnavailable
	}
	seen := map[string]bool{}
	for _, a := range l.state.Activations {
		_, sha, e := canonicalActivation(l.cfg, a.Intent)
		at, te := time.Parse(time.RFC3339Nano, a.UpdatedAt)
		if e != nil || sha != a.IntentSHA256 || seen[a.Intent.OperationID] || te != nil || !strings.HasSuffix(a.UpdatedAt, "Z") || at.Year() < 1 {
			return ErrUnavailable
		}
		seen[a.Intent.OperationID] = true
		switch a.State {
		case "preparing":
			if a.Stage != "recorded" && a.Stage != "quarantined" && a.Stage != "bootstrapped" && a.Stage != "programmed" && a.Stage != "releasing" {
				return ErrUnavailable
			}
		case "completed":
			if a.Stage != "completed" {
				return ErrUnavailable
			}
		case "uncertain":
			if a.Stage != "activation_unconfirmed" && a.Stage != "isolation_unconfirmed" {
				return ErrUnavailable
			}
		default:
			return ErrUnavailable
		}
	}
	return nil
}
func decodeActivationRecord(raw []byte) error {
	var a activationRecord
	if object(raw, []string{"intent", "intent_sha256", "state", "stage", "updated_at"}, &a) != nil {
		return ErrUnavailable
	}
	var outer map[string]json.RawMessage
	_ = json.Unmarshal(raw, &outer)
	if object(outer["intent"], []string{"operation_id", "request_sha256", "instance_id", "vpcs", "ports"}, &a.Intent) != nil {
		return ErrUnavailable
	}
	var inner map[string]json.RawMessage
	_ = json.Unmarshal(outer["intent"], &inner)
	var vpcs, ports []json.RawMessage
	if json.Unmarshal(inner["vpcs"], &vpcs) != nil || json.Unmarshal(inner["ports"], &ports) != nil || len(vpcs) > 32 || len(ports) > 128 {
		return ErrUnavailable
	}
	for _, v := range vpcs {
		var p VPC
		if object(v, []string{"id", "owner_ref", "cidr", "vlan_id"}, &p) != nil {
			return ErrUnavailable
		}
	}
	for _, v := range ports {
		var p PortIntent
		if object(v, []string{"instance_id", "interface_id", "owner_ref", "vpc_id", "ipv4", "mac", "inbound_mbps", "outbound_mbps", "enabled"}, &p) != nil {
			return ErrUnavailable
		}
	}
	return nil
}

// activationTopology resolves ephemeral ofports only from exact current stable
// identities. A missing enabled peer is failure, not a silent partial network.
func activationTopology(c Config, in ActivationIntent, bs []binding, revision int64, requireTarget bool) (Topology, error) {
	t := Topology{Schema: 1, NodeID: c.NodeID, Revision: revision, VPCs: append([]VPC{}, in.VPCs...), Ports: []Port{}}
	byName := map[string]PortIntent{}
	present := map[string]bool{}
	for _, p := range in.Ports {
		byName[TAPName(p.InstanceID)] = p
	}
	for _, b := range bs {
		p, ok := byName[b.Name]
		if !ok || p.InstanceID != b.InstanceID || p.InterfaceID != b.InterfaceID || p.OwnerRef != b.OwnerRef || p.VPCID != b.VPCID {
			return Topology{}, ErrUncertain
		}
		present[p.InstanceID] = true
		if p.Enabled {
			t.Ports = append(t.Ports, p.port(b.OFPort))
		}
	}
	for _, p := range in.Ports {
		if p.Enabled && (p.InstanceID != in.InstanceID || requireTarget) && !present[p.InstanceID] {
			return Topology{}, ErrUncertain
		}
	}
	if _, e := Compile(t); e != nil {
		return Topology{}, ErrUncertain
	}
	return t, nil
}

// Activate holds one exclusive cross-process flock across quarantine, the
// caller's paused/link-down bootstrap, dynamic identity binding, apply/readback,
// and its final link-up/resume. Callbacks are trusted compiled node lifecycle
// operations, never external scripts. There is no retry, historical start permit
// or automatic release on error. Every failure returns a zero live proof.
func (e *Executor) Activate(ctx context.Context, input ActivationIntent, bootstrap, release func(context.Context) error) (LiveVerification, error) {
	return e.transition(ctx, input, bootstrap, release, false)
}

// Deactivate quarantines before a trusted stop/delete callback and requires the
// target TAP to disappear before rebuilding only the remaining enabled peers.
// The target remains in intent with Enabled=false; no stale ofport allow survives.
func (e *Executor) Deactivate(ctx context.Context, input ActivationIntent, stop func(context.Context) error) (LiveVerification, error) {
	return e.transition(ctx, input, stop, nil, true)
}

func (e *Executor) transition(ctx context.Context, input ActivationIntent, bootstrap, release func(context.Context) error, deactivate bool) (LiveVerification, error) {
	if e == nil || e.Runner == nil || e.tap == nil || e.euid == nil || e.euid() != 0 || !e.Config.Validate() || bootstrap == nil || (!deactivate && release == nil) || ctx.Err() != nil {
		return LiveVerification{}, ErrInvalid
	}
	in, sha, err := canonicalActivation(e.Config, input)
	if err != nil {
		return LiveVerification{}, err
	}
	for _, p := range in.Ports {
		if p.InstanceID == in.InstanceID && p.Enabled == deactivate {
			return LiveVerification{}, ErrInvalid
		}
	}
	l, err := openLedger(e.Config, true, e.fault)
	if err != nil {
		return LiveVerification{}, err
	}
	defer l.close()
	if err := l.legacyGuard(); err != nil {
		return LiveVerification{}, err
	}
	if l.activationPending() {
		return LiveVerification{}, ErrUncertain
	}
	if l.operationSeen(in.OperationID) {
		return LiveVerification{}, ErrConflict
	}
	if l.compact() != nil {
		return LiveVerification{}, ErrUnavailable
	}
	revision := int64(1)
	for _, r := range l.state.Records {
		if r.Receipt.State != "applied" {
			return LiveVerification{}, ErrUncertain
		}
		if r.Receipt.Revision >= revision {
			revision = r.Receipt.Revision + 1
		}
		if revision < 1 {
			return LiveVerification{}, ErrUncertain
		}
	}
	empty := Plan{Topology: Topology{Schema: 1, NodeID: e.Config.NodeID, Revision: revision, VPCs: []VPC{}, Ports: []Port{}}}
	before, owned, probeErr := e.probeActivation(ctx, empty, &in, false)
	if !owned {
		return LiveVerification{}, ErrUncertain
	}
	for _, b := range before {
		if !deactivate && b.InstanceID == in.InstanceID {
			return LiveVerification{}, ErrConflict
		}
	}
	if l.state.Schema < 2 {
		l.state.Schema = 2
	}
	l.state.Activations = append(l.state.Activations, activationRecord{in, sha, "preparing", "recorded", time.Now().UTC().Format(time.RFC3339Nano)})
	index := len(l.state.Activations) - 1
	stage := func(s string) error {
		l.state.Activations[index].Stage = s
		l.state.Activations[index].UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		return l.save()
	}
	if l.save() != nil {
		return LiveVerification{}, ErrUncertain
	}
	isolation := filepath.Join(e.Config.StateDirectory, "isolation.flows")
	isolated := false
	quarantine := func(c context.Context) error {
		if _, e2 := e.of(c, "--bundle", "replace-flows", e.Config.Bridge, isolation); e2 != nil {
			return e2
		}
		_, e2 := e.of(c, "diff-flows", isolation, e.Config.Bridge)
		return e2
	}
	fail := func() (LiveVerification, error) {
		state := "activation_unconfirmed"
		if isolated {
			c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if quarantine(c) != nil {
				state = "isolation_unconfirmed"
			}
			cancel()
		}
		l.state.Activations[index].State = "uncertain"
		_ = stage(state)
		return LiveVerification{}, ErrUncertain
	}
	if l.atomic("isolation.flows", []byte(strings.Join(isolationFlows(), "\n")+"\n")) != nil {
		return fail()
	}
	if e.ownedFlows(ctx) != nil {
		return fail()
	}
	// A command timeout is uncertain even if it may have installed drop. Mark the
	// safety domain before issuing it, so the failure path never releases a VM.
	isolated = true
	if quarantine(ctx) != nil {
		return fail()
	}
	if probeErr != nil {
		return fail()
	}
	if _, err = activationTopology(e.Config, in, before, revision, false); err != nil {
		return fail()
	}
	if stage("quarantined") != nil {
		return fail()
	}
	if callLifecycle(ctx, bootstrap) != nil || ctx.Err() != nil {
		return fail()
	}
	// libvirt 8.0.0 writes iface-id, attached-mac, vm-id, iface-status=active.
	// Only the just-created target may lack aster labels, never conflict with them.
	// https://raw.githubusercontent.com/libvirt/libvirt/v8.0.0/src/util/virnetdevopenvswitch.c
	bs, owned, err := e.probeActivation(ctx, empty, &in, !deactivate)
	if err != nil || !owned {
		return fail()
	}
	if deactivate {
		for _, b := range bs {
			if b.InstanceID == in.InstanceID {
				return fail()
			}
		}
	}
	t, err := activationTopology(e.Config, in, bs, revision, true)
	if err != nil {
		return fail()
	}
	var target PortIntent
	for _, p := range in.Ports {
		if p.InstanceID == in.InstanceID {
			target = p
		}
	}
	if !deactivate {
		if _, err = e.run(ctx, Vsctl, "--timeout=3", "set", "Interface", TAPName(target.InstanceID), "external_ids:aster-node-id="+e.Config.NodeID, "external_ids:aster-owner="+target.OwnerRef, "external_ids:aster-instance="+target.InstanceID, "external_ids:aster-vpc="+target.VPCID); err != nil {
			return fail()
		}
	}
	after, owned, err := e.probeActivation(ctx, empty, &in, false)
	if err != nil || !owned || !sameBindings(bs, after) {
		return fail()
	}
	if stage("bootstrapped") != nil {
		return fail()
	}
	plan, err := Compile(t)
	if err != nil {
		return fail()
	}
	if _, err = e.applyLocked(ctx, plan, l, true); err != nil {
		return fail()
	}
	if stage("programmed") != nil {
		return fail()
	}
	if _, err = e.verifyLocked(ctx, l); err != nil {
		return fail()
	}
	verified, owned, err := e.probeActivation(ctx, plan, &in, false)
	if err != nil || !owned || !sameBindings(after, verified) {
		return fail()
	}
	if !deactivate {
		if stage("releasing") != nil {
			return fail()
		}
		if callLifecycle(ctx, release) != nil || ctx.Err() != nil {
			return fail()
		}
	}
	live, err := e.verifyLocked(ctx, l)
	if err != nil {
		return fail()
	}
	verified, owned, err = e.probeActivation(ctx, plan, &in, false)
	if err != nil || !owned || !sameBindings(after, verified) {
		return fail()
	}
	l.state.Activations[index].State = "completed"
	if stage("completed") != nil {
		return fail()
	}
	return live, nil
}

// Check verifies an already-running target against current applied flows and
// exact immutable bindings. It never repairs/applies, calls callbacks or grants
// an activation. Unknown/missing/disabled targets return no proof.
func (e *Executor) Check(ctx context.Context, input ActivationIntent) (LiveVerification, error) {
	if e == nil || e.Runner == nil || e.tap == nil || e.euid == nil || e.euid() != 0 || !e.Config.Validate() {
		return LiveVerification{}, ErrInvalid
	}
	in, _, err := canonicalActivation(e.Config, input)
	if err != nil {
		return LiveVerification{}, err
	}
	for _, p := range in.Ports {
		if p.InstanceID == in.InstanceID && !p.Enabled {
			return LiveVerification{}, ErrInvalid
		}
	}
	l, err := openLedger(e.Config, false, nil)
	if err != nil {
		return LiveVerification{}, err
	}
	defer l.close()
	if err := l.legacyGuard(); err != nil {
		return LiveVerification{}, err
	}
	if l.activationPending() || len(l.state.Records) == 0 {
		return LiveVerification{}, ErrUncertain
	}
	last := l.state.Records[len(l.state.Records)-1]
	reader := *e
	reader.readOnly = true
	bs, owned, err := reader.probeActivation(ctx, Plan{Topology: last.Topology}, &in, false)
	if err != nil || !owned {
		return LiveVerification{}, ErrUncertain
	}
	t, err := activationTopology(e.Config, in, bs, last.Topology.Revision, true)
	if err != nil {
		return LiveVerification{}, err
	}
	p, err := Compile(t)
	if err != nil || p.Digest != last.Receipt.Digest {
		return LiveVerification{}, ErrUncertain
	}
	live, err := reader.verifyLocked(ctx, l)
	if err != nil {
		return LiveVerification{}, err
	}
	after, owned, err := reader.probeActivation(ctx, p, &in, false)
	if err != nil || !owned || !sameBindings(bs, after) {
		return LiveVerification{}, ErrUncertain
	}
	return live, nil
}

// A compiled callback panic is an unconfirmed lifecycle effect, not permission
// to skip the safety quarantine or expose a private panic value to callers.
func callLifecycle(ctx context.Context, fn func(context.Context) error) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrUncertain
		}
	}()
	return fn(ctx)
}

// Inspect is a root-only, read-only bridge prerequisite check. It intentionally
// needs no journal, creates no state, and supports the first empty-bridge boot.
// It is not applied-flow verification, connectivity, or VM start authorization.
func (e *Executor) Inspect(ctx context.Context) error {
	if e == nil || e.Runner == nil || e.tap == nil || e.euid == nil || e.euid() != 0 || !e.Config.Validate() || securePath(e.Config.StateDirectory) != nil {
		return ErrInvalid
	}
	// A first empty bridge needs no ledger; an existing initialization
	// tombstone or unresolved journal must not advertise fresh readiness.
	if _, statErr := os.Lstat(filepath.Join(e.Config.StateDirectory, "fabric.lock")); statErr == nil {
		l, openErr := openLedger(e.Config, false, nil)
		if openErr != nil {
			return ErrUnavailable
		}
		if err := l.legacyGuard(); err != nil {
			l.close()
			return err
		}
		pending := l.activationPending()
		for _, r := range l.state.Records {
			if r.Receipt.State != "applied" {
				pending = true
			}
		}
		l.close()
		if pending {
			return ErrUncertain
		}
	} else if !os.IsNotExist(statErr) {
		return ErrUnavailable
	}
	if err := legacyOverlayGuard(e.Config); err != nil {
		return err
	}
	reader := *e
	reader.readOnly = true
	reader.fault = nil
	_, owned, err := reader.probe(ctx, Plan{})
	if err != nil || !owned {
		return ErrUnavailable
	}
	return reader.ownedFlows(ctx)
}

package fabric

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const Vsctl = "/usr/bin/ovs-vsctl"
const Ofctl = "/usr/bin/ovs-ofctl"

type Runner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}
type OSRunner struct{}
type limitedOutput struct{ bytes.Buffer }

func (b *limitedOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 1<<20 {
		return 0, ErrUnavailable
	}
	return b.Buffer.Write(p)
}
func (OSRunner) Run(ctx context.Context, binary string, args ...string) ([]byte, error) {
	if binary != Vsctl && binary != Ofctl && binary != NATIP {
		return nil, ErrInvalid
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	// Do not let a caller-controlled cwd supply an ovs-ofctl relative socket
	// with the same basename as the approved bridge.
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "LANG=C", "LC_ALL=C"}
	cmd.WaitDelay = 2 * time.Second
	out := &limitedOutput{}
	cmd.Stdout = out
	cmd.Stderr = out
	err := cmd.Run()
	if err != nil {
		return nil, ErrUnavailable
	}
	return out.Bytes(), nil
}

type Executor struct {
	Config          Config
	Runner          Runner
	tap             func(string) error
	euid            func() int
	fault           func(string) error
	readOnly        bool
	overlayUnderlay func(OverlayConfig) error
}

func NewExecutor(c Config, r Runner) (*Executor, error) {
	if !c.Validate() || r == nil {
		return nil, ErrInvalid
	}
	return &Executor{Config: c, Runner: r, tap: tapInterface, euid: os.Geteuid, overlayUnderlay: verifyOverlayUnderlay}, nil
}
func (e *Executor) run(ctx context.Context, binary string, args ...string) ([]byte, error) {
	if e.readOnly && !readOnlyCommand(e.Config, binary, args) {
		return nil, ErrInvalid
	}
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	raw, err := e.Runner.Run(c, binary, args...)
	if err != nil || c.Err() != nil || len(raw) > 1<<20 {
		return nil, ErrUnavailable
	}
	return raw, nil
}

// OF1.3 match/meter semantics are transported over OF1.4: upstream OVS bundles
// REQUIRE OF1.4. Bundle commit acknowledgement replaces the per-mod barrier;
// there is no standalone ovs-ofctl "barrier bridge" command.
// https://www.openvswitch.org/support/dist-docs/ovs-ofctl.8.txt
func (e *Executor) of(ctx context.Context, args ...string) ([]byte, error) {
	prefix := []string{"-O", "OpenFlow14", "--no-names"}
	if e.readOnly {
		prefix = append(prefix, "--read-only")
	}
	return e.run(ctx, Ofctl, append(prefix, args...)...)
}

func (e *Executor) Apply(ctx context.Context, t Topology, confirm string) (Receipt, error) {
	if e == nil || e.Runner == nil || e.tap == nil || e.euid == nil {
		return Receipt{}, ErrInvalid
	}
	p, err := Compile(t)
	if err != nil || !e.Config.Validate() || e.Config.NodeID != t.NodeID || confirm != e.Config.Bridge || e.euid() != 0 {
		return Receipt{}, ErrInvalid
	}
	l, err := openLedger(e.Config, true, e.fault)
	if err != nil {
		return Receipt{}, err
	}
	defer l.close()
	if err := l.legacyGuard(); err != nil {
		return Receipt{}, err
	}
	if l.activationPending() {
		return Receipt{}, ErrUncertain
	}
	return e.applyLocked(ctx, p, l, false)
}

// applyLocked never acquires a second flock. Activation may permit ofport reuse
// only after it has independently confirmed whole-bridge drop isolation.
func (e *Executor) applyLocked(ctx context.Context, p Plan, l *ledger, isolated bool) (Receipt, error) {
	t := p.Topology
	var err error
	for _, r := range l.allRecords() {
		if r.Receipt.Revision == t.Revision {
			if r.Receipt.Digest != p.Digest {
				return Receipt{}, ErrConflict
			}
			if r.Receipt.State != "applied" {
				return interrupted(r.Receipt), ErrUncertain
			}
			return r.Receipt, nil
		}
	}
	var previous []binding
	for _, r := range l.state.Records {
		if r.Receipt.State != "applied" {
			return interrupted(r.Receipt), ErrUncertain
		}
		if r.Receipt.Revision >= t.Revision {
			return Receipt{}, ErrConflict
		}
		previous = []binding{}
		for _, b := range r.Bindings {
			for _, port := range r.Topology.Ports {
				if b.OFPort == port.OFPort {
					previous = append(previous, b)
					break
				}
			}
		}
	}
	if !isolated && l.compact() != nil {
		return Receipt{}, ErrUnavailable
	}
	r := record{Topology: p.Topology, Receipt: Receipt{Schema: 1, NodeID: t.NodeID, Revision: t.Revision, Digest: p.Digest, State: "intent", Stage: "recorded", UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano)}, Bindings: []binding{}}
	bindings, owned, probeErr := e.probe(ctx, p)
	r.Bindings = append([]binding{}, bindings...)
	l.state.Records = append(l.state.Records, r)
	index := len(l.state.Records) - 1
	if err = l.save(); err != nil {
		r.Receipt.State = "uncertain"
		r.Receipt.Stage = "intent_unconfirmed"
		return r.Receipt, ErrUncertain
	}
	dropPath := filepath.Join(e.Config.StateDirectory, "isolation.flows")
	flowsPath := filepath.Join(e.Config.StateDirectory, "desired.flows")
	isolate := func(c context.Context) error {
		_, err := e.of(c, "--bundle", "replace-flows", e.Config.Bridge, dropPath)
		return err
	}
	fail := func(stage string, quarantine bool) (Receipt, error) {
		if quarantine {
			c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if isolate(c) != nil {
				stage = "isolation_unconfirmed"
			}
			cancel()
		}
		r := &l.state.Records[index].Receipt
		r.State = "uncertain"
		r.Stage = stage
		r.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		_ = l.save()
		return *r, ErrUncertain
	}
	if l.atomic("isolation.flows", []byte(strings.Join(isolationFlows(), "\n")+"\n")) != nil || l.atomic("desired.flows", []byte(strings.Join(p.Flows, "\n")+"\n")) != nil {
		return fail("plan_storage_unconfirmed", false)
	}
	if probeErr != nil && !owned {
		return fail("probe_unconfirmed", false)
	}
	if e.ownedFlows(ctx) != nil {
		return fail("foreign_flows_rejected", false)
	}
	if isolate(ctx) != nil {
		return fail("isolation_unconfirmed", false)
	}
	if probeErr != nil || !matchesTopology(bindings, p) {
		return fail("port_identity_unconfirmed", false)
	}
	// Old authorised ofport now attached to a different stable identity must be
	// quarantined, not silently adopted. Removed (unused) old ports are safe.
	for _, old := range previous {
		for _, b := range bindings {
			if !isolated && old.OFPort == b.OFPort && (old.InterfaceID != b.InterfaceID || old.InstanceID != b.InstanceID || old.OwnerRef != b.OwnerRef || old.VPCID != b.VPCID) {
				return fail("port_identity_changed", false)
			}
		}
	}
	stable, _, err := e.probe(ctx, p)
	if err != nil || !sameBindings(bindings, stable) {
		return fail("port_mapping_changed", true)
	}
	allowedMeters := append([]Meter{}, p.Meters...)
	for _, r := range l.state.Records[:index] {
		old, _ := Compile(r.Topology)
		allowedMeters = append(allowedMeters, old.Meters...)
	}
	if l.state.Recovery != nil && l.state.Recovery.State != "completed" {
		for _, j := range l.history {
			for _, r := range j.Records {
				old, _ := Compile(r.Topology)
				allowedMeters = append(allowedMeters, old.Meters...)
			}
		}
	}
	if e.checkMeters(ctx, allowedMeters, false) != nil {
		return fail("foreign_meters_rejected", false)
	}
	if _, err = e.of(ctx, "del-meters", e.Config.Bridge); err != nil {
		return fail("meters_unconfirmed", false)
	}
	for _, m := range p.Meters {
		spec := "meter=" + strconv.Itoa(m.ID) + ",kbps,stats,bands=type=drop,rate=" + strconv.Itoa(m.Kbps)
		if _, err = e.of(ctx, "add-meter", e.Config.Bridge, spec); err != nil {
			return fail("meters_unconfirmed", false)
		}
	}
	if e.checkMeters(ctx, p.Meters, true) != nil {
		return fail("meter_readback_unconfirmed", false)
	}
	stable, _, err = e.probe(ctx, p)
	if err != nil || !sameBindings(bindings, stable) {
		return fail("port_mapping_changed", true)
	}
	if _, err = e.of(ctx, "--bundle", "replace-flows", e.Config.Bridge, flowsPath); err != nil {
		return fail("flows_unconfirmed", true)
	}
	// diff-flows queries the live switch after bundle acknowledgement. Exit 2
	// (different rules) is an error, not a successful apply receipt.
	if _, err = e.of(ctx, "diff-flows", flowsPath, e.Config.Bridge); err != nil {
		return fail("flow_readback_unconfirmed", true)
	}
	stable, _, err = e.probe(ctx, p)
	if err != nil || !sameBindings(bindings, stable) {
		return fail("port_mapping_changed", true)
	}
	l.state.Records[index].Receipt.State = "applied"
	l.state.Records[index].Receipt.Stage = "verified"
	l.state.Records[index].Receipt.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if l.save() != nil {
		return fail("receipt_storage_unconfirmed", true)
	}
	return l.state.Records[index].Receipt, nil
}

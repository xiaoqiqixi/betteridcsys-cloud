package fabric

import (
	"aster/cloud/internal/overlayproto"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"time"
)

const NATIP = "/usr/sbin/ip"
const NATNFT = "/usr/sbin/nft"
const NATSysctl = "/usr/sbin/sysctl"
const NATConntrack = "/usr/sbin/conntrack"

type namespaceRunner interface {
	RunNamespace(context.Context, NATProfile, string, ...string) ([]byte, error)
}

func natBinary(s string) bool {
	return s == NATIP || s == NATNFT || s == NATSysctl || s == NATConntrack
}
func (e *Executor) natRun(ctx context.Context, p NATProfile, binary string, args ...string) ([]byte, error) {
	r, ok := e.Runner.(namespaceRunner)
	if !ok || !natBinary(binary) {
		return nil, ErrUnavailable
	}
	if e.readOnly && !(binary == NATNFT && strings.Join(args, " ") == "-j -n list ruleset" || binary == NATSysctl && strings.Join(args, " ") == "-n net.ipv4.ip_forward" || binary == NATIP && len(args) > 0 && args[0] == "-j") {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := r.RunNamespace(ctx, p, binary, args...)
	if err != nil || ctx.Err() != nil || len(out) > 1<<20 {
		return nil, ErrUnavailable
	}
	return out, nil
}
func (e *Executor) natForwarding(ctx context.Context, p NATProfile, enabled bool, write bool) error {
	want := "0"
	if enabled {
		want = "1"
	}
	if write {
		if _, err := e.natRun(ctx, p, NATSysctl, "-w", "net.ipv4.ip_forward="+want); err != nil {
			return err
		}
	}
	raw, err := e.natRun(ctx, p, NATSysctl, "-n", "net.ipv4.ip_forward")
	if err != nil || strings.TrimSpace(string(raw)) != want {
		return ErrUncertain
	}
	return nil
}
func (e *Executor) natRules(ctx context.Context, p NATProfile) ([]byte, bool, error) {
	raw, err := e.natRun(ctx, p, NATNFT, "-j", "-n", "list", "ruleset")
	if err != nil {
		return nil, false, err
	}
	return normalizeNFT(raw)
}

// Every root-approved NAT gateway is isolated, including a removed policy. An
// omitted policy compiles a default-drop table, not a fall back to old NAT.
func (e *Executor) isolateNAT(ctx context.Context, c OverlayConfig) error {
	var failure error
	for _, p := range c.NATProfiles {
		if err := e.natForwarding(ctx, p, false, true); err != nil {
			failure = err
		}
	}
	return failure
}
func (e *Executor) prepareNAT(ctx context.Context, c OverlayConfig, l *ledger, s overlayproto.Snapshot, tasks ...overlayproto.Task) error {
	if l.checkNATInventory(c) != nil {
		return ErrConflict
	}
	for _, p := range c.NATProfiles {
		if e.probeNAT(ctx, c, s, p) != nil {
			return ErrUnavailable
		}
		_, exists, err := e.natRules(ctx, p)
		if err != nil {
			return err
		}
		// Never adopt a pre-existing table absent durable ownership.
		if e.natOwner(l, p, !exists) != nil {
			if len(tasks) != 1 || e.migrateNATOwner(ctx, c, l, p, tasks[0], exists) != nil {
				return ErrUnavailable
			}
		}
		if l.pinNATOwner(p) != nil {
			return ErrUncertain
		}
		if e.natForwarding(ctx, p, false, true) != nil {
			return ErrUncertain
		}
	}
	return nil
}
func (e *Executor) programNAT(ctx context.Context, c OverlayConfig, l *ledger, s overlayproto.Snapshot) error {
	for _, p := range c.NATProfiles {
		if e.probeNAT(ctx, c, s, p) != nil || e.natOwner(l, p, false) != nil || e.natForwarding(ctx, p, false, false) != nil {
			return ErrUncertain
		}
		_, exists, err := e.natRules(ctx, p)
		if err != nil {
			return err
		}
		objects, err := compileNAT(c, s, p, false)
		if err != nil {
			return err
		}
		name := "nat-desired-" + p.ID + ".json"
		if l.atomic(name, nftProgram(objects, exists)) != nil {
			return ErrUncertain
		}
		path := filepath.Join(l.cfg.StateDirectory, name)
		if _, err = e.natRun(ctx, p, NATNFT, "-j", "-c", "-f", path); err != nil {
			return err
		}
		if _, err = e.natRun(ctx, p, NATNFT, "-j", "-f", path); err != nil {
			return err
		}
		// Stateful NAT caches the first packet's mapping. Clear only this dedicated
		// namespace so a removed forwarding cannot survive the policy commit.
		if _, err = e.natRun(ctx, p, NATConntrack, "-F"); err != nil {
			return err
		}
		if e.verifyNATRules(ctx, c, s, p) != nil || e.natForwarding(ctx, p, false, false) != nil {
			return ErrUncertain
		}
	}
	return nil
}
func (e *Executor) verifyNATRules(ctx context.Context, c OverlayConfig, s overlayproto.Snapshot, p NATProfile) error {
	objects, err := compileNAT(c, s, p, false)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(nftObject{"nftables": objects})
	want, _, ne := normalizeNFT(raw)
	if ne != nil {
		return ne
	}
	actual, exists, err := e.natRules(ctx, p)
	if err != nil || !exists || string(actual) != string(want) {
		return ErrUncertain
	}
	return nil
}
func natPolicyActive(c OverlayConfig, s overlayproto.Snapshot, p NATProfile) bool {
	for _, f := range s.FloatingIPs {
		if f.NodeID == c.Base.NodeID && f.ProfileID == p.ID {
			return true
		}
	}
	for _, n := range s.NATPolicies {
		if n.NodeID == c.Base.NodeID && n.ProfileID == p.ID && (n.SNATEnabled || len(n.Forwardings) > 0) {
			return true
		}
	}
	return false
}
func (e *Executor) verifyNAT(ctx context.Context, c OverlayConfig, l *ledger, s overlayproto.Snapshot, enabled bool) error {
	if l.checkNATInventory(c) != nil {
		return ErrUnavailable
	}
	for _, p := range c.NATProfiles {
		if e.natOwner(l, p, false) != nil || e.probeNAT(ctx, c, s, p) != nil || e.verifyNATRules(ctx, c, s, p) != nil || e.natForwarding(ctx, p, enabled && natPolicyActive(c, s, p), false) != nil {
			return ErrUncertain
		}
	}
	return nil
}
func (e *Executor) releaseNAT(ctx context.Context, c OverlayConfig, l *ledger, s overlayproto.Snapshot) error {
	if e.verifyNAT(ctx, c, l, s, false) != nil {
		return ErrUncertain
	}
	for _, p := range c.NATProfiles {
		if e.natForwarding(ctx, p, natPolicyActive(c, s, p), true) != nil {
			return ErrUncertain
		}
	}
	return e.verifyNAT(ctx, c, l, s, true)
}

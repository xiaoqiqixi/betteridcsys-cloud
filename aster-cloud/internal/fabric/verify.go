package fabric

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const LiveProtocol = "aster.fabric.live/1"

// LiveVerification is only a current readback observation. It is not a durable
// apply receipt, signature, VM-start authorisation, or promise of future state.
// Failed verification returns no populated result. Private names/IPs/paths are
// not exposed; the exact live identity map is bound by a digest instead.
type LiveVerification struct {
	Protocol       string `json:"protocol"`
	NodeID         string `json:"node_id"`
	Revision       int64  `json:"revision"`
	Digest         string `json:"digest"`
	BindingsSHA256 string `json:"bindings_sha256"`
	State          string `json:"state"`
	ObservedAt     string `json:"observed_at"`
}

// readOnlyCommand is a second boundary: future changes to shared probe helpers
// cannot accidentally turn VerifyLive into an apply or quarantine operation.
func readOnlyCommand(c Config, binary string, args []string) bool {
	if overlayReadOnlyCommand(c, binary, args) {
		return true
	}
	if binary == Vsctl {
		if len(args) == 3 && args[0] == "--timeout=3" && (args[1] == "br-exists" || args[1] == "list-ifaces") {
			return args[2] == c.Bridge
		}
		if len(args) == 6 && args[0] == "--timeout=3" && args[1] == "--format=json" && args[2] == "--columns=name,controller,fail_mode,external_ids,protocols" && args[3] == "list" && args[4] == "Bridge" {
			return args[5] == c.Bridge
		}
		return len(args) == 5 && args[0] == "--timeout=3" && args[1] == "--format=json" && args[2] == "--columns=name,ofport,type,external_ids" && args[3] == "list" && args[4] == "Interface"
	}
	if binary != Ofctl {
		return false
	}
	if len(args) == 1 && args[0] == "--version" {
		return true
	}
	if len(args) < 6 || args[0] != "-O" || args[1] != "OpenFlow14" || args[2] != "--no-names" || args[3] != "--read-only" {
		return false
	}
	if len(args) == 6 && (args[4] == "dump-flows" || args[4] == "dump-meters") {
		return args[5] == c.Bridge
	}
	return len(args) == 7 && args[4] == "diff-flows" && args[5] == filepath.Join(c.StateDirectory, "desired.flows") && args[6] == c.Bridge
}

func (e *Executor) VerifyLive(ctx context.Context) (LiveVerification, error) {
	if e == nil || e.Runner == nil || e.tap == nil || e.euid == nil || e.euid() != 0 || !e.Config.Validate() {
		return LiveVerification{}, ErrInvalid
	}
	// Shared read lock: no mkdir, new lock file, intent, receipt, or cleanup.
	l, err := openLedger(e.Config, false, nil)
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
	return e.verifyLocked(ctx, l)
}

func (e *Executor) verifyLocked(ctx context.Context, l *ledger) (LiveVerification, error) {
	if len(l.state.Records) == 0 {
		return LiveVerification{}, ErrUncertain
	}
	for _, r := range l.state.Records {
		if r.Receipt.State != "applied" {
			return LiveVerification{}, ErrUncertain
		}
	}
	last := l.state.Records[len(l.state.Records)-1]
	p, err := Compile(last.Topology)
	if err != nil || last.Receipt.NodeID != e.Config.NodeID || last.Receipt.Digest != p.Digest || last.Receipt.Revision != p.Topology.Revision {
		return LiveVerification{}, ErrUncertain
	}
	// Never regenerate a missing/changed desired file on a read. Both the file
	// inode and its exact contents must agree with the current journal topology.
	path := filepath.Join(e.Config.StateDirectory, "desired.flows")
	wanted := []byte(strings.Join(p.Flows, "\n") + "\n")
	content, err := readPrivate(path, uint32(os.Geteuid()), 8<<20)
	if err != nil || !bytes.Equal(content, wanted) {
		return LiveVerification{}, ErrUncertain
	}
	reader := *e
	reader.readOnly = true
	reader.fault = nil
	before, owned, err := reader.probe(ctx, p)
	if err != nil || !owned || !sameBindings(last.Bindings, before) || !matchesTopology(before, p) {
		return LiveVerification{}, ErrUncertain
	}
	if reader.ownedFlows(ctx) != nil {
		return LiveVerification{}, ErrUncertain
	}
	if _, err = reader.of(ctx, "diff-flows", path, e.Config.Bridge); err != nil {
		return LiveVerification{}, ErrUncertain
	}
	if reader.checkMeters(ctx, p.Meters, true) != nil {
		return LiveVerification{}, ErrUncertain
	}
	after, owned, err := reader.probe(ctx, p)
	if err != nil || !owned || !sameBindings(before, after) || !sameBindings(last.Bindings, after) || !matchesTopology(after, p) {
		return LiveVerification{}, ErrUncertain
	}
	// Root-private directories eliminate unprivileged replacement. Rechecking
	// the file also refuses any observed root-side concurrent edit during readback.
	content, err = readPrivate(path, uint32(os.Geteuid()), 8<<20)
	if err != nil || !bytes.Equal(content, wanted) {
		return LiveVerification{}, ErrUncertain
	}
	if _, err = reader.of(ctx, "diff-flows", path, e.Config.Bridge); err != nil {
		return LiveVerification{}, ErrUncertain
	}
	if reader.checkMeters(ctx, p.Meters, true) != nil {
		return LiveVerification{}, ErrUncertain
	}
	final, owned, err := reader.probe(ctx, p)
	if err != nil || !owned || !sameBindings(after, final) || !sameBindings(last.Bindings, final) || !matchesTopology(final, p) || ctx.Err() != nil {
		return LiveVerification{}, ErrUncertain
	}
	raw, _ := json.Marshal(final)
	h := sha256.Sum256(raw)
	return LiveVerification{Protocol: LiveProtocol, NodeID: e.Config.NodeID, Revision: last.Receipt.Revision, Digest: p.Digest, BindingsSHA256: hex.EncodeToString(h[:]), State: "verified", ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}, nil
}

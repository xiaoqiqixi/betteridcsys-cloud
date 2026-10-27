package fabric

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"time"
)

// RecoveryExpectation pins the exact current journal as well as its most recent
// operation and topology. Zero revision/digest is valid only before a first plan.
// The old operation remains historically uncertain; recovery is a NEW operation.
type RecoveryExpectation struct {
	ExpectedJournalSHA256 string `json:"expected_journal_sha256"`
	ExpectedOperationID   string `json:"expected_operation_id"`
	ExpectedIntentSHA256  string `json:"expected_intent_sha256"`
	ExpectedRevision      int64  `json:"expected_revision"`
	ExpectedDigest        string `json:"expected_digest"`
}
type RecoveryIntent struct {
	OperationID   string `json:"operation_id"`
	RequestSHA256 string `json:"request_sha256"`
	RecoveryExpectation
	Intent ActivationIntent `json:"intent"`
}
type recoveryRecord struct {
	Intent    RecoveryIntent `json:"intent"`
	State     string         `json:"state"`
	Stage     string         `json:"stage"`
	UpdatedAt string         `json:"updated_at"`
}

func (l *ledger) recoveryExpectation() RecoveryExpectation {
	_, sha := journalBytes(l.state)
	out := RecoveryExpectation{ExpectedJournalSHA256: sha}
	if len(l.state.Activations) > 0 {
		a := l.state.Activations[len(l.state.Activations)-1]
		out.ExpectedOperationID = a.Intent.OperationID
		out.ExpectedIntentSHA256 = a.IntentSHA256
	} else if l.state.Recovery != nil {
		out.ExpectedOperationID = l.state.Recovery.Intent.OperationID
		_, out.ExpectedIntentSHA256 = journalBytes(journal{Recovery: l.state.Recovery})
	}
	if len(l.state.Records) > 0 {
		r := l.state.Records[len(l.state.Records)-1]
		out.ExpectedRevision = r.Receipt.Revision
		out.ExpectedDigest = r.Receipt.Digest
	}
	return out
}

// RecoveryStatus is strictly read-only and gives no permission to start guests.
func RecoveryStatus(c Config) (RecoveryExpectation, error) {
	l, err := openLedger(c, false, nil)
	if err != nil {
		return RecoveryExpectation{}, err
	}
	defer l.close()
	return l.recoveryExpectation(), nil
}
func validateRecovery(j journal) error {
	if j.Schema != 3 {
		if j.Recovery != nil || j.ArchiveHead != "" {
			return ErrUnavailable
		}
		return nil
	}
	if !validSHA(j.ArchiveHead) {
		return ErrUnavailable
	}
	if j.Recovery == nil {
		return nil
	}
	r := j.Recovery
	at, err := time.Parse(time.RFC3339Nano, r.UpdatedAt)
	if err != nil || at.Year() < 1 || !strings.HasSuffix(r.UpdatedAt, "Z") || !idRE.MatchString(r.Intent.OperationID) || !validSHA(r.Intent.RequestSHA256) || r.Intent.Intent.OperationID != r.Intent.OperationID || r.Intent.Intent.RequestSHA256 != r.Intent.RequestSHA256 || r.Intent.ExpectedJournalSHA256 != j.ArchiveHead {
		return ErrUnavailable
	}
	if r.Intent.ExpectedOperationID != "" && (!idRE.MatchString(r.Intent.ExpectedOperationID) || !validSHA(r.Intent.ExpectedIntentSHA256)) {
		return ErrUnavailable
	}
	if r.Intent.ExpectedOperationID == "" && r.Intent.ExpectedIntentSHA256 != "" {
		return ErrUnavailable
	}
	if r.Intent.ExpectedRevision < 0 || r.Intent.ExpectedRevision == 0 && r.Intent.ExpectedDigest != "" || r.Intent.ExpectedRevision > 0 && !validSHA(r.Intent.ExpectedDigest) {
		return ErrUnavailable
	}
	switch r.State {
	case "preparing":
		if r.Stage != "recorded" && r.Stage != "quarantined" && r.Stage != "fenced" && r.Stage != "programmed" && r.Stage != "releasing" {
			return ErrUnavailable
		}
	case "uncertain":
		if r.Stage != "recovery_unconfirmed" && r.Stage != "isolation_unconfirmed" {
			return ErrUnavailable
		}
	case "completed":
		if r.Stage != "completed" || len(j.Records) == 0 || j.Records[len(j.Records)-1].Receipt.State != "applied" {
			return ErrUnavailable
		}
	default:
		return ErrUnavailable
	}
	return nil
}
func decodeRecovery(raw []byte, c Config) error {
	var r recoveryRecord
	if object(raw, []string{"intent", "state", "stage", "updated_at"}, &r) != nil {
		return ErrUnavailable
	}
	var root map[string]json.RawMessage
	_ = json.Unmarshal(raw, &root)
	keys := []string{"operation_id", "request_sha256", "expected_journal_sha256", "expected_operation_id", "expected_intent_sha256", "expected_revision", "expected_digest", "intent"}
	if object(root["intent"], keys, &r.Intent) != nil {
		return ErrUnavailable
	}
	_, _, err := canonicalActivation(c, r.Intent.Intent)
	if err != nil {
		return ErrUnavailable
	}
	// Reuse the nested activation strict decoder, including duplicate/null checks.
	var intentFields map[string]json.RawMessage
	_ = json.Unmarshal(root["intent"], &intentFields)
	synthetic := append([]byte(`{"intent":`), intentFields["intent"]...)
	synthetic = append(synthetic, []byte(`,"intent_sha256":"","state":"","stage":"","updated_at":""}`)...)
	return decodeActivationRecord(synthetic)
}

// Recover rebuilds ALL same-bridge ports under the existing exclusive flock.
// fence must independently verify/stop NIC transmission and pause every owned
// active guest; release may resume only those authorized by the complete Intent.
// Neither callback may replay the original create/start/stop/delete operation.
// This does not adopt foreign bridges/ports, repair persistent XML, or recreate
// missing VMs. No success is returned on a lost ack, callback panic or fsync error.
func (e *Executor) Recover(ctx context.Context, input RecoveryIntent, fence, release func(context.Context) error) (LiveVerification, error) {
	if e == nil || e.Runner == nil || e.tap == nil || e.euid == nil || e.euid() != 0 || !e.Config.Validate() || fence == nil || release == nil || ctx.Err() != nil {
		return LiveVerification{}, ErrInvalid
	}
	in, _, err := canonicalActivation(e.Config, input.Intent)
	if err != nil || input.OperationID != in.OperationID || input.RequestSHA256 != in.RequestSHA256 || !validSHA(input.ExpectedJournalSHA256) {
		return LiveVerification{}, ErrInvalid
	}
	input.Intent = in
	l, err := openLedger(e.Config, true, e.fault)
	if err != nil {
		return LiveVerification{}, err
	}
	defer l.close()
	if err := l.legacyGuard(); err != nil {
		return LiveVerification{}, err
	}
	if l.operationSeen(input.OperationID) || input.RecoveryExpectation != l.recoveryExpectation() {
		return LiveVerification{}, ErrConflict
	}
	revision := l.lastRevision() + 1
	if revision < 1 {
		return LiveVerification{}, ErrUnavailable
	}
	// Verify the trusted bridge boundary before authorizing a whole-bridge drop.
	empty := Plan{Topology: Topology{Schema: 1, NodeID: e.Config.NodeID, Revision: revision, VPCs: []VPC{}, Ports: []Port{}}}
	_, owned, initialProbeErr := e.probeActivation(ctx, empty, &in, true)
	if !owned || e.ownedFlows(ctx) != nil {
		return LiveVerification{}, ErrUncertain
	}
	old := l.state
	head, err := l.archive(old)
	if err != nil {
		return LiveVerification{}, ErrUnavailable
	}
	l.state = journal{Schema: 3, NodeID: e.Config.NodeID, Bridge: e.Config.Bridge, ArchiveHead: head, Records: []record{}, Activations: []activationRecord{}, Recovery: &recoveryRecord{Intent: input, State: "preparing", Stage: "recorded", UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano)}}
	if l.save() != nil {
		return LiveVerification{}, ErrUncertain
	}
	l.history = append([]journal{old}, l.history...)
	stage := func(s string) error {
		l.state.Recovery.Stage = s
		l.state.Recovery.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		return l.save()
	}
	isolation := filepath.Join(e.Config.StateDirectory, "isolation.flows")
	quarantine := func(c context.Context) error {
		if _, err := e.of(c, "--bundle", "replace-flows", e.Config.Bridge, isolation); err != nil {
			return err
		}
		_, err := e.of(c, "diff-flows", isolation, e.Config.Bridge)
		return err
	}
	isolated := false
	fail := func() (LiveVerification, error) {
		s := "recovery_unconfirmed"
		if isolated {
			c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if quarantine(c) != nil {
				s = "isolation_unconfirmed"
			}
			cancel()
		}
		l.state.Recovery.State = "uncertain"
		_ = stage(s)
		return LiveVerification{}, ErrUncertain
	}
	if l.atomic("isolation.flows", []byte(strings.Join(isolationFlows(), "\n")+"\n")) != nil {
		return fail()
	}
	isolated = true
	if quarantine(ctx) != nil || stage("quarantined") != nil || initialProbeErr != nil {
		return fail()
	}
	if callLifecycle(ctx, fence) != nil || ctx.Err() != nil {
		return fail()
	}
	bs, owned, err := e.probeActivation(ctx, empty, &in, true)
	if err != nil || !owned {
		return fail()
	}
	t, err := activationTopology(e.Config, in, bs, revision, true)
	if err != nil {
		return fail()
	}
	// Only the original target can have the exact libvirt identity but no Aster
	// labels after a crash in bootstrap. Never overwrite a conflicting label.
	for _, b := range bs {
		if b.InstanceID == in.InstanceID {
			for _, p := range in.Ports {
				if p.InstanceID == b.InstanceID {
					if _, err = e.run(ctx, Vsctl, "--timeout=3", "set", "Interface", TAPName(p.InstanceID), "external_ids:aster-node-id="+e.Config.NodeID, "external_ids:aster-owner="+p.OwnerRef, "external_ids:aster-instance="+p.InstanceID, "external_ids:aster-vpc="+p.VPCID); err != nil {
						return fail()
					}
				}
			}
		}
	}
	after, owned, err := e.probeActivation(ctx, empty, &in, false)
	if err != nil || !owned || !sameBindings(bs, after) || stage("fenced") != nil {
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
	if stage("releasing") != nil || callLifecycle(ctx, release) != nil || ctx.Err() != nil {
		return fail()
	}
	live, err := e.verifyLocked(ctx, l)
	if err != nil {
		return fail()
	}
	final, owned, err := e.probeActivation(ctx, plan, &in, false)
	if err != nil || !owned || !sameBindings(after, final) {
		return fail()
	}
	l.state.Recovery.State = "completed"
	if stage("completed") != nil {
		return fail()
	}
	return live, nil
}

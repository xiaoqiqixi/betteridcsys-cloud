package hypervisor

import (
	"aster/cloud/internal/fabric"
	"aster/cloud/internal/nodeproto"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeRecoveryGate struct {
	*fakeOVSGate
	callsRecovery int
	recovery      fabric.RecoveryIntent
	failRecovery  string
}

func (g *fakeRecoveryGate) Recover(ctx context.Context, r fabric.RecoveryIntent, fence, release func(context.Context) error) (fabric.LiveVerification, error) {
	g.callsRecovery++
	g.recovery = r
	if e := fence(ctx); e != nil {
		return fabric.LiveVerification{}, e
	}
	if g.failRecovery == "program" {
		return fabric.LiveVerification{}, errors.New("readback failed")
	}
	if e := release(ctx); e != nil {
		return fabric.LiveVerification{}, e
	}
	if g.failRecovery == "ack" {
		return fabric.LiveVerification{}, errors.New("lost ack")
	}
	return fabric.LiveVerification{}, nil
}
func recoveryFixture(t *testing.T, oldSuccess bool) (*Manager, *ovsRunner, *fakeRecoveryGate, nodeproto.NodeTask, NetworkRecoveryRequest) {
	t.Helper()
	m, r, g, task := newOVSFixture(t)
	if !oldSuccess {
		g.fail = "lost-final-ack"
	}
	old := submit(t, m, task)
	if oldSuccess && old.Status != "succeeded" || !oldSuccess && old.Status != "uncertain" {
		t.Fatal(old)
	}
	gate := &fakeRecoveryGate{fakeOVSGate: g}
	m.ovsFactory = func(fabric.Config) (ovsGate, error) { return gate, nil }
	request := NetworkRecoveryRequest{Protocol: NetworkRecoveryProtocol, OperationID: strings.Repeat("d", 32), OriginalOperationID: task.OperationID, ProfileID: task.Network.ProfileID, Expected: fabric.RecoveryExpectation{ExpectedJournalSHA256: strings.Repeat("a", 64), ExpectedOperationID: task.OperationID, ExpectedIntentSHA256: strings.Repeat("b", 64), ExpectedRevision: 1, ExpectedDigest: strings.Repeat("c", 64)}, EnabledInstances: []string{task.InstanceID}}
	return m, r, gate, task, request
}
func TestNetworkRecoveryAfterUncertainDoesNotRepeatCreate(t *testing.T) {
	m, r, g, task, req := recoveryFixture(t, false)
	starts := r.count(" start ")
	out, e := m.RecoverNetwork(context.Background(), req)
	if e != nil || out.OriginalOperation.Status != "succeeded" || g.callsRecovery != 1 {
		t.Fatal(out, e)
	}
	if r.count(" start ") != starts || r.count(" define ") != 1 {
		t.Fatal("original creation repeated")
	}
	if m.Ledger.HasPendingInstance(task.InstanceID, "") {
		t.Fatal("recovery did not resolve original outcome")
	}
	i, _ := m.Ledger.Instance(task.InstanceID)
	if i.Network != task.Network || i.State != "running" || r.states[i.Domain] != "running" {
		t.Fatal("immutable binding changed or not resumed")
	}
	n := len(r.commands)
	replay, e := m.RecoverNetwork(context.Background(), req)
	if e != nil || replay != out || len(r.commands) != n || g.callsRecovery != 1 {
		t.Fatal("recovery replay repeated writes", e)
	}
	evidence, e := os.ReadFile(filepath.Join(m.Ledger.directory, "network-recovery-"+req.OperationID+".intent.json"))
	var old networkRecoveryEvidence
	if e != nil || json.Unmarshal(evidence, &old) != nil || old.Original.Result.Status != "uncertain" || old.Original.Task != task {
		t.Fatal("original uncertainty evidence discarded", e)
	}
}
func TestNetworkRecoveryRepairsLostOVSWithPreviouslySuccessfulNodeTask(t *testing.T) {
	m, r, _, task, req := recoveryFixture(t, true)
	before, _ := m.Ledger.Query(task.OperationID)
	if _, e := m.RecoverNetwork(context.Background(), req); e != nil {
		t.Fatal(e)
	}
	after, _ := m.Ledger.Query(task.OperationID)
	a, _ := json.Marshal(before)
	b, _ := json.Marshal(after)
	if string(a) != string(b) {
		t.Fatal("already completed operation rewritten")
	}
	i, _ := m.Ledger.Instance(task.InstanceID)
	if r.states[i.Domain] != "running" {
		t.Fatal("not recovered")
	}
	if _, e := m.RecoverNetwork(context.Background(), req); e != nil {
		t.Fatal("historical recovery query failed", e)
	}
}
func TestNetworkRecoveryFailureAndEvidenceFailureNeverCompleteOldOperation(t *testing.T) {
	for _, stage := range []string{"program", "ack", "evidence"} {
		t.Run(stage, func(t *testing.T) {
			m, r, g, task, req := recoveryFixture(t, false)
			if stage == "evidence" {
				if e := os.Mkdir(filepath.Join(m.Ledger.directory, "network-recovery-"+req.OperationID+".result.json"), 0700); e != nil {
					t.Fatal(e)
				}
			} else {
				g.failRecovery = stage
			}
			if _, e := m.RecoverNetwork(context.Background(), req); e == nil {
				t.Fatal("unknown succeeded")
			}
			op, _ := m.Ledger.Query(task.OperationID)
			i, _ := m.Ledger.Instance(task.InstanceID)
			if op.Result.Status != "uncertain" || r.states[i.Domain] != "paused" || r.links[i.Domain] != "down" {
				t.Fatal("failed recovery left success/running guest", op.Result)
			}
			calls := g.callsRecovery
			if _, e := m.RecoverNetwork(context.Background(), req); e == nil || g.callsRecovery != calls {
				t.Fatal("interrupted recovery repeated")
			}
		})
	}
}
func TestNetworkRecoveryRejectsChangedIdentityApprovalAndConflictingReplay(t *testing.T) {
	for _, kind := range []string{"profile", "operation", "enabled", "duplicate", "hostname"} {
		t.Run(kind, func(t *testing.T) {
			m, _, g, task, req := recoveryFixture(t, false)
			switch kind {
			case "profile":
				req.ProfileID = "other"
			case "operation":
				req.OriginalOperationID = strings.Repeat("e", 32)
			case "enabled":
				req.EnabledInstances = []string{}
			case "duplicate":
				req.EnabledInstances = append(req.EnabledInstances, task.InstanceID)
			case "hostname":
				m.Ledger.mu.Lock()
				i := m.Ledger.state.Instances[task.InstanceID]
				i.Hostname = "changed"
				m.Ledger.state.Instances[task.InstanceID] = i
				m.Ledger.mu.Unlock()
			}
			if _, e := m.RecoverNetwork(context.Background(), req); e == nil || g.callsRecovery != 0 {
				t.Fatal("bad recovery passed", e)
			}
		})
	}
	m, _, g, _, req := recoveryFixture(t, false)
	if _, e := m.RecoverNetwork(context.Background(), req); e != nil {
		t.Fatal(e)
	}
	req.Expected.ExpectedJournalSHA256 = strings.Repeat("e", 64)
	if _, e := m.RecoverNetwork(context.Background(), req); !errors.Is(e, ErrConflict) || g.callsRecovery != 1 {
		t.Fatal("conflicting recovery accepted", e)
	}
}
func TestNetworkRecoveryApprovalDecoderRejectsAmbiguity(t *testing.T) {
	_, _, _, _, req := recoveryFixture(t, false)
	raw, _ := json.Marshal(req)
	if _, e := DecodeNetworkRecovery(raw); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{string(raw) + "{}", strings.Replace(string(raw), `"operation_id":`, `"operation_id":"`+req.OperationID+`","operation_id":`, 1), strings.Replace(string(raw), `"profile_id"`, `"Profile_ID"`, 1), strings.Replace(string(raw), `"enabled_instances":["`+req.EnabledInstances[0]+`"]`, `"enabled_instances":null`, 1)} {
		if _, e := DecodeNetworkRecovery([]byte(bad)); e == nil {
			t.Fatal("ambiguous approval accepted")
		}
	}
}

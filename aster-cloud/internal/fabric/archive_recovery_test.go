package fabric

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestJournalArchivesMoreThan64ChangesAndKeepsExactOldReplay(t *testing.T) {
	e, f, top := fixtureExecutor(t)
	var first Receipt
	for n := int64(1); n <= 130; n++ {
		top.Revision = n
		got, err := e.Apply(context.Background(), top, e.Config.Bridge)
		if err != nil {
			t.Fatalf("change %d: %v", n, err)
		}
		if n == 1 {
			first = got
		}
	}
	l, err := openLedger(e.Config, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if l.state.Schema != 3 || len(l.state.Records) > journalPageSize || len(l.history) < 4 {
		t.Fatal("not bounded and archived", len(l.state.Records), len(l.history))
	}
	l.close()
	top.Revision = 1
	before := len(f.calls)
	got, err := e.Apply(context.Background(), top, e.Config.Bridge)
	if err != nil || got != first || len(f.calls) != before {
		t.Fatal("old replay not exact/read-only", got, err)
	}
	top.Ports[0].InboundMbps++
	if _, err = e.Apply(context.Background(), top, e.Config.Bridge); !errors.Is(err, ErrConflict) || len(f.calls) != before {
		t.Fatal("old conflict lost", err)
	}
	got, err = Status(e.Config, 1)
	if err != nil || got != first {
		t.Fatal(got, err)
	}
	if _, err = e.VerifyLive(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func TestActivationArchivesMoreThan64ChangesAndRejectsOldActivation(t *testing.T) {
	e, f, in, boot := activationFixture(t)
	first := in
	for n := 0; n < 66; n++ {
		in.OperationID = fmt.Sprintf("%032x", n*2+1)
		in.Ports[0].Enabled = true
		if n == 0 {
			first = in
			first.Ports = append([]PortIntent{}, in.Ports...)
		}
		if _, err := e.Activate(context.Background(), in, boot, func(context.Context) error { return nil }); err != nil {
			t.Fatalf("start %d: %v", n, err)
		}
		in.OperationID = fmt.Sprintf("%032x", n*2+2)
		in.Ports[0].Enabled = false
		if _, err := e.Deactivate(context.Background(), in, func(context.Context) error { f.topology.Ports = []Port{}; return nil }); err != nil {
			t.Fatalf("stop %d: %v", n, err)
		}
	}
	before := len(f.calls)
	if _, err := e.Activate(context.Background(), first, boot, func(context.Context) error { return nil }); !errors.Is(err, ErrConflict) || len(f.calls) != before {
		t.Fatal("historical activation replayed", err)
	}
}
func TestArchiveCorruptionMissingAndCheckpointFaultsFailClosed(t *testing.T) {
	for _, mode := range []string{"missing", "changed", "hardlink", "world_readable"} {
		t.Run(mode, func(t *testing.T) {
			e, _, top := fixtureExecutor(t)
			for n := int64(1); n <= 33; n++ {
				top.Revision = n
				if _, err := e.Apply(context.Background(), top, e.Config.Bridge); err != nil {
					t.Fatal(err)
				}
			}
			l, err := openLedger(e.Config, false, nil)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(e.Config.StateDirectory, "history-"+l.state.ArchiveHead+".json")
			l.close()
			switch mode {
			case "missing":
				_ = os.Remove(path)
			case "changed":
				_ = os.WriteFile(path, []byte("{}"), 0600)
			case "hardlink":
				_ = os.Link(path, path+".link")
			case "world_readable":
				_ = os.Chmod(path, 0644)
			}
			if _, err = Status(e.Config, 1); err == nil {
				t.Fatal("damaged history accepted")
			}
			top.Revision = 34
			if _, err = e.Apply(context.Background(), top, e.Config.Bridge); err == nil {
				t.Fatal("lost history allowed mutation")
			}
		})
	}
	for _, point := range []string{"before_write", "before_sync", "before_rename", "after_rename", "after_dir_sync"} {
		t.Run(point, func(t *testing.T) {
			e, f, top := fixtureExecutor(t)
			for n := int64(1); n <= 32; n++ {
				top.Revision = n
				if _, err := e.Apply(context.Background(), top, e.Config.Bridge); err != nil {
					t.Fatal(err)
				}
			}
			once := false
			e.fault = func(at string) error {
				if !once && strings.HasPrefix(at, "history-") && strings.HasSuffix(at, ":"+point) {
					once = true
					return errors.New("disk fault")
				}
				return nil
			}
			before := len(f.calls)
			top.Revision = 33
			if _, err := e.Apply(context.Background(), top, e.Config.Bridge); err == nil || len(f.calls) != before {
				t.Fatal("archive fault performed mutation", err)
			}
			e.fault = nil
			if _, err := e.Apply(context.Background(), top, e.Config.Bridge); err != nil {
				t.Fatal("orphan archive cannot safely reuse", err)
			}
			if _, err := Status(e.Config, 1); err != nil {
				t.Fatal("history lost", err)
			}
		})
	}
}
func recoveryFixture(t *testing.T) (*Executor, *fakeOVS, ActivationIntent, RecoveryIntent) {
	t.Helper()
	e, f, in, boot := activationFixture(t)
	if _, err := e.Activate(context.Background(), in, boot, func(context.Context) error { return ErrUnavailable }); !errors.Is(err, ErrUncertain) {
		t.Fatal(err)
	}
	expected, err := RecoveryStatus(e.Config)
	if err != nil {
		t.Fatal(err)
	}
	next := in
	next.OperationID = strings.Repeat("c", 32)
	next.RequestSHA256 = strings.Repeat("d", 64)
	return e, f, in, RecoveryIntent{OperationID: next.OperationID, RequestSHA256: next.RequestSHA256, RecoveryExpectation: expected, Intent: next}
}
func TestRecoveryNewOperationPreservesOldUncertaintyAndRebuildsCurrentOFPorts(t *testing.T) {
	e, f, old, in := recoveryFixture(t)
	prior, err := Status(e.Config, 1)
	if !errors.Is(err, ErrUncertain) || prior != (Receipt{}) {
		t.Fatal(prior, err)
	}
	f.topology.Ports[0].OFPort = 17
	fenced, released := 0, 0
	live, err := e.Recover(context.Background(), in, func(context.Context) error { fenced++; assertDrop(t, f); return nil }, func(context.Context) error {
		released++
		if !strings.Contains(f.flows, "in_port=17") {
			t.Fatal("stale ofport")
		}
		return nil
	})
	if err != nil || live.Revision != 2 || fenced != 1 || released != 1 {
		t.Fatal(live, err, fenced, released)
	}
	l, err := openLedger(e.Config, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if l.activationPending() || l.state.Recovery.State != "completed" || len(l.history) != 1 || l.history[0].Activations[0].State != "uncertain" {
		t.Fatal("old outcome rewritten", l.state)
	}
	l.close()
	before := len(f.calls)
	if _, err = e.Recover(context.Background(), in, func(context.Context) error { t.Fatal("re-fence"); return nil }, func(context.Context) error { t.Fatal("re-release"); return nil }); !errors.Is(err, ErrConflict) || len(f.calls) != before {
		t.Fatal("replayed recovery", err)
	}
	if _, err = e.Check(context.Background(), old); err != nil {
		t.Fatal("recovered network unusable", err)
	}
}
func TestRecoveryRejectsChangedExpectationsBeforeEffects(t *testing.T) {
	for _, field := range []string{"journal", "operation", "intent", "revision", "digest", "id_reuse"} {
		t.Run(field, func(t *testing.T) {
			e, f, old, in := recoveryFixture(t)
			switch field {
			case "journal":
				in.ExpectedJournalSHA256 = strings.Repeat("0", 64)
			case "operation":
				in.ExpectedOperationID = strings.Repeat("0", 32)
			case "intent":
				in.ExpectedIntentSHA256 = strings.Repeat("0", 64)
			case "revision":
				in.ExpectedRevision++
			case "digest":
				in.ExpectedDigest = strings.Repeat("0", 64)
			case "id_reuse":
				in.OperationID = old.OperationID
				in.Intent.OperationID = old.OperationID
			}
			before := len(f.calls)
			files := snapshotFiles(t, e.Config.StateDirectory)
			if _, err := e.Recover(context.Background(), in, func(context.Context) error { t.Fatal("fence"); return nil }, func(context.Context) error { t.Fatal("release"); return nil }); !errors.Is(err, ErrConflict) || len(f.calls) != before || !reflect.DeepEqual(files, snapshotFiles(t, e.Config.StateDirectory)) {
				t.Fatal("stale expectation had effect", err)
			}
		})
	}
}
func TestRecoveryFailureNeverReleasesOrUnblocksAndAllowsNewExplicitRecovery(t *testing.T) {
	for _, fail := range []string{"fence", "panic", "release", "journal_final"} {
		t.Run(fail, func(t *testing.T) {
			e, f, _, in := recoveryFixture(t)
			released := 0
			if fail == "journal_final" {
				e.fault = func(at string) error {
					if at == "journal.json:before_write" {
						raw, _ := os.ReadFile(filepath.Join(e.Config.StateDirectory, "journal.json"))
						var j journal
						_ = json.Unmarshal(raw, &j)
						if j.Recovery != nil && j.Recovery.Stage == "releasing" {
							return ErrUnavailable
						}
					}
					return nil
				}
			}
			_, err := e.Recover(context.Background(), in, func(context.Context) error {
				if fail == "panic" {
					panic("private")
				}
				if fail == "fence" {
					return ErrUnavailable
				}
				return nil
			}, func(context.Context) error {
				released++
				if fail == "release" {
					return ErrUnavailable
				}
				return nil
			})
			if !errors.Is(err, ErrUncertain) {
				t.Fatal(err)
			}
			assertDrop(t, f)
			if (fail == "fence" || fail == "panic") && released != 0 {
				t.Fatal("released failed fence")
			}
			if _, err = e.Check(context.Background(), in.Intent); err == nil {
				t.Fatal("failed recovery unblocked")
			}
			e.fault = nil
			expected, err := RecoveryStatus(e.Config)
			if err != nil {
				t.Fatal(err)
			}
			in.RecoveryExpectation = expected
			in.OperationID = strings.Repeat("e", 32)
			in.Intent.OperationID = in.OperationID
			if _, err = e.Recover(context.Background(), in, func(context.Context) error { return nil }, func(context.Context) error { return nil }); err != nil {
				t.Fatal("explicit next recovery blocked", err)
			}
		})
	}
}

func TestRecoveryEveryCommandFailureReturnsNoProofAndDoesNotReplayCallbacks(t *testing.T) {
	e, f, _, in := recoveryFixture(t)
	begin := len(f.calls)
	if _, err := e.Recover(context.Background(), in, func(context.Context) error { return nil }, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	count := len(f.calls) - begin
	for n := 1; n <= count; n++ {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			e, f, _, in := recoveryFixture(t)
			f.failAt = len(f.calls) + n
			fences, releases := 0, 0
			got, err := e.Recover(context.Background(), in, func(context.Context) error { fences++; return nil }, func(context.Context) error { releases++; return nil })
			if err == nil || got != (LiveVerification{}) || fences > 1 || releases > 1 {
				t.Fatal("command failure accepted/replayed", n, got, err)
			}
			if releases > 0 {
				assertDrop(t, f)
			}
		})
	}
}
func TestRecoveryBeforeFirstTopologyCanFinishOnlyExistingExactBootstrapTarget(t *testing.T) {
	e, f, in, boot := activationFixture(t)
	if _, err := e.Activate(context.Background(), in, func(c context.Context) error { _ = boot(c); return ErrUnavailable }, func(context.Context) error { t.Fatal("release"); return nil }); err == nil {
		t.Fatal("accepted failed bootstrap")
	}
	expected, err := RecoveryStatus(e.Config)
	if err != nil || expected.ExpectedRevision != 0 || expected.ExpectedDigest != "" {
		t.Fatal(expected, err)
	}
	in.OperationID = strings.Repeat("c", 32)
	recovery := RecoveryIntent{OperationID: in.OperationID, RequestSHA256: in.RequestSHA256, RecoveryExpectation: expected, Intent: in}
	if _, err = e.Recover(context.Background(), recovery, func(context.Context) error { assertDrop(t, f); return nil }, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if f.externalIDs[in.InstanceID]["aster-owner"] != in.Ports[0].OwnerRef {
		t.Fatal("lost bootstrap label not completed")
	}
}
func TestRecoveryAllMutationBoundariesNeedFreshIntentAndExclusiveLock(t *testing.T) {
	for _, at := range []string{"journal.json:before_write", "journal.json:before_sync", "journal.json:before_rename", "journal.json:after_rename", "journal.json:after_dir_sync", "isolation.flows:before_write", "desired.flows:before_write"} {
		t.Run(at, func(t *testing.T) {
			e, _, _, in := recoveryFixture(t)
			e.fault = func(s string) error {
				if s == at {
					return ErrUnavailable
				}
				return nil
			}
			releases := 0
			got, err := e.Recover(context.Background(), in, func(context.Context) error { return nil }, func(context.Context) error { releases++; return nil })
			if err == nil || got != (LiveVerification{}) || releases != 0 {
				t.Fatal("storage fault yielded permission", got, err)
			}
		})
	}
	e, _, _, in := recoveryFixture(t)
	guard := func(context.Context) error {
		if _, err := RecoveryStatus(e.Config); err == nil {
			t.Fatal("status escaped exclusive lock")
		}
		return nil
	}
	if _, err := e.Recover(context.Background(), in, guard, guard); err != nil {
		t.Fatal(err)
	}
}

func TestJournalOverlayModeSurvivesMissingOwnerAndRejectsOldMutators(t *testing.T) {
	e, f, in, boot := activationFixture(t)
	l, err := openLedger(e.Config, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	pin := strings.Repeat("e", 64)
	if err = l.pinOverlay(pin); err != nil {
		t.Fatal(err)
	}
	l.close()
	// No overlay.owner exists: even a crash immediately after pin must never
	// revert to a fresh old-mode bridge. The root-private journal is the fence.
	l, err = openLedger(e.Config, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !l.overlayOwned() || l.state.OverlayProfileSHA256 != pin {
		t.Fatal("overlay opt-in lost")
	}
	l.close()
	before := len(f.calls)
	if _, err = e.Activate(context.Background(), in, boot, func(context.Context) error { t.Fatal("release"); return nil }); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if _, err = e.Apply(context.Background(), topologyFixture(), e.Config.Bridge); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if _, err = e.VerifyLive(context.Background()); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if err = e.Inspect(context.Background()); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if len(f.calls) != before {
		t.Fatal("old gate touched overlay host")
	}
}
func TestRecoveryCancellationDuringFenceOrReleaseReturnsNoProof(t *testing.T) {
	for _, phase := range []string{"fence", "release"} {
		t.Run(phase, func(t *testing.T) {
			e, f, _, in := recoveryFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			releases := 0
			got, err := e.Recover(ctx, in, func(context.Context) error {
				if phase == "fence" {
					cancel()
				}
				return nil
			}, func(context.Context) error { releases++; cancel(); return nil })
			if err == nil || got != (LiveVerification{}) || phase == "fence" && releases != 0 {
				t.Fatal(got, err, releases)
			}
			assertDrop(t, f)
		})
	}
}

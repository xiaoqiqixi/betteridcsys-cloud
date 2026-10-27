package fabric

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

type fileSnapshot struct {
	Raw      []byte
	Mode     os.FileMode
	Modified time.Time
}

func snapshotFiles(t *testing.T, dir string) map[string]fileSnapshot {
	t.Helper()
	entries, e := os.ReadDir(dir)
	if e != nil {
		t.Fatal(e)
	}
	out := map[string]fileSnapshot{}
	for _, entry := range entries {
		info, e := entry.Info()
		if e != nil {
			t.Fatal(e)
		}
		if !info.Mode().IsRegular() {
			continue
		}
		raw, e := os.ReadFile(filepath.Join(dir, entry.Name()))
		if e != nil {
			t.Fatal(e)
		}
		out[entry.Name()] = fileSnapshot{raw, info.Mode(), info.ModTime()}
	}
	return out
}

func TestVerifyLiveUsesCurrentExactReadbackAndNeverWrites(t *testing.T) {
	e, f, top := fixtureExecutor(t)
	receipt, err := e.Apply(context.Background(), top, e.Config.Bridge)
	if err != nil {
		t.Fatal(err)
	}
	files := snapshotFiles(t, e.Config.StateDirectory)
	hostFlows := f.flows
	hostMeters := map[int]int{}
	for k, v := range f.meters {
		hostMeters[k] = v
	}
	mutations := mutationCount(f)
	start := len(f.calls)
	e.fault = func(string) error { t.Fatal("verification attempted storage write"); return ErrUnavailable }
	live, err := e.VerifyLive(context.Background())
	if err != nil || live.Protocol != LiveProtocol || live.State != "verified" || live.NodeID != top.NodeID || live.Revision != receipt.Revision || live.Digest != receipt.Digest || len(live.BindingsSHA256) != 64 {
		t.Fatal(live, err)
	}
	if _, err = time.Parse(time.RFC3339Nano, live.ObservedAt); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(files, snapshotFiles(t, e.Config.StateDirectory)) || mutationCount(f) != mutations || hostFlows != f.flows || !reflect.DeepEqual(hostMeters, f.meters) {
		t.Fatal("verify wrote files or host")
	}
	if len(f.calls) <= start {
		t.Fatal("historical receipt returned without live reads")
	}
	for _, c := range f.calls[start:] {
		if !readOnlyCommand(e.Config, c.binary, c.args) {
			t.Fatal("non-readonly verify command", c)
		}
	}
	raw, _ := json.Marshal(live)
	for _, secret := range []string{e.Config.StateDirectory, "vnet1", top.Ports[0].IPv4, top.Ports[0].MAC, top.Ports[0].InterfaceID} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("private binding leaked", string(raw))
		}
	}
	stored, err := Status(e.Config, 0)
	if err != nil || stored != receipt {
		t.Fatal("live observation rewrote receipt", stored, err)
	}
}

func TestVerifyLiveLostChangedOrUnknownStateFailsWithoutRepair(t *testing.T) {
	for _, name := range []string{"flows_lost", "foreign_flows", "meter_lost", "meter_rate_changed", "foreign_meter", "initial_map_changed", "middle_map_changed", "final_map_changed", "physical_interface", "external_controller", "desired_file_changed", "desired_file_missing", "desired_symlink", "desired_hardlink", "journal_uncertain", "journal_interrupted"} {
		t.Run(name, func(t *testing.T) {
			e, f, top := fixtureExecutor(t)
			receipt, err := e.Apply(context.Background(), top, e.Config.Bridge)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(e.Config.StateDirectory, "desired.flows")
			switch name {
			case "flows_lost":
				f.flows = ""
			case "foreign_flows":
				f.foreign = true
			case "meter_lost":
				f.meters = map[int]int{}
			case "meter_rate_changed":
				f.meters[2]++
			case "foreign_meter":
				f.meters[888] = 10
			case "initial_map_changed":
				f.driftAt = f.probes + 1
			case "middle_map_changed":
				f.driftAt = f.probes + 2
			case "final_map_changed":
				f.driftAt = f.probes + 3
			case "physical_interface":
				f.physical = true
			case "external_controller":
				f.controller = true
			case "desired_file_changed":
				_ = os.WriteFile(path, []byte("altered"), 0600)
			case "desired_file_missing":
				_ = os.Remove(path)
			case "desired_symlink", "desired_hardlink":
				_ = os.Remove(path)
				target := filepath.Join(filepath.Dir(e.Config.StateDirectory), "other")
				p, _ := Compile(top)
				_ = os.WriteFile(target, []byte(strings.Join(p.Flows, "\n")+"\n"), 0600)
				if name == "desired_symlink" {
					_ = os.Symlink(target, path)
				} else {
					_ = os.Link(target, path)
				}
			case "journal_uncertain", "journal_interrupted":
				l, err := openLedger(e.Config, true, nil)
				if err != nil {
					t.Fatal(err)
				}
				state, stage := "uncertain", "flows_unconfirmed"
				if name == "journal_interrupted" {
					state, stage = "intent", "recorded"
				}
				l.state.Records[0].Receipt.State = state
				l.state.Records[0].Receipt.Stage = stage
				if l.save() != nil {
					t.Fatal("prepare state")
				}
				l.close()
			}
			before, _ := os.ReadFile(filepath.Join(e.Config.StateDirectory, "journal.json"))
			mutations := mutationCount(f)
			r, err := e.VerifyLive(context.Background())
			if err == nil || r != (LiveVerification{}) {
				t.Fatal("unknown state reported verified", r, err)
			}
			after, _ := os.ReadFile(filepath.Join(e.Config.StateDirectory, "journal.json"))
			if !bytes.Equal(before, after) || mutationCount(f) != mutations {
				t.Fatal("read verification tried to repair host/journal")
			}
			if !strings.HasPrefix(name, "journal_") {
				historical, err := Status(e.Config, 0)
				if err != nil || historical != receipt {
					t.Fatal("history unexpectedly changed", historical, err)
				}
			}
		})
	}
}

func TestVerifyLiveEveryCommandFailureNoMutationOrPopulatedProof(t *testing.T) {
	e, f, top := fixtureExecutor(t)
	if _, err := e.Apply(context.Background(), top, e.Config.Bridge); err != nil {
		t.Fatal(err)
	}
	start := len(f.calls)
	if _, err := e.VerifyLive(context.Background()); err != nil {
		t.Fatal(err)
	}
	count := len(f.calls) - start
	for n := 1; n <= count; n++ {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			e, f, top := fixtureExecutor(t)
			if _, err := e.Apply(context.Background(), top, e.Config.Bridge); err != nil {
				t.Fatal(err)
			}
			f.failAt = len(f.calls) + n
			files := snapshotFiles(t, e.Config.StateDirectory)
			mutations := mutationCount(f)
			r, err := e.VerifyLive(context.Background())
			if err == nil || r != (LiveVerification{}) || mutationCount(f) != mutations || !reflect.DeepEqual(files, snapshotFiles(t, e.Config.StateDirectory)) {
				t.Fatal("failed read fabricated proof or wrote state", r, err)
			}
		})
	}
}

func TestVerifyLiveLatestRevisionOnlyAndNoFallbackAcrossUncertainty(t *testing.T) {
	e, f, top := fixtureExecutor(t)
	first, err := e.Apply(context.Background(), top, e.Config.Bridge)
	if err != nil {
		t.Fatal(err)
	}
	top.Revision = 2
	second, err := e.Apply(context.Background(), top, e.Config.Bridge)
	if err != nil {
		t.Fatal(err)
	}
	live, err := e.VerifyLive(context.Background())
	if err != nil || live.Revision != 2 || live.Digest != second.Digest || live.Digest == first.Digest {
		t.Fatal(live, err)
	}
	top.Revision = 3
	f.failAt = len(f.calls) + 1
	if _, err = e.Apply(context.Background(), top, e.Config.Bridge); !errors.Is(err, ErrUncertain) {
		t.Fatal(err)
	}
	f.failAt = 0
	calls := len(f.calls)
	live, err = e.VerifyLive(context.Background())
	if !errors.Is(err, ErrUncertain) || live != (LiveVerification{}) || len(f.calls) != calls {
		t.Fatal("fell back to earlier applied revision", live, err)
	}
}

func TestVerifyLiveRequiresRootExistingStateAndNoWriteLock(t *testing.T) {
	e, f, _ := fixtureExecutor(t)
	if _, err := e.VerifyLive(context.Background()); err == nil || len(f.calls) != 0 {
		t.Fatal("missing state queried host", err)
	}
	if _, err := os.Lstat(e.Config.StateDirectory); !os.IsNotExist(err) {
		t.Fatal("verify created state directory", err)
	}
	top := topologyFixture()
	if _, err := e.Apply(context.Background(), top, e.Config.Bridge); err != nil {
		t.Fatal(err)
	}
	e.euid = func() int { return 1000 }
	calls := len(f.calls)
	if r, err := e.VerifyLive(context.Background()); err == nil || r != (LiveVerification{}) || len(f.calls) != calls {
		t.Fatal("non-root verified", r, err)
	}
	e.euid = func() int { return 0 }
	l, err := openLedger(e.Config, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer l.close()
	if r, err := e.VerifyLive(context.Background()); err == nil || r != (LiveVerification{}) || len(f.calls) != calls {
		t.Fatal("verify ignored writer lock", r, err)
	}
}

func TestVerifyReadonlyCommandGuardRejectsMutationAndArbitraryTargets(t *testing.T) {
	e, f, _ := fixtureExecutor(t)
	reader := *e
	reader.readOnly = true
	for _, c := range []command{{Vsctl, []string{"--timeout=3", "add-br", e.Config.Bridge}}, {Vsctl, []string{"--timeout=3", "br-exists", "aster-other"}}, {Ofctl, []string{"-O", "OpenFlow14", "--no-names", "--read-only", "del-meters", e.Config.Bridge}}, {Ofctl, []string{"-O", "OpenFlow14", "--no-names", "--read-only", "diff-flows", "/etc/private", e.Config.Bridge}}, {Ofctl, []string{"-O", "OpenFlow14", "--no-names", "dump-meters", e.Config.Bridge}}, {"/bin/sh", []string{"-c", "id"}}} {
		if _, err := reader.run(context.Background(), c.binary, c.args...); !errors.Is(err, ErrInvalid) || len(f.calls) != 0 {
			t.Fatal("readonly command guard accepted", c, err)
		}
	}
}

func TestVerifyCancelledContextDoesNotRefreshHistoricalProof(t *testing.T) {
	e, f, top := fixtureExecutor(t)
	if _, err := e.Apply(context.Background(), top, e.Config.Bridge); err != nil {
		t.Fatal(err)
	}
	before := snapshotFiles(t, e.Config.StateDirectory)
	mutations := mutationCount(f)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, err := e.VerifyLive(ctx)
	if err == nil || r != (LiveVerification{}) || mutationCount(f) != mutations || !reflect.DeepEqual(before, snapshotFiles(t, e.Config.StateDirectory)) {
		t.Fatal("cancelled verification returned proof or wrote", r, err)
	}
}

type rewritingReader struct {
	base    Runner
	rewrite func(string, []string, []byte) []byte
}

func (r rewritingReader) Run(ctx context.Context, binary string, args ...string) ([]byte, error) {
	raw, err := r.base.Run(ctx, binary, args...)
	if err != nil {
		return raw, err
	}
	return r.rewrite(binary, args, raw), nil
}

func TestVerifyMalformedOVSReadbackNeverBecomesLiveProof(t *testing.T) {
	for _, name := range []string{"json_trailing", "json_duplicate", "json_unknown", "rate_suffix", "rate_leading_zero", "id_suffix", "id_leading_zero", "unit_substring", "drop_substring", "unknown_flags"} {
		t.Run(name, func(t *testing.T) {
			e, f, top := fixtureExecutor(t)
			if _, err := e.Apply(context.Background(), top, e.Config.Bridge); err != nil {
				t.Fatal(err)
			}
			mutations := mutationCount(f)
			files := snapshotFiles(t, e.Config.StateDirectory)
			e.Runner = rewritingReader{f, func(binary string, args []string, raw []byte) []byte {
				s := string(raw)
				joined := strings.Join(args, " ")
				if binary == Vsctl && strings.Contains(joined, "--format=json") {
					switch name {
					case "json_trailing":
						return append(raw, []byte("{}")...)
					case "json_duplicate":
						return []byte(strings.Replace(s, `"headings":`, `"headings":[],"headings":`, 1))
					case "json_unknown":
						return []byte(strings.Replace(s, `"headings":`, `"surprise":true,"headings":`, 1))
					}
				}
				if binary == Ofctl && strings.Contains(joined, "dump-meters") {
					switch name {
					case "rate_suffix":
						s = strings.Replace(s, "rate=100000", "rate=100000evil", 1)
					case "rate_leading_zero":
						s = strings.Replace(s, "rate=100000", "rate=0100000", 1)
					case "id_suffix":
						s = strings.Replace(s, "meter=2 ", "meter=2evil ", 1)
					case "id_leading_zero":
						s = strings.Replace(s, "meter=2 ", "meter=02 ", 1)
					case "unit_substring":
						s = strings.Replace(s, " kbps ", " notkbps ", 1)
					case "drop_substring":
						s = strings.Replace(s, "type=drop ", "type=dropping ", 1)
					case "unknown_flags":
						s = strings.Replace(s, " kbps ", " kbps flags:0x100 ", 1)
					}
				}
				return []byte(s)
			}}
			r, err := e.VerifyLive(context.Background())
			if err == nil || r != (LiveVerification{}) || mutationCount(f) != mutations || !reflect.DeepEqual(files, snapshotFiles(t, e.Config.StateDirectory)) {
				t.Fatal("malformed provider output accepted or repaired", r, err)
			}
		})
	}
}

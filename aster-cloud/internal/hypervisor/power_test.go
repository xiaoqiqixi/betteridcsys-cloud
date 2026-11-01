package hypervisor

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestShutdownTimeoutConfig(t *testing.T) {
	m, _, _ := newFixture(t)
	for _, seconds := range []int{-1, 0, 9, 10, 120, 600, 601} {
		c := m.Config
		c.ShutdownTimeoutSeconds = seconds
		raw, _ := json.Marshal(c)
		path := filepath.Join(filepath.Dir(c.StateDirectory), "node.json")
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		got, err := LoadConfig(path)
		if seconds >= 10 && seconds <= 600 {
			if err != nil || got.ShutdownTimeoutSeconds != seconds {
				t.Fatal(got, err)
			}
		} else if err == nil {
			t.Fatal("invalid timeout accepted", seconds)
		}
	}
	raw, _ := json.Marshal(m.Config)
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	delete(fields, "shutdown_timeout_seconds")
	raw, _ = json.Marshal(fields)
	path := filepath.Join(filepath.Dir(m.Config.StateDirectory), "default.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(path)
	if err != nil || c.ShutdownTimeoutSeconds != 120 {
		t.Fatal(c, err)
	}
}

// Simulate an ACPI acknowledgement with no guest action, while preserving all
// actual state observations and ordering in the engine.
type powerRunner struct {
	*fakeRunner
	ignoreShutdown bool
	failReadAfter  string
	saw            string
}

func (r *powerRunner) Run(ctx context.Context, binary string, args ...string) ([]byte, error) {
	if binary == Virsh && len(args) > 3 {
		verb := args[2]
		if verb == "domstate" && r.saw == r.failReadAfter && r.failReadAfter != "" {
			return nil, errors.New("read lost")
		}
		if verb == "shutdown" && r.ignoreShutdown {
			r.mu.Lock()
			r.commands = append(r.commands, binary+" "+strings.Join(args, " "))
			r.mu.Unlock()
			r.saw = verb
			return nil, nil
		}
		out, err := r.fakeRunner.Run(ctx, binary, args...)
		if verb == "shutdown" || verb == "destroy" || verb == "start" {
			r.saw = verb
		}
		return out, err
	}
	return r.fakeRunner.Run(ctx, binary, args...)
}
func TestRebootObservesStopBeforeStartAndRunningBeforeSuccess(t *testing.T) {
	for _, failure := range []string{"", "shutdown", "start", "stop_read", "start_read"} {
		t.Run(failure, func(t *testing.T) {
			m, f, task := newFixture(t)
			if r := submit(t, m, task); r.Status != "succeeded" {
				t.Fatal(r)
			}
			r := &powerRunner{fakeRunner: f}
			m.Runner = r
			if failure == "stop_read" {
				r.failReadAfter = "shutdown"
			} else if failure == "start_read" {
				r.failReadAfter = "start"
			} else {
				f.fail = failure
			}
			before := len(f.commands)
			task = next(task, "4", "reboot")
			out := submit(t, m, task)
			want := "succeeded"
			if failure != "" {
				want = "uncertain"
			}
			if out.Status != want {
				t.Fatal(out)
			}
			commands := strings.Join(f.commands[before:], "\n")
			if strings.Contains(commands, " reboot ") {
				t.Fatal("unobservable virsh reboot", commands)
			}
			if failure == "" {
				stop := strings.Index(commands, " shutdown ")
				start := strings.Index(commands, " start ")
				if stop < 0 || start <= stop || !strings.Contains(commands[stop:start], " domstate ") || !strings.Contains(commands[start:], " domstate ") {
					t.Fatal(commands)
				}
				if got := submit(t, m, next(task, "5", "force_off")); got.Status != "succeeded" {
					t.Fatal("reboot retained quarantine", got)
				}
			}
			count := len(f.commands)
			if got := submit(t, m, task); got.Status != want || len(f.commands) != count {
				t.Fatal("mutation replayed", got)
			}
		})
	}
}
func TestRebootGracefulTimeoutAndExplicitForce(t *testing.T) {
	for _, force := range []bool{false, true} {
		t.Run(map[bool]string{false: "graceful", true: "force"}[force], func(t *testing.T) {
			m, f, task := newFixture(t)
			if r := submit(t, m, task); r.Status != "succeeded" {
				t.Fatal(r)
			}
			m.Config.ShutdownTimeoutSeconds = 10
			m.Runner = &powerRunner{fakeRunner: f, ignoreShutdown: true}
			task = next(task, "4", "reboot")
			task.Force = force
			raw, _, _ := task.BytesAndDigest()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			out, err := m.Submit(ctx, task, raw)
			if err != nil {
				t.Fatal(err)
			}
			op, _ := m.Ledger.Query(task.OperationID)
			i, _ := m.Ledger.Instance(task.InstanceID)
			if force {
				if out.Status != "succeeded" || f.count(" destroy ") != 1 || f.count(" start ") != 2 {
					t.Fatal(out, f.commands)
				}
			} else if out.Status != "rejected" || op.ErrorCode != "GUEST_SHUTDOWN_TIMEOUT" || f.count(" destroy ") != 0 || f.count(" start ") != 1 {
				t.Fatal(out, op.ErrorCode)
			}
			if i.State != "running" || m.Ledger.HasPendingInstance(i.ID, "") {
				t.Fatal("timeout quarantined unchanged guest", i)
			}
			if force && m.Ledger.state.Schema != 6 {
				t.Fatal("force not fenced from old binaries")
			}
		})
	}
}
func TestRebootCancellationRetainsUncertainty(t *testing.T) {
	m, f, task := newFixture(t)
	if r := submit(t, m, task); r.Status != "succeeded" {
		t.Fatal(r)
	}
	entered := make(chan struct{}, 1)
	f.block = make(chan struct{})
	f.blockVerb = "shutdown"
	f.blocked = entered
	task = next(task, "4", "reboot")
	raw, _, _ := task.BytesAndDigest()
	if _, err := m.Accept(task, raw); err != nil {
		t.Fatal(err)
	}
	<-entered
	m.Shutdown()
	op, _ := m.Ledger.Query(task.OperationID)
	i, _ := m.Ledger.Instance(task.InstanceID)
	if op.Result.Status != "uncertain" || i.State != "uncertain" {
		t.Fatal(op, i)
	}
}
func TestForceTaskIsExplicitAndBoundToDigest(t *testing.T) {
	_, _, task := newFixture(t)
	task = next(task, "4", "reboot")
	raw, sha, _ := task.BytesAndDigest()
	if strings.Contains(string(raw), "force") {
		t.Fatal("default changed legacy bytes")
	}
	task.Force = true
	forced, digest, err := task.BytesAndDigest()
	got, e := nodeproto.DecodeTask(forced)
	if err != nil || e != nil || !got.Force || digest == sha {
		t.Fatal(got, err, e)
	}
	task.Action = "start"
	if task.Valid() {
		t.Fatal("force accepted on unrelated action")
	}
}

// A guest that needs eleven seconds used to exceed the fixed ten-second wait.
// Exercise both normal and OVS shutdown through their real polling loops.
type slowShutdownRunner struct {
	Runner
	fake      *fakeRunner
	stoppedAt time.Time
}

func (r *slowShutdownRunner) Run(ctx context.Context, binary string, args ...string) ([]byte, error) {
	if binary == Virsh && len(args) > 3 {
		if args[2] == "shutdown" {
			r.stoppedAt = time.Now()
			return nil, nil
		}
		if args[2] == "domstate" && !r.stoppedAt.IsZero() && time.Since(r.stoppedAt) >= 11*time.Second {
			r.fake.mu.Lock()
			r.fake.states[args[3]] = "shut off"
			r.fake.mu.Unlock()
		}
	}
	return r.Runner.Run(ctx, binary, args...)
}
func TestConfiguredShutdownWaitsBeyondTenSeconds(t *testing.T) {
	for _, network := range []string{"normal", "ovs"} {
		t.Run(network, func(t *testing.T) {
			t.Parallel()
			m, f, task := newFixture(t)
			if network == "ovs" {
				var r *ovsRunner
				m, r, _, task = newOVSFixture(t)
				f = r.fakeRunner
			}
			if r := submit(t, m, task); r.Status != "succeeded" {
				t.Fatal(r)
			}
			m.Config.ShutdownTimeoutSeconds = 12
			m.Runner = &slowShutdownRunner{Runner: m.Runner, fake: f}
			task = next(task, "a", "shutdown")
			raw, _, _ := task.BytesAndDigest()
			ctx, cancel := context.WithTimeout(context.Background(), 18*time.Second)
			defer cancel()
			out, err := m.Submit(ctx, task, raw)
			if err != nil || out.Status != "succeeded" {
				t.Fatal(out, err)
			}
		})
	}
}

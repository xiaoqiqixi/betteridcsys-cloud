package hypervisor

import (
	"context"
	"errors"
	"testing"
	"time"
)

type deadlineObservationRunner struct{ calls int }

func (r *deadlineObservationRunner) Run(ctx context.Context, binary string, args ...string) ([]byte, error) {
	r.calls++
	if binary != Virsh || len(args) != 4 || args[2] != "domstate" {
		return nil, errors.New("unexpected mutation")
	}
	if r.calls == 1 {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return []byte("running\n"), nil
}
func TestPowerDeadlineDuringReadStillRequiresFinalObservation(t *testing.T) {
	r := &deadlineObservationRunner{}
	m := Manager{Runner: r}
	state, e := m.observePower(context.Background(), "owned-test", "shut off", time.Millisecond)
	if state != "running" || !errors.Is(e, errPowerObservationTimeout) || r.calls != 2 {
		t.Fatal(state, e, r.calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.calls = 0
	if _, e = m.observePower(ctx, "owned-test", "shut off", time.Millisecond); !errors.Is(e, context.Canceled) || r.calls != 0 {
		t.Fatal("caller cancellation caused another read", e, r.calls)
	}
}

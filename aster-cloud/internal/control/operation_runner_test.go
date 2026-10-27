package control

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestTransferRunnerBoundedTrackedCancelledWithoutImplicitRestart(t *testing.T) {
	runner := NewOperationRunner(OperationWorker{})
	var calls atomic.Int32
	started := make(chan struct{}, 4)
	runner.run = func(ctx context.Context, op string) (Operation, error) {
		calls.Add(1)
		started <- struct{}{}
		<-ctx.Done()
		return Operation{ID: op, State: "uncertain"}, ctx.Err()
	}
	for i := 0; i < 4; i++ {
		op := strings.Repeat(string(rune('a'+i)), 32)
		if e := runner.Start(op); e != nil {
			t.Fatal(e)
		}
	}
	for range 4 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("not started")
		}
	}
	if e := runner.Start(strings.Repeat("a", 32)); e != nil {
		t.Fatal("duplicate must only refer to existing worker", e)
	}
	if e := runner.Start(strings.Repeat("e", 32)); !errors.Is(e, ErrCapacity) {
		t.Fatal("unbounded transfers", e)
	}
	runner.Close()
	if calls.Load() != 4 {
		t.Fatal("duplicate/replayed workers", calls.Load())
	}
	if e := runner.Start(strings.Repeat("f", 32)); !errors.Is(e, ErrUnavailable) {
		t.Fatal("shutdown admitted transfer", e)
	}
}

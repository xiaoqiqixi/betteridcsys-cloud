package control

import (
	"context"
	"sync"
	"time"
)

// OperationRunner tracks bounded long transfers independently of an HTTP read
// deadline. Only an explicitly requested dispatch starts work. Restart never
// reconstructs/replays the in-flight POST; the durable intent stays sending.
type OperationRunner struct {
	mu        sync.Mutex
	worker    OperationWorker
	active    map[string]context.CancelFunc
	stopping  bool
	wg        sync.WaitGroup
	run       func(context.Context, string) (Operation, error)
	reconcile func(context.Context, string) (Operation, error)
}

func NewOperationRunner(worker OperationWorker) *OperationRunner {
	return &OperationRunner{worker: worker, active: map[string]context.CancelFunc{}, run: worker.Dispatch, reconcile: worker.Reconcile}
}
func (r *OperationRunner) Start(op string) error          { return r.launch(op, false) }
func (r *OperationRunner) StartReconcile(op string) error { return r.launch(op, true) }
func (r *OperationRunner) launch(op string, reconcile bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopping {
		return ErrUnavailable
	}
	if _, ok := r.active[op]; ok {
		return nil
	}
	if len(r.active) >= 4 {
		return ErrCapacity
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	r.active[op] = cancel
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer cancel()
		var o Operation
		var e error
		if reconcile {
			o, e = r.reconcile(ctx, op)
		} else {
			o, e = r.run(ctx, op)
		}
		logTransferOutcome(ctx, op, o.State, e)
		r.mu.Lock()
		delete(r.active, op)
		r.mu.Unlock()
	}()
	return nil
}
func (r *OperationRunner) Close() {
	r.mu.Lock()
	r.stopping = true
	for _, cancel := range r.active {
		cancel()
	}
	r.mu.Unlock()
	done := make(chan struct{})
	go func() { r.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
	}
}

func (r *OperationRunner) Active(op string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.active[op]
	return ok
}

package control

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"sync"
	"time"
)

// OverlayRunner advances only durable unsent tasks. A daemon restart never
// replays sending/uncertain POSTs. Each operator-approved epoch is bounded, and
// one active coordinator per epoch plus SQL claims prevents duplicate sends.
type OverlayRunner struct {
	worker         OverlayWorker
	billing        Worker
	operations     OperationWorker
	reconcileAfter map[string]string
	dispatchAfter  map[string]string
	mu             sync.Mutex
	active         map[string]context.CancelFunc
	stopping       bool
	wg             sync.WaitGroup
	run            func(context.Context, string) error
}

func NewOverlayRunner(w OverlayWorker) *OverlayRunner {
	r := &OverlayRunner{worker: w, active: map[string]context.CancelFunc{}, billing: Worker{Store: w.Store, Config: w.Config}, operations: OperationWorker{Store: w.Store, Config: w.Config}, reconcileAfter: map[string]string{}, dispatchAfter: map[string]string{}}
	r.run = r.advance
	return r
}
func (r *OverlayRunner) advance(ctx context.Context, id string) error {
	for n := 0; n < 96; n++ {
		epoch, e := r.worker.Advance(ctx, id)
		if e != nil {
			return e
		}
		if epoch.State == "succeeded" {
			return nil
		}
		if epoch.State != "pending" {
			return ErrState
		}
	}
	return ErrState
}
func (r *OverlayRunner) Start(id string) error {
	if !nodeproto.ValidID(id) {
		return ErrInput
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopping {
		return ErrUnavailable
	}
	if _, ok := r.active[id]; ok {
		return nil
	}
	if len(r.active) >= 4 {
		return ErrCapacity
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	r.active[id] = cancel
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer cancel()
		e := r.run(ctx, id)
		if e != nil {
			slog.Warn("aster_overlay_epoch_stopped", "operation_id", id, "code", "OUTCOME_UNCONFIRMED")
		}
		r.mu.Lock()
		delete(r.active, id)
		r.mu.Unlock()
	}()
	return nil
}
func (r *OverlayRunner) Close() {
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

// Run uses the existing accepted intent as authorization, not an HTTP GET.
// Outcome probes are GET-only reconciliation, never automatic POST retries.
func (r *OverlayRunner) Run(ctx context.Context) {
	timer := time.NewTicker(2 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			r.sweep(ctx)
		}
	}
}
func (r *OverlayRunner) sweep(ctx context.Context) {
	read, cancel := context.WithTimeout(ctx, 5*time.Second)
	rows, e := r.worker.Store.DB.QueryContext(read, "SELECT e.id FROM controller_overlay_epochs e WHERE e.state='pending' AND NOT EXISTS(SELECT 1 FROM controller_overlay_tasks t WHERE t.epoch_id=e.id AND t.phase=e.phase AND t.state IN ('sending','uncertain','rejected')) ORDER BY e.created_at,e.id LIMIT 32")
	ids := []string{}
	if e == nil {
		for rows.Next() {
			var id string
			if rows.Scan(&id) != nil {
				e = ErrUnavailable
				break
			}
			ids = append(ids, id)
		}
		if rows.Err() != nil {
			e = ErrUnavailable
		}
		rows.Close()
	}
	cancel()
	if e != nil {
		return
	}
	for _, id := range ids {
		_ = r.Start(id)
	}
	// Only overlay-reserved create operations are selected here. The original
	// worker claims all capacity/profile/heartbeat/IPAM gates and writes sending
	// before the first node request. No ordinary job is newly auto-dispatched.
	for _, kind := range []string{"billing", "console"} {
		r.dispatchCreate(ctx, kind)
		r.reconcileOutcome(ctx, kind)
	}
}
func (r *OverlayRunner) dispatchCreate(ctx context.Context, kind string) {
	if kind != "billing" && kind != "console" {
		return
	}
	table, column, action := "controller_jobs", "operation_id", ""
	if kind == "console" {
		table, column, action = "controller_operations", "id", " AND j.action='create'"
	}
	r.mu.Lock()
	after := r.dispatchAfter[kind]
	r.mu.Unlock()
	q := "SELECT j." + column + " FROM " + table + " j JOIN controller_overlay_members m ON m.instance_id=j.instance_id WHERE CAST(j.state AS BINARY)='accepted'" + action + " AND j." + column + ">? AND EXISTS(SELECT 1 FROM controller_overlay_epochs e WHERE e.cluster_id=m.cluster_id AND e.state='succeeded' AND e.epoch=(SELECT MAX(x.epoch) FROM controller_overlay_epochs x WHERE x.cluster_id=m.cluster_id)) ORDER BY j." + column + " LIMIT 1"
	read, cancel := context.WithTimeout(ctx, 5*time.Second)
	var id string
	e := r.worker.Store.DB.QueryRowContext(read, q, after).Scan(&id)
	cancel()
	if errors.Is(e, sql.ErrNoRows) {
		r.mu.Lock()
		r.dispatchAfter[kind] = ""
		r.mu.Unlock()
		return
	}
	if e != nil {
		return
	}
	// Advance even when the original claim rejects an unavailable node. The
	// persisted accepted state is untouched; another eligible node cannot starve.
	r.mu.Lock()
	r.dispatchAfter[kind] = id
	r.mu.Unlock()
	call, done := context.WithTimeout(ctx, 15*time.Second)
	defer done()
	if kind == "billing" {
		_, _ = r.billing.Dispatch(call, id)
	} else {
		_, _ = r.operations.Dispatch(call, id)
	}
}

// A normal asynchronous node create returns accepted, not success. Continue
// exact GET reconciliation so creating/dispatched does not become permanent.
// This also observes overlay member power/delete outcomes after recovery. A
// persistent unknown node cannot starve later rows: cursors round-robin IDs.
func (r *OverlayRunner) reconcileOutcome(ctx context.Context, kind string) {
	if kind != "billing" && kind != "console" {
		return
	}
	table, column := "controller_jobs", "operation_id"
	if kind == "console" {
		table, column = "controller_operations", "id"
	}
	r.mu.Lock()
	after := r.reconcileAfter[kind]
	r.mu.Unlock()
	query := "SELECT j." + column + " FROM " + table + " j JOIN controller_overlay_members m ON m.instance_id=j.instance_id WHERE CAST(j.state AS BINARY) IN ('sending','dispatched','uncertain') AND j." + column + ">? ORDER BY j." + column + " LIMIT 1"
	read, cancel := context.WithTimeout(ctx, 5*time.Second)
	var id string
	e := r.worker.Store.DB.QueryRowContext(read, query, after).Scan(&id)
	cancel()
	if errors.Is(e, sql.ErrNoRows) {
		r.mu.Lock()
		r.reconcileAfter[kind] = ""
		r.mu.Unlock()
		return
	}
	if e != nil {
		return
	}
	r.mu.Lock()
	r.reconcileAfter[kind] = id
	r.mu.Unlock()
	call, done := context.WithTimeout(ctx, 15*time.Second)
	defer done()
	if kind == "billing" {
		_, _ = r.billing.Reconcile(call, id)
	} else {
		_, _ = r.operations.Reconcile(call, id)
	}
}

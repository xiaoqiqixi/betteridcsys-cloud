package control

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"strings"
	"time"
)

// DispatcherConfig is root policy. The zero value never starts a worker.
type DispatcherConfig struct {
	Enabled bool `json:"enabled"`
}

type DispatchLease struct {
	OperationID string
	Kind        string
	State       string
}

// LeaseDispatch selects work under the same gate used by manual dispatch.
// A lease permits queue inspection, never a second POST: Claim/ClaimOperation
// must still durably change accepted to sending before the first send.
// Expired sending leases can only issue read-only status requests. Uncertain
// records are deliberately left for an operator, even after lease expiry.
func (s *SQLStore) LeaseDispatch(ctx context.Context, holder string, c Config, now time.Time) (DispatchLease, error) {
	if !identifier.MatchString(holder) || len(holder) != 32 {
		return DispatchLease{}, ErrInput
	}
	tx, err := s.locked(ctx)
	if err != nil {
		return DispatchLease{}, err
	}
	defer tx.Rollback()
	var lease DispatchLease
	if len(c.Nodes) == 0 {
		return lease, ErrNotFound
	}
	placeholders := make([]string, len(c.Nodes))
	args := []any{now}
	for i, n := range c.Nodes {
		placeholders[i] = "?"
		args = append(args, n.ID)
	}
	err = tx.QueryRowContext(ctx, `SELECT q.op,q.kind,q.state FROM (
SELECT operation_id AS op,'billing' AS kind,state,created_at,node_id FROM controller_jobs WHERE CAST(state AS BINARY) IN ('accepted','sending','dispatched')
UNION ALL SELECT id AS op,'operation' AS kind,state,created_at,node_id FROM controller_operations o WHERE CAST(state AS BINARY) IN ('accepted','sending','dispatched') AND NOT (state='accepted' AND EXISTS (SELECT 1 FROM controller_service_operations s WHERE s.operation_id=o.id AND s.requires_secret=TRUE))
) q LEFT JOIN controller_dispatch_leases l ON l.operation_id=q.op
WHERE (l.operation_id IS NULL OR l.expires_at<=?) AND q.node_id IN (`+strings.Join(placeholders, ",")+`)
ORDER BY COALESCE(l.expires_at,q.created_at),q.op LIMIT 1`, args...).Scan(&lease.OperationID, &lease.Kind, &lease.State)
	if errors.Is(err, sql.ErrNoRows) {
		return DispatchLease{}, ErrNotFound
	}
	if err != nil {
		return DispatchLease{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO controller_dispatch_leases(operation_id,kind,holder,expires_at) VALUES(?,?,?,?) ON DUPLICATE KEY UPDATE holder=VALUES(holder),expires_at=VALUES(expires_at)`, lease.OperationID, lease.Kind, holder, now.Add(time.Minute))
	if err != nil {
		return DispatchLease{}, err
	}
	if err = audit(ctx, tx, "dispatcher", "dispatcher."+lease.Kind+"_leased", lease.OperationID, now); err != nil {
		return DispatchLease{}, err
	}
	return lease, tx.Commit()
}

// Dispatcher shares the server's lifetime and host fence. Manual commands use
// exactly the same durable workers; enabling this loop changes only selection.
type Dispatcher struct {
	Store      *SQLStore
	Config     Config
	Billing    Worker
	Operations OperationWorker
	Holder     string
}

func NewDispatcher(s *SQLStore, c Config) *Dispatcher {
	return &Dispatcher{Store: s, Config: c, Billing: Worker{Store: s, Config: c}, Operations: OperationWorker{Store: s, Config: c}, Holder: id()}
}

func (d *Dispatcher) Step(ctx context.Context, now time.Time) error {
	if !d.Config.Dispatcher.Enabled {
		return ErrState
	}
	lease, err := d.Store.LeaseDispatch(ctx, d.Holder, d.Config, now)
	if err != nil {
		return err
	}
	if lease.Kind == "billing" {
		if lease.State == "accepted" {
			_, err = d.Billing.Dispatch(ctx, lease.OperationID)
		} else {
			_, err = d.Billing.Reconcile(ctx, lease.OperationID)
		}
	} else {
		if lease.State == "accepted" {
			_, err = d.Operations.Dispatch(ctx, lease.OperationID)
		} else {
			_, err = d.Operations.Reconcile(ctx, lease.OperationID)
		}
	}
	return err
}

func (d *Dispatcher) Run(ctx context.Context) {
	if !d.Config.Dispatcher.Enabled {
		return
	}
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			work, cancel := context.WithTimeout(ctx, 30*time.Minute)
			err := d.Step(work, now.UTC())
			cancel()
			if err != nil && !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrState) && !errors.Is(err, ErrCapacity) && ctx.Err() == nil {
				slog.Warn("aster_dispatcher_dependency_unavailable")
			}
		}
	}
}

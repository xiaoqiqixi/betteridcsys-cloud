package control

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"strings"
	"time"
)

// AuditOperationRequest records who explicitly requested dispatch/reconciliation,
// separately from the immutable intent creator and the node's eventual result.
// Failure is fatal before RPC; this event promises neither dispatch nor success.
func (s *SQLStore) AuditOperationRequest(ctx context.Context, actor, op, action string, now time.Time) error {
	if !nodeproto.ValidID(op) || (action != "dispatch" && action != "reconcile") || (actor != "host-operator" && (!strings.HasPrefix(actor, "user:") || !nodeproto.ValidID(strings.TrimPrefix(actor, "user:")))) {
		return ErrInput
	}
	tx, e := s.locked(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var stored string
	if e = tx.QueryRowContext(ctx, "SELECT id FROM controller_operations WHERE id=?", op).Scan(&stored); e != nil {
		return e
	}
	if e = audit(ctx, tx, actor, "operation."+action+"_requested", op, now); e != nil {
		return e
	}
	return tx.Commit()
}

package control

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"errors"
)

func (c Console) retirementView(ctx context.Context, m *Migration) error {
	if m.Phase != "active" {
		return nil
	}
	prepare, e := c.Store.Operation(ctx, m.SourceOperationID)
	if errors.Is(e, ErrNotFound) {
		// Retirement metadata is an additive storage/2 projection. Historical
		// storage/1 rows did not require a retained console source operation.
		// Absence is not proof of retirement or permission to delete: the write
		// path still requires the exact original source task and target receipt.
		return nil
	}
	if e != nil {
		return e
	}
	if prepare.Protocol != nodeproto.StorageDirectProtocol {
		return nil
	}
	m.SourceRetirementState = "required"
	o, e := scanOperation(c.Store.DB.QueryRowContext(ctx, "SELECT "+operationColumns+" FROM controller_operations WHERE artifact_id=? AND instance_id=? AND action='migrate_retire_source' ORDER BY seq DESC LIMIT 1", m.ID, m.InstanceID))
	if errors.Is(e, ErrNotFound) {
		return nil
	}
	if e != nil {
		return e
	}
	m.SourceRetirementOperationID = o.ID
	switch o.State {
	case "succeeded":
		m.SourceRetirementState = "succeeded"
	case "accepted":
		m.SourceRetirementState = "pending"
	case "rejected":
		m.SourceRetirementState = "required"
	default:
		m.SourceRetirementState = "blocked"
	}
	return nil
}

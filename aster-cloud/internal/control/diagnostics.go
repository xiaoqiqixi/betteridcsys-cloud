package control

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
)

// This classifies diagnostic certainty only; it does not advance a task or claim
// that an accepted/dispatched operation completed successfully.
func workerOutcomeRequiresInspection(state string, err error) bool {
	if err != nil {
		return true
	}
	switch state {
	case "accepted", "dispatched", "succeeded", "rejected":
		return false
	default:
		return true
	}
}

func logTransferOutcome(ctx context.Context, operation, state string, err error) {
	result, level := "confirmed", slog.LevelInfo
	if workerOutcomeRequiresInspection(state, err) {
		result, level = "inspect_original_operation", slog.LevelWarn
	}
	slog.Log(ctx, level, "aster_controller_transfer", "operation_id", operation, "state", state, "result", result)
}

// Operational metadata supplements, but never replaces, transaction-bound audit.
// No raw error, request, path, endpoint, owner, credential or guest data is logged.
func logWorkerOutcome(ctx context.Context, event, command, operation, state string, err error) {
	code := "STATUS_RECORDED"
	switch {
	case errors.Is(err, ErrInput):
		code = "INVALID_REQUEST"
	case errors.Is(err, ErrNotFound), errors.Is(err, sql.ErrNoRows):
		code = "NOT_FOUND"
	case errors.Is(err, ErrConflict):
		code = "IDEMPOTENCY_CONFLICT"
	case errors.Is(err, ErrState):
		code = "STATE_CONFLICT"
	case errors.Is(err, ErrCapacity):
		code = "NODE_NOT_READY"
	case err != nil:
		code = "DEPENDENCY_UNAVAILABLE"
	}
	level := slog.LevelInfo
	if workerOutcomeRequiresInspection(state, err) {
		level = slog.LevelWarn
	}
	slog.Log(ctx, level, event, "command", command, "operation_id", operation, "state", state, "code", code)
}

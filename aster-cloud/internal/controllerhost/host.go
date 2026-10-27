// Package controllerhost owns local admission fencing for controller processes.
// It is not a distributed lease, a database backup or a migration receipt.
package controllerhost

import "errors"

var (
	ErrFenced      = errors.New("controller admission fenced")
	ErrBusy        = errors.New("controller process still active")
	ErrInvalid     = errors.New("controller host intent rejected")
	ErrUnavailable = errors.New("controller host state unavailable")
)

type Status struct {
	Schema           int    `json:"schema"`
	ControllerID     string `json:"controller_id"`
	OperationID      string `json:"operation_id,omitempty"`
	Phase            string `json:"phase"`
	AdmissionBlocked bool   `json:"admission_blocked"`
	GuardedDrained   bool   `json:"guarded_processes_drained"`
	SourceIsolated   bool   `json:"source_isolated"`
	MigrationReady   bool   `json:"migration_ready"`
}

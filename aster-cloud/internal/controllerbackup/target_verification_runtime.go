package controllerbackup

import (
	"context"
	"path/filepath"
	"time"
)

// TargetVerificationRuntimeReport is a stopped-host preflight, not a permit
// to launch a process. Root must also verify its complete account/object and
// host inventory. No credential, private key or caller-chosen path is returned.
type TargetVerificationRuntimeReport struct {
	Schema              int                          `json:"schema"`
	OperationID         string                       `json:"operation_id"`
	Phase               TargetVerificationDataReport `json:"phase"`
	CredentialVerified  bool                         `json:"credential_verified"`
	SQLIdentityVerified bool                         `json:"sql_identity_verified"`
	ReadOnly            bool                         `json:"readonly"`
	ServiceStarted      bool                         `json:"service_started"`
	MigrationReady      bool                         `json:"migration_ready"`
}

// CheckTargetVerificationRuntime reauthenticates the saved minimum credential
// against the ORIGINAL immutable data phase. Unlike the initial credential
// check it permits validated login/logout deltas, never an arbitrary current
// image. It refuses expired phases and any begun revocation without unlocking,
// extending approval or rewriting the original intent. Both proofs are made
// under the same original sealed-target lock with no workers admitted.
func CheckTargetVerificationRuntime(ctx context.Context, operation string) (TargetVerificationRuntimeReport, error) {
	var result TargetVerificationRuntimeReport
	err := withTargetArchiveMode(operation, true, func(plan TargetPlan, sha string, a *Archive) error {
		phase, err := targetVerificationData(ctx, plan, sha, a, "verification-data-status")
		if err != nil {
			return err
		}
		start, err := time.Parse(time.RFC3339Nano, phase.StartedAt)
		if err != nil {
			return ErrInvalid
		}
		end, err := time.Parse(time.RFC3339Nano, phase.ExpiresAt)
		if err != nil {
			return ErrInvalid
		}
		withinPeriod := func() bool {
			now := time.Now().UTC()
			return !now.Before(start) && now.Before(end)
		}
		if !withinPeriod() {
			return ErrInvalid
		}
		db, _, err := importedTargetInputs(ctx, a, plan, sha)
		if err != nil {
			return err
		}
		runtime := RuntimeTarget{Directory: filepath.Join(targetRoot, operation), DSN: db.runtimeDSN, PlanSHA256: sha}
		if _, err = targetVerificationCredential(ctx, operation, phase.Plan, phase.PlanSHA256, runtime); err != nil {
			return err
		}
		if !withinPeriod() {
			return ErrInvalid
		}
		result = TargetVerificationRuntimeReport{Schema: 1, OperationID: operation, Phase: phase,
			CredentialVerified: true, SQLIdentityVerified: true, ReadOnly: true}
		return nil
	})
	if err != nil {
		return TargetVerificationRuntimeReport{}, err
	}
	return result, nil
}

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
		var err error
		result, _, err = targetVerificationRuntime(ctx, plan, sha, a)
		return err
	})
	if err != nil {
		return TargetVerificationRuntimeReport{}, err
	}
	return result, nil
}

// Reused only while holding the original sealed-target control lock. The DSN
// never leaves the root coordinator except over the isolated child's private
// bootstrap; the public preflight deliberately discards it.
func targetVerificationRuntime(ctx context.Context, plan TargetPlan, sha string, a *Archive) (TargetVerificationRuntimeReport, string, error) {
	fail := func(err error) (TargetVerificationRuntimeReport, string, error) {
		return TargetVerificationRuntimeReport{}, "", err
	}
	phase, err := targetVerificationData(ctx, plan, sha, a, "verification-data-status")
	if err != nil {
		return fail(err)
	}
	if _, err = verificationDeadline(ctx, phase); err != nil {
		return fail(err)
	}
	db, _, err := importedTargetInputs(ctx, a, plan, sha)
	if err != nil {
		return fail(err)
	}
	runtime := RuntimeTarget{Directory: filepath.Join(targetRoot, plan.OperationID), DSN: db.runtimeDSN, PlanSHA256: sha}
	dsn, err := targetVerificationCredential(ctx, plan.OperationID, phase.Plan, phase.PlanSHA256, runtime)
	if err != nil {
		return fail(err)
	}
	if _, err = verificationDeadline(ctx, phase); err != nil {
		return fail(err)
	}
	return TargetVerificationRuntimeReport{Schema: 1, OperationID: plan.OperationID, Phase: phase,
		CredentialVerified: true, SQLIdentityVerified: true, ReadOnly: true}, dsn, nil
}

func verificationDeadline(ctx context.Context, phase TargetVerificationDataReport) (time.Time, error) {
	if ctx == nil || ctx.Err() != nil {
		return time.Time{}, ErrInvalid
	}
	start, err := time.Parse(time.RFC3339Nano, phase.StartedAt)
	if err != nil {
		return time.Time{}, ErrInvalid
	}
	end, err := time.Parse(time.RFC3339Nano, phase.ExpiresAt)
	now := time.Now().UTC()
	if err != nil || now.Before(start) || !now.Before(end) {
		return time.Time{}, ErrInvalid
	}
	return end, nil
}

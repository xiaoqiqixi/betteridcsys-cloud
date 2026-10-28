package controllerbackup

import (
	"aster/cloud/internal/control"
	"context"
	"path/filepath"
)

type TargetConfigurationReport struct {
	Schema                 int               `json:"schema"`
	OperationID            string            `json:"operation_id"`
	Plan                   ConfigurationPlan `json:"plan"`
	ReadOnly               bool              `json:"readonly"`
	SessionsRevoked        bool              `json:"sessions_revoked"`
	ExactDatabaseVerified  bool              `json:"exact_database_verified"`
	ConfigurationPublished bool              `json:"configuration_published"`
	MigrationReady         bool              `json:"migration_ready"`
}

// Fixed root entry: the original seal, exact database postimage, material bytes
// and immutable revocation intent precede a plan. No arbitrary path, DSN or
// caller-supplied session proof reaches the offline configuration module.
func PlanTargetConfiguration(ctx context.Context, operation string) (TargetConfigurationReport, error) {
	var result TargetConfigurationReport
	err := withTargetArchive(operation, func(plan TargetPlan, sha string, a *Archive) error {
		db, proof, err := importedTargetInputs(ctx, a, plan, sha)
		if err != nil {
			return err
		}
		runtime := RuntimeTarget{Directory: filepath.Join(targetRoot, operation), DSN: db.runtimeDSN, PlanSHA256: sha}
		binding, intent, err := targetSessionBinding(a, runtime, true)
		if err != nil {
			return err
		}
		store, err := control.OpenDSN(db.migrationDSN)
		if err != nil {
			return ErrInvalid
		}
		defer store.DB.Close()
		if _, err := a.VerifyRevokedSessions(ctx, store.DB, db.ownerRaw, db.runtimeDSN, proof, binding, intent); err != nil {
			return err
		}
		request, err := targetRead(filepath.Join(runtime.Directory, "configuration-request.json"), 8192)
		if err != nil {
			return err
		}
		configuration, err := a.PlanConfiguration(runtime, request, digestBytes(intent))
		if err != nil {
			return err
		}
		result = TargetConfigurationReport{Schema: 1, OperationID: operation, Plan: configuration, ReadOnly: true, SessionsRevoked: true, ExactDatabaseVerified: true}
		return nil
	})
	if err != nil {
		return TargetConfigurationReport{}, err
	}
	return result, nil
}

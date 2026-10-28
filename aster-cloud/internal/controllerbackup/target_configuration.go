package controllerbackup

import (
	"aster/cloud/internal/control"
	"context"
	"encoding/json"
	"path/filepath"
)

type TargetConfigurationReport struct {
	PlanSHA256             string            `json:"plan_sha256"`
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
		runtime, request, sessionSHA, err := targetConfigurationInputs(ctx, a, plan, sha)
		if err != nil {
			return err
		}
		configuration, err := a.PlanConfiguration(runtime, request, sessionSHA)
		if err != nil {
			return err
		}
		encoded, err := json.Marshal(configuration)
		if err != nil {
			return ErrInvalid
		}
		result = TargetConfigurationReport{PlanSHA256: digestBytes(encoded), Schema: 1, OperationID: operation, Plan: configuration, ReadOnly: true, SessionsRevoked: true, ExactDatabaseVerified: true}
		return nil
	})
	if err != nil {
		return TargetConfigurationReport{}, err
	}
	return result, nil
}

func targetConfigurationInputs(ctx context.Context, a *Archive, plan TargetPlan, sha string) (RuntimeTarget, []byte, string, error) {
	fail := func(err error) (RuntimeTarget, []byte, string, error) { return RuntimeTarget{}, nil, "", err }
	db, proof, err := importedTargetInputs(ctx, a, plan, sha)
	if err != nil {
		return fail(err)
	}
	runtime := RuntimeTarget{Directory: filepath.Join(targetRoot, plan.OperationID), DSN: db.runtimeDSN, PlanSHA256: sha}
	binding, intent, err := targetSessionBinding(a, runtime, true)
	if err != nil {
		return fail(err)
	}
	store, err := control.OpenDSN(db.migrationDSN)
	if err != nil {
		return fail(ErrInvalid)
	}
	defer store.DB.Close()
	if _, err := a.VerifyRevokedSessions(ctx, store.DB, db.ownerRaw, db.runtimeDSN, proof, binding, intent); err != nil {
		return fail(err)
	}
	request, err := targetRead(filepath.Join(runtime.Directory, "configuration-request.json"), 8192)
	if err != nil {
		return fail(err)
	}
	return runtime, request, digestBytes(intent), nil
}

type TargetConfigurationPublicationReport struct {
	ConfigurationPublicationReport
	SessionsRevoked       bool `json:"sessions_revoked"`
	ExactDatabaseVerified bool `json:"exact_database_verified"`
}

// Publishing does not change the installation receipt, original target seal,
// material stage, SQL, source host, service units, or ordinary serve admission.
func TargetConfigurationPublication(ctx context.Context, operation, action string) (TargetConfigurationPublicationReport, error) {
	if action != "configuration-publish" && action != "configuration-status" && action != "configuration-resume" {
		return TargetConfigurationPublicationReport{}, ErrInvalid
	}
	var result TargetConfigurationPublicationReport
	err := withTargetArchiveMode(operation, true, func(plan TargetPlan, sha string, a *Archive) error {
		runtime, request, sessionSHA, err := targetConfigurationInputs(ctx, a, plan, sha)
		if err != nil {
			return err
		}
		approval, err := targetRead(filepath.Join(runtime.Directory, "configuration-approval.json"), 8192)
		if err != nil {
			return err
		}
		target := ConfigurationPublicationTarget{Runtime: runtime, ParentDirectory: "/etc"}
		var report ConfigurationPublicationReport
		switch action {
		case "configuration-publish":
			report, err = a.PublishConfiguration(target, request, approval, sessionSHA)
		case "configuration-status":
			report, err = a.VerifyPublishedConfiguration(target, request, approval, sessionSHA)
		case "configuration-resume":
			report, err = a.ResumeConfigurationPublication(target, request, approval, sessionSHA)
		}
		if err != nil {
			return err
		}
		result = TargetConfigurationPublicationReport{report, true, true}
		return nil
	})
	if err != nil {
		return TargetConfigurationPublicationReport{}, err
	}
	return result, nil
}

package controllerbackup

import (
	"aster/cloud/internal/control"
	"context"
	"os"
	"path/filepath"
	"time"
)

type verificationDataApproval struct {
	Schema                 int    `json:"schema"`
	OperationID            string `json:"operation_id"`
	VerificationPlanSHA256 string `json:"verification_plan_sha256"`
	AccountReceiptSHA256   string `json:"account_receipt_sha256"`
	StartedAt              string `json:"started_at"`
	ExpiresAt              string `json:"expires_at"`
}

type verificationAccountReceipt struct {
	Schema           int    `json:"schema"`
	OperationID      string `json:"operation_id"`
	PlanSHA256       string `json:"plan_sha256"`
	IntentSHA256     string `json:"intent_sha256"`
	AuthSHA256       string `json:"auth_sha256"`
	GrantsSHA256     string `json:"grants_sha256"`
	CredentialSHA256 string `json:"credential_sha256"`
}

type TargetVerificationDataReport struct {
	Schema               int                    `json:"schema"`
	OperationID          string                 `json:"operation_id"`
	Plan                 TargetVerificationPlan `json:"plan"`
	PlanSHA256           string                 `json:"plan_sha256"`
	AccountReceiptSHA256 string                 `json:"account_receipt_sha256"`
	StartedAt            string                 `json:"started_at"`
	ExpiresAt            string                 `json:"expires_at"`
	Data                 VerificationDataReport `json:"data"`
	ReadOnlyVerification bool                   `json:"read_only_verification"`
	ServiceStarted       bool                   `json:"service_started"`
	MigrationReady       bool                   `json:"migration_ready"`
}

// TargetVerificationData persists or checks only the stopped host's data phase.
// Root must independently verify the complete account/object inventory and
// authenticated credential before begin; no HTTP service or lease is admitted.
// Status is also valid after ACCOUNT LOCK, so it never tries to log in using
// the revoked verification credential or weakens the original exact-image API.
func TargetVerificationData(ctx context.Context, operation, action string) (TargetVerificationDataReport, error) {
	if action != "verification-data-begin" && action != "verification-data-status" {
		return TargetVerificationDataReport{}, ErrInvalid
	}
	var result TargetVerificationDataReport
	err := withTargetArchiveMode(operation, true, func(plan TargetPlan, sha string, a *Archive) error {
		var err error
		result, err = targetVerificationData(ctx, plan, sha, a, action)
		return err
	})
	if err != nil {
		return TargetVerificationDataReport{}, err
	}
	return result, nil
}

// Called only inside the original archive and sealed-target control lock.
// Status never creates a new baseline and remains valid after account locking.
func targetVerificationData(ctx context.Context, plan TargetPlan, sha string, a *Archive, action string) (TargetVerificationDataReport, error) {
	operation := plan.OperationID
	var result TargetVerificationDataReport
	err := func() error {
		db, proof, e := importedTargetInputs(ctx, a, plan, sha)
		if e != nil {
			return e
		}
		runtime := RuntimeTarget{Directory: filepath.Join(targetRoot, operation), DSN: db.runtimeDSN, PlanSHA256: sha}
		sessions, sessionIntent, e := targetSessionBinding(a, runtime, true)
		if e != nil {
			return e
		}
		request, e := targetRead(filepath.Join(runtime.Directory, "configuration-request.json"), 8192)
		if e != nil {
			return e
		}
		bound, planSHA, e := publishedVerificationPlan(a, plan, sha, runtime, request, digestBytes(sessionIntent))
		if e != nil {
			return e
		}
		directory := filepath.Join(runtime.Directory, "database")
		accountRaw, e := targetRead(filepath.Join(directory, "verification-account.json"), 8192)
		var account verificationAccountReceipt
		if e != nil || !exactSourceRecord(accountRaw, &account) || account.Schema != 1 || account.OperationID != operation || account.PlanSHA256 != planSHA {
			return ErrInvalid
		}
		for _, digest := range []string{account.IntentSHA256, account.AuthSHA256, account.GrantsSHA256, account.CredentialSHA256} {
			if !shaPattern.MatchString(digest) {
				return ErrInvalid
			}
		}
		for name, digest := range map[string]string{"verification-started.json": account.IntentSHA256, "verification-mysql-dsn": account.CredentialSHA256} {
			raw, e := targetRead(filepath.Join(directory, name), 8192)
			if e != nil || digestBytes(raw) != digest {
				return ErrInvalid
			}
		}
		approvalRaw, e := targetRead(filepath.Join(runtime.Directory, "verification-data-approval.json"), 8192)
		var approval verificationDataApproval
		if e != nil || !exactSourceRecord(approvalRaw, &approval) || approval.Schema != 1 || approval.OperationID != operation ||
			approval.VerificationPlanSHA256 != planSHA || approval.AccountReceiptSHA256 != digestBytes(accountRaw) {
			return ErrInvalid
		}
		start, e := time.Parse(time.RFC3339Nano, approval.StartedAt)
		if e != nil {
			return ErrInvalid
		}
		end, e := time.Parse(time.RFC3339Nano, approval.ExpiresAt)
		if e != nil {
			return ErrInvalid
		}
		binding := VerificationDataBinding{VerificationPlanSHA256: planSHA, AccountReceiptSHA256: digestBytes(accountRaw), StartedAt: start, ExpiresAt: end}
		store, e := control.OpenDSN(db.migrationDSN)
		if e != nil {
			return ErrInvalid
		}
		defer store.DB.Close()
		path := filepath.Join(runtime.Directory, "verification-data-started.json")
		var intent []byte
		if action == "verification-data-begin" {
			// No automatic retry/rebaseline or extension. Only this immutable
			// first intent can precede admission; later calls select status.
			for _, name := range []string{"verification-revoke-started.json", "verification-revoked.json"} {
				if _, e := os.Lstat(filepath.Join(directory, name)); !os.IsNotExist(e) {
					return ErrInvalid
				}
			}
			now := time.Now().UTC()
			if now.Before(start) || !now.Before(end) {
				return ErrInvalid
			}
			intent, e = a.PlanVerificationDataPhase(ctx, store.DB, db.ownerRaw, db.runtimeDSN, proof, sessions, sessionIntent, binding)
			if e != nil || writePrivateNew(path, intent) != nil {
				return ErrInvalid
			}
		} else {
			intent, e = targetRead(path, 8192)
			if e != nil {
				return e
			}
		}
		data, e := a.VerifyVerificationDataPhase(ctx, store.DB, db.ownerRaw, db.runtimeDSN, proof, sessions, sessionIntent, binding, intent)
		if e != nil {
			return e
		}
		result = TargetVerificationDataReport{Schema: 1, OperationID: operation, Plan: bound, PlanSHA256: planSHA,
			AccountReceiptSHA256: binding.AccountReceiptSHA256, StartedAt: approval.StartedAt, ExpiresAt: approval.ExpiresAt,
			Data: data, ReadOnlyVerification: action == "verification-data-status"}
		return nil
	}()
	if err != nil {
		return TargetVerificationDataReport{}, err
	}
	return result, nil
}

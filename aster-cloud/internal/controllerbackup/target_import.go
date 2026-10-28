package controllerbackup

import (
	"aster/cloud/internal/control"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
)

type targetImportApproval struct {
	Schema          int                `json:"schema"`
	Plan            TargetDatabasePlan `json:"plan"`
	OwnershipSHA256 string             `json:"ownership_sha256"`
}
type TargetDataReport struct {
	Schema                int                   `json:"schema"`
	OperationID           string                `json:"operation_id"`
	DatabaseRestored      bool                  `json:"database_restored"`
	ReadOnlyVerification  bool                  `json:"read_only_verification"`
	Data                  DatabaseRestoreReport `json:"data"`
	TargetRestoreApproved bool                  `json:"target_restore_approved"`
	MigrationReady        bool                  `json:"migration_ready"`
}

// ImportTargetDatabase accepts ONLY fixed operation state. The root coordinator
// must approve the full root-visible empty inventory before the first import,
// and recheck root-visible objects/grants before every later status report.
// Once import-started exists, this command cannot repeat DDL or INSERT. An
// unknown response is resolved only by VerifyTargetDatabase's read-only check.
func ImportTargetDatabase(ctx context.Context, operation string) (TargetDataReport, error) {
	return targetData(ctx, operation, false, nil)
}
func VerifyTargetDatabase(ctx context.Context, operation string) (TargetDataReport, error) {
	return targetData(ctx, operation, true, nil)
}
func targetData(ctx context.Context, operation string, verify bool, afterVerified func(TargetPlan, string, *Archive, targetDatabase) error) (TargetDataReport, error) {
	var result TargetDataReport
	err := withTargetArchive(operation, func(plan TargetPlan, sha string, a *Archive) error {
		db, e := loadTargetDatabase(ctx, a, plan, sha)
		if e != nil {
			return e
		}
		dir := filepath.Join(targetRoot, operation, "database")
		raw, e := targetRead(filepath.Join(dir, "import-approval.json"), 32768)
		var approval targetImportApproval
		want := targetImportApproval{1, db.plan, digestBytes(db.ownerRaw)}
		if e != nil || !exactSourceRecord(raw, &approval) || !reflect.DeepEqual(approval, want) {
			return ErrInvalid
		}
		intent, e := json.Marshal(approval)
		if e != nil {
			return ErrInvalid
		}
		intent = append(intent, '\n')
		if e = checkTargetAccounts(ctx, db); e != nil {
			return e
		}
		started := filepath.Join(dir, "import-started.json")
		if verify {
			have, e := targetRead(started, 32768)
			if e != nil || !bytes.Equal(have, intent) {
				return ErrInvalid
			}
		} else {
			// O_EXCL + file and directory fsync precede every possible target
			// DDL/data write; corruption, interrupted write and replay all fail.
			if _, e := os.Lstat(filepath.Join(dir, "structure.json")); !os.IsNotExist(e) {
				return ErrInvalid
			}
			if e = writePrivateNew(started, intent); e != nil {
				return e
			}
		}
		store, e := control.OpenDSN(db.migrationDSN)
		if e != nil {
			return ErrInvalid
		}
		defer store.DB.Close()
		if !verify {
			_, e = a.RestoreRecoverableDatabase(ctx, store.DB, db.ownerRaw, db.runtimeDSN, func(proof []byte) error {
				return writePrivateNew(filepath.Join(dir, "structure.json"), proof)
			})
			if e != nil {
				return e
			}
		}
		proof, e := targetRead(filepath.Join(dir, "structure.json"), 65536)
		if e != nil {
			return e
		}
		confirmed, e := a.VerifyRestoredDatabase(ctx, store.DB, db.ownerRaw, db.runtimeDSN, proof)
		if e != nil {
			return e
		}
		result = TargetDataReport{Schema: 1, OperationID: operation, DatabaseRestored: true, ReadOnlyVerification: verify, Data: confirmed}
		if afterVerified != nil {
			return afterVerified(plan, sha, a, db)
		}
		return nil
	})
	if err != nil {
		return TargetDataReport{}, err
	}
	return result, nil
}

// RestoreTargetMaterials accepts only the existing operation's fixed private
// paths. Exact database readback and material writes share one target seal lock;
// an archived DSN, profile path or caller argument never chooses a destination.
func RestoreTargetMaterials(ctx context.Context, operation string, verifyOnly bool) (RuntimeMaterialReport, error) {
	var result RuntimeMaterialReport
	err := withTargetArchive(operation, func(plan TargetPlan, sha string, a *Archive) error {
		db, proof, e := importedTargetInputs(ctx, a, plan, sha)
		if e != nil {
			return e
		}
		target := RuntimeTarget{Directory: filepath.Join(targetRoot, operation), DSN: db.runtimeDSN, PlanSHA256: sha}
		store, e := control.OpenDSN(db.migrationDSN)
		if e != nil {
			return ErrInvalid
		}
		defer store.DB.Close()
		existing, e := targetSessionExists(operation)
		if e != nil {
			return e
		}
		if existing {
			binding, intent, e := targetSessionBinding(a, target, true)
			if e != nil {
				return e
			}
			if _, e = a.VerifyRevokedSessions(ctx, store.DB, db.ownerRaw, db.runtimeDSN, proof, binding, intent); e != nil {
				return e
			}
		} else if _, e = a.VerifyRestoredDatabase(ctx, store.DB, db.ownerRaw, db.runtimeDSN, proof); e != nil {
			return e
		}
		if verifyOnly {
			result, e = a.VerifyRuntimeMaterials(target)
		} else {
			result, e = a.RestoreRuntimeMaterials(target)
		}
		result.SessionsRevoked = existing
		return e
	})
	if err != nil {
		return RuntimeMaterialReport{}, err
	}
	return result, nil
}

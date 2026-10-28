package controllerbackup

import (
	"aster/cloud/internal/control"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"time"
)

// All inputs are fixed, protected operation files. This prerequisite does not
// choose a data phase: the caller must verify either the exact imported image
// or the explicit session-transition image before reporting success.
func importedTargetInputs(ctx context.Context, a *Archive, plan TargetPlan, sha string) (targetDatabase, []byte, error) {
	fail := func() (targetDatabase, []byte, error) { return targetDatabase{}, nil, ErrInvalid }
	db, e := loadTargetDatabase(ctx, a, plan, sha)
	if e != nil || checkTargetAccounts(ctx, db) != nil {
		return fail()
	}
	dir := filepath.Join(targetRoot, plan.OperationID, "database")
	raw, e := targetRead(filepath.Join(dir, "import-approval.json"), 32768)
	var approval targetImportApproval
	want := targetImportApproval{1, db.plan, digestBytes(db.ownerRaw)}
	if e != nil || !exactSourceRecord(raw, &approval) || !reflect.DeepEqual(approval, want) {
		return fail()
	}
	intent, e := json.Marshal(want)
	if e != nil {
		return fail()
	}
	started, e := targetRead(filepath.Join(dir, "import-started.json"), 32768)
	if e != nil || !bytes.Equal(started, append(intent, '\n')) {
		return fail()
	}
	proof, e := targetRead(filepath.Join(dir, "structure.json"), 65536)
	if e != nil {
		return fail()
	}
	return db, proof, nil
}

func targetSessionPath(operation string) string {
	return filepath.Join(targetRoot, operation, "sessions-started.json")
}

func targetSessionExists(operation string) (bool, error) {
	_, e := os.Lstat(targetSessionPath(operation))
	if os.IsNotExist(e) {
		return false, nil
	}
	if e != nil {
		return false, ErrInvalid
	}
	return true, nil
}

// The timestamp comes from the original protected intent on reentry, never a
// fresh clock/HTTP parameter. Both live material bytes and its manifest are
// rechecked before accepting this binding, including on status and recovery.
func targetSessionBinding(a *Archive, runtime RuntimeTarget, existing bool) (SessionTransitionBinding, []byte, error) {
	if _, e := a.VerifyRuntimeMaterials(runtime); e != nil {
		return SessionTransitionBinding{}, nil, ErrInvalid
	}
	manifest, e := targetRead(filepath.Join(runtime.Directory, "runtime", "manifest.json"), 65536)
	if e != nil {
		return SessionTransitionBinding{}, nil, ErrInvalid
	}
	b := SessionTransitionBinding{TargetPlanSHA256: runtime.PlanSHA256, MaterialManifestSHA256: digestBytes(manifest), CreatedAt: time.Now().UTC().Truncate(time.Microsecond)}
	if !existing {
		return b, nil, nil
	}
	raw, e := targetRead(filepath.Join(runtime.Directory, "sessions-started.json"), 65536)
	var intent sessionIntent
	if e != nil || !bytes.HasSuffix(raw, []byte("\n")) || !canonicalRecord(bytes.TrimSuffix(raw, []byte("\n")), &intent) {
		return SessionTransitionBinding{}, nil, ErrInvalid
	}
	b.CreatedAt, e = time.Parse(time.RFC3339Nano, intent.CreatedAt)
	if e != nil {
		return SessionTransitionBinding{}, nil, ErrInvalid
	}
	return b, raw, nil
}

// TargetSessions only operates on the already sealed/imported target. The
// root coordinator separately verifies global MySQL objects/grants and the
// unused host before calling this fixed entry. Reentry never retries a write;
// only the separately selected session-resume action can retry the same intent.
func TargetSessions(ctx context.Context, operation, action string) (SessionRevocationReport, error) {
	if action != "revoke-sessions" && action != "session-status" && action != "session-resume" {
		return SessionRevocationReport{}, ErrInvalid
	}
	var report SessionRevocationReport
	e := withTargetArchive(operation, func(plan TargetPlan, sha string, a *Archive) error {
		db, proof, e := importedTargetInputs(ctx, a, plan, sha)
		if e != nil {
			return e
		}
		existing, e := targetSessionExists(operation)
		if e != nil || !existing && action != "revoke-sessions" {
			return ErrInvalid
		}
		binding, intent, e := targetSessionBinding(a, RuntimeTarget{Directory: filepath.Join(targetRoot, operation), DSN: db.runtimeDSN, PlanSHA256: sha}, existing)
		if e != nil {
			return e
		}
		store, e := control.OpenDSN(db.migrationDSN)
		if e != nil {
			return ErrInvalid
		}
		defer store.DB.Close()
		if !existing {
			intent, e = a.PlanSessionRevocation(ctx, store.DB, db.ownerRaw, db.runtimeDSN, proof, binding)
			if e != nil {
				return e
			}
			if e = writePrivateNew(targetSessionPath(operation), intent); e != nil {
				return e
			}
			report, e = a.ApplySessionRevocation(ctx, store.DB, db.ownerRaw, db.runtimeDSN, proof, binding, intent)
		} else if action == "session-resume" {
			report, e = a.ResumeSessionRevocation(ctx, store.DB, db.ownerRaw, db.runtimeDSN, proof, binding, intent)
		} else {
			report, e = a.VerifyRevokedSessions(ctx, store.DB, db.ownerRaw, db.runtimeDSN, proof, binding, intent)
		}
		return e
	})
	if e != nil {
		return SessionRevocationReport{}, e
	}
	return report, nil
}

package controllerbackup

import (
	"aster/cloud/internal/control"
	"aster/cloud/internal/controllerhost"
	"aster/cloud/internal/verificationprocess"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
)

// VerificationSystemIdentity is supplied by the managed root coordinator only
// after checking its dedicated, locked, non-login OS account. Numeric IDs are
// not a public CLI option and a fixture's nobody identity is not that approval.
type VerificationSystemIdentity struct {
	UID uint32
	GID uint32
}

// RunTargetVerification joins the ORIGINAL installed-target approval to the
// isolated read-only service. It never returns credentials or admits ordinary
// workers. The managed caller holds its installation/target locks throughout,
// and approve must recheck the complete root-visible SQL account/object and OS
// inventory against the supplied freshly derived report. A cached preflight
// JSON, nil callback, or caller-chosen archive/UI/DSN is not an authority.
//
// This is for a dedicated, short-lived root coordinator ONLY: after acquiring
// independent guards, its parent guard intentionally survives until OS exit,
// including cleanup or handshake failure. Return must cause that process to
// exit. The root manager separately checks process/SQL drain and the original
// data phase before account revocation. Return is NOT migration readiness.
func RunTargetVerification(ctx context.Context, operation string, approve func(TargetVerificationRuntimeReport) (VerificationSystemIdentity, error)) error {
	if ctx == nil || ctx.Err() != nil || approve == nil || !operationID.MatchString(operation) || runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return ErrInvalid
	}
	var child *os.File
	defer func() {
		if child != nil {
			child.Close()
		}
	}()
	var cfg verificationprocess.Config
	_, err := planTargetArchiveMode(operation, true, func(plan TargetPlan, archive *Archive) error {
		// Do not call withTargetArchiveMode here: nesting its WithSealedTarget
		// around PrepareVerificationRuntime would reacquire the same lock.
		directory := filepath.Join(targetRoot, operation)
		raw, err := targetRead(filepath.Join(directory, "plan.json"), 4096)
		var approved TargetPlan
		if err != nil || !exactSourceRecord(raw, &approved) || approved != plan {
			return ErrInvalid
		}
		canonical, err := json.Marshal(approved)
		if err != nil {
			return ErrInvalid
		}
		planSHA := digestBytes(canonical)
		if _, err := targetRead(filepath.Join("/var/lib/aster-controller", plan.ControllerID, "target-restore.json"), 4096); err != nil {
			return err
		}
		host, err := controllerhost.Open(plan.ControllerID, plan.CanonicalConfigurationSHA256)
		if err != nil {
			return err
		}
		defer host.Close()
		child, err = host.PrepareVerificationRuntime(operation, planSHA, func() error {
			if _, err := archive.ValidateSource(plan.SourceCommit); err != nil {
				return err
			}
			if hash, err := targetHash(filepath.Join(directory, "backup.age")); err != nil || hash != plan.ArchiveSHA256 {
				return ErrInvalid
			}
			proof, dsn, err := targetVerificationRuntime(ctx, plan, planSHA, archive)
			if err != nil {
				return err
			}
			// The public phase proof has already checked exact published bytes.
			// Derive only configuration and TLS again from the same authenticated
			// archive; never call LoadConfig (it opens all production credentials).
			db, _, err := importedTargetInputs(ctx, archive, plan, planSHA)
			if err != nil {
				return err
			}
			target := RuntimeTarget{Directory: directory, DSN: db.runtimeDSN, PlanSHA256: planSHA}
			request, err := targetRead(filepath.Join(directory, "configuration-request.json"), 8192)
			if err != nil {
				return err
			}
			configuration, files, err := archive.configurationCandidate(target, request, proof.Phase.Plan.SessionIntentSHA256)
			if err != nil {
				return err
			}
			configurationRaw, err := json.Marshal(configuration)
			if err != nil || digestBytes(configurationRaw) != proof.Phase.Plan.ConfigurationPlanSHA256 {
				return ErrInvalid
			}
			controller, err := control.ParseConfig(files["config.json"])
			if err != nil || controller.ControllerID != plan.ControllerID || controller.Listen != proof.Phase.Plan.Listen {
				return ErrInvalid
			}
			if len(files["server.crt"]) == 0 || len(files["server.crt"]) > 64<<10 || len(files["server.key"]) == 0 || len(files["server.key"]) > 64<<10 {
				return ErrInvalid
			}
			executable, err := os.Executable() // exact installed path was checked above
			if err != nil {
				return ErrInvalid
			}
			ui := filepath.Join(filepath.Dir(filepath.Dir(executable)), "ui")
			if _, err := control.Web(ui); err != nil {
				return ErrInvalid
			}
			identity, err := approve(proof)
			if err != nil {
				return err
			}
			if identity.UID < 100 || identity.UID >= 65534 || identity.GID < 100 || identity.GID >= 65534 {
				return ErrInvalid
			}
			expires, err := verificationDeadline(ctx, proof.Phase)
			if err != nil {
				return err
			}
			cfg = verificationprocess.Config{Controller: controller, Operation: operation, Origin: proof.Phase.Plan.ConsoleOrigin,
				ExpiresAt: expires, UID: identity.UID, GID: identity.GID, DSN: dsn,
				CertificatePEM: files["server.crt"], PrivateKeyPEM: files["server.key"], UIDirectory: ui}
			return nil
		})
		return err
	})
	// planTargetArchiveMode does not return until WithVerifiedArchive has
	// invalidated its capability and successfully destroyed staged plaintext.
	// Even an approved child guard cannot bypass an archive cleanup failure.
	if err != nil {
		return err
	}
	if ctx.Err() != nil || child == nil {
		return ErrInvalid
	}
	return verificationprocess.Serve(ctx, child, cfg)
}

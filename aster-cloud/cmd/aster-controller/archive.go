package main

import (
	"aster/cloud/internal/controllerbackup"
	"context"
	"encoding/json"
	"flag"
	"io"
	"os"
	"time"
)

func inspectArchive(args []string) error {
	flags := flag.NewFlagSet("migration-inspect", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	archive := flags.String("archive", "", "private encrypted input")
	key := flags.String("key-file", "", "private recovery key input")
	controller := flags.String("controller-id", "", "independently expected source identity")
	operation := flags.String("operation", "", "independently expected operation identity")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return controllerbackup.ErrInvalid
	}
	proof, err := controllerbackup.InspectFiles(*archive, *key, *controller, *operation)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(proof)
}

// This command only validates an offline source package. It cannot create a
// database, write host configuration, unseal a source or authorize takeover.
func validateArchiveSource(args []string) error {
	flags := flag.NewFlagSet("migration-validate-source", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	archive := flags.String("archive", "", "private encrypted input")
	key := flags.String("key-file", "", "private recovery key input")
	controller := flags.String("controller-id", "", "independently expected source identity")
	operation := flags.String("operation", "", "independently expected operation identity")
	source := flags.String("source-commit", "", "independently approved exact source commit")
	stage := flags.String("staging-dir", "", "private temporary staging parent")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return controllerbackup.ErrInvalid
	}
	var report controllerbackup.SourceReport
	err := controllerbackup.WithVerifiedArchive(*archive, *key, *controller, *operation, *stage, func(a *controllerbackup.Archive) error {
		var e error
		report, e = a.ValidateSource(*source)
		return e
	})
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(report)
}

func targetArchive(command string, args []string) error {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	operation := flags.String("operation", "", "exact target operation identity")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return controllerbackup.ErrInvalid
	}
	var report any
	var err error
	if command == "migration-target-plan" {
		report, err = controllerbackup.PlanTarget(*operation)
	} else if command == "migration-target-database-plan" || command == "migration-target-provision-check" || command == "migration-target-import" || command == "migration-target-data-status" || command == "migration-target-materials" || command == "migration-target-material-status" || command == "migration-target-revoke-sessions" || command == "migration-target-session-status" || command == "migration-target-session-resume" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		if command == "migration-target-database-plan" {
			report, err = controllerbackup.PlanTargetDatabase(ctx, *operation)
		} else if command == "migration-target-import" {
			report, err = controllerbackup.ImportTargetDatabase(ctx, *operation)
		} else if command == "migration-target-data-status" {
			report, err = controllerbackup.VerifyTargetDatabase(ctx, *operation)
		} else if command == "migration-target-materials" || command == "migration-target-material-status" {
			report, err = controllerbackup.RestoreTargetMaterials(ctx, *operation, command == "migration-target-material-status")
		} else if command == "migration-target-revoke-sessions" || command == "migration-target-session-status" || command == "migration-target-session-resume" {
			report, err = controllerbackup.TargetSessions(ctx, *operation, command[len("migration-target-"):])
		} else {
			report, err = controllerbackup.CheckTargetProvision(ctx, *operation)
		}
	} else {
		report, err = controllerbackup.SealTarget(*operation, command == "migration-target-status")
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(report)
}

//go:build linux

package main

import (
	"aster/cloud/internal/controllerbackup"
	"os"
	"path/filepath"
	"testing"
)

func testConfigurationAtomicPublication(t *testing.T, a *controllerbackup.Archive, target controllerbackup.ConfigurationPublicationTarget, request, approval []byte, plan controllerbackup.ConfigurationPlan) {
	t.Helper()
	report, err := a.PublishConfiguration(target, request, approval, plan.SessionIntentSHA256)
	if err != nil {
		t.Fatal("approved atomic publication rejected", err)
	}
	if !report.ConfigurationPublished || report.ReadOnlyVerification || report.TargetActivationApproved || report.MigrationReady {
		t.Fatal("publication phase overclaimed", report)
	}
	for _, f := range plan.Files {
		raw, err := os.ReadFile(filepath.Join(target.ParentDirectory, "aster-controller", f.Name))
		if err != nil || sourceHash(raw) != f.SHA256 || len(raw) != int(f.Size) {
			t.Fatal("published bytes differ from approved plan", f.Name)
		}
	}
	completed := filepath.Join(target.ParentDirectory, "aster-controller")
	intentPath := filepath.Join(target.Runtime.Directory, "configuration-started.json")
	intent, err := os.ReadFile(intentPath)
	if err != nil {
		t.Fatal(err)
	}
	again, err := a.PublishConfiguration(target, request, approval, plan.SessionIntentSHA256)
	if err != nil || !again.ReadOnlyVerification || !again.ConfigurationPublished {
		t.Fatal("lost reply cannot be resolved read-only", err)
	}
	if _, err := a.ResumeConfigurationPublication(target, request, approval, plan.SessionIntentSHA256); err == nil {
		t.Fatal("explicit resume accepted completed publication")
	}
	// Reachable pre-rename interruption image: original durable intent, exact
	// partial files, no completion manifest. No production fault hooks exist.
	stage := filepath.Join(target.ParentDirectory, ".aster-controller-configuration-"+plan.OperationID)
	key, err := os.ReadFile(filepath.Join(completed, "server.key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(completed, stage); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"manifest.json", "server.key"} {
		if err := os.Remove(filepath.Join(stage, name)); err != nil {
			t.Fatal(err)
		}
	}
	for _, call := range []func() (controllerbackup.ConfigurationPublicationReport, error){
		func() (controllerbackup.ConfigurationPublicationReport, error) {
			return a.PublishConfiguration(target, request, approval, plan.SessionIntentSHA256)
		},
		func() (controllerbackup.ConfigurationPublicationReport, error) {
			return a.VerifyPublishedConfiguration(target, request, approval, plan.SessionIntentSHA256)
		},
	} {
		if _, err := call(); err == nil {
			t.Fatal("ordinary reentry silently repaired partial publication")
		}
	}
	if _, err := os.Lstat(filepath.Join(stage, "server.key")); !os.IsNotExist(err) {
		t.Fatal("ordinary reentry filled missing private key")
	}
	resumed, err := a.ResumeConfigurationPublication(target, request, approval, plan.SessionIntentSHA256)
	if err != nil || !resumed.ConfigurationPublished || resumed.ReadOnlyVerification {
		t.Fatal("explicit same-intent recovery failed", err)
	}
	if err := os.Rename(completed, stage); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "server.key"), []byte("PARTIAL"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ResumeConfigurationPublication(target, request, approval, plan.SessionIntentSHA256); err == nil {
		t.Fatal("corrupt partial file silently repaired")
	}
	got, err := os.ReadFile(filepath.Join(stage, "server.key"))
	if err != nil || string(got) != "PARTIAL" {
		t.Fatal("failed recovery overwrote evidence")
	}
	if err := os.WriteFile(filepath.Join(stage, "server.key"), key, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ResumeConfigurationPublication(target, request, approval, plan.SessionIntentSHA256); err != nil {
		t.Fatal("complete pre-rename stage could not resume", err)
	}
	got, err = os.ReadFile(intentPath)
	if err != nil || string(got) != string(intent) {
		t.Fatal("publication changed original intent")
	}
}

package main

import (
	"aster/cloud/internal/control"
	"aster/cloud/internal/controllerbackup"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The public readback boundary must distinguish an exact completed directory
// from an unapproved copy. This fixture writes actual files, never mocks crypto.
func testConfigurationPublicationApproval(t *testing.T, a *controllerbackup.Archive, target controllerbackup.RuntimeTarget, request []byte, plan controllerbackup.ConfigurationPlan) {
	t.Helper()
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	publication := controllerbackup.ConfigurationPublicationTarget{Runtime: target, ParentDirectory: parent}
	planRaw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	approval, err := json.Marshal(controllerbackup.ConfigurationApproval{Schema: 1, OperationID: plan.OperationID,
		TargetPlanSHA256: plan.TargetPlanSHA256, ConfigurationPlanSHA256: sourceHash(planRaw)})
	if err != nil {
		t.Fatal(err)
	}
	// An unknown phase must be rejected without creating any intent/directory.
	if _, err := a.VerifyPublishedConfiguration(publication, request, approval, plan.SessionIntentSHA256); err == nil {
		t.Fatal("missing publication reported complete")
	}
	if _, err := a.ResumeConfigurationPublication(publication, request, approval, plan.SessionIntentSHA256); err == nil {
		t.Fatal("resume silently started a new publication")
	}
	for _, bad := range [][]byte{nil, []byte(`{"schema":1}`), append(append([]byte{}, approval...), []byte(`{}`)...)} {
		if _, err := a.PublishConfiguration(publication, request, bad, plan.SessionIntentSHA256); err == nil {
			t.Fatal("unapproved configuration published")
		}
	}
	for _, name := range []string{"configuration-started.json"} {
		if _, err := os.Lstat(filepath.Join(target.Directory, name)); !os.IsNotExist(err) {
			t.Fatal("refused publication wrote intent")
		}
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatal("refused publication wrote host configuration")
	}
	// A self-claimed empty directory is never sufficient, even with approval.
	if err := os.Mkdir(filepath.Join(parent, "aster-controller"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := a.VerifyPublishedConfiguration(publication, request, approval, plan.SessionIntentSHA256); err == nil {
		t.Fatal("foreign directory adopted")
	}
	if err := os.Remove(filepath.Join(parent, "aster-controller")); err != nil {
		t.Fatal(err)
	}
	// Independently construct the documented complete on-disk image to test
	// readback on all hosts. This does NOT claim atomic publication on macOS.
	cfgRaw, err := os.ReadFile(filepath.Join(target.Directory, "runtime", "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := control.ParseConfig(cfgRaw)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Listen, cfg.TLSCertFile, cfg.TLSKeyFile = "127.0.0.1:9555", "/etc/aster-controller/server.crt", "/etc/aster-controller/server.key"
	cfgRaw, err = json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := os.ReadFile(filepath.Join(target.Directory, "configuration-tls.crt"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(filepath.Join(target.Directory, "configuration-tls.key"))
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(parent, "aster-controller")
	intent, err := json.Marshal(controllerbackup.ConfigurationPublicationIntent{Schema: 1, Destination: destination, ApprovalSHA256: sourceHash(approval), Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	intent = append(intent, '\n')
	files := map[string][]byte{"config.json": append(cfgRaw, '\n'), "console.json": []byte(`{"schema":1,"enabled":true,"origin":"https://console.target.invalid:9555"}` + "\n"), "server.crt": cert, "server.key": key, "manifest.json": intent}
	if err := os.Mkdir(destination, 0700); err != nil {
		t.Fatal(err)
	}
	for name, raw := range files {
		if err := os.WriteFile(filepath.Join(destination, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	intentPath := filepath.Join(target.Directory, "configuration-started.json")
	if err := os.WriteFile(intentPath, intent, 0600); err != nil {
		t.Fatal(err)
	}
	report, err := a.VerifyPublishedConfiguration(publication, request, approval, plan.SessionIntentSHA256)
	if err != nil || !report.ConfigurationPublished || !report.ReadOnlyVerification || report.TargetActivationApproved || report.MigrationReady || report.IntentSHA256 != sourceHash(intent) || report.PlanSHA256 != sourceHash(planRaw) {
		t.Fatal("approved exact directory not confirmed", err, report)
	}
	for name, raw := range files {
		t.Run("published drift "+name, func(t *testing.T) {
			file := filepath.Join(destination, name)
			if err := os.WriteFile(file, append(append([]byte{}, raw...), ' '), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := a.VerifyPublishedConfiguration(publication, request, approval, plan.SessionIntentSHA256); err == nil {
				t.Fatal("changed published bytes accepted")
			}
			got, err := os.ReadFile(file)
			if err != nil || len(got) != len(raw)+1 {
				t.Fatal("readback repaired changed bytes")
			}
			if err := os.WriteFile(file, raw, 0600); err != nil {
				t.Fatal(err)
			}
		})
	}
	file := filepath.Join(destination, "server.key")
	if err := os.Chmod(file, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := a.VerifyPublishedConfiguration(publication, request, approval, plan.SessionIntentSHA256); err == nil {
		t.Fatal("public private key accepted")
	}
	if err := os.Chmod(file, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "foreign-key-link")
	if err := os.Link(file, link); err != nil {
		t.Fatal(err)
	}
	if _, err := a.VerifyPublishedConfiguration(publication, request, approval, plan.SessionIntentSHA256); err == nil {
		t.Fatal("shared private key accepted")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(intentPath); err != nil {
		t.Fatal(err)
	}
	if _, err := a.VerifyPublishedConfiguration(publication, request, approval, plan.SessionIntentSHA256); err == nil {
		t.Fatal("self-reported manifest adopted without original intent")
	}
	if err := os.WriteFile(intentPath, intent, 0600); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(parent, ".aster-controller-configuration-"+plan.OperationID)
	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := a.VerifyPublishedConfiguration(publication, request, approval, plan.SessionIntentSHA256); err == nil {
		t.Fatal("ambiguous target plus stage accepted")
	}
	if err := os.Remove(stage); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(intentPath)
	if !bytes.Equal(before, intent) {
		t.Fatal("readback changed intent")
	}
	// Remove only this test-owned image; the next Linux-only test exercises the
	// real atomic publisher from a fresh filesystem, not this manual copy.
	if err := os.RemoveAll(destination); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(intentPath); err != nil {
		t.Fatal(err)
	}
	testConfigurationAtomicPublication(t, a, publication, request, approval, plan)
}

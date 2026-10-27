package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"filippo.io/age"
)

// This crosses the actual command interface. The fixture is encrypted by the
// upstream age API, not by the production exporter under test. Empty table
// files prove container integrity only, never a restorable database.
func TestControllerArchiveInspection(t *testing.T) {
	if os.Getenv("ASTER_ARCHIVE_CLI_HELPER") == "1" {
		os.Args = append([]string{"aster-controller"}, os.Args[3:]...)
		main()
		os.Exit(0)
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	key := "ASTER-CONTROLLER-RECOVERY-1:" + strings.Repeat("71", 32)
	files := map[string][]byte{
		"controller/materials.json": []byte("[]\n"),
		"controller/config.json":    []byte("{}\n"), "source/installation.json": []byte("{}\n"),
		"source/plan.json": []byte("{}\n"), "source/isolated.json": []byte("{}\n"),
	}
	// Independent inventory from the version-12 SQL migrations.
	for _, name := range strings.Fields(`controller_schema controller_lock controller_nodes controller_instances
controller_jobs controller_reservations controller_audit controller_identity_lock controller_console_users
controller_console_sessions controller_console_login_limits controller_identity_audit controller_operations
controller_artifacts controller_migrations controller_network_vpcs controller_network_pools controller_network_leases
controller_instance_networks controller_overlay_vpcs controller_overlay_epochs controller_overlay_tasks controller_overlay_members
controller_public_ip_pools controller_public_ip_inventory controller_public_ip_leases controller_public_ip_active
controller_public_ip_operations controller_public_ip_resources controller_public_ip_resource_operations controller_public_ip_bindings
controller_public_ingress_versions controller_public_ingress_operations controller_identity_operations`) {
		files["database/"+name+".jsonl"] = nil
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	entries := []map[string]any{}
	for _, name := range names {
		hash := sha256.Sum256(files[name])
		entries = append(entries, map[string]any{"name": name, "size": len(files[name]), "sha256": hex.EncodeToString(hash[:])})
	}
	planHash := sha256.Sum256(files["source/plan.json"])
	planDigest := hex.EncodeToString(planHash[:])
	manifest, _ := json.Marshal(map[string]any{
		"schema": 1, "protocol": "aster.controller-backup/1", "controller_id": "source-one",
		"operation_id": strings.Repeat("a", 32), "source_commit": strings.Repeat("b", 40),
		"schema_version": 12, "source_plan_sha256": planDigest, "files": entries,
	})
	var plain bytes.Buffer
	tw := tar.NewWriter(&plain)
	write := func(name string, raw []byte) {
		t.Helper()
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(raw)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(raw); err != nil {
			t.Fatal(err)
		}
	}
	write("manifest.json", manifest)
	for _, name := range names {
		write(name, files[name])
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	encrypt := func(raw []byte) []byte {
		t.Helper()
		recipient, err := age.NewScryptRecipient(key)
		if err != nil {
			t.Fatal(err)
		}
		recipient.SetWorkFactor(18)
		var encrypted bytes.Buffer
		w, err := age.Encrypt(&encrypted, recipient)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write(raw); err != nil {
			t.Fatal(err)
		}
		if err = w.Close(); err != nil {
			t.Fatal(err)
		}
		return encrypted.Bytes()
	}
	encrypted := encrypt(plain.Bytes())
	archive, keyFile := filepath.Join(dir, "backup.age"), filepath.Join(dir, "recovery.key")
	if err := os.WriteFile(archive, encrypted, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte(key+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	invoke := func() ([]byte, []byte, error) {
		cmd := exec.Command(os.Args[0], "-test.run=^TestControllerArchiveInspection$", "--", "migration-inspect",
			"-archive", archive, "-key-file", keyFile, "-controller-id", "source-one", "-operation", strings.Repeat("a", 32))
		cmd.Env = append(os.Environ(), "ASTER_ARCHIVE_CLI_HELPER=1")
		var out, diagnostic bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &diagnostic
		err := cmd.Run()
		return out.Bytes(), diagnostic.Bytes(), err
	}
	out, diagnostic, err := invoke()
	if err != nil {
		t.Fatalf("actual inspection failed: %v; %s", err, diagnostic)
	}
	var report map[string]any
	if json.Unmarshal(out, &report) != nil || report["authenticated"] != true || report["content_integrity_verified"] != true ||
		report["controller_id"] != "source-one" || report["entries"] != float64(39) || report["data_semantics_verified"] != false ||
		report["target_restore_approved"] != false || report["migration_ready"] != false {
		t.Fatalf("container proof must not claim restore approval: %s", out)
	}
	if bytes.Contains(out, []byte(key)) || len(diagnostic) != 0 {
		t.Fatal("private input was exposed")
	}
	after, err := os.ReadDir(dir)
	if err != nil || len(after) != 2 {
		t.Fatal("read-only inspection wrote host files")
	}
	refused := func(t *testing.T, ciphertext []byte) {
		t.Helper()
		if err := os.WriteFile(archive, ciphertext, 0600); err != nil {
			t.Fatal(err)
		}
		out, diagnostic, err := invoke()
		exit, ok := err.(*exec.ExitError)
		var event map[string]any
		if !ok || exit.ExitCode() != 1 || len(out) != 0 || json.Unmarshal(diagnostic, &event) != nil ||
			event["code"] != "COMMAND_FAILED" || event["component"] != "controller" || bytes.Contains(diagnostic, []byte(key)) {
			t.Fatalf("expected a complete fixed refusal, not crash/output: %v %q %q", err, out, diagnostic)
		}
	}
	t.Run("source plan digest must match its actual entry", func(t *testing.T) {
		bad := bytes.Replace(plain.Bytes(), []byte(`"source_plan_sha256":"`+planDigest+`"`),
			[]byte(`"source_plan_sha256":"`+strings.Repeat("c", 64)+`"`), 1)
		if bytes.Equal(bad, plain.Bytes()) {
			t.Fatal("fixture did not change")
		}
		refused(t, encrypt(bad))
	})
	t.Run("authenticated tar without its two EOF blocks is incomplete", func(t *testing.T) {
		refused(t, encrypt(plain.Bytes()[:plain.Len()-1024]))
	})
	t.Run("USTAR padding cannot carry undeclared content", func(t *testing.T) {
		if len(manifest)%512 == 0 {
			t.Fatal("fixture needs nonempty padding")
		}
		bad := bytes.Clone(plain.Bytes())
		bad[512+len(manifest)] = 'X'
		refused(t, encrypt(bad))
	})
	t.Run("wrong recovery key", func(t *testing.T) {
		if err := os.WriteFile(keyFile, []byte("ASTER-CONTROLLER-RECOVERY-1:"+strings.Repeat("72", 32)+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		refused(t, encrypted)
		if err := os.WriteFile(keyFile, []byte(key+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	})
	corrupt := bytes.Clone(encrypted)
	corrupt[len(corrupt)/2] ^= 1
	for name, raw := range map[string][]byte{
		"truncated age authentication": encrypted[:len(encrypted)-1],
		"truncated age body":           encrypted[:len(encrypted)/2],
		"ciphertext corruption":        corrupt,
		"trailing ciphertext":          append(bytes.Clone(encrypted), 0),
		"unencrypted container":        plain.Bytes(),
	} {
		t.Run(name, func(t *testing.T) { refused(t, raw) })
	}
	for name, raw := range map[string][]byte{
		"trailing plaintext":         append(bytes.Clone(plain.Bytes()), 'X'),
		"wrong source identity":      bytes.Replace(plain.Bytes(), []byte(`"controller_id":"source-one"`), []byte(`"controller_id":"source-two"`), 1),
		"wrong source operation":     bytes.Replace(plain.Bytes(), []byte(`"operation_id":"`+strings.Repeat("a", 32)+`"`), []byte(`"operation_id":"`+strings.Repeat("b", 32)+`"`), 1),
		"path traversal in manifest": bytes.Replace(plain.Bytes(), []byte(`"controller/config.json"`), []byte(`"../`+strings.Repeat("x", 19)+`"`), 1),
		"case alias in manifest":     bytes.Replace(plain.Bytes(), []byte(`"schema":1`), []byte(`"Schema":1`), 1),
	} {
		t.Run(name, func(t *testing.T) { refused(t, encrypt(raw)) })
	}
	t.Run("publicly readable recovery key", func(t *testing.T) {
		if err := os.Chmod(keyFile, 0644); err != nil {
			t.Fatal(err)
		}
		refused(t, encrypted)
		if err := os.Chmod(keyFile, 0600); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("hardlinked encrypted input", func(t *testing.T) {
		if err := os.WriteFile(archive, encrypted, 0600); err != nil {
			t.Fatal(err)
		}
		alias := filepath.Join(dir, "alias.age")
		if err := os.Link(archive, alias); err != nil {
			t.Fatal(err)
		}
		refused(t, encrypted)
		if err := os.Remove(alias); err != nil {
			t.Fatal(err)
		}
	})
	// A rejected input must not poison a later valid read or consume the key.
	if err := os.WriteFile(archive, encrypted, 0600); err != nil {
		t.Fatal(err)
	}
	if out, diagnostic, err := invoke(); err != nil || len(diagnostic) != 0 || len(out) == 0 {
		t.Fatal("valid archive no longer inspectable", err)
	}
}

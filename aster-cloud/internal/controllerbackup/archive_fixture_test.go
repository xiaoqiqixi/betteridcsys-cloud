package controllerbackup_test

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"filippo.io/age"
)

// Independent age/USTAR writer for the agreed actual-SQL boundary. These
// config placeholders deliberately do not authorize a host restore, a service
// activation or node takeover; this fixture proves database bytes only.
func encryptedSQLFixture(t *testing.T, files map[string][]byte, operation string) (string, string, string) {
	t.Helper()
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("private fixture directory required")
	}
	all := map[string][]byte{"controller/config.json": []byte("{}\n"), "controller/materials.json": []byte("[]\n"), "source/plan.json": []byte("{}\n"), "source/installation.json": []byte("{}\n"), "source/isolated.json": []byte("{}\n")}
	for name, raw := range files {
		all[name] = raw
	}
	var names []string
	for name := range all {
		names = append(names, name)
	}
	sort.Strings(names)
	var entries []map[string]any
	for _, name := range names {
		h := sha256.Sum256(all[name])
		entries = append(entries, map[string]any{"name": name, "size": len(all[name]), "sha256": hex.EncodeToString(h[:])})
	}
	plan := sha256.Sum256(all["source/plan.json"])
	manifest, e := json.Marshal(map[string]any{"schema": 1, "protocol": "aster.controller-backup/1", "controller_id": "source-sql-test", "operation_id": operation, "source_commit": strings.Repeat("c", 40), "schema_version": 12, "source_plan_sha256": hex.EncodeToString(plan[:]), "files": entries})
	if e != nil {
		t.Fatal(e)
	}
	var clear bytes.Buffer
	tw := tar.NewWriter(&clear)
	for _, name := range append([]string{"manifest.json"}, names...) {
		raw := all[name]
		if name == "manifest.json" {
			raw = manifest
		}
		if e = tw.WriteHeader(&tar.Header{Name: name, Size: int64(len(raw)), Mode: 0600, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); e != nil {
			t.Fatal(e)
		}
		if _, e = tw.Write(raw); e != nil {
			t.Fatal(e)
		}
	}
	if e = tw.Close(); e != nil {
		t.Fatal(e)
	}
	key := "ASTER-CONTROLLER-RECOVERY-1:" + strings.Repeat("71", 32)
	r, e := age.NewScryptRecipient(key)
	if e != nil {
		t.Fatal(e)
	}
	r.SetWorkFactor(18)
	var encrypted bytes.Buffer
	w, e := age.Encrypt(&encrypted, r)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = w.Write(clear.Bytes()); e != nil {
		t.Fatal(e)
	}
	if e = w.Close(); e != nil {
		t.Fatal(e)
	}
	archive, keyFile := filepath.Join(dir, "backup.age"), filepath.Join(dir, "recovery.key")
	if os.WriteFile(archive, encrypted.Bytes(), 0600) != nil || os.WriteFile(keyFile, []byte(key+"\n"), 0600) != nil {
		t.Fatal("cannot prepare private fixture")
	}
	return dir, archive, keyFile
}

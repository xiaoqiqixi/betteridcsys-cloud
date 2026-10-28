package main

import (
	"aster/cloud/internal/control"
	"aster/cloud/internal/controllerbackup"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestAuthenticatedRuntimeMaterialRestore(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	files := sourceWithNode(t, sourceFixture(t))
	key := controllerbackup.KeyPrefix + strings.Repeat("d", 64)
	archive, keyPath := filepath.Join(dir, "backup.age"), filepath.Join(dir, "recovery.key")
	if err = os.WriteFile(archive, sourceArchive(t, files, key), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyPath, []byte(key+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	operation := strings.Repeat("a", 32)
	target := controllerbackup.RuntimeTarget{Directory: dir, PlanSHA256: strings.Repeat("c", 64),
		DSN: "aster_r_" + operation[:23] + ":new-private-target-password@unix(/run/mysqld/mysqld.sock)/aster_cloud_restore_" + operation}
	// Authenticate the actual encrypted archive once for sequential target-file
	// faults. They change files, not ciphertext: repeated scrypt for chmod/link
	// provides no additional authentication coverage. Ciphertext faults remain
	// separate independently encrypted cases in the archive inspection tests.
	err = controllerbackup.WithVerifiedArchive(archive, keyPath, "source-one", operation, dir, func(a *controllerbackup.Archive) error {
		exerciseRuntimeMaterialRestore(t, a, files, target, dir)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// A separate reopening still proves authenticated durable reentry.
	if err := controllerbackup.WithVerifiedArchive(archive, keyPath, "source-one", operation, dir, func(a *controllerbackup.Archive) error {
		r, e := a.VerifyRuntimeMaterials(target)
		if e == nil && (!r.MaterialsStaged || !r.ReadOnlyVerification || r.MaterialReferences != 9) {
			t.Fatal("reopened stage unconfirmed")
		}
		return e
	}); err != nil {
		t.Fatal(err)
	}
}

func exerciseRuntimeMaterialRestore(t *testing.T, a *controllerbackup.Archive, files map[string][]byte, target controllerbackup.RuntimeTarget, dir string) {
	t.Helper()
	inArchive := func(fn func(*controllerbackup.Archive) error) error { return fn(a) }
	if err := inArchive(func(a *controllerbackup.Archive) error { _, e := a.VerifyRuntimeMaterials(target); return e }); err == nil {
		t.Fatal("readonly status created a missing material stage")
	}
	if _, err := os.Lstat(filepath.Join(dir, "materials-started.json")); !os.IsNotExist(err) {
		t.Fatal("readonly status wrote an intent")
	}
	if err := inArchive(func(a *controllerbackup.Archive) error {
		proof, e := a.RestoreRuntimeMaterials(target)
		if e != nil {
			return e
		}
		if !proof.MaterialsStaged || proof.ReadOnlyVerification || proof.MaterialReferences != 9 || proof.ConfigurationPublished || proof.SessionsRevoked || proof.MigrationReady {
			t.Fatal("material restore overclaims activation or does not cover all references")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	runtimeDir := filepath.Join(dir, "runtime")
	raw, err := os.ReadFile(filepath.Join(runtimeDir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := control.ParseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	original, err := control.ParseConfig(files["controller/config.json"])
	if err != nil {
		t.Fatal(err)
	}
	oldNode, _ := json.Marshal(original.Nodes[0])
	newNode, _ := json.Marshal(cfg.Nodes[0])
	if !bytes.Equal(oldNode, newNode) || cfg.Nodes[0].Digest() != original.Nodes[0].Digest() || cfg.ControllerID != original.ControllerID || cfg.Listen != original.Listen {
		t.Fatal("restoring material changed approved node identity or listener")
	}
	var index []map[string]string
	if err = json.Unmarshal(files["controller/materials.json"], &index); err != nil {
		t.Fatal(err)
	}
	byLabel := map[string][]byte{}
	for _, m := range index {
		byLabel[m["label"]] = files["materials/"+m["sha256"]+".bin"]
	}
	refs, err := cfg.RuntimeMaterials()
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range refs {
		if filepath.Dir(ref.Path) != runtimeDir {
			t.Fatal("reference escaped owned runtime directory")
		}
		data, e := os.ReadFile(ref.Path)
		if e != nil {
			t.Fatal(e)
		}
		want := byLabel[ref.Label]
		if ref.Label == "dsn_file" {
			want = []byte(target.DSN)
		}
		if !bytes.Equal(data, want) {
			t.Fatal("material differs from independent source or target credential")
		}
		st, e := os.Lstat(ref.Path)
		if e != nil || st.Mode().Perm() != 0600 || !st.Mode().IsRegular() {
			t.Fatal("private material protection lost")
		}
	}
	keyFile := cfg.NodeMaterials[0].ClientKeyFile
	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	keyInfo, err := os.Stat(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range mustRuntimeEntries(t, runtimeDir) {
		raw, e := os.ReadFile(filepath.Join(runtimeDir, entry.Name()))
		if e != nil {
			t.Fatal(e)
		}
		if bytes.Contains(raw, byLabel["dsn_file"]) {
			t.Fatal("source database credential copied to target runtime")
		}
	}
	repeat := func() error {
		return inArchive(func(a *controllerbackup.Archive) error {
			proof, e := a.RestoreRuntimeMaterials(target)
			if e == nil && (!proof.MaterialsStaged || !proof.ReadOnlyVerification) {
				t.Fatal("repeat did not perform readonly verification")
			}
			return e
		})
	}
	if err = repeat(); err != nil {
		t.Fatal("repeat refused unchanged material", err)
	}
	current, err := os.Stat(keyFile)
	if err != nil || !os.SameFile(keyInfo, current) || !keyInfo.ModTime().Equal(current.ModTime()) {
		t.Fatal("readonly repeat rewrote the credential")
	}
	for _, name := range []string{"changed", "shared", "linked", "shared_directory", "missing_manifest", "missing_intent", "foreign_file"} {
		t.Run(name, func(t *testing.T) {
			check := func(e error) {
				t.Helper()
				if e != nil {
					t.Fatal(e)
				}
			}
			switch name {
			case "changed":
				check(os.WriteFile(keyFile, append(append([]byte{}, keyBytes...), '\n'), 0600))
				defer func() { check(os.WriteFile(keyFile, keyBytes, 0600)) }()
			case "shared":
				check(os.Chmod(keyFile, 0644))
				defer func() { check(os.Chmod(keyFile, 0600)) }()
			case "linked":
				check(os.Link(keyFile, filepath.Join(dir, "key-alias")))
				defer func() { check(os.Remove(filepath.Join(dir, "key-alias"))) }()
			case "shared_directory":
				check(os.Chmod(runtimeDir, 0755))
				defer func() { check(os.Chmod(runtimeDir, 0700)) }()
			case "missing_manifest", "missing_intent":
				path := filepath.Join(runtimeDir, "manifest.json")
				if name == "missing_intent" {
					path = filepath.Join(dir, "materials-started.json")
				}
				check(os.Rename(path, path+".held"))
				defer func() { check(os.Rename(path+".held", path)) }()
			case "foreign_file":
				path := filepath.Join(runtimeDir, "unapproved")
				check(os.WriteFile(path, []byte("unapproved"), 0600))
				defer func() { check(os.Remove(path)) }()
			}
			if e := repeat(); e == nil {
				t.Fatal("unsafe stage accepted or overwritten")
			}
			if name == "changed" {
				got, e := os.ReadFile(keyFile)
				check(e)
				if bytes.Equal(got, keyBytes) {
					t.Fatal("refusal repaired changed material")
				}
			}
		})
	}
	if err = repeat(); err != nil {
		t.Fatal("fault-injection cleanup did not restore original state", err)
	}
}

func mustRuntimeEntries(t *testing.T, dir string) []os.DirEntry {
	t.Helper()
	entries, e := os.ReadDir(dir)
	if e != nil {
		t.Fatal(e)
	}
	return entries
}

func TestRuntimeMaterialRestoreAll64ApprovedNodes(t *testing.T) {
	files := sourceWithNode(t, sourceFixture(t))
	var document map[string]any
	var index []map[string]string
	if json.Unmarshal(files["controller/config.json"], &document) != nil || json.Unmarshal(files["controller/materials.json"], &index) != nil {
		t.Fatal("fixture JSON")
	}
	node := document["nodes"].([]any)[0].(map[string]any)
	var nodes []any
	var materials []map[string]string
	for _, entry := range index {
		if !strings.Contains(entry["label"], ":") {
			materials = append(materials, entry)
		}
	}
	for i := 0; i < 64; i++ {
		id := fmt.Sprintf("node-%02d", i)
		n := map[string]any{}
		for k, v := range node {
			n[k] = v
		}
		n["id"] = id
		nodes = append(nodes, n)
		for _, entry := range index {
			if field, ok := strings.CutPrefix(entry["label"], "fixture-node:"); ok {
				materials = append(materials, map[string]string{"label": id + ":" + field, "path": entry["path"], "sha256": entry["sha256"]})
			}
		}
	}
	document["nodes"] = nodes
	sort.Slice(materials, func(i, j int) bool { return materials[i]["label"] < materials[j]["label"] })
	files["controller/config.json"], files["controller/materials.json"] = sourceJSON(document), sourceJSON(materials)
	sourceRebind(t, files)
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	key := controllerbackup.KeyPrefix + strings.Repeat("d", 64)
	archive, keyPath := filepath.Join(dir, "backup.age"), filepath.Join(dir, "recovery.key")
	if e = os.WriteFile(archive, sourceArchive(t, files, key), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(keyPath, []byte(key+"\n"), 0600); e != nil {
		t.Fatal(e)
	}
	op := strings.Repeat("a", 32)
	e = controllerbackup.WithVerifiedArchive(archive, keyPath, "source-one", op, dir, func(a *controllerbackup.Archive) error {
		r, e := a.RestoreRuntimeMaterials(controllerbackup.RuntimeTarget{Directory: dir, PlanSHA256: strings.Repeat("c", 64), DSN: "aster_r_" + op[:23] + ":new-private-target-password@unix(/run/mysqld/mysqld.sock)/aster_cloud_restore_" + op})
		if e == nil && r.MaterialReferences != 198 {
			t.Fatal("approved node material capacity reduced")
		}
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join(dir, "runtime/config.json"))
	if e != nil {
		t.Fatal(e)
	}
	c, e := control.ParseConfig(raw)
	if e != nil || len(c.Nodes) != 64 || len(c.NodeMaterials) != 64 {
		t.Fatal("full configuration cannot reload", e)
	}
}

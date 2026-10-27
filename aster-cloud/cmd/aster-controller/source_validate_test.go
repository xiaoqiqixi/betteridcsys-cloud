package main

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

func sourceHash(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func sourceJSON(value any) []byte {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return raw
}

// Absent source paths are intentional: only authenticated staged bytes may be
// read, never source file references or source database/network endpoints.
func sourceFixture(t *testing.T) map[string][]byte {
	t.Helper()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Offline source fixture"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"source.invalid"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	keyDER, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	config := map[string]any{"schema": 1, "controller_id": "source-one", "listen": "127.0.0.1:9443", "heartbeat_ttl_seconds": 60, "nodes": []any{}, "presets": []any{}}
	labels := []string{"dsn_file", "tls_cert_file", "tls_key_file", "billing_token_file", "admin_read_token_file", "admin_write_token_file"}
	values := [][]byte{[]byte("aster_source:private-password@unix(/unavailable-source/mysql.sock)/aster_cloud_source?parseTime=true"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), []byte(strings.Repeat("b", 64)), []byte(strings.Repeat("r", 64)), []byte(strings.Repeat("w", 64))}
	files := map[string][]byte{"database/schema.json": []byte(`{"schema":1,"charset":"utf8mb4","collation":"utf8mb4_bin"}`)}
	var materials []map[string]string
	var digestInput bytes.Buffer
	for i, label := range labels {
		path := "/unavailable-source/" + label
		config[label] = path
		sha := sourceHash(values[i])
		files["materials/"+sha+".bin"] = values[i]
		materials = append(materials, map[string]string{"label": label, "path": path, "sha256": sha})
		digestInput.Write(sourceJSON([]string{label, path, sha}))
		digestInput.WriteByte('\n')
	}
	sort.Slice(materials, func(i, j int) bool { return materials[i]["label"] < materials[j]["label"] })
	files["controller/materials.json"] = sourceJSON(materials)
	files["controller/config.json"] = sourceJSON(config)
	files["source/installation.json"] = sourceJSON(map[string]any{"schema": 1, "component": "controller", "version": "0.1.0-dev.1", "bundle_sha256": strings.Repeat("d", 64), "source_commit": strings.Repeat("b", 40), "steps": []string{"software-installed", "configuration-approved", "inactive-systemd-unit"}, "status": "configuration-approved", "configuration": "approved", "service": "not-started", "current_step": nil, "native_options": map[string]bool{"install_dependencies": false, "provision_mysql": false, "prepare_libvirt": false}})
	identity := map[string]string{"controller_id": "source-one", "configuration_sha256": sourceHash(files["controller/config.json"]), "installation_sha256": sourceHash(files["source/installation.json"]), "manifest_sha256": strings.Repeat("c", 64), "source_commit": strings.Repeat("b", 40), "bundle_sha256": strings.Repeat("d", 64), "machine_id_sha256": strings.Repeat("e", 64), "runtime_materials_sha256": sourceHash(digestInput.Bytes())}
	files["source/plan.json"] = sourceJSON(map[string]any{"schema": 1, "identity": identity, "units": []any{map[string]any{"name": "aster-controller.service", "fragment": "/etc/systemd/system/aster-controller.service", "sha256": strings.Repeat("f", 64), "original_inode": map[string]int{"device": 1, "inode": 2}, "control_group": "/system.slice/aster-controller.service", "enabled": "disabled", "index": 0}}})
	files["source/isolated.json"] = sourceJSON(map[string]any{"schema": 1, "operation_id": strings.Repeat("a", 32), "identity": identity})
	for _, name := range strings.Fields(`controller_schema controller_lock controller_nodes controller_instances controller_jobs controller_reservations controller_audit controller_identity_lock controller_console_users controller_console_sessions controller_console_login_limits controller_identity_audit controller_operations controller_artifacts controller_migrations controller_network_vpcs controller_network_pools controller_network_leases controller_instance_networks controller_overlay_vpcs controller_overlay_epochs controller_overlay_tasks controller_overlay_members controller_public_ip_pools controller_public_ip_inventory controller_public_ip_leases controller_public_ip_active controller_public_ip_operations controller_public_ip_resources controller_public_ip_resource_operations controller_public_ip_bindings controller_public_ingress_versions controller_public_ingress_operations controller_identity_operations`) {
		files["database/"+name+".jsonl"] = nil
	}
	return files
}
func sourceArchive(t *testing.T, files map[string][]byte, key string) []byte {
	t.Helper()
	var names []string
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var entries []map[string]any
	for _, name := range names {
		entries = append(entries, map[string]any{"name": name, "size": len(files[name]), "sha256": sourceHash(files[name])})
	}
	manifest := sourceJSON(map[string]any{"schema": 1, "protocol": "aster.controller-backup/1", "controller_id": "source-one", "operation_id": strings.Repeat("a", 32), "source_commit": strings.Repeat("b", 40), "schema_version": 12, "source_plan_sha256": sourceHash(files["source/plan.json"]), "files": entries})
	var plaintext bytes.Buffer
	tw := tar.NewWriter(&plaintext)
	for _, name := range append([]string{"manifest.json"}, names...) {
		raw := files[name]
		if name == "manifest.json" {
			raw = manifest
		}
		if e := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(raw)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); e != nil {
			t.Fatal(e)
		}
		if _, e := tw.Write(raw); e != nil {
			t.Fatal(e)
		}
	}
	if e := tw.Close(); e != nil {
		t.Fatal(e)
	}
	recipient, e := age.NewScryptRecipient(key)
	if e != nil {
		t.Fatal(e)
	}
	recipient.SetWorkFactor(18)
	var ciphertext bytes.Buffer
	w, e := age.Encrypt(&ciphertext, recipient)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = w.Write(plaintext.Bytes()); e != nil {
		t.Fatal(e)
	}
	if e = w.Close(); e != nil {
		t.Fatal(e)
	}
	return ciphertext.Bytes()
}
func TestControllerSourceValidation(t *testing.T) {
	if os.Getenv("ASTER_SOURCE_CLI_HELPER") == "1" {
		os.Args = append([]string{"aster-controller"}, os.Args[3:]...)
		main()
		os.Exit(0)
	}
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	archive, keyFile := filepath.Join(dir, "backup.age"), filepath.Join(dir, "recovery.key")
	key := "ASTER-CONTROLLER-RECOVERY-1:" + strings.Repeat("71", 32)
	if e = os.WriteFile(keyFile, []byte(key+"\n"), 0600); e != nil {
		t.Fatal(e)
	}
	files := sourceFixture(t)
	if e = os.WriteFile(archive, sourceArchive(t, files, key), 0600); e != nil {
		t.Fatal(e)
	}
	expectedSource := strings.Repeat("b", 40)
	invoke := func() ([]byte, []byte, error) {
		cmd := exec.Command(os.Args[0], "-test.run=^TestControllerSourceValidation$", "--", "migration-validate-source", "-archive", archive, "-key-file", keyFile, "-controller-id", "source-one", "-operation", strings.Repeat("a", 32), "-source-commit", expectedSource, "-staging-dir", dir)
		cmd.Env = append(os.Environ(), "ASTER_SOURCE_CLI_HELPER=1")
		var out, diag bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &diag
		e := cmd.Run()
		return out.Bytes(), diag.Bytes(), e
	}
	out, diag, e := invoke()
	if e != nil || len(diag) != 0 {
		t.Fatalf("source validation command: %v %s", e, diag)
	}
	var report map[string]any
	if json.Unmarshal(out, &report) != nil || report["source_bindings_verified"] != true || report["runtime_materials_verified"] != true || report["material_references"] != float64(6) || report["database_semantics_verified"] != false || report["target_restore_approved"] != false || report["migration_ready"] != false || report["publisher_provenance_verified"] != false {
		t.Fatalf("overclaimed or missing offline evidence: %s", out)
	}
	for _, secret := range []string{key, "private-password", "/unavailable-source/", strings.Repeat("r", 64)} {
		if bytes.Contains(out, []byte(secret)) {
			t.Fatal("private data exposed")
		}
	}

	refused := func(t *testing.T, candidate map[string][]byte) {
		t.Helper()
		if e := os.WriteFile(archive, sourceArchive(t, candidate, key), 0600); e != nil {
			t.Fatal(e)
		}
		out, diag, e := invoke()
		exit, ok := e.(*exec.ExitError)
		var event map[string]any
		if !ok || exit.ExitCode() != 1 || len(out) != 0 || json.Unmarshal(diag, &event) != nil || event["code"] != "COMMAND_FAILED" || event["component"] != "controller" {
			t.Fatalf("expected complete redacted refusal, not success/crash: %v %s %s", e, out, diag)
		}
		if bytes.Contains(diag, []byte("private-password")) || bytes.Contains(diag, []byte(key)) {
			t.Fatal("secret leaked in refusal")
		}
		entries, e := os.ReadDir(dir)
		if e != nil || len(entries) != 2 {
			t.Fatal("rejected input left staged plaintext")
		}
	}

	t.Run("independently supplied source SHA", func(t *testing.T) {
		expectedSource = strings.Repeat("c", 40)
		defer func() { expectedSource = strings.Repeat("b", 40) }()
		refused(t, files)
	})
	t.Run("Unicode node material paths and deduplication", func(t *testing.T) {
		candidate := sourceWithNode(t, files)
		if e := os.WriteFile(archive, sourceArchive(t, candidate, key), 0600); e != nil {
			t.Fatal(e)
		}
		out, diag, e := invoke()
		var proof map[string]any
		if e != nil || len(diag) != 0 || json.Unmarshal(out, &proof) != nil || proof["material_references"] != float64(9) {
			t.Fatalf("Python-source digest interoperability: %v %s %s", e, out, diag)
		}
	})
	t.Run("archived source owner binds to archived DSN only", func(t *testing.T) {
		candidate := map[string][]byte{}
		for k, v := range files {
			candidate[k] = bytes.Clone(v)
		}
		candidate["source/database-ownership.json"] = sourceJSON(map[string]any{"schema": 1, "database": "aster_cloud_source", "runtime_user": "aster_source", "migration_user": "aster_migration", "server_uuid": "12345678-1234-1234-1234-123456789abc", "nonce": strings.Repeat("9", 64), "steps": []string{"database-created", "runtime-created", "runtime-granted", "migration-created", "migration-granted"}, "status": "dedicated-database-provisioned"})
		if e := os.WriteFile(archive, sourceArchive(t, candidate, key), 0600); e != nil {
			t.Fatal(e)
		}
		out, diag, e := invoke()
		if e != nil || len(diag) != 0 || len(out) == 0 {
			t.Fatalf("valid archived ownership: %v %s", e, diag)
		}
		candidate["source/database-ownership.json"] = bytes.Replace(candidate["source/database-ownership.json"], []byte("aster_cloud_source"), []byte("aster_cloud_foreign"), 1)
		refused(t, candidate)
	})
	for name, change := range map[string]func(map[string][]byte){
		"authenticated but invalid TLS key": func(f map[string][]byte) { sourceReplaceMaterial(t, f, "tls_key_file", []byte("not a key")) },
		"unsafe source DSN option": func(f map[string][]byte) {
			sourceReplaceMaterial(t, f, "dsn_file", []byte("aster_source:private-password@unix(/unavailable-source/mysql.sock)/aster_cloud_source?multiStatements=true"))
		},
		"duplicate access tokens": func(f map[string][]byte) {
			sourceReplaceMaterial(t, f, "admin_write_token_file", []byte(strings.Repeat("r", 64)))
		},
		"unreferenced encrypted material": func(f map[string][]byte) {
			raw := []byte("unrelated secret")
			f["materials/"+sourceHash(raw)+".bin"] = raw
		},
		"changed config source binding": func(f map[string][]byte) {
			f["controller/config.json"] = bytes.Replace(f["controller/config.json"], []byte("127.0.0.1:9443"), []byte("127.0.0.1:9444"), 1)
		},
		"case alias in config": func(f map[string][]byte) {
			f["controller/config.json"] = bytes.Replace(f["controller/config.json"], []byte(`"schema"`), []byte(`"Schema"`), 1)
			sourceRebind(t, f)
		},
		"duplicate config key": func(f map[string][]byte) {
			f["controller/config.json"] = bytes.Replace(f["controller/config.json"], []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1)
			sourceRebind(t, f)
		},
		"duplicate plan key": func(f map[string][]byte) {
			f["source/plan.json"] = bytes.Replace(f["source/plan.json"], []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1)
		},
		"case alias in source receipt": func(f map[string][]byte) {
			f["source/isolated.json"] = bytes.Replace(f["source/isolated.json"], []byte(`"schema"`), []byte(`"Schema"`), 1)
		},
		"different isolation operation": func(f map[string][]byte) {
			f["source/isolated.json"] = bytes.Replace(f["source/isolated.json"], []byte(strings.Repeat("a", 32)), []byte(strings.Repeat("c", 32)), 1)
		},
		"failed managed installation": func(f map[string][]byte) {
			f["source/installation.json"] = bytes.Replace(f["source/installation.json"], []byte(`"status":"configuration-approved"`), []byte(`"status":"failed"`), 1)
			sourceRebind(t, f)
		},
		"unmanaged startup unit": func(f map[string][]byte) {
			f["source/plan.json"] = bytes.ReplaceAll(f["source/plan.json"], []byte("aster-controller.service"), []byte("arbitrary-root.service"))
		},
		"invalid optional database owner": func(f map[string][]byte) { f["source/database-ownership.json"] = []byte("{}") },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := map[string][]byte{}
			for k, v := range files {
				candidate[k] = bytes.Clone(v)
			}
			change(candidate)
			refused(t, candidate)
		})
	}

	for _, label := range []string{"fixture-node:ca_file", "fixture-node:client_key_file"} {
		t.Run("invalid node material "+label, func(t *testing.T) {
			candidate := sourceWithNode(t, files)
			sourceReplaceMaterial(t, candidate, label, []byte("invalid TLS material"))
			refused(t, candidate)
		})
	}
	// A complete authenticated source must remain valid after all refusals.
	if e := os.WriteFile(archive, sourceArchive(t, files, key), 0600); e != nil {
		t.Fatal(e)
	}
	if _, diag, e := invoke(); e != nil || len(diag) != 0 {
		t.Fatal("prior refusal poisoned a valid archive", e)
	}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 2 {
		t.Fatal("staged plaintext was not cleaned")
	}
}

// Independent Python encoder checks interoperability with the already-shipped
// source coordinator (ensure_ascii, sorted node order), including non-BMP paths.
func sourceRebind(t *testing.T, files map[string][]byte) {
	t.Helper()
	var config map[string]any
	var materials []map[string]string
	var plan, receipt map[string]any
	for name, target := range map[string]any{"controller/config.json": &config, "controller/materials.json": &materials, "source/plan.json": &plan, "source/isolated.json": &receipt} {
		if e := json.Unmarshal(files[name], target); e != nil {
			t.Fatal(e)
		}
	}
	cmd := exec.Command("python3", "-I", "-c", `import json,hashlib,sys
c,m=json.load(sys.stdin); m={x['label']:x for x in m}
labels=['dsn_file','tls_cert_file','tls_key_file','billing_token_file','admin_read_token_file','admin_write_token_file']
for n in sorted(c['nodes'],key=lambda n:n['id']):
 labels.extend(n['id']+':'+s for s in ['ca_file','client_cert_file','client_key_file'])
h=hashlib.sha256()
for label in labels:
 x=m[label];h.update(json.dumps([label,x['path'],x['sha256']],separators=(',',':')).encode()+b'\n')
print(h.hexdigest())`)
	cmd.Stdin = bytes.NewReader(sourceJSON([]any{config, materials}))
	out, e := cmd.Output()
	if e != nil {
		t.Fatal(e)
	}
	id := plan["identity"].(map[string]any)
	id["configuration_sha256"] = sourceHash(files["controller/config.json"])
	id["installation_sha256"] = sourceHash(files["source/installation.json"])
	id["runtime_materials_sha256"] = strings.TrimSpace(string(out))
	receipt["identity"] = id
	files["source/plan.json"] = sourceJSON(plan)
	files["source/isolated.json"] = sourceJSON(receipt)
}

func sourceReplaceMaterial(t *testing.T, files map[string][]byte, label string, raw []byte) {
	t.Helper()
	var index []map[string]string
	if e := json.Unmarshal(files["controller/materials.json"], &index); e != nil {
		t.Fatal(e)
	}
	old := ""
	for _, m := range index {
		if m["label"] == label {
			old = m["sha256"]
			m["sha256"] = sourceHash(raw)
		}
	}
	if old == "" {
		t.Fatal("fixture material missing")
	}
	used := false
	for _, m := range index {
		used = used || m["sha256"] == old
	}
	if !used {
		delete(files, "materials/"+old+".bin")
	}
	files["materials/"+sourceHash(raw)+".bin"] = raw
	files["controller/materials.json"] = sourceJSON(index)
	sourceRebind(t, files)
}

func sourceWithNode(t *testing.T, original map[string][]byte) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	for k, v := range original {
		files[k] = bytes.Clone(v)
	}
	var config map[string]any
	var index []map[string]string
	if json.Unmarshal(files["controller/config.json"], &config) != nil || json.Unmarshal(files["controller/materials.json"], &index) != nil {
		t.Fatal("fixture JSON")
	}
	hashes := map[string]string{}
	for _, m := range index {
		hashes[m["label"]] = m["sha256"]
	}
	node := map[string]any{"id": "fixture-node", "datacenter_id": "fixture", "group_id": "fixture", "endpoint": "https://node.invalid:9443", "allowed_cidrs": []string{"192.0.2.0/24"}, "server_certificate_sha256": strings.Repeat("7", 64)}
	for field, source := range map[string]string{"ca_file": "tls_cert_file", "client_cert_file": "tls_cert_file", "client_key_file": "tls_key_file"} {
		path := "/unavailable-source/节点😀<&>/" + field
		node[field] = path
		index = append(index, map[string]string{"label": "fixture-node:" + field, "path": path, "sha256": hashes[source]})
	}
	sort.Slice(index, func(i, j int) bool { return index[i]["label"] < index[j]["label"] })
	config["nodes"] = []any{node}
	files["controller/config.json"] = sourceJSON(config)
	files["controller/materials.json"] = sourceJSON(index)
	sourceRebind(t, files)
	return files
}

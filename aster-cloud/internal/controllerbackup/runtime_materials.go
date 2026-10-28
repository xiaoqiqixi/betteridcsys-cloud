package controllerbackup

import (
	"aster/cloud/internal/control"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/go-sql-driver/mysql"
)

// RuntimeTarget is supplied by the sealed target coordinator, never by an HTTP
// request or an archived pathname. This library interface writes only a private
// candidate; it does not authorize service startup, SQL access or node takeover.
type RuntimeTarget struct{ Directory, DSN, PlanSHA256 string }

type RuntimeMaterialReport struct {
	Schema                 int    `json:"schema"`
	OperationID            string `json:"operation_id"`
	MaterialReferences     int    `json:"material_references"`
	MaterialsStaged        bool   `json:"materials_staged"`
	ReadOnlyVerification   bool   `json:"read_only_verification"`
	ConfigurationPublished bool   `json:"configuration_published"`
	SessionsRevoked        bool   `json:"sessions_revoked"`
	MigrationReady         bool   `json:"migration_ready"`
}

type runtimeManifest struct {
	Schema               int     `json:"schema"`
	OperationID          string  `json:"operation_id"`
	ControllerID         string  `json:"controller_id"`
	TargetPlanSHA256     string  `json:"target_plan_sha256"`
	SourceManifestSHA256 string  `json:"source_manifest_sha256"`
	Files                []Entry `json:"files"`
}

func privateRuntimeDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n") {
		return ErrInvalid
	}
	for current := path; ; current = filepath.Dir(current) {
		st, e := os.Lstat(current)
		if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return ErrInvalid
		}
		native, ok := st.Sys().(*syscall.Stat_t)
		if !ok || native.Uid != 0 && native.Uid != uint32(os.Geteuid()) || st.Mode().Perm()&0022 != 0 && !(native.Uid == 0 && st.Mode()&os.ModeSticky != 0) {
			return ErrInvalid
		}
		if current == path && (native.Uid != uint32(os.Geteuid()) || st.Mode().Perm() != 0700 || st.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0) {
			return ErrInvalid
		}
		if current == "/" {
			return nil
		}
	}
}

func (a *Archive) runtimeCandidate(target RuntimeTarget) (map[string][]byte, []byte, int, error) {
	fail := func() (map[string][]byte, []byte, int, error) { return nil, nil, 0, ErrInvalid }
	if a == nil || !a.valid || !shaPattern.MatchString(target.PlanSHA256) || privateRuntimeDirectory(target.Directory) != nil {
		return fail()
	}
	if _, e := a.ValidateSource(a.manifest.SourceCommit); e != nil {
		return fail()
	}
	op := a.manifest.OperationID
	dsn, e := mysql.ParseDSN(target.DSN)
	if e != nil || len(target.DSN) > 4096 || len(dsn.Passwd) < 16 || strings.ContainsAny(target.DSN, "\x00\r\n") ||
		dsn.User != "aster_r_"+op[:23] || dsn.DBName != "aster_cloud_restore_"+op || dsn.Net != "unix" || dsn.Addr != "/run/mysqld/mysqld.sock" ||
		target.DSN != dsn.User+":"+dsn.Passwd+"@unix(/run/mysqld/mysqld.sock)/"+dsn.DBName {
		return fail()
	}
	raw, e := a.readSmall("controller/config.json", control.MaxConfigBytes)
	if e != nil {
		return fail()
	}
	c, e := control.ParseConfig(raw)
	if e != nil {
		return fail()
	}
	refs, e := c.RuntimeMaterials()
	if e != nil {
		return fail()
	}
	var index []Material
	if _, e = a.sourceRecord("controller/materials.json", 256<<10, &index); e != nil {
		return fail()
	}
	byLabel := map[string]Material{}
	for _, m := range index {
		byLabel[m.Label] = m
	}
	files := map[string][]byte{}
	paths, hashes := map[string]string{}, map[string]string{}
	for _, ref := range refs {
		m, ok := byLabel[ref.Label]
		if !ok {
			return fail()
		}
		content, e := a.readSmall("materials/"+m.SHA256+".bin", ref.Maximum)
		if e != nil || digestBytes(content) != m.SHA256 {
			return fail()
		}
		if ref.Label == "dsn_file" {
			content = []byte(target.DSN)
		}
		sha := digestBytes(content)
		name := "material-" + sha + ".bin"
		if prior, ok := files[name]; ok && !bytes.Equal(prior, content) {
			return fail()
		}
		files[name] = content
		paths[ref.Label], hashes[ref.Label] = filepath.Join(target.Directory, "runtime", name), sha
	}
	c.DSNFile, c.TLSCertFile, c.TLSKeyFile = paths["dsn_file"], paths["tls_cert_file"], paths["tls_key_file"]
	c.BillingTokenFile, c.AdminReadTokenFile, c.AdminWriteTokenFile = paths["billing_token_file"], paths["admin_read_token_file"], paths["admin_write_token_file"]
	c.NodeMaterials = nil
	for _, n := range c.Nodes {
		prefix := n.ID + ":"
		c.NodeMaterials = append(c.NodeMaterials, control.NodeMaterialBinding{NodeID: n.ID, ProfileSHA256: n.Digest(),
			CAFile: paths[prefix+"ca_file"], CASHA256: hashes[prefix+"ca_file"],
			ClientCertFile: paths[prefix+"client_cert_file"], ClientCertSHA256: hashes[prefix+"client_cert_file"],
			ClientKeyFile: paths[prefix+"client_key_file"], ClientKeySHA256: hashes[prefix+"client_key_file"]})
	}
	config, e := json.Marshal(c)
	if e != nil {
		return fail()
	}
	if _, e = control.ParseConfig(config); e != nil {
		return fail()
	}
	files["config.json"] = append(config, '\n')
	sourceManifest, e := json.Marshal(a.manifest)
	if e != nil {
		return fail()
	}
	manifest := runtimeManifest{Schema: 1, OperationID: op, ControllerID: c.ControllerID, TargetPlanSHA256: target.PlanSHA256, SourceManifestSHA256: digestBytes(sourceManifest)}
	var names []string
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		manifest.Files = append(manifest.Files, Entry{Name: name, Size: int64(len(files[name])), SHA256: digestBytes(files[name])})
	}
	encoded, e := json.Marshal(manifest)
	if e != nil {
		return fail()
	}
	return files, append(encoded, '\n'), len(refs), nil
}

// RestoreRuntimeMaterials persists intent before any candidate file. Existing
// intent permits only exact readback, never recreation, key rotation or repair.
func (a *Archive) RestoreRuntimeMaterials(target RuntimeTarget) (RuntimeMaterialReport, error) {
	return a.runtimeMaterials(target, false)
}
func (a *Archive) VerifyRuntimeMaterials(target RuntimeTarget) (RuntimeMaterialReport, error) {
	return a.runtimeMaterials(target, true)
}

func (a *Archive) runtimeMaterials(target RuntimeTarget, verifyOnly bool) (RuntimeMaterialReport, error) {
	fail := func() (RuntimeMaterialReport, error) { return RuntimeMaterialReport{}, ErrInvalid }
	files, manifest, count, e := a.runtimeCandidate(target)
	if e != nil {
		return fail()
	}
	dir := filepath.Join(target.Directory, "runtime")
	intentPath := filepath.Join(target.Directory, "materials-started.json")
	_, statErr := os.Lstat(intentPath)
	readonly := statErr == nil
	if statErr != nil && !os.IsNotExist(statErr) {
		return fail()
	}
	if readonly {
		raw, e := targetRead(intentPath, 65536)
		if e != nil || !bytes.Equal(raw, manifest) {
			return fail()
		}
	} else {
		if verifyOnly {
			return fail()
		}
		if _, e := os.Lstat(dir); !os.IsNotExist(e) {
			return fail()
		}
		if e = writePrivateNew(intentPath, manifest); e != nil {
			return fail()
		}
		if e = os.Mkdir(dir, 0700); e != nil {
			return fail()
		}
		parent, e := os.Open(target.Directory)
		if e != nil {
			return fail()
		}
		e = parent.Sync()
		parent.Close()
		if e != nil {
			return fail()
		}
		// Recheck the directory and its parents before every set of writes.
		if privateRuntimeDirectory(dir) != nil {
			return fail()
		}
		var names []string
		for name := range files {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if e = writePrivateNew(filepath.Join(dir, name), files[name]); e != nil {
				return fail()
			}
		}
		// Completion proof is last. A partial directory is never adopted or
		// discarded on retry; it remains sealed for explicit recovery.
		if e = writePrivateNew(filepath.Join(dir, "manifest.json"), manifest); e != nil {
			return fail()
		}
	}
	if privateRuntimeDirectory(dir) != nil {
		return fail()
	}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != len(files)+1 {
		return fail()
	}
	for _, entry := range entries {
		want, ok := files[entry.Name()]
		if entry.Name() == "manifest.json" {
			want, ok = manifest, true
		}
		if !ok {
			return fail()
		}
		raw, e := targetRead(filepath.Join(dir, entry.Name()), int64(len(want)))
		if e != nil || !bytes.Equal(raw, want) {
			return fail()
		}
	}
	return RuntimeMaterialReport{Schema: 1, OperationID: a.manifest.OperationID, MaterialReferences: count, MaterialsStaged: true, ReadOnlyVerification: readonly}, nil
}

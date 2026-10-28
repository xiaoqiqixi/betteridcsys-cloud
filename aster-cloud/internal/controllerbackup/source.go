package controllerbackup

import (
	"aster/cloud/internal/control"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strings"
	"unicode/utf8"
)

type SourceReport struct {
	ConsoleEntrypoint            *SourceConsoleEntrypoint `json:"console_entrypoint"`
	CanonicalConfigurationSHA256 string                   `json:"canonical_configuration_sha256"`
	SourceMachineIDSHA256        string                   `json:"source_machine_id_sha256"`
	Schema                       int                      `json:"schema"`
	ControllerID                 string                   `json:"controller_id"`
	OperationID                  string                   `json:"operation_id"`
	SourceCommit                 string                   `json:"source_commit"`
	MaterialReferences           int                      `json:"material_references"`
	SourceBindingsVerified       bool                     `json:"source_bindings_verified"`
	RuntimeMaterialsVerified     bool                     `json:"runtime_materials_verified"`
	DatabaseSemanticsVerified    bool                     `json:"database_semantics_verified"`
	PublisherProvenanceVerified  bool                     `json:"publisher_provenance_verified"`
	TargetRestoreApproved        bool                     `json:"target_restore_approved"`
	MigrationReady               bool                     `json:"migration_ready"`
}

type sourceIdentity struct {
	ControllerID           string `json:"controller_id"`
	ConfigurationSHA256    string `json:"configuration_sha256"`
	InstallationSHA256     string `json:"installation_sha256"`
	ManifestSHA256         string `json:"manifest_sha256"`
	SourceCommit           string `json:"source_commit"`
	BundleSHA256           string `json:"bundle_sha256"`
	MachineIDSHA256        string `json:"machine_id_sha256"`
	RuntimeMaterialsSHA256 string `json:"runtime_materials_sha256"`
}
type sourceUnit struct {
	Name          string `json:"name"`
	Fragment      string `json:"fragment"`
	SHA256        string `json:"sha256"`
	OriginalInode *struct {
		Device uint64 `json:"device"`
		Inode  uint64 `json:"inode"`
	} `json:"original_inode"`
	ControlGroup string `json:"control_group"`
	Enabled      string `json:"enabled"`
	Index        int    `json:"index"`
}
type sourcePlan struct {
	Schema   int            `json:"schema"`
	Identity sourceIdentity `json:"identity"`
	Units    []sourceUnit   `json:"units"`
}
type sourceInstallation struct {
	Schema              int      `json:"schema"`
	Component           string   `json:"component"`
	Version             string   `json:"version"`
	BundleSHA256        string   `json:"bundle_sha256"`
	SourceCommit        string   `json:"source_commit"`
	Steps               []string `json:"steps"`
	Status              string   `json:"status"`
	Configuration       string   `json:"configuration"`
	Service             string   `json:"service"`
	CurrentStep         *string  `json:"current_step"`
	ApprovalSHA256      string   `json:"approval_sha256,omitempty"`
	WizardRequestSHA256 string   `json:"wizard_request_sha256,omitempty"`
	NativeOptions       *struct {
		InstallDependencies bool   `json:"install_dependencies"`
		ProvisionMySQL      bool   `json:"provision_mysql"`
		PrepareLibvirt      bool   `json:"prepare_libvirt,omitempty"`
		Database            string `json:"database,omitempty"`
		RuntimeUser         string `json:"runtime_user,omitempty"`
		MigrationUser       string `json:"migration_user,omitempty"`
	} `json:"native_options,omitempty"`
}

// Exact keys, no duplicate aliases, null only for nullable fields; accepting
// Go's case-insensitive JSON matching would weaken the source/config binding.
func exactSourceRecord(raw []byte, value any) bool {
	if len(raw) == 0 || !utf8.Valid(raw) {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(reflect.Type, int) bool
	walk = func(t reflect.Type, depth int) bool {
		if depth > 16 {
			return false
		}
		token, e := d.Token()
		if e != nil {
			return false
		}
		if t.Kind() == reflect.Pointer {
			if token == nil {
				return true
			}
			t = t.Elem()
		} else if token == nil {
			return false
		}
		switch t.Kind() {
		case reflect.Struct:
			if token != json.Delim('{') {
				return false
			}
			fields := map[string]reflect.StructField{}
			required := map[string]bool{}
			for i := 0; i < t.NumField(); i++ {
				f := t.Field(i)
				tag := strings.Split(f.Tag.Get("json"), ",")
				if tag[0] == "-" {
					continue
				}
				fields[tag[0]] = f
				if len(tag) == 1 {
					required[tag[0]] = true
				}
			}
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				name, ok := k.(string)
				f, exists := fields[name]
				if e != nil || !ok || !exists || seen[name] || !walk(f.Type, depth+1) {
					return false
				}
				seen[name] = true
				delete(required, name)
			}
			end, e := d.Token()
			return e == nil && end == json.Delim('}') && len(required) == 0
		case reflect.Slice:
			if token != json.Delim('[') {
				return false
			}
			for d.More() {
				if !walk(t.Elem(), depth+1) {
					return false
				}
			}
			end, e := d.Token()
			return e == nil && end == json.Delim(']')
		default:
			_, bad := token.(json.Delim)
			return !bad
		}
	}
	return walk(reflect.TypeOf(value).Elem(), 0) && d.Decode(new(any)) == io.EOF && strictRecord(raw, value)
}

func (a *Archive) sourceRecord(name string, maximum int64, value any) ([]byte, error) {
	raw, e := a.readSmall(name, maximum)
	if e != nil || !exactSourceRecord(raw, value) {
		return nil, ErrInvalid
	}
	return raw, nil
}

// ValidateSource checks only the authenticated package's internal source
// bindings. A recovery key is not a publisher signature or a target-host lease.
// No source pathname is opened, SQL executed or network connection made here.
func (a *Archive) ValidateSource(expectedCommit string) (SourceReport, error) {
	fail := func() (SourceReport, error) { return SourceReport{}, ErrInvalid }
	if a == nil || !a.valid || !sourceSHA.MatchString(expectedCommit) || a.manifest.SourceCommit != expectedCommit {
		return fail()
	}
	configRaw, e := a.readSmall("controller/config.json", control.MaxConfigBytes)
	if e != nil {
		return fail()
	}
	config, e := control.ParseConfig(configRaw)
	if e != nil || config.ControllerID != a.manifest.ControllerID {
		return fail()
	}
	var plan sourcePlan
	planRaw, e := a.sourceRecord("source/plan.json", 256<<10, &plan)
	if e != nil || plan.Schema != 1 || digestBytes(planRaw) != a.manifest.SourcePlanSHA256 {
		return fail()
	}
	id := plan.Identity
	if id.ControllerID != config.ControllerID || id.SourceCommit != expectedCommit || id.ConfigurationSHA256 != digestBytes(configRaw) {
		return fail()
	}
	for _, sha := range []string{id.InstallationSHA256, id.ManifestSHA256, id.BundleSHA256, id.MachineIDSHA256, id.RuntimeMaterialsSHA256} {
		if !shaPattern.MatchString(sha) {
			return fail()
		}
	}
	var receipt struct {
		Schema      int            `json:"schema"`
		OperationID string         `json:"operation_id"`
		Identity    sourceIdentity `json:"identity"`
	}
	if _, e = a.sourceRecord("source/isolated.json", 256<<10, &receipt); e != nil || receipt.Schema != 1 || receipt.OperationID != a.manifest.OperationID || receipt.Identity != id {
		return fail()
	}
	var installed sourceInstallation
	raw, e := a.sourceRecord("source/installation.json", 1<<20, &installed)
	version := regexp.MustCompile(`^0\.[0-9]+\.[0-9]+-(?:dev(?:\.[0-9]+)?|rc\.[0-9]+)$`)
	if e != nil || digestBytes(raw) != id.InstallationSHA256 || installed.Schema != 1 || installed.Component != "controller" || installed.BundleSHA256 != id.BundleSHA256 || installed.SourceCommit != expectedCommit || !version.MatchString(installed.Version) || installed.CurrentStep != nil || installed.Configuration != "approved" {
		return fail()
	}
	if !(installed.Status == "configuration-approved" && installed.Service == "not-started" || installed.Status == "service-ready" && installed.Service == "ready") {
		return fail()
	}
	steps := map[string]bool{}
	for _, s := range installed.Steps {
		if steps[s] {
			return fail()
		}
		steps[s] = true
	}
	if !steps["software-installed"] || !steps["configuration-approved"] || !steps["inactive-systemd-unit"] {
		return fail()
	}
	for _, sha := range []string{installed.ApprovalSHA256, installed.WizardRequestSHA256} {
		if sha != "" && !shaPattern.MatchString(sha) {
			return fail()
		}
	}
	if !validSourceUnits(plan.Units, config) {
		return fail()
	}
	console, e := a.sourceConsole(installed, plan.Units)
	if e != nil {
		return fail()
	}
	count, e := a.validateMaterials(config, id.RuntimeMaterialsSHA256)
	if e != nil {
		return fail()
	}
	canonical, e := json.Marshal(config)
	if e != nil {
		return fail()
	}
	return SourceReport{ConsoleEntrypoint: console, CanonicalConfigurationSHA256: digestBytes(canonical), SourceMachineIDSHA256: id.MachineIDSHA256, Schema: 1, ControllerID: config.ControllerID, OperationID: a.manifest.OperationID, SourceCommit: expectedCommit, MaterialReferences: count, SourceBindingsVerified: true, RuntimeMaterialsVerified: true}, nil
}
func validSourceUnits(units []sourceUnit, c control.Config) bool {
	if len(units) < 1 || len(units) > 1+2*len(c.Nodes) {
		return false
	}
	seen := map[string]bool{}
	previous := ""
	for i, u := range units {
		if u.Name <= previous || u.Index != i || !shaPattern.MatchString(u.SHA256) {
			return false
		}
		previous = u.Name
		seen[u.Name] = true
		if u.Name == "aster-controller.service" {
			if u.Fragment != "/etc/systemd/system/aster-controller.service" || u.OriginalInode == nil || u.OriginalInode.Device == 0 || u.OriginalInode.Inode == 0 {
				return false
			}
			continue
		}
		found := false
		for _, n := range c.Nodes {
			for _, suffix := range []string{"service", "timer"} {
				if u.Name == "controller-heartbeat@"+n.ID+"."+suffix {
					found = u.Fragment == "/etc/systemd/system/controller-heartbeat@."+suffix && u.OriginalInode == nil
				}
			}
		}
		if !found {
			return false
		}
	}
	if !seen["aster-controller.service"] {
		return false
	}
	// A template applies to the entire approved node inventory, not a chosen subset.
	for _, suffix := range []string{"service", "timer"} {
		n := 0
		for _, p := range c.Nodes {
			if seen["controller-heartbeat@"+p.ID+"."+suffix] {
				n++
			}
			if suffix == "timer" && seen["controller-heartbeat@"+p.ID+".timer"] && !seen["controller-heartbeat@"+p.ID+".service"] {
				return false
			}
		}
		if n != 0 && n != len(c.Nodes) {
			return false
		}
	}
	return true
}

// Python's source coordinator hashes ensure_ascii JSON triples. Preserve that
// existing byte contract, including Unicode paths, without touching node paths:
// those paths participate in historical NodeProfile.Digest values.
func asciiJSON(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 || r >= 0x7f {
				if r > 0xffff {
					v := r - 0x10000
					fmt.Fprintf(&b, `\u%04x\u%04x`, 0xd800+(v>>10), 0xdc00+(v&0x3ff))
				} else {
					fmt.Fprintf(&b, `\u%04x`, r)
				}
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}
func (a *Archive) validateMaterials(c control.Config, expectedSHA string) (int, error) {
	refs, err := c.RuntimeMaterials()
	if err != nil {
		return 0, ErrInvalid
	}
	var index []Material
	if _, e := a.sourceRecord("controller/materials.json", 256<<10, &index); e != nil || len(index) != len(refs) {
		return 0, ErrInvalid
	}
	byLabel := map[string]Material{}
	previous := ""
	for _, m := range index {
		if m.Label <= previous || !shaPattern.MatchString(m.SHA256) {
			return 0, ErrInvalid
		}
		previous = m.Label
		byLabel[m.Label] = m
	}
	used := map[string]bool{}
	byPath := map[string]string{}
	contents := map[string][]byte{}
	var digestInput strings.Builder
	for _, r := range refs {
		m, ok := byLabel[r.Label]
		if !ok || m.Path != r.Path || strings.ContainsAny(r.Path, "\x00\r\n") || r.ExpectedSHA256 != "" && r.ExpectedSHA256 != m.SHA256 {
			return 0, ErrInvalid
		}
		name := "materials/" + m.SHA256 + ".bin"
		raw, e := a.readSmall(name, r.Maximum)
		if e != nil || len(raw) == 0 || digestBytes(raw) != m.SHA256 {
			return 0, ErrInvalid
		}
		if sha, exists := byPath[r.Path]; exists && sha != m.SHA256 {
			return 0, ErrInvalid
		}
		byPath[r.Path] = m.SHA256
		used[name] = true
		contents[r.Label] = raw
		digestInput.WriteString("[" + asciiJSON(r.Label) + "," + asciiJSON(r.Path) + "," + asciiJSON(m.SHA256) + "]\n")
	}
	if digestBytes([]byte(digestInput.String())) != expectedSHA {
		return 0, ErrInvalid
	}
	for name := range a.files {
		if strings.HasPrefix(name, "materials/") && !used[name] {
			return 0, ErrInvalid
		}
	}
	// OpenDSN is a parser + lazy sql.Open only; never Ping/Conn or use its DSN on
	// the target. Reuse the runtime's local-only/unsafe-option rejection policy.
	store, e := control.OpenDSN(strings.TrimSpace(string(contents["dsn_file"])))
	if e != nil {
		return 0, ErrInvalid
	}
	store.DB.Close()
	if _, exists := a.files["source/database-ownership.json"]; exists {
		raw, err := a.readSmall("source/database-ownership.json", 65536)
		if err != nil {
			return 0, ErrInvalid
		}
		if _, err = decodeDatabaseOwnership(raw, strings.TrimSpace(string(contents["dsn_file"]))); err != nil {
			return 0, ErrInvalid
		}
	}
	tokens := map[string]bool{}
	for _, label := range []string{"billing_token_file", "admin_read_token_file", "admin_write_token_file"} {
		token := strings.TrimSpace(string(contents[label]))
		if len(token) < 32 || len(token) > 4096 || strings.ContainsAny(token, " \t\r\n") || tokens[token] {
			return 0, ErrInvalid
		}
		tokens[token] = true
	}
	if _, e := tls.X509KeyPair(contents["tls_cert_file"], contents["tls_key_file"]); e != nil {
		return 0, ErrInvalid
	}
	for _, n := range c.Nodes {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(contents[n.ID+":ca_file"]) {
			return 0, ErrInvalid
		}
		if _, e := tls.X509KeyPair(contents[n.ID+":client_cert_file"], contents[n.ID+":client_key_file"]); e != nil {
			return 0, ErrInvalid
		}
	}
	return len(refs), nil
}

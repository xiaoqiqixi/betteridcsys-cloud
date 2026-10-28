package controllerbackup

import (
	"aster/cloud/internal/control"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ConfigurationRequest is a protected root-reviewed migration choice. It is
// not a public HTTP input and contains no paths, SQL, credentials or unit text.
type ConfigurationRequest struct {
	Schema           int    `json:"schema"`
	OperationID      string `json:"operation_id"`
	TargetPlanSHA256 string `json:"target_plan_sha256"`
	ConsoleEnabled   bool   `json:"console_enabled"`
	ConsoleOrigin    string `json:"console_origin"`
	Listen           string `json:"listen"`
	TLSMode          string `json:"tls_mode"`
}

type ConfigurationPlan struct {
	Schema                       int                      `json:"schema"`
	Protocol                     string                   `json:"protocol"`
	ControllerID                 string                   `json:"controller_id"`
	OperationID                  string                   `json:"operation_id"`
	TargetPlanSHA256             string                   `json:"target_plan_sha256"`
	SourceConfigurationSHA256    string                   `json:"source_configuration_sha256"`
	SourceManifestSHA256         string                   `json:"source_manifest_sha256"`
	MaterialManifestSHA256       string                   `json:"material_manifest_sha256"`
	SessionIntentSHA256          string                   `json:"session_intent_sha256"`
	RequestSHA256                string                   `json:"request_sha256"`
	CanonicalConfigurationSHA256 string                   `json:"canonical_configuration_sha256"`
	SourceConsole                *SourceConsoleEntrypoint `json:"source_console"`
	ConsoleEnabled               bool                     `json:"console_enabled"`
	ConsoleOrigin                string                   `json:"console_origin"`
	Listen                       string                   `json:"listen"`
	TLSMode                      string                   `json:"tls_mode"`
	CertificateNotBefore         string                   `json:"certificate_not_before"`
	CertificateNotAfter          string                   `json:"certificate_not_after"`
	Files                        []Entry                  `json:"files"`
}

// PlanConfiguration is an offline filesystem plan, not proof of SQL state or
// authority to activate. The fixed root coordinator verifies session revocation
// under its target seal before supplying the corresponding intent digest.
func (a *Archive) PlanConfiguration(target RuntimeTarget, request []byte, sessionIntentSHA256 string) (ConfigurationPlan, error) {
	plan, _, err := a.configurationCandidate(target, request, sessionIntentSHA256)
	return plan, err
}

func validConfigurationListen(listen string) bool {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return false
	}
	address, err := netip.ParseAddr(host)
	if err != nil || address.Zone() != "" || address.IsMulticast() {
		return false
	}
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535 && listen == net.JoinHostPort(address.String(), strconv.Itoa(n))
}

// Verify pair, complete PEM framing, chain links, server usage, lifetime and
// optional hostname. This is NOT browser trust verification, DNS or reachability.
func configurationCertificate(certPEM, keyPEM []byte, hostname string) (*x509.Certificate, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil || len(pair.Certificate) == 0 || len(pair.Certificate) > 16 {
		return nil, ErrInvalid
	}
	rest := certPEM
	for i := 0; i < len(pair.Certificate); i++ {
		trimmed := bytes.TrimSpace(rest)
		footer := []byte("-----END CERTIFICATE-----")
		end := bytes.Index(trimmed, footer)
		if !bytes.HasPrefix(trimmed, []byte("-----BEGIN CERTIFICATE-----")) || end < 0 {
			return nil, ErrInvalid
		}
		end += len(footer)
		segment := trimmed[:end]
		block, unused := pem.Decode(segment)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(unused)) != 0 || bytes.Count(segment, []byte("-----BEGIN ")) != 1 {
			return nil, ErrInvalid
		}
		rest = trimmed[end:]
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, ErrInvalid
	}
	block, rest := pem.Decode(keyPEM)
	if block == nil || len(block.Headers) != 0 || strings.TrimSpace(string(rest)) != "" {
		return nil, ErrInvalid
	}
	if !bytes.HasPrefix(bytes.TrimSpace(keyPEM), []byte("-----BEGIN "+block.Type+"-----")) || bytes.Count(keyPEM, []byte("-----BEGIN ")) != 1 {
		return nil, ErrInvalid
	}
	if block.Type != "PRIVATE KEY" && block.Type != "RSA PRIVATE KEY" && block.Type != "EC PRIVATE KEY" {
		return nil, ErrInvalid
	}
	now := time.Now().UTC()
	var leaf, previous *x509.Certificate
	for _, der := range pair.Certificate {
		cert, err := x509.ParseCertificate(der)
		if err != nil || now.Before(cert.NotBefore) || cert.NotAfter.Before(now.Add(24*time.Hour)) {
			return nil, ErrInvalid
		}
		if previous != nil && previous.CheckSignatureFrom(cert) != nil {
			return nil, ErrInvalid
		}
		if leaf == nil {
			leaf = cert
		}
		previous = cert
	}
	server := len(leaf.ExtKeyUsage) == 0
	for _, usage := range leaf.ExtKeyUsage {
		server = server || usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny
	}
	if !server || hostname != "" && leaf.VerifyHostname(hostname) != nil {
		return nil, ErrInvalid
	}
	return leaf, nil
}

func (a *Archive) configurationCandidate(target RuntimeTarget, raw []byte, sessionIntentSHA256 string) (ConfigurationPlan, map[string][]byte, error) {
	fail := func() (ConfigurationPlan, map[string][]byte, error) { return ConfigurationPlan{}, nil, ErrInvalid }
	var request ConfigurationRequest
	if a == nil || !a.valid || len(raw) > 8192 || !exactSourceRecord(raw, &request) || request.Schema != 1 ||
		request.OperationID != a.manifest.OperationID || request.TargetPlanSHA256 != target.PlanSHA256 || !shaPattern.MatchString(sessionIntentSHA256) ||
		!validConfigurationListen(request.Listen) || request.ConsoleEnabled && !validConsoleOrigin(request.ConsoleOrigin) ||
		!request.ConsoleEnabled && request.ConsoleOrigin != "" || request.TLSMode != "source" && request.TLSMode != "replacement" {
		return fail()
	}
	if _, err := a.VerifyRuntimeMaterials(target); err != nil {
		return fail()
	}
	runtimeFiles, materialManifest, _, err := a.runtimeCandidate(target)
	if err != nil {
		return fail()
	}
	source, err := a.ValidateSource(a.manifest.SourceCommit)
	if err != nil {
		return fail()
	}
	cfg, err := control.ParseConfig(runtimeFiles["config.json"])
	if err != nil {
		return fail()
	}
	cert, key := runtimeFiles[filepath.Base(cfg.TLSCertFile)], runtimeFiles[filepath.Base(cfg.TLSKeyFile)]
	if request.TLSMode == "replacement" {
		cert, err = targetRead(filepath.Join(target.Directory, "configuration-tls.crt"), 1<<20)
		if err != nil {
			return fail()
		}
		key, err = targetRead(filepath.Join(target.Directory, "configuration-tls.key"), 1<<20)
		if err != nil {
			return fail()
		}
	} else {
		for _, name := range []string{"configuration-tls.crt", "configuration-tls.key"} {
			if _, err := os.Lstat(filepath.Join(target.Directory, name)); !os.IsNotExist(err) {
				return fail()
			}
		}
	}
	hostname := ""
	if request.ConsoleEnabled {
		parsed, _ := url.Parse(request.ConsoleOrigin)
		hostname = parsed.Hostname()
	}
	leaf, err := configurationCertificate(cert, key, hostname)
	if err != nil {
		return fail()
	}
	cfg.Listen, cfg.TLSCertFile, cfg.TLSKeyFile = request.Listen, "/etc/aster-controller/server.crt", "/etc/aster-controller/server.key"
	canonical, err := json.Marshal(cfg)
	if err != nil {
		return fail()
	}
	if _, err := control.ParseConfig(canonical); err != nil {
		return fail()
	}
	console, err := json.Marshal(struct {
		Schema  int    `json:"schema"`
		Enabled bool   `json:"enabled"`
		Origin  string `json:"origin"`
	}{1, request.ConsoleEnabled, request.ConsoleOrigin})
	if err != nil {
		return fail()
	}
	files := map[string][]byte{"config.json": append(canonical, '\n'), "console.json": append(console, '\n'), "server.crt": cert, "server.key": key}
	manifest, err := json.Marshal(a.manifest)
	if err != nil {
		return fail()
	}
	plan := ConfigurationPlan{Schema: 1, Protocol: "aster.controller-configuration/1", ControllerID: a.manifest.ControllerID, OperationID: a.manifest.OperationID,
		TargetPlanSHA256: target.PlanSHA256, SourceConfigurationSHA256: source.CanonicalConfigurationSHA256, SourceManifestSHA256: digestBytes(manifest),
		MaterialManifestSHA256: digestBytes(materialManifest), SessionIntentSHA256: sessionIntentSHA256, RequestSHA256: digestBytes(raw), CanonicalConfigurationSHA256: digestBytes(canonical),
		SourceConsole: source.ConsoleEntrypoint, ConsoleEnabled: request.ConsoleEnabled, ConsoleOrigin: request.ConsoleOrigin, Listen: request.Listen, TLSMode: request.TLSMode,
		CertificateNotBefore: leaf.NotBefore.UTC().Format(time.RFC3339), CertificateNotAfter: leaf.NotAfter.UTC().Format(time.RFC3339)}
	for name, content := range files {
		plan.Files = append(plan.Files, Entry{Name: name, Size: int64(len(content)), SHA256: digestBytes(content)})
	}
	sort.Slice(plan.Files, func(i, j int) bool { return plan.Files[i].Name < plan.Files[j].Name })
	return plan, files, nil
}

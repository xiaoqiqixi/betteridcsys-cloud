package controllerbackup

import (
	"aster/cloud/internal/control"
	"aster/cloud/internal/controllerhost"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

const targetRoot = "/var/lib/aster-controller-restore"
const targetState = "/var/lib/aster-cloud-installer/controller/state.json"

type TargetPlan struct {
	Schema                       int    `json:"schema"`
	Protocol                     string `json:"protocol"`
	ControllerID                 string `json:"controller_id"`
	OperationID                  string `json:"operation_id"`
	SourceCommit                 string `json:"source_commit"`
	CanonicalConfigurationSHA256 string `json:"canonical_configuration_sha256"`
	ArchiveSHA256                string `json:"archive_sha256"`
	InstallationSHA256           string `json:"installation_sha256"`
	ManifestSHA256               string `json:"manifest_sha256"`
	ExecutableSHA256             string `json:"executable_sha256"`
	MachineIDSHA256              string `json:"machine_id_sha256"`
	SourceMachineIDSHA256        string `json:"source_machine_id_sha256"`
}

type targetRequest struct {
	Schema        int    `json:"schema"`
	ControllerID  string `json:"controller_id"`
	OperationID   string `json:"operation_id"`
	SourceCommit  string `json:"source_commit"`
	ArchiveSHA256 string `json:"archive_sha256"`
}

func targetRead(path string, maximum int64) ([]byte, error) {
	f, st, e := ownedInput(path, maximum)
	if e != nil {
		return nil, ErrInvalid
	}
	defer f.Close()
	raw, e := io.ReadAll(io.LimitReader(f, maximum+1))
	if e != nil || int64(len(raw)) != st.Size() {
		return nil, ErrInvalid
	}
	return raw, nil
}
func targetHash(path string) (string, error) {
	f, st, e := ownedInput(path, MaxCipherBytes)
	if e != nil {
		return "", ErrInvalid
	}
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, MaxCipherBytes+1))
	after, statErr := f.Stat()
	if e != nil || statErr != nil || n != st.Size() || after.Size() != st.Size() || !after.ModTime().Equal(st.ModTime()) {
		return "", ErrInvalid
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// PlanTarget reads only fixed root-protected input and the current managed
// installation. It never imports SQL, follows source paths or contacts a node.
// Its private temporary plaintext is removed before the plan is returned.
func PlanTarget(operation string) (TargetPlan, error) {
	return planTargetArchive(operation, nil)
}

// Keep one authenticated archive alive for one root command. PlanTarget's
// public read-only behavior is unchanged. Internal actions may use this same
// capability only before its cleanup; nothing is cached between commands.
func planTargetArchive(operation string, action func(TargetPlan, *Archive) error) (TargetPlan, error) {
	return planTargetArchiveMode(operation, false, action)
}

// Only publication commands may inspect an existing configuration. Their action
// must rederive and verify it under the original seal before reporting success.
func planTargetArchiveMode(operation string, configuration bool, action func(TargetPlan, *Archive) error) (TargetPlan, error) {
	fail := func() (TargetPlan, error) { return TargetPlan{}, ErrInvalid }
	if os.Geteuid() != 0 || !operationID.MatchString(operation) || configuration && action == nil {
		return fail()
	}
	dir := filepath.Join(targetRoot, operation)
	for _, path := range []string{targetRoot, dir} {
		info, e := os.Lstat(path)
		if e != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
			return fail()
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			return fail()
		}
	}
	raw, e := targetRead(filepath.Join(dir, "request.json"), 4096)
	var request targetRequest
	if e != nil || !exactSourceRecord(raw, &request) || request.Schema != 1 || request.OperationID != operation ||
		!controllerID.MatchString(request.ControllerID) || !sourceSHA.MatchString(request.SourceCommit) || !shaPattern.MatchString(request.ArchiveSHA256) {
		return fail()
	}
	stateRaw, e := targetRead(targetState, 1<<20)
	var state sourceInstallation
	if e != nil || !exactSourceRecord(stateRaw, &state) || state.Schema != 1 || state.Component != "controller" || state.Status != "software-installed" ||
		state.Configuration != "waiting-approval" || state.Service != "not-started" || state.CurrentStep != nil || state.SourceCommit != request.SourceCommit ||
		!shaPattern.MatchString(state.BundleSHA256) || !regexp.MustCompile(`^0\.[0-9]+\.[0-9]+-(dev(\.[0-9]+)?|rc\.[0-9]+)$`).MatchString(state.Version) ||
		state.ApprovalSHA256 != "" || state.WizardRequestSHA256 != "" {
		return fail()
	}
	steps := map[string]bool{}
	for _, step := range state.Steps {
		if steps[step] || step != "software-installed" && step != "native-dependencies" {
			return fail()
		}
		steps[step] = true
	}
	if !steps["software-installed"] || state.NativeOptions != nil && (state.NativeOptions.ProvisionMySQL || state.NativeOptions.PrepareLibvirt || state.NativeOptions.Database != "" || state.NativeOptions.RuntimeUser != "" || state.NativeOptions.MigrationUser != "") {
		return fail()
	}
	version := filepath.Join("/opt/aster-cloud/controller/versions", state.Version+"-"+state.BundleSHA256[:16])
	exe, e := os.Executable()
	if e != nil || exe != filepath.Join(version, "bin/aster-controller") {
		return fail()
	}
	binary, e := control.ReadProtected(exe, false, 128<<20)
	if e != nil {
		return fail()
	}
	manifest, e := control.ReadProtected(filepath.Join(version, "manifest.json"), false, 4<<20)
	if e != nil {
		return fail()
	}
	machine, e := control.ReadProtected("/etc/machine-id", false, 128)
	if e != nil {
		return fail()
	}
	machine = []byte(strings.TrimSpace(string(machine)))
	if !operationID.Match(machine) {
		return fail()
	}
	// No existing live configuration or units may be adopted as a fresh target.
	for _, path := range []string{"/etc/aster-controller", "/etc/systemd/system/aster-controller.service", "/etc/systemd/system/controller-heartbeat@.service", "/etc/systemd/system/controller-heartbeat@.timer"} {
		if configuration && path == "/etc/aster-controller" {
			if _, e := os.Lstat(path); e == nil {
				if privateRuntimeDirectory(path) != nil {
					return fail()
				}
			} else if !os.IsNotExist(e) {
				return fail()
			}
			continue
		}
		if _, e := os.Lstat(path); !os.IsNotExist(e) {
			return fail()
		}
	}
	archive := filepath.Join(dir, "backup.age")
	hash, e := targetHash(archive)
	if e != nil || hash != request.ArchiveSHA256 {
		return fail()
	}
	var result TargetPlan
	e = WithVerifiedArchive(archive, filepath.Join(dir, "recovery.key"), request.ControllerID, operation, dir, func(a *Archive) error {
		source, e := a.ValidateSource(request.SourceCommit)
		if e != nil || source.SourceMachineIDSHA256 == digestBytes(machine) {
			return ErrInvalid
		}
		// Recheck ciphertext after authentication, before accepting a plan or
		// entering any action. The action separately rechecks under its seal.
		after, e := targetHash(archive)
		if e != nil || after != hash {
			return ErrInvalid
		}
		result = TargetPlan{1, "aster.controller-target/1", request.ControllerID, operation, request.SourceCommit, source.CanonicalConfigurationSHA256, hash, digestBytes(stateRaw), digestBytes(manifest), digestBytes(binary), digestBytes(machine), source.SourceMachineIDSHA256}
		if action != nil {
			return action(result, a)
		}
		return nil
	})
	if e != nil {
		return TargetPlan{}, e
	}
	return result, nil
}

// SealTarget consumes an immutable plan written by the managed Python host
// coordinator after its whole-bundle and systemd preflight. Root's approval is
// not publisher provenance. No arbitrary path, destination DSN or release flag.
func SealTarget(operation string, statusOnly bool) (controllerhost.Status, error) {
	plan, e := PlanTarget(operation)
	if e != nil {
		return controllerhost.Status{}, e
	}
	path := filepath.Join(targetRoot, operation, "plan.json")
	raw, e := targetRead(path, 4096)
	var approved TargetPlan
	if e != nil || !exactSourceRecord(raw, &approved) || approved != plan {
		return controllerhost.Status{}, ErrInvalid
	}
	canonical, e := json.Marshal(approved)
	if e != nil {
		return controllerhost.Status{}, ErrInvalid
	}
	if statusOnly {
		if _, e := targetRead(filepath.Join("/var/lib/aster-controller", plan.ControllerID, "target-restore.json"), 4096); e != nil {
			return controllerhost.Status{}, ErrInvalid
		}
	}
	host, e := controllerhost.Open(plan.ControllerID, plan.CanonicalConfigurationSHA256)
	if e != nil {
		return controllerhost.Status{}, e
	}
	defer host.Close()
	if statusOnly {
		return host.TargetStatus(operation, digestBytes(canonical))
	}
	return host.PrepareTarget(operation, digestBytes(canonical))
}

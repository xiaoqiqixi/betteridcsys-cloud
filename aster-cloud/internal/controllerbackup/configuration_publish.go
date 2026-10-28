package controllerbackup

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
)

// ConfigurationPublicationTarget is supplied only by the installed root
// coordinator. ParentDirectory is fixed to /etc there, never an HTTP/CLI input.
type ConfigurationPublicationTarget struct {
	Runtime         RuntimeTarget
	ParentDirectory string
}

type ConfigurationApproval struct {
	Schema                  int    `json:"schema"`
	OperationID             string `json:"operation_id"`
	TargetPlanSHA256        string `json:"target_plan_sha256"`
	ConfigurationPlanSHA256 string `json:"configuration_plan_sha256"`
}

// ConfigurationPublicationIntent is the durable, root-private phase record.
// Destination binds the caller-controlled protected filesystem boundary.
type ConfigurationPublicationIntent struct {
	Schema         int               `json:"schema"`
	Destination    string            `json:"destination"`
	ApprovalSHA256 string            `json:"approval_sha256"`
	Plan           ConfigurationPlan `json:"plan"`
}

type ConfigurationPublicationReport struct {
	PlanSHA256               string            `json:"plan_sha256"`
	Schema                   int               `json:"schema"`
	OperationID              string            `json:"operation_id"`
	Plan                     ConfigurationPlan `json:"plan"`
	IntentSHA256             string            `json:"intent_sha256"`
	ReadOnlyVerification     bool              `json:"read_only_verification"`
	ConfigurationPublished   bool              `json:"configuration_published"`
	TargetActivationApproved bool              `json:"target_activation_approved"`
	MigrationReady           bool              `json:"migration_ready"`
}

// These filesystem operations require the caller's installation and target
// seal locks. They do not authorize SQL, service activation or node takeover.
func (a *Archive) PublishConfiguration(target ConfigurationPublicationTarget, request, approval []byte, sessionSHA string) (ConfigurationPublicationReport, error) {
	return a.configurationPublication(target, request, approval, sessionSHA, "publish")
}
func (a *Archive) VerifyPublishedConfiguration(target ConfigurationPublicationTarget, request, approval []byte, sessionSHA string) (ConfigurationPublicationReport, error) {
	return a.configurationPublication(target, request, approval, sessionSHA, "verify")
}
func (a *Archive) ResumeConfigurationPublication(target ConfigurationPublicationTarget, request, approval []byte, sessionSHA string) (ConfigurationPublicationReport, error) {
	return a.configurationPublication(target, request, approval, sessionSHA, "resume")
}

func configurationParent(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n") {
		return ErrInvalid
	}
	for current := path; ; current = filepath.Dir(current) {
		st, err := os.Lstat(current)
		if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return ErrInvalid
		}
		native, ok := st.Sys().(*syscall.Stat_t)
		if !ok || native.Uid != 0 && native.Uid != uint32(os.Geteuid()) || st.Mode().Perm()&0022 != 0 && !(native.Uid == 0 && st.Mode()&os.ModeSticky != 0 && current != path) {
			return ErrInvalid
		}
		if current == path && st.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			return ErrInvalid
		}
		if current == "/" {
			return nil
		}
	}
}

func configurationDirectoryMatches(dir string, files map[string][]byte, partial bool) error {
	if privateRuntimeDirectory(dir) != nil {
		return ErrInvalid
	}
	entries, err := os.ReadDir(dir)
	if err != nil || !partial && len(entries) != len(files) {
		return ErrInvalid
	}
	for _, entry := range entries {
		want, ok := files[entry.Name()]
		if !ok {
			return ErrInvalid
		}
		raw, err := targetRead(filepath.Join(dir, entry.Name()), int64(len(want)))
		if err != nil || !bytes.Equal(raw, want) {
			return ErrInvalid
		}
	}
	// A completion manifest cannot authorize filling a directory with missing
	// files. Only a pre-completion stage may resume incomplete exact writes.
	if _, err := os.Lstat(filepath.Join(dir, "manifest.json")); err == nil && len(entries) != len(files) {
		return ErrInvalid
	}
	return nil
}

func configurationExists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, ErrInvalid
	}
	return true, nil
}

func (a *Archive) configurationPublication(target ConfigurationPublicationTarget, request, approval []byte, sessionSHA, action string) (ConfigurationPublicationReport, error) {
	fail := func() (ConfigurationPublicationReport, error) { return ConfigurationPublicationReport{}, ErrInvalid }
	// Unsupported hosts must not write a publication intent and leave a partial
	// operation. Portable readback is deliberately separate from Linux rename.
	if action != "verify" && runtime.GOOS != "linux" {
		return fail()
	}
	if configurationParent(target.ParentDirectory) != nil {
		return fail()
	}
	plan, files, err := a.configurationCandidate(target.Runtime, request, sessionSHA)
	if err != nil {
		return fail()
	}
	planRaw, err := json.Marshal(plan)
	var accepted ConfigurationApproval
	if err != nil || len(approval) > 8192 || !exactSourceRecord(approval, &accepted) || accepted.Schema != 1 ||
		accepted.OperationID != plan.OperationID || accepted.TargetPlanSHA256 != plan.TargetPlanSHA256 || accepted.ConfigurationPlanSHA256 != digestBytes(planRaw) {
		return fail()
	}
	destination := filepath.Join(target.ParentDirectory, "aster-controller")
	stage := filepath.Join(target.ParentDirectory, ".aster-controller-configuration-"+plan.OperationID)
	intentPath := filepath.Join(target.Runtime.Directory, "configuration-started.json")
	intent, err := json.Marshal(ConfigurationPublicationIntent{1, destination, digestBytes(approval), plan})
	if err != nil {
		return fail()
	}
	intent = append(intent, '\n')
	files["manifest.json"] = intent
	exists, err := configurationExists(intentPath)
	if err != nil {
		return fail()
	}
	hasStage, err := configurationExists(stage)
	if err != nil {
		return fail()
	}
	hasTarget, err := configurationExists(destination)
	if err != nil {
		return fail()
	}
	if exists {
		raw, err := targetRead(intentPath, 65536)
		if err != nil || !bytes.Equal(raw, intent) {
			return fail()
		}
	} else {
		if action != "publish" || hasStage || hasTarget {
			return fail()
		}
		if writePrivateNew(intentPath, intent) != nil {
			return fail()
		}
	}
	readonly := exists && hasTarget
	if readonly {
		if hasStage || action == "resume" || configurationDirectoryMatches(destination, files, false) != nil {
			return fail()
		}
	} else {
		if action == "verify" || exists && action != "resume" || hasTarget {
			return fail()
		}
		if hasStage {
			if configurationDirectoryMatches(stage, files, true) != nil {
				return fail()
			}
		} else {
			if os.Mkdir(stage, 0700) != nil || privateRuntimeDirectory(stage) != nil {
				return fail()
			}
			parent, err := os.Open(target.ParentDirectory)
			if err != nil {
				return fail()
			}
			err = parent.Sync()
			parent.Close()
			if err != nil {
				return fail()
			}
		}
		var names []string
		for name := range files {
			if name != "manifest.json" {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		names = append(names, "manifest.json")
		for _, name := range names {
			file := filepath.Join(stage, name)
			present, err := configurationExists(file)
			if err != nil {
				return fail()
			}
			if !present && writePrivateNew(file, files[name]) != nil {
				return fail()
			}
		}
		if configurationDirectoryMatches(stage, files, false) != nil || configurationParent(target.ParentDirectory) != nil || publishNew(stage, destination) != nil {
			return fail()
		}
		if configurationDirectoryMatches(destination, files, false) != nil {
			return fail()
		}
	}
	return ConfigurationPublicationReport{PlanSHA256: digestBytes(planRaw), Schema: 1, OperationID: plan.OperationID, Plan: plan, IntentSHA256: digestBytes(intent), ReadOnlyVerification: readonly, ConfigurationPublished: true}, nil
}

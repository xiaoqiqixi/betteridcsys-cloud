package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
	"testing"
)

// Cross the command interface, not the private host-lock implementation.
func TestControllerMigrationCapabilities(t *testing.T) {
	if os.Getenv("ASTER_MIGRATION_CLI_HELPER") == "1" {
		os.Args = []string{"aster-controller", "migration-capabilities"}
		main()
		os.Exit(0)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestControllerMigrationCapabilities$")
	cmd.Env = append(os.Environ(), "ASTER_MIGRATION_CLI_HELPER=1")
	raw, err := cmd.Output()
	if err != nil {
		t.Fatal("capability command failed", err)
	}
	var got map[string]any
	if json.Unmarshal(raw, &got) != nil || got["schema"] != float64(1) ||
		got["protocol"] != "aster.controller-host/1" || got["runtime_fence"] != (runtime.GOOS == "linux") ||
		got["host_migration_seal"] != (runtime.GOOS == "linux") ||
		got["migration_ready"] != false || got["export_restore"] != false {
		t.Fatal("capability must distinguish runtime fencing from complete migration", string(raw))
	}
}

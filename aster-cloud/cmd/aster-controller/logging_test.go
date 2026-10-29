package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestControllerCLIRejectsArgumentsWithoutEchoingPrivateInput(t *testing.T) {
	if os.Getenv("ASTER_LOGGING_HELPER") == "1" {
		command := os.Getenv("ASTER_LOGGING_COMMAND")
		if command != "serve" && command != "migration-target-verification-plan" && command != "migration-target-verification-credential-check" && command != "migration-target-verification-data-begin" && command != "migration-target-verification-data-status" {
			t.Fatal("unknown logging fixture command")
		}
		os.Args = []string{"aster-controller", command, "--PRIVATE-SENTINEL=password"}
		main()
		return
	}
	for _, command := range []string{"serve", "migration-target-verification-plan", "migration-target-verification-credential-check", "migration-target-verification-data-begin", "migration-target-verification-data-status"} {
		t.Run(command, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestControllerCLIRejectsArgumentsWithoutEchoingPrivateInput$")
			cmd.Env = append(os.Environ(), "ASTER_LOGGING_HELPER=1", "ASTER_LOGGING_COMMAND="+command)
			var out, errOut bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &errOut
			if err := cmd.Run(); err == nil || out.Len() != 0 || strings.Contains(errOut.String(), "PRIVATE-SENTINEL") {
				t.Fatal("CLI error did not remain private", err)
			}
			var event map[string]any
			if err := json.Unmarshal(errOut.Bytes(), &event); err != nil || event["msg"] != "aster_command_failed" || event["component"] != "controller" || event["level"] != "ERROR" {
				t.Fatal(event, err)
			}

		})
	}
}

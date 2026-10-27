package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestNodeCLIRejectsArgumentsWithoutEchoingPrivateInput(t *testing.T) {
	if os.Getenv("ASTER_LOGGING_HELPER") == "1" {
		os.Args = []string{"aster-node", "--PRIVATE-SENTINEL=password"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestNodeCLIRejectsArgumentsWithoutEchoingPrivateInput$")
	cmd.Env = append(os.Environ(), "ASTER_LOGGING_HELPER=1")
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err == nil || out.Len() != 0 || strings.Contains(errOut.String(), "PRIVATE-SENTINEL") {
		t.Fatal("CLI error did not remain private", err)
	}
	var event map[string]any
	if err := json.Unmarshal(errOut.Bytes(), &event); err != nil || event["msg"] != "aster_command_failed" || event["component"] != "node" || event["level"] != "ERROR" {
		t.Fatal(event, err)
	}
}

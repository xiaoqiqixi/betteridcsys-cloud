package main

import (
	"aster/cloud/internal/controllerbackup"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestVerificationCoordinatorRequiresItsPrivateRootManager(t *testing.T) {
	if err := run([]string{"migration-verification-coordinator"}); !errors.Is(err, controllerbackup.ErrInvalid) {
		t.Fatal("direct command did not refuse missing private root authority")
	}
}

func TestVerificationCoordinatorFailureCodesKeepCausesPrivate(t *testing.T) {
	private := fmt.Errorf("PRIVATE_SOCKET_DETAIL: %w", controllerbackup.ErrInvalid)
	for _, stage := range []string{"PEER", "SOCKET", "CONNECTION", "REQUEST", "PROOF"} {
		failure := &verificationCoordinatorFailure{stage, private}
		if got := verificationCoordinatorFailureCode(fmt.Errorf("wrapped: %w", failure)); got != "VERIFICATION_COORDINATOR_"+stage {
			t.Fatal(got)
		}
		if !errors.Is(failure, controllerbackup.ErrInvalid) || strings.Contains(failure.Error(), "PRIVATE") {
			t.Fatal("failure changed identity or disclosed its cause")
		}
	}
	for _, err := range []error{nil, private, &verificationCoordinatorFailure{"PRIVATE_PATH", private}} {
		if verificationCoordinatorFailureCode(err) != "COMMAND_FAILED" {
			t.Fatal("foreign diagnostic escaped the allowlist")
		}
	}
}

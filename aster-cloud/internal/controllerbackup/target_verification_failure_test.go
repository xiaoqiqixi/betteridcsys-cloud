package controllerbackup

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestVerificationLaunchFailureCodesKeepCausesPrivate(t *testing.T) {
	private := fmt.Errorf("PRIVATE_SQL_DSN: %w", ErrInvalid)
	for _, stage := range []string{"INPUT", "ARCHIVE", "PLAN", "HOST", "SOURCE", "RUNTIME", "IMPORT", "CONFIGURATION", "BINDING", "CONTROLLER", "TLS", "EXECUTABLE", "UI"} {
		failure := &verificationLaunchFailure{stage, private}
		if got := VerificationLaunchFailureCode(fmt.Errorf("wrapped: %w", failure)); got != "VERIFICATION_LAUNCH_"+stage {
			t.Fatal(got)
		}
		if !errors.Is(failure, ErrInvalid) || strings.Contains(failure.Error(), "PRIVATE") {
			t.Fatal("failure changed identity or disclosed its cause")
		}
	}
	for _, err := range []error{nil, private, &verificationLaunchFailure{"PRIVATE_PATH", private}} {
		if VerificationLaunchFailureCode(err) != "COMMAND_FAILED" {
			t.Fatal("foreign diagnostic escaped the allowlist")
		}
	}
}

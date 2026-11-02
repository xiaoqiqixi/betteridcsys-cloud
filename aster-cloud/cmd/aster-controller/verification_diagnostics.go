package main

import "errors"

type verificationCoordinatorFailure struct {
	stage string
	cause error
}

func (e *verificationCoordinatorFailure) Error() string { return "verification coordinator refused" }
func (e *verificationCoordinatorFailure) Unwrap() error { return e.cause }

func verificationCoordinatorFailureCode(err error) string {
	var failure *verificationCoordinatorFailure
	if errors.As(err, &failure) {
		switch failure.stage {
		case "PEER", "SOCKET", "CONNECTION", "REQUEST", "PROOF":
			return "VERIFICATION_COORDINATOR_" + failure.stage
		}
	}
	return "COMMAND_FAILED"
}

package verificationprocess

import "errors"

// FailureCode returns only an allowlisted stage, never a syscall/SQL error,
// credential, path or peer-controlled string. It is a diagnostic, not approval.
func FailureCode(err error) string {
	var failure *processFailure
	if errors.As(err, &failure) && failureCodeAllowed(failure.code) {
		return failure.code
	}
	return "VERIFICATION_UNCONFIRMED"
}

type processFailure struct{ code string }

func (e *processFailure) Error() string { return e.code }
func (e *processFailure) Unwrap() error { return ErrRefused }
func refused(code string) error {
	if !failureCodeAllowed(code) {
		return ErrRefused
	}
	return &processFailure{code: code}
}
func failureCodeAllowed(code string) bool {
	switch code {
	case "VERIFICATION_HOST_GUARD", "VERIFICATION_HOST_EXECUTABLE", "VERIFICATION_LISTENER",
		"VERIFICATION_SPAWN", "VERIFICATION_HANDSHAKE", "VERIFICATION_EARLY_EXIT",
		"VERIFICATION_CHILD_AUTHORITY", "VERIFICATION_CHILD_IDENTITY", "VERIFICATION_CHILD_GUARD",
		"VERIFICATION_CHILD_BOOTSTRAP", "VERIFICATION_CHILD_LISTENER", "VERIFICATION_CHILD_SQL",
		"VERIFICATION_CHILD_RECHECK", "VERIFICATION_CHILD_SERVICE":
		return true
	}
	return false
}

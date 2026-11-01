package controllerbackup_test

import (
	"aster/cloud/internal/controllerbackup"
	"context"
	"errors"
	"testing"
)

func TestTargetVerificationLaunchRequiresLiveContextAndRootApproval(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name string
		ctx  context.Context
		op   string
	}{
		{"missing context", nil, "0123456789abcdef0123456789abcdef"},
		{"cancelled context", cancelled, "0123456789abcdef0123456789abcdef"},
		{"missing operation", context.Background(), ""},
		{"path is not an operation", context.Background(), "../../other-target"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			err := controllerbackup.RunTargetVerification(tc.ctx, tc.op, func(controllerbackup.TargetVerificationRuntimeReport) (controllerbackup.VerificationSystemIdentity, error) {
				called = true
				return controllerbackup.VerificationSystemIdentity{}, nil
			})
			if !errors.Is(err, controllerbackup.ErrInvalid) || called {
				t.Fatal("invalid request reached root approval or admitted a process")
			}
		})
	}
	if err := controllerbackup.RunTargetVerification(context.Background(), "0123456789abcdef0123456789abcdef", nil); !errors.Is(err, controllerbackup.ErrInvalid) {
		t.Fatal("missing complete root inventory approval was admitted")
	}
}

func TestTargetVerificationLaunchCannotUseAnUninstalledTestExecutable(t *testing.T) {
	called := false
	err := controllerbackup.RunTargetVerification(context.Background(), "0123456789abcdef0123456789abcdef", func(controllerbackup.TargetVerificationRuntimeReport) (controllerbackup.VerificationSystemIdentity, error) {
		called = true
		return controllerbackup.VerificationSystemIdentity{UID: 65532, GID: 65532}, nil
	})
	if err == nil || called {
		t.Fatal("non-managed executable bypassed the original installation and archive approval")
	}
}

package verificationprocess_test

import (
	"aster/cloud/internal/verificationprocess"
	"context"
	"errors"
	"os"
	"testing"
)

func TestVerificationProcessRejectsMissingHostAuthority(t *testing.T) {
	if err := verificationprocess.Serve(context.Background(), nil, verificationprocess.Config{}); !errors.Is(err, verificationprocess.ErrRefused) {
		t.Fatal("missing original guard or approved configuration admitted")
	}
}

func TestVerificationProcessConsumesInvalidGuardWithoutStarting(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "unapproved-guard")
	if err != nil {
		t.Fatal(err)
	}
	if err = verificationprocess.Serve(context.Background(), file, verificationprocess.Config{}); !errors.Is(err, verificationprocess.ErrRefused) {
		t.Fatal("invalid bootstrap admitted")
	}
	if _, err = file.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("rejected guard still open")
	}
}

func TestVerificationChildRefusesDirectInvocation(t *testing.T) {
	if err := verificationprocess.Child(); !errors.Is(err, verificationprocess.ErrRefused) {
		t.Fatal("unrelated process admitted as verification child")
	}
}

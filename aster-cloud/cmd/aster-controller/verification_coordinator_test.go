package main

import (
	"aster/cloud/internal/controllerbackup"
	"errors"
	"testing"
)

func TestVerificationCoordinatorRequiresItsPrivateRootManager(t *testing.T) {
	if err := run([]string{"migration-verification-coordinator"}); !errors.Is(err, controllerbackup.ErrInvalid) {
		t.Fatal("direct command did not refuse missing private root authority")
	}
}

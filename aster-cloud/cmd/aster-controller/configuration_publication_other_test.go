//go:build !linux

package main

import (
	"aster/cloud/internal/controllerbackup"
	"testing"
)

func testConfigurationAtomicPublication(t *testing.T, a *controllerbackup.Archive, target controllerbackup.ConfigurationPublicationTarget, request, approval []byte, plan controllerbackup.ConfigurationPlan) {
	t.Helper()
	if _, err := a.PublishConfiguration(target, request, approval, plan.SessionIntentSHA256); err == nil {
		t.Fatal("unsupported host published configuration")
	}
}

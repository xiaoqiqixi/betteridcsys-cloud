package control

import (
	"strings"
	"testing"
)

func TestPublicIPBindingTasksHaveExecutionGrantsButNoGenericPlanningInput(t *testing.T) {
	instance := strings.Repeat("1", 32)
	for _, action := range []string{"public_adopt", "public_detach"} {
		if OperationPermission(action) != "instances.manage" {
			t.Fatal("missing public binding execution permission", action)
		}
		for _, confirmation := range []string{"", instance} {
			if (OperationInput{Action: action, Confirmation: confirmation}).valid(instance) {
				t.Fatal("generic action input bypasses resource generation/CAS", action)
			}
		}
	}
	if OperationPermission("public_unknown") != "" {
		t.Fatal("unknown public action acquired execution permission")
	}
}

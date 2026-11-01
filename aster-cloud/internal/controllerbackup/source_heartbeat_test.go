package controllerbackup

import (
	"aster/cloud/internal/control"
	"encoding/json"
	"strings"
	"testing"
)

func TestSourceHeartbeatReceiptBindings(t *testing.T) {
	for _, name := range []string{
		"managed", "legacy", "no nodes", "recovered rollback",
		"missing timers", "missing digests", "missing timer digest", "unknown digest key",
		"foreign timer", "duplicate timer", "unsorted timers", "missing unit", "service drift", "timer drift",
		"invalid digest", "missing install step", "unknown cleanup", "unknown service cleanup",
		"null timers", "null digests", "unknown field", "case alias", "duplicate field",
	} {
		t.Run(name, func(t *testing.T) {
			service, timer := strings.Repeat("a", 64), strings.Repeat("b", 64)
			digests := map[string]any{"controller-heartbeat@.service": service, "controller-heartbeat@.timer": timer}
			receipt := map[string]any{
				"schema": 1, "component": "controller", "version": "0.1.0-dev.1",
				"bundle_sha256": strings.Repeat("c", 64), "source_commit": strings.Repeat("d", 40),
				"steps":  []string{"software-installed", "configuration-approved", "inactive-systemd-unit", "inactive-heartbeat-units"},
				"status": "configuration-approved", "configuration": "approved", "service": "not-started", "current_step": nil,
				"heartbeat_timers":       []string{"controller-heartbeat@node-a.timer", "controller-heartbeat@node-b.timer"},
				"heartbeat_units_sha256": digests,
			}
			config := control.Config{Nodes: []control.NodeProfile{{ID: "node-b"}, {ID: "node-a"}}}
			units := []sourceUnit{
				{Name: "controller-heartbeat@node-a.service", SHA256: service},
				{Name: "controller-heartbeat@node-a.timer", SHA256: timer},
				{Name: "controller-heartbeat@node-b.service", SHA256: service},
				{Name: "controller-heartbeat@node-b.timer", SHA256: timer},
			}
			want := false
			switch name {
			case "managed":
				want = true
			case "legacy":
				delete(receipt, "heartbeat_timers")
				delete(receipt, "heartbeat_units_sha256")
				want = true
			case "no nodes":
				receipt["heartbeat_timers"] = []string{}
				config.Nodes, units = nil, nil
				want = true
			case "recovered rollback":
				receipt["heartbeat_cleanup"] = "approved-timers-disabled-and-services-stopped"
				receipt["failure_cleanup"] = "own-service-stopped"
				want = true
			case "missing timers":
				delete(receipt, "heartbeat_timers")
			case "missing digests":
				delete(receipt, "heartbeat_units_sha256")
			case "missing timer digest":
				delete(digests, "controller-heartbeat@.timer")
			case "unknown digest key":
				digests["foreign.service"] = service
			case "foreign timer":
				receipt["heartbeat_timers"].([]string)[0] = "controller-heartbeat@foreign.timer"
			case "duplicate timer":
				receipt["heartbeat_timers"].([]string)[1] = "controller-heartbeat@node-a.timer"
			case "unsorted timers":
				receipt["heartbeat_timers"] = []string{"controller-heartbeat@node-b.timer", "controller-heartbeat@node-a.timer"}
			case "missing unit":
				units = units[:3]
			case "service drift":
				units[0].SHA256 = strings.Repeat("e", 64)
			case "timer drift":
				units[1].SHA256 = strings.Repeat("e", 64)
			case "invalid digest":
				digests["controller-heartbeat@.timer"] = "invalid"
			case "missing install step":
				receipt["steps"] = []string{"software-installed", "configuration-approved", "inactive-systemd-unit"}
			case "unknown cleanup":
				receipt["heartbeat_cleanup"] = "all-units-accepted"
			case "unknown service cleanup":
				receipt["failure_cleanup"] = "all-units-accepted"
			case "null timers":
				receipt["heartbeat_timers"] = nil
			case "null digests":
				receipt["heartbeat_units_sha256"] = nil
			case "unknown field":
				receipt["enable_foreign_units"] = true
			case "case alias":
				receipt["Heartbeat_Timers"] = receipt["heartbeat_timers"]
			}
			raw, err := json.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			if name == "duplicate field" {
				raw = append([]byte(`{"heartbeat_timers":[],`), raw[1:]...)
			}
			var installed sourceInstallation
			if got := exactSourceRecord(raw, &installed) && validSourceHeartbeats(installed, config, units); got != want {
				t.Fatalf("receipt accepted = %v, want %v", got, want)
			}
		})
	}
}

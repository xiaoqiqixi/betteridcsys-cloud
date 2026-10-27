package control

import (
	"aster/cloud/internal/diagnostics"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func TestWorkerDiagnosticDistinguishesUnconfirmedWithoutRawError(t *testing.T) {
	for _, tc := range []struct {
		state, code, level string
		err                error
	}{
		{"accepted", "STATUS_RECORDED", "INFO", nil},
		{"uncertain", "STATUS_RECORDED", "WARN", nil},
		{"dispatched", "STATUS_RECORDED", "INFO", nil},
		{"succeeded", "STATUS_RECORDED", "INFO", nil},
		{"rejected", "STATUS_RECORDED", "INFO", nil},
		{"sending", "STATUS_RECORDED", "WARN", nil},
		{"", "STATUS_RECORDED", "WARN", nil},
		{"unknown", "STATUS_RECORDED", "WARN", nil},
		{"sending", "DEPENDENCY_UNAVAILABLE", "WARN", errors.New("PRIVATE DSN/password/path")},
		{"", "STATE_CONFLICT", "WARN", ErrState},
	} {
		t.Run(tc.state+tc.code, func(t *testing.T) {
			var out bytes.Buffer
			previous := slog.Default()
			slog.SetDefault(diagnostics.New(&out, "controller"))
			defer slog.SetDefault(previous)
			logWorkerOutcome(context.Background(), "aster_controller_operation", "dispatch", strings.Repeat("a", 32), tc.state, tc.err)
			var event map[string]any
			if err := json.Unmarshal(out.Bytes(), &event); err != nil || event["code"] != tc.code || event["level"] != tc.level || strings.Contains(out.String(), "PRIVATE") {
				t.Fatal(event, err)
			}
		})
	}
}

func TestTransferRunnerDiagnosticConfirmsOnlyKnownOutcomeWithoutError(t *testing.T) {
	for _, tc := range []struct {
		name, state, result, level string
		err                        error
	}{
		{"accepted", "accepted", "confirmed", "INFO", nil},
		{"dispatched", "dispatched", "confirmed", "INFO", nil},
		{"succeeded", "succeeded", "confirmed", "INFO", nil},
		{"rejected", "rejected", "confirmed", "INFO", nil},
		{"uncertain_without_error", "uncertain", "inspect_original_operation", "WARN", nil},
		{"sending_without_error", "sending", "inspect_original_operation", "WARN", nil},
		{"empty_without_error", "", "inspect_original_operation", "WARN", nil},
		{"unknown_without_error", "PRIVATE_STATE/path?token=secret", "inspect_original_operation", "WARN", nil},
		{"known_with_error", "succeeded", "inspect_original_operation", "WARN", errors.New("PRIVATE_ERROR DSN/password/endpoint/guest")},
	} {
		for _, reconcile := range []bool{false, true} {
			command := "dispatch"
			if reconcile {
				command = "reconcile"
			}
			t.Run(tc.name+"/"+command, func(t *testing.T) {
				var out bytes.Buffer
				previous := slog.Default()
				slog.SetDefault(diagnostics.New(&out, "controller"))
				defer slog.SetDefault(previous)
				op := strings.Repeat("b", 32)
				runner := NewOperationRunner(OperationWorker{})
				run := func(context.Context, string) (Operation, error) {
					return Operation{ID: op, State: tc.state}, tc.err
				}
				runner.run, runner.reconcile = run, run
				var err error
				if reconcile {
					err = runner.StartReconcile(op)
				} else {
					err = runner.Start(op)
				}
				if err != nil {
					t.Fatal(err)
				}
				runner.Close()
				var event map[string]any
				if err = json.Unmarshal(out.Bytes(), &event); err != nil {
					t.Fatal(err, out.String())
				}
				if event["msg"] != "aster_controller_transfer" || event["operation_id"] != op || event["result"] != tc.result || event["level"] != tc.level {
					t.Fatal(event)
				}
				if strings.Contains(out.String(), "PRIVATE") || strings.Contains(out.String(), "secret") || strings.Contains(out.String(), "password") {
					t.Fatal("diagnostic leaked private error or unknown state", out.String())
				}
				for key := range event {
					switch key {
					case "time", "level", "msg", "component", "operation_id", "state", "result":
					default:
						t.Fatal("unexpected diagnostic field", key)
					}
				}
			})
		}
	}
}

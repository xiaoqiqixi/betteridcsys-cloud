package control

import (
	"context"
	"testing"
	"time"
)

func TestDelayedAcceptanceCannotClearControllerUncertainty(t *testing.T) {
	for _, kind := range []string{"provisioning", "operation"} {
		t.Run(kind, func(t *testing.T) {
			now := time.Now().UTC()
			operation := id()
			f := &stateMachineFixture{
				job:      &Job{OperationID: operation, State: "uncertain", CreatedAt: now, UpdatedAt: now},
				op:       Operation{ID: operation, State: "uncertain", CreatedAt: now, UpdatedAt: now},
				instance: Instance{ID: id(), State: "unknown"},
			}
			s := stateMachineStore(t, f)
			var state string
			var updated time.Time
			var err error
			if kind == "provisioning" {
				var job Job
				job, err = s.Complete(context.Background(), operation, "accepted", now.Add(time.Minute))
				state, updated = job.State, job.UpdatedAt
			} else {
				var op Operation
				op, err = s.CompleteOperation(context.Background(), Config{}, operation, "accepted", nil, now.Add(time.Minute))
				state, updated = op.State, op.UpdatedAt
			}
			if err != nil || state != "uncertain" || !updated.Equal(now) || f.writes != 0 || f.instance.State != "unknown" {
				t.Fatalf("late acceptance changed uncertainty: state=%s writes=%d err=%v", state, f.writes, err)
			}
		})
	}
}

//go:build linux

package controllerhost

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"syscall"
	"time"
)

// This immutable seal is deliberately not a source fence: migration-cancel
// cannot release it. No activation/removal operation exists in this protocol.
type targetIntent struct {
	Schema       int    `json:"schema"`
	ControllerID string `json:"controller_id"`
	OperationID  string `json:"operation_id"`
	ConfigSHA    string `json:"configuration_sha256"`
	PlanSHA      string `json:"plan_sha256"`
	CreatedAt    string `json:"created_at"`
	Phase        string `json:"phase"`
}

func (h *Host) noTarget() error {
	f, e := h.file("target-restore.json", false)
	if f != nil {
		f.Close()
	}
	if errors.Is(e, syscall.ENOENT) {
		return nil
	}
	if e != nil {
		return ErrUnavailable
	}
	return ErrFenced
}
func (h *Host) readTarget() (targetIntent, error) {
	f, e := h.file("target-restore.json", false)
	if e != nil {
		return targetIntent{}, e
	}
	defer f.Close()
	raw, e := io.ReadAll(io.LimitReader(f, 4097))
	var v targetIntent
	if e != nil || json.Unmarshal(raw, &v) != nil {
		return targetIntent{}, ErrUnavailable
	}
	// Our own write-once canonical bytes exclude duplicate/case aliases and
	// unknown fields. A partial/corrupt record must remain admission-blocking.
	canonical, e := json.Marshal(v)
	if e != nil || !bytes.Equal(raw, append(canonical, '\n')) || v.Schema != 1 || v.ControllerID != h.id ||
		!operationName.MatchString(v.OperationID) || !digestName.MatchString(v.ConfigSHA) || !digestName.MatchString(v.PlanSHA) || v.Phase != "target-sealed" {
		return targetIntent{}, ErrUnavailable
	}
	if _, e = time.Parse(time.RFC3339Nano, v.CreatedAt); e != nil {
		return targetIntent{}, ErrUnavailable
	}
	return v, nil
}
func (h *Host) targetStatus(v targetIntent) (Status, error) {
	drained, e := h.drained()
	return Status{Schema: 1, ControllerID: h.id, OperationID: v.OperationID, Phase: "target-sealed", AdmissionBlocked: true, GuardedDrained: drained}, e
}

// PrepareTarget permits only an unused local controller identity or an exact
// replay of this same immutable plan. It seals before any database/configuration
// write and does not acquire a distributed node lease or authorize activation.
func (h *Host) PrepareTarget(operation, planSHA string) (Status, error) {
	if !operationName.MatchString(operation) || !digestName.MatchString(planSHA) {
		return Status{}, ErrInvalid
	}
	if e := h.lock(); e != nil {
		return Status{}, e
	}
	defer h.unlock()
	v, e := h.readTarget()
	if e == nil {
		if v.OperationID != operation || v.ConfigSHA != h.configSHA || v.PlanSHA != planSHA {
			return Status{}, ErrInvalid
		}
		return h.targetStatus(v)
	}
	if !errors.Is(e, syscall.ENOENT) {
		return Status{}, ErrUnavailable
	}
	// Rewind the protected directory descriptor; enumerate without path-based
	// reopening and refuse any source history or unknown state, not just fences.
	if _, e = h.dir.Seek(0, 0); e != nil {
		return Status{}, ErrUnavailable
	}
	names, e := h.dir.Readdirnames(-1)
	if e != nil {
		return Status{}, ErrUnavailable
	}
	for _, name := range names {
		if name != "control.lock" && name != "runtime.lock" {
			return Status{}, ErrInvalid
		}
	}
	drained, e := h.drained()
	if e != nil {
		return Status{}, e
	}
	if !drained {
		return Status{}, ErrBusy
	}
	v = targetIntent{1, h.id, operation, h.configSHA, planSHA, time.Now().UTC().Format(time.RFC3339Nano), "target-sealed"}
	if e = h.writeNew("target-restore.json", v); e != nil {
		return Status{}, e
	}
	return h.targetStatus(v)
}

// TargetStatus validates the exact immutable plan, not merely the operation ID.
func (h *Host) TargetStatus(operation, planSHA string) (Status, error) {
	if !operationName.MatchString(operation) || !digestName.MatchString(planSHA) {
		return Status{}, ErrInvalid
	}
	if e := h.lock(); e != nil {
		return Status{}, e
	}
	defer h.unlock()
	v, e := h.readTarget()
	if e != nil {
		return Status{}, ErrUnavailable
	}
	if v.OperationID != operation || v.ConfigSHA != h.configSHA || v.PlanSHA != planSHA {
		return Status{}, ErrInvalid
	}
	return h.targetStatus(v)
}

// WithSealedTarget holds local admission exclusion through a target data step.
// It grants neither service activation nor remote node ownership.
func (h *Host) WithSealedTarget(operation, planSHA string, action func() error) error {
	if !operationName.MatchString(operation) || !digestName.MatchString(planSHA) || action == nil {
		return ErrInvalid
	}
	if e := h.lock(); e != nil {
		return e
	}
	defer h.unlock()
	v, e := h.readTarget()
	if e != nil || v.OperationID != operation || v.ConfigSHA != h.configSHA || v.PlanSHA != planSHA {
		return ErrInvalid
	}
	drained, e := h.drained()
	if e != nil || !drained {
		return ErrBusy
	}
	return action()
}

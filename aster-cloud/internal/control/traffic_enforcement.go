package control

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"database/sql"
	"errors"
	"math"
	"strconv"
	"strings"
	"time"
)

func trafficExceeded(p TrafficPolicy, rx, tx uint64) bool {
	if p.LimitBytes == nil {
		return false
	}
	limit := *p.LimitBytes
	switch p.Direction {
	case "in":
		return rx > limit
	case "out":
		return tx > limit
	default:
		return math.MaxUint64-rx < tx || rx+tx > limit
	}
}

// Enforcement only admits a durable operation. Dispatcher/explicit dispatch use
// the same sending fence as every console operation. Stable IDs never retry an
// uncertain policy, including after a collector/controller process restart.
func (s *SQLStore) EnforceTraffic(ctx context.Context, c Config, id string, now time.Time) error {
	view, e := s.TrafficView(ctx, id, now)
	if e != nil {
		return e
	}
	if !view.AccountingSupported || view.ObservedAt == nil {
		return nil
	}
	rx, _ := strconv.ParseUint(view.RXBytes, 10, 64)
	tx, _ := strconv.ParseUint(view.TXBytes, 10, 64)
	desired := trafficDesired(view.Policy, rx, tx, view.PeriodEnd)
	if desired == (nodeproto.TrafficControl{}) {
		if view.Enforcement == nil {
			return nil
		}
		old, e := nodeproto.DecodeTask(view.Enforcement.Request)
		if e != nil {
			return ErrState
		}
		if old.TrafficControl == desired {
			return nil
		}
	}
	key := nodeproto.Digest(mustJSON(struct {
		Instance string
		Node     string
		Period   time.Time
		Policy   TrafficPolicy
		Version  time.Time
		Control  nodeproto.TrafficControl
	}{id, view.NodeID, view.PeriodStart, view.Policy, view.PolicyUpdatedAt, desired}))[:32]
	actor := nodeproto.Digest([]byte("aster.controller.traffic/1:" + c.ControllerID))[:32]
	_, _, e = s.CreateOperation(ctx, c, actor, id, key, OperationInput{Action: nodeproto.TrafficControlAction, TrafficControl: desired, trafficEnforcement: &trafficEnforcementIntent{Updated: view.PolicyUpdatedAt, Desired: desired}}, now)
	return e
}
func presetTrafficSupported(c Config, id string, caps Capability, network string) bool {
	for _, p := range c.Presets {
		if p.ID == id && p.TrafficPolicy != nil {
			return trafficPolicySupported(caps, *p.TrafficPolicy, network)
		}
	}
	return true
}

type trafficEnforcementIntent struct {
	Updated time.Time
	Desired nodeproto.TrafficControl
}

func trafficDesired(p TrafficPolicy, rx, tx uint64, end time.Time) nodeproto.TrafficControl {
	desired := nodeproto.TrafficControl{}
	if trafficExceeded(p, rx, tx) {
		if p.OveragePolicy == "suspend" {
			desired.Suspended = true
		}
		if strings.HasPrefix(p.OveragePolicy, "throttle:") {
			desired.ThrottleMbps, _ = strconv.Atoi(strings.TrimPrefix(p.OveragePolicy, "throttle:"))
		}
	}
	if desired.ThrottleMbps > 0 || desired.Suspended {
		desired.ExpiresAt = end.UTC().Format(time.RFC3339Nano)
	}
	return desired
}
func trafficEnforcementGateTx(ctx context.Context, tx *sql.Tx, i Instance, expected *trafficEnforcementIntent, now time.Time) error {
	if expected == nil {
		return nil
	}
	p, updated, e := trafficPolicyTx(ctx, tx, i)
	if e != nil {
		return e
	}
	if !updated.Equal(expected.Updated) {
		return ErrState
	}
	start, end := TrafficPeriod(now, p.ResetDay)
	var rx, bytes uint64
	e = tx.QueryRowContext(ctx, "SELECT rx_bytes,tx_bytes FROM controller_traffic WHERE instance_id=? AND period_start=?", i.ID, start).Scan(&rx, &bytes)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	if trafficDesired(p, rx, bytes, end) != expected.Desired {
		return ErrState
	}
	return nil
}

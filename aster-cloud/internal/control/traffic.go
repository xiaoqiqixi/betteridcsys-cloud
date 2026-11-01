package control

import (
	"aster/billing/controllerapi"
	"aster/billing/serviceapi"
	"aster/cloud/internal/nodeproto"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type TrafficPolicy struct {
	ResetDay      int     `json:"reset_day"`
	Direction     string  `json:"direction"`
	LimitBytes    *uint64 `json:"limit_bytes"`
	OveragePolicy string  `json:"overage_policy"`
}

func (p TrafficPolicy) Valid() bool {
	if p.ResetDay < 1 || p.ResetDay > 31 || (p.Direction != "in" && p.Direction != "out" && p.Direction != "both") {
		return false
	}
	if p.OveragePolicy == "none" {
		return true
	}
	if p.LimitBytes == nil {
		return false
	}
	if p.OveragePolicy == "suspend" {
		return true
	}
	if !strings.HasPrefix(p.OveragePolicy, "throttle:") {
		return false
	}
	s := strings.TrimPrefix(p.OveragePolicy, "throttle:")
	n, e := strconv.Atoi(s)
	return e == nil && n >= 1 && n <= 100000 && strconv.Itoa(n) == s
}
func defaultTrafficPolicy(r controllerapi.Resources) TrafficPolicy {
	p := TrafficPolicy{ResetDay: 1, Direction: r.TrafficDirection, OveragePolicy: "none"}
	if p.Direction == "all" || p.Direction == "" {
		p.Direction = "both"
	}
	if r.TransferGiB > 0 {
		n := uint64(r.TransferGiB) * (1 << 30)
		p.LimitBytes = &n
	}
	return p
}

// Reset days 29-31 clamp to the last day of shorter months. Boundaries are UTC.
func TrafficPeriod(at time.Time, resetDay int) (time.Time, time.Time) {
	at = at.UTC()
	boundary := func(year int, month time.Month) time.Time {
		last := time.Date(year, month+1, 0, 0, 0, 0, 0, time.UTC).Day()
		day := resetDay
		if day > last {
			day = last
		}
		return time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
	}
	start := boundary(at.Year(), at.Month())
	if at.Before(start) {
		previous := time.Date(at.Year(), at.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, -1, 0)
		start = boundary(previous.Year(), previous.Month())
	}
	next := time.Date(start.Year(), start.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0)
	return start, boundary(next.Year(), next.Month())
}
func trafficPolicyTx(ctx context.Context, tx *sql.Tx, i Instance) (TrafficPolicy, time.Time, error) {
	var raw []byte
	var updated time.Time
	e := tx.QueryRowContext(ctx, "SELECT policy,updated_at FROM controller_traffic_policies WHERE instance_id=?", i.ID).Scan(&raw, &updated)
	if errors.Is(e, sql.ErrNoRows) {
		return defaultTrafficPolicy(i.Resources), i.CreatedAt, nil
	}
	if e != nil {
		return TrafficPolicy{}, updated, e
	}
	var p TrafficPolicy
	if json.Unmarshal(raw, &p) != nil || !p.Valid() {
		return p, updated, ErrState
	}
	return p, updated, nil
}
func writeTrafficPolicy(ctx context.Context, tx *sql.Tx, id string, p TrafficPolicy, now time.Time) error {
	_, e := tx.ExecContext(ctx, "INSERT INTO controller_traffic_policies(instance_id,policy,updated_at) VALUES(?,?,?) ON DUPLICATE KEY UPDATE policy=VALUES(policy),updated_at=VALUES(updated_at)", id, mustJSON(p), now)
	return e
}
func presetTrafficPolicy(ctx context.Context, tx *sql.Tx, c Config, id, preset string, now time.Time) error {
	for _, p := range c.Presets {
		if p.ID == preset && p.TrafficPolicy != nil {
			return writeTrafficPolicy(ctx, tx, id, *p.TrafficPolicy, now)
		}
	}
	return nil
}
func (s *SQLStore) SetTrafficPolicy(ctx context.Context, c Config, actor, id string, p TrafficPolicy, now time.Time) error {
	if !nodeproto.ValidID(id) || !p.Valid() || !nodeproto.ValidID(actor) {
		return ErrInput
	}
	tx, e := s.locked(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	i, e := scanInstance(tx.QueryRowContext(ctx, "SELECT id,owner_ref,node_id,hostname,state,resources,created_at,updated_at FROM controller_instances WHERE id=?", id))
	if e != nil {
		return e
	}
	if i.State == "deleted" {
		return ErrState
	}
	if _, ok := c.Node(i.NodeID); !ok {
		return ErrState
	}
	old, _, e := trafficPolicyTx(ctx, tx, i)
	if e != nil {
		return e
	}
	if string(mustJSON(old)) == string(mustJSON(p)) {
		return nil
	}
	var pending int
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM controller_operations WHERE instance_id=? AND action=? AND state NOT IN ('succeeded','rejected','resolved')", id, nodeproto.TrafficControlAction).Scan(&pending); e != nil {
		return e
	}
	if pending != 0 {
		return ErrState
	}
	if old.ResetDay != p.ResetDay {
		var count int
		if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM controller_traffic_samples WHERE instance_id=? AND (rx_bytes>0 OR tx_bytes>0)", id).Scan(&count); e != nil {
			return e
		}
		if count > 0 {
			return ErrState
		}
	}
	var raw []byte
	var caps Capability
	if e = tx.QueryRowContext(ctx, "SELECT capabilities FROM controller_nodes WHERE id=?", i.NodeID).Scan(&raw); e != nil {
		return e
	}
	if !strict(raw, &caps) || !trafficPolicySupported(caps, p, i.Resources.NetworkType) {
		return ErrState
	}
	if e = writeTrafficPolicy(ctx, tx, id, p, now); e != nil {
		return e
	}
	if e = audit(ctx, tx, "user:"+actor, "traffic.policy."+p.OveragePolicy, id, now); e != nil {
		return e
	}
	return tx.Commit()
}
func trafficPolicySupported(c Capability, p TrafficPolicy, network string) bool {
	if !contains(c.NetworkProfiles, nodeproto.TrafficCapability) {
		return false
	}
	if p.OveragePolicy == "suspend" {
		return contains(c.NetworkProfiles, nodeproto.TrafficSuspendCapability)
	}
	if strings.HasPrefix(p.OveragePolicy, "throttle:") {
		return network == "normal" && contains(c.NetworkProfiles, nodeproto.TrafficThrottleCapability)
	}
	return true
}
func supportsTraffic(c Capability, r controllerapi.Resources) bool {
	return r.TransferGiB == 0 && r.TrafficDirection == "all" || contains(c.NetworkProfiles, nodeproto.TrafficCapability)
}
func (c *NodeClient) Traffic(ctx context.Context, id string) (nodeproto.InstanceTraffic, error) {
	if !nodeproto.ValidID(id) {
		return nodeproto.InstanceTraffic{}, ErrInput
	}
	raw, status, e := c.callStatus(ctx, http.MethodGet, "/v1/instances/"+id+"/traffic", nil, "")
	if e != nil || status != http.StatusOK {
		return nodeproto.InstanceTraffic{}, ErrUnavailable
	}
	v, e := nodeproto.DecodeTraffic(raw)
	if e != nil || v.NodeID != c.profile.ID || v.InstanceID != id {
		return v, ErrUnavailable
	}
	return v, nil
}

// AggregateTraffic applies only positive differences from daily cumulative
// revisions under controller_lock. Replays, concurrent collectors and a lost
// response after COMMIT cannot bill a byte twice.
func (s *SQLStore) AggregateTraffic(ctx context.Context, v nodeproto.InstanceTraffic, now time.Time) error {
	if !v.Valid() {
		return ErrInput
	}
	observed, _ := time.Parse(time.RFC3339Nano, v.ObservedAt)
	if observed.After(now.Add(5 * time.Second)) {
		return ErrInput
	}
	tx, e := s.locked(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	i, e := scanInstance(tx.QueryRowContext(ctx, "SELECT id,owner_ref,node_id,hostname,state,resources,created_at,updated_at FROM controller_instances WHERE id=?", v.InstanceID))
	if e != nil {
		return e
	}
	if i.OwnerRef != v.OwnerRef {
		return ErrState
	}
	if i.NodeID != v.NodeID {
		var known int
		if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM controller_migrations WHERE instance_id=? AND source_node_id=?", i.ID, v.NodeID).Scan(&known); e != nil {
			return e
		}
		if known == 0 {
			return ErrState
		}
	}
	p, _, e := trafficPolicyTx(ctx, tx, i)
	if e != nil {
		return e
	}
	for _, d := range v.Days {
		day, _ := time.Parse("2006-01-02", d.Day)
		rx, _ := strconv.ParseUint(d.RXBytes, 10, 64)
		txBytes, _ := strconv.ParseUint(d.TXBytes, 10, 64)
		var revision, oldRX, oldTX uint64
		e = tx.QueryRowContext(ctx, "SELECT revision,rx_bytes,tx_bytes FROM controller_traffic_samples WHERE instance_id=? AND node_id=? AND stream_id=? AND sample_day=?", i.ID, v.NodeID, v.StreamID, day).Scan(&revision, &oldRX, &oldTX)
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		if d.Revision < revision {
			continue
		}
		if d.Revision == revision {
			if rx != oldRX || txBytes != oldTX {
				return ErrConflict
			}
			continue
		}
		if rx < oldRX || txBytes < oldTX {
			return ErrConflict
		}
		start, end := TrafficPeriod(day, p.ResetDay)
		if _, e = tx.ExecContext(ctx, "INSERT INTO controller_traffic(instance_id,period_start,period_end,rx_bytes,tx_bytes) VALUES(?,?,?,?,?) ON DUPLICATE KEY UPDATE rx_bytes=rx_bytes+VALUES(rx_bytes),tx_bytes=tx_bytes+VALUES(tx_bytes)", i.ID, start, end, rx-oldRX, txBytes-oldTX); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, "INSERT INTO controller_traffic_samples(instance_id,node_id,stream_id,sample_day,revision,rx_bytes,tx_bytes,observed_at) VALUES(?,?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE revision=VALUES(revision),rx_bytes=VALUES(rx_bytes),tx_bytes=VALUES(tx_bytes),observed_at=VALUES(observed_at)", i.ID, v.NodeID, v.StreamID, day, d.Revision, rx, txBytes, observed); e != nil {
			return e
		}
	}
	return tx.Commit()
}

type TrafficView struct {
	ResetDayLocked      bool          `json:"reset_day_locked"`
	NodeID              string        `json:"-"`
	PolicyUpdatedAt     time.Time     `json:"-"`
	Policy              TrafficPolicy `json:"policy"`
	RXBytes             string        `json:"rx_bytes"`
	TXBytes             string        `json:"tx_bytes"`
	PeriodStart         time.Time     `json:"period_start"`
	PeriodEnd           time.Time     `json:"period_end"`
	ObservedAt          *time.Time    `json:"observed_at"`
	InboundMbps         int           `json:"inbound_mbps"`
	OutboundMbps        int           `json:"outbound_mbps"`
	AccountingSupported bool          `json:"accounting_supported"`
	ThrottleSupported   bool          `json:"throttle_supported"`
	SuspendSupported    bool          `json:"suspend_supported"`
	Enforcement         *Operation    `json:"enforcement"`
}

func (s *SQLStore) Traffic(ctx context.Context, id string, now time.Time) (serviceapi.Traffic, error) {
	view, e := s.TrafficView(ctx, id, now)
	if e != nil {
		return serviceapi.Traffic{}, e
	}
	rx, _ := strconv.ParseUint(view.RXBytes, 10, 64)
	tx, _ := strconv.ParseUint(view.TXBytes, 10, 64)
	return serviceapi.Traffic{RXBytes: rx, TXBytes: tx, LimitBytes: view.Policy.LimitBytes, PeriodStart: view.PeriodStart, PeriodEnd: view.PeriodEnd}, nil
}
func (s *SQLStore) TrafficView(ctx context.Context, id string, now time.Time) (TrafficView, error) {
	// One read-only transaction prevents a policy change from mixing boundaries.
	out := TrafficView{RXBytes: "0", TXBytes: "0"}
	tx, e := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	i, e := scanInstance(tx.QueryRowContext(ctx, "SELECT id,owner_ref,node_id,hostname,state,resources,created_at,updated_at FROM controller_instances WHERE id=?", id))
	if e != nil {
		return out, e
	}
	out.Policy, out.PolicyUpdatedAt, e = trafficPolicyTx(ctx, tx, i)
	if e != nil {
		return out, e
	}
	out.PeriodStart, out.PeriodEnd = TrafficPeriod(now, out.Policy.ResetDay)
	out.NodeID = i.NodeID
	out.InboundMbps = i.Resources.InboundBandwidthMbps
	out.OutboundMbps = i.Resources.BandwidthMbps
	var rx, bytes uint64
	e = tx.QueryRowContext(ctx, "SELECT rx_bytes,tx_bytes FROM controller_traffic WHERE instance_id=? AND period_start=?", id, out.PeriodStart).Scan(&rx, &bytes)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return out, e
	}
	out.RXBytes = strconv.FormatUint(rx, 10)
	out.TXBytes = strconv.FormatUint(bytes, 10)
	var seen sql.NullTime
	var sampledDays int
	if e = tx.QueryRowContext(ctx, "SELECT MAX(observed_at),COALESCE(SUM(rx_bytes>0 OR tx_bytes>0),0) FROM controller_traffic_samples WHERE instance_id=?", id).Scan(&seen, &sampledDays); e != nil {
		return out, e
	}
	out.ResetDayLocked = sampledDays > 0
	if seen.Valid {
		at := seen.Time.UTC()
		out.ObservedAt = &at
	}
	var raw []byte
	var caps Capability
	e = tx.QueryRowContext(ctx, "SELECT capabilities FROM controller_nodes WHERE id=?", i.NodeID).Scan(&raw)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return out, e
	}
	if e == nil && strict(raw, &caps) {
		out.AccountingSupported = contains(caps.NetworkProfiles, nodeproto.TrafficCapability)
		out.ThrottleSupported = i.Resources.NetworkType == "normal" && contains(caps.NetworkProfiles, nodeproto.TrafficThrottleCapability)
		out.SuspendSupported = contains(caps.NetworkProfiles, nodeproto.TrafficSuspendCapability)
	}
	op, e := scanOperation(tx.QueryRowContext(ctx, "SELECT "+operationColumns+" FROM controller_operations WHERE instance_id=? AND action=? ORDER BY seq DESC LIMIT 1", id, nodeproto.TrafficControlAction))
	if e == nil {
		out.Enforcement = &op
	} else if !errors.Is(e, ErrNotFound) {
		return out, e
	}
	return out, tx.Commit()
}

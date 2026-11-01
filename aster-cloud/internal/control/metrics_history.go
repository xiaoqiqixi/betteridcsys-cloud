package control

import (
	"aster/billing/serviceapi"
	"aster/cloud/internal/nodeproto"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"time"
)

const metricStep = 5 * time.Minute

type metricAggregate struct {
	Sum     [5]float64 `json:"sum"`
	Seconds [5]float64 `json:"seconds"`
}

// Rates are time-weighted, not averaged by sample count. A reset, unavailable
// counter or a gap longer than ten minutes remains null rather than a zero.
// Network and disk rates are bytes/second; CPU is a percent of allocated vCPUs.
func metricRates(previous, next nodeproto.InstanceMetrics) [5]*float64 {
	var out [5]*float64
	a, _ := time.Parse(time.RFC3339Nano, previous.ObservedAt)
	b, _ := time.Parse(time.RFC3339Nano, next.ObservedAt)
	seconds := b.Sub(a).Seconds()
	if seconds <= 0 || seconds > 600 || previous.NodeID != next.NodeID || previous.VCPUs != next.VCPUs {
		return out
	}
	old := []*string{previous.CPUTimeNS, previous.NetworkReceiveBytes, previous.NetworkTransmitBytes, previous.BlockReadBytes, previous.BlockWriteBytes}
	current := []*string{next.CPUTimeNS, next.NetworkReceiveBytes, next.NetworkTransmitBytes, next.BlockReadBytes, next.BlockWriteBytes}
	for j := range old {
		if old[j] == nil || current[j] == nil {
			continue
		}
		x, e := strconv.ParseUint(*old[j], 10, 64)
		y, f := strconv.ParseUint(*current[j], 10, 64)
		if e != nil || f != nil || y < x {
			continue
		}
		v := float64(y-x) / seconds
		if j == 0 {
			v = v / 1e9 / float64(next.VCPUs) * 100
			if v > 100 {
				continue
			}
		}
		out[j] = &v
	}
	return out
}

// RecordMetrics is an explicit collector write. HTTP monitoring and operation
// reconciliation never call it. Placement is checked again inside the lock.
func (s *SQLStore) RecordMetrics(ctx context.Context, v nodeproto.InstanceMetrics, now time.Time) error {
	if !v.Validate() || !metricsFresh(v.ObservedAt, now) {
		return ErrInput
	}
	tx, e := s.locked(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	instance, e := scanInstance(tx.QueryRowContext(ctx, "SELECT id,owner_ref,node_id,hostname,state,resources,created_at,updated_at FROM controller_instances WHERE id=?", v.InstanceID))
	if e != nil {
		return e
	}
	if instance.OwnerRef != v.OwnerRef || instance.NodeID != v.NodeID || instance.Hostname != v.Hostname || instance.Resources.CPUCores != v.VCPUs || instance.State == "deleted" {
		return ErrState
	}
	at, _ := time.Parse(time.RFC3339Nano, v.ObservedAt)
	var raw []byte
	var previous nodeproto.InstanceMetrics
	e = tx.QueryRowContext(ctx, "SELECT sample FROM controller_metric_cursors WHERE instance_id=?", v.InstanceID).Scan(&raw)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	if e == nil {
		if json.Unmarshal(raw, &previous) != nil || !previous.Validate() {
			return ErrState
		}
		before, _ := time.Parse(time.RFC3339Nano, previous.ObservedAt)
		if !at.After(before) {
			return nil
		}
		rates := metricRates(previous, v)
		if at.Sub(before) <= 10*time.Minute {
			for start := before; start.Before(at); {
				bucket := start.Truncate(metricStep)
				end := bucket.Add(metricStep)
				if end.After(at) {
					end = at
				}
				seconds := end.Sub(start).Seconds()
				var agg metricAggregate
				var data []byte
				err := tx.QueryRowContext(ctx, "SELECT aggregate_json FROM controller_metrics WHERE instance_id=? AND bucket=?", v.InstanceID, bucket).Scan(&data)
				if err != nil && !errors.Is(err, sql.ErrNoRows) {
					return err
				}
				if err == nil && json.Unmarshal(data, &agg) != nil {
					return ErrState
				}
				for k, value := range rates {
					if value != nil {
						agg.Sum[k] += *value * seconds
						agg.Seconds[k] += seconds
					}
				}
				data, _ = json.Marshal(agg)
				if _, e = tx.ExecContext(ctx, "INSERT INTO controller_metrics(instance_id,bucket,aggregate_json) VALUES(?,?,?) ON DUPLICATE KEY UPDATE aggregate_json=VALUES(aggregate_json)", v.InstanceID, bucket, data); e != nil {
					return e
				}
				start = end
			}
		}
	}
	raw, _ = json.Marshal(v)
	if _, e = tx.ExecContext(ctx, "INSERT INTO controller_metric_cursors(instance_id,observed_at,sample) VALUES(?,?,?) ON DUPLICATE KEY UPDATE observed_at=VALUES(observed_at),sample=VALUES(sample)", v.InstanceID, at, raw); e != nil {
		return e
	}
	return tx.Commit()
}

func (s *SQLStore) PruneMetrics(ctx context.Context, now time.Time) error {
	// Time-based retention also removes cursors for instances no longer sampled.
	tx, e := s.locked(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	for _, q := range []string{"DELETE FROM controller_metrics WHERE bucket<?", "DELETE FROM controller_metric_cursors WHERE observed_at<?"} {
		if _, e = tx.ExecContext(ctx, q, now.UTC().Add(-30*24*time.Hour)); e != nil {
			return e
		}
	}
	return tx.Commit()
}

// QueryMetrics returns exactly the requested 5-minute grid, including null
// gaps. It is read-only and ready for the aster.service/1 metrics endpoint.
func (s *SQLStore) QueryMetrics(ctx context.Context, instance, window string, now time.Time) (serviceapi.Metrics, error) {
	result := serviceapi.Metrics{StepSeconds: 300, Points: []serviceapi.MetricPoint{}}
	durations := map[string]time.Duration{"1h": time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour}
	duration, ok := durations[window]
	if !ok || !nodeproto.ValidID(instance) {
		return result, ErrInput
	}
	if _, e := s.Instance(ctx, instance); e != nil {
		return result, e
	}
	end := now.UTC().Truncate(metricStep).Add(metricStep)
	start := end.Add(-duration)
	rows, e := s.DB.QueryContext(ctx, "SELECT bucket,aggregate_json FROM controller_metrics WHERE instance_id=? AND bucket>=? AND bucket<? ORDER BY bucket", instance, start, end)
	if e != nil {
		return result, e
	}
	defer rows.Close()
	values := map[time.Time]metricAggregate{}
	for rows.Next() {
		var at time.Time
		var raw []byte
		var a metricAggregate
		if e = rows.Scan(&at, &raw); e != nil {
			return result, e
		}
		if json.Unmarshal(raw, &a) != nil {
			return result, ErrState
		}
		values[at.UTC()] = a
	}
	if e = rows.Err(); e != nil {
		return result, e
	}
	for at := start; at.Before(end); at = at.Add(metricStep) {
		p := serviceapi.MetricPoint{At: at}
		a := values[at]
		out := []**float64{&p.CPUPercent, &p.NetInBPS, &p.NetOutBPS, &p.DiskReadBPS, &p.DiskWriteBPS}
		for j := range out {
			if a.Seconds[j] > 0 {
				v := a.Sum[j] / a.Seconds[j]
				*out[j] = &v
			}
		}
		result.Points = append(result.Points, p)
	}
	return result, nil
}

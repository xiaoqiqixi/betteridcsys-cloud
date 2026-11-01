package control

import (
	"context"
	"log/slog"
	"time"
)

type TelemetryConfig struct {
	Enabled bool `json:"enabled"`
}
type TelemetryCollector struct {
	Store  *SQLStore
	Config Config
}

func (c TelemetryCollector) Run(ctx context.Context) {
	if !c.Config.Telemetry.Enabled {
		return
	}
	timer := time.NewTicker(time.Minute)
	defer timer.Stop()
	for {
		if err := c.Collect(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("aster_telemetry_collection_incomplete")
		}
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
	}
}
func (c TelemetryCollector) Collect(ctx context.Context) error {
	// Keyset traversal includes fleets larger than the console's first page.
	after := ""
	var first error
	for {
		rows, e := c.Store.DB.QueryContext(ctx, "SELECT id,node_id FROM controller_instances WHERE id>? AND state <> 'rejected' ORDER BY id LIMIT 100", after)
		if e != nil {
			return e
		}
		type target struct{ id, node string }
		batch := []target{}
		for rows.Next() {
			var t target
			if e = rows.Scan(&t.id, &t.node); e != nil {
				rows.Close()
				return e
			}
			batch = append(batch, t)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		for _, t := range batch {
			after = t.id
			p, ok := c.Config.Node(t.node)
			if !ok {
				continue
			}
			e = c.collectInstance(ctx, p, t.id)
			if e != nil && first == nil {
				first = e
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
		}
		if len(batch) < 100 {
			break
		}
	}
	if e := c.Store.PruneMetrics(ctx, time.Now().UTC()); e != nil && first == nil {
		first = e
	}
	return first
}
func (c TelemetryCollector) collectTraffic(parent context.Context, p NodeProfile, id string) error {
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	client, e := NewNodeClient(ctx, p)
	if e != nil {
		return e
	}
	snapshot, trafficErr := client.Traffic(ctx, id)
	if trafficErr == nil {
		trafficErr = c.Store.AggregateTraffic(ctx, snapshot, time.Now().UTC())
	}
	// Old migration sources retain a final journal snapshot after retirement.
	rows, e := c.Store.DB.QueryContext(ctx, "SELECT DISTINCT source_node_id FROM controller_migrations WHERE instance_id=? AND source_node_id<>?", id, p.ID)
	if e != nil {
		return e
	}
	sources := []string{}
	for rows.Next() {
		var node string
		if e = rows.Scan(&node); e != nil {
			rows.Close()
			return e
		}
		sources = append(sources, node)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, node := range sources {
		profile, ok := c.Config.Node(node)
		if !ok {
			continue
		}
		old, e := NewNodeClient(ctx, profile)
		if e != nil {
			continue
		}
		sample, e := old.Traffic(ctx, id)
		if e == nil {
			e = c.Store.AggregateTraffic(ctx, sample, time.Now().UTC())
		}
		if e != nil && trafficErr == nil {
			trafficErr = e
		}
	}
	if e := c.Store.EnforceTraffic(ctx, c.Config, id, time.Now().UTC()); e != nil && trafficErr == nil {
		trafficErr = e
	}
	return trafficErr
}

func (c TelemetryCollector) collectInstance(parent context.Context, p NodeProfile, id string) error {
	// Each read family has its own deadline. A slow or unsupported live metrics
	// endpoint must not prevent journal accounting (or vice versa).
	trafficErr := c.collectTraffic(parent, p, id)
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	client, e := NewNodeClient(ctx, p)
	if e != nil {
		return e
	}
	v, e := client.Metrics(ctx, id)
	if e == nil {
		e = c.Store.RecordMetrics(ctx, v, time.Now().UTC())
	}
	if e != nil {
		return e
	}
	return trafficErr
}

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
		rows, e := c.Store.DB.QueryContext(ctx, "SELECT id,node_id FROM controller_instances WHERE id>? AND state NOT IN ('deleted','rejected') ORDER BY id LIMIT 100", after)
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
func (c TelemetryCollector) collectInstance(parent context.Context, p NodeProfile, id string) error {
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	client, e := NewNodeClient(ctx, p)
	if e != nil {
		return e
	}
	v, e := client.Metrics(ctx, id)
	if e != nil {
		return e
	}
	return c.Store.RecordMetrics(ctx, v, time.Now().UTC())
}

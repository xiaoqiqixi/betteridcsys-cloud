package control

import (
	"aster/billing/serviceapi"
	"context"
	"time"
)

// The service HTTP adapter authenticates the owner before these read-only
// interfaces. Neither endpoint samples a node, writes data or enforces policy.
func (s *SQLStore) ServiceMetrics(ctx context.Context, id, window string, now time.Time) (serviceapi.Metrics, error) {
	return s.QueryMetrics(ctx, id, window, now)
}
func (s *SQLStore) ServiceTraffic(ctx context.Context, id string, now time.Time) (serviceapi.Traffic, error) {
	return s.Traffic(ctx, id, now)
}

package control

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"encoding/json"
	"math"
	"testing"
	"time"
)

func historySample(at time.Time) nodeproto.InstanceMetrics {
	return nodeproto.InstanceMetrics{Protocol: nodeproto.MetricsProtocol, NodeID: "node-a", InstanceID: "11111111111111111111111111111111", OwnerRef: "22222222222222222222222222222222", Hostname: "history-test", State: "running", ObservedAt: at.UTC().Format(time.RFC3339Nano), VCPUs: 2, CPUTimeNS: metricString("0"), NetworkReceiveBytes: metricString("0")}
}
func TestMetricRatesHandleGapsResetAndMissing(t *testing.T) {
	now := time.Now()
	a := historySample(now)
	b := a
	b.ObservedAt = now.Add(time.Minute).UTC().Format(time.RFC3339Nano)
	b.CPUTimeNS = metricString("60000000000")
	b.NetworkReceiveBytes = metricString("6000")
	r := metricRates(a, b)
	if r[0] == nil || *r[0] != 50 || r[1] == nil || *r[1] != 100 || r[2] != nil {
		t.Fatal(r)
	}
	a.CPUTimeNS = metricString("70000000000")
	if metricRates(a, b)[0] != nil {
		t.Fatal("counter reset was a rate")
	}
	b.ObservedAt = now.Add(11 * time.Minute).UTC().Format(time.RFC3339Nano)
	if metricRates(a, b)[1] != nil {
		t.Fatal("gap interpolated")
	}
}
func TestMySQLMetricHistoryReplayWeightingAndRetention(t *testing.T) {
	s := consoleHTTPStore(t)
	_, _, i, _ := readyConsoleInstance(t, s)
	ctx := context.Background()
	start := time.Now().UTC().Truncate(metricStep).Add(-metricStep)
	a := historySample(start)
	a.NodeID = i.NodeID
	a.InstanceID = i.ID
	a.OwnerRef = i.OwnerRef
	a.Hostname = i.Hostname
	a.VCPUs = i.Resources.CPUCores
	if e := s.RecordMetrics(ctx, a, start); e != nil {
		t.Fatal(e)
	}
	b := a
	b.ObservedAt = start.Add(2 * time.Minute).Format(time.RFC3339Nano)
	b.NetworkReceiveBytes = metricString("12000")
	if e := s.RecordMetrics(ctx, b, start.Add(2*time.Minute)); e != nil {
		t.Fatal(e)
	}
	b.ObservedAt = start.Add(5 * time.Minute).Format(time.RFC3339Nano)
	b.NetworkReceiveBytes = metricString("48000")
	for n := 0; n < 3; n++ {
		if e := s.RecordMetrics(ctx, b, start.Add(5*time.Minute)); e != nil {
			t.Fatal(e)
		}
	}
	result, e := s.QueryMetrics(ctx, i.ID, "1h", start.Add(5*time.Minute))
	if e != nil || len(result.Points) != 12 {
		t.Fatal(e, result)
	}
	var rate *float64
	for _, p := range result.Points {
		if p.At.Equal(start) {
			rate = p.NetInBPS
		}
	}
	if rate == nil || math.Abs(*rate-160) > 0.00001 {
		t.Fatal("replay/sample-count biased weighted average", rate)
	}
	var raw []byte
	if e = s.DB.QueryRow("SELECT aggregate_json FROM controller_metrics WHERE instance_id=? AND bucket=?", i.ID, start).Scan(&raw); e != nil {
		t.Fatal(e)
	}
	var agg metricAggregate
	json.Unmarshal(raw, &agg)
	if agg.Seconds[1] != 300 {
		t.Fatal("replay doubled accounting")
	}
	for _, window := range []string{"24h", "7d", "30d"} {
		if _, e = s.QueryMetrics(ctx, i.ID, window, time.Now()); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = s.QueryMetrics(ctx, i.ID, "2h", time.Now()); e != ErrInput {
		t.Fatal(e)
	}
	if e = s.PruneMetrics(ctx, start.Add(31*24*time.Hour)); e != nil {
		t.Fatal(e)
	}
	var count int
	if e = s.DB.QueryRow("SELECT COUNT(*) FROM controller_metrics").Scan(&count); e != nil || count != 0 {
		t.Fatal("retention", e, count)
	}
}

package control

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"encoding/json"
	"math"
	"sync"
	"testing"
	"time"
)

func TestTrafficBillingPeriodsClampLeapAndMonthEnds(t *testing.T) {
	for _, test := range []struct {
		at         string
		day        int
		start, end string
	}{{"2024-02-28", 31, "2024-01-31", "2024-02-29"}, {"2024-02-29", 31, "2024-02-29", "2024-03-31"}, {"2025-03-01", 31, "2025-02-28", "2025-03-31"}, {"2025-12-31", 1, "2025-12-01", "2026-01-01"}} {
		at, _ := time.Parse("2006-01-02", test.at)
		a, b := TrafficPeriod(at, test.day)
		if a.Format("2006-01-02") != test.start || b.Format("2006-01-02") != test.end {
			t.Fatal(test, a, b)
		}
	}
}
func TestTrafficDirectionAndUnsignedOverflow(t *testing.T) {
	limit := uint64(100)
	p := TrafficPolicy{ResetDay: 1, Direction: "both", LimitBytes: &limit, OveragePolicy: "throttle:1"}
	if !p.Valid() || !trafficExceeded(p, 60, 41) || trafficExceeded(p, 60, 40) {
		t.Fatal("both threshold")
	}
	p.Direction = "in"
	if trafficExceeded(p, 60, 999) {
		t.Fatal("out charged as in")
	}
	p.Direction = "out"
	if trafficExceeded(p, 999, 60) {
		t.Fatal("in charged as out")
	}
	p.Direction = "both"
	limit = math.MaxUint64
	if !trafficExceeded(p, math.MaxUint64, 1) {
		t.Fatal("uint64 overflow hid overage")
	}
	for _, bad := range []string{"throttle:0", "throttle:01", "throttle:100001", "auto-retry"} {
		p.OveragePolicy = bad
		if p.Valid() {
			t.Fatal(bad)
		}
	}
}
func TestMySQLTrafficReplayConcurrentAggregationAndUncertainEnforcement(t *testing.T) {
	s := consoleHTTPStore(t)
	c, p, i, now := readyConsoleInstance(t, s)
	ctx := context.Background()
	caps := testCapabilities(p, now)
	caps.NetworkProfiles = append(caps.NetworkProfiles, nodeproto.TrafficCapability, nodeproto.TrafficThrottleCapability, nodeproto.TrafficSuspendCapability)
	if _, e := s.DB.Exec("UPDATE controller_nodes SET capabilities=? WHERE id=?", mustJSON(caps), p.ID); e != nil {
		t.Fatal(e)
	}
	limit := uint64(100)
	policy := TrafficPolicy{ResetDay: now.Day(), Direction: "both", LimitBytes: &limit, OveragePolicy: "throttle:8"}
	if e := s.SetTrafficPolicy(ctx, c, id(), i.ID, policy, now); e != nil {
		t.Fatal(e)
	}
	sample := nodeproto.InstanceTraffic{Protocol: nodeproto.TrafficProtocol, NodeID: p.ID, InstanceID: i.ID, OwnerRef: i.OwnerRef, StreamID: id(), ObservedAt: now.Format(time.RFC3339Nano), Days: []nodeproto.TrafficDay{{Day: now.Format("2006-01-02"), Revision: 1, RXBytes: "80", TXBytes: "30"}}}
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for n := 0; n < 12; n++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- s.AggregateTraffic(ctx, sample, now) }()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	traffic, e := s.Traffic(ctx, i.ID, now)
	if e != nil || traffic.RXBytes != 80 || traffic.TXBytes != 30 {
		t.Fatal("replay double billed", traffic, e)
	}
	bad := sample
	bad.Days = append([]nodeproto.TrafficDay{}, sample.Days...)
	bad.Days[0].RXBytes = "81"
	if e = s.AggregateTraffic(ctx, bad, now); e != ErrConflict {
		t.Fatal("changed revision accepted", e)
	}
	sample.Days[0].Revision = 2
	sample.Days[0].RXBytes = "90"
	if e = s.AggregateTraffic(ctx, sample, now); e != nil {
		t.Fatal(e)
	}
	for n := 0; n < 3; n++ {
		if e = s.EnforceTraffic(ctx, c, i.ID, now); e != nil {
			t.Fatal(e)
		}
	}
	view, e := s.TrafficView(ctx, i.ID, now)
	if e != nil || view.Enforcement == nil || view.Enforcement.State != "accepted" {
		t.Fatal(view, e)
	}
	var task nodeproto.NodeTask
	if e = json.Unmarshal(view.Enforcement.Request, &task); e != nil || task.TrafficControl.ThrottleMbps != 8 {
		t.Fatal(task, e)
	}
	if _, e = s.ClaimOperation(ctx, view.Enforcement.ID, c, now); e != nil {
		t.Fatal(e)
	}
	if _, e = s.CompleteOperation(ctx, c, view.Enforcement.ID, "uncertain", nil, now); e != nil {
		t.Fatal(e)
	}
	if e = s.EnforceTraffic(ctx, c, i.ID, now); e != nil {
		t.Fatal(e)
	}
	var count int
	if e = s.DB.QueryRow("SELECT COUNT(*) FROM controller_operations WHERE action=?", nodeproto.TrafficControlAction).Scan(&count); e != nil || count != 1 {
		t.Fatal("uncertain enforcement duplicated", count, e)
	}
	if e = s.DB.QueryRow("SELECT COUNT(*) FROM controller_audit WHERE action=?", "operation."+nodeproto.TrafficControlAction).Scan(&count); e != nil || count != 1 {
		t.Fatal("policy operation missing audit", count, e)
	}
}

package control

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

func metricString(v string) *string { return &v }

func metricFixtureValue(f *observationFixture) nodeproto.InstanceMetrics {
	return nodeproto.InstanceMetrics{
		Protocol: nodeproto.MetricsProtocol, NodeID: f.value.NodeID, InstanceID: f.value.InstanceID,
		OwnerRef: f.value.OwnerRef, Hostname: f.value.Hostname, State: "running",
		ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), VCPUs: 2,
		CPUTimeNS: metricString("18446744073709551615"), MemoryRSSKiB: metricString("102400"),
		MemoryActualKiB: metricString("262144"), MemoryUnusedKiB: nil,
		BlockReadBytes: metricString("9007199254740993"), BlockWriteBytes: metricString("0"),
		NetworkReceiveBytes: metricString("1048576"), NetworkTransmitBytes: nil,
	}
}

func TestMetricsPinnedMutualTLSReadPreservesCountersAndAbsence(t *testing.T) {
	f := newObservationFixture(t, "/metrics")
	want := metricFixtureValue(f)
	raw, _ := json.Marshal(want)
	f.reply(http.StatusOK, raw)
	got, err := f.client.Metrics(context.Background(), want.InstanceID)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("bound metrics read changed uint64 counters or nulls", err)
	}
	if f.requests.Load() != 1 || f.verifiedPeers.Load() != 1 {
		t.Fatal("metrics did not perform exactly one mutual-TLS GET")
	}
	f.reply(409, []byte(`{"error":{"code":"LIVE_INSTANCE_METRICS_UNCONFIRMED"}}`))
	got, err = f.client.Metrics(context.Background(), want.InstanceID)
	if !errors.Is(err, ErrState) || !reflect.DeepEqual(got, nodeproto.InstanceMetrics{}) || f.requests.Load() != 2 {
		t.Fatal("busy read reused prior data or retried", err)
	}
	before := f.requests.Load()
	if _, err = f.client.Metrics(context.Background(), "not-an-instance"); !errors.Is(err, ErrInput) || f.requests.Load() != before {
		t.Fatal("invalid ID reached a node")
	}
}

func TestMetricsRejectsMismatchedStaleAmbiguousAndFailedResponses(t *testing.T) {
	f := newObservationFixture(t, "/metrics")
	want := metricFixtureValue(f)
	for name, mutate := range map[string]func(*nodeproto.InstanceMetrics){
		"node":     func(v *nodeproto.InstanceMetrics) { v.NodeID = "other-node" },
		"instance": func(v *nodeproto.InstanceMetrics) { v.InstanceID = id() },
		"owner":    func(v *nodeproto.InstanceMetrics) { v.OwnerRef = "invalid" },
		"protocol": func(v *nodeproto.InstanceMetrics) { v.Protocol = "unrelated/1" },
		"stale": func(v *nodeproto.InstanceMetrics) {
			v.ObservedAt = time.Now().Add(-61 * time.Second).UTC().Format(time.RFC3339Nano)
		},
		"future": func(v *nodeproto.InstanceMetrics) {
			v.ObservedAt = time.Now().Add(6 * time.Second).UTC().Format(time.RFC3339Nano)
		},
		"state":        func(v *nodeproto.InstanceMetrics) { v.State = "Succeeded" },
		"overflow":     func(v *nodeproto.InstanceMetrics) { v.CPUTimeNS = metricString("18446744073709551616") },
		"negative":     func(v *nodeproto.InstanceMetrics) { v.MemoryRSSKiB = metricString("-1") },
		"noncanonical": func(v *nodeproto.InstanceMetrics) { v.NetworkReceiveBytes = metricString("01") },
		"fraction":     func(v *nodeproto.InstanceMetrics) { v.BlockReadBytes = metricString("1.0") },
		"vcpus":        func(v *nodeproto.InstanceMetrics) { v.VCPUs = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			v := want
			mutate(&v)
			raw, _ := json.Marshal(v)
			f.reply(200, raw)
			before := f.requests.Load()
			got, err := f.client.Metrics(context.Background(), want.InstanceID)
			if !errors.Is(err, ErrUnavailable) || !reflect.DeepEqual(got, nodeproto.InstanceMetrics{}) || f.requests.Load() != before+1 {
				t.Fatal("untrusted metrics accepted, leaked or retried", err)
			}
		})
	}
	raw, _ := json.Marshal(want)
	for name, body := range map[string]string{
		"duplicate":      strings.Replace(string(raw), `"vcpus":2`, `"vcpus":2,"vcpus":3`, 1),
		"missing_null":   strings.Replace(string(raw), `,"network_transmit_bytes":null`, "", 1),
		"null_identity":  strings.Replace(string(raw), `"instance_id":"`+want.InstanceID+`"`, `"instance_id":null`, 1),
		"wrong_case":     strings.Replace(string(raw), `"vcpus":`, `"VCPUs":`, 1),
		"number_counter": strings.Replace(string(raw), `"block_write_bytes":"0"`, `"block_write_bytes":0`, 1),
		"unknown":        strings.Replace(string(raw), `"protocol":`, `"host_path":"PRIVATE","protocol":`, 1),
		"trailing":       string(raw) + " {}",
		"oversize":       strings.Repeat(" ", 65537),
	} {
		t.Run(name, func(t *testing.T) {
			f.reply(200, []byte(body))
			if got, err := f.client.Metrics(context.Background(), want.InstanceID); err == nil || !reflect.DeepEqual(got, nodeproto.InstanceMetrics{}) {
				t.Fatal("ambiguous metrics confirmed")
			}
		})
	}
	for _, status := range []int{202, 302, 409, 404, 500} {
		f.reply(status, raw)
		before := f.requests.Load()
		if got, err := f.client.Metrics(context.Background(), want.InstanceID); err == nil || !reflect.DeepEqual(got, nodeproto.InstanceMetrics{}) || f.requests.Load() != before+1 {
			t.Fatal("non-200 response confirmed a sample or retried", status)
		}
	}
}

func TestMetricsBindingAndFreshnessDoNotGuessInstanceIdentity(t *testing.T) {
	f := newObservationFixture(t, "/metrics")
	v := metricFixtureValue(f)
	instance := Instance{ID: v.InstanceID, NodeID: v.NodeID, OwnerRef: v.OwnerRef, Hostname: v.Hostname}
	instance.Resources.CPUCores = v.VCPUs
	if !metricsBound(v, instance) {
		t.Fatal("valid complete binding rejected")
	}
	for _, mutate := range []func(*Instance){
		func(i *Instance) { i.ID = id() }, func(i *Instance) { i.NodeID = "other" },
		func(i *Instance) { i.OwnerRef = id() }, func(i *Instance) { i.Hostname = "other" },
		func(i *Instance) { i.Resources.CPUCores++ },
	} {
		changed := instance
		mutate(&changed)
		if metricsBound(v, changed) {
			t.Fatal("sample crossed an instance identity boundary")
		}
	}
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		delta time.Duration
		valid bool
	}{
		{-time.Minute, true}, {-time.Minute - time.Nanosecond, false},
		{5 * time.Second, true}, {5*time.Second + time.Nanosecond, false},
	} {
		if got := metricsFresh(now.Add(tc.delta).Format(time.RFC3339Nano), now); got != tc.valid {
			t.Fatal("freshness boundary mismatch", tc.delta, got)
		}
	}
	if metricsFresh("2026-02-30T00:00:00Z", now) {
		t.Fatal("invalid calendar accepted")
	}
}

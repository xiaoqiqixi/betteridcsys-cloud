package nodeproto

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func metricsFixture() InstanceMetrics {
	max := "18446744073709551615"
	zero := "0"
	return InstanceMetrics{Protocol: MetricsProtocol, NodeID: "node-a", InstanceID: strings.Repeat("2", 32), OwnerRef: strings.Repeat("3", 32), Hostname: "vm-a", State: "running", ObservedAt: "2026-10-23T01:02:03.123456789Z", VCPUs: 2, CPUTimeNS: &max, BlockReadBytes: &zero}
}

func TestInstanceMetricsExactContractAndNull(t *testing.T) {
	want := metricsFixture()
	if !want.Validate() {
		t.Fatal("valid sample rejected")
	}
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeInstanceMetrics(raw)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal(got, err)
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 16 || string(fields["memory_rss_kib"]) != "null" || string(fields["cpu_time_ns"]) != `"18446744073709551615"` || string(fields["block_read_bytes"]) != `"0"` {
		t.Fatal("required fields, uint64 or null changed", string(raw))
	}
}

func TestInstanceMetricsRejectAmbiguousWire(t *testing.T) {
	raw, _ := json.Marshal(metricsFixture())
	s := string(raw)
	cases := map[string]string{
		"duplicate":          strings.Replace(s, `"vcpus":2`, `"vcpus":2,"vcpus":2`, 1),
		"escaped_duplicate":  strings.Replace(s, `"vcpus":2`, `"vcpus":2,"\u0076cpus":2`, 1),
		"wrong_case":         strings.Replace(s, `"node_id"`, `"Node_ID"`, 1),
		"counter_wrong_case": strings.Replace(s, `"cpu_time_ns"`, `"CPU_Time_NS"`, 1),
		"unknown":            strings.TrimSuffix(s, "}") + `,"path":"/private"}`,
		"trailing":           s + "{}", "array": "[" + s + "]", "empty_object": "{}", "null": "null",
		"oversize":       s + strings.Repeat(" ", 65536),
		"counter_number": strings.Replace(s, `"cpu_time_ns":"18446744073709551615"`, `"cpu_time_ns":18446744073709551615`, 1),
		"counter_object": strings.Replace(s, `"memory_rss_kib":null`, `"memory_rss_kib":{}`, 1),
		"vcpus_string":   strings.Replace(s, `"vcpus":2`, `"vcpus":"2"`, 1),
		"vcpus_float":    strings.Replace(s, `"vcpus":2`, `"vcpus":2.0`, 1),
		"vcpus_exp":      strings.Replace(s, `"vcpus":2`, `"vcpus":2e0`, 1),
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeInstanceMetrics([]byte(value)); err == nil {
				t.Fatal("ambiguous sample accepted", value)
			}
		})
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	for key := range fields {
		t.Run("missing_"+key, func(t *testing.T) {
			copy := map[string]json.RawMessage{}
			for k, v := range fields {
				if k != key {
					copy[k] = v
				}
			}
			b, _ := json.Marshal(copy)
			if _, err := DecodeInstanceMetrics(b); err == nil {
				t.Fatal("missing field accepted", key)
			}
		})
	}
	for _, key := range []string{"protocol", "node_id", "instance_id", "owner_ref", "hostname", "state", "observed_at", "vcpus"} {
		t.Run("null_"+key, func(t *testing.T) {
			copy := map[string]json.RawMessage{}
			for k, v := range fields {
				copy[k] = v
			}
			copy[key] = json.RawMessage("null")
			b, _ := json.Marshal(copy)
			if _, err := DecodeInstanceMetrics(b); err == nil {
				t.Fatal("null identity accepted", key)
			}
		})
	}
}

func TestInstanceMetricsValidateIdentityAndCounters(t *testing.T) {
	for _, value := range []string{"", "00", "01", "-1", "+1", "1.0", "1e2", " 1", "1 ", "18446744073709551616", "１２", "0x10", "999999999999999999999"} {
		t.Run("counter_"+value, func(t *testing.T) {
			m := metricsFixture()
			m.CPUTimeNS = &value
			if m.Validate() {
				t.Fatal("noncanonical counter accepted", value)
			}
		})
	}
	for name, mutate := range map[string]func(*InstanceMetrics){
		"protocol":       func(m *InstanceMetrics) { m.Protocol = Protocol },
		"node":           func(m *InstanceMetrics) { m.NodeID = "../node" },
		"instance":       func(m *InstanceMetrics) { m.InstanceID = strings.Repeat("A", 32) },
		"owner":          func(m *InstanceMetrics) { m.OwnerRef = "" },
		"hostname":       func(m *InstanceMetrics) { m.Hostname = "vm\n-a" },
		"unknown_state":  func(m *InstanceMetrics) { m.State = "paid" },
		"raw_state":      func(m *InstanceMetrics) { m.State = "shut off" },
		"invalid_time":   func(m *InstanceMetrics) { m.ObservedAt = "2026-02-30T01:02:03Z" },
		"local_time":     func(m *InstanceMetrics) { m.ObservedAt = "2026-10-23T01:02:03+01:00" },
		"comma_fraction": func(m *InstanceMetrics) { m.ObservedAt = "2026-10-23T01:02:03,123Z" },
		"long_fraction":  func(m *InstanceMetrics) { m.ObservedAt = "2026-10-23T01:02:03.1234567891Z" },
		"single_hour":    func(m *InstanceMetrics) { m.ObservedAt = "2026-10-23T1:02:03Z" },
		"zero_cpu":       func(m *InstanceMetrics) { m.VCPUs = 0 },
		"excess_cpu":     func(m *InstanceMetrics) { m.VCPUs = 4097 },
	} {
		t.Run(name, func(t *testing.T) {
			m := metricsFixture()
			mutate(&m)
			if m.Validate() {
				t.Fatal("invalid identity accepted")
			}
			raw, _ := json.Marshal(m)
			if _, err := DecodeInstanceMetrics(raw); err == nil {
				t.Fatal("invalid identity accepted by wire decoder")
			}
		})
	}
}

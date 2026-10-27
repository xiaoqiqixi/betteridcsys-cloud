package nodeproto

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"strconv"
	"time"
)

const MetricsProtocol = "aster.node.metrics/1"

var metricsTimestamp = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$`)

// InstanceMetrics is a read-only sample, not a billing or guest-health result.
// Counters use decimal strings so uint64 values survive JavaScript unchanged.
// Missing libvirt statistics are null, never invented zeroes. MemoryActualKiB is
// the current balloon allocation; RSS is the host QEMU process, not guest usage.
// The node withholds MemoryUnusedKiB unless the guest balloon report timestamp
// is no older than 60 seconds and no more than 5 seconds ahead of the sample.
type InstanceMetrics struct {
	Protocol             string  `json:"protocol"`
	NodeID               string  `json:"node_id"`
	InstanceID           string  `json:"instance_id"`
	OwnerRef             string  `json:"owner_ref"`
	Hostname             string  `json:"hostname"`
	State                string  `json:"state"`
	ObservedAt           string  `json:"observed_at"`
	VCPUs                int     `json:"vcpus"`
	CPUTimeNS            *string `json:"cpu_time_ns"`
	MemoryRSSKiB         *string `json:"memory_rss_kib"`
	MemoryActualKiB      *string `json:"memory_actual_kib"`
	MemoryUnusedKiB      *string `json:"memory_unused_kib"`
	BlockReadBytes       *string `json:"block_read_bytes"`
	BlockWriteBytes      *string `json:"block_write_bytes"`
	NetworkReceiveBytes  *string `json:"network_receive_bytes"`
	NetworkTransmitBytes *string `json:"network_transmit_bytes"`
}

func canonicalMetricCounter(s string) bool {
	if len(s) == 0 || len(s) > 20 || len(s) > 1 && s[0] == '0' {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	_, err := strconv.ParseUint(s, 10, 64)
	return err == nil
}

func (m InstanceMetrics) Validate() bool {
	if m.Protocol != MetricsProtocol || !ValidNodeID(m.NodeID) || !ValidID(m.InstanceID) || !ValidID(m.OwnerRef) || !hostname.MatchString(m.Hostname) || m.VCPUs < 1 || m.VCPUs > 4096 {
		return false
	}
	switch m.State {
	case "running", "shutoff", "paused", "in_shutdown", "crashed", "pmsuspended", "idle", "blocked":
	default:
		return false
	}
	at, err := time.Parse(time.RFC3339Nano, m.ObservedAt)
	if err != nil || at.Year() < 1 || !metricsTimestamp.MatchString(m.ObservedAt) {
		return false
	}
	for _, value := range []*string{m.CPUTimeNS, m.MemoryRSSKiB, m.MemoryActualKiB, m.MemoryUnusedKiB, m.BlockReadBytes, m.BlockWriteBytes, m.NetworkReceiveBytes, m.NetworkTransmitBytes} {
		if value != nil && !canonicalMetricCounter(*value) {
			return false
		}
	}
	return true
}

// DecodeInstanceMetrics rejects absent fields (including absent null counters),
// duplicate keys, unknown/case-insensitive aliases and ambiguous JSON types.
func DecodeInstanceMetrics(raw []byte) (InstanceMetrics, error) {
	var m InstanceMetrics
	if len(raw) == 0 || len(raw) > 65536 || !uniqueFields(raw) {
		return m, ErrInvalid
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return m, ErrInvalid
	}
	allowed := map[string]bool{
		"protocol": false, "node_id": false, "instance_id": false, "owner_ref": false,
		"hostname": false, "state": false, "observed_at": false, "vcpus": false,
		"cpu_time_ns": true, "memory_rss_kib": true, "memory_actual_kib": true,
		"memory_unused_kib": true, "block_read_bytes": true, "block_write_bytes": true,
		"network_receive_bytes": true, "network_transmit_bytes": true,
	}
	if len(fields) != len(allowed) {
		return m, ErrInvalid
	}
	for key, value := range fields {
		nullable, ok := allowed[key]
		if !ok || !nullable && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return m, ErrInvalid
		}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || d.Decode(new(any)) != io.EOF || !m.Validate() {
		return InstanceMetrics{}, ErrInvalid
	}
	return m, nil
}

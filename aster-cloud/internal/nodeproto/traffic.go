package nodeproto

import (
	"bytes"
	"encoding/json"
	"time"
)

const TrafficProtocol = "aster.node.traffic/1"
const TrafficCapability = "journal-interface-traffic-v1"

// Daily cumulative totals, not deltas in a lossy delivery queue. Each revision
// replaces the preceding value in the same (node, stream, day) namespace.
type TrafficDay struct {
	Day      string `json:"day"`
	Revision uint64 `json:"revision"`
	RXBytes  string `json:"rx_bytes"`
	TXBytes  string `json:"tx_bytes"`
}
type InstanceTraffic struct {
	Protocol   string       `json:"protocol"`
	NodeID     string       `json:"node_id"`
	InstanceID string       `json:"instance_id"`
	OwnerRef   string       `json:"owner_ref"`
	StreamID   string       `json:"stream_id"`
	ObservedAt string       `json:"observed_at"`
	Days       []TrafficDay `json:"days"`
}

func (t InstanceTraffic) Valid() bool {
	if t.Protocol != TrafficProtocol || !ValidNodeID(t.NodeID) || !ValidID(t.InstanceID) || !ValidID(t.OwnerRef) || !ValidID(t.StreamID) || len(t.Days) > 63 {
		return false
	}
	at, e := time.Parse(time.RFC3339Nano, t.ObservedAt)
	if e != nil || at.UTC().Format(time.RFC3339Nano) != t.ObservedAt {
		return false
	}
	previous := ""
	for _, d := range t.Days {
		day, e := time.Parse("2006-01-02", d.Day)
		if e != nil || d.Day <= previous || d.Revision == 0 || !canonicalMetricCounter(d.RXBytes) || !canonicalMetricCounter(d.TXBytes) || day.After(at) || day.Before(at.Truncate(24*time.Hour).Add(-62*24*time.Hour)) {
			return false
		}
		previous = d.Day
	}
	return true
}
func DecodeTraffic(raw []byte) (InstanceTraffic, error) {
	var t InstanceTraffic
	if len(raw) > 65536 || json.Unmarshal(raw, &t) != nil || !t.Valid() {
		return t, ErrInvalid
	}
	canonical, e := json.Marshal(t)
	if e != nil || !bytes.Equal(bytes.TrimSpace(raw), canonical) {
		return InstanceTraffic{}, ErrInvalid
	}
	return t, nil
}

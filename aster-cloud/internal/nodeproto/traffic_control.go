package nodeproto

import "time"

const TrafficControlAction = "traffic_policy"
const TrafficThrottleCapability = "traffic-throttle-libvirt-v1"
const TrafficSuspendCapability = "traffic-suspend-v1"

// Separate from billing suspension and from product rates. Clearing this
// override never unsuspends a billing hold or starts a stopped guest.
type TrafficControl struct {
	ExpiresAt    string `json:"expires_at,omitempty"`
	ThrottleMbps int    `json:"throttle_mbps,omitempty"`
	Suspended    bool   `json:"suspended,omitempty"`
}

func (t TrafficControl) Valid() bool {
	if t.ExpiresAt != "" {
		at, e := time.Parse(time.RFC3339Nano, t.ExpiresAt)
		if e != nil || at.UTC().Format(time.RFC3339Nano) != t.ExpiresAt {
			return false
		}
	}
	return t.ThrottleMbps >= 0 && t.ThrottleMbps <= 100000 && !(t.Suspended && t.ThrottleMbps != 0)
}

package hypervisor

import "aster/billing/controllerapi"

const bandwidthJournalSchema = 8

type bandwidthRateXML struct {
	Average uint64 `xml:"average,attr"`
}
type bandwidthXML struct {
	Inbound  *bandwidthRateXML `xml:"inbound,omitempty"`
	Outbound *bandwidthRateXML `xml:"outbound,omitempty"`
}

// Libvirt's historical KB/s spelling means KiB/s, not decimal kB/s.
// Decimal Mbps -> kbit/s (*1000) -> bytes/s (*1000/8) -> KiB/s (/1024).
// Round down so the effective rate never exceeds the requested limit.
// https://libvirt.org/formatnetwork.html#quality-of-service
func bandwidthKiB(mbps int) uint64 { return uint64(mbps) * 1000 * 1000 / (8 * 1024) }
func hasBandwidth(r controllerapi.Resources) bool {
	return r.BandwidthMbps > 0 || r.InboundBandwidthMbps > 0
}
func bandwidthFor(r controllerapi.Resources) *bandwidthXML {
	if !hasBandwidth(r) {
		return nil
	}
	b := &bandwidthXML{}
	if r.InboundBandwidthMbps > 0 {
		b.Inbound = &bandwidthRateXML{bandwidthKiB(r.InboundBandwidthMbps)}
	}
	if r.BandwidthMbps > 0 {
		b.Outbound = &bandwidthRateXML{bandwidthKiB(r.BandwidthMbps)}
	}
	return b
}
func bandwidthMatches(a, b *bandwidthXML) bool {
	if a == nil || b == nil {
		return a == b
	}
	equal := func(a, b *bandwidthRateXML) bool {
		if a == nil || b == nil {
			return a == b
		}
		return a.Average == b.Average
	}
	return equal(a.Inbound, b.Inbound) && equal(a.Outbound, b.Outbound)
}
func (c Config) allowsBandwidth(r controllerapi.Resources) bool {
	if r.BandwidthMbps < 0 || r.BandwidthMbps > 100000 || r.InboundBandwidthMbps < 0 || r.InboundBandwidthMbps > 100000 {
		return false
	}
	if hasBandwidth(r) && (!c.AllowBandwidthLimits || r.IPv4Count != 1) {
		return false
	}
	return (r.BandwidthMbps > 0 && r.InboundBandwidthMbps > 0) || c.AllowUnmeteredDefault
}

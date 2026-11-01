package control

import (
	"aster/billing/controllerapi"
	"aster/cloud/internal/nodeproto"
)

func supportsNormalBandwidth(c Capability, r controllerapi.Resources) bool {
	if r.BandwidthMbps == 0 && r.InboundBandwidthMbps == 0 {
		return true
	}
	return contains(c.NetworkProfiles, nodeproto.BandwidthCapability) && r.BandwidthMbps >= 0 && r.BandwidthMbps <= 100000 && r.InboundBandwidthMbps >= 0 && r.InboundBandwidthMbps <= 100000
}

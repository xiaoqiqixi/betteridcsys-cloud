package control

import (
	"aster/cloud/internal/nodeproto"
	"testing"
	"time"
)

func TestNormalBandwidthRequiresPositiveNodeCapability(t *testing.T) {
	p := testProfile()
	r := testResources(p)
	r.BandwidthMbps = 10
	r.InboundBandwidthMbps = 100
	c := testCapabilities(p, time.Now())
	if c.Supports(r, p) {
		t.Fatal("unadvertised bandwidth ignored")
	}
	c.NetworkProfiles = append(c.NetworkProfiles, nodeproto.BandwidthCapability)
	if !c.Supports(r, p) {
		t.Fatal("approved bandwidth rejected")
	}
	r.InboundBandwidthMbps = 100001
	if c.Supports(r, p) {
		t.Fatal("unsupported rate admitted")
	}
}

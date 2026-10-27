package control

import (
	"aster/cloud/internal/nodeproto"
	"encoding/json"
	"testing"
	"time"
)

func TestPublicIngressFeatureRequiresExactNonduplicatedOVSApproval(t *testing.T) {
	p := testProfile()
	base := vpcTestCapabilities(p, time.Now())
	base.NetworkProfiles = []string{"normal-static-ipv4-dedicated-bridge", nodeproto.OVSNetworkCapability, nodeproto.PublicIngressCapability}
	if !base.validNetworkCapabilities() || !base.SupportsNetwork(vpcTestResources(p), p, "vpc-a-v1") {
		t.Fatal("well-formed new feature rejected")
	}
	for name, edit := range map[string]func(*Capability){
		"duplicate_feature": func(c *Capability) { c.NetworkProfiles = append(c.NetworkProfiles, nodeproto.PublicIngressCapability) },
		"duplicate_ovs":     func(c *Capability) { c.NetworkProfiles = append(c.NetworkProfiles, nodeproto.OVSNetworkCapability) },
		"duplicate_legacy_marker": func(c *Capability) {
			c.NetworkProfiles = append(c.NetworkProfiles, "normal-static-ipv4-dedicated-bridge")
		},
		"feature_without_ovs": func(c *Capability) {
			c.NetworkProfiles = []string{nodeproto.PublicIngressCapability}
			c.OVSNetworkProfiles = nil
		},
		"feature_without_profiles":  func(c *Capability) { c.OVSNetworkProfiles = nil },
		"profiles_without_ovs_flag": func(c *Capability) { c.NetworkProfiles = []string{nodeproto.PublicIngressCapability} },
		"duplicate_profile":         func(c *Capability) { c.OVSNetworkProfiles = []string{"vpc-a-v1", "vpc-a-v1"} },
		"malformed_profile":         func(c *Capability) { c.OVSNetworkProfiles = []string{"arbitrary/path"} },
	} {
		t.Run(name, func(t *testing.T) {
			c := base
			c.NetworkProfiles = append([]string{}, base.NetworkProfiles...)
			c.OVSNetworkProfiles = append([]string{}, base.OVSNetworkProfiles...)
			edit(&c)
			if c.validNetworkCapabilities() || c.SupportsNetwork(vpcTestResources(p), p, "vpc-a-v1") {
				t.Fatal("malformed feature claim authorized execution", c)
			}
		})
	}
	base.Maintenance = true
	if base.SupportsNetwork(vpcTestResources(p), p, "vpc-a-v1") {
		t.Fatal("feature overrode maintenance")
	}
}

func TestPublicIngressFeatureAbsencePreservesLegacyCapabilityWire(t *testing.T) {
	c := testCapabilities(testProfile(), time.Now().UTC())
	before, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if !c.validNetworkCapabilities() {
		t.Fatal("legacy approval rejected")
	}
	var decoded Capability
	if !strict(before, &decoded) || !decoded.validNetworkCapabilities() {
		t.Fatal("legacy capability no longer reads")
	}
	after, _ := json.Marshal(decoded)
	if string(before) != string(after) {
		t.Fatal("old wire changed")
	}
	for _, feature := range decoded.NetworkProfiles {
		if feature == nodeproto.PublicIngressCapability {
			t.Fatal("legacy overlay support acquired ingress authority")
		}
	}
}

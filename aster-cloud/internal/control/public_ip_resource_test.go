package control

import (
	"aster/cloud/internal/nodeproto"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestPublicVMStrictOptionalNodeFieldsPreserveOldBytes(t *testing.T) {
	old := nodeproto.InstanceObservation{Protocol: nodeproto.InstanceProtocol, NodeID: "node-a", InstanceID: strings.Repeat("1", 32), OwnerRef: strings.Repeat("2", 32), Hostname: "legacy", State: "shutoff", IPv4: "8.8.4.3", MAC: "52:54:00:00:00:01", ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	raw, _ := json.Marshal(old)
	if strings.Contains(string(raw), "direct_public") {
		t.Fatal("zero new field rewrote legacy bytes")
	}
	var parsed nodeproto.InstanceObservation
	if !strict(raw, &parsed) || parsed != old {
		t.Fatal("old exact protocol rejected")
	}
	for _, tail := range []string{`,"direct_public":null}`, `,"Direct_public":{}}`, `,"direct_public_detached":null}`} {
		bad := strings.TrimSuffix(string(raw), "}") + tail
		if strict([]byte(bad), &parsed) {
			t.Fatal("ambiguous optional field accepted", bad)
		}
	}
}
func TestPublicVMDirectRootApprovalSeparatesNATAndProtectsGateway(t *testing.T) {
	p := testProfile()
	c := testConfig(p)
	root := DirectPublicProfile{ClusterID: "public", NodeID: p.ID, ProfileID: nodeproto.DirectPublicProfile, ProfileSHA256: strings.Repeat("c", 64), CIDR: "8.8.4.0/24", GatewayIPv4: "8.8.4.1", PublicIPv4s: []string{"8.8.4.3"}}
	c.DirectPublicProfiles = []DirectPublicProfile{root}
	if !c.Valid() {
		t.Fatal("valid direct profile")
	}
	for name, edit := range map[string]func(*DirectPublicProfile){"gateway_network": func(v *DirectPublicProfile) { v.GatewayIPv4 = "8.8.4.0" }, "gateway_broadcast": func(v *DirectPublicProfile) { v.GatewayIPv4 = "8.8.4.255" }, "private": func(v *DirectPublicProfile) { v.PublicIPv4s = []string{"10.1.2.3"} }, "unapproved_profile": func(v *DirectPublicProfile) { v.ProfileID = "arbitrary" }, "same_gateway": func(v *DirectPublicProfile) { v.PublicIPv4s = []string{v.GatewayIPv4} }} {
		t.Run(name, func(t *testing.T) {
			changed := c
			changed.DirectPublicProfiles = []DirectPublicProfile{root}
			edit(&changed.DirectPublicProfiles[0])
			if changed.Valid() {
				t.Fatal("unsafe root accepted")
			}
		})
	}
}
func TestPublicVMRawFloatingSelectionIsNotAResourceCAS(t *testing.T) {
	empty := []struct{}{}
	_ = empty
	for _, body := range []string{`{"members":[],"gateways":[],"floating_ips":null}`, `{"members":[],"gateways":[],"floating_ips":[]}`} {
		var replacement OverlayReplacementInput
		if strings.Contains(body, "null") {
			if strict([]byte(body), &replacement) {
				t.Fatal("null selection accepted")
			}
		} else {
			if !strict([]byte(body), &replacement) {
				t.Fatal("shape invalid")
			}
			if _, e := canonicalOverlayRecoveryInput(OverlayRecoveryInput{ExpectedSnapshotSHA256: strings.Repeat("a", 64), Replacement: &replacement}); e == nil {
				t.Fatal("public recovery accepted raw floating CAS bypass")
			}
		}
	}
}

package hypervisor

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"encoding/json"
	"reflect"
	"testing"
)

// This unit tests the decision after a doctor report, not real KVM readiness.
// The integration case below separately proves an actual failed doctor cannot
// advertise the feature even when a configured OVS profile exists.
func TestPublicIngressCapabilityNeedsReadyDoctorAndApprovedOVS(t *testing.T) {
	for _, tc := range []struct {
		name        string
		ready       bool
		maintenance bool
		ovsFlag     bool
		ovsProfiles []string
		want        bool
	}{
		{name: "ready", ready: true, ovsFlag: true, ovsProfiles: []string{"vpc-a-v1"}, want: true},
		{name: "doctor_failure", ovsFlag: true, ovsProfiles: []string{"vpc-a-v1"}},
		{name: "maintenance", ready: true, maintenance: true, ovsFlag: true, ovsProfiles: []string{"vpc-a-v1"}},
		{name: "no_ovs_flag", ready: true, ovsProfiles: []string{"vpc-a-v1"}},
		{name: "no_profiles", ready: true, ovsFlag: true},
		{name: "legacy_bridge_only", ready: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := nodeproto.Capabilities{Maintenance: tc.maintenance, NetworkProfiles: []string{"normal-static-ipv4-dedicated-bridge"}, OVSNetworkProfiles: tc.ovsProfiles}
			if tc.ovsFlag {
				c.NetworkProfiles = append(c.NetworkProfiles, nodeproto.OVSNetworkCapability)
			}
			before, _ := json.Marshal(c)
			report := DoctorReport{Ready: tc.ready}
			advertisePublicIngressCapability(&c, report)
			advertisePublicIngressCapability(&c, report) // Repeated projection must not duplicate the feature.
			count := 0
			for _, feature := range c.NetworkProfiles {
				if feature == nodeproto.PublicIngressCapability {
					count++
				}
			}
			if (count == 1) != tc.want || count > 1 {
				t.Fatal("invalid feature advertisement", count, c)
			}
			if !tc.want {
				after, _ := json.Marshal(c)
				if string(before) != string(after) {
					t.Fatal("failed gate changed historical capability bytes", string(after))
				}
			}
			if !reflect.DeepEqual(c.OVSNetworkProfiles, tc.ovsProfiles) || c.Maintenance != tc.maintenance {
				t.Fatal("advertisement changed root approval or maintenance")
			}
		})
	}
}

func TestPublicIngressCapabilityFailedRealDoctorIsReadOnly(t *testing.T) {
	m, runner, _, _ := newOVSFixture(t)
	runner.fail = "list"
	c := m.Capabilities(context.Background())
	if !c.Maintenance || len(c.Actions) != 0 {
		t.Fatal("failed real doctor advertised mutation readiness", c)
	}
	for _, feature := range c.NetworkProfiles {
		if feature == nodeproto.PublicIngressCapability {
			t.Fatal("failed real doctor advertised ingress execution")
		}
	}
	for _, mutation := range []string{" define ", " start ", " create ", " nwfilter-define ", " destroy "} {
		if runner.count(mutation) != 0 {
			t.Fatal("capability inspection mutated libvirt", runner.commands)
		}
	}
}

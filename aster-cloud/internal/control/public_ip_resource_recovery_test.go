package control

import (
	"aster/cloud/internal/overlayproto"
	"reflect"
	"strings"
	"testing"
)

func TestPublicVMRecoveryRepinsOnlyUnchangedApprovedFloatingIdentity(t *testing.T) {
	old := overlayproto.FloatingIP{ResourceID: strings.Repeat("a", 32), NodeID: "node-a", VPCID: strings.Repeat("b", 32), OwnerRef: strings.Repeat("c", 32), ProfileID: "nat", ProfileSHA256: strings.Repeat("d", 64), GatewayInstanceID: strings.Repeat("e", 32), InstanceID: strings.Repeat("f", 32), TargetIPv4: "10.25.0.10", PublicIPv4: "8.8.8.9"}
	root := OverlayNATProfile{NodeID: old.NodeID, VPCID: old.VPCID, GatewayInstanceID: old.GatewayInstanceID, ProfileID: old.ProfileID, ProfileSHA256: strings.Repeat("1", 64), PublicIPv4: "8.8.8.8", PublicIPv4s: []string{old.PublicIPv4}, AllowFloatingIP: true, AllowInternetEgress: true}
	in := []overlayproto.FloatingIP{old}
	got := recoveryFloatingPins(OverlayCluster{NATProfiles: []OverlayNATProfile{root}}, in)
	wanted := old
	wanted.ProfileSHA256 = root.ProfileSHA256
	if !reflect.DeepEqual(got, []overlayproto.FloatingIP{wanted}) || in[0] != old {
		t.Fatal("repin mutated historical identity", got)
	}
	for _, kind := range []string{"node", "vpc", "gateway", "profile", "address", "floating-withdrawn", "internet-withdrawn"} {
		t.Run(kind, func(t *testing.T) {
			withdrawn := root
			switch kind {
			case "node":
				withdrawn.NodeID = "foreign"
			case "vpc":
				withdrawn.VPCID = strings.Repeat("0", 32)
			case "gateway":
				withdrawn.GatewayInstanceID = strings.Repeat("0", 32)
			case "profile":
				withdrawn.ProfileID = "foreign"
			case "address":
				withdrawn.PublicIPv4s = []string{}
			case "floating-withdrawn":
				withdrawn.AllowFloatingIP = false
			case "internet-withdrawn":
				withdrawn.AllowInternetEgress = false
			}
			out := recoveryFloatingPins(OverlayCluster{NATProfiles: []OverlayNATProfile{withdrawn}}, in)
			if out[0] != old {
				t.Fatal("withdrawn/different root repinned resource", out)
			}
		})
	}
}

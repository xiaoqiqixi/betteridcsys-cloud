package hypervisor

import (
	"aster/cloud/internal/fabric"
	"aster/cloud/internal/overlayproto"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOVSInternetGuestSeedUsesExplicitRootRouteAndDNSWithoutChangingBinding(t *testing.T) {
	for _, public := range []bool{false, true} {
		t.Run(map[bool]string{false: "no-default-without-approval", true: "root-approved-default-and-dns"}[public], func(t *testing.T) {
			m, _, _, task := newOVSFixture(t)
			original, _ := json.Marshal(task.Network)
			p := m.Config.OVSProfiles[task.Network.ProfileID]
			p.OverlayConfig = "/etc/aster/overlay.json"
			m.Config.OVSProfiles[task.Network.ProfileID] = p
			base, err := m.loadOVSConfig(p.FabricConfig)
			if err != nil {
				t.Fatal(err)
			}
			gateway := overlayproto.Gateway{NodeID: task.NodeID, InstanceID: strings.Repeat("8", 32), InterfaceID: fabric.InterfaceID(strings.Repeat("8", 32)), OwnerRef: task.OwnerRef, VPCID: strings.Repeat("a", 32), IPv4: "10.20.0.1", MAC: "52:54:00:00:00:01", AllowedPrefixes: []string{}}
			gn := fabric.OverlayGuestNetwork{LocalVPCID: task.Network.VPCID, OwnerRef: task.OwnerRef, CIDR: task.Network.CIDR, GatewayIPv4: gateway.IPv4, AllowedPrefixes: []string{}}
			if public {
				gn.AllowInternetEgress = true
				gn.VPCID = gateway.VPCID
				gn.DNSIPv4 = []string{"1.1.1.1", "8.8.8.8"}
			}
			cfg := fabric.OverlayConfig{Schema: 1, Base: base, LocalIPv4: "192.0.2.1", UnderlayMTU: 1550, GuestMTU: 1500, UnderlayTrustedAck: true, TrustReference: "isolated-test", ProtectedCIDRs: []string{"192.0.2.0/24"}, Peers: []fabric.OverlayPeer{}, Gateways: []overlayproto.Gateway{gateway}, GuestNetworks: []fabric.OverlayGuestNetwork{gn}}
			pin, err := fabric.OverlayConfigSHA256(cfg)
			if err != nil {
				t.Fatal(err)
			}
			m.loadOverlayConfig = func(string) (fabric.OverlayConfig, error) { return cfg, nil }
			g := &fakeOverlayGate{receipts: map[string]overlayproto.Receipt{}}
			m.overlayFactory = func(fabric.Config) (overlayGate, error) { return g, nil }
			n := task.Network
			s := overlayproto.Snapshot{Protocol: overlayproto.Protocol, ClusterID: "seed-test", Epoch: 1, Profiles: []overlayproto.ProfilePin{{NodeID: task.NodeID, ProfileID: n.ProfileID, ProfileSHA256: pin}}, VPCs: []overlayproto.VPC{{ID: gateway.VPCID, OwnerRef: task.OwnerRef, CIDR: n.CIDR, VNI: 5001}}, Members: []overlayproto.Member{{NodeID: task.NodeID, InstanceID: task.InstanceID, InterfaceID: n.InterfaceID, OwnerRef: n.OwnerRef, VPCID: gateway.VPCID, LocalVPCID: n.VPCID, LeaseID: n.LeaseID, PoolID: n.PoolID, NetworkSHA256: n.Digest(), IPv4: n.IPv4, MAC: n.MAC, InboundMbps: n.InboundMbps, OutboundMbps: n.OutboundMbps, Enabled: true, Reserved: true}}, Gateways: []overlayproto.Gateway{}}
			m.readOverlaySnapshot = func(fabric.OverlayConfig) (overlayproto.Snapshot, string, error) { return s, "applied", nil }
			requireOVSSuccess(t, m, task)
			i, _ := m.Ledger.Instance(task.InstanceID)
			raw, err := os.ReadFile(filepath.Join(i.Directory, "network-config"))
			if err != nil {
				t.Fatal(err)
			}
			if public {
				for _, want := range []string{`to: "0.0.0.0/0"`, `via: "10.20.0.1"`, "nameservers:", `- "1.1.1.1"`, `- "8.8.8.8"`} {
					if !strings.Contains(string(raw), want) {
						t.Fatalf("missing seed %q", want)
					}
				}
			} else if strings.Contains(string(raw), "routes:") || strings.Contains(string(raw), "nameservers:") || strings.Contains(string(raw), "0.0.0.0/0") {
				t.Fatal("root approval bypassed")
			}
			after, _ := json.Marshal(i.Network)
			if string(after) != string(original) {
				t.Fatal("original create binding changed")
			}
			if err := m.seedOVS(context.Background(), i); err == nil {
				t.Fatal("existing seed was overwritten")
			}
			unchanged, _ := os.ReadFile(filepath.Join(i.Directory, "network-config"))
			if string(unchanged) != string(raw) {
				t.Fatal("existing guest seed changed")
			}
		})
	}
}

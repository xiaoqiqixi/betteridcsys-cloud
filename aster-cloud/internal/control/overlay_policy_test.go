package control

import (
	"aster/cloud/internal/nodeproto"
	"aster/cloud/internal/overlayproto"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func overlayPolicyFixture() (Config, overlayproto.Snapshot) {
	p := testProfile()
	c := testConfig(p)
	owner, vpc, guest, gateway := strings.Repeat("a", 32), strings.Repeat("b", 32), strings.Repeat("c", 32), strings.Repeat("d", 32)
	g := overlayproto.Gateway{NodeID: p.ID, InstanceID: gateway, InterfaceID: nodeproto.NetworkInterfaceID(gateway), OwnerRef: owner, VPCID: vpc, IPv4: "10.24.0.1", MAC: nodeproto.NetworkMAC(p.ID, gateway), AllowedPrefixes: []string{"192.0.2.0/24"}}
	root := OverlayNATProfile{NodeID: p.ID, VPCID: vpc, GatewayInstanceID: gateway, ProfileID: "nat-public", ProfileSHA256: strings.Repeat("e", 64), PublicIPv4: "198.51.100.2", AllowSNAT: true, AllowedSourceCIDRs: []string{"192.0.2.0/24"}, AllowedPorts: []OverlayNATPortRange{{Protocol: "tcp", Start: 40000, End: 41000}}}
	cluster := OverlayCluster{ClusterID: "policy-test", Profiles: []overlayproto.ProfilePin{{NodeID: p.ID, ProfileID: "ovs-profile", ProfileSHA256: strings.Repeat("f", 64)}}, Gateways: []overlayproto.Gateway{g}, NATProfiles: []OverlayNATProfile{root}}
	c.OverlayClusters = []OverlayCluster{cluster}
	policy := overlayproto.NATPolicy{ID: strings.Repeat("1", 32), NodeID: p.ID, VPCID: vpc, GatewayInstanceID: gateway, ProfileID: root.ProfileID, ProfileSHA256: root.ProfileSHA256, SNATEnabled: true, Forwardings: []overlayproto.NATForwarding{{ID: strings.Repeat("2", 32), Protocol: "tcp", PublicPort: 40001, TargetInstanceID: guest, TargetPort: 22, SourceCIDR: "192.0.2.0/25"}}}
	s := overlayproto.Snapshot{Protocol: overlayproto.Protocol, ClusterID: cluster.ClusterID, Epoch: 1, Profiles: cluster.Profiles, VPCs: []overlayproto.VPC{{ID: vpc, OwnerRef: owner, CIDR: "10.24.0.0/24", VNI: 10}}, Members: []overlayproto.Member{{NodeID: p.ID, InstanceID: guest, InterfaceID: nodeproto.NetworkInterfaceID(guest), OwnerRef: owner, VPCID: vpc, LocalVPCID: strings.Repeat("3", 32), LeaseID: strings.Repeat("4", 32), PoolID: strings.Repeat("5", 32), NetworkSHA256: strings.Repeat("6", 64), IPv4: "10.24.0.2", MAC: nodeproto.NetworkMAC(p.ID, guest), InboundMbps: 10, OutboundMbps: 10, Enabled: true}}, Gateways: []overlayproto.Gateway{g}, NATPolicies: []overlayproto.NATPolicy{policy}}
	return c, s
}

func TestOverlayPolicyRootApprovalAndBoundedSelection(t *testing.T) {
	c, s := overlayPolicyFixture()
	if !c.Valid() || !overlayPoliciesApproved(c.OverlayClusters[0], s) {
		t.Fatal("valid root policy refused")
	}
	if _, _, err := overlayproto.CanonicalSnapshot(s); err != nil {
		t.Fatal(err)
	}
	s.Gateways[0].AllowedPrefixes = []string{"192.0.2.0/25"}
	if !overlayPoliciesApproved(c.OverlayClusters[0], s) {
		t.Fatal("contained route refused")
	}
	cases := map[string]func(*Config, *overlayproto.Snapshot){
		"route_broaden":  func(_ *Config, s *overlayproto.Snapshot) { s.Gateways[0].AllowedPrefixes = []string{"192.0.0.0/16"} },
		"route_identity": func(_ *Config, s *overlayproto.Snapshot) { s.Gateways[0].MAC = "52:54:00:00:00:01" },
		"nat_identity": func(_ *Config, s *overlayproto.Snapshot) {
			s.NATPolicies[0].GatewayInstanceID = strings.Repeat("7", 32)
		},
		"nat_pin":                       func(_ *Config, s *overlayproto.Snapshot) { s.NATPolicies[0].ProfileSHA256 = strings.Repeat("0", 64) },
		"snat_root":                     func(c *Config, _ *overlayproto.Snapshot) { c.OverlayClusters[0].NATProfiles[0].AllowSNAT = false },
		"source_broaden":                func(_ *Config, s *overlayproto.Snapshot) { s.NATPolicies[0].Forwardings[0].SourceCIDR = "192.0.0.0/16" },
		"source_outside_selected_route": func(_ *Config, s *overlayproto.Snapshot) { s.Gateways[0].AllowedPrefixes = []string{"192.0.2.128/25"} },
		"public_port":                   func(_ *Config, s *overlayproto.Snapshot) { s.NATPolicies[0].Forwardings[0].PublicPort = 22 },
		"protocol":                      func(_ *Config, s *overlayproto.Snapshot) { s.NATPolicies[0].Forwardings[0].Protocol = "udp" },
		"root_withdrawn":                func(c *Config, _ *overlayproto.Snapshot) { c.OverlayClusters[0].NATProfiles = nil },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			c, s := overlayPolicyFixture()
			edit(&c, &s)
			if overlayPoliciesApproved(c.OverlayClusters[0], s) {
				t.Fatal("unapproved policy accepted")
			}
		})
	}
}

func TestOverlayPolicyRootConfigRejectsAmbiguousAuthority(t *testing.T) {
	cases := map[string]func(*OverlayCluster){
		"gateway_alias": func(c *OverlayCluster) { c.Gateways = append(c.Gateways, c.Gateways[0]) },
		"profile_alias": func(c *OverlayCluster) { c.NATProfiles = append(c.NATProfiles, c.NATProfiles[0]) },
		"vpc_gateway_profile_alias": func(c *OverlayCluster) {
			p := c.NATProfiles[0]
			p.ProfileID = "second-nat"
			p.PublicIPv4 = "198.51.100.3"
			p.ProfileSHA256 = strings.Repeat("7", 64)
			c.NATProfiles = append(c.NATProfiles, p)
		},
		"profile_foreign_node": func(c *OverlayCluster) { c.NATProfiles[0].NodeID = "foreign" },
		"source_not_routed":    func(c *OverlayCluster) { c.NATProfiles[0].AllowedSourceCIDRs = []string{"203.0.113.0/24"} },
		"source_null":          func(c *OverlayCluster) { c.NATProfiles[0].AllowedSourceCIDRs = nil },
		"ports_overlap": func(c *OverlayCluster) {
			c.NATProfiles[0].AllowedPorts = append(c.NATProfiles[0].AllowedPorts, OverlayNATPortRange{"tcp", 40500, 42000})
		},
		"port_zero":     func(c *OverlayCluster) { c.NATProfiles[0].AllowedPorts[0].Start = 0 },
		"multicast":     func(c *OverlayCluster) { c.NATProfiles[0].PublicIPv4 = "224.0.0.1" },
		"default_route": func(c *OverlayCluster) { c.Gateways[0].AllowedPrefixes = []string{"0.0.0.0/0"} },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			c, _ := overlayPolicyFixture()
			edit(&c.OverlayClusters[0])
			if c.Valid() {
				t.Fatal("ambiguous root approved")
			}
		})
	}
}

func TestOverlayNATInputDistinguishesOmittedEmptyAndNull(t *testing.T) {
	old := `{"cluster_id":"policy-test","expected_epoch":0,"members":[],"gateways":[]}`
	var a, b OverlayEpochInput
	if !strict([]byte(old), &a) || !strict([]byte(strings.TrimSuffix(old, "}")+`,"nat_policies":[]}`), &b) {
		t.Fatal("valid input rejected")
	}
	_, shaA, err := canonicalOverlayInput(a)
	if err != nil {
		t.Fatal(err)
	}
	_, shaB, err := canonicalOverlayInput(b)
	if err != nil {
		t.Fatal(err)
	}
	if shaA == shaB || shaA != overlayproto.Digest([]byte(old)) {
		t.Fatal("old digest changed or explicit removal lost")
	}
	for _, bad := range []string{strings.TrimSuffix(old, "}") + `,"nat_policies":null}`, strings.TrimSuffix(old, "}") + `,"nat_policies":[],"nat_policies":[]}`, strings.TrimSuffix(old, "}") + `,"NATPolicies":[]}`} {
		var in OverlayEpochInput
		if strict([]byte(bad), &in) {
			t.Fatal("ambiguous NAT accepted", bad)
		}
	}
	var replacement OverlayRecoveryInput
	if strict([]byte(`{"expected_snapshot_sha256":"`+strings.Repeat("a", 64)+`","replacement":{"members":[],"gateways":[],"nat_policies":null}}`), &replacement) {
		t.Fatal("replacement null treated as preserve")
	}
	_, s := overlayPolicyFixture()
	policies := s.NATPolicies
	policies[0].Forwardings = append(policies[0].Forwardings, overlayproto.NATForwarding{ID: strings.Repeat("1", 32), Protocol: "tcp", PublicPort: 40002, TargetPort: 22, TargetInstanceID: s.Members[0].InstanceID, SourceCIDR: "192.0.2.0/25"})
	a.NATPolicies = &policies
	c, _, err := canonicalOverlayInput(a)
	if err != nil {
		t.Fatal(err)
	}
	if (*a.NATPolicies)[0].Forwardings[0].ID == (*c.NATPolicies)[0].Forwardings[0].ID {
		t.Fatal("caller mutated or not sorted")
	}
	raw, _ := json.Marshal(c)
	var decoded OverlayEpochInput
	if !strict(raw, &decoded) {
		t.Fatal("canonical input not strict")
	}
}

func TestOverlayRootProfileMigrationRequiresExplicitPreviousPins(t *testing.T) {
	c, s := overlayPolicyFixture()
	e := OverlayEpoch{ClusterID: s.ClusterID, Snapshot: s}
	old := c.OverlayClusters[0].Profiles[0]
	c.OverlayClusters[0].Profiles = append([]overlayproto.ProfilePin{}, c.OverlayClusters[0].Profiles...)
	c.OverlayClusters[0].Profiles[0].ProfileSHA256 = strings.Repeat("9", 64)
	if overlayPinsMatch(c, e) || overlayRecoveryPinsApproved(c, e) {
		t.Fatal("profile drift implicitly adopted")
	}
	c.OverlayClusters[0].PreviousProfiles = []overlayproto.ProfilePin{old}
	if !c.Valid() || !overlayRecoveryPinsApproved(c, e) || overlayPinsMatch(c, e) {
		t.Fatal("explicit recovery migration approval invalid")
	}
	c.OverlayClusters[0].PreviousProfiles[0].ProfileID = "foreign-profile"
	if c.Valid() {
		t.Fatal("previous profile changed original device identity")
	}
	c.OverlayClusters[0].PreviousProfiles = []overlayproto.ProfilePin{c.OverlayClusters[0].Profiles[0]}
	if c.Valid() {
		t.Fatal("same current pin called migration")
	}
}

func TestOverlayNATRootPortRangeLimitMatchesNodeContract(t *testing.T) {
	c, _ := overlayPolicyFixture()
	ports := []OverlayNATPortRange{}
	for i := 0; i < 64; i++ {
		ports = append(ports, OverlayNATPortRange{Protocol: "tcp", Start: 1000 + i*2, End: 1000 + i*2})
	}
	c.OverlayClusters[0].NATProfiles[0].AllowedPorts = ports
	if !c.Valid() {
		t.Fatal("64 approved ranges rejected")
	}
	c.OverlayClusters[0].NATProfiles[0].AllowedPorts = append(ports, OverlayNATPortRange{Protocol: "tcp", Start: 2000, End: 2000})
	if c.Valid() {
		t.Fatal("65 ranges cannot execute on node")
	}
}

func internetOverlayPolicyFixture() (Config, overlayproto.Snapshot) {
	c, s := overlayPolicyFixture()
	c.OverlayClusters[0].NATProfiles[0].PublicIPv4 = "8.8.8.8"
	c.OverlayClusters[0].NATProfiles[0].AllowInternetEgress = true
	c.OverlayClusters[0].NATProfiles[0].AllowedSourceCIDRs = []string{}
	c.OverlayClusters[0].Gateways[0].AllowedPrefixes = []string{}
	s.Gateways[0].AllowedPrefixes = []string{}
	s.NATPolicies[0].Forwardings = []overlayproto.NATForwarding{}
	s.NATPolicies[0].InternetEgressEnabled = true
	return c, s
}

func TestOverlayInternetEgressRequiresSeparateRootApproval(t *testing.T) {
	c, s := internetOverlayPolicyFixture()
	if !c.Valid() || !overlayPoliciesApproved(c.OverlayClusters[0], s) {
		t.Fatal("approved Internet-only gateway rejected")
	}
	if _, _, err := overlayproto.CanonicalSnapshot(s); err != nil {
		t.Fatal("Internet-only snapshot rejected", err)
	}
	cases := map[string]func(*Config, *overlayproto.Snapshot){
		"internet_not_approved": func(c *Config, _ *overlayproto.Snapshot) {
			c.OverlayClusters[0].NATProfiles[0].AllowInternetEgress = false
		},
		"snat_not_approved":     func(c *Config, _ *overlayproto.Snapshot) { c.OverlayClusters[0].NATProfiles[0].AllowSNAT = false },
		"snat_not_selected":     func(_ *Config, s *overlayproto.Snapshot) { s.NATPolicies[0].SNATEnabled = false },
		"root_withdrawn":        func(c *Config, _ *overlayproto.Snapshot) { c.OverlayClusters[0].NATProfiles = nil },
		"root_gateway_null":     func(c *Config, _ *overlayproto.Snapshot) { c.OverlayClusters[0].Gateways[0].AllowedPrefixes = nil },
		"selected_gateway_null": func(_ *Config, s *overlayproto.Snapshot) { s.Gateways[0].AllowedPrefixes = nil },
		"default_route":         func(_ *Config, s *overlayproto.Snapshot) { s.Gateways[0].AllowedPrefixes = []string{"0.0.0.0/0"} },
		"unrouted_dnat": func(_ *Config, s *overlayproto.Snapshot) {
			s.NATPolicies[0].Forwardings = []overlayproto.NATForwarding{{ID: strings.Repeat("2", 32), Protocol: "tcp", PublicPort: 40001, TargetInstanceID: s.Members[0].InstanceID, TargetPort: 22, SourceCIDR: "192.0.2.0/25"}}
		},
	}
	// A gateway retained with explicit empty routes is a safe inactive state.
	for _, nat := range [][]overlayproto.NATPolicy{nil, {}} {
		inactive := s
		inactive.NATPolicies = nat
		if !overlayPoliciesApproved(c.OverlayClusters[0], inactive) {
			t.Fatal("explicit empty gateway could not be retained when disabled")
		}
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			c, s := internetOverlayPolicyFixture()
			edit(&c, &s)
			if c.Valid() && overlayPoliciesApproved(c.OverlayClusters[0], s) {
				t.Fatal("unapproved Internet egress accepted")
			}
		})
	}
	for _, ip := range []string{"10.0.0.1", "127.0.0.1", "100.64.0.1", "169.254.169.254", "192.0.2.1", "198.51.100.2", "203.0.113.1", "198.18.0.1", "224.0.0.1", "::1", "8.8.8.8 "} {
		t.Run(ip, func(t *testing.T) {
			c, s := internetOverlayPolicyFixture()
			c.OverlayClusters[0].NATProfiles[0].PublicIPv4 = ip
			if c.Valid() || overlayPoliciesApproved(c.OverlayClusters[0], s) {
				t.Fatal("non-public Internet SNAT address approved", ip)
			}
		})
	}
}

func TestOverlayInternetEgressDoesNotBroadenDNATAuthority(t *testing.T) {
	c, s := overlayPolicyFixture()
	c.OverlayClusters[0].NATProfiles[0].PublicIPv4 = "8.8.8.8"
	c.OverlayClusters[0].NATProfiles[0].AllowInternetEgress = true
	s.NATPolicies[0].InternetEgressEnabled = true
	if !c.Valid() || !overlayPoliciesApproved(c.OverlayClusters[0], s) {
		t.Fatal("approved mixed prefix / Internet mode rejected")
	}
	for name, edit := range map[string]func(*overlayproto.Snapshot){
		"source_outside_root": func(s *overlayproto.Snapshot) { s.NATPolicies[0].Forwardings[0].SourceCIDR = "1.1.1.0/24" },
		"source_outside_selected": func(s *overlayproto.Snapshot) {
			s.Gateways[0].AllowedPrefixes = []string{"192.0.2.128/25"}
		},
		"unapproved_port": func(s *overlayproto.Snapshot) { s.NATPolicies[0].Forwardings[0].PublicPort = 22 },
	} {
		t.Run(name, func(t *testing.T) {
			_, selected := overlayPolicyFixture()
			selected.NATPolicies[0].InternetEgressEnabled = true
			edit(&selected)
			if overlayPoliciesApproved(c.OverlayClusters[0], selected) {
				t.Fatal("Internet approval broadened port forwarding")
			}
		})
	}
}

func TestOverlayInternetIntentPreservesLegacyBytes(t *testing.T) {
	_, s := overlayPolicyFixture()
	policies := s.NATPolicies
	in := OverlayEpochInput{ClusterID: s.ClusterID, Members: []OverlayMemberInput{}, Gateways: s.Gateways, NATPolicies: &policies}
	old, digest, err := canonicalOverlayInput(in)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(old)
	if strings.Contains(string(raw), "internet_egress_enabled") || strings.Contains(string(raw), "allow_internet_egress") {
		t.Fatal("default false modified legacy request bytes")
	}
	// Explicit false is the same existing intent; true is a distinct request.
	decodedJSON := strings.Replace(string(raw), `"snat_enabled":true`, `"snat_enabled":true,"internet_egress_enabled":false`, 1)
	var decoded OverlayEpochInput
	if !strict([]byte(decodedJSON), &decoded) {
		t.Fatal("explicit false did not decode")
	}
	_, falseDigest, err := canonicalOverlayInput(decoded)
	if err != nil || falseDigest != digest {
		t.Fatal("explicit false changed old intent", err)
	}
	(*decoded.NATPolicies)[0].InternetEgressEnabled = true
	_, internetDigest, err := canonicalOverlayInput(decoded)
	if err != nil || internetDigest == digest {
		t.Fatal("Internet mode reused old idempotent intent", err)
	}
	root, _ := overlayPolicyFixture()
	rootJSON, _ := json.Marshal(root.OverlayClusters[0].NATProfiles[0])
	if strings.Contains(string(rootJSON), "allow_internet_egress") {
		t.Fatal("default false changed root projection")
	}
}

func TestOverlayGatewayPrefixesMustBeExplicitEvenForInternet(t *testing.T) {
	_, s := internetOverlayPolicyFixture()
	policies := s.NATPolicies
	in := OverlayEpochInput{ClusterID: s.ClusterID, Members: []OverlayMemberInput{}, Gateways: s.Gateways, NATPolicies: &policies}
	if _, _, err := canonicalOverlayInput(in); err != nil {
		t.Fatal("explicit empty prefixes rejected", err)
	}
	in.Gateways[0].AllowedPrefixes = nil
	if _, _, err := canonicalOverlayInput(in); !errors.Is(err, ErrInput) {
		t.Fatal("null route array laundered to explicit empty", err)
	}
}

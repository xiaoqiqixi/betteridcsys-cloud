package control

import (
	"aster/billing/controllerapi"
	"aster/cloud/internal/nodeproto"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func vpcTestResources(p NodeProfile) controllerapi.Resources {
	r := testResources(p)
	r.NetworkType, r.BandwidthMbps, r.InboundBandwidthMbps = "vpc", 100, 200
	return r
}
func vpcTestConfig(p NodeProfile, pool string) Config {
	c := testConfig(p)
	c.NetworkProfiles = []NetworkProfile{{ID: "vpc-a-v1", NodeID: p.ID, PoolID: pool, ProfileSHA256: strings.Repeat("b", 64), OwnerRef: strings.Repeat("a", 32)}}
	c.Presets = []Preset{{ID: "ovs-vpc-private-v1", NodeID: p.ID, Resources: vpcTestResources(p), NetworkProfileID: "vpc-a-v1"}}
	return c
}
func vpcTestCapabilities(p NodeProfile, now time.Time) Capability {
	c := testCapabilities(p, now)
	c.NetworkProfiles = append(c.NetworkProfiles, nodeproto.OVSNetworkCapability, nodeproto.PublicIngressCapability)
	c.OVSNetworkProfiles = []string{"vpc-a-v1"}
	return c
}
func TestVPCProfilesRequireExplicitProductAndNodeApproval(t *testing.T) {
	p := testProfile()
	c := vpcTestConfig(p, strings.Repeat("1", 32))
	if !c.Valid() {
		t.Fatal("explicit VPC config rejected")
	}
	r := vpcTestResources(p)
	caps := vpcTestCapabilities(p, time.Now())
	if caps.Supports(r, p) || !caps.SupportsNetwork(r, p, "vpc-a-v1") || caps.SupportsNetwork(testResources(p), p, "vpc-a-v1") || caps.SupportsNetwork(r, p, "other") {
		t.Fatal("legacy/default or unapproved profile acquired VPC semantics")
	}
	for name, mutate := range map[string]func(*controllerapi.Resources){
		"default_outbound": func(r *controllerapi.Resources) { r.BandwidthMbps = 0 },
		"default_inbound":  func(r *controllerapi.Resources) { r.InboundBandwidthMbps = 0 },
		"outbound_excess":  func(r *controllerapi.Resources) { r.BandwidthMbps = 100001 },
		"inbound_excess":   func(r *controllerapi.Resources) { r.InboundBandwidthMbps = 100001 },
		"normal":           func(r *controllerapi.Resources) { r.NetworkType = "normal" },
		"ipv6":             func(r *controllerapi.Resources) { r.IPv6Count = 1 },
		"two_ipv4":         func(r *controllerapi.Resources) { r.IPv4Count = 2 },
		"no_ipv4":          func(r *controllerapi.Resources) { r.IPv4Count = 0 },
		"quota":            func(r *controllerapi.Resources) { r.TransferGiB = 1 },
		"one_direction":    func(r *controllerapi.Resources) { r.TrafficDirection = "in" },
		"data_disk":        func(r *controllerapi.Resources) { r.DataDiskGiB = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := r
			mutate(&changed)
			if caps.SupportsNetwork(changed, p, "vpc-a-v1") {
				t.Fatal("resource silently converted/ignored")
			}
		})
	}
	for name, mutate := range map[string]func(*Capability){
		"no_flag":         func(c *Capability) { c.NetworkProfiles = []string{"normal-static-ipv4-dedicated-bridge"} },
		"no_profiles":     func(c *Capability) { c.OVSNetworkProfiles = nil },
		"duplicate":       func(c *Capability) { c.OVSNetworkProfiles = []string{"vpc-a-v1", "vpc-a-v1"} },
		"wrong_case":      func(c *Capability) { c.OVSNetworkProfiles = []string{"VPC-A-V1"} },
		"foreign_profile": func(c *Capability) { c.OVSNetworkProfiles = []string{"vpc-b-v1"} },
		"maintenance":     func(c *Capability) { c.Maintenance = true },
	} {
		t.Run(name, func(t *testing.T) {
			changed := caps
			mutate(&changed)
			if changed.SupportsNetwork(r, p, "vpc-a-v1") {
				t.Fatal("invalid/unapproved capability authorized VPC")
			}
		})
	}
	request := testRequest(p)
	request.OwnerRef = c.NetworkProfiles[0].OwnerRef
	*request.Product.Resources = r
	request.ConfigurationSHA256, _ = request.Product.Digest()
	if len(c.Candidates(request)) != 0 {
		t.Fatal("custom VPC guessed a pool without immutable digest approval")
	}
	c.NetworkProfiles[0].ConfigurationSHA256 = request.ConfigurationSHA256
	got := c.Candidates(request)
	if len(got) != 1 || got[0].NetworkPoolID != c.NetworkProfiles[0].PoolID || got[0].NetworkProfileSHA != c.NetworkProfiles[0].ProfileSHA256 {
		t.Fatal("custom immutable digest mapping lost")
	}
	request.Product.Resources.BandwidthMbps++
	request.ConfigurationSHA256, _ = request.Product.Digest()
	if len(c.Candidates(request)) != 0 {
		t.Fatal("changed financial specification adopted old profile approval")
	}
	for name, mutate := range map[string]func(*Config){
		"missing_profile":                 func(c *Config) { c.NetworkProfiles = nil },
		"missing_preset_selection":        func(c *Config) { c.Presets[0].NetworkProfileID = "" },
		"profile_invalid_id":              func(c *Config) { c.NetworkProfiles[0].ID = "arbitrary.profile" },
		"profile_wrong_node":              func(c *Config) { c.NetworkProfiles[0].NodeID = "other" },
		"profile_invalid_pool":            func(c *Config) { c.NetworkProfiles[0].PoolID = "pool" },
		"profile_missing_owner":           func(c *Config) { c.NetworkProfiles[0].OwnerRef = "" },
		"legacy_preset_id_cannot_upgrade": func(c *Config) { c.Presets[0].ID = "old-normal-plan" },
		"profile_missing_sha":             func(c *Config) { c.NetworkProfiles[0].ProfileSHA256 = "" },
		"normal_preset_with_profile":      func(c *Config) { c.Presets[0].Resources = testResources(p) },
		"duplicate_custom_mapping": func(c *Config) {
			c.NetworkProfiles = append(c.NetworkProfiles, c.NetworkProfiles[0])
			c.NetworkProfiles[1].ID = "vpc-b-v1"
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := c
			changed.Presets = append([]Preset{}, c.Presets...)
			changed.NetworkProfiles = append([]NetworkProfile{}, c.NetworkProfiles...)
			mutate(&changed)
			if changed.Valid() {
				t.Fatal("ambiguous/unapproved config accepted")
			}
		})
	}
}
func TestNetworkProfileAdditionKeepsLegacyJSONAndStrictBoundaries(t *testing.T) {
	old := testConfig(testProfile())
	raw, e := json.Marshal(old)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(raw), `"network_profiles"`) {
		t.Fatal("legacy config unexpectedly gained required field")
	}
	var out Config
	if !strict(raw, &out) || !out.Valid() {
		t.Fatal("legacy root config no longer loads")
	}
	vpc := vpcTestConfig(testProfile(), strings.Repeat("1", 32))
	raw, _ = json.Marshal(vpc)
	if !strict(raw, &out) || !out.Valid() {
		t.Fatal("new root config does not round-trip")
	}
	if example, err := os.ReadFile("../../deploy/controller-ovs.example.json"); err != nil || !strict(example, &out) || !out.Valid() {
		t.Fatal("documented synthetic root config has incompatible shape", err)
	}
	for _, raw := range []string{
		strings.Replace(string(raw), `"profile_sha256":`, `"Profile_SHA256":`, 1),
		strings.Replace(string(raw), `"profile_sha256":`, `"profile_sha256":"`+strings.Repeat("c", 64)+`","profile_sha256":`, 1),
		strings.Replace(string(raw), `"profile_sha256":`, `"endpoint":"https://unapproved.invalid","profile_sha256":`, 1),
	} {
		if strict([]byte(raw), &out) {
			t.Fatal("ambiguous/unknown root network config accepted")
		}
	}
}

func TestVPCCustomMappingIsExactPerTenantNotSharedPoolAdoption(t *testing.T) {
	p := testProfile()
	c := vpcTestConfig(p, strings.Repeat("1", 32))
	r := testRequest(p)
	*r.Product.Resources = vpcTestResources(p)
	r.ConfigurationSHA256, _ = r.Product.Digest()
	r.OwnerRef = c.NetworkProfiles[0].OwnerRef
	c.NetworkProfiles[0].ConfigurationSHA256 = r.ConfigurationSHA256
	other := c.NetworkProfiles[0]
	other.ID = "vpc-b-v1"
	other.OwnerRef = strings.Repeat("b", 32)
	other.PoolID = strings.Repeat("2", 32)
	c.NetworkProfiles = append(c.NetworkProfiles, other)
	if !c.Valid() {
		t.Fatal("same product with independently approved tenant pools rejected")
	}
	for _, profile := range c.NetworkProfiles {
		r.OwnerRef = profile.OwnerRef
		got := c.Candidates(r)
		if len(got) != 1 || got[0].NetworkPoolID != profile.PoolID || got[0].NetworkOwnerRef != profile.OwnerRef {
			t.Fatal("tenant selected another tenant's pool", got)
		}
	}
	r.OwnerRef = strings.Repeat("c", 32)
	if len(c.Candidates(r)) != 0 {
		t.Fatal("unapproved tenant adopted a shared financial digest")
	}
	preset := testRequest(p)
	preset.Product = controllerapi.ProductSpec{Mode: "preset", ControllerID: c.ControllerID, RemoteProductID: c.Presets[0].ID}
	preset.OwnerRef = other.OwnerRef
	if len(c.Candidates(preset)) != 0 {
		t.Fatal("preapproved single-owner preset silently became multi-tenant")
	}
}

func TestVPCPresetProjectionDoesNotExposeNewRootPolicySelectors(t *testing.T) {
	c := vpcTestConfig(testProfile(), strings.Repeat("1", 32))
	raw, e := json.Marshal(publicPresets(c.Presets))
	if e != nil {
		t.Fatal(e)
	}
	var out []map[string]json.RawMessage
	if json.Unmarshal(raw, &out) != nil || len(out) != 1 || len(out[0]) != 3 || out[0]["id"] == nil || out[0]["node_id"] == nil || out[0]["resources"] == nil {
		t.Fatal("public preset DTO changed with root policy", string(raw))
	}
	if string(mustPublicPresetJSON(t, nil)) != "[]" {
		t.Fatal("empty presets became null")
	}
}
func mustPublicPresetJSON(t *testing.T, presets []Preset) []byte {
	t.Helper()
	raw, e := json.Marshal(publicPresets(presets))
	if e != nil {
		t.Fatal(e)
	}
	return raw
}

func TestControllerFixtureDatabasePrefixCannotWidenTemporaryGrant(t *testing.T) {
	if p, e := controllerFixtureDatabasePrefix(""); e != nil || p != "aster_cloud_test_console_http_" {
		t.Fatal("legacy CI prefix changed", p, e)
	}
	if p, e := controllerFixtureDatabasePrefix("aster_cloud_test_123456abcdef_"); e != nil || p != "aster_cloud_test_123456abcdef_" {
		t.Fatal("owned random case prefix rejected", p, e)
	}
	for _, p := range []string{"aster_ci_test", "aster_cloud_test_%", "aster_cloud_test_", "aster_cloud_test_ABCDEF123456_", "aster_cloud_test_123456abcdef%;DROP_", "aster_cloud_test_" + strings.Repeat("a", 25) + "_"} {
		if _, e := controllerFixtureDatabasePrefix(p); e == nil {
			t.Fatal("broad/arbitrary fixture database grant accepted", p)
		}
	}
}

func TestVPCPowerRequiresShutdownStartInsteadOfLegacyReboot(t *testing.T) {
	for _, action := range []string{"start", "shutdown", "force_off", "delete"} {
		if !networkActionSupported(action) {
			t.Fatal("supported bound power action rejected", action)
		}
	}
	for _, action := range []string{"reboot", "snapshot_create", "snapshot_restore", "backup_create", "backup_restore", "migrate_prepare", "migrate_activate", ""} {
		if networkActionSupported(action) {
			t.Fatal("unbound legacy action authorized for VPC", action)
		}
	}
}

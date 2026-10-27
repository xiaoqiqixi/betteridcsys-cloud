package control

import (
	"aster/billing/controllerapi"
	"aster/cloud/internal/nodeproto"
	"aster/cloud/internal/overlayproto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

type Config struct {
	Schema               int                   `json:"schema"`
	ControllerID         string                `json:"controller_id"`
	Listen               string                `json:"listen"`
	TLSCertFile          string                `json:"tls_cert_file"`
	TLSKeyFile           string                `json:"tls_key_file"`
	DSNFile              string                `json:"dsn_file"`
	BillingTokenFile     string                `json:"billing_token_file"`
	AdminReadTokenFile   string                `json:"admin_read_token_file"`
	AdminWriteTokenFile  string                `json:"admin_write_token_file"`
	HeartbeatTTLSeconds  int                   `json:"heartbeat_ttl_seconds"`
	Nodes                []NodeProfile         `json:"nodes"`
	Presets              []Preset              `json:"presets"`
	NetworkProfiles      []NetworkProfile      `json:"network_profiles,omitempty"`
	OverlayClusters      []OverlayCluster      `json:"overlay_clusters,omitempty"`
	DirectPublicProfiles []DirectPublicProfile `json:"direct_public_profiles,omitempty"`
}
type NodeProfile struct {
	ID                      string   `json:"id"`
	DatacenterID            string   `json:"datacenter_id"`
	GroupID                 string   `json:"group_id"`
	Endpoint                string   `json:"endpoint"`
	AllowedCIDRs            []string `json:"allowed_cidrs"`
	CAFile                  string   `json:"ca_file"`
	ClientCertFile          string   `json:"client_cert_file"`
	ClientKeyFile           string   `json:"client_key_file"`
	ServerCertificateSHA256 string   `json:"server_certificate_sha256"`
}
type Preset struct {
	ID               string                  `json:"id"`
	NodeID           string                  `json:"node_id"`
	Resources        controllerapi.Resources `json:"resources"`
	NetworkProfileID string                  `json:"network_profile_id,omitempty"`
}

// NetworkProfile is a root-controlled IPAM selection, not a customer resource
// selector. Custom financial products require an exact immutable Spec digest.
type NetworkProfile struct {
	ID                  string `json:"id"`
	NodeID              string `json:"node_id"`
	PoolID              string `json:"pool_id"`
	OwnerRef            string `json:"owner_ref"`
	ProfileSHA256       string `json:"profile_sha256"`
	ConfigurationSHA256 string `json:"configuration_sha256,omitempty"`
}
type OverlayMapping struct {
	NodeID     string `json:"node_id"`
	LocalVPCID string `json:"local_vpc_id"`
	VPCID      string `json:"vpc_id"`
}
type OverlayCluster struct {
	ClusterID        string                    `json:"cluster_id"`
	Profiles         []overlayproto.ProfilePin `json:"profiles"`
	PreviousProfiles []overlayproto.ProfilePin `json:"previous_profiles,omitempty"`
	Mappings         []OverlayMapping          `json:"mappings,omitempty"`
	Gateways         []overlayproto.Gateway    `json:"gateways,omitempty"`
	NATProfiles      []OverlayNATProfile       `json:"nat_profiles,omitempty"`
}

func (c Config) OverlayCluster(id string) (OverlayCluster, bool) {
	for _, x := range c.OverlayClusters {
		if x.ClusterID == id {
			return x, true
		}
	}
	return OverlayCluster{}, false
}
func (c Config) validOverlayClusters() bool {
	if len(c.OverlayClusters) > 32 {
		return false
	}
	seen := map[string]bool{}
	profiles := map[string]bool{}
	for _, cluster := range c.OverlayClusters {
		if !nodeproto.ValidNodeID(cluster.ClusterID) || seen[cluster.ClusterID] || len(cluster.Profiles) < 1 || len(cluster.Profiles) > 32 {
			return false
		}
		seen[cluster.ClusterID] = true
		nodes := map[string]bool{}
		if len(cluster.Mappings) > 128 {
			return false
		}
		mappingKeys := map[string]bool{}
		for _, pin := range cluster.Profiles {
			_, ok := c.Node(pin.NodeID)
			key := pin.NodeID + ":" + pin.ProfileID
			if !ok || nodes[pin.NodeID] || profiles[key] || !nodeproto.ValidNodeID(pin.ProfileID) || !overlayproto.ValidSHA(pin.ProfileSHA256) {
				return false
			}
			nodes[pin.NodeID] = true
			profiles[key] = true
		}
		for _, m := range cluster.Mappings {
			key := m.NodeID + ":" + m.LocalVPCID
			if !nodes[m.NodeID] || !nodeproto.ValidID(m.LocalVPCID) || !nodeproto.ValidID(m.VPCID) || mappingKeys[key] {
				return false
			}
			mappingKeys[key] = true
		}
		previousNodes := map[string]bool{}
		if len(cluster.PreviousProfiles) > len(cluster.Profiles) {
			return false
		}
		for _, old := range cluster.PreviousProfiles {
			found := false
			for _, current := range cluster.Profiles {
				if current.NodeID == old.NodeID && current.ProfileID == old.ProfileID && current.ProfileSHA256 != old.ProfileSHA256 {
					found = true
				}
			}
			if !found || previousNodes[old.NodeID] || !overlayproto.ValidSHA(old.ProfileSHA256) {
				return false
			}
			previousNodes[old.NodeID] = true
		}
		if !validOverlayPolicyApproval(cluster, nodes) {
			return false
		}
	}
	return true
}

type Secrets struct{ Billing, AdminRead, AdminWrite string }

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
var shaRE = regexp.MustCompile(`^[a-f0-9]{64}$`)
var vpcPresetID = regexp.MustCompile(`^ovs-vpc-[a-z0-9][a-z0-9_-]*-v[1-9][0-9]*$`)

func ReadProtected(path string, private bool, maximum int64) ([]byte, error) {
	return readProtected(path, private, maximum, 0)
}
func readProtected(path string, private bool, maximum int64, owner uint32) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n") {
		return nil, ErrInput
	}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrUnavailable
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (st.Uid != 0 && st.Uid != owner) || info.Mode().Perm()&0022 != 0 && !(st.Uid == 0 && info.Mode()&os.ModeSticky != 0) {
			return nil, ErrUnavailable
		}
		if parent == "/" {
			break
		}
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	f := os.NewFile(uintptr(fd), "protected-controller-file")
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > maximum || before.Mode().Perm()&0022 != 0 || private && before.Mode().Perm()&0077 != 0 {
		return nil, ErrUnavailable
	}
	st, ok := before.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != owner || st.Nlink != 1 {
		return nil, ErrUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(f, maximum+1))
	after, e := f.Stat()
	if err != nil || e != nil || len(raw) == 0 || int64(len(raw)) > maximum || !os.SameFile(before, after) || before.Size() != after.Size() || before.ModTime() != after.ModTime() {
		return nil, ErrUnavailable
	}
	return raw, nil
}
func LoadConfig(path string) (Config, Secrets, error) {
	raw, err := ReadProtected(path, true, 65536)
	var c Config
	if err != nil || !strict(raw, &c) || !c.Valid() {
		return Config{}, Secrets{}, ErrInput
	}
	token := func(path string) (string, error) {
		b, e := ReadProtected(path, true, 4096)
		s := strings.TrimSpace(string(b))
		if e != nil || len(s) < 32 || len(s) > 4096 || strings.ContainsAny(s, " \t\r\n") {
			return "", ErrInput
		}
		return s, nil
	}
	b, e1 := token(c.BillingTokenFile)
	r, e2 := token(c.AdminReadTokenFile)
	w, e3 := token(c.AdminWriteTokenFile)
	if e1 != nil || e2 != nil || e3 != nil || b == r || b == w || r == w {
		return Config{}, Secrets{}, ErrInput
	}
	return c, Secrets{b, r, w}, nil
}
func (c Config) Valid() bool {
	if !c.validDirectPublicProfiles() {
		return false
	}
	if c.Schema != 1 || !nodeproto.ValidNodeID(c.ControllerID) || c.HeartbeatTTLSeconds < 10 || c.HeartbeatTTLSeconds > 300 || len(c.Nodes) > 64 || c.Nodes == nil || c.Presets == nil || len(c.Presets) > 256 {
		return false
	}
	if _, _, e := net.SplitHostPort(c.Listen); e != nil {
		return false
	}
	for _, p := range []string{c.TLSCertFile, c.TLSKeyFile, c.DSNFile, c.BillingTokenFile, c.AdminReadTokenFile, c.AdminWriteTokenFile} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return false
		}
	}
	seen := map[string]bool{}
	for _, n := range c.Nodes {
		if !n.Valid() || seen[n.ID] {
			return false
		}
		seen[n.ID] = true
	}
	if !c.validOverlayClusters() {
		return false
	}
	if len(c.NetworkProfiles) > 256 {
		return false
	}
	networkSeen, customSeen := map[string]bool{}, map[string]bool{}
	for _, p := range c.NetworkProfiles {
		_, nodeOK := c.Node(p.NodeID)
		if !nodeproto.ValidNodeID(p.ID) || networkSeen[p.ID] || !nodeOK || !nodeproto.ValidID(p.PoolID) || !nodeproto.ValidID(p.OwnerRef) || !shaRE.MatchString(p.ProfileSHA256) || p.ConfigurationSHA256 != "" && (!shaRE.MatchString(p.ConfigurationSHA256) || customSeen[p.ConfigurationSHA256+":"+p.OwnerRef]) {
			return false
		}
		networkSeen[p.ID] = true
		if p.ConfigurationSHA256 != "" {
			customSeen[p.ConfigurationSHA256+":"+p.OwnerRef] = true
		}
	}
	presetSeen := map[string]bool{}
	for _, p := range c.Presets {
		n, ok := c.Node(p.NodeID)
		spec := controllerapi.ProductSpec{Mode: "custom", ControllerID: c.ControllerID, Resources: &p.Resources}
		if !identifier.MatchString(p.ID) || presetSeen[p.ID] || !ok || !spec.Valid() || p.Resources.ComputeNodeID != n.ID || p.Resources.DatacenterID != n.DatacenterID || p.Resources.NodeGroupID != n.GroupID {
			return false
		}
		if p.Resources.NetworkType == "vpc" {
			profile, ok := c.NetworkProfile(p.NetworkProfileID)
			if !ok || profile.NodeID != p.NodeID || !vpcResources(p.Resources) || !vpcPresetID.MatchString(p.ID) {
				return false
			}
		} else if p.NetworkProfileID != "" {
			return false
		}
		presetSeen[p.ID] = true
	}
	return true
}
func (c Config) NetworkProfile(id string) (NetworkProfile, bool) {
	for _, p := range c.NetworkProfiles {
		if p.ID == id {
			return p, true
		}
	}
	return NetworkProfile{}, false
}

// Current root approval is checked without rebuilding a task from mutable
// presets. Removing/changing a profile blocks new writes, not GET reconciliation.
func (c Config) approvesTaskNetwork(t nodeproto.NodeTask) bool {
	if t.Protocol == nodeproto.DirectPublicProtocol {
		return t.Network.IsZero() && (directCleanupAction(t.Action) && t.DirectPublic.ValidFor(t) || c.approvesDirectPublic(t.DirectPublic))
	}
	if t.Protocol == nodeproto.Protocol {
		return t.Network.IsZero() && t.DirectPublic.IsZero() && (!c.directRequired(t.NodeID) || t.Resources.NetworkType != "normal" || t.Resources.IPv4Count != 1 || t.Action != "create" && t.Action != "start" && t.Action != "reboot")
	}
	if t.Protocol != nodeproto.NetworkProtocol || !t.Network.ValidFor(t) {
		return false
	}
	p, ok := c.NetworkProfile(t.Network.ProfileID)
	return ok && p.NodeID == t.NodeID && p.PoolID == t.Network.PoolID && p.OwnerRef == t.OwnerRef && p.ProfileSHA256 == t.Network.ProfileSHA256
}
func (c Config) Node(id string) (NodeProfile, bool) {
	for _, n := range c.Nodes {
		if n.ID == id {
			return n, true
		}
	}
	return NodeProfile{}, false
}
func (p NodeProfile) Valid() bool {
	u, e := url.Parse(p.Endpoint)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || strings.ToLower(u.Host) != u.Host || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || strings.ContainsAny(p.Endpoint, "\x00\r\n\\") || !nodeproto.ValidNodeID(p.ID) || !identifier.MatchString(p.DatacenterID) || p.GroupID != "" && !identifier.MatchString(p.GroupID) || !shaRE.MatchString(p.ServerCertificateSHA256) || len(p.AllowedCIDRs) < 1 || len(p.AllowedCIDRs) > 16 {
		return false
	}
	for _, s := range p.AllowedCIDRs {
		x, e := netip.ParsePrefix(s)
		if e != nil || x.Masked().String() != s || x.Addr().Is4In6() || x.Bits() < 8 || x.Addr().Is6() && x.Bits() < 32 {
			return false
		}
	}
	for _, s := range []string{p.CAFile, p.ClientCertFile, p.ClientKeyFile} {
		if !filepath.IsAbs(s) || filepath.Clean(s) != s {
			return false
		}
	}
	return true
}
func (p NodeProfile) Digest() string { raw, _ := json.Marshal(p); return nodeproto.Digest(raw) }
func (c Config) Candidates(r controllerapi.Request) []Candidate {
	if r.Product.ControllerID != c.ControllerID {
		return nil
	}
	add := func(n NodeProfile, resources controllerapi.Resources, profileID string) (Candidate, bool) {
		candidate := Candidate{Node: n, ProfileSHA: n.Digest(), Resources: resources, DirectPublicRequired: c.directRequired(n.ID) && resources.NetworkType == "normal"}
		if resources.NetworkType == "vpc" {
			profile, ok := c.NetworkProfile(profileID)
			if !ok || profile.NodeID != n.ID || profile.OwnerRef != r.OwnerRef || !vpcResources(resources) {
				return Candidate{}, false
			}
			candidate.NetworkProfileID, candidate.NetworkPoolID, candidate.NetworkProfileSHA = profile.ID, profile.PoolID, profile.ProfileSHA256
			candidate.NetworkOwnerRef = profile.OwnerRef
			for _, cluster := range c.OverlayClusters {
				for _, pin := range cluster.Profiles {
					if pin.NodeID == n.ID && pin.ProfileID == profileID {
						candidate.Overlay = &OverlayAdmission{ControllerID: c.ControllerID, Cluster: cluster, Nodes: append([]NodeProfile{}, c.Nodes...), RootClusters: append([]OverlayCluster{}, c.OverlayClusters...), HeartbeatTTLSeconds: c.HeartbeatTTLSeconds}
					}
				}
			}
		} else if profileID != "" {
			return Candidate{}, false
		}
		return candidate, true
	}
	if r.Product.Mode == "preset" {
		for _, p := range c.Presets {
			if p.ID == r.Product.RemoteProductID {
				n, ok := c.Node(p.NodeID)
				if ok {
					if candidate, ok := add(n, p.Resources, p.NetworkProfileID); ok {
						return []Candidate{candidate}
					}
				}
			}
		}
		return nil
	}
	if r.Product.Mode != "custom" || r.Product.Resources == nil {
		return nil
	}
	wanted := *r.Product.Resources
	profileID := ""
	if wanted.NetworkType == "vpc" {
		hash, err := r.Product.Digest()
		if err != nil || hash != r.ConfigurationSHA256 {
			return nil
		}
		for _, profile := range c.NetworkProfiles {
			if profile.ConfigurationSHA256 == hash && profile.OwnerRef == r.OwnerRef {
				if profileID != "" {
					return nil
				}
				profileID = profile.ID
			}
		}
		if profileID == "" {
			return nil
		}
	}
	// This first vertical slice requires explicit concrete IDs. It never silently
	// maps a custom node group, storage, bandwidth or VPC to a different resource.
	for _, n := range c.Nodes {
		if wanted.ComputeNodeID == n.ID && wanted.DatacenterID == n.DatacenterID && wanted.NodeGroupID == n.GroupID {
			if candidate, ok := add(n, wanted, profileID); ok {
				return []Candidate{candidate}
			}
		}
	}
	return nil
}
func loadNodeTLS(p NodeProfile) (*tls.Config, error) { return loadNodeTLSOwned(p, 0) }

func loadNodeTLSOwned(p NodeProfile, owner uint32) (*tls.Config, error) {
	ca, e1 := readProtected(p.CAFile, false, 65536, owner)
	cert, e2 := readProtected(p.ClientCertFile, false, 65536, owner)
	key, e3 := readProtected(p.ClientKeyFile, true, 65536, owner)
	pool := x509.NewCertPool()
	pair, e4 := tls.X509KeyPair(cert, key)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || !pool.AppendCertsFromPEM(ca) {
		return nil, ErrUnavailable
	}
	u, _ := url.Parse(p.Endpoint)
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, Certificates: []tls.Certificate{pair}, ServerName: u.Hostname(), VerifyConnection: func(cs tls.ConnectionState) error {
		if len(cs.VerifiedChains) == 0 || len(cs.PeerCertificates) == 0 {
			return ErrUnavailable
		}
		h := sha256.Sum256(cs.PeerCertificates[0].Raw)
		if hex.EncodeToString(h[:]) != p.ServerCertificateSHA256 {
			return ErrUnavailable
		}
		return nil
	}}, nil
}
func heartbeatFresh(at *time.Time, now time.Time, ttl time.Duration) bool {
	return at != nil && !at.After(now.Add(30*time.Second)) && now.Sub(*at) <= ttl
}

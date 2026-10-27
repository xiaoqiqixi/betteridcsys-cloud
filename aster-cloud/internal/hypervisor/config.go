// Package hypervisor implements the narrowly approved local libvirt/KVM executor.
package hypervisor

import (
	"aster/cloud/internal/nodeproto"
	"aster/cloud/internal/overlayproto"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

var ErrUnsupported = errors.New("UNSUPPORTED_RESOURCES")
var ErrConflict = errors.New("OPERATION_CONFLICT")
var ErrOwnership = errors.New("OWNERSHIP_REJECTED")
var ErrNotFound = errors.New("INSTANCE_NOT_FOUND")
var safeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
var bridgeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$`)

type Image struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type Network struct {
	RequirePublicLease          bool     `json:"require_public_lease,omitempty"`
	Enabled                     bool     `json:"enabled"`
	DedicatedBridgeAcknowledged bool     `json:"dedicated_bridge_acknowledged"`
	Bridge                      string   `json:"bridge"`
	CIDR                        string   `json:"cidr"`
	Gateway                     string   `json:"gateway"`
	Addresses                   []string `json:"addresses"`
	DNS                         []string `json:"dns"`
	Filter                      string   `json:"filter"`
	FilterSHA256                string   `json:"filter_sha256"`
	SSHAuthorizedKeys           []string `json:"ssh_authorized_keys"`
}
type StorageConfig struct {
	Enabled                      bool              `json:"enabled"`
	Directory                    string            `json:"directory"`
	InboxDirectory               string            `json:"inbox_directory"`
	MaxArtifactBytes             int64             `json:"max_artifact_bytes"`
	MaxTotalBytes                int64             `json:"max_total_bytes"`
	AllowControllerInboxApproval bool              `json:"allow_controller_inbox_approval"`
	AllowMigration               bool              `json:"allow_migration"`
	SourceCertificatePins        map[string]string `json:"source_certificate_pins"`
}

type Config struct {
	OVSProfiles                         map[string]OVSProfile `json:"ovs_profiles,omitempty"`
	Storage                             StorageConfig         `json:"storage"`
	NodeID                              string                `json:"node_id"`
	DatacenterID                        string                `json:"datacenter_id"`
	NodeGroupID                         string                `json:"node_group_id"`
	Listen                              string                `json:"listen"`
	AllowPublicListen                   bool                  `json:"allow_public_listen"`
	Certificate                         string                `json:"certificate"`
	PrivateKey                          string                `json:"private_key"`
	ControllerCA                        string                `json:"controller_ca"`
	ExpectedControllerCertificateSHA256 string                `json:"expected_controller_certificate_sha256"`
	StateDirectory                      string                `json:"state_directory"`
	StorageID                           string                `json:"storage_id"`
	StorageDirectory                    string                `json:"storage_directory"`
	Images                              map[string]Image      `json:"images"`
	Network                             Network               `json:"network"`
	AllowIsolatedNoNIC                  bool                  `json:"allow_isolated_no_nic"`
	AllowUnmeteredDefault               bool                  `json:"allow_unmetered_default"`
	AllowDelete                         bool                  `json:"allow_delete"`
	Maintenance                         bool                  `json:"maintenance"`
	CPUAllocationLimit                  int                   `json:"cpu_allocation_limit"`
	MemoryAllocationLimitMiB            int                   `json:"memory_allocation_limit_mib"`
	DiskAllocationLimitGiB              int                   `json:"disk_allocation_limit_gib"`
}

func hashString(s string) bool {
	raw, e := hex.DecodeString(s)
	return e == nil && len(raw) == 32 && strings.ToLower(s) == s
}

// NoSymlinkPath refuses every existing symlink component, including an absent final target.
func NoSymlinkPath(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("path must be canonical absolute")
	}
	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(path, current), current) {
		current = filepath.Join(current, part)
		st, e := os.Lstat(current)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return e
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return errors.New("symlink path refused")
		}
		uid, ok := st.Sys().(*syscall.Stat_t)
		if !ok || (uid.Uid != 0 && uid.Uid != uint32(os.Geteuid())) {
			return errors.New("untrusted ancestor owner")
		}
		if st.IsDir() && st.Mode().Perm()&0022 != 0 && !(uid.Uid == 0 && st.Mode()&os.ModeSticky != 0 && current != path) {
			return errors.New("writable ancestor refused")
		}
	}
	return nil
}
func ownedPath(path string, private bool, directory bool) error {
	if err := NoSymlinkPath(path); err != nil {
		return err
	}
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if st.IsDir() != directory || (!directory && !st.Mode().IsRegular()) {
		return errors.New("unexpected file type")
	}
	uid, ok := st.Sys().(*syscall.Stat_t)
	if !ok || uid.Uid != uint32(os.Geteuid()) || (!directory && uid.Nlink != 1) {
		return errors.New("path owner rejected")
	}
	if private && st.Mode().Perm()&0077 != 0 || st.Mode().Perm()&0022 != 0 {
		return errors.New("unsafe path permissions")
	}
	return nil
}
func LoadConfig(path string) (Config, error) {
	var cfg Config
	if err := ownedPath(path, true, false); err != nil {
		return cfg, err
	}
	raw, err := readApproved(path, true, 65536)
	if err != nil {
		return cfg, err
	}
	if len(raw) > 65536 {
		return cfg, errors.New("config too large")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&cfg) != nil || d.Decode(new(any)) != io.EOF {
		return cfg, errors.New("invalid config")
	}
	return cfg, cfg.Validate()
}
func (c Config) Validate() error {
	if !nodeproto.ValidNodeID(c.NodeID) || !safeName.MatchString(c.StorageID) || !hashString(c.ExpectedControllerCertificateSHA256) || len(c.Images) == 0 {
		return errors.New("invalid node identity/config")
	}
	if c.CPUAllocationLimit < 1 || c.CPUAllocationLimit > 4096 || c.MemoryAllocationLimitMiB < 128 || c.DiskAllocationLimitGiB < 1 {
		return errors.New("explicit allocation budgets required")
	}
	host, _, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return errors.New("invalid listen address")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return errors.New("listen must use literal IP")
	}
	if !ip.IsLoopback() && !c.AllowPublicListen {
		return errors.New("non-loopback listen requires approval")
	}
	for _, path := range []string{c.StateDirectory, c.StorageDirectory, c.Certificate, c.PrivateKey, c.ControllerCA} {
		if err = NoSymlinkPath(path); err != nil {
			return err
		}
	}
	if c.StateDirectory == c.StorageDirectory || strings.HasPrefix(c.StateDirectory, c.StorageDirectory+"/") || strings.HasPrefix(c.StorageDirectory, c.StateDirectory+"/") {
		return errors.New("state/storage paths must be separate")
	}
	for id, image := range c.Images {
		if !safeName.MatchString(id) || !hashString(image.SHA256) {
			return errors.New("invalid image approval")
		}
		if err = ownedPath(image.Path, false, false); err != nil {
			return fmt.Errorf("image: %w", err)
		}
	}
	if !c.AllowUnmeteredDefault && (c.Network.Enabled || c.AllowIsolatedNoNIC || len(c.OVSProfiles) == 0) {
		return errors.New("zero-bandwidth/transfer default requires explicit operator approval")
	}
	if err := c.Network.Validate(); err != nil {
		return err
	}
	if err := c.validateOVSProfiles(); err != nil {
		return err
	}
	return c.validateStorage()
}
func (n Network) Validate() error {
	if !n.Enabled {
		if n.RequirePublicLease {
			return errors.New("public lease mode requires enabled dedicated network")
		}
		return nil
	}
	if !n.DedicatedBridgeAcknowledged || !bridgeName.MatchString(n.Bridge) || !strings.HasPrefix(n.Filter, "aster-") || !safeName.MatchString(n.Filter) || !hashString(n.FilterSHA256) || len(n.Addresses) == 0 && !n.RequirePublicLease || len(n.SSHAuthorizedKeys) == 0 {
		return errors.New("approved dedicated bridge/filter/IPv4 pool/SSH keys required")
	}
	prefix, err := netip.ParsePrefix(n.CIDR)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() < 1 || prefix.Bits() > 30 {
		return errors.New("invalid IPv4 prefix")
	}
	prefix = prefix.Masked()
	gateway, err := netip.ParseAddr(n.Gateway)
	if err != nil || !gateway.Is4() || !prefix.Contains(gateway) {
		return errors.New("invalid gateway")
	}
	if n.RequirePublicLease && (n.CIDR != prefix.String() || !overlayproto.PublicInternetIPv4(n.Gateway) || gateway == prefix.Addr() || !prefix.Contains(gateway.Next()) || len(n.Addresses) > 4096) {
		return errors.New("direct public lease mode requires canonical public gateway and bounded address approvals")
	}
	seen := map[string]bool{}
	for _, raw := range n.Addresses {
		ip, e := netip.ParseAddr(raw)
		if e != nil || !ip.Is4() || n.RequirePublicLease && !overlayproto.PublicInternetIPv4(raw) || !prefix.Contains(ip) || ip == gateway || ip == prefix.Addr() || ip.IsUnspecified() || ip.IsMulticast() || seen[raw] {
			return errors.New("invalid/duplicate allocated IPv4")
		}
		b := ip.As4()
		mask := uint32(1)<<(32-prefix.Bits()) - 1
		if binary.BigEndian.Uint32(b[:])&mask == mask {
			return errors.New("broadcast address refused")
		}
		seen[raw] = true
	}
	for _, raw := range n.DNS {
		ip, e := netip.ParseAddr(raw)
		if e != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() || n.RequirePublicLease && !overlayproto.PublicInternetIPv4(raw) {
			return errors.New("invalid DNS")
		}
	}
	return validateSSHKeys(n.SSHAuthorizedKeys)
}

func validateSSHKeys(keys []string) error {
	if len(keys) == 0 {
		return errors.New("approved SSH public keys required")
	}
	for _, key := range keys {
		parts := strings.Fields(key)
		if len(parts) < 2 || parts[0] != "ssh-ed25519" || strings.ContainsAny(key, "\r\n") {
			return errors.New("only approved Ed25519 SSH public keys")
		}
		raw, e := base64.StdEncoding.DecodeString(parts[1])
		if e != nil || len(raw) != 51 || binary.BigEndian.Uint32(raw[:4]) != 11 || string(raw[4:15]) != "ssh-ed25519" || binary.BigEndian.Uint32(raw[15:19]) != 32 {
			return errors.New("invalid Ed25519 key")
		}
	}
	return nil
}

// openApproved prevents final-component symlink/hardlink substitution and checks the opened inode.
func openApproved(path string, private bool) (*os.File, error) {
	if err := NoSymlinkPath(path); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || st.Mode().Perm()&0022 != 0 || private && st.Mode().Perm()&0077 != 0 {
		f.Close()
		return nil, errors.New("opened inode rejected")
	}
	return f, nil
}
func readApproved(path string, private bool, max int64) ([]byte, error) {
	f, err := openApproved(path, private)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(raw)) > max {
		return nil, errors.New("approved file exceeds limit")
	}
	return raw, nil
}

func (c Config) validateStorage() error {
	st := c.Storage
	if st.AllowControllerInboxApproval && (!st.Enabled || !st.AllowMigration || len(st.SourceCertificatePins) == 0) {
		return errors.New("controller inbox approval requires explicit migration/source approvals")
	}
	if !st.Enabled {
		return nil
	}
	if st.MaxArtifactBytes < 1 || st.MaxArtifactBytes > 1<<44 || st.MaxTotalBytes < st.MaxArtifactBytes || st.MaxTotalBytes > 1<<48 {
		return errors.New("explicit bounded artifact budgets required")
	}
	paths := []string{st.Directory, st.InboxDirectory, c.StateDirectory, c.StorageDirectory}
	for n, p := range paths {
		if err := NoSymlinkPath(p); err != nil {
			return err
		}
		for k, q := range paths {
			if k != n && (p == q || strings.HasPrefix(p, q+"/")) {
				return errors.New("storage/state/inbox/artifact roots must be separate")
			}
		}
	}
	for node, pin := range st.SourceCertificatePins {
		if !nodeproto.ValidNodeID(node) || node == c.NodeID || !hashString(pin) {
			return errors.New("invalid migration source certificate approval")
		}
	}
	return nil
}

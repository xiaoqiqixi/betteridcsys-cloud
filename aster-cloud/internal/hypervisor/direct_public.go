package hypervisor

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
)

// DirectNetworkSHA256 pins the complete root network approval. Changing even
// bridge, filter, pool, DNS or approved SSH keys invalidates new activations.
func DirectNetworkSHA256(n Network) (string, error) {
	if !n.Enabled || !n.RequirePublicLease || n.Validate() != nil {
		return "", ErrUnsupported
	}
	raw, e := json.Marshal(n)
	if e != nil {
		return "", e
	}
	return nodeproto.Digest(raw), nil
}
func (m *Manager) approvedDirect(b nodeproto.DirectPublicBinding) error {
	sha, e := DirectNetworkSHA256(m.Config.Network)
	if e != nil || !b.ValidIdentity() || b.NodeID != m.Config.NodeID || b.ProfileSHA256 != sha || b.CIDR != m.Config.Network.CIDR || b.Gateway != m.Config.Network.Gateway {
		return ErrOwnership
	}
	hostIPs, e := m.directHostIPv4s()
	if e != nil {
		return e
	}
	for _, ip := range hostIPs {
		if ip == b.IPv4 {
			return errors.New("guest public IP is already assigned to the host")
		}
	}
	for _, ip := range m.Config.Network.Addresses {
		if ip == b.IPv4 {
			return nil
		}
	}
	return ErrOwnership
}
func directTaskMatches(i Instance, t nodeproto.NodeTask) bool {
	if t.Action == "public_adopt" {
		return i.Network.IsZero() && i.IPv4 == t.DirectPublic.IPv4 && i.MAC == t.DirectPublic.MAC && (i.DirectPublic.IsZero() || i.DirectPublicDetached && t.DirectPublic.Generation > i.DirectPublic.Generation || !i.DirectPublicDetached && i.DirectPublic == t.DirectPublic)
	}
	return i.DirectPublic == t.DirectPublic
}

// mutateDirect does not rewrite guest configuration. Adoption only pins the
// already configured exact primary IP/MAC while powered off. Detach persists a
// down link and leaves a tombstone preventing node/1 from reopening this guest.
func (m *Manager) mutateDirect(ctx context.Context, i Instance, t nodeproto.NodeTask) (Instance, error) {
	if t.Action == "public_adopt" {
		if e := m.approvedDirect(t.DirectPublic); e != nil {
			return i, e
		}
		if e := m.verifyNetwork(ctx); e != nil {
			return i, e
		}
	}
	if !i.Network.IsZero() || i.IPv4 != t.DirectPublic.IPv4 || i.MAC != t.DirectPublic.MAC {
		return i, ErrOwnership
	}
	if e := m.assertOwned(ctx, i); e != nil {
		return i, e
	}
	state, e := m.state(ctx, i.Domain)
	if e != nil || state != "shut off" {
		return i, errors.New("PUBLIC_PRIMARY_CHANGE_REQUIRES_SHUT_OFF")
	}
	for _, other := range m.Ledger.Instances() {
		if other.ID != i.ID && other.State != "deleted" && !other.DirectPublicDetached && (other.IPv4 == i.IPv4 || !other.DirectPublic.IsZero() && other.DirectPublic.LeaseID == t.DirectPublic.LeaseID) {
			return i, ErrConflict
		}
	}
	i.DirectPublic = t.DirectPublic
	i.DirectPublicDetached = t.Action == "public_detach"
	raw, e := m.domainXML(i)
	if e != nil {
		return i, e
	}
	path := filepath.Join(m.Config.StateDirectory, "direct-"+t.OperationID+".xml")
	if e = writeExclusive(path, raw); e != nil {
		return i, e
	}
	defer os.Remove(path)
	if _, e = m.virsh(ctx, "define", path); e != nil {
		return i, e
	}
	if e = m.assertOwned(ctx, i); e != nil {
		return i, e
	}
	state, e = m.state(ctx, i.Domain)
	if e != nil || state != "shut off" {
		return i, errors.New("PUBLIC_PRIMARY_READBACK_UNCONFIRMED")
	}
	i.State = "shut off"
	return i, nil
}

// bindDirectImportTask derives a target placement only from a verified signed
// source manifest. Address, lease, guest MAC and root network pin remain exact.
func bindDirectImportTask(t *nodeproto.TypedStorageTask, a nodeproto.StorageManifest) {
	if !a.DirectPublic.IsZero() {
		t.Protocol = nodeproto.StorageDirectProtocol
		t.DirectPublic = a.DirectPublic
		t.DirectPublic.NodeID = t.NodeID
		t.DirectPublic.Generation++
	}
}
func (m *Manager) defineDirectNetwork(ctx context.Context, i Instance, operationID string) error {
	raw, e := m.domainXML(i)
	if e != nil {
		return e
	}
	path := filepath.Join(m.Config.StateDirectory, "direct-"+operationID+".xml")
	if e = writeExclusive(path, raw); e != nil {
		return e
	}
	defer os.Remove(path)
	if _, e = m.virsh(ctx, "define", path); e != nil {
		return e
	}
	return m.assertOwned(ctx, i)
}

func (m *Manager) directHostIPv4s() ([]string, error) {
	if m.hostIPv4s != nil {
		return m.hostIPv4s()
	}
	interfaces, e := net.Interfaces()
	if e != nil {
		return nil, e
	}
	seen := map[string]bool{"127.0.0.1": true}
	for _, iface := range interfaces {
		addrs, e := iface.Addrs()
		if e != nil {
			return nil, e
		}
		for _, raw := range addrs {
			prefix, e := netip.ParsePrefix(raw.String())
			if e != nil {
				return nil, errors.New("host address inventory rejected")
			}
			a := prefix.Addr()
			if a.Is4() {
				seen[a.String()] = true
			}
		}
	}
	if host, _, e := net.SplitHostPort(m.Config.Listen); e == nil {
		if a, e := netip.ParseAddr(host); e == nil && a.Is4() && !a.IsUnspecified() {
			seen[a.String()] = true
		}
	}
	if len(seen) > 128 {
		return nil, errors.New("host IPv4 inventory exceeds protected interface budget")
	}
	ips := make([]string, 0, len(seen))
	for ip := range seen {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	return ips, nil
}

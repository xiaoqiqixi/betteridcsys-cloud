package hypervisor

import (
	"aster/cloud/internal/fabric"
	"aster/cloud/internal/nodeproto"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// OVSProfile is root configuration, never supplied by a tenant/task. The wire
// pins the canonical fabric config SHA, so reusing an ID cannot move old guests.
type OVSProfile struct {
	FabricConfig      string   `json:"fabric_config"`
	OverlayConfig     string   `json:"overlay_config,omitempty"`
	SSHAuthorizedKeys []string `json:"ssh_authorized_keys"`
}
type ovsGate interface {
	Activate(context.Context, fabric.ActivationIntent, func(context.Context) error, func(context.Context) error) (fabric.LiveVerification, error)
	Deactivate(context.Context, fabric.ActivationIntent, func(context.Context) error) (fabric.LiveVerification, error)
	Check(context.Context, fabric.ActivationIntent) (fabric.LiveVerification, error)
}

func profileDigest(c fabric.Config) string { raw, _ := json.Marshal(c); return nodeproto.Digest(raw) }
func (c Config) validateOVSProfiles() error {
	bridges, states := map[string]bool{}, map[string]bool{}
	if len(c.OVSProfiles) > 8 {
		return errors.New("too many OVS profiles")
	}
	for id, p := range c.OVSProfiles {
		if !nodeproto.ValidNodeID(id) || len(p.SSHAuthorizedKeys) == 0 {
			return ErrUnsupported
		}
		if validateSSHKeys(p.SSHAuthorizedKeys) != nil {
			return ErrUnsupported
		}
		f, err := fabric.LoadConfig(p.FabricConfig)
		if err != nil || f.NodeID != c.NodeID || bridges[f.Bridge] || states[f.StateDirectory] || f.Bridge == c.Network.Bridge {
			return ErrUnsupported
		}
		if p.OverlayConfig != "" {
			o, err := fabric.LoadOverlayConfig(p.OverlayConfig)
			if err != nil || o.Base != f {
				return ErrUnsupported
			}
		}
		for _, d := range []string{c.StateDirectory, c.StorageDirectory, c.Storage.Directory, c.Storage.InboxDirectory} {
			if d != "" && (d == f.StateDirectory || strings.HasPrefix(d, f.StateDirectory+"/") || strings.HasPrefix(f.StateDirectory, d+"/")) {
				return ErrUnsupported
			}
		}
		bridges[f.Bridge], states[f.StateDirectory] = true, true
	}
	return nil
}
func (m *Manager) approvedOVS(n nodeproto.NetworkBinding) (fabric.Config, OVSProfile, error) {
	p, ok := m.Config.OVSProfiles[n.ProfileID]
	if !ok {
		return fabric.Config{}, p, ErrUnsupported
	}
	load := m.loadOVSConfig
	if load == nil {
		load = fabric.LoadConfig
	}
	c, e := load(p.FabricConfig)
	if e != nil || !c.Validate() || c.NodeID != m.Config.NodeID || profileDigest(c) != n.ProfileSHA256 || c.Bridge == m.Config.Network.Bridge {
		return fabric.Config{}, p, ErrUnsupported
	}
	return c, p, nil
}
func (m *Manager) gateFor(n nodeproto.NetworkBinding) (ovsGate, error) {
	c, _, err := m.approvedOVS(n)
	if err != nil {
		return nil, err
	}
	if m.Config.OVSProfiles[n.ProfileID].OverlayConfig != "" {
		oc, og, err := m.approvedOverlay(n.ProfileID)
		if err != nil {
			return nil, err
		}
		gate, ok := og.(overlayLifecycleGate)
		if !ok {
			return nil, ErrUnsupported
		}
		return overlayLifecycleAdapter{oc, gate, n.Digest()}, nil
	}
	if m.ovsFactory != nil {
		return m.ovsFactory(c)
	}
	return fabric.NewExecutor(c, fabric.OSRunner{})
}
func (m *Manager) networkIntent(t nodeproto.NodeTask, sha string, active bool) (fabric.ActivationIntent, error) {
	intent := fabric.ActivationIntent{OperationID: t.OperationID, RequestSHA256: sha, InstanceID: t.InstanceID, VPCs: []fabric.VPC{}, Ports: []fabric.PortIntent{}}
	vpcs := map[string]fabric.VPC{}
	found := false
	for _, i := range m.Ledger.Instances() {
		n := i.Network
		if n.IsZero() || n.ProfileID != t.Network.ProfileID || i.State == "deleted" {
			continue
		}
		if n.ProfileSHA256 != t.Network.ProfileSHA256 || !n.ValidFor(nodeproto.NodeTask{NodeID: m.Config.NodeID, OwnerRef: i.OwnerRef, InstanceID: i.ID, Resources: i.Resources}) {
			return intent, ErrOwnership
		}
		enabled := i.State == "running"
		if i.ID == t.InstanceID {
			if n != t.Network {
				return intent, ErrOwnership
			}
			found = true
			enabled = active
		}
		v := fabric.VPC{ID: n.VPCID, OwnerRef: n.OwnerRef, CIDR: n.CIDR, VLANID: n.VLANID}
		if old, ok := vpcs[v.ID]; ok && old != v {
			return intent, ErrOwnership
		}
		vpcs[v.ID] = v
		intent.Ports = append(intent.Ports, fabric.PortIntent{InstanceID: i.ID, InterfaceID: n.InterfaceID, OwnerRef: n.OwnerRef, VPCID: n.VPCID, IPv4: n.IPv4, MAC: n.MAC, InboundMbps: n.InboundMbps, OutboundMbps: n.OutboundMbps, Enabled: enabled})
	}
	if !found {
		return intent, ErrOwnership
	}
	for _, v := range vpcs {
		intent.VPCs = append(intent.VPCs, v)
	}
	sort.Slice(intent.VPCs, func(i, j int) bool { return intent.VPCs[i].ID < intent.VPCs[j].ID })
	sort.Slice(intent.Ports, func(i, j int) bool { return intent.Ports[i].InstanceID < intent.Ports[j].InstanceID })
	return intent, nil
}

// No managed-save restore or autostart may substitute an unapproved NIC image.
func (m *Manager) ovsBootPolicy(ctx context.Context, i Instance) error {
	raw, e := m.virsh(ctx, "dominfo", i.Domain)
	if e != nil {
		return ErrOwnership
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		p := strings.SplitN(line, ":", 2)
		if len(p) == 2 {
			k := strings.TrimSpace(p[0])
			if _, ok := values[k]; ok {
				return ErrOwnership
			}
			values[k] = strings.TrimSpace(p[1])
		}
	}
	if values["Autostart"] != "disable" || values["Managed save"] != "no" {
		return ErrOwnership
	}
	raw, e = m.virsh(ctx, "dumpxml", i.Domain, "--inactive")
	if e != nil {
		return ErrOwnership
	}
	return m.assertOVSInactive(i, raw)
}
func (m *Manager) startOVS(ctx context.Context, i Instance, t nodeproto.NodeTask, sha string) error {
	g, e := m.gateFor(i.Network)
	if e != nil {
		return e
	}
	intent, e := m.networkIntent(t, sha, true)
	if e != nil {
		return e
	}
	if e = m.ovsBootPolicy(ctx, i); e != nil {
		return e
	}
	_, e = g.Activate(ctx, intent, func(ctx context.Context) error {
		if e := m.assertOwned(ctx, i); e != nil {
			return e
		}
		if s, e := m.state(ctx, i.Domain); e != nil || s != "shut off" {
			return ErrOwnership
		}
		if e := m.ovsBootPolicy(ctx, i); e != nil {
			return e
		}
		if _, e := m.virsh(ctx, "start", i.Domain, "--paused"); e != nil {
			return e
		}
		if s, e := m.state(ctx, i.Domain); e != nil || s != "paused" {
			return errors.New("paused state unconfirmed")
		}
		return m.assertOVSLink(ctx, i, "down")
	}, func(ctx context.Context) error {
		if e := m.assertOwned(ctx, i); e != nil {
			return e
		}
		if s, e := m.state(ctx, i.Domain); e != nil || s != "paused" {
			return ErrOwnership
		}
		if e := m.assertOVSLink(ctx, i, "down"); e != nil {
			return e
		}
		if _, e := m.virsh(ctx, "domif-setlink", i.Domain, i.MAC, "up"); e != nil {
			return e
		}
		if e := m.assertOVSLink(ctx, i, "up"); e != nil {
			return e
		}
		if _, e := m.virsh(ctx, "resume", i.Domain); e != nil {
			return e
		}
		if s, e := m.state(ctx, i.Domain); e != nil || s != "running" {
			return errors.New("running state unconfirmed")
		}
		return m.assertOwned(ctx, i)
	})
	// A failed release/quarantine can leave a running VM. This independent,
	// bounded safety fence never retries start/resume or claims success.
	if e != nil {
		m.fenceOVSGuest(i)
	}
	return e
}
func (m *Manager) checkOVS(ctx context.Context, i Instance, t nodeproto.NodeTask, sha string) (err error) {
	// A broken root profile, boot policy or observation is not proof that a
	// previously running guest is isolated. Cover every early return as well as
	// the fabric check itself; the independent fence re-verifies ownership.
	defer func() {
		if err != nil {
			m.fenceOVSGuest(i)
		}
	}()
	if e := m.ovsBootPolicy(ctx, i); e != nil {
		return e
	}
	if e := m.assertOVSLink(ctx, i, "up"); e != nil {
		return e
	}
	g, e := m.gateFor(i.Network)
	if e != nil {
		return e
	}
	intent, e := m.networkIntent(t, sha, true)
	if e != nil {
		return e
	}
	_, e = g.Check(ctx, intent)
	return e
}

// Only independently owned active guests may be fenced; no off-domain update
// (virsh would change persistent XML), no destructive stop and no implicit retry.
// Failure still means uncertain, never proof of isolation.
func (m *Manager) fenceOVSGuest(i Instance) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if m.assertOwned(ctx, i) != nil {
		return
	}
	state, err := m.state(ctx, i.Domain)
	if err != nil || state != "running" && state != "paused" {
		return
	}
	_, _ = m.virsh(ctx, "domif-setlink", i.Domain, i.MAC, "down")
	// Suspending is a separate fail-safe attempt even if link-down lost ACK.
	state, err = m.state(ctx, i.Domain)
	if err == nil && state == "running" {
		if m.assertOwned(ctx, i) == nil {
			_, _ = m.virsh(ctx, "suspend", i.Domain)
		}
	}
}

func (m *Manager) assertOVSLink(ctx context.Context, i Instance, want string) error {
	raw, e := m.virsh(ctx, "domif-getlink", i.Domain, i.MAC)
	// libvirt 8 domif-getlink/setlink default to the live active domain. There
	// is no --live option (only --config); callers require paused/running state.
	// virsh prints '<interface> <state>'; neither a missing nor an extra line is proof.
	fields := strings.Fields(string(raw))
	if e != nil || len(fields) != 2 || (fields[0] != i.MAC && fields[0] != fabric.TAPName(i.ID)) || fields[1] != want {
		return ErrOwnership
	}
	return nil
}
func (m *Manager) stopOVS(ctx context.Context, i Instance, t nodeproto.NodeTask, sha, command string) (err error) {
	// Deactivate may reject before invoking the stop callback (for example a
	// stale overlay pin or damaged head). Do not leave an owned guest live just
	// because its operation is now uncertain. Never retry shutdown/destroy.
	defer func() {
		if err != nil {
			m.fenceOVSGuest(i)
		}
	}()
	g, e := m.gateFor(i.Network)
	if e != nil {
		return e
	}
	intent, e := m.networkIntent(t, sha, false)
	if e != nil {
		return e
	}
	_, e = g.Deactivate(ctx, intent, func(ctx context.Context) error {
		if e := m.assertOwned(ctx, i); e != nil {
			return e
		}
		s, e := m.state(ctx, i.Domain)
		if e != nil {
			return e
		}
		if s == "shut off" {
			return nil
		}
		if s != "running" && !(s == "paused" && command == "destroy") {
			return ErrOwnership
		}
		if _, e = m.virsh(ctx, command, i.Domain); e != nil {
			return e
		}
		deadline := time.NewTimer(10 * time.Second)
		defer deadline.Stop()
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			s, e = m.state(ctx, i.Domain)
			if e == nil && s == "shut off" {
				return nil
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-deadline.C:
				return errors.New("stop unconfirmed")
			case <-tick.C:
			}
		}
	})
	return e
}
func (m *Manager) seedOVS(ctx context.Context, i Instance) error {
	_, p, e := m.approvedOVS(i.Network)
	if e != nil {
		return e
	}
	prefix := strings.Split(i.Network.CIDR, "/")[1]
	network := fmt.Sprintf("version: 2\nethernets:\n  aster0:\n    match:\n      macaddress: %q\n    set-name: aster0\n    dhcp4: false\n    dhcp6: false\n    accept-ra: false\n    link-local: []\n    addresses: [%q]\n", i.MAC, i.IPv4+"/"+prefix)
	if p.OverlayConfig != "" {
		o, _, err := m.approvedOverlay(i.Network.ProfileID)
		if err != nil {
			return err
		}
		network += fmt.Sprintf("    mtu: %d\n", o.GuestMTU)
		for _, route := range o.GuestNetworks {
			if route.LocalVPCID != i.Network.VPCID {
				continue
			}
			if route.OwnerRef != i.OwnerRef || route.CIDR != i.Network.CIDR || route.GatewayIPv4 == i.IPv4 {
				return ErrOwnership
			}
			if len(route.AllowedPrefixes) > 0 || route.AllowInternetEgress {
				network += "    routes:\n"
			}
			for _, prefix := range route.AllowedPrefixes {
				network += fmt.Sprintf("      - to: %q\n        via: %q\n", prefix, route.GatewayIPv4)
			}
			if route.AllowInternetEgress {
				network += fmt.Sprintf("      - to: %q\n        via: %q\n", "0.0.0.0/0", route.GatewayIPv4)
			}
			if len(route.DNSIPv4) > 0 {
				network += "    nameservers:\n      addresses:\n"
				for _, address := range route.DNSIPv4 {
					network += fmt.Sprintf("        - %q\n", address)
				}
			}
		}
	}
	return m.seedFiles(ctx, i, p.SSHAuthorizedKeys, network)
}

func (m *Manager) assertOVSDomain(i Instance, d domainXML, inactive bool) error {
	c, _, e := m.approvedOVS(i.Network)
	if e != nil {
		return e
	}
	if !i.Network.ValidFor(nodeproto.NodeTask{NodeID: m.Config.NodeID, OwnerRef: i.OwnerRef, InstanceID: i.ID, Resources: i.Resources}) || d.UUID != fabric.DomainID(i.ID) || d.Metadata.Instance.NetworkSHA256 != i.Network.Digest() || d.OnReboot != "destroy" || d.OnPoweroff != "destroy" || d.OnCrash != "preserve" || len(d.Devices.Interfaces) != 1 {
		return ErrOwnership
	}
	n := d.Devices.Interfaces[0]
	if m.Config.OVSProfiles[i.Network.ProfileID].OverlayConfig != "" {
		o, _, err := m.approvedOverlay(i.Network.ProfileID)
		if err != nil || n.MTU == nil && o.GuestMTU != 1500 || n.MTU != nil && n.MTU.Size != o.GuestMTU {
			return ErrOwnership
		}
	}
	if n.Type != "bridge" || n.MAC.Address != i.MAC || n.Source.Bridge != c.Bridge || n.Model.Type != "virtio" || n.Filter != nil || n.Port != nil || n.Target == nil || n.Target.Dev != fabric.TAPName(i.ID) || n.VirtualPort == nil || n.VirtualPort.Type != "openvswitch" || n.VirtualPort.Parameters.InterfaceID != i.Network.InterfaceID || n.Link == nil || (n.Link.State != "down" && n.Link.State != "up") || inactive && n.Link.State != "down" {
		return ErrOwnership
	}
	return nil
}
func (m *Manager) assertOVSInactive(i Instance, raw []byte) error {
	var d domainXML
	if xml.Unmarshal(raw, &d) != nil || d.Name != i.Domain || d.Metadata.Instance.InstanceID != i.ID || d.Metadata.Instance.OwnerRef != i.OwnerRef || d.Metadata.Instance.NodeID != m.Config.NodeID {
		return ErrOwnership
	}
	return m.assertOVSDomain(i, d, true)
}

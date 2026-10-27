package fabric

import (
	"aster/cloud/internal/overlayproto"
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func verifyOverlayUnderlay(c OverlayConfig) error {
	interfaces, e := net.Interfaces()
	if e != nil {
		return ErrUnavailable
	}
	found := false
	for _, i := range interfaces {
		addrs, e := i.Addrs()
		if e != nil {
			return ErrUnavailable
		}
		for _, raw := range addrs {
			p, e := netip.ParsePrefix(raw.String())
			if e == nil && p.Addr().String() == c.LocalIPv4 {
				if found || i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 || i.MTU < c.UnderlayMTU || i.Name == c.Base.Bridge {
					return ErrUnavailable
				}
				found = true
			}
		}
	}
	if !found {
		return ErrUnavailable
	}
	return nil
}
func (e *Executor) overlayBridge(ctx context.Context) (bool, error) {
	if _, err := e.run(ctx, Vsctl, "--timeout=3", "br-exists", e.Config.Bridge); err != nil {
		return false, err
	}
	raw, err := e.run(ctx, Ofctl, "--version")
	v := versionRE.FindSubmatch(raw)
	if err != nil || len(v) != 3 {
		return false, ErrUnavailable
	}
	major, _ := strconv.Atoi(string(v[1]))
	minor, _ := strconv.Atoi(string(v[2]))
	if major < 2 || major == 2 && minor < 17 {
		return false, ErrUnavailable
	}
	raw, err = e.run(ctx, Vsctl, "--timeout=3", "--format=json", "--columns=name,controller,fail_mode,external_ids,protocols", "list", "Bridge", e.Config.Bridge)
	if err != nil {
		return false, err
	}
	rows, err := ovsRows(raw, []string{"name", "controller", "fail_mode", "external_ids", "protocols"})
	if err != nil || len(rows) != 1 || rows[0][0] != e.Config.Bridge {
		return false, ErrUnavailable
	}
	r := rows[0]
	controllers, ce := ovsSet(r[1])
	mode, me := ovsSet(r[2])
	ids, ie := ovsMap(r[3])
	protocols, pe := ovsSet(r[4])
	has14 := false
	for _, p := range protocols {
		if p == "OpenFlow14" {
			has14 = true
		}
	}
	if ce != nil || me != nil || ie != nil || pe != nil || len(controllers) != 0 || len(mode) != 1 || mode[0] != "secure" || ids["aster-node-id"] != e.Config.NodeID || ids["aster-dedicated"] != "true" || !has14 {
		return false, ErrUnavailable
	}
	return true, nil
}

var ovsUUIDRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func ovsUUID(v any) (string, bool) {
	a, ok := v.([]any)
	if !ok || len(a) != 2 || a[0] != "uuid" {
		return "", false
	}
	s, ok := a[1].(string)
	return s, ok && ovsUUIDRE.MatchString(s)
}
func ovsInt(v any) (int, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, e := strconv.Atoi(string(n))
	return i, e == nil && strconv.Itoa(i) == string(n)
}
func overlayTunnelOptions(c OverlayConfig, p OverlayPeer) map[string]string {
	return map[string]string{"local_ip": c.LocalIPv4, "remote_ip": p.IPv4, "key": "flow", "dst_port": "4789", "df_default": "true", "csum": "true"}
}
func equalMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// probeOverlay checks the entire bridge, including inactive known members. A
// foreign port, VLAN configuration, port reuse or changed OVSDB UUID fences the
// operation instead of being adopted as another authorised endpoint.
func (e *Executor) probeOverlay(ctx context.Context, c OverlayConfig, s overlayproto.Snapshot, allowMissingTunnels bool) ([]overlayPort, bool, error) {
	return e.probeOverlayAdmitting(ctx, c, s, allowMissingTunnels, "")
}

// Only a newly bootstrapped, independently identity-proved target may lack our
// labels. Existing nonmatching labels are never overwritten or adopted.
func (e *Executor) probeOverlayAdmitting(ctx context.Context, c OverlayConfig, s overlayproto.Snapshot, allowMissingTunnels bool, admitID string) ([]overlayPort, bool, error) {
	owned, err := e.overlayBridge(ctx)
	if err != nil {
		return nil, owned, err
	}
	if e.overlayUnderlay == nil || e.overlayUnderlay(c) != nil {
		return nil, owned, ErrUnavailable
	}
	raw, err := e.run(ctx, Vsctl, "--timeout=3", "list-ifaces", e.Config.Bridge)
	if err != nil {
		return nil, owned, err
	}
	names := map[string]bool{}
	for _, n := range strings.Fields(string(raw)) {
		if !nameRE.MatchString(n) || names[n] {
			return nil, owned, ErrUnavailable
		}
		names[n] = true
	}
	if len(names) > 191 {
		return nil, owned, ErrUnavailable
	}
	members := map[string]overlayproto.Member{}
	gateways := map[string]overlayproto.Gateway{}
	peers := map[string]OverlayPeer{}
	required := map[string]bool{}
	for _, m := range s.Members {
		if m.NodeID == c.Base.NodeID {
			members[TAPName(m.InstanceID)] = m
		}
	}
	for _, g := range c.Gateways {
		if g.NodeID == c.Base.NodeID {
			gateways[TAPName(g.InstanceID)] = g
			required[TAPName(g.InstanceID)] = true
		}
	}
	for _, pin := range s.Profiles {
		if pin.NodeID != c.Base.NodeID {
			for _, p := range c.Peers {
				if p.NodeID == pin.NodeID {
					n := overlayTunnelName(c.Base.NodeID, p.NodeID)
					peers[n] = p
					if !allowMissingTunnels {
						required[n] = true
					}
				}
			}
		}
	}
	raw, err = e.run(ctx, Vsctl, "--timeout=3", "--format=json", "--columns=_uuid,name,ofport,type,external_ids,options,mtu", "list", "Interface")
	if err != nil {
		return nil, owned, err
	}
	rows, err := ovsRows(raw, []string{"_uuid", "name", "ofport", "type", "external_ids", "options", "mtu"})
	if err != nil {
		return nil, owned, err
	}
	ports := []overlayPort{}
	seen := map[string]bool{}
	ofports := map[int]bool{}
	uuids := map[string]bool{}
	for _, r := range rows {
		name, ok := r[1].(string)
		if !ok {
			return nil, owned, ErrUnavailable
		}
		if !names[name] {
			// OVS tunnel lookup is host-wide, not keyed by our Bridge or cluster.
			// Another bridge with the same fixed/wildcard ingress tuple cannot be
			// assumed separate merely because its controller chose another VNI.
			if r[3] == "vxlan" {
				opts, err := ovsMap(r[5])
				if err != nil {
					return nil, owned, ErrUnavailable
				}
				port := opts["dst_port"]
				if port == "" {
					port = "4789"
				}
				local, remote := opts["local_ip"], opts["remote_ip"]
				portNumber, portErr := strconv.Atoi(port)
				if portErr != nil || portNumber < 1 || portNumber > 65535 {
					return nil, owned, ErrUnavailable
				}
				if portNumber == 4789 && (local == "" || local == "0.0.0.0" || local == "flow" || local == c.LocalIPv4) {
					for _, peer := range peers {
						if remote == "" || remote == "0.0.0.0" || remote == "flow" || remote == peer.IPv4 {
							return nil, owned, ErrUnavailable
						}
					}
				}
			}
			continue
		}
		uuid, uok := ovsUUID(r[0])
		ofport, pok := ovsInt(r[2])
		ids, ie := ovsMap(r[4])
		opts, oe := ovsMap(r[5])
		if !uok || !pok || ofport < 1 || ofport > 32767 || ofports[ofport] || uuids[uuid] || seen[name] || ie != nil || oe != nil {
			return nil, owned, ErrUnavailable
		}
		seen[name] = true
		ofports[ofport] = true
		uuids[uuid] = true
		o := overlayPort{Name: name, UUID: uuid, OFPort: ofport}
		if p, ok := peers[name]; ok {
			if r[3] != "vxlan" || !equalMap(opts, overlayTunnelOptions(c, p)) || !equalMap(ids, map[string]string{"aster-node-id": c.Base.NodeID, "aster-overlay-peer": p.NodeID, "aster-interface-id": overlayTunnelID(c.Base.NodeID, p.NodeID)}) {
				return nil, owned, ErrUnavailable
			}
			o.Kind = "tunnel"
			o.Identity = p.NodeID
		} else {
			gateway := gateways[name]
			natProfile, isNAT := natGatewayProfile(c, gateway.InstanceID)
			if r[3] != "" && r[3] != "system" || len(opts) != 0 || (!isNAT && e.tap(name) != nil) {
				return nil, owned, ErrUnavailable
			}
			mtu, mok := ovsInt(r[6])
			if !mok || mtu != c.GuestMTU {
				return nil, owned, ErrUnavailable
			}
			if m, ok := members[name]; ok {
				if ids["iface-id"] != m.InterfaceID || ids["attached-mac"] != m.MAC || ids["vm-id"] != DomainID(m.InstanceID) || ids["iface-status"] != "active" {
					return nil, owned, ErrUnavailable
				}
				labels := map[string]string{"aster-node-id": c.Base.NodeID, "aster-owner": m.OwnerRef, "aster-instance": m.InstanceID, "aster-vpc": m.LocalVPCID}
				for key, want := range labels {
					actual, present := ids[key]
					if actual != want && !(m.InstanceID == admitID && !present) {
						return nil, owned, ErrUnavailable
					}
				}

				o.Kind = "member"
				o.Identity = m.InstanceID
			} else if g, ok := gateways[name]; ok {
				if isNAT {
					want := map[string]string{"aster-node-id": c.Base.NodeID, "aster-owner": g.OwnerRef, "aster-gateway-vpc": g.VPCID, "aster-nat-profile": natProfile.ID, "aster-interface-id": g.InterfaceID, "aster-gateway-mac": g.MAC}
					if !equalMap(ids, want) || e.probeNAT(ctx, c, s, natProfile) != nil {
						return nil, owned, ErrUnavailable
					}
				} else if ids["iface-id"] != g.InterfaceID || ids["attached-mac"] != g.MAC || ids["vm-id"] != DomainID(g.InstanceID) || ids["iface-status"] != "active" || ids["aster-node-id"] != c.Base.NodeID || ids["aster-owner"] != g.OwnerRef || ids["aster-gateway-vpc"] != g.VPCID {
					return nil, owned, ErrUnavailable
				}
				o.Kind = "gateway"
				o.Identity = g.InstanceID
			} else {
				return nil, owned, ErrUnavailable
			}
		}
		ports = append(ports, o)
	}
	if len(seen) != len(names) {
		return nil, owned, ErrUnavailable
	}
	for n := range required {
		if !seen[n] {
			return nil, owned, ErrUnavailable
		}
	}
	// OVS Port-level access/trunk/bond changes must not reinterpret the compiled
	// untagged interface matches. One Port must reference exactly that Interface.
	raw, err = e.run(ctx, Vsctl, "--timeout=3", "--format=json", "--columns=name,interfaces,tag,trunks,vlan_mode", "list", "Port")
	if err != nil {
		return nil, owned, err
	}
	rows, err = ovsRows(raw, []string{"name", "interfaces", "tag", "trunks", "vlan_mode"})
	if err != nil {
		return nil, owned, err
	}
	portSeen := map[string]bool{}
	byName := map[string]overlayPort{}
	for _, p := range ports {
		byName[p.Name] = p
	}
	for _, r := range rows {
		name, ok := r[0].(string)
		if !ok {
			return nil, owned, ErrUnavailable
		}
		p, ok := byName[name]
		if !ok {
			continue
		}
		ifs, ie := ovsSet(r[1])
		tag, te := ovsSet(r[2])
		trunks, tre := ovsSet(r[3])
		mode, me := ovsSet(r[4])
		if portSeen[name] || ie != nil || te != nil || tre != nil || me != nil || len(ifs) != 1 || len(tag) != 0 || len(trunks) != 0 || len(mode) != 0 {
			return nil, owned, ErrUnavailable
		}
		uuid, ok := ovsUUID(ifs[0])
		if !ok || uuid != p.UUID {
			return nil, owned, ErrUnavailable
		}
		portSeen[name] = true
	}
	if len(portSeen) != len(ports) {
		return nil, owned, ErrUnavailable
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i].Name < ports[j].Name })
	return ports, owned, nil
}
func (e *Executor) createOverlayTunnels(ctx context.Context, c OverlayConfig, s overlayproto.Snapshot, observed []overlayPort) error {
	seen := map[string]bool{}
	for _, p := range observed {
		seen[p.Name] = true
	}
	for _, pin := range s.Profiles {
		if pin.NodeID == c.Base.NodeID {
			continue
		}
		for _, peer := range c.Peers {
			if peer.NodeID != pin.NodeID {
				continue
			}
			name := overlayTunnelName(c.Base.NodeID, peer.NodeID)
			if seen[name] {
				continue
			}
			args := []string{"--timeout=3", "add-port", c.Base.Bridge, name, "--", "set", "Interface", name, "type=vxlan", "options:local_ip=" + c.LocalIPv4, "options:remote_ip=" + peer.IPv4, "options:key=flow", "options:dst_port=4789", "options:df_default=true", "options:csum=true", "external_ids:aster-node-id=" + c.Base.NodeID, "external_ids:aster-overlay-peer=" + peer.NodeID, "external_ids:aster-interface-id=" + overlayTunnelID(c.Base.NodeID, peer.NodeID)}
			if _, err := e.run(ctx, Vsctl, args...); err != nil {
				return err
			}
		}
	}
	return nil
}

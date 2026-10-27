package fabric

import (
	"aster/cloud/internal/overlayproto"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type overlayPort struct {
	Name     string `json:"name"`
	UUID     string `json:"uuid"`
	OFPort   int    `json:"ofport"`
	Kind     string `json:"kind"`
	Identity string `json:"identity"`
}
type overlayPlan struct {
	Flows  []string
	Meters []Meter
}

// compileOverlay never learns/floods an address. Remote ingress carries an
// internal bit, so a peer cannot turn this node into an overlay transit router.
// Only local ports carry local policing; no remote enforcement is inferred.
func compileOverlay(c OverlayConfig, s overlayproto.Snapshot, ports []overlayPort) (overlayPlan, error) {
	var p overlayPlan
	_, s, _, e := validateOverlayApproval(c, s)
	if e != nil {
		return p, e
	}
	p.Flows = append(isolationFlows(), "cookie="+cookie+",table=0,priority=500,vlan_tci=0x1000/0x1000 actions=drop")
	byName := map[string]overlayPort{}
	used := map[int]bool{}
	for _, o := range ports {
		if o.OFPort < 1 || o.OFPort > 32767 || used[o.OFPort] || byName[o.Name].Name != "" {
			return overlayPlan{}, ErrInvalid
		}
		used[o.OFPort] = true
		byName[o.Name] = o
	}
	vpcs := map[string]overlayproto.VPC{}
	for _, v := range s.VPCs {
		vpcs[v.ID] = v
	}
	peers := map[string]OverlayPeer{}
	for _, v := range c.Peers {
		peers[v.NodeID] = v
	}
	incoming := func(node, id, mac string, vni int) (string, string, bool) {
		if node == c.Base.NodeID {
			o, ok := byName[TAPName(id)]
			if !ok {
				return "", "", false
			}
			return fmt.Sprintf("cookie=%s,table=0,priority=200,in_port=%d,dl_vlan=0xffff,dl_src=%s,", cookie, o.OFPort, mac), fmt.Sprintf("write_metadata:0x%x/0x1ffffff,goto_table:10", vni), true
		}
		peer, ok := peers[node]
		if !ok {
			return "", "", false
		}
		o, ok := byName[overlayTunnelName(c.Base.NodeID, node)]
		if !ok {
			return "", "", false
		}
		return fmt.Sprintf("cookie=%s,table=0,priority=200,in_port=%d,tun_src=%s,tun_dst=%s,tun_id=0x%x,dl_vlan=0xffff,dl_src=%s,", cookie, o.OFPort, peer.IPv4, c.LocalIPv4, vni, mac), fmt.Sprintf("write_metadata:0x%x/0x1ffffff,goto_table:10", vni|1<<24), true
	}
	outgoing := func(node, id string, vni int) (string, string, bool) {
		if node == c.Base.NodeID {
			o, ok := byName[TAPName(id)]
			if !ok {
				return "", "", false
			}
			return fmt.Sprintf("cookie=%s,table=10,priority=200,metadata=0x%x/0xffffff,", cookie, vni), fmt.Sprintf("output:%d", o.OFPort), true
		}
		o, ok := byName[overlayTunnelName(c.Base.NodeID, node)]
		if !ok {
			return "", "", false
		}
		return fmt.Sprintf("cookie=%s,table=10,priority=200,metadata=0x%x/0x1ffffff,", cookie, vni), fmt.Sprintf("set_tunnel:0x%x,output:%d", vni, o.OFPort), true
	}
	appendARPIn := func(src, ip, mac, act string) {
		for _, op := range []int{1, 2} {
			p.Flows = append(p.Flows, src+fmt.Sprintf("arp,arp_op=%d,arp_sha=%s,arp_spa=%s actions=%s", op, mac, ip, act))
		}
	}
	appendARPOut := func(dst, ip, mac, act string) {
		for _, dm := range []string{"ff:ff:ff:ff:ff:ff", mac} {
			p.Flows = append(p.Flows, dst+"arp,arp_op=1,arp_tpa="+ip+",dl_dst="+dm+" actions="+act)
		}
		p.Flows = append(p.Flows, dst+"arp,arp_op=2,arp_tpa="+ip+",arp_tha="+mac+",dl_dst="+mac+" actions="+act)
	}
	for _, m := range s.Members {
		if !m.Enabled {
			continue
		}
		v := vpcs[m.VPCID]
		src, act, ok := incoming(m.NodeID, m.InstanceID, m.MAC, v.VNI)
		if ok {
			if m.NodeID == c.Base.NodeID {
				o := byName[TAPName(m.InstanceID)]
				in, out := o.OFPort*2, o.OFPort*2+1
				p.Meters = append(p.Meters, Meter{in, m.InboundMbps * 1000}, Meter{out, m.OutboundMbps * 1000})
				act = fmt.Sprintf("meter:%d,", out) + act
			}
			p.Flows = append(p.Flows, src+"ip,nw_src="+m.IPv4+" actions="+act)
			appendARPIn(src, m.IPv4, m.MAC, act)
		}
		dst, act, ok := outgoing(m.NodeID, m.InstanceID, v.VNI)
		if ok {
			if m.NodeID == c.Base.NodeID {
				act = fmt.Sprintf("meter:%d,", byName[TAPName(m.InstanceID)].OFPort*2) + act
			}
			p.Flows = append(p.Flows, dst+"ip,nw_dst="+m.IPv4+",dl_dst="+m.MAC+" actions="+act)
			appendARPOut(dst, m.IPv4, m.MAC, act)
		}
	}
	for _, g := range s.Gateways {
		v := vpcs[g.VPCID]
		internet := internetGatewayEnabled(s, g)
		src, act, ok := incoming(g.NodeID, g.InstanceID, g.MAC, v.VNI)
		if ok {
			p.Flows = append(p.Flows, src+"ip,nw_src="+g.IPv4+" actions="+act)
			for _, prefix := range g.AllowedPrefixes {
				p.Flows = append(p.Flows, src+"ip,nw_src="+prefix+" actions="+act)
			}
			if internet {
				for _, blocked := range internetBlockedCIDRs(c, s) {
					p.Flows = append(p.Flows, strings.Replace(src, "priority=200,", "priority=195,", 1)+"ip,nw_src="+blocked+" actions=drop")
				}
				p.Flows = append(p.Flows, strings.Replace(src, "priority=200,", "priority=190,", 1)+"ip actions="+act)
			}
			appendARPIn(src, g.IPv4, g.MAC, act)
		}
		dst, act, ok := outgoing(g.NodeID, g.InstanceID, v.VNI)
		if ok {
			p.Flows = append(p.Flows, dst+"ip,nw_dst="+g.IPv4+",dl_dst="+g.MAC+" actions="+act)
			for _, prefix := range g.AllowedPrefixes {
				p.Flows = append(p.Flows, dst+"ip,nw_dst="+prefix+",dl_dst="+g.MAC+" actions="+act)
			}
			if internet {
				for _, blocked := range internetBlockedCIDRs(c, s) {
					p.Flows = append(p.Flows, strings.Replace(dst, "priority=200,", "priority=195,", 1)+"ip,nw_dst="+blocked+",dl_dst="+g.MAC+" actions=drop")
				}
				p.Flows = append(p.Flows, strings.Replace(dst, "priority=200,", "priority=190,", 1)+"ip,dl_dst="+g.MAC+" actions="+act)
			}
			appendARPOut(dst, g.IPv4, g.MAC, act)
		}
	}
	sort.Strings(p.Flows)
	sort.Slice(p.Meters, func(i, j int) bool { return p.Meters[i].ID < p.Meters[j].ID })
	return p, nil
}
func sameOverlayPorts(a, b []overlayPort) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

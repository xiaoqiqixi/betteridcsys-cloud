package fabric

import (
	"aster/cloud/internal/overlayproto"
	"sort"
)

// internetBlockedCIDRs is shared by the namespace firewall and the overlay's
// lower-priority Internet path. Explicit, root-approved routes remain separate.
// In particular a public management/underlay address is never made reachable by
// merely turning on Internet egress. Namespace uplink addresses are also not
// guest destinations, even if they happen to be globally routable.
func internetBlockedCIDRs(c OverlayConfig, s overlayproto.Snapshot) []string {
	blocked := append(overlayproto.InternetReservedCIDRs(), c.ProtectedCIDRs...)
	blocked = append(blocked, c.LocalIPv4+"/32")
	for _, p := range c.Peers {
		blocked = append(blocked, p.IPv4+"/32")
	}
	for _, v := range s.VPCs {
		blocked = append(blocked, v.CIDR)
	}
	// Explicit selected addresses are visible even on non-gateway participants;
	// they must not become public fallback destinations/sources on other nodes.
	for _, policy := range s.NATPolicies {
		if policy.PublicIPv4 != "" {
			blocked = append(blocked, policy.PublicIPv4+"/32")
		}
	}
	for _, f := range s.FloatingIPs {
		blocked = append(blocked, f.PublicIPv4+"/32")
	}
	for _, p := range c.NATProfiles {
		blocked = append(blocked, p.UplinkGatewayIPv4+"/32")
		for _, ip := range natProfilePublicIPv4s(p) {
			blocked = append(blocked, ip+"/32")
		}
	}
	sort.Strings(blocked)
	out := make([]string, 0, len(blocked))
	for _, p := range blocked {
		if len(out) == 0 || out[len(out)-1] != p {
			out = append(out, p)
		}
	}
	return out
}

func internetGatewayEnabled(s overlayproto.Snapshot, g overlayproto.Gateway) bool {
	for _, f := range s.FloatingIPs {
		if f.GatewayInstanceID == g.InstanceID && f.NodeID == g.NodeID && f.VPCID == g.VPCID {
			return true
		}
	}
	for _, p := range s.NATPolicies {
		if p.GatewayInstanceID == g.InstanceID && p.NodeID == g.NodeID && p.VPCID == g.VPCID && p.InternetEgressEnabled && p.SNATEnabled {
			return true
		}
	}
	return false
}

func compileInternetNAT(c OverlayConfig, s overlayproto.Snapshot, root NATProfile, policy overlayproto.NATPolicy, add func(string, ...any)) []nftObject {
	chains := []nftObject{}
	for _, name := range []string{"internet_out", "internet_in", "internet_snat"} {
		chains = append(chains, nftObject{"chain": nftObject{"family": "inet", "table": natTable, "name": name}})
	}
	// The shared deny lists avoid multiplying protected ranges by the number of
	// members. They run only after legacy explicit-prefix and DNAT rules.
	for _, blocked := range internetBlockedCIDRs(c, s) {
		for _, chain := range []string{"internet_out", "internet_snat"} {
			add(chain, match(payload("ip", "daddr"), prefixExpr(blocked)), nftObject{"drop": nil})
		}
		add("internet_in", match(payload("ip", "saddr"), prefixExpr(blocked)), nftObject{"drop": nil})
	}
	accept := nftObject{"accept": nil}
	// Only TCP/UDP and ICMP echo may initiate an Internet flow. Responses must
	// belong to an established, source-NATed flow; related ICMP errors are limited
	// to destination-unreachable (including PMTU), time-exceeded and parameter-
	// problem. No blanket established/related rule permits unsolicited ingress.
	for _, m := range s.Members {
		if !m.Enabled || m.VPCID != policy.VPCID {
			continue
		}
		source := match(payload("ip", "saddr"), m.IPv4)
		dest := match(payload("ip", "daddr"), m.IPv4)
		for _, proto := range []int{6, 17} {
			add("internet_out", source, match(meta("l4proto"), proto), bitmatch(ct("state"), []int{2, 8}), accept)
			add("internet_in", dest, match(meta("l4proto"), proto), bitmatch(ct("state"), 2), bitmatch(ct("status"), 16), accept)
		}
		// The named ICMP payload carries the L4 protocol dependency. nft 1.0.2
		// and 1.0.9 remove a redundant meta-l4proto match when listing it. Retain
		// the protocol-specific payload, not a readback exception for that guard.
		add("internet_out", source, match(payload("icmp", "type"), 8), bitmatch(ct("state"), []int{2, 8}), accept)
		add("internet_in", dest, match(payload("icmp", "type"), 0), bitmatch(ct("state"), 2), bitmatch(ct("status"), 16), accept)
		for _, kind := range []int{3, 11, 12} {
			add("internet_in", dest, match(payload("icmp", "type"), kind), bitmatch(ct("state"), 4), accept)
		}
		add("internet_snat", source, nftObject{"snat": nftObject{"addr": natPolicyPublicIPv4(root, policy), "family": "ip"}})
	}
	for _, v := range []struct{ chain, in, out, target string }{{"forward", root.InsideInterface, root.OutsideInterface, "internet_out"}, {"forward", root.OutsideInterface, root.InsideInterface, "internet_in"}, {"postrouting", root.InsideInterface, root.OutsideInterface, "internet_snat"}} {
		add(v.chain, match(meta("iifname"), v.in), match(meta("oifname"), v.out), nftObject{"jump": nftObject{"target": v.target}})
	}
	return chains
}

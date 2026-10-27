package fabric

import "aster/cloud/internal/overlayproto"

// Whole-address NAT is independently approved and exclusive; it is not a port
// forwarding expansion and never makes the guest claim a public address.
// These chains precede shared NAT so a target's assigned source cannot be
// replaced by the VPC default. The original compiler is byte-identical with no
// floating intent. Protocols other than TCP/UDP/ICMP remain default denied.
func compileFloatingNAT(c OverlayConfig, s overlayproto.Snapshot, root NATProfile) ([]nftObject, error) {
	mappings := []overlayproto.FloatingIP{}
	for _, f := range s.FloatingIPs {
		if f.NodeID == c.Base.NodeID && f.ProfileID == root.ID {
			mappings = append(mappings, f)
		}
	}
	if len(mappings) == 0 {
		return nil, nil
	}
	if !root.AllowFloatingIP || !root.AllowInternetEgress {
		return nil, ErrConflict
	}
	objects := []nftObject{}
	for _, name := range []string{"floating_in", "floating_out"} {
		objects = append(objects, nftObject{"chain": nftObject{"family": "inet", "table": natTable, "name": name}})
	}
	add := func(chain string, expr ...any) {
		objects = append(objects, nftObject{"rule": nftObject{"family": "inet", "table": natTable, "chain": chain, "expr": expr}})
	}
	accept := nftObject{"accept": nil}
	drop := nftObject{"drop": nil}
	// Explicit routes are a separate root grant and retain precedence over
	// the generic public fallback deny list, just as in the legacy compiler.
	for _, f := range mappings {
		for _, g := range s.Gateways {
			if g.InstanceID == f.GatewayInstanceID {
				for _, prefix := range g.AllowedPrefixes {
					add("floating_out", match(payload("ip", "saddr"), f.TargetIPv4), match(payload("ip", "daddr"), prefixExpr(prefix)), accept)
					add("floating_in", match(payload("ip", "daddr"), f.TargetIPv4), match(payload("ip", "saddr"), prefixExpr(prefix)), bitmatch(ct("state"), 2), bitmatch(ct("status"), 16), accept)
				}
			}
		}
	}
	for _, blocked := range internetBlockedCIDRs(c, s) {
		add("floating_out", match(payload("ip", "daddr"), prefixExpr(blocked)), drop)
		add("floating_in", match(payload("ip", "saddr"), prefixExpr(blocked)), drop)
	}
	for _, f := range mappings {
		if !natPublicIPv4Approved(root, f.PublicIPv4) {
			return nil, ErrConflict
		}
		if f.Ingress != nil {
			if _, e := overlayproto.CanonicalPublicIngress(*f.Ingress); e != nil || f.Ingress.InstanceID != f.InstanceID || f.Ingress.OwnerRef != f.OwnerRef || !overlayproto.ValidSHA(f.Ingress.SHA256) {
				return nil, ErrConflict
			}
		}
		source, dest := match(payload("ip", "saddr"), f.TargetIPv4), match(payload("ip", "daddr"), f.TargetIPv4)
		add("prerouting", match(meta("iifname"), root.OutsideInterface), match(payload("ip", "daddr"), f.PublicIPv4), nftObject{"dnat": nftObject{"addr": f.TargetIPv4, "family": "ip"}})
		// Every incoming initiation must have matched this exact public destination;
		// a peer route to the target's private address grants no access.
		for _, proto := range []int{6, 17} {
			if f.Ingress == nil { // Original immutable legacy behavior only.
				add("floating_in", dest, match(meta("l4proto"), proto), bitmatch(ct("status"), 32), bitmatch(ct("state"), []int{2, 8}), accept)
			}
			add("floating_in", dest, match(meta("l4proto"), proto), bitmatch(ct("status"), 16), bitmatch(ct("state"), 2), accept)
			add("floating_out", source, match(meta("l4proto"), proto), bitmatch(ct("state"), []int{2, 8}), accept)
		}
		if f.Ingress == nil {
			add("floating_in", dest, match(payload("icmp", "type"), 8), bitmatch(ct("status"), 32), bitmatch(ct("state"), []int{2, 8}), accept)
		} else {
			for _, rule := range f.Ingress.Rules {
				expr := []any{dest, match(payload("ip", "saddr"), prefixExpr(rule.SourceCIDR))}
				if rule.Protocol == "icmp" {
					expr = append(expr, match(payload("icmp", "type"), 8))
				} else {
					var port any = rule.PortStart
					if rule.PortEnd != rule.PortStart {
						port = nftObject{"range": []int{rule.PortStart, rule.PortEnd}}
					}
					expr = append(expr, match(payload(rule.Protocol, "dport"), port))
				}
				expr = append(expr, bitmatch(ct("status"), 32), bitmatch(ct("state"), []int{2, 8}), accept)
				add("floating_in", expr...)
			}
		}
		add("floating_in", dest, match(payload("icmp", "type"), 0), bitmatch(ct("status"), 16), bitmatch(ct("state"), 2), accept)
		add("floating_out", source, match(payload("icmp", "type"), 8), bitmatch(ct("state"), []int{2, 8}), accept)
		add("floating_out", source, match(payload("icmp", "type"), 0), bitmatch(ct("status"), 32), bitmatch(ct("state"), 2), accept)
		for _, kind := range []int{3, 11, 12} {
			add("floating_in", dest, match(payload("icmp", "type"), kind), bitmatch(ct("state"), 4), accept)
			if f.Ingress != nil {
				add("floating_out", source, match(payload("icmp", "type"), kind), bitmatch(ct("state"), 4), bitmatch(ct("status"), 32), accept)
			}
		}
		if f.Ingress != nil {
			// Returning to the shared NAT rules could otherwise accept a denied
			// packet on a shared DNAT port for the same private target.
			add("floating_in", dest, drop)
		}
		add("forward", match(meta("iifname"), root.InsideInterface), match(meta("oifname"), root.OutsideInterface), source, nftObject{"jump": nftObject{"target": "floating_out"}})
		if f.Ingress == nil {
			add("forward", match(meta("iifname"), root.OutsideInterface), match(meta("oifname"), root.InsideInterface), dest, nftObject{"jump": nftObject{"target": "floating_in"}})
		} else {
			// Bind ingress filtering to this exact public destination, not a
			// different shared-NAT forwarding to the same private instance.
			// Ubuntu22/24 nft infers the tuple's IPv4 family from the preceding
			// ip daddr match and omits the redundant family in its JSON readback.
			// Emit that native shape, retaining the original direction and exact
			// public destination. Never erase a tuple guard in normalization.
			original := nftObject{"ct": nftObject{"key": "daddr", "dir": "original"}}
			add("forward", match(meta("iifname"), root.OutsideInterface), match(meta("oifname"), root.InsideInterface), dest, match(original, f.PublicIPv4), nftObject{"jump": nftObject{"target": "floating_in"}})
			// Public ingress default deny must not disable legitimate replies to
			// this instance's independently approved outbound SNAT connections.
			add("forward", match(meta("iifname"), root.OutsideInterface), match(meta("oifname"), root.InsideInterface), dest, bitmatch(ct("status"), 16), nftObject{"jump": nftObject{"target": "floating_in"}})
		}
		add("postrouting", match(meta("iifname"), root.InsideInterface), match(meta("oifname"), root.OutsideInterface), source, nftObject{"snat": nftObject{"addr": f.PublicIPv4, "family": "ip"}})
	}
	return objects, nil
}

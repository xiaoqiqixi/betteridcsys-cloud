package fabric

import (
	"aster/cloud/internal/overlayproto"
	"encoding/json"
	"net/netip"
	"sort"
)

type nftObject = map[string]any

const natTable = "aster_nat"

func meta(k string) any { return nftObject{"meta": nftObject{"key": k}} }
func payload(proto, key string) any {
	return nftObject{"payload": nftObject{"protocol": proto, "field": key}}
}
func ct(k string) any { return nftObject{"ct": nftObject{"key": k}} }
func bitmatch(left, right any) nftObject {
	return nftObject{"match": nftObject{"op": "in", "left": left, "right": right}}
}
func match(left, right any) nftObject {
	return nftObject{"match": nftObject{"op": "==", "left": left, "right": right}}
}
func prefixExpr(raw string) any {
	p, _ := netip.ParsePrefix(raw)
	// nft's canonical JSON represents a /32 as its exact address. Generate the
	// same expression, rather than erasing or rewriting live address matches in
	// normalizeNFT (which must remain a strict security readback comparison).
	if p.Bits() == 32 {
		return p.Addr().String()
	}
	return nftObject{"prefix": nftObject{"addr": p.Addr().String(), "len": p.Bits()}}
}
func compileNAT(c OverlayConfig, s overlayproto.Snapshot, root NATProfile, isolated bool) ([]nftObject, error) {
	if _, _, _, err := validateOverlayApproval(c, s); err != nil {
		return nil, err
	}
	objects := []nftObject{{"table": nftObject{"family": "inet", "name": natTable}}}
	for _, v := range []struct {
		name, kind, hook string
		priority         int
	}{{"input", "filter", "input", 0}, {"output", "filter", "output", 0}, {"forward", "filter", "forward", 0}, {"prerouting", "nat", "prerouting", -100}, {"postrouting", "nat", "postrouting", 100}} {
		policy := "drop"
		if v.kind == "nat" {
			policy = "accept"
		}
		objects = append(objects, nftObject{"chain": nftObject{"family": "inet", "table": natTable, "name": v.name, "type": v.kind, "hook": v.hook, "prio": v.priority, "policy": policy}})
	}
	add := func(chain string, expr ...any) {
		objects = append(objects, nftObject{"rule": nftObject{"family": "inet", "table": natTable, "chain": chain, "expr": expr}})
	}
	if isolated {
		return objects, nil
	}
	var policy *overlayproto.NATPolicy
	for i := range s.NATPolicies {
		p := &s.NATPolicies[i]
		if p.NodeID == c.Base.NodeID && p.ProfileID == root.ID {
			policy = p
		}
	}
	// Independent floating mappings execute even without a shared NAT policy.
	floating, err := compileFloatingNAT(c, s, root)
	if err != nil {
		return nil, err
	}
	objects = append(objects, floating...)
	if policy == nil {
		raw, _ := json.Marshal(objects)
		if len(raw) > 512<<10 {
			return nil, ErrInvalid
		}
		return objects, nil
	}
	members := map[string]overlayproto.Member{}
	for _, m := range s.Members {
		members[m.InstanceID] = m
	}
	var gateway overlayproto.Gateway
	for _, g := range s.Gateways {
		if g.InstanceID == root.GatewayInstanceID {
			gateway = g
		}
	}
	accept := nftObject{"accept": nil}
	directions := func(in, out, source, dest string) []any {
		return []any{match(meta("iifname"), in), match(meta("oifname"), out), match(payload("ip", "saddr"), source), match(payload("ip", "daddr"), prefixExpr(dest))}
	}
	// Linux nf_conntrack UAPI: ESTABLISHED bit=2, IPS_DST_NAT bit=32.
	// nft -j -n emits these numeric bitmasks; compare them exactly, not by
	// removing the conntrack guard during normalization.
	established := bitmatch(ct("state"), 2)
	if policy.SNATEnabled {
		for _, m := range s.Members {
			if m.VPCID != policy.VPCID || !m.Enabled {
				continue
			}
			for _, dest := range gateway.AllowedPrefixes {
				base := directions(root.InsideInterface, root.OutsideInterface, m.IPv4, dest)
				add("forward", append(append([]any{}, base...), accept)...)
				add("postrouting", append(append([]any{}, base...), nftObject{"snat": nftObject{"addr": natPolicyPublicIPv4(root, *policy), "family": "ip"}})...)
				add("forward", match(meta("iifname"), root.OutsideInterface), match(meta("oifname"), root.InsideInterface), match(payload("ip", "saddr"), prefixExpr(dest)), match(payload("ip", "daddr"), m.IPv4), established, accept)
			}
		}
	}
	for _, f := range policy.Forwardings {
		m := members[f.TargetInstanceID]
		add("prerouting", match(meta("iifname"), root.OutsideInterface), match(payload("ip", "daddr"), natPolicyPublicIPv4(root, *policy)), match(payload("ip", "saddr"), prefixExpr(f.SourceCIDR)), match(payload(f.Protocol, "dport"), f.PublicPort), nftObject{"dnat": nftObject{"addr": m.IPv4, "port": f.TargetPort, "family": "ip"}})
		add("forward", match(meta("iifname"), root.OutsideInterface), match(meta("oifname"), root.InsideInterface), match(payload("ip", "saddr"), prefixExpr(f.SourceCIDR)), match(payload("ip", "daddr"), m.IPv4), match(payload(f.Protocol, "dport"), f.TargetPort), bitmatch(ct("status"), 32), accept)
		add("forward", match(meta("iifname"), root.InsideInterface), match(meta("oifname"), root.OutsideInterface), match(payload("ip", "saddr"), m.IPv4), match(payload("ip", "daddr"), prefixExpr(f.SourceCIDR)), match(payload(f.Protocol, "sport"), f.TargetPort), bitmatch(ct("status"), 32), established, accept)
	}
	if policy.InternetEgressEnabled {
		// Declare ordinary chains before rules; nft input declaration order is
		// significant even though cross-chain listing order is not.
		rules := []nftObject{}
		appendRule := func(chain string, expr ...any) {
			rules = append(rules, nftObject{"rule": nftObject{"family": "inet", "table": natTable, "chain": chain, "expr": expr}})
		}
		objects = append(objects, compileInternetNAT(c, s, root, *policy, appendRule)...)
		objects = append(objects, rules...)
	}
	raw, _ := json.Marshal(objects)
	if len(raw) > 512<<10 {
		return nil, ErrInvalid
	}
	return objects, nil
}
func nftProgram(objects []nftObject, exists bool) []byte {
	commands := []nftObject{}
	if exists {
		commands = append(commands, nftObject{"delete": nftObject{"table": nftObject{"family": "inet", "name": natTable}}})
	}
	for _, o := range objects {
		commands = append(commands, nftObject{"add": o})
	}
	raw, _ := json.Marshal(nftObject{"nftables": commands})
	return raw
}

// Ignore only kernel handles/metainfo; retain every expression and rule order.
func normalizeNFT(raw []byte) ([]byte, bool, error) {
	var top struct {
		Objects []map[string]map[string]any `json:"nftables"`
	}
	if json.Unmarshal(raw, &top) != nil || top.Objects == nil {
		return nil, false, ErrUnavailable
	}
	out := []nftObject{}
	exists := false
	for _, o := range top.Objects {
		if len(o) != 1 {
			return nil, false, ErrUnavailable
		}
		for kind, v := range o {
			if kind == "metainfo" {
				continue
			}
			if kind != "table" && kind != "chain" && kind != "rule" {
				return nil, false, ErrUnavailable
			}
			if v["family"] != "inet" {
				return nil, false, ErrUnavailable
			}
			if kind == "table" {
				if v["name"] != natTable || exists {
					return nil, false, ErrUnavailable
				}
				exists = true
			} else if v["table"] != natTable {
				return nil, false, ErrUnavailable
			}
			delete(v, "handle")
			delete(v, "index")
			out = append(out, nftObject{kind: v})
		}
	}
	// nft lists rules grouped with their owning chain; command input may
	// interleave chains. Cross-chain ordering is immaterial, per-chain order is not.
	key := func(o nftObject) string {
		for kind, body := range o {
			v := body.(map[string]any)
			switch kind {
			case "table":
				return "0"
			case "chain":
				return "1:" + v["name"].(string)
			case "rule":
				return "2:" + v["chain"].(string)
			}
		}
		return ""
	}
	for _, o := range out {
		for kind, body := range o {
			v := body.(map[string]any)
			if kind == "chain" {
				if _, ok := v["name"].(string); !ok {
					return nil, false, ErrUnavailable
				}
			}
			if kind == "rule" {
				if _, ok := v["chain"].(string); !ok {
					return nil, false, ErrUnavailable
				}
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return key(out[i]) < key(out[j]) })
	b, _ := json.Marshal(out)
	return b, exists, nil
}

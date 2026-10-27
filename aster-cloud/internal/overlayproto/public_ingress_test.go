package overlayproto

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func ingressPolicyFixture() PublicIngressPolicy {
	f := floatingSnapshot().FloatingIPs[0]
	return PublicIngressPolicy{Schema: 1, InstanceID: f.InstanceID, OwnerRef: f.OwnerRef, Revision: 1, Rules: []PublicIngressRule{{ID: strings.Repeat("2", 32), Protocol: "tcp", SourceCIDR: "9.9.9.0/24", PortStart: 443, PortEnd: 443}, {ID: strings.Repeat("1", 32), Protocol: "icmp", SourceCIDR: "0.0.0.0/0"}}}
}
func TestPublicIngressCanonicalDigestAndImmutableRuleCopy(t *testing.T) {
	original := ingressPolicyFixture()
	p, e := CanonicalPublicIngress(original)
	if e != nil || !ValidSHA(p.SHA256) || p.Rules[0].ID != strings.Repeat("1", 32) || original.Rules[0].ID != strings.Repeat("2", 32) {
		t.Fatal("canonical policy/copy", p, e)
	}
	reversed := original
	reversed.Rules = []PublicIngressRule{original.Rules[1], original.Rules[0]}
	again, e := CanonicalPublicIngress(reversed)
	if e != nil || !reflect.DeepEqual(p, again) {
		t.Fatal("rule order changed digest", e)
	}
	s := floatingSnapshot()
	old, oldsha, e := CanonicalSnapshot(s)
	if e != nil {
		t.Fatal(e)
	}
	legacy, _ := json.Marshal(old)
	if strings.Contains(string(legacy), "ingress") {
		t.Fatal("changed historical wire")
	}
	s.FloatingIPs[0].Ingress = &p
	with, sha, e := CanonicalSnapshot(s)
	if e != nil || sha == oldsha {
		t.Fatal("policy absent from snapshot digest", e)
	}
	raw, _ := json.Marshal(with)
	decoded, e := DecodeSnapshot(raw)
	if e != nil || decoded.FloatingIPs[0].Ingress.SHA256 != p.SHA256 {
		t.Fatal("strict roundtrip", e)
	}
	d := DefaultPublicIngress(p.InstanceID, p.OwnerRef)
	if d.Revision != 0 || d.Rules == nil || len(d.Rules) != 0 || !ValidSHA(d.SHA256) {
		t.Fatal("default is not explicit empty deny", d)
	}
	s.FloatingIPs[0].Ingress = &d
	if _, denysha, e := CanonicalSnapshot(s); e != nil || denysha == oldsha || denysha == sha {
		t.Fatal("default deny conflated with legacy", e)
	}
}
func TestPublicIngressRejectsMalformedPolicy(t *testing.T) {
	for kind, edit := range map[string]func(*PublicIngressPolicy){
		"nil": func(p *PublicIngressPolicy) { p.Rules = nil }, "schema": func(p *PublicIngressPolicy) { p.Schema = 0 }, "owner": func(p *PublicIngressPolicy) { p.OwnerRef = "bad" }, "revision": func(p *PublicIngressPolicy) { p.Revision = MaxPublicIngressRevision + 1 }, "zero-rules": func(p *PublicIngressPolicy) { p.Revision = 0 }, "hash": func(p *PublicIngressPolicy) { p.SHA256 = strings.Repeat("a", 64) }, "duplicate-id": func(p *PublicIngressPolicy) { p.Rules[1].ID = p.Rules[0].ID }, "duplicate-rule": func(p *PublicIngressPolicy) {
			r := p.Rules[0]
			r.ID = strings.Repeat("3", 32)
			p.Rules = append(p.Rules, r)
		}, "source": func(p *PublicIngressPolicy) { p.Rules[0].SourceCIDR = "9.9.9.1/24" }, "ipv6": func(p *PublicIngressPolicy) { p.Rules[0].SourceCIDR = "::/0" }, "portzero": func(p *PublicIngressPolicy) { p.Rules[0].PortStart = 0 }, "portorder": func(p *PublicIngressPolicy) { p.Rules[0].PortEnd = 1 }, "portoverflow": func(p *PublicIngressPolicy) { p.Rules[0].PortEnd = 65536 }, "icmp-port": func(p *PublicIngressPolicy) { p.Rules[1].PortStart = 1 }, "unsupported": func(p *PublicIngressPolicy) { p.Rules[0].Protocol = "all" }, "rule-limit": func(p *PublicIngressPolicy) {
			for len(p.Rules) < 65 {
				p.Rules = append(p.Rules, p.Rules[0])
			}
		},
	} {
		t.Run(kind, func(t *testing.T) {
			p := ingressPolicyFixture()
			edit(&p)
			if _, e := CanonicalPublicIngress(p); e == nil {
				t.Fatal("unsafe policy accepted")
			}
		})
	}
}
func TestPublicIngressStrictWireNeverDowngradesToLegacy(t *testing.T) {
	p, _ := CanonicalPublicIngress(ingressPolicyFixture())
	s := floatingSnapshot()
	s.FloatingIPs[0].Ingress = &p
	canon, _, e := CanonicalSnapshot(s)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(canon)
	wire := string(raw)
	for name, bad := range map[string]string{
		"null":          strings.Replace(wire, `"ingress":`+string(mustPolicyJSON(p)), `"ingress":null`, 1),
		"wrong-case":    strings.Replace(wire, `"ingress":`, `"Ingress":`, 1),
		"duplicate":     strings.Replace(wire, `"schema":1`, `"schema":1,"schema":1`, 1),
		"null-rules":    strings.Replace(wire, `"rules":[`, `"rules":null,"x":[`, 1),
		"hash":          strings.Replace(wire, p.SHA256, strings.Repeat("a", 64), 1),
		"missing-rules": strings.Replace(wire, `"rules":`, `"unknown":`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if bad == wire {
				t.Fatal("test did not mutate wire")
			}
			if _, e := DecodeSnapshot([]byte(bad)); e == nil {
				t.Fatal("ambiguous policy wire accepted")
			}
		})
	}
	for _, kind := range []string{"instance", "owner"} {
		t.Run(kind, func(t *testing.T) {
			q := p
			q.SHA256 = ""
			if kind == "instance" {
				q.InstanceID = strings.Repeat("f", 32)
			} else {
				q.OwnerRef = strings.Repeat("f", 32)
			}
			q, _ = CanonicalPublicIngress(q)
			s.FloatingIPs[0].Ingress = &q
			if _, _, e := CanonicalSnapshot(s); e == nil {
				t.Fatal("foreign target/owner policy accepted")
			}
		})
	}
}
func mustPolicyJSON(p PublicIngressPolicy) []byte { raw, _ := json.Marshal(p); return raw }

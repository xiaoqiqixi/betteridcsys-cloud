package networking

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

const testOwner = "11111111111111111111111111111111"
const testActor = "22222222222222222222222222222222"
const testID = "33333333333333333333333333333333"
const testInstance = "44444444444444444444444444444444"

func vpcInput() CreateVPCInput {
	return CreateVPCInput{testOwner, "node-a", "香港私网", "10.10.0.0/24", 42}
}
func poolInput() CreatePoolInput {
	return CreatePoolInput{"node-a", "", "香港地址池", "192.0.2.0/24", "192.0.2.1", []string{"192.0.2.10", "192.0.2.2"}, true}
}
func reserveInput() ReserveInput { return ReserveInput{testID, testInstance, testOwner, ""} }
func testNow() time.Time         { return time.Date(2026, 10, 23, 1, 2, 3, 123456789, time.UTC) }
func ipSequence(t *testing.T, start string, n int) []string {
	t.Helper()
	a, e := netip.ParseAddr(start)
	if e != nil {
		t.Fatal(e)
	}
	out := make([]string, n)
	for j := range n {
		out[j] = a.String()
		a = a.Next()
	}
	return out
}

func TestVPCRequiresCanonicalRFC1918AndFixedIdentifiers(t *testing.T) {
	if !vpcInput().Valid() {
		t.Fatal("valid VPC rejected")
	}
	for _, cidr := range []string{"10.0.0.0/16", "172.16.0.0/16", "172.31.255.252/30", "192.168.0.0/16", "192.168.9.0/24"} {
		in := vpcInput()
		in.CIDR = cidr
		if !in.Valid() {
			t.Fatal("private prefix rejected", cidr)
		}
	}
	for _, cidr := range []string{"10.10.0.1/24", "10.0.0.0/8", "10.10.0.0/31", "10.10.0.1/32", "172.32.0.0/16", "192.0.2.0/24", "100.64.0.0/16", "127.0.0.0/16", "169.254.0.0/16", "224.0.0.0/16", "::ffff:10.0.0.0/120", "fd00::/64", "10.10.0.0/024", "10.010.0.0/24", "10.10.0.0/24\n", "10.10.0.0"} {
		t.Run(cidr, func(t *testing.T) {
			in := vpcInput()
			in.CIDR = cidr
			if in.Valid() {
				t.Fatal("invalid VPC prefix accepted")
			}
		})
	}
	for name, mutate := range map[string]func(*CreateVPCInput){"owner": func(v *CreateVPCInput) { v.OwnerRef = "../owner" }, "upper_id": func(v *CreateVPCInput) { v.OwnerRef = strings.Repeat("A", 32) }, "node": func(v *CreateVPCInput) { v.NodeID = "https://host" }, "name_empty": func(v *CreateVPCInput) { v.Name = "" }, "name_space": func(v *CreateVPCInput) { v.Name = " 测试" }, "name_control": func(v *CreateVPCInput) { v.Name = "测试\n" }, "name_bidi": func(v *CreateVPCInput) { v.Name = "\u202ehost" }, "name_long": func(v *CreateVPCInput) { v.Name = strings.Repeat("中", 81) }, "name_invalid_utf8": func(v *CreateVPCInput) { v.Name = string([]byte{255}) }, "vlan_zero": func(v *CreateVPCInput) { v.VLANID = 0 }, "vlan_reserved": func(v *CreateVPCInput) { v.VLANID = 4095 }} {
		t.Run(name, func(t *testing.T) {
			in := vpcInput()
			mutate(&in)
			if in.Valid() {
				t.Fatal("invalid input accepted")
			}
		})
	}
}
func TestPoolCanonicalNumericOrderCopyAndPayloadDigest(t *testing.T) {
	in := poolInput()
	original := append([]string{}, in.Addresses...)
	c, e := in.Canonical()
	if e != nil || !reflect.DeepEqual(c.Addresses, []string{"192.0.2.2", "192.0.2.10"}) || !reflect.DeepEqual(in.Addresses, original) {
		t.Fatal("numeric sort mutated input or sorted lexically", c, e)
	}
	reordered := in
	reordered.Addresses = []string{"192.0.2.2", "192.0.2.10"}
	other, e := reordered.Canonical()
	if e != nil || bodyDigest(c) != bodyDigest(other) {
		t.Fatal("same address set changed intent")
	}
	other.Enabled = false
	if bodyDigest(c) == bodyDigest(other) {
		t.Fatal("changed policy kept digest")
	}
	for name, mutate := range map[string]func(*CreatePoolInput){"unknown_vpc": func(p *CreatePoolInput) { p.VPCID = "id" }, "bad_node": func(p *CreatePoolInput) { p.NodeID = "node/a" }, "no_addresses": func(p *CreatePoolInput) { p.Addresses = nil }, "duplicate": func(p *CreatePoolInput) { p.Addresses = []string{"192.0.2.10", "192.0.2.10"} }, "outside": func(p *CreatePoolInput) { p.Addresses = []string{"192.0.3.10"} }, "network": func(p *CreatePoolInput) { p.Addresses = []string{"192.0.2.0"} }, "broadcast": func(p *CreatePoolInput) { p.Addresses = []string{"192.0.2.255"} }, "gateway_allocated": func(p *CreatePoolInput) { p.Addresses = []string{p.Gateway} }, "gateway_broadcast": func(p *CreatePoolInput) { p.Gateway = "192.0.2.255" }, "gateway_outside": func(p *CreatePoolInput) { p.Gateway = "192.0.3.1" }, "gateway_network": func(p *CreatePoolInput) { p.Gateway = "192.0.2.0" }, "mapped": func(p *CreatePoolInput) { p.Addresses = []string{"::ffff:192.0.2.10"} }, "ipv6": func(p *CreatePoolInput) { p.Addresses = []string{"2001:db8::10"} }, "spaces": func(p *CreatePoolInput) { p.Addresses = []string{"192.0.2.10 "} }, "host_prefix": func(p *CreatePoolInput) { p.CIDR = "192.0.2.5/24" }, "zero_prefix": func(p *CreatePoolInput) { p.CIDR = "0.0.0.0/0" }, "short_prefix": func(p *CreatePoolInput) { p.CIDR = "192.0.2.0/31" }} {
		t.Run(name, func(t *testing.T) {
			p := poolInput()
			mutate(&p)
			if _, e := p.Canonical(); e == nil {
				t.Fatal("invalid pool accepted")
			}
		})
	}
}
func TestPool4096BoundaryAndHTTPBodyAbove64KiB(t *testing.T) {
	in := poolInput()
	in.CIDR = "192.168.0.0/16"
	in.Gateway = "192.168.0.1"
	in.Addresses = ipSequence(t, "192.168.200.1", 4096)
	c, e := in.Canonical()
	if e != nil || len(c.Addresses) != MaxAddresses {
		t.Fatal("4096 valid addresses rejected", e)
	}
	raw, _ := json.Marshal(in)
	if len(raw) <= 65536 || len(raw) > maxBodyBytes {
		t.Fatal("fixture does not cover >64KiB", len(raw))
	}
	var decoded CreatePoolInput
	r := httptest.NewRequest("POST", APIBase+"pools", bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json; charset=utf-8")
	w := httptest.NewRecorder()
	if !readInput(w, r, &decoded, []string{"node_id", "vpc_id", "name", "cidr", "gateway", "addresses", "enabled"}) || len(decoded.Addresses) != 4096 {
		t.Fatal("valid pool HTTP boundary refused", w.Code, w.Body.String())
	}
	in.Addresses = append(in.Addresses, "192.168.220.1")
	if _, e = in.Canonical(); e == nil {
		t.Fatal("4097 addresses accepted")
	}
}
func TestLeaseInputAndTimestamps(t *testing.T) {
	if !reserveInput().Valid() || !validWrite(testActor, testID, testNow()) {
		t.Fatal("valid IDs/time rejected")
	}
	for _, ip := range []string{"192.0.2.10", "10.1.1.1"} {
		r := reserveInput()
		r.Address = ip
		if !r.Valid() {
			t.Fatal(ip)
		}
	}
	for _, ip := range []string{"192.0.2.10/24", "::ffff:192.0.2.10", "127.0.0.1", "0.0.0.0", "224.0.0.1", "192.0.2.10\n"} {
		r := reserveInput()
		r.Address = ip
		if r.Valid() {
			t.Fatal("invalid address accepted", ip)
		}
	}
	for _, now := range []time.Time{{}, time.Date(999, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		if validWrite(testActor, testID, now) {
			t.Fatal("invalid SQL timestamp accepted")
		}
	}
	if stamp(testNow()).Location() != time.UTC || stamp(testNow()).Nanosecond() != 123456000 {
		t.Fatal("timestamp precision not UTC microseconds")
	}
}
func TestHTTPStrictExactInputsAndQuery(t *testing.T) {
	raw, _ := json.Marshal(vpcInput())
	var out CreateVPCInput
	fields := []string{"owner_ref", "node_id", "name", "cidr", "vlan_id"}
	if !decodeInput(raw, &out, fields) {
		t.Fatal("valid body rejected")
	}
	for name, s := range map[string]string{"duplicate": strings.Replace(string(raw), `"vlan_id":42`, `"vlan_id":42,"vlan_id":42`, 1), "escaped_duplicate": strings.Replace(string(raw), `"vlan_id":42`, `"vlan_id":42,"\u0076lan_id":42`, 1), "wrong_case": strings.Replace(string(raw), `"node_id"`, `"Node_ID"`, 1), "null": strings.Replace(string(raw), `"name":"香港私网"`, `"name":null`, 1), "missing": strings.Replace(string(raw), `,"vlan_id":42`, "", 1), "unknown": strings.TrimSuffix(string(raw), "}") + `,"command":"id"}`, "trailing": string(raw) + "{}", "array": "[" + string(raw) + "]", "fraction": strings.Replace(string(raw), `"vlan_id":42`, `"vlan_id":42.0`, 1), "exp": strings.Replace(string(raw), `"vlan_id":42`, `"vlan_id":42e0`, 1), "depth": `{"owner_ref":` + strings.Repeat("[", 10) + `1` + strings.Repeat("]", 10) + `}`, "invalid_utf8": string(append([]byte{255}, raw...)), "large": strings.Repeat(" ", maxBodyBytes+1)} {
		t.Run(name, func(t *testing.T) {
			if decodeInput([]byte(s), &out, fields) {
				t.Fatal("ambiguous body accepted")
			}
		})
	}
	for _, raw := range []string{"cursor=bad", "cursor=" + testID + "&cursor=" + testID, "ignored=true", "cursor=%zz", "cursor=" + testID + "&ignored=x"} {
		u := &url.URL{RawQuery: raw}
		if _, e := parseQuery(u, true); e == nil {
			t.Fatal("invalid query accepted", raw)
		}
	}
	if got, e := parseQuery(&url.URL{RawQuery: "cursor=" + testID}, true); e != nil || got != testID {
		t.Fatal(got, e)
	}
	for _, u := range []*url.URL{{ForceQuery: true}, {RawQuery: "cursor=" + testID}} {
		if _, e := parseQuery(u, false); e == nil {
			t.Fatal("query accepted on detail/write")
		}
	}
	for _, method := range []string{"GET", "POST", "DELETE"} {
		w := httptest.NewRecorder()
		NewHandler(nil, []string{"node-a"}).ServeHTTP(w, httptest.NewRequest(method, APIBase+"vpcs", nil))
		if w.Code != 401 || !strings.Contains(w.Body.String(), "AUTH_REQUIRED") {
			t.Fatal("missing actor reached storage", method, w.Code)
		}
	}
}
func TestNilStoreAndInvalidIDsFailClosed(t *testing.T) {
	ctx := t.Context()
	s := &Store{}
	if _, _, e := s.CreateVPC(ctx, testActor, testID, vpcInput(), testNow()); e != ErrUnavailable {
		t.Fatal(e)
	}
	if _, _, e := s.CreatePool(ctx, testActor, testID, poolInput(), testNow()); e != ErrUnavailable {
		t.Fatal(e)
	}
	if _, _, e := s.Reserve(ctx, testActor, testID, reserveInput(), testNow()); e != ErrUnavailable {
		t.Fatal(e)
	}
	if _, e := s.GetVPC(ctx, "invalid"); e != ErrInput {
		t.Fatal(e)
	}
	if _, e := s.GetPool(ctx, testID); e != ErrUnavailable {
		t.Fatal(e)
	}
	if _, e := s.GetLease(ctx, testID); e != ErrUnavailable {
		t.Fatal(e)
	}
	if _, e := s.ListVPCs(ctx, "bad"); e != ErrInput {
		t.Fatal(e)
	}
	if _, e := s.ListPools(ctx, ""); e != ErrUnavailable {
		t.Fatal(e)
	}
	if _, e := s.ListLeases(ctx, ""); e != ErrUnavailable {
		t.Fatal(e)
	}
	if e := s.Check(ctx); e != ErrUnavailable {
		t.Fatal(e)
	}
}

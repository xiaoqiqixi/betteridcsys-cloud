package control

import (
	"aster/cloud/internal/overlayproto"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestPublicIPPoolStrictCanonicalInventoryAndApproval(t *testing.T) {
	good := PublicIPPoolInput{ClusterID: "cluster-test", Name: "公网出口", CIDR: "8.8.8.0/24", Addresses: []string{"8.8.8.8", "8.8.8.9"}, Enabled: true}
	if !publicPoolValid(good) {
		t.Fatal("valid inventory rejected")
	}
	edits := map[string]func(*PublicIPPoolInput){"private": func(v *PublicIPPoolInput) { v.Addresses = []string{"10.0.0.1"} }, "metadata": func(v *PublicIPPoolInput) { v.Addresses = []string{"169.254.169.254"} }, "special": func(v *PublicIPPoolInput) { v.CIDR = "198.51.100.0/24"; v.Addresses = []string{"198.51.100.1"} }, "outside": func(v *PublicIPPoolInput) { v.Addresses = []string{"9.9.9.9"} }, "duplicate": func(v *PublicIPPoolInput) { v.Addresses = []string{"8.8.8.8", "8.8.8.8"} }, "nil": func(v *PublicIPPoolInput) { v.Addresses = nil }, "empty": func(v *PublicIPPoolInput) { v.Addresses = []string{} }, "large": func(v *PublicIPPoolInput) { v.Addresses = make([]string, 4097) }, "host_cidr": func(v *PublicIPPoolInput) { v.CIDR = "8.8.8.1/24" }, "zero_prefix": func(v *PublicIPPoolInput) { v.CIDR = "0.0.0.0/0" }, "ipv6": func(v *PublicIPPoolInput) { v.CIDR = "2001:4860::/32" }, "bidi": func(v *PublicIPPoolInput) { v.Name = "pool\u202e" }, "whitespace": func(v *PublicIPPoolInput) { v.Name = " pool" }}
	for name, edit := range edits {
		t.Run(name, func(t *testing.T) {
			v := good
			edit(&v)
			if publicPoolValid(v) {
				t.Fatal("unsafe inventory accepted")
			}
		})
	}
	c, s := overlayPolicyFixture()
	p := &c.OverlayClusters[0].NATProfiles[0]
	p.PublicIPv4 = "8.8.8.8"
	p.PublicIPv4s = []string{"8.8.8.9"}
	good.ClusterID = c.OverlayClusters[0].ClusterID
	if !c.Valid() || !publicPoolApproved(c, good) {
		t.Fatal("root primary+additional rejected")
	}
	s.NATPolicies[0].PublicIPv4 = "8.8.8.9"
	if !overlayPoliciesApproved(c.OverlayClusters[0], s) {
		t.Fatal("approved explicit selector rejected")
	}
	s.NATPolicies[0].PublicIPv4 = "8.8.8.10"
	if overlayPoliciesApproved(c.OverlayClusters[0], s) {
		t.Fatal("selector escaped root inventory")
	}
	for _, addresses := range [][]string{{"8.8.8.8"}, {"10.0.0.1"}, {"8.8.8.9", "8.8.8.9"}, make([]string, 65)} {
		p.PublicIPv4s = addresses
		if c.Valid() {
			t.Fatal("ambiguous root inventory accepted")
		}
	}
}
func TestPublicIPOperationDigestBindsActionTargetCanonicalBody(t *testing.T) {
	a := json.RawMessage(`{"enabled":true}`)
	b := json.RawMessage(`{"enabled":false}`)
	id := strings.Repeat("a", 32)
	want := publicOperationDigest("pool.state", id, a)
	if !overlayproto.ValidSHA(want) {
		t.Fatal("invalid digest")
	}
	for _, got := range []string{publicOperationDigest("pool.create", id, a), publicOperationDigest("pool.state", strings.Repeat("b", 32), a), publicOperationDigest("pool.state", id, b)} {
		if got == want {
			t.Fatal("intent collision")
		}
	}
}

func TestPublicIPResponseBudgetPaginatesWithoutSkippingLargePoolsOrOperations(t *testing.T) {
	addresses := make([]string, 4096)
	for i := range addresses {
		addresses[i] = "123.123.123.123"
	}
	pool := PublicIPPool{ID: strings.Repeat("a", 32), ClusterID: "cluster", Name: "pool", CIDR: "123.123.0.0/16", Addresses: addresses}
	pools := make([]PublicIPPool, 101)
	for i := range pools {
		pools[i] = pool
		pools[i].ID = fmt.Sprintf("%032x", i+1)
	}
	page, next, e := publicIPBudgetPage(pools, func(v PublicIPPool) string { return v.ID })
	if e != nil || len(page) < 1 || len(page) >= 100 || next != page[len(page)-1].ID {
		t.Fatal("large pool budget", len(page), next, e)
	}
	raw, _ := json.Marshal(map[string]any{"items": page, "next_cursor": next})
	if len(raw) > publicIPPageBytes {
		t.Fatal("pool page exceeded budget", len(raw))
	}
	remaining := pools[len(page):]
	second, _, e := publicIPBudgetPage(remaining, func(v PublicIPPool) string { return v.ID })
	if e != nil || second[0].ID != pools[len(page)].ID {
		t.Fatal("size cursor skipped pool", e)
	}
	operations := make([]PublicIPOperation, 101)
	request, _ := json.Marshal(PublicIPPoolInput{ClusterID: pool.ClusterID, Name: pool.Name, CIDR: pool.CIDR, Addresses: addresses, Enabled: true})
	for i := range operations {
		copyPool := pool
		operations[i] = PublicIPOperation{ID: fmt.Sprintf("%032x", i+1), Request: request, Result: PublicIPResult{Pool: &copyPool}}
	}
	ops, cursor, e := publicIPBudgetPage(operations, func(v PublicIPOperation) string { return v.ID })
	if e != nil || len(ops) < 1 || len(ops) >= len(page) || cursor != ops[len(ops)-1].ID {
		t.Fatal("large operation budget", len(ops), cursor, e)
	}
	raw, _ = json.Marshal(map[string]any{"items": ops, "next_cursor": cursor})
	if len(raw) > publicIPPageBytes {
		t.Fatal("operation page exceeded budget", len(raw))
	}
	tiny := make([]PublicIPPool, 101)
	for i := range tiny {
		tiny[i].ID = fmt.Sprintf("%032x", i+1)
	}
	page, next, e = publicIPBudgetPage(tiny, func(v PublicIPPool) string { return v.ID })
	if e != nil || len(page) != 100 || next != tiny[99].ID {
		t.Fatal("count bound/cursor", len(page), next, e)
	}
	if publicIPProjectionFits(strings.Repeat("x", publicIPProjectionBytes)) {
		t.Fatal("oversized complete projection accepted")
	}
}

func TestPublicIPStrict128KiBAndImmutableResultTimeRoundTrip(t *testing.T) {
	addresses := make([]string, 4096)
	for i := range addresses {
		addresses[i] = fmt.Sprintf("123.123.%d.%d", 100+i/256, i%256)
	}
	in := PublicIPPoolInput{ClusterID: "cluster-test", Name: "最大池", CIDR: "123.123.0.0/16", Addresses: addresses, Enabled: true}
	raw, _ := json.Marshal(in)
	if len(raw) <= 65536 {
		t.Fatal("fixture did not exercise original64KiB boundary", len(raw))
	}
	var decoded PublicIPPoolInput
	if !strictPublicIP(raw, &decoded) || !reflect.DeepEqual(in, decoded) {
		t.Fatal("maximum public inventory rejected")
	}
	if strict(raw, &decoded) {
		t.Fatal("original API unexpectedly widened")
	}
	now := time.Date(2026, 10, 24, 1, 2, 3, 4000, time.UTC)
	pool := PublicIPPool{ID: strings.Repeat("a", 32), ClusterID: in.ClusterID, Name: in.Name, CIDR: in.CIDR, Addresses: in.Addresses, Enabled: true, CreatedAt: now, UpdatedAt: now}
	result := PublicIPResult{Pool: &pool}
	stored, _ := json.Marshal(result)
	var parsed PublicIPResult
	if !strictPublicIP(stored, &parsed) || !reflect.DeepEqual(parsed, result) {
		t.Fatal("stored immutable result times did not roundtrip")
	}
	op := PublicIPOperation{ID: pool.ID, ActorID: strings.Repeat("b", 32), Action: "pool.create", ResourceID: pool.ID, Request: raw, Result: result, CreatedAt: now}
	op.RequestSHA256 = publicOperationDigest(op.Action, "", raw)
	if !publicOperationResultValid(op) {
		t.Fatal("valid maximum pool operation rejected")
	}
	for name, body := range map[string]string{"missing": `{}`, "duplicate": `{"enabled":true,"enabled":false}`, "wrong_case": `{"Enabled":true}`, "null": `null`, "unknown": `{"enabled":true,"device":"eth0"}`, "oversize": `{"enabled":true,"padding":"` + strings.Repeat("x", 131072) + `"}`} {
		t.Run(name, func(t *testing.T) {
			var state struct {
				Enabled bool `json:"enabled"`
			}
			if strictPublicIP([]byte(body), &state) {
				t.Fatal("loose public JSON accepted")
			}
		})
	}
}

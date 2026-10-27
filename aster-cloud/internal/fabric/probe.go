package fabric

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type binding struct {
	Name        string `json:"name"`
	OFPort      int    `json:"ofport"`
	InterfaceID string `json:"interface_id"`
	InstanceID  string `json:"instance_id"`
	OwnerRef    string `json:"owner_ref"`
	VPCID       string `json:"vpc_id"`
}

func sameBindings(a, b []binding) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

func tapInterface(name string) error {
	if !nameRE.MatchString(name) {
		return ErrUnavailable
	}
	raw, e := os.ReadFile(filepath.Join("/sys/class/net", name, "tun_flags"))
	if e != nil || len(raw) > 64 {
		return ErrUnavailable
	}
	n, e := strconv.ParseUint(strings.TrimSpace(string(raw)), 0, 32)
	if e != nil || n&2 == 0 || n&1 != 0 {
		return ErrUnavailable
	}
	return nil
}
func ovsMap(v any) (map[string]string, error) {
	a, ok := v.([]any)
	if !ok || len(a) != 2 || a[0] != "map" {
		return nil, ErrUnavailable
	}
	items, ok := a[1].([]any)
	if !ok {
		return nil, ErrUnavailable
	}
	out := map[string]string{}
	for _, item := range items {
		kv, ok := item.([]any)
		if !ok || len(kv) != 2 {
			return nil, ErrUnavailable
		}
		k, kok := kv[0].(string)
		val, vok := kv[1].(string)
		if !kok || !vok {
			return nil, ErrUnavailable
		}
		if _, dup := out[k]; dup {
			return nil, ErrUnavailable
		}
		out[k] = val
	}
	return out, nil
}
func ovsSet(v any) ([]any, error) {
	if a, ok := v.([]any); ok && len(a) == 2 && a[0] == "set" {
		items, ok := a[1].([]any)
		if !ok {
			return nil, ErrUnavailable
		}
		return items, nil
	}
	return []any{v}, nil
}
func ovsRows(raw []byte, headings []string) ([][]any, error) {
	if len(raw) > 1<<20 {
		return nil, ErrUnavailable
	}
	// Reject duplicate/unknown root fields, null arrays and trailing JSON before
	// UseNumber decoding. The standard ovs-vsctl table has only these two keys.
	var envelope struct{}
	if object(raw, []string{"headings", "data"}, &envelope) != nil {
		return nil, ErrUnavailable
	}
	var t struct {
		Headings []string `json:"headings"`
		Data     [][]any  `json:"data"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&t) != nil || len(t.Headings) != len(headings) || len(t.Data) > 1024 {
		return nil, ErrUnavailable
	}
	for n, h := range headings {
		if t.Headings[n] != h {
			return nil, ErrUnavailable
		}
	}
	for _, r := range t.Data {
		if len(r) != len(headings) {
			return nil, ErrUnavailable
		}
	}
	return t.Data, nil
}

var versionRE = regexp.MustCompile(`Open vSwitch\) ([0-9]+)\.([0-9]+)\.`)
var meterIDRE = regexp.MustCompile(`meter=([0-9]+)(?:[ ,\t\n]|$)`)
var meterRateRE = regexp.MustCompile(`rate=([0-9]+)(?:[ ,\t\n]|$)`)
var meterKbpsRE = regexp.MustCompile(`(?:^|[ ,\n])kbps(?:[ ,\n]|$)`)
var meterStatsRE = regexp.MustCompile(`(?:^|[ ,\n])stats(?:[ ,\n]|$)`)
var meterDropRE = regexp.MustCompile(`(?:^|[ ,\n])type=drop(?:[ ,\n]|$)`)

func (e *Executor) probe(ctx context.Context, p Plan) ([]binding, bool, error) {
	return e.probeActivation(ctx, p, nil, false)
}

func (e *Executor) probeActivation(ctx context.Context, p Plan, intent *ActivationIntent, bootstrap bool) ([]binding, bool, error) {
	owned := false
	if _, err := e.run(ctx, Vsctl, "--timeout=3", "br-exists", e.Config.Bridge); err != nil {
		return nil, owned, err
	}
	raw, err := e.run(ctx, Ofctl, "--version")
	if err != nil {
		return nil, owned, err
	}
	v := versionRE.FindSubmatch(raw)
	if len(v) != 3 {
		return nil, owned, ErrUnavailable
	}
	major, majorErr := strconv.Atoi(string(v[1]))
	minor, minorErr := strconv.Atoi(string(v[2]))
	if majorErr != nil || minorErr != nil || major < 2 || major == 2 && minor < 17 {
		return nil, owned, ErrUnavailable
	}
	raw, err = e.run(ctx, Vsctl, "--timeout=3", "--format=json", "--columns=name,controller,fail_mode,external_ids,protocols", "list", "Bridge", e.Config.Bridge)
	if err != nil {
		return nil, owned, err
	}
	rows, err := ovsRows(raw, []string{"name", "controller", "fail_mode", "external_ids", "protocols"})
	if err != nil || len(rows) != 1 || rows[0][0] != e.Config.Bridge {
		return nil, owned, ErrUnavailable
	}
	row := rows[0]
	controllers, ce := ovsSet(row[1])
	mode, me := ovsSet(row[2])
	ids, ie := ovsMap(row[3])
	protocols, pe := ovsSet(row[4])
	has14 := false
	for _, v := range protocols {
		if v == "OpenFlow14" {
			has14 = true
		}
	}
	if ce != nil || me != nil || ie != nil || pe != nil || len(controllers) != 0 || len(mode) != 1 || mode[0] != "secure" || ids["aster-node-id"] != e.Config.NodeID || ids["aster-dedicated"] != "true" || !has14 {
		return nil, owned, ErrUnavailable
	}
	owned = true
	raw, err = e.run(ctx, Vsctl, "--timeout=3", "list-ifaces", e.Config.Bridge)
	if err != nil {
		return nil, owned, err
	}
	owned = true
	names := strings.Fields(string(raw))
	if len(names) > 128 {
		return nil, owned, ErrUnavailable
	}
	wanted := map[string]bool{}
	for _, n := range names {
		if !nameRE.MatchString(n) || wanted[n] {
			return nil, owned, ErrUnavailable
		}
		wanted[n] = true
	}
	raw, err = e.run(ctx, Vsctl, "--timeout=3", "--format=json", "--columns=name,ofport,type,external_ids", "list", "Interface")
	if err != nil {
		return nil, owned, err
	}
	rows, err = ovsRows(raw, []string{"name", "ofport", "type", "external_ids"})
	if err != nil {
		return nil, owned, err
	}
	bindings := []binding{}
	ports := map[int]binding{}
	ifaceIDs := map[string]bool{}
	for _, row := range rows {
		name, ok := row[0].(string)
		if !ok {
			return nil, owned, ErrUnavailable
		}
		if !wanted[name] {
			continue
		}
		if err = e.tap(name); err != nil {
			return nil, owned, err
		}
		if row[2] != "" && row[2] != "system" {
			return nil, owned, ErrUnavailable
		}
		number, ok := row[1].(json.Number)
		if !ok {
			return nil, owned, ErrUnavailable
		}
		n, err := strconv.Atoi(string(number))
		if err != nil || n < 1 || n > 32767 {
			return nil, owned, ErrUnavailable
		}
		ids, err := ovsMap(row[3])
		if err == nil && intent != nil {
			var expected *PortIntent
			for j := range intent.Ports {
				if TAPName(intent.Ports[j].InstanceID) == name {
					expected = &intent.Ports[j]
					break
				}
			}
			if expected == nil || ids["iface-id"] != expected.InterfaceID || ids["attached-mac"] != expected.MAC || ids["vm-id"] != DomainID(expected.InstanceID) || ids["iface-status"] != "active" {
				return nil, owned, ErrUnavailable
			}
			labels := map[string]string{"aster-node-id": e.Config.NodeID, "aster-owner": expected.OwnerRef, "aster-instance": expected.InstanceID, "aster-vpc": expected.VPCID}
			for key, value := range labels {
				actual, present := ids[key]
				if actual != value && (!bootstrap || expected.InstanceID != intent.InstanceID || present) {
					return nil, owned, ErrUnavailable
				}
				ids[key] = value
			}
		}
		if err != nil || ids["aster-node-id"] != e.Config.NodeID || !idRE.MatchString(ids["aster-instance"]) || ids["iface-id"] != InterfaceID(ids["aster-instance"]) || !idRE.MatchString(ids["aster-owner"]) || !idRE.MatchString(ids["aster-vpc"]) {
			return nil, owned, ErrUnavailable
		}
		if status, exists := ids["iface-status"]; exists && status != "active" {
			return nil, owned, ErrUnavailable
		}
		b := binding{name, n, ids["iface-id"], ids["aster-instance"], ids["aster-owner"], ids["aster-vpc"]}
		if _, exists := ports[n]; exists || ifaceIDs[b.InterfaceID] {
			return nil, owned, ErrUnavailable
		}
		ports[n] = b
		ifaceIDs[b.InterfaceID] = true
		bindings = append(bindings, b)
	}
	if len(bindings) != len(wanted) {
		return nil, owned, ErrUnavailable
	}
	sort.Slice(bindings, func(i, j int) bool { return bindings[i].OFPort < bindings[j].OFPort })
	return bindings, owned, nil
}

func (e *Executor) ownedFlows(ctx context.Context) error {
	raw, err := e.of(ctx, "dump-flows", e.Config.Bridge)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "OFPST_FLOW reply") || strings.HasPrefix(line, "OFPMP_FLOW reply") {
			continue
		}
		s := strings.ToLower(line)
		if !strings.Contains(s, "cookie="+cookie+",") || !strings.Contains(s, "actions=") || strings.Contains(s, "normal") || strings.Contains(s, "controller") || strings.Contains(s, "local") {
			return ErrUnavailable
		}
	}
	return nil
}

func matchesTopology(bindings []binding, p Plan) bool {
	byPort := map[int]binding{}
	for _, b := range bindings {
		byPort[b.OFPort] = b
	}
	for _, n := range p.Topology.Ports {
		b, ok := byPort[n.OFPort]
		if !ok || b.InterfaceID != n.InterfaceID || b.InstanceID != n.InstanceID || b.OwnerRef != n.OwnerRef || b.VPCID != n.VPCID {
			return false
		}
	}
	return true
}

func (e *Executor) checkMeters(ctx context.Context, expected []Meter, exact bool) error {
	raw, err := e.of(ctx, "dump-meters", e.Config.Bridge)
	if err != nil {
		return err
	}
	want := map[int]int{}
	for _, m := range expected {
		want[m.ID] = m.Kbps
	}
	text := string(raw)
	locations := meterIDRE.FindAllStringSubmatchIndex(text, -1)
	if len(locations) > 256 || strings.Count(text, "meter=") != len(locations) {
		return ErrUnavailable
	}
	seen := map[int]bool{}
	for n, loc := range locations {
		id, err := strconv.Atoi(text[loc[2]:loc[3]])
		if err != nil || seen[id] || strconv.Itoa(id) != text[loc[2]:loc[3]] {
			return ErrUnavailable
		}
		seen[id] = true
		rate, exists := want[id]
		if !exists {
			return ErrUnavailable
		}
		end := len(text)
		if n+1 < len(locations) {
			end = locations[n+1][0]
		}
		section := text[loc[0]:end]
		if exact {
			r := meterRateRE.FindAllStringSubmatch(section, -1)
			if !meterKbpsRE.MatchString(section) || !meterStatsRE.MatchString(section) || strings.Contains(section, "flags:") || strings.Contains(section, "pktps") || strings.Contains(section, "burst") || strings.Count(section, "type=") != 1 || !meterDropRE.MatchString(section) || len(r) != 1 || strings.Count(section, "rate=") != 1 || r[0][1] != strconv.Itoa(rate) {
				return ErrUnavailable
			}
		}
	}
	if exact && len(seen) != len(want) {
		return ErrUnavailable
	}
	// Text other than the standard reply header must describe a real meter.
	if len(locations) == 0 {
		for _, line := range strings.Split(text, "\n") {
			s := strings.TrimSpace(line)
			if s != "" && !strings.HasPrefix(s, "OFPST_METER_CONFIG reply") && !strings.HasPrefix(s, "OFPMP_METER_CONFIG reply") {
				return ErrUnavailable
			}
		}
	}
	return nil
}

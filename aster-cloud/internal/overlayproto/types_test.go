package overlayproto

import (
	"aster/cloud/internal/nodeproto"
	"encoding/json"
	"strings"
	"testing"
)

func fixture() Snapshot {
	instance := strings.Repeat("a", 32)
	owner := strings.Repeat("b", 32)
	vpc := strings.Repeat("c", 32)
	return Snapshot{Protocol: Protocol, ClusterID: "test-cluster", Epoch: 1, Profiles: []ProfilePin{{"node-a", "private", strings.Repeat("d", 64)}, {"node-b", "private", strings.Repeat("e", 64)}}, VPCs: []VPC{{vpc, owner, "10.24.0.0/24", 100}}, Members: []Member{{NodeID: "node-a", InstanceID: instance, InterfaceID: nodeproto.NetworkInterfaceID(instance), OwnerRef: owner, VPCID: vpc, LocalVPCID: strings.Repeat("d", 32), LeaseID: strings.Repeat("e", 32), PoolID: strings.Repeat("f", 32), NetworkSHA256: strings.Repeat("f", 64), IPv4: "10.24.0.2", MAC: nodeproto.NetworkMAC("node-a", instance), InboundMbps: 20, OutboundMbps: 10, Enabled: true}}, Gateways: []Gateway{}}
}
func TestSnapshotCanonicalAndStrictContract(t *testing.T) {
	s, sha, e := CanonicalSnapshot(fixture())
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(s)
	decoded, e := DecodeSnapshot(b)
	if e != nil || decoded.ClusterID != s.ClusterID || Digest(b) != sha {
		t.Fatal(e)
	}
	for _, edit := range []func(string) string{func(s string) string { return strings.Replace(s, `"epoch":1`, `"epoch":1,"epoch":2`, 1) }, func(s string) string { return strings.Replace(s, `"epoch":1`, `"Epoch":1`, 1) }, func(s string) string { return strings.Replace(s, `"gateways":[]`, `"gateways":null`, 1) }, func(s string) string {
		return strings.Replace(s, `"protocol":"aster.overlay/1"`, `"protocol":"aster.node/2"`, 1)
	}, func(s string) string { return strings.Replace(s, `"previous_sha256":"",`, ``, 1) }} {
		if _, e := DecodeSnapshot([]byte(edit(string(b)))); e == nil {
			t.Fatal("ambiguous input accepted")
		}
	}
	original := fixture()
	reverse := fixture()
	reverse.Profiles[0], reverse.Profiles[1] = reverse.Profiles[1], reverse.Profiles[0]
	_, a, _ := CanonicalSnapshot(original)
	_, c, _ := CanonicalSnapshot(reverse)
	if a != c || reverse.Profiles[0].NodeID != "node-b" {
		t.Fatal("not canonical or mutated caller")
	}
}
func TestSnapshotRejectsConfusedIdentities(t *testing.T) {
	cases := map[string]func(*Snapshot){"owner": func(s *Snapshot) { s.Members[0].OwnerRef = strings.Repeat("c", 32) }, "mac": func(s *Snapshot) { s.Members[0].MAC = "52:54:00:01:02:03" }, "vni": func(s *Snapshot) { s.VPCs[0].VNI = 16777216 }, "broadcast": func(s *Snapshot) { s.Members[0].IPv4 = "10.24.0.255" }, "network": func(s *Snapshot) { s.Members[0].IPv4 = "10.24.0.0" }, "foreign_ip": func(s *Snapshot) { s.Members[0].IPv4 = "10.25.0.2" }, "duplicate": func(s *Snapshot) { s.Members = append(s.Members, s.Members[0]) }, "missing_profile": func(s *Snapshot) { s.Members[0].NodeID = "node-c" }, "zero_meter": func(s *Snapshot) { s.Members[0].InboundMbps = 0 }, "missing_binding": func(s *Snapshot) { s.Members[0].NetworkSHA256 = "" }, "bad_local_vpc": func(s *Snapshot) { s.Members[0].LocalVPCID = "" }, "legacy_epoch": func(s *Snapshot) { s.Epoch = 0 }, "unbound_epoch": func(s *Snapshot) { s.Epoch = 2 }, "extra_profile": func(s *Snapshot) { s.Profiles = append(s.Profiles, s.Profiles[0]) }}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			s := fixture()
			edit(&s)
			if _, _, e := CanonicalSnapshot(s); e == nil {
				t.Fatal("accepted")
			}
		})
	}
}
func TestGatewayPrefixAndIdentityAdmission(t *testing.T) {
	s := fixture()
	g := Gateway{NodeID: "node-a", InstanceID: strings.Repeat("1", 32), InterfaceID: nodeproto.NetworkInterfaceID(strings.Repeat("1", 32)), OwnerRef: s.VPCs[0].OwnerRef, VPCID: s.VPCs[0].ID, IPv4: "10.24.0.1", MAC: "52:54:00:00:00:01", AllowedPrefixes: []string{"192.0.2.0/24"}}
	s.Gateways = []Gateway{g}
	if _, _, e := CanonicalSnapshot(s); e != nil {
		t.Fatal(e)
	}
	for _, prefix := range []string{"0.0.0.0/0", "10.24.0.0/24", "192.0.2.1/24", "::/0"} {
		s.Gateways[0].AllowedPrefixes = []string{prefix}
		if _, _, e := CanonicalSnapshot(s); e == nil {
			t.Fatal("unsafe route", prefix)
		}
	}
	s.Gateways[0] = g
	s.Gateways[0].IPv4 = s.Members[0].IPv4
	if _, _, e := CanonicalSnapshot(s); e == nil {
		t.Fatal("gateway/member IP alias")
	}
}
func TestTaskReceiptAndRecoveryHeads(t *testing.T) {
	s, sha, e := CanonicalSnapshot(fixture())
	if e != nil {
		t.Fatal(e)
	}
	task := Task{Protocol: Protocol, OperationID: strings.Repeat("1", 32), NodeID: "node-a", Phase: "prepare", Snapshot: s, SnapshotSHA256: sha}
	raw, requestSHA, e := task.BytesAndDigest()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = DecodeTask(raw); e != nil {
		t.Fatal(e)
	}
	r := Receipt{Protocol: Protocol, OperationID: task.OperationID, NodeID: task.NodeID, ClusterID: s.ClusterID, Epoch: s.Epoch, Phase: task.Phase, SnapshotSHA256: sha, RequestSHA256: requestSHA, Status: "succeeded", Code: "PREPARED"}
	if !r.Matches(task, requestSHA) {
		t.Fatal("exact receipt rejected")
	}
	r.Epoch++
	if r.Matches(task, requestSHA) {
		t.Fatal("wrong epoch accepted")
	}
	if _, e = DecodeTask(append([]byte(" "), raw...)); e == nil {
		t.Fatal("noncanonical task accepted")
	}
	task.Snapshot.Epoch = 2
	task.Snapshot.PreviousSHA256 = sha
	task.Snapshot, task.SnapshotSHA256, _ = CanonicalSnapshot(task.Snapshot)
	task.Recovery = &Recovery{Epoch: 1, SnapshotSHA256: sha, Heads: []Head{{NodeID: "node-b"}, {NodeID: "node-a", ClusterID: s.ClusterID, Epoch: 1, SnapshotSHA256: sha}}}
	raw, _, e = task.BytesAndDigest()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = DecodeTask(raw); e != nil {
		t.Fatal(e)
	}
	for _, edit := range []func(*Task){func(t *Task) { t.Recovery.Heads[0].Epoch = 3 }, func(t *Task) { t.Recovery.Heads[1].ClusterID = "foreign" }, func(t *Task) { t.Recovery.Heads = t.Recovery.Heads[:1] }, func(t *Task) { t.Recovery.SnapshotSHA256 = strings.Repeat("0", 64) }} {
		bad, _ := DecodeTask(raw)
		edit(&bad)
		if _, _, e = bad.BytesAndDigest(); e == nil {
			t.Fatal("unbound recovery accepted")
		}
	}
	for _, phase := range []string{"prepare", "program", "release"} {
		if PhaseOperationID(strings.Repeat("1", 32), "node-a", phase) == PhaseOperationID(strings.Repeat("1", 32), "node-b", phase) {
			t.Fatal("cross node replay")
		}
	}
}

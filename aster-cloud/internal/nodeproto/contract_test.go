package nodeproto

import (
	"aster/billing/controllerapi"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func fixture() NodeTask {
	return NodeTask{Protocol: Protocol, OperationID: strings.Repeat("1", 32), InstanceID: strings.Repeat("2", 32), OwnerRef: strings.Repeat("3", 32), NodeID: "node-a", Action: "create", Hostname: "vm-a", Resources: controllerapi.Resources{ImageID: "ubuntu22", CPUCores: 1, MemoryMiB: 512, SystemDiskGiB: 10, SystemStorageID: "local", NetworkType: "normal", TrafficDirection: "all", IPv4Count: 1}}
}
func TestExactContractAndDigest(t *testing.T) {
	task := fixture()
	raw, sha, e := task.BytesAndDigest()
	if e != nil {
		t.Fatal(e)
	}
	decoded, e := DecodeTask(raw)
	if e != nil || decoded != task {
		t.Fatal(e, string(raw))
	}
	r := NodeResult{Protocol: Protocol, OperationID: task.OperationID, InstanceID: task.InstanceID, RequestSHA256: sha, Status: "accepted"}
	if !r.Matches(task, sha) {
		t.Fatal("valid result mismatch")
	}
	if Digest(append(raw, ' ')) == sha {
		t.Fatal("digest must bind exact bytes")
	}
	r.Status = "paid"
	if r.Matches(task, sha) {
		t.Fatal("invented status accepted")
	}
}
func TestRejectAmbiguousWire(t *testing.T) {
	task := fixture()
	raw, _, _ := task.BytesAndDigest()
	s := string(raw)
	cases := map[string]string{"duplicate": strings.Replace(s, `"protocol":`, `"protocol":"aster.node/1","protocol":`, 1), "nestedduplicate": strings.Replace(s, `"cpu_cores":1`, `"cpu_cores":1,"cpu_cores":2`, 1), "wrongcase": strings.Replace(s, `"operation_id"`, `"Operation_ID"`, 1), "nestedcase": strings.Replace(s, `"cpu_cores"`, `"CPU_Cores"`, 1), "unknown": strings.TrimSuffix(s, "}") + `,"shell":"id"}`, "null": strings.Replace(s, `"ipv6_count":0`, `"ipv6_count":null`, 1), "missing": strings.Replace(s, `"ipv6_count":0`, `"different":0`, 1), "trailing": s + "{}", "oversize": s + strings.Repeat(" ", 65536), "array": "[" + s + "]"}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, e := DecodeTask([]byte(raw)); e == nil {
				t.Fatal("ambiguous task accepted")
			}
		})
	}
}
func TestRejectMissingRequiredResourceEvenZero(t *testing.T) {
	raw, _, _ := fixture().BytesAndDigest()
	var m map[string]json.RawMessage
	_ = json.Unmarshal(raw, &m)
	var r map[string]any
	_ = json.Unmarshal(m["resources"], &r)
	delete(r, "data_disk_gib")
	m["resources"], _ = json.Marshal(r)
	raw, _ = json.Marshal(m)
	if _, e := DecodeTask(raw); e == nil {
		t.Fatal("missing zero-valued field accepted")
	}
}
func TestStrictIDsActionsAndDelete(t *testing.T) {
	for _, id := range []string{"0", "1", "../../vm", strings.Repeat("A", 32), strings.Repeat("0", 31)} {
		x := fixture()
		x.InstanceID = id
		if x.Valid() {
			t.Fatal("unsafe id", id)
		}
	}
	x := fixture()
	x.Action = "delete"
	if x.Valid() {
		t.Fatal("unconfirmed delete")
	}
	x.ConfirmInstanceID = x.InstanceID
	if !x.Valid() {
		t.Fatal("confirmed delete invalid")
	}
	x.Action = "create"
	if x.Valid() {
		t.Fatal("unexpected confirm allowed")
	}
	x = fixture()
	x.Hostname = "host\n;id"
	if x.Valid() {
		t.Fatal("hostname accepted")
	}
}

func TestApprovedStaticIPv4CapabilityFixture(t *testing.T) {
	raw, e := os.ReadFile("testdata/capabilities-approved-static-ipv4.json")
	if e != nil {
		t.Fatal(e)
	}
	var c Capabilities
	if e = json.Unmarshal(raw, &c); e != nil {
		t.Fatal(e)
	}
	if c.Protocol != Protocol || c.Maintenance || len(c.NetworkProfiles) != 1 || c.NetworkProfiles[0] != "normal-static-ipv4-dedicated-bridge" || len(c.IPv4Counts) != 1 || c.IPv4Counts[0] != 1 || len(c.IPv6Counts) != 1 || c.IPv6Counts[0] != 0 {
		t.Fatal(c)
	}
}

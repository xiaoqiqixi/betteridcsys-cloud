package nodeproto

import (
	"aster/billing/controllerapi"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func networkTask() NodeTask {
	t := NodeTask{Protocol: NetworkProtocol, OperationID: strings.Repeat("1", 32), InstanceID: strings.Repeat("2", 32), NodeID: "n1", OwnerRef: strings.Repeat("3", 32), Hostname: "vm-a", Action: "create", Resources: controllerapi.Resources{NetworkType: "vpc", IPv4Count: 1, BandwidthMbps: 100, InboundBandwidthMbps: 50, TrafficDirection: "all"}}
	t.Network = NetworkBinding{Schema: 1, ProfileID: "private-v1", ProfileSHA256: strings.Repeat("a", 64), LeaseID: strings.Repeat("4", 32), PoolID: strings.Repeat("5", 32), VPCID: strings.Repeat("6", 32), NodeID: t.NodeID, OwnerRef: t.OwnerRef, InstanceID: t.InstanceID, CIDR: "10.8.0.0/24", IPv4: "10.8.0.2", MAC: NetworkMAC(t.NodeID, t.InstanceID), InterfaceID: NetworkInterfaceID(t.InstanceID), VLANID: 10, InboundMbps: 50, OutboundMbps: 100}
	return t
}
func TestNetworkTaskExplicitVersionAndFrozenBinding(t *testing.T) {
	task := networkTask()
	raw, sha, e := task.BytesAndDigest()
	if e != nil {
		t.Fatal(e)
	}
	got, e := DecodeTask(raw)
	if e != nil || got != task {
		t.Fatal(got, e)
	}
	result := NodeResult{Protocol: NetworkProtocol, OperationID: task.OperationID, InstanceID: task.InstanceID, RequestSHA256: sha, Status: "accepted"}
	if !result.Matches(task, sha) {
		t.Fatal("new result rejected")
	}
	result.Protocol = Protocol
	if result.Matches(task, sha) {
		t.Fatal("old protocol accepted")
	}
	old := task
	old.Network = NetworkBinding{}
	old.Protocol = Protocol
	raw, _, e = old.BytesAndDigest()
	if e != nil || bytes.Contains(raw, []byte(`"network":`)) {
		t.Fatal("legacy wire changed", string(raw), e)
	}
	var fields map[string]any
	_ = json.Unmarshal(raw, &fields)
	if len(fields) != 8 {
		t.Fatal(fields)
	}
	old.Network = task.Network
	if old.Valid() {
		t.Fatal("legacy network binding accepted")
	}
	task.Network = NetworkBinding{}
	if task.Valid() {
		t.Fatal("new task without binding")
	}
}
func TestNetworkTaskRejectsEveryAmbiguousBinding(t *testing.T) {
	task := networkTask()
	raw, _, _ := task.BytesAndDigest()
	for _, field := range []string{"schema", "profile_id", "profile_sha256", "lease_id", "pool_id", "vpc_id", "node_id", "owner_ref", "instance_id", "cidr", "ipv4", "mac", "interface_id", "vlan_id", "inbound_mbps", "outbound_mbps"} {
		for _, mode := range []string{"missing", "null", "wrong-case", "duplicate"} {
			t.Run(field+"/"+mode, func(t *testing.T) {
				var root map[string]json.RawMessage
				_ = json.Unmarshal(raw, &root)
				var n map[string]json.RawMessage
				_ = json.Unmarshal(root["network"], &n)
				v := n[field]
				switch mode {
				case "missing":
					delete(n, field)
				case "null":
					n[field] = json.RawMessage("null")
				case "wrong-case":
					delete(n, field)
					n[strings.ToUpper(field)] = v
				}
				b, _ := json.Marshal(n)
				if mode == "duplicate" {
					b = append(b[:len(b)-1], []byte(`,"`+field+`":`+string(v)+`}`)...)
				}
				root["network"] = b
				bad, _ := json.Marshal(root)
				if _, err := DecodeTask(bad); err == nil {
					t.Fatal("accepted ambiguous network", string(bad))
				}
			})
		}
	}
	for name, change := range map[string]func(*NodeTask){"other owner": func(t *NodeTask) { t.Network.OwnerRef = strings.Repeat("9", 32) }, "other node": func(t *NodeTask) { t.Network.NodeID = "n2" }, "other instance": func(t *NodeTask) { t.Network.InstanceID = strings.Repeat("8", 32) }, "public CIDR": func(t *NodeTask) { t.Network.CIDR = "8.8.8.0/24"; t.Network.IPv4 = "8.8.8.2" }, "noncanonical": func(t *NodeTask) { t.Network.CIDR = "10.8.0.1/24" }, "broadcast": func(t *NodeTask) { t.Network.IPv4 = "10.8.0.255" }, "default rate": func(t *NodeTask) { t.Network.InboundMbps = 0; t.Resources.InboundBandwidthMbps = 0 }, "rate drift": func(t *NodeTask) { t.Resources.InboundBandwidthMbps++ }, "normal": func(t *NodeTask) { t.Resources.NetworkType = "normal" }, "wrong mac": func(t *NodeTask) { t.Network.MAC = "52:54:00:01:02:03" }, "wrong UUID": func(t *NodeTask) { t.Network.InterfaceID = "e" + t.Network.InterfaceID[1:] }, "unbound config": func(t *NodeTask) { t.Network.ProfileSHA256 = "" }} {
		t.Run(name, func(t *testing.T) {
			v := networkTask()
			change(&v)
			if v.Valid() {
				t.Fatal("invalid binding accepted")
			}
		})
	}
}

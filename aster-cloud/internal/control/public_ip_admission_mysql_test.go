package control

import (
	"aster/cloud/internal/nodeproto"
	"aster/cloud/internal/overlayproto"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// Both clusters share one actual MySQL controller. Their separate dedicated
// profiles deliberately use overlapping private CIDRs but distinct public NAT
// sources, exercising the global public-IP proof rather than a fake second DB.
func mysqlPublicIPTwoClusterAdmissionFixture(t *testing.T) (overlayFixture, OverlayEpoch, OverlayEpoch) {
	t.Helper()
	f := mysqlOverlayFixture(t)
	ctx := context.Background()
	original := f.config.OverlayClusters[0]
	first := original
	first.Profiles = append([]overlayproto.ProfilePin{}, original.Profiles[:1]...)
	first.Mappings = append([]OverlayMapping{}, original.Mappings[:1]...)
	second := OverlayCluster{ClusterID: "cluster-other", Profiles: append([]overlayproto.ProfilePin{}, original.Profiles[1:]...)}
	f.config.OverlayClusters = []OverlayCluster{first, second}
	other, _, err := f.store.CreateOverlayVPC(ctx, f.config, f.actor, id(), OverlayVPCInput{ClusterID: second.ClusterID, OwnerRef: f.vpc.OwnerRef, Name: "other cluster", CIDR: f.vpc.CIDR, VNI: 502}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	otherMapping := original.Mappings[1]
	otherMapping.VPCID = other.ID
	f.config.OverlayClusters[1].Mappings = []OverlayMapping{otherMapping}
	gateway, policies := f.approveInternetNAT(t)
	otherGateway := gateway
	otherGateway.NodeID = f.config.Nodes[1].ID
	otherGateway.InstanceID = id()
	otherGateway.InterfaceID = nodeproto.NetworkInterfaceID(otherGateway.InstanceID)
	otherGateway.MAC = nodeproto.NetworkMAC(otherGateway.NodeID, otherGateway.InstanceID)
	otherGateway.VPCID = other.ID
	otherRoot := f.config.OverlayClusters[0].NATProfiles[0]
	otherRoot.NodeID = otherGateway.NodeID
	otherRoot.VPCID = other.ID
	otherRoot.GatewayInstanceID = otherGateway.InstanceID
	otherRoot.ProfileID = "approved-nat-other"
	otherRoot.ProfileSHA256 = strings.Repeat("b", 64)
	otherRoot.PublicIPv4 = "9.9.9.9"
	f.config.OverlayClusters[1].Gateways = []overlayproto.Gateway{otherGateway}
	f.config.OverlayClusters[1].NATProfiles = []OverlayNATProfile{otherRoot}
	if !f.config.Valid() {
		t.Fatal("invalid independent-cluster root config")
	}
	firstMembers := append([]OverlayMemberInput{}, f.members[:1]...)
	otherMember := f.members[1]
	otherMember.VPCID = other.ID
	firstEpoch, _, err := f.store.PlanOverlayEpoch(ctx, f.config, f.actor, id(), OverlayEpochInput{ClusterID: f.vpc.ClusterID, Members: firstMembers, Gateways: []overlayproto.Gateway{gateway}, NATPolicies: &policies}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	rpc := &overlayFakeRPC{}
	w := f.worker(rpc)
	advanceOverlayFixture(t, w, firstEpoch.ID)
	otherPolicy := policies[0]
	otherPolicy.ID = id()
	otherPolicy.NodeID = otherGateway.NodeID
	otherPolicy.VPCID = other.ID
	otherPolicy.GatewayInstanceID = otherGateway.InstanceID
	otherPolicy.ProfileID = otherRoot.ProfileID
	otherPolicy.ProfileSHA256 = otherRoot.ProfileSHA256
	otherPolicies := []overlayproto.NATPolicy{otherPolicy}
	otherEpoch, _, err := f.store.PlanOverlayEpoch(ctx, f.config, f.actor, id(), OverlayEpochInput{ClusterID: second.ClusterID, Members: []OverlayMemberInput{otherMember}, Gateways: []overlayproto.Gateway{otherGateway}, NATPolicies: &otherPolicies}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	advanceOverlayFixture(t, w, otherEpoch.ID)
	return f, firstEpoch, otherEpoch
}
func TestMySQLPublicIPAdmissionUsesAllRootClustersWithoutWeakeningGlobalIsolation(t *testing.T) {
	for _, kind := range []string{"billing", "console"} {
		for _, scenario := range []string{"different_public_ips", "same_public_ip", "missing_other_root_context", "unknown_other_root_pin"} {
			t.Run(kind+"/"+scenario, func(t *testing.T) {
				f, firstEpoch, otherEpoch := mysqlPublicIPTwoClusterAdmissionFixture(t)
				ctx := context.Background()
				originalTask, err := nodeproto.DecodeTask(f.jobs[0].NodeRequest)
				if err != nil {
					t.Fatal(err)
				}
				addresses, _ := json.Marshal([]string{originalTask.Network.IPv4, "10.25.0.30"})
				if _, err = f.store.DB.Exec("UPDATE controller_network_pools SET addresses=? WHERE id=?", addresses, originalTask.Network.PoolID); err != nil {
					t.Fatal(err)
				}
				firstSnapshot, _ := json.Marshal(firstEpoch.Snapshot)
				otherSnapshot, _ := json.Marshal(otherEpoch.Snapshot)
				firstTasks, err := f.store.OverlayTasks(ctx, firstEpoch.ID)
				if err != nil {
					t.Fatal(err)
				}
				otherTasks, err := f.store.OverlayTasks(ctx, otherEpoch.ID)
				if err != nil {
					t.Fatal(err)
				}
				firstReceiptBytes, _ := json.Marshal(firstTasks)
				otherReceiptBytes, _ := json.Marshal(otherTasks)
				switch scenario {
				case "same_public_ip":
					// Root-approved projections can introduce a collision after older implicit
					// epochs were stored. Admission must inspect the other cluster's live NAT,
					// not infer that current-cluster approval makes a public source exclusive.
					f.config.OverlayClusters[0].NATProfiles[0].PublicIPv4 = "9.9.9.9"
				case "missing_other_root_context":
					f.config.OverlayClusters = append([]OverlayCluster{}, f.config.OverlayClusters[:1]...)
				case "unknown_other_root_pin":
					f.config.OverlayClusters[1].NATProfiles[0].ProfileSHA256 = strings.Repeat("f", 64)
				}
				if !f.config.Valid() {
					t.Fatal("invalid test root config")
				}
				p, _ := f.config.Node(originalTask.NodeID)
				request := mysqlVPCRequest(p, originalTask.OwnerRef)
				financialBefore, financialSHA, err := request.BytesAndDigest()
				if err != nil {
					t.Fatal(err)
				}
				candidates := f.config.Candidates(request)
				if len(candidates) != 1 || candidates[0].Overlay == nil || len(candidates[0].Overlay.RootClusters) != len(f.config.OverlayClusters) {
					t.Fatal("candidate lost complete root context")
				}
				admissionRaw, _ := json.Marshal(candidates[0].Overlay)
				if bytes.Contains(admissionRaw, []byte("RootClusters")) || bytes.Contains(admissionRaw, []byte("root_clusters")) || bytes.Contains(admissionRaw, []byte("cluster-other")) {
					t.Fatal("global resolution context became serializable")
				}
				tables := []string{"controller_instances", "controller_jobs", "controller_operations", "controller_overlay_epochs", "controller_instance_networks", "controller_network_leases", "controller_reservations", "controller_overlay_members", "controller_overlay_tasks", "controller_audit"}
				countsBefore := make([]int, len(tables))
				for i, table := range tables {
					if err = f.store.DB.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&countsBefore[i]); err != nil {
						t.Fatal(err)
					}
				}
				var operationID, instanceID string
				var nodeRequest []byte
				if kind == "billing" {
					job, replay, e := f.store.Admit(ctx, request, candidates, f.now, time.Minute)
					err = e
					if err == nil {
						if replay || job.RequestSHA != financialSHA || !bytes.Equal(job.RequestJSON, financialBefore) {
							t.Fatal("financial request bytes changed during admission")
						}
						operationID, instanceID, nodeRequest = job.OperationID, job.InstanceID, job.NodeRequest
					}
				} else {
					preset := ""
					for _, v := range f.config.Presets {
						if v.NodeID == p.ID {
							preset = v.ID
						}
					}
					op, replay, e := f.store.CreateInstance(ctx, f.config, f.actor, id(), CreateInstanceInput{OwnerRef: originalTask.OwnerRef, Hostname: "public-ip-reserved", PresetID: preset}, f.now)
					err = e
					if err == nil {
						if replay {
							t.Fatal("unexpected console replay")
						}
						operationID, instanceID, nodeRequest = op.ID, op.InstanceID, op.Request
					}
				}
				if scenario == "different_public_ips" {
					if err != nil {
						t.Fatal("unrelated approved public NAT blocked admission", err)
					}
					task, e := nodeproto.DecodeTask(nodeRequest)
					if e != nil || task.Protocol != nodeproto.NetworkProtocol || task.Network.IPv4 != "10.25.0.30" || task.NodeID != originalTask.NodeID || task.OwnerRef != originalTask.OwnerRef {
						t.Fatal("node/2 binding changed", e)
					}
					canonical, sha, e := task.BytesAndDigest()
					if e != nil || !bytes.Equal(canonical, nodeRequest) || nodeproto.Digest(nodeRequest) != sha {
						t.Fatal("node request was not original canonical bytes", e)
					}
					admissionID := overlayproto.Digest([]byte("aster.overlay.admission/1:" + operationID))[:32]
					epoch, e := f.store.OverlayEpoch(ctx, admissionID)
					if e != nil || epoch.ClusterID != firstEpoch.ClusterID || epoch.Epoch != 2 || len(epoch.Snapshot.Members) != 2 || len(epoch.Snapshot.Profiles) != 1 {
						t.Fatal("wrong scoped reservation epoch", e)
					}
					found := false
					for _, m := range epoch.Snapshot.Members {
						if m.InstanceID == instanceID {
							found = m.Reserved && m.Enabled && m.NetworkSHA256 == task.Network.Digest()
						}
					}
					if !found {
						t.Fatal("new member not reserved before node dispatch")
					}
					before, _ := json.Marshal(firstEpoch.Snapshot.NATPolicies)
					after, _ := json.Marshal(epoch.Snapshot.NATPolicies)
					if !bytes.Equal(before, after) {
						t.Fatal("admission rewrote inherited NAT intent")
					}
				} else {
					if !errors.Is(err, ErrState) {
						t.Fatal("public IP collision or unresolved foreign root admitted", err)
					}
					for i, table := range tables {
						var n int
						if e := f.store.DB.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); e != nil || n != countsBefore[i] {
							t.Fatal("rejected admission persisted partial state", table, n, e)
						}
					}
				}
				for _, old := range []struct {
					epoch              OverlayEpoch
					snapshot, receipts []byte
				}{{firstEpoch, firstSnapshot, firstReceiptBytes}, {otherEpoch, otherSnapshot, otherReceiptBytes}} {
					saved, e := f.store.OverlayEpoch(ctx, old.epoch.ID)
					snapshot, _ := json.Marshal(saved.Snapshot)
					tasks, e2 := f.store.OverlayTasks(ctx, old.epoch.ID)
					receipts, _ := json.Marshal(tasks)
					if e != nil || e2 != nil || !bytes.Equal(snapshot, old.snapshot) || !bytes.Equal(receipts, old.receipts) {
						t.Fatal("admission rewrote existing epoch bytes or receipts", e, e2)
					}
				}
				assertOriginalOverlayJobs(t, f)
			})
		}
	}
}

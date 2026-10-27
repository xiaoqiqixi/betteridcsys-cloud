package hypervisor

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func configureDirect(t *testing.T, m *Manager, task nodeproto.NodeTask) nodeproto.NodeTask {
	t.Helper()
	m.Config.Network.RequirePublicLease = true
	m.hostIPv4s = func() ([]string, error) { return []string{"127.0.0.1", "9.9.9.1"}, nil }
	if f, ok := m.Runner.(*fakeRunner); ok {
		f.filter = DirectApprovedFilterXML(m.Config.Network.Filter)
		m.Config.Network.FilterSHA256 = nodeproto.Digest(f.filter)
	}
	m.Config.Network.CIDR = "8.8.8.0/24"
	m.Config.Network.Gateway = "8.8.8.1"
	m.Config.Network.Addresses = []string{"8.8.8.8", "8.8.8.9"}
	m.Config.Network.DNS = []string{"8.8.4.4"}
	sha, e := DirectNetworkSHA256(m.Config.Network)
	if e != nil {
		t.Fatal(e)
	}
	task.Protocol = nodeproto.DirectPublicProtocol
	task.DirectPublic = nodeproto.DirectPublicBinding{Generation: 1, Schema: 1, LeaseID: strings.Repeat("8", 32), PoolID: strings.Repeat("9", 32), NodeID: task.NodeID, OwnerRef: task.OwnerRef, InstanceID: task.InstanceID, ProfileID: nodeproto.DirectPublicProfile, ProfileSHA256: sha, CIDR: m.Config.Network.CIDR, Gateway: m.Config.Network.Gateway, IPv4: "8.8.8.9", MAC: nodeproto.NetworkMAC(task.NodeID, task.InstanceID)}
	return task
}
func TestDirectPublicCreatesExactGuestAddressAndFencesDetachedLegacyBoot(t *testing.T) {
	m, f, task := newFixture(t)
	task = configureDirect(t, m, task)
	if r := submit(t, m, task); r.Status != "succeeded" {
		op, _ := m.Ledger.Query(task.OperationID)
		t.Fatal(r, op.ErrorCode)
	}
	i, _ := m.Ledger.Instance(task.InstanceID)
	if i.IPv4 != "8.8.8.9" || i.DirectPublic != task.DirectPublic {
		t.Fatal("node chose first-free instead of exact lease", i)
	}
	raw, e := os.ReadFile(filepath.Join(i.Directory, "network-config"))
	if e != nil || !strings.Contains(string(raw), "8.8.8.9/24") || !strings.Contains(string(raw), "8.8.8.1") {
		t.Fatal("guest did not receive actual public address", e, string(raw))
	}
	var d domainXML
	if e = xml.Unmarshal(f.domains[i.Domain], &d); e != nil || d.Metadata.Instance.DirectPublicSHA256 != task.DirectPublic.Digest() || d.Devices.Interfaces[0].Filter == nil {
		t.Fatal("unbound direct NIC", e)
	}
	if r := submit(t, m, next(task, "4", "force_off")); r.Status != "succeeded" {
		t.Fatal(r)
	}
	detach := next(task, "5", "public_detach")
	detach.ConfirmInstanceID = task.InstanceID
	if r := submit(t, m, detach); r.Status != "succeeded" {
		op, _ := m.Ledger.Query(detach.OperationID)
		t.Fatal(r, op.ErrorCode)
	}
	i, _ = m.Ledger.Instance(i.ID)
	if !i.DirectPublicDetached {
		t.Fatal("missing durable detach tombstone")
	}
	d = domainXML{}
	if e = xml.Unmarshal(f.domains[i.Domain], &d); e != nil || d.Devices.Interfaces[0].Link.State != "down" {
		t.Fatal("detached NIC not really down", e)
	}
	if r := submit(t, m, next(task, "6", "start")); r.Status != "rejected" {
		t.Fatal("detached node3 booted", r)
	}
	legacy := next(task, "7", "start")
	legacy.Protocol = nodeproto.Protocol
	legacy.DirectPublic = nodeproto.DirectPublicBinding{}
	if r := submit(t, m, legacy); r.Status != "rejected" {
		t.Fatal("legacy task bypassed detached fence", r)
	}
	adopt := next(task, "a", "public_adopt")
	adopt.DirectPublic.Generation++
	adopt.ConfirmInstanceID = task.InstanceID
	if r := submit(t, m, adopt); r.Status != "succeeded" {
		t.Fatal(r)
	}
	task.DirectPublic = adopt.DirectPublic
	if r := submit(t, m, next(task, "b", "start")); r.Status != "succeeded" {
		t.Fatal(r)
	}
}
func TestDirectPublicRequireLeaseLegacyCleanupAndExactAdoption(t *testing.T) {
	m, f, legacy := newFixture(t)
	direct := configureDirect(t, m, legacy)
	m.Config.Network.RequirePublicLease = false
	f.filter = ApprovedFilterXML(m.Config.Network.Filter)
	m.Config.Network.FilterSHA256 = nodeproto.Digest(f.filter)
	if r := submit(t, m, legacy); r.Status != "succeeded" {
		t.Fatal(r)
	}
	m.Config.Network.RequirePublicLease = true
	f.filter = DirectApprovedFilterXML(m.Config.Network.Filter)
	m.Config.Network.FilterSHA256 = nodeproto.Digest(f.filter)
	if r := submit(t, m, next(legacy, "4", "force_off")); r.Status != "succeeded" {
		t.Fatal("safe cleanup forbidden", r)
	}
	if r := submit(t, m, next(legacy, "5", "start")); r.Status != "rejected" {
		t.Fatal("unleased legacy guest booted", r)
	}
	i, _ := m.Ledger.Instance(legacy.InstanceID)
	direct.DirectPublic.IPv4 = i.IPv4
	direct.DirectPublic.MAC = i.MAC
	adopt := next(direct, "6", "public_adopt")
	adopt.ConfirmInstanceID = i.ID
	if r := submit(t, m, adopt); r.Status != "succeeded" {
		op, _ := m.Ledger.Query(adopt.OperationID)
		t.Fatal(r, op.ErrorCode)
	}
	if r := submit(t, m, next(direct, "7", "start")); r.Status != "succeeded" {
		t.Fatal(r)
	}
}
func TestDirectPublicRejectsChangedRootAndConflictingAddress(t *testing.T) {
	for _, kind := range []string{"root", "not_approved", "duplicate", "running_adopt"} {
		t.Run(kind, func(t *testing.T) {
			m, f, task := newFixture(t)
			task = configureDirect(t, m, task)
			switch kind {
			case "root":
				m.Config.Network.DNS = []string{"1.1.1.1"}
			case "not_approved":
				task.DirectPublic.IPv4 = "8.8.8.10"
			case "duplicate", "running_adopt":
				if r := submit(t, m, task); r.Status != "succeeded" {
					t.Fatal(r)
				}
				if kind == "duplicate" {
					task.InstanceID = strings.Repeat("a", 32)
					task.DirectPublic.InstanceID = task.InstanceID
					task.DirectPublic.MAC = nodeproto.NetworkMAC(task.NodeID, task.InstanceID)
					task.Hostname = "vm-b"
				} else {
					task.Action = "public_adopt"
					task.ConfirmInstanceID = task.InstanceID
				}
			}
			task.OperationID = strings.Repeat("b", 32)
			before := f.count(" define ")
			if r := submit(t, m, task); r.Status != "rejected" {
				op, _ := m.Ledger.Query(task.OperationID)
				t.Fatal(r, op.ErrorCode)
			}
			if f.count(" define ") != before {
				t.Fatal("rejected binding rewrote XML")
			}
		})
	}
}
func TestDirectPublicMigrationPreservesAddressMACAndSourceLinkFence(t *testing.T) {
	source, sf, task := newStorageFixture(t, "node-a")
	task = configureDirect(t, source, task)
	createOff(t, source, task)
	export := storageTask(task, 10, "migrate_prepare", 100)
	export.Protocol = nodeproto.StorageDirectProtocol
	export.DirectPublic = task.DirectPublic
	export.TargetNodeID = "node-b"
	receipt := assertStorageStatus(t, source, export, "succeeded")
	var d domainXML
	i, _ := source.Ledger.Instance(task.InstanceID)
	if xml.Unmarshal(sf.domains[i.Domain], &d) != nil || d.Devices.Interfaces[0].Link.State != "down" {
		t.Fatal("source public NIC was not fenced")
	}
	target, tf, targetTask := newStorageFixture(t, "node-b")
	_ = configureDirect(t, target, targetTask)
	imp := handoffFixture(t, source, target, export, receipt)
	imp.Protocol = nodeproto.StorageDirectProtocol
	imp.DirectPublic = task.DirectPublic
	imp.DirectPublic.NodeID = target.Config.NodeID
	imp.DirectPublic.Generation++
	if e := target.approveInbox(context.Background(), imp.ArtifactID, imp.FenceToken); e != nil {
		t.Fatal(e)
	}
	assertStorageStatus(t, target, imp, "succeeded")
	dst, _ := target.Ledger.Instance(task.InstanceID)
	if dst.IPv4 != i.IPv4 || dst.MAC != i.MAC || !nodeproto.SameDirectAddress(dst.DirectPublic, i.DirectPublic) {
		t.Fatal("migration rotated public identity", dst, i)
	}
	activate := imp
	activate.OperationID = fmt.Sprintf("%032x", 22)
	activate.Action = "migrate_activate"
	activate.ConfirmArtifactID = activate.ArtifactID
	assertStorageStatus(t, target, activate, "succeeded")
	if tf.count(" start ") != 1 || sf.count(" start ") != 1 {
		t.Fatal("migration double start")
	}
	if r := submit(t, source, next(task, "7", "start")); r.Status != "rejected" {
		t.Fatal("source fence reopened", r)
	}
	body, e := os.ReadFile(filepath.Join(source.Config.Storage.Directory, export.ArtifactID, "manifest.json"))
	var signed nodeproto.SignedStorageManifest
	if e != nil || json.Unmarshal(body, &signed) != nil || signed.Manifest.DirectPublic != task.DirectPublic || signed.Manifest.Protocol != nodeproto.StorageDirectProtocol {
		t.Fatal("signed source network missing", e)
	}
}

func TestDirectPublicDetachUnknownSurvivesRestartWithoutReplayingDefine(t *testing.T) {
	m, f, task := newFixture(t)
	task = configureDirect(t, m, task)
	createOff(t, m, task)
	f.fail = "define"
	detach := next(task, "5", "public_detach")
	detach.ConfirmInstanceID = task.InstanceID
	if r := submit(t, m, detach); r.Status != "uncertain" {
		t.Fatal("failed detach falsely succeeded", r)
	}
	count := f.count(" define ")
	if r := submit(t, m, detach); r.Status != "uncertain" || f.count(" define ") != count {
		t.Fatal("unknown detach repeated effect", r)
	}
	if _, e := m.ObserveInstance(context.Background(), task.InstanceID); e == nil {
		t.Fatal("unknown detach treated as actual state")
	}
	if e := m.Ledger.Close(); e != nil {
		t.Fatal(e)
	}
	l, e := OpenLedger(m.Config.StateDirectory, m.Config.NodeID)
	if e != nil {
		t.Fatal(e)
	}
	m.Ledger = l
	defer l.Close()
	if r := submit(t, m, detach); r.Status != "uncertain" || f.count(" define ") != count {
		t.Fatal("restart replayed unknown detach", r)
	}
	if r := submit(t, m, next(task, "6", "start")); r.Status != "rejected" {
		t.Fatal("unknown detached guest booted", r)
	}
}
func TestDirectPublicDetachAllowsIndependentReuseButNotOldGuestReactivation(t *testing.T) {
	m, _, task := newFixture(t)
	task = configureDirect(t, m, task)
	createOff(t, m, task)
	detach := next(task, "5", "public_detach")
	detach.ConfirmInstanceID = task.InstanceID
	if r := submit(t, m, detach); r.Status != "succeeded" {
		t.Fatal(r)
	}
	other := task
	other.OperationID = strings.Repeat("6", 32)
	other.InstanceID = strings.Repeat("a", 32)
	other.Hostname = "vm-b"
	other.DirectPublic.InstanceID = other.InstanceID
	other.DirectPublic.LeaseID = strings.Repeat("b", 32)
	other.DirectPublic.MAC = nodeproto.NetworkMAC(other.NodeID, other.InstanceID)
	if r := submit(t, m, other); r.Status != "succeeded" {
		t.Fatal("confirmed down link did not release node reservation", r)
	}
	adopt := next(task, "7", "public_adopt")
	adopt.ConfirmInstanceID = task.InstanceID
	if r := submit(t, m, adopt); r.Status != "uncertain" && r.Status != "rejected" {
		t.Fatal("old guest reacquired another live guest IP", r)
	}
	if e := m.Ledger.Close(); e != nil {
		t.Fatal(e)
	}
	l, e := OpenLedger(m.Config.StateDirectory, m.Config.NodeID)
	if e != nil {
		t.Fatal("detached tombstone made reused IP journal unloadable", e)
	}
	m.Ledger = l
	defer l.Close()
}
func TestDirectPublicStorageDoesNotDowngradeOrRotateMigrationIdentity(t *testing.T) {
	for _, kind := range []string{"legacy_storage", "target_root", "target_ip", "target_mac", "target_lease"} {
		t.Run(kind, func(t *testing.T) {
			source, _, task := newStorageFixture(t, "node-a")
			task = configureDirect(t, source, task)
			createOff(t, source, task)
			export := storageTask(task, 10, "migrate_prepare", 100)
			export.Protocol = nodeproto.StorageDirectProtocol
			export.DirectPublic = task.DirectPublic
			export.TargetNodeID = "node-b"
			if kind == "legacy_storage" {
				export.Protocol = nodeproto.StorageProtocol
				export.DirectPublic = nodeproto.DirectPublicBinding{}
				assertStorageStatus(t, source, export, "rejected")
				i, _ := source.Ledger.Instance(task.InstanceID)
				if i.SourceFence != nil {
					t.Fatal("invalid old storage request fenced source")
				}
				return
			}
			receipt := assertStorageStatus(t, source, export, "succeeded")
			target, tf, targetTask := newStorageFixture(t, "node-b")
			_ = configureDirect(t, target, targetTask)
			imp := handoffFixture(t, source, target, export, receipt)
			imp.Protocol = nodeproto.StorageDirectProtocol
			imp.DirectPublic = task.DirectPublic
			imp.DirectPublic.NodeID = "node-b"
			imp.DirectPublic.Generation++
			if kind == "target_root" {
				target.Config.Network.DNS = []string{"1.1.1.1"}
				if e := target.approveInbox(context.Background(), imp.ArtifactID, imp.FenceToken); e == nil {
					t.Fatal("changed root approved source public identity")
				}
				assertStorageStatus(t, target, imp, "rejected")
				return
			}
			if e := target.approveInbox(context.Background(), imp.ArtifactID, imp.FenceToken); e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "target_ip":
				imp.DirectPublic.IPv4 = "8.8.8.8"
			case "target_mac":
				imp.DirectPublic.MAC = "52:54:00:01:02:03"
			case "target_lease":
				imp.DirectPublic.LeaseID = strings.Repeat("c", 32)
			}
			before := tf.count(" define ")
			assertStorageStatus(t, target, imp, "rejected")
			if len(target.Ledger.Instances()) != 0 || tf.count(" define ") != before {
				t.Fatal("changed network imported target")
			}
		})
	}
}
func TestDirectPublicRootDigestPreservesLegacyOmissionAndPinsAllFields(t *testing.T) {
	m, _, task := newFixture(t)
	raw, _ := json.Marshal(m.Config.Network)
	if strings.Contains(string(raw), "require_public_lease") {
		t.Fatal("old network root bytes changed")
	}
	if _, e := DirectNetworkSHA256(m.Config.Network); e == nil {
		t.Fatal("unleased root falsely advertised direct capability")
	}
	task = configureDirect(t, m, task)
	sha, _ := DirectNetworkSHA256(m.Config.Network)
	m.Config.Network.SSHAuthorizedKeys = append(m.Config.Network.SSHAuthorizedKeys, m.Config.Network.SSHAuthorizedKeys[0])
	changed, _ := DirectNetworkSHA256(m.Config.Network)
	if sha == changed {
		t.Fatal("root digest omitted SSH approval")
	}
}

func TestDirectPublicSchemaFiveSurvivesColdMigrationAndRestart(t *testing.T) {
	m, _, task := newStorageFixture(t, "node-a")
	task = configureDirect(t, m, task)
	createOff(t, m, task)
	export := storageTask(task, 10, "migrate_prepare", 100)
	export.Protocol = nodeproto.StorageDirectProtocol
	export.DirectPublic = task.DirectPublic
	export.TargetNodeID = "node-b"
	assertStorageStatus(t, m, export, "succeeded")
	if e := m.Ledger.Close(); e != nil {
		t.Fatal(e)
	}
	l, e := OpenLedger(m.Config.StateDirectory, m.Config.NodeID)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	m.Ledger = l
	i, _ := l.Instance(task.InstanceID)
	if i.DirectPublic != task.DirectPublic || i.SourceFence == nil {
		t.Fatal("restart forgot public source fence")
	}
	if l.state.Schema != 5 {
		t.Fatal("unsafe journal version", l.state.Schema)
	}
	if r := submit(t, m, next(task, "5", "start")); r.Status != "rejected" {
		t.Fatal("source restarted", r)
	}
}

func TestDirectPublicReadOnlyReconcileRequiresExactNICNotJustPower(t *testing.T) {
	for _, applied := range []bool{false, true} {
		t.Run(fmt.Sprint(applied), func(t *testing.T) {
			m, f, task := newFixture(t)
			task = configureDirect(t, m, task)
			createOff(t, m, task)
			detach := next(task, "5", "public_detach")
			detach.ConfirmInstanceID = task.InstanceID
			raw, sha, _ := detach.BytesAndDigest()
			_ = raw
			if _, fresh, e := m.Ledger.Claim(detach, sha); e != nil || !fresh {
				t.Fatal(e)
			}
			i, _ := m.Ledger.Instance(task.InstanceID)
			i.State = "uncertain"
			if _, e := m.Ledger.Finish(detach.OperationID, "uncertain", "SIMULATED_CRASH", &i); e != nil {
				t.Fatal(e)
			}
			if applied {
				live := i
				live.DirectPublicDetached = true
				body, e := m.domainXML(live)
				if e != nil {
					t.Fatal(e)
				}
				f.domains[i.Domain] = body
			}
			before := f.count(" define ")
			out, e := m.Reconcile(context.Background(), detach.OperationID)
			if applied {
				if e != nil || out.Status != "succeeded" {
					t.Fatal(out, e)
				}
			} else if e == nil {
				t.Fatal("power alone proved detach")
			}
			if f.count(" define ") != before {
				t.Fatal("read-only recovery repeated a define")
			}
		})
	}
}

func TestDirectPublicHTTPDigestIdentityAndOriginalOperationLookup(t *testing.T) {
	m, f, task := newFixture(t)
	task = configureDirect(t, m, task)
	certs := certificates(t)
	m.Config.ExpectedControllerCertificateSHA256 = nodeproto.Digest(certs.goodLeaf.Raw)
	raw, _, e := task.BytesAndDigest()
	if e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{"digest", "identity", "case"} {
		body := raw
		if bad == "case" {
			body = []byte(strings.Replace(string(raw), `"ipv4":`, `"IPv4":`, 1))
		}
		r := authorizedRequest(m, "POST", "/v1/tasks", body, certs.goodLeaf)
		if bad == "digest" {
			r.Header.Set("X-Request-SHA256", strings.Repeat("0", 64))
		}
		if bad == "identity" {
			r.TLS.VerifiedChains = nil
		}
		w := httptest.NewRecorder()
		m.Handler().ServeHTTP(w, r)
		if w.Code < 400 {
			t.Fatal("invalid direct task passed HTTP", bad, w.Code)
		}
	}
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, authorizedRequest(m, "POST", "/v1/tasks", raw, certs.goodLeaf))
	if w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	m.workers.Wait()
	before := f.count(" define ")
	w = httptest.NewRecorder()
	m.Handler().ServeHTTP(w, authorizedRequest(m, "POST", "/v1/tasks", raw, certs.goodLeaf))
	if w.Code != 200 || f.count(" define ") != before {
		t.Fatal("HTTP replay repeated create", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	m.Handler().ServeHTTP(w, authorizedRequest(m, "GET", "/v1/tasks/"+task.OperationID, nil, certs.goodLeaf))
	var out nodeproto.NodeResult
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Protocol != nodeproto.DirectPublicProtocol || out.Status != "succeeded" {
		t.Fatal(w.Code, w.Body.String())
	}
}

func directMigrationPair(t *testing.T) (*Manager, *fakeRunner, *Manager, *fakeRunner, nodeproto.NodeTask, nodeproto.TypedStorageTask, nodeproto.StorageResult, nodeproto.TypedStorageTask, nodeproto.StorageResult) {
	t.Helper()
	source, sf, task := newStorageFixture(t, "node-a")
	source.Config.AllowDelete = true
	task = configureDirect(t, source, task)
	createOff(t, source, task)
	export := storageTask(task, 10, "migrate_prepare", 100)
	export.Protocol = nodeproto.StorageDirectProtocol
	export.DirectPublic = task.DirectPublic
	export.TargetNodeID = "node-b"
	receipt := assertStorageStatus(t, source, export, "succeeded")
	target, tf, targetTask := newStorageFixture(t, "node-b")
	_ = configureDirect(t, target, targetTask)
	imp := handoffFixture(t, source, target, export, receipt)
	imp.Protocol = nodeproto.StorageDirectProtocol
	imp.DirectPublic = task.DirectPublic
	imp.DirectPublic.NodeID = "node-b"
	imp.DirectPublic.Generation++
	if e := target.approveInbox(context.Background(), imp.ArtifactID, imp.FenceToken); e != nil {
		t.Fatal(e)
	}
	assertStorageStatus(t, target, imp, "succeeded")
	activate := imp
	activate.OperationID = fmt.Sprintf("%032x", 22)
	activate.Action = "migrate_activate"
	activate.ConfirmArtifactID = activate.ArtifactID
	activated := assertStorageStatus(t, target, activate, "succeeded")
	return source, sf, target, tf, task, export, receipt, activate, activated
}
func retireTask(task nodeproto.NodeTask, export nodeproto.TypedStorageTask, receipt nodeproto.StorageResult, activate nodeproto.TypedStorageTask, activated nodeproto.StorageResult) nodeproto.TypedStorageTask {
	raw, _ := json.Marshal(activated)
	_, sha, _ := activate.BytesAndDigest()
	return nodeproto.TypedStorageTask{Protocol: nodeproto.StorageDirectProtocol, OperationID: fmt.Sprintf("%032x", 30), NodeID: task.NodeID, Action: "migrate_retire_source", InstanceID: task.InstanceID, OwnerRef: task.OwnerRef, DirectPublic: task.DirectPublic, ArtifactID: export.ArtifactID, SourceNodeID: task.NodeID, TargetNodeID: export.TargetNodeID, SourceOperationID: export.OperationID, ManifestSHA256: receipt.ManifestSHA256, FenceToken: receipt.FenceToken, ConfirmArtifactID: export.ArtifactID, RetireProof: nodeproto.PublicRetireProof{ActivateOperationID: activate.OperationID, ActivateRequestSHA256: sha, ActivateReceiptSHA256: nodeproto.Digest(raw), TargetProfileSHA256: task.DirectPublic.ProfileSHA256, TargetGeneration: task.DirectPublic.Generation + 1, ConfirmInstanceID: task.InstanceID}}
}
func TestDirectPublicExplicitRetirementAllowsSafeReturnMigrationAndRejectsOldGeneration(t *testing.T) {
	source, sf, target, _, task, export, receipt, activate, activated := directMigrationPair(t)
	retire := retireTask(task, export, receipt, activate, activated)
	assertStorageStatus(t, source, retire, "succeeded")
	old, _ := source.Ledger.Instance(task.InstanceID)
	if !old.PublicRetired || old.State != "retired" || len(source.Ledger.state.PublicRetirements) != 1 {
		t.Fatal("missing permanent retired source tombstone", old)
	}
	if _, e := os.Stat(old.Directory); !os.IsNotExist(e) {
		t.Fatal("retired disk directory remained", e)
	}
	if _, ok := sf.domains[old.Domain]; ok {
		t.Fatal("retired libvirt definition remained")
	}
	if r := submit(t, source, next(task, "5", "start")); r.Status != "rejected" {
		t.Fatal("old generation booted", r)
	}
	dst, _ := target.Ledger.Instance(task.InstanceID)
	power := task
	power.NodeID = target.Config.NodeID
	power.Resources = dst.Resources
	power.DirectPublic = dst.DirectPublic
	if r := submit(t, target, next(power, "6", "force_off")); r.Status != "succeeded" {
		t.Fatal(r)
	}
	back := storageTask(power, 40, "migrate_prepare", 200)
	back.Protocol = nodeproto.StorageDirectProtocol
	back.DirectPublic = power.DirectPublic
	back.TargetNodeID = source.Config.NodeID
	br := assertStorageStatus(t, target, back, "succeeded")
	imp := handoffFixture(t, target, source, back, br)
	imp.Protocol = nodeproto.StorageDirectProtocol
	imp.DirectPublic = power.DirectPublic
	imp.DirectPublic.NodeID = source.Config.NodeID
	imp.DirectPublic.Generation++
	if e := source.approveInbox(context.Background(), imp.ArtifactID, imp.FenceToken); e != nil {
		t.Fatal(e)
	}
	assertStorageStatus(t, source, imp, "succeeded")
	active := imp
	active.OperationID = fmt.Sprintf("%032x", 42)
	active.Action = "migrate_activate"
	active.ConfirmArtifactID = active.ArtifactID
	assertStorageStatus(t, source, active, "succeeded")
	now, _ := source.Ledger.Instance(task.InstanceID)
	if now.DirectPublic.Generation != 3 || now.MAC != task.DirectPublic.MAC || now.IPv4 != task.DirectPublic.IPv4 || now.PublicRetired {
		t.Fatal("return migration did not create new same-IP incarnation", now)
	}
	if r := submit(t, source, next(task, "7", "force_off")); r.Status != "rejected" {
		t.Fatal("old task affected returned guest", r)
	}
	before := sf.count(" undefine ")
	assertStorageStatus(t, source, retire, "succeeded")
	if sf.count(" undefine ") != before {
		t.Fatal("old retire replay deleted new incarnation")
	}
	if e := source.Ledger.Close(); e != nil {
		t.Fatal(e)
	}
	l, e := OpenLedger(source.Config.StateDirectory, source.Config.NodeID)
	if e != nil {
		t.Fatal("return migration tombstone did not survive restart", e)
	}
	source.Ledger = l
	defer l.Close()
	now, _ = l.Instance(task.InstanceID)
	if now.DirectPublic.Generation != 3 || len(l.state.PublicRetirements) != 1 {
		t.Fatal("restart lost incarnation history")
	}
}
func TestDirectPublicRetirementRequiresExactTargetProofAndRootDeleteApproval(t *testing.T) {
	for _, kind := range []string{"delete_disabled", "receipt", "root", "generation", "confirmation", "fence"} {
		t.Run(kind, func(t *testing.T) {
			source, sf, _, _, task, export, receipt, activate, activated := directMigrationPair(t)
			retire := retireTask(task, export, receipt, activate, activated)
			switch kind {
			case "delete_disabled":
				source.Config.AllowDelete = false
			case "receipt":
				retire.RetireProof.ActivateReceiptSHA256 = strings.Repeat("0", 64)
			case "root":
				retire.RetireProof.TargetProfileSHA256 = strings.Repeat("0", 64)
			case "generation":
				retire.RetireProof.TargetGeneration++
			case "confirmation":
				retire.RetireProof.ConfirmInstanceID = strings.Repeat("0", 32)
			case "fence":
				retire.FenceToken = strings.Repeat("0", 64)
			}
			before := sf.count(" undefine ")
			if retire.Valid() {
				assertStorageStatus(t, source, retire, "rejected")
			} else {
				raw, _ := json.Marshal(retire)
				if _, e := source.AcceptStorage(retire, raw); e == nil {
					t.Fatal("invalid retire accepted")
				}
			}
			if sf.count(" undefine ") != before {
				t.Fatal("unproved retire removed source")
			}
			i, _ := source.Ledger.Instance(task.InstanceID)
			if i.PublicRetired || i.SourceFence == nil {
				t.Fatal("failed retire lost source fence")
			}
		})
	}
}

func TestDirectPublicRetireTaskProofStrictDecode(t *testing.T) {
	source, _, _, _, task, export, receipt, activate, activated := directMigrationPair(t)
	_ = source
	retire := retireTask(task, export, receipt, activate, activated)
	raw, _, e := retire.BytesAndDigest()
	if e != nil {
		t.Fatal(e)
	}
	decoded, e := nodeproto.DecodeStorageTask(raw)
	if e != nil || decoded != retire {
		t.Fatal(e, string(raw))
	}
	for _, bad := range []string{strings.Replace(string(raw), `"target_generation":2`, `"target_generation":2,"target_generation":2`, 1), strings.Replace(string(raw), `"confirm_instance_id":`, `"Confirm_Instance_ID":`, 1), strings.Replace(string(raw), `"retire_proof":{`, `"retire_proof":{"unknown":true,`, 1), strings.Replace(string(raw), `"generation":1`, `"generation":0`, 1)} {
		if _, e := nodeproto.DecodeStorageTask([]byte(bad)); e == nil {
			t.Fatal("ambiguous retirement accepted")
		}
	}
}
func TestDirectPublicRetireUnknownDoesNotRetryDestruction(t *testing.T) {
	source, sf, _, _, task, export, receipt, activate, activated := directMigrationPair(t)
	retire := retireTask(task, export, receipt, activate, activated)
	sf.fail = "undefine"
	assertStorageStatus(t, source, retire, "uncertain")
	count := sf.count(" undefine ")
	assertStorageStatus(t, source, retire, "uncertain")
	if sf.count(" undefine ") != count {
		t.Fatal("unknown retirement repeated destructive command")
	}
	i, _ := source.Ledger.Instance(task.InstanceID)
	if i.PublicRetired || i.SourceFence == nil {
		t.Fatal("unknown retirement fabricated tombstone")
	}
}

func TestDirectPublicWithdrawnApprovalAllowsOnlyExactStoppedDetachCleanup(t *testing.T) {
	for _, kind := range []string{"address", "all_addresses", "root_digest", "filter_identity"} {
		t.Run(kind, func(t *testing.T) {
			m, f, task := newFixture(t)
			task = configureDirect(t, m, task)
			createOff(t, m, task)
			switch kind {
			case "address":
				m.Config.Network.Addresses = []string{"8.8.8.8"}
			case "all_addresses":
				m.Config.Network.Addresses = []string{}
				if e := m.Config.Network.Validate(); e != nil {
					t.Fatal("fully withdrawn lease-required network cannot admit cleanup service", e)
				}
			case "root_digest":
				m.Config.Network.DNS = []string{"1.1.1.1"}
			case "filter_identity":
				m.Config.Network.Filter = "aster-other-filter"
			}
			if r := submit(t, m, next(task, "5", "start")); r.Status != "rejected" {
				t.Fatal("revoked root reopened guest", r)
			}
			before := f.count(" nwfilter-dumpxml ")
			detach := next(task, "6", "public_detach")
			detach.ConfirmInstanceID = task.InstanceID
			r := submit(t, m, detach)
			if kind == "filter_identity" {
				if r.Status != "rejected" {
					t.Fatal("changed bridge/filter identity authorized cleanup", r)
				}
				return
			}
			if r.Status != "succeeded" {
				op, _ := m.Ledger.Query(detach.OperationID)
				t.Fatal("withdrawn root prevented pure stopped link-down", r, op.ErrorCode)
			}
			if f.count(" nwfilter-dumpxml ") != before {
				t.Fatal("pure cleanup required a live uplink/filter permission probe")
			}
			i, _ := m.Ledger.Instance(task.InstanceID)
			var d domainXML
			if !i.DirectPublicDetached || xml.Unmarshal(f.domains[i.Domain], &d) != nil || d.Devices.Interfaces[0].Link.State != "down" || i.DirectPublic != task.DirectPublic {
				t.Fatal("cleanup changed identity instead of only fencing exact NIC", i)
			}
			adopt := next(task, "7", "public_adopt")
			adopt.DirectPublic.Generation++
			adopt.ConfirmInstanceID = task.InstanceID
			if r := submit(t, m, adopt); r.Status != "rejected" {
				t.Fatal("withdrawal permitted re-adopt/open", r)
			}
		})
	}
}

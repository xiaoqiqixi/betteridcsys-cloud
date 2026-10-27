package hypervisor

import (
	"aster/cloud/internal/fabric"
	"aster/cloud/internal/nodeproto"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The libvirt fixture deliberately keeps persistent XML separate from live NIC
// state: default live updates must never turn the next boot's link on.
type ovsRunner struct {
	*fakeRunner
	links                                     map[string]string
	autostart, managedSave, pausedUnsupported bool
	linkOutput                                string
}

func (f *ovsRunner) Run(ctx context.Context, binary string, args ...string) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if binary != Virsh || len(args) < 4 {
		return f.fakeRunner.Run(ctx, binary, args...)
	}
	verb, name := args[2], args[3]
	special := verb == "dominfo" || verb == "domif-getlink" || verb == "domif-setlink" || verb == "resume" || verb == "suspend" || verb == "start" || verb == "dumpxml"
	if !special {
		return f.fakeRunner.Run(ctx, binary, args...)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.commands = append(f.commands, binary+" "+strings.Join(args, " "))
	if f.fail == verb {
		return nil, errors.New("injected command failure")
	}
	raw, exists := f.domains[name]
	if !exists {
		return nil, errors.New("absent domain")
	}
	switch verb {
	case "dominfo":
		a, s := "disable", "no"
		if f.autostart {
			a = "enable"
		}
		if f.managedSave {
			s = "yes"
		}
		return []byte("Autostart: " + a + "\nManaged save: " + s + "\n"), nil
	case "start":
		if len(args) != 5 || args[4] != "--paused" {
			return nil, errors.New("unguarded start")
		}
		f.states[name] = "paused"
		if f.pausedUnsupported {
			f.states[name] = "running"
		}
		f.links[name] = "down"
		return nil, nil
	case "domif-getlink":
		if len(args) != 5 {
			return nil, errors.New("must read live link")
		}
		if f.linkOutput != "" {
			return []byte(f.linkOutput), nil
		}
		return []byte(args[4] + " " + f.links[name] + "\n"), nil
	case "domif-setlink":
		if len(args) != 6 || args[5] != "up" && args[5] != "down" || f.states[name] != "paused" && f.states[name] != "running" || args[5] == "up" && f.states[name] != "paused" {
			return nil, errors.New("invalid release")
		}
		f.links[name] = args[5]
		return nil, nil
	case "suspend":
		if f.states[name] != "running" {
			return nil, errors.New("not running")
		}
		f.states[name] = "paused"
		return nil, nil
	case "resume":
		if f.states[name] != "paused" || f.links[name] != "up" {
			return nil, errors.New("invalid resume")
		}
		f.states[name] = "running"
		return nil, nil
	case "dumpxml":
		if len(args) == 5 && args[4] == "--inactive" || f.states[name] == "shut off" {
			return raw, nil
		}
		var d domainXML
		if e := xml.Unmarshal(raw, &d); e != nil {
			return nil, e
		}
		d.Devices.Interfaces[0].Link.State = f.links[name]
		return xml.Marshal(d)
	}
	return nil, errors.New("unsupported fixture command")
}

type fakeOVSGate struct {
	calls   []string
	fail    string
	intents []fabric.ActivationIntent
}

func (g *fakeOVSGate) Activate(ctx context.Context, i fabric.ActivationIntent, bootstrap, release func(context.Context) error) (fabric.LiveVerification, error) {
	g.calls = append(g.calls, "drop")
	g.intents = append(g.intents, i)
	fail := func() error { return errors.New("injected fabric failure") }
	if g.fail == "before-bootstrap" {
		return fabric.LiveVerification{}, fail()
	}
	g.calls = append(g.calls, "bootstrap")
	if e := bootstrap(ctx); e != nil {
		return fabric.LiveVerification{}, e
	}
	if g.fail == "verify" {
		return fabric.LiveVerification{}, fail()
	}
	g.calls = append(g.calls, "verified")
	if e := release(ctx); e != nil {
		return fabric.LiveVerification{}, e
	}
	g.calls = append(g.calls, "released")
	if g.fail == "lost-final-ack" {
		return fabric.LiveVerification{}, fail()
	}
	return fabric.LiveVerification{}, nil
}
func (g *fakeOVSGate) Deactivate(ctx context.Context, i fabric.ActivationIntent, stop func(context.Context) error) (fabric.LiveVerification, error) {
	g.calls = append(g.calls, "drop-before-stop")
	g.intents = append(g.intents, i)
	if g.fail == "stop" {
		return fabric.LiveVerification{}, errors.New("injected stop gate failure")
	}
	if e := stop(ctx); e != nil {
		return fabric.LiveVerification{}, e
	}
	g.calls = append(g.calls, "stale-port-removed")
	return fabric.LiveVerification{}, nil
}
func (g *fakeOVSGate) Check(_ context.Context, i fabric.ActivationIntent) (fabric.LiveVerification, error) {
	g.calls = append(g.calls, "read-only-check")
	g.intents = append(g.intents, i)
	if g.fail == "check" {
		return fabric.LiveVerification{}, errors.New("live drift")
	}
	return fabric.LiveVerification{}, nil
}
func newOVSFixture(t *testing.T) (*Manager, *ovsRunner, *fakeOVSGate, nodeproto.NodeTask) {
	t.Helper()
	m, f, task := newFixture(t)
	cfg := fabric.Config{Schema: 1, NodeID: m.Config.NodeID, Bridge: "aster-vpc0", StateDirectory: filepath.Join(filepath.Dir(m.Config.StateDirectory), "fabric"), DedicatedAck: true}
	keys := m.Config.Network.SSHAuthorizedKeys
	m.Config.Network = Network{}
	m.Config.AllowUnmeteredDefault = false
	m.Config.OVSProfiles = map[string]OVSProfile{"private-v1": {FabricConfig: "/etc/aster/fabric.json", SSHAuthorizedKeys: keys}}
	m.loadOVSConfig = func(string) (fabric.Config, error) { return cfg, nil }
	r := &ovsRunner{fakeRunner: f, links: map[string]string{}}
	m.Runner = r
	g := &fakeOVSGate{}
	m.ovsFactory = func(c fabric.Config) (ovsGate, error) {
		if c != cfg {
			t.Error("profile substituted")
		}
		return g, nil
	}
	task.Protocol = nodeproto.NetworkProtocol
	task.Resources.NetworkType = "vpc"
	task.Resources.BandwidthMbps = 25
	task.Resources.InboundBandwidthMbps = 50
	task.Network = nodeproto.NetworkBinding{Schema: 1, ProfileID: "private-v1", ProfileSHA256: profileDigest(cfg), LeaseID: strings.Repeat("4", 32), PoolID: strings.Repeat("5", 32), VPCID: strings.Repeat("6", 32), NodeID: task.NodeID, OwnerRef: task.OwnerRef, InstanceID: task.InstanceID, CIDR: "10.20.0.0/24", IPv4: "10.20.0.10", MAC: nodeproto.NetworkMAC(task.NodeID, task.InstanceID), InterfaceID: nodeproto.NetworkInterfaceID(task.InstanceID), VLANID: 201, InboundMbps: 50, OutboundMbps: 25}
	if !task.Valid() {
		t.Fatal("invalid OVS fixture")
	}
	return m, r, g, task
}
func requireOVSSuccess(t *testing.T, m *Manager, task nodeproto.NodeTask) nodeproto.NodeResult {
	t.Helper()
	r := submit(t, m, task)
	if r.Status != "succeeded" {
		op, _ := m.Ledger.Query(task.OperationID)
		t.Fatalf("OVS operation: %+v code=%s", r, op.ErrorCode)
	}
	return r
}
func TestOVSLifecycleUsesGateAndPersistentDownNIC(t *testing.T) {
	m, r, g, task := newOVSFixture(t)
	first := requireOVSSuccess(t, m, task)
	if first.Protocol != nodeproto.NetworkProtocol || strings.Join(g.calls, ",") != "drop,bootstrap,verified,released" {
		t.Fatal(first, g.calls)
	}
	if r.count(" start ") != 1 || r.count(" --paused") != 1 || r.count(" resume ") != 1 || r.count("nwfilter") != 0 {
		t.Fatal(r.commands)
	}
	i, _ := m.Ledger.Instance(task.InstanceID)
	var d domainXML
	if e := xml.Unmarshal(r.domains[i.Domain], &d); e != nil {
		t.Fatal(e)
	}
	n := d.Devices.Interfaces[0]
	if n.Link.State != "down" || n.Target.Dev != fabric.TAPName(i.ID) || n.VirtualPort.Type != "openvswitch" || n.VirtualPort.Parameters.InterfaceID != task.Network.InterfaceID || n.Filter != nil || n.Port != nil || d.OnReboot != "destroy" || d.UUID != fabric.DomainID(i.ID) || d.Metadata.Instance.NetworkSHA256 != task.Network.Digest() {
		t.Fatal("incorrect OVS XML", d)
	}
	raw, e := os.ReadFile(filepath.Join(i.Directory, "network-config"))
	if e != nil || !strings.Contains(string(raw), "10.20.0.10/24") || strings.Contains(string(raw), "gateway") || strings.Contains(string(raw), "nameservers") {
		t.Fatal("false L3 promise", string(raw), e)
	}
	if replay := submit(t, m, task); replay != first || len(g.calls) != 4 {
		t.Fatal("create replayed", replay, g.calls)
	}
	requireOVSSuccess(t, m, next(task, "7", "start"))
	if g.calls[len(g.calls)-1] != "read-only-check" || r.count(" start ") != 1 {
		t.Fatal("running start mutated", g.calls, r.commands)
	}
	requireOVSSuccess(t, m, next(task, "8", "shutdown"))
	if g.calls[len(g.calls)-1] != "stale-port-removed" || g.intents[len(g.intents)-1].Ports[0].Enabled {
		t.Fatal("stop kept permission", g.calls)
	}
	requireOVSSuccess(t, m, next(task, "9", "start"))
	if r.count(" start ") != 2 || r.count(" resume ") != 2 {
		t.Fatal("restart bypassed gate", r.commands)
	}
	requireOVSSuccess(t, m, next(task, "a", "force_off"))
	m.Config.AllowDelete = true
	requireOVSSuccess(t, m, next(task, "b", "delete"))
	if len(r.domains) != 0 || g.calls[len(g.calls)-1] != "stale-port-removed" {
		t.Fatal("delete did not clear fabric", g.calls)
	}
}
func TestOVSFailuresRemainUncertainAndNeverRetryAfterRestart(t *testing.T) {
	for _, failure := range []string{"before-bootstrap", "verify", "lost-final-ack", "start", "domif-setlink", "resume", "paused-unsupported", "initial-link-up", "autostart", "managed-save"} {
		t.Run(failure, func(t *testing.T) {
			m, r, g, task := newOVSFixture(t)
			switch failure {
			case "start", "domif-setlink", "resume":
				r.fail = failure
			case "paused-unsupported":
				r.pausedUnsupported = true
			case "initial-link-up":
				r.linkOutput = task.Network.MAC + " up"
			case "autostart":
				r.autostart = true
			case "managed-save":
				r.managedSave = true
			default:
				g.fail = failure
			}
			result := submit(t, m, task)
			i, _ := m.Ledger.Instance(task.InstanceID)
			if result.Status != "uncertain" || i.State != "uncertain" {
				t.Fatal(result, i.State)
			}
			if failure != "lost-final-ack" && failure != "resume" && r.count(" resume ") != 0 {
				t.Fatal("resumed without verified release", r.commands)
			}
			if (failure == "autostart" || failure == "managed-save" || failure == "before-bootstrap") && r.count(" start ") != 0 {
				t.Fatal("unsafe bootstrap", r.commands)
			}
			count := len(r.commands)
			calls := len(g.calls)
			m.Shutdown()
			m.Ledger.Close()
			l, e := OpenLedger(m.Config.StateDirectory, m.Config.NodeID)
			if e != nil {
				t.Fatal(e)
			}
			defer l.Close()
			m.Ledger = l
			m.stopping = false
			if l.state.Schema != 3 {
				t.Fatal("network journal downgraded")
			}
			if replay := submit(t, m, task); replay != result {
				t.Fatal("lost exact uncertain result", replay, result)
			}
			if again := submit(t, m, next(task, "f", "start")); again.Status != "rejected" {
				t.Fatal("uncertain instance restarted", again)
			}
			if len(r.commands) != count || len(g.calls) != calls {
				t.Fatal("uncertain replay issued commands")
			}
		})
	}
}
func TestOVSBindingDriftAndLegacyCommandsCannotBypass(t *testing.T) {
	m, r, g, task := newOVSFixture(t)
	requireOVSSuccess(t, m, task)
	for j, mutate := range []func(*nodeproto.NodeTask){
		func(t *nodeproto.NodeTask) { t.Protocol = nodeproto.Protocol; t.Network = nodeproto.NetworkBinding{} },
		func(t *nodeproto.NodeTask) { t.Network.LeaseID = strings.Repeat("a", 32) },
		func(t *nodeproto.NodeTask) { t.Network.IPv4 = "10.20.0.11" },
		func(t *nodeproto.NodeTask) { t.Network.ProfileSHA256 = strings.Repeat("b", 64) },
		func(t *nodeproto.NodeTask) { t.Network.InboundMbps++; t.Resources.InboundBandwidthMbps++ },
		func(t *nodeproto.NodeTask) { t.Action = "reboot" },
	} {
		q := next(task, string("abcdef"[j]), "start")
		mutate(&q)
		before := len(r.commands)
		if result := submit(t, m, q); result.Status != "rejected" || before != len(r.commands) {
			t.Fatal("identity/reboot bypass", j, result)
		}
	}
	if len(g.calls) != 4 {
		t.Fatal("gate called for rejected binding", g.calls)
	}
}
func TestOVSRunningDriftCheckNeverRepairsOrStarts(t *testing.T) {
	m, r, g, task := newOVSFixture(t)
	requireOVSSuccess(t, m, task)
	g.fail = "check"
	result := submit(t, m, next(task, "8", "start"))
	if result.Status != "uncertain" || r.count(" start ") != 1 || r.count(" resume ") != 1 || g.calls[len(g.calls)-1] != "read-only-check" {
		t.Fatal(result, g.calls, r.commands)
	}
}
func TestOVSJournalCannotBeDowngradedOrLoseBinding(t *testing.T) {
	for _, change := range []string{"schema", "missing-binding", "wrong-lease-instance", "wrong-ip"} {
		t.Run(change, func(t *testing.T) {
			m, _, _, task := newOVSFixture(t)
			requireOVSSuccess(t, m, task)
			m.Shutdown()
			m.Ledger.Close()
			path := filepath.Join(m.Config.StateDirectory, "journal.json")
			raw, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			var j journal
			if json.Unmarshal(raw, &j) != nil {
				t.Fatal("fixture")
			}
			i := j.Instances[task.InstanceID]
			switch change {
			case "schema":
				j.Schema = 2
			case "missing-binding":
				i.Network = nodeproto.NetworkBinding{}
			case "wrong-lease-instance":
				i.Network.InstanceID = strings.Repeat("f", 32)
			case "wrong-ip":
				i.IPv4 = "10.20.0.11"
			}
			j.Instances[i.ID] = i
			raw, _ = json.Marshal(j)
			if os.WriteFile(path, raw, 0600) != nil {
				t.Fatal("write fixture")
			}
			l, e := OpenLedger(m.Config.StateDirectory, m.Config.NodeID)
			if e == nil {
				l.Close()
				t.Fatal("accepted corrupt OVS journal")
			}
		})
	}
}
func TestOVSIntentOnlyKnownRunningPeersGetPermission(t *testing.T) {
	m, _, _, task := newOVSFixture(t)
	requireOVSSuccess(t, m, task)
	original, _ := m.Ledger.Instance(task.InstanceID)
	for j, state := range []string{"running", "shut off", "uncertain", "reserved", "deleted"} {
		id := strings.Repeat(string("abcde"[j]), 32)
		i := original
		i.ID = id
		i.State = state
		i.Network.InstanceID = id
		i.Network.IPv4 = "10.20.0." + string('2'+rune(j)) + "0"
		i.IPv4 = i.Network.IPv4
		i.Network.LeaseID = id
		i.Network.MAC = nodeproto.NetworkMAC(task.NodeID, id)
		i.MAC = i.Network.MAC
		i.Network.InterfaceID = nodeproto.NetworkInterfaceID(id)
		m.Ledger.mu.Lock()
		m.Ledger.state.Instances[id] = i
		m.Ledger.mu.Unlock()
	}
	_, sha, _ := task.BytesAndDigest()
	intent, e := m.networkIntent(task, sha, true)
	if e != nil {
		t.Fatal(e)
	}
	if len(intent.Ports) != 5 {
		t.Fatal(intent)
	}
	for _, p := range intent.Ports {
		want := p.InstanceID == task.InstanceID || p.InstanceID == strings.Repeat("a", 32)
		if p.Enabled != want {
			t.Fatal("unknown/stopped peer enabled", p)
		}
	}
}

func TestOVSLegacyStorageContractsCannotActivateOrChangeGuest(t *testing.T) {
	m, r, _, task := newOVSFixture(t)
	requireOVSSuccess(t, m, task)
	root := privateDir(t)
	m.Config.Storage = StorageConfig{Enabled: true, Directory: filepath.Join(root, "artifacts"), InboxDirectory: filepath.Join(root, "inbox"), MaxArtifactBytes: 32 << 30, MaxTotalBytes: 128 << 30, AllowMigration: true, SourceCertificatePins: map[string]string{}}
	for _, p := range []string{m.Config.Storage.Directory, m.Config.Storage.InboxDirectory} {
		if e := os.Mkdir(p, 0700); e != nil {
			t.Fatal(e)
		}
	}
	for j, action := range []string{"snapshot_create", "snapshot_list", "snapshot_restore", "snapshot_delete", "backup_create", "backup_list", "backup_verify", "backup_restore", "backup_delete", "migrate_prepare", "migrate_activate"} {
		artifact := 100
		if strings.HasSuffix(action, "_list") {
			artifact = 0
		}
		q := storageTask(task, 30+j, action, artifact)
		if action == "migrate_prepare" {
			q.TargetNodeID = "node-b"
		}
		if action == "migrate_activate" {
			q.SourceNodeID = "node-b"
			q.TargetNodeID = task.NodeID
			q.ConfirmArtifactID = q.ArtifactID
			q.SourceOperationID = strings.Repeat("a", 32)
			q.ManifestSHA256 = strings.Repeat("b", 64)
			q.FenceToken = strings.Repeat("c", 64)
		}
		before := len(r.commands)
		result := waitStorage(t, m, q)
		op, _ := m.Ledger.QueryStorage(q.OperationID)
		if result.Status != "rejected" || op.ErrorCode != "OVS_STORAGE_CONTRACT_UNSUPPORTED" || len(r.commands) != before {
			t.Fatal(action, result, op.ErrorCode)
		}
		if m.Ledger.state.Schema != 3 {
			t.Fatal("storage downgraded network journal")
		}
	}
}
func TestOVSDomainIdentityDriftRejectedBeforePower(t *testing.T) {
	for _, field := range []string{"bridge", "interface", "tap", "uuid", "digest", "reboot", "persistent-link", "filter"} {
		t.Run(field, func(t *testing.T) {
			m, r, _, task := newOVSFixture(t)
			requireOVSSuccess(t, m, task)
			requireOVSSuccess(t, m, next(task, "8", "force_off"))
			i, _ := m.Ledger.Instance(task.InstanceID)
			var d domainXML
			if e := xml.Unmarshal(r.domains[i.Domain], &d); e != nil {
				t.Fatal(e)
			}
			n := &d.Devices.Interfaces[0]
			switch field {
			case "bridge":
				n.Source.Bridge = "aster-other"
			case "interface":
				n.VirtualPort.Parameters.InterfaceID = nodeproto.NetworkInterfaceID(strings.Repeat("f", 32))
			case "tap":
				n.Target.Dev = "vnet1"
			case "uuid":
				d.UUID = fabric.DomainID(strings.Repeat("f", 32))
			case "digest":
				d.Metadata.Instance.NetworkSHA256 = strings.Repeat("a", 64)
			case "reboot":
				d.OnReboot = "restart"
			case "persistent-link":
				n.Link.State = "up"
			case "filter":
				n.Filter = &nicFilterXML{Filter: "aster-filter"}
			}
			raw, e := xml.Marshal(d)
			if e != nil {
				t.Fatal(e)
			}
			r.domains[i.Domain] = raw
			result := submit(t, m, next(task, "9", "start"))
			if result.Status == "succeeded" || r.count(" start ") != 1 {
				t.Fatal("drift powered on", field, result, r.commands)
			}
		})
	}
}

func TestOVSReconcileCannotTurnLostFabricAckIntoSuccess(t *testing.T) {
	m, r, g, task := newOVSFixture(t)
	g.fail = "lost-final-ack"
	r.fail = "suspend" // fence failure must not make power-only reconciliation safe.
	result := submit(t, m, task)
	if result.Status != "uncertain" {
		t.Fatal(result)
	}
	i, _ := m.Ledger.Instance(task.InstanceID)
	if r.states[i.Domain] != "running" {
		t.Fatal("fixture must model released VM with lost gate ACK")
	}
	commands := len(r.commands)
	observed, e := m.Reconcile(context.Background(), task.OperationID)
	if e == nil || observed.Status != "uncertain" || len(r.commands) != commands {
		t.Fatal("false OVS reconciliation", observed, e)
	}
	persisted, _ := m.Ledger.Query(task.OperationID)
	if persisted.Result != result {
		t.Fatal("uncertain receipt overwritten")
	}
}

func TestOVSMetricsRequireExactBoundTAP(t *testing.T) {
	m, _, _, task := newOVSFixture(t)
	requireOVSSuccess(t, m, task)
	i, _ := m.Ledger.Instance(task.InstanceID)
	for _, name := range []string{fabric.TAPName(i.ID), "vnet7", fabric.TAPName(strings.Repeat("f", 32)), "ast"} {
		raw := strings.ReplaceAll(string(sampleMetrics(i)), "vnet7", name)
		result, e := parseInstanceMetrics([]byte(raw), i, time.Now().UTC())
		if name == fabric.TAPName(i.ID) {
			if e != nil {
				t.Fatal(e)
			}
			assertCounter(t, result.NetworkReceiveBytes, "42")
		} else if e == nil {
			t.Fatal("unbound metric interface", name)
		}
	}
}
func TestOVSLostReleaseACKAttemptsOnlyNonDestructiveFence(t *testing.T) {
	m, r, g, task := newOVSFixture(t)
	g.fail = "lost-final-ack"
	result := submit(t, m, task)
	i, _ := m.Ledger.Instance(task.InstanceID)
	if result.Status != "uncertain" || r.states[i.Domain] != "paused" || r.links[i.Domain] != "down" || r.count(" start ") != 1 || r.count(" resume ") != 1 || r.count(" suspend ") != 1 || r.count(" destroy ") != 0 {
		t.Fatal(result, r.commands)
	}
}

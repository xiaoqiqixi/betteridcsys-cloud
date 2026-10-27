package hypervisor

import (
	"aster/billing/controllerapi"
	"aster/cloud/internal/nodeproto"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeRunner struct {
	mu        sync.Mutex
	commands  []string
	domains   map[string][]byte
	states    map[string]string
	autostart map[string]bool
	filter    []byte
	fail      string
	info      string
	before    func(string)
	block     <-chan struct{}
	// Empty blockVerb preserves the all-command gate used by other fixtures.
	blockVerb string
	blocked   chan<- struct{}
}

func (f *fakeRunner) Run(ctx context.Context, binary string, args ...string) ([]byte, error) {
	verb := ""
	if binary == Virsh && len(args) > 2 {
		verb = args[2]
	} else if len(args) > 0 {
		verb = args[0]
	}
	cmd := binary + " " + strings.Join(args, " ")
	if f.before != nil {
		f.before(cmd)
	}
	if f.block != nil && (f.blockVerb == "" || f.blockVerb == verb) {
		select {
		case f.blocked <- struct{}{}:
		default:
		}
		select {
		case <-f.block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.commands = append(f.commands, cmd)
	if f.fail == verb {
		return nil, errors.New("injected command failure")
	}
	if binary == QemuImg {
		if verb == "info" {
			if f.info != "" {
				return []byte(f.info), nil
			}
			return []byte(`{"format":"qcow2","virtual-size":1073741824}`), nil
		}
		if verb == "create" {
			return nil, os.WriteFile(args[len(args)-2], fakeQcowBytes(), 0600)
		}
		if verb == "convert" {
			raw, e := os.ReadFile(args[len(args)-2])
			if e != nil {
				return nil, e
			}
			return nil, os.WriteFile(args[len(args)-1], raw, 0600)
		}
		if verb == "check" {
			return nil, nil
		}
	}
	if binary == CloudLocalDS {
		return nil, os.WriteFile(args[2], []byte("synthetic seed, not bootable"), 0600)
	}
	if binary != Virsh {
		return nil, errors.New("unapproved binary")
	}
	tail := args[3:]
	switch verb {
	case "list":
		var names []string
		for name := range f.domains {
			if strings.Contains(cmd, "--autostart") && !f.autostart[name] {
				continue
			}
			names = append(names, name)
		}
		return []byte(strings.Join(names, "\n")), nil
	case "nwfilter-dumpxml":
		return f.filter, nil
	case "define":
		raw, e := os.ReadFile(tail[0])
		if e != nil {
			return nil, e
		}
		var d domainXML
		if e = xml.Unmarshal(raw, &d); e != nil {
			return nil, e
		}
		f.domains[d.Name] = raw
		f.states[d.Name] = "shut off"
		return nil, nil
	case "dumpxml":
		raw, ok := f.domains[tail[0]]
		if !ok {
			return nil, errors.New("domain absent")
		}
		return raw, nil
	case "domstate":
		s, ok := f.states[tail[0]]
		if !ok {
			return nil, errors.New("domain absent")
		}
		return []byte(s + "\n"), nil
	case "start":
		f.states[tail[0]] = "running"
		return nil, nil
	case "shutdown", "destroy":
		f.states[tail[0]] = "shut off"
		return nil, nil
	case "reboot":
		return nil, nil
	case "undefine":
		delete(f.domains, tail[0])
		delete(f.states, tail[0])
		return nil, nil
	}
	return nil, errors.New("unexpected fake command " + cmd)
}
func (f *fakeRunner) count(needle string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, s := range f.commands {
		if strings.Contains(s, needle) {
			n++
		}
	}
	return n
}
func privateDir(t *testing.T) string {
	t.Helper()
	base := "/private/tmp"
	if _, e := os.Stat(base); e != nil {
		base = "/tmp"
	}
	p, e := os.MkdirTemp(base, "aster-node-test-")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(p, 0700); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(p) })
	return p
}
func newFixture(t *testing.T) (*Manager, *fakeRunner, nodeproto.NodeTask) {
	t.Helper()
	root := privateDir(t)
	storage := filepath.Join(root, "storage")
	_ = os.Mkdir(storage, 0755)
	imagePath := filepath.Join(root, "base.qcow2")
	body := []byte("synthetic qcow2 fixture; fake runner only")
	if e := os.WriteFile(imagePath, body, 0600); e != nil {
		t.Fatal(e)
	}
	f := &fakeRunner{domains: map[string][]byte{}, states: map[string]string{}, filter: ApprovedFilterXML("aster-static-ipv4")}
	key := make([]byte, 51)
	binary.BigEndian.PutUint32(key[:4], 11)
	copy(key[4:], "ssh-ed25519")
	binary.BigEndian.PutUint32(key[15:19], 32)
	for i := 19; i < 51; i++ {
		key[i] = byte(i)
	}
	c := Config{NodeID: "node-a", DatacenterID: "dc-a", NodeGroupID: "group-a", Listen: "127.0.0.1:9443", ExpectedControllerCertificateSHA256: strings.Repeat("a", 64), Certificate: filepath.Join(root, "server.crt"), PrivateKey: filepath.Join(root, "server.key"), ControllerCA: filepath.Join(root, "ca.crt"), StateDirectory: filepath.Join(root, "state"), StorageID: "local", StorageDirectory: storage, Images: map[string]Image{"ubuntu22": {imagePath, nodeproto.Digest(body)}}, AllowUnmeteredDefault: true, CPUAllocationLimit: 32, MemoryAllocationLimitMiB: 32768, DiskAllocationLimitGiB: 1000, Network: Network{Enabled: true, DedicatedBridgeAcknowledged: true, Bridge: "asterbr0", CIDR: "192.0.2.0/24", Gateway: "192.0.2.1", Addresses: []string{"192.0.2.10", "192.0.2.11"}, DNS: []string{"192.0.2.53"}, Filter: "aster-static-ipv4", FilterSHA256: nodeproto.Digest(f.filter), SSHAuthorizedKeys: []string{"ssh-ed25519 " + base64.StdEncoding.EncodeToString(key)}}}
	if e := c.Validate(); e != nil {
		t.Fatal("fixture config", e)
	}
	ledger, e := OpenLedger(c.StateDirectory, c.NodeID)
	if e != nil {
		t.Fatal(e)
	}
	m := &Manager{Config: c, Ledger: ledger, Runner: f, bridgeReady: func(string) error { return nil }, capacityRead: func(string) (nodeproto.Capacity, error) {
		return nodeproto.Capacity{CPUCoresTotal: 64, MemoryTotalMiB: 65536, MemoryAvailableMiB: 60000, StorageTotalGiB: 5000, StorageAvailableGiB: 4000}, nil
	}}
	t.Cleanup(func() { m.Shutdown(); ledger.Close() })
	task := nodeproto.NodeTask{Protocol: nodeproto.Protocol, OperationID: strings.Repeat("1", 32), NodeID: c.NodeID, Action: "create", InstanceID: strings.Repeat("2", 32), OwnerRef: strings.Repeat("3", 32), Hostname: "vm-a", Resources: controllerapi.Resources{DatacenterID: c.DatacenterID, NodeGroupID: c.NodeGroupID, ComputeNodeID: c.NodeID, ImageID: "ubuntu22", CPUCores: 1, MemoryMiB: 512, SystemDiskGiB: 10, SystemStorageID: c.StorageID, NetworkType: "normal", TrafficDirection: "all", IPv4Count: 1}}
	return m, f, task
}
func submit(t *testing.T, m *Manager, task nodeproto.NodeTask) nodeproto.NodeResult {
	t.Helper()
	raw, _, e := task.BytesAndDigest()
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r, e := m.Submit(ctx, task, raw)
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func next(task nodeproto.NodeTask, op, action string) nodeproto.NodeTask {
	task.OperationID = strings.Repeat(op, 32)
	task.Action = action
	task.ConfirmInstanceID = ""
	if action == "delete" {
		task.ConfirmInstanceID = task.InstanceID
	}
	return task
}
func TestCreateDurableClaimReserveAndExactReplay(t *testing.T) {
	m, f, task := newFixture(t)
	var once sync.Once
	f.before = func(string) {
		once.Do(func() {
			raw, e := readApproved(filepath.Join(m.Config.StateDirectory, "journal.json"), true, maxJournalBytes)
			if e != nil {
				t.Error(e)
				return
			}
			var j journal
			if json.Unmarshal(raw, &j) != nil || j.Operations[task.OperationID].Result.Status != "accepted" || j.Instances[task.InstanceID].IPv4 != "192.0.2.10" {
				t.Error("claim/address not durable before exec")
			}
		})
	}
	r := submit(t, m, task)
	if r.Status != "succeeded" {
		op, _ := m.Ledger.Query(task.OperationID)
		t.Fatal(r, op.ErrorCode)
	}
	r2 := submit(t, m, task)
	if r2 != r || f.count(" start ") != 1 || f.count(" define ") != 1 {
		t.Fatal("replayed create", r, r2, f.commands)
	}
	raw, _, _ := task.BytesAndDigest()
	if _, e := m.Accept(task, append(raw, ' ')); !errors.Is(e, ErrConflict) {
		t.Fatal("exact body conflict", e)
	}
	i, _ := m.Ledger.Instance(task.InstanceID)
	network, e := os.ReadFile(filepath.Join(i.Directory, "network-config"))
	if e != nil || !strings.Contains(string(network), "192.0.2.10/24") || !strings.Contains(string(network), "accept-ra: false") {
		t.Fatal("static seed missing", e)
	}
	if f.count("/bin/sh") != 0 {
		t.Fatal("shell invocation")
	}
}
func TestHTTPWaiterCancellationDoesNotCancelAcceptedWorker(t *testing.T) {
	m, f, task := newFixture(t)
	gate := make(chan struct{})
	f.block = gate
	raw, _, _ := task.BytesAndDigest()
	start := time.Now()
	r, e := m.Accept(task, raw)
	if e != nil || r.Status != "accepted" || time.Since(start) > time.Second {
		t.Fatal(r, e)
	}
	wait, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = m.Submit(wait, task, raw); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	busy := next(task, "4", "start")
	b := submit(t, m, busy)
	if b.Status != "rejected" {
		t.Fatal("single slot not enforced", b)
	}
	close(gate)
	if r = submit(t, m, task); r.Status != "succeeded" {
		t.Fatal(r)
	}
	if f.count(" define ") != 1 {
		t.Fatal("worker retried")
	}
}
func TestConcurrentSameOperationRunsOnce(t *testing.T) {
	m, f, task := newFixture(t)
	raw, _, _ := task.BytesAndDigest()
	var wg sync.WaitGroup
	for j := 0; j < 20; j++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := m.Accept(task, raw); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if r := submit(t, m, task); r.Status != "succeeded" {
		t.Fatal(r)
	}
	if f.count(" define ") != 1 {
		t.Fatal("concurrent duplicate execution")
	}
}
func TestInterruptedClaimNeverReexecutes(t *testing.T) {
	m, f, task := newFixture(t)
	raw, sha, _ := task.BytesAndDigest()
	if _, _, e := m.Ledger.Claim(task, sha); e != nil {
		t.Fatal(e)
	}
	_ = m.Ledger.Close()
	l, e := OpenLedger(m.Config.StateDirectory, m.Config.NodeID)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	m.Ledger = l
	r, e := m.Accept(task, raw)
	if e != nil || r.Status != "uncertain" || len(f.commands) != 0 {
		t.Fatal(r, e, f.commands)
	}
}
func TestCreateFailureRetainsDiskAddressAndNoCleanupRetry(t *testing.T) {
	m, f, task := newFixture(t)
	f.fail = "start"
	r := submit(t, m, task)
	if r.Status != "uncertain" {
		t.Fatal(r)
	}
	i, _ := m.Ledger.Instance(task.InstanceID)
	if i.State != "uncertain" || i.IPv4 == "" {
		t.Fatal(i)
	}
	if _, e := os.Stat(i.Disk); e != nil {
		t.Fatal("customer disk removed", e)
	}
	r = submit(t, m, task)
	if r.Status != "uncertain" || f.count(" start ") != 1 || f.count(" undefine ") != 0 {
		t.Fatal("uncertain was retried/rolled back", r)
	}
}
func TestShutdownCancelsWorkerAndRetainsUnknown(t *testing.T) {
	m, f, task := newFixture(t)
	gate := make(chan struct{})
	f.block = gate
	raw, _, _ := task.BytesAndDigest()
	if _, e := m.Accept(task, raw); e != nil {
		t.Fatal(e)
	}
	m.Shutdown()
	op, _ := m.Ledger.Query(task.OperationID)
	if op.Result.Status != "uncertain" {
		t.Fatal(op)
	}
	if r, e := m.Accept(task, raw); e != nil || r.Status != "uncertain" {
		t.Fatal(r, e)
	}
}
func TestRejectEveryUnsupportedResourceNotIgnored(t *testing.T) {
	cases := map[string]func(*controllerapi.Resources){"vpc": func(r *controllerapi.Resources) { r.NetworkType = "vpc" }, "ipv6": func(r *controllerapi.Resources) { r.IPv6Count = 1 }, "two_ipv4": func(r *controllerapi.Resources) { r.IPv4Count = 2 }, "bandwidth": func(r *controllerapi.Resources) { r.BandwidthMbps = 1 }, "inbound": func(r *controllerapi.Resources) { r.InboundBandwidthMbps = 1 }, "transfer": func(r *controllerapi.Resources) { r.TransferGiB = 1 }, "direction": func(r *controllerapi.Resources) { r.TrafficDirection = "out" }, "data_disk": func(r *controllerapi.Resources) { r.DataDiskGiB = 1 }, "data_storage": func(r *controllerapi.Resources) { r.DataStorageID = "other" }, "storage": func(r *controllerapi.Resources) { r.SystemStorageID = "other" }, "image": func(r *controllerapi.Resources) { r.ImageID = "../../etc/passwd" }, "node": func(r *controllerapi.Resources) { r.ComputeNodeID = "other" }, "cpu": func(r *controllerapi.Resources) { r.CPUCores = 0 }, "memory": func(r *controllerapi.Resources) { r.MemoryMiB = 129 }, "negative_disk": func(r *controllerapi.Resources) { r.SystemDiskGiB = -1 }, "no_nic": func(r *controllerapi.Resources) { r.IPv4Count = 0 }}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m, f, task := newFixture(t)
			mutate(&task.Resources)
			if r := submit(t, m, task); r.Status != "rejected" {
				t.Fatal(r)
			}
			if len(f.commands) != 0 {
				t.Fatal("unsupported reached host", f.commands)
			}
		})
	}
}
func TestCapacityAndAddressPoolConservative(t *testing.T) {
	m, _, task := newFixture(t)
	m.capacityRead = func(string) (nodeproto.Capacity, error) {
		return nodeproto.Capacity{MemoryAvailableMiB: 600, StorageAvailableGiB: 100}, nil
	}
	if r := submit(t, m, task); r.Status != "rejected" {
		t.Fatal(r)
	}
	m2, _, task2 := newFixture(t)
	m2.Config.Network.Addresses = []string{"192.0.2.10"}
	if r := submit(t, m2, task2); r.Status != "succeeded" {
		t.Fatal(r)
	}
	other := next(task2, "4", "create")
	other.InstanceID = strings.Repeat("5", 32)
	if r := submit(t, m2, other); r.Status != "rejected" {
		t.Fatal("address overallocated", r)
	}
}
func TestPreexistingForeignDomainNeverDefinedOrDiskTouched(t *testing.T) {
	m, f, task := newFixture(t)
	foreign := []byte(`<domain type="kvm"><name>foreign</name></domain>`)
	f.domains["aster-"+task.InstanceID] = foreign
	f.states["aster-"+task.InstanceID] = "running"
	if r := submit(t, m, task); r.Status != "uncertain" {
		t.Fatal(r)
	}
	if f.count(" define ") != 0 || f.count(" create ") != 0 || string(f.domains["aster-"+task.InstanceID]) != string(foreign) {
		t.Fatal("foreign domain overwritten")
	}
	if _, e := os.Stat(filepath.Join(m.Config.StorageDirectory, "aster-"+task.InstanceID)); !os.IsNotExist(e) {
		t.Fatal("disk directory touched", e)
	}
}
func TestInventoryFailureNeverMeansAbsent(t *testing.T) {
	m, f, task := newFixture(t)
	f.fail = "list"
	if r := submit(t, m, task); r.Status != "uncertain" {
		t.Fatal(r)
	}
	if f.count(" define ") != 0 || f.count(" create ") != 0 {
		t.Fatal("inventory error ignored")
	}
}
func TestImageAndNetworkFailureNeverStart(t *testing.T) {
	cases := map[string]func(*Manager, *fakeRunner){"digest": func(m *Manager, _ *fakeRunner) {
		im := m.Config.Images["ubuntu22"]
		im.SHA256 = strings.Repeat("0", 64)
		m.Config.Images["ubuntu22"] = im
	}, "large_virtual": func(_ *Manager, f *fakeRunner) { f.info = `{"format":"qcow2","virtual-size":999999999999}` }, "backing": func(_ *Manager, f *fakeRunner) {
		f.info = `{"format":"qcow2","virtual-size":1,"backing-filename":"/etc/passwd"}`
	}, "datafile": func(_ *Manager, f *fakeRunner) {
		f.info = `{"format":"qcow2","virtual-size":1,"format-specific":{"data-file":"/etc/passwd"}}`
	}, "filter_pin": func(_ *Manager, f *fakeRunner) { f.filter = []byte(`<filter/>`) }, "filter_policy": func(m *Manager, f *fakeRunner) {
		f.filter = []byte(`<filter name="aster-static-ipv4" chain="root"><rule action="accept" direction="inout"/></filter>`)
		m.Config.Network.FilterSHA256 = nodeproto.Digest(f.filter)
	}, "bridge": func(m *Manager, _ *fakeRunner) {
		m.bridgeReady = func(string) error { return errors.New("missing bridge") }
	}}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m, f, task := newFixture(t)
			mutate(m, f)
			if r := submit(t, m, task); r.Status != "uncertain" {
				t.Fatal(r)
			}
			if f.count(" define ") != 0 || f.count(" start ") != 0 {
				t.Fatal("unsafe image/network started")
			}
		})
	}
}
func TestPowerOwnershipAndDeleteGates(t *testing.T) {
	m, f, task := newFixture(t)
	if r := submit(t, m, task); r.Status != "succeeded" {
		t.Fatal(r)
	}
	bad := next(task, "4", "force_off")
	bad.OwnerRef = strings.Repeat("9", 32)
	if r := submit(t, m, bad); r.Status != "rejected" {
		t.Fatal(r)
	}
	if f.count(" destroy ") != 0 {
		t.Fatal("foreign power")
	}
	del := next(task, "5", "delete")
	if r := submit(t, m, del); r.Status != "rejected" {
		t.Fatal("default delete enabled", r)
	}
	m.Config.AllowDelete = true
	del = next(task, "6", "delete")
	if r := submit(t, m, del); r.Status != "rejected" {
		t.Fatal("running delete", r)
	}
	off := next(task, "7", "force_off")
	if r := submit(t, m, off); r.Status != "succeeded" {
		t.Fatal(r)
	}
	del = next(task, "8", "delete")
	if r := submit(t, m, del); r.Status != "succeeded" {
		t.Fatal(r)
	}
	i, _ := m.Ledger.Instance(task.InstanceID)
	if i.State != "deleted" || f.count(" undefine ") != 1 {
		t.Fatal(i)
	}
}
func TestOwnedXMLRejectsTamperingBeforePower(t *testing.T) {
	cases := map[string]func([]byte) []byte{"owner": func(s []byte) []byte {
		return []byte(strings.Replace(string(s), `owner_ref="`+strings.Repeat("3", 32)+`"`, `owner_ref="`+strings.Repeat("4", 32)+`"`, 1))
	}, "external_disk": func(s []byte) []byte { return []byte(strings.Replace(string(s), "system.qcow2", "foreign.qcow2", 1)) }, "bridge": func(s []byte) []byte { return []byte(strings.Replace(string(s), "asterbr0", "foreignbr", 1)) }, "isolation": func(s []byte) []byte { return []byte(strings.Replace(string(s), `isolated="yes"`, `isolated="no"`, 1)) }, "filter": func(s []byte) []byte {
		return []byte(strings.Replace(string(s), "aster-static-ipv4", "clean-traffic", 1))
	}, "hostdev": func(s []byte) []byte {
		return []byte(strings.Replace(string(s), "</devices>", "<hostdev/></devices>", 1))
	}, "cpu": func(s []byte) []byte {
		return []byte(strings.Replace(string(s), "<vcpu>1</vcpu>", "<vcpu>2</vcpu>", 1))
	}}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m, f, task := newFixture(t)
			if r := submit(t, m, task); r.Status != "succeeded" {
				t.Fatal(r)
			}
			f.domains["aster-"+task.InstanceID] = mutate(f.domains["aster-"+task.InstanceID])
			if r := submit(t, m, next(task, "4", "force_off")); r.Status != "rejected" {
				t.Fatal(r)
			}
			if f.count(" destroy ") != 0 {
				t.Fatal("tampered domain mutated")
			}
		})
	}
}
func TestNoVMZeroAndNoArbitraryCommands(t *testing.T) {
	m, f, task := newFixture(t)
	task.InstanceID = "0"
	raw, _ := json.Marshal(task)
	if _, e := m.Accept(task, raw); e == nil {
		t.Fatal("VM0 accepted")
	}
	if len(f.commands) != 0 {
		t.Fatal("VM0 host access")
	}
	if _, e := (OSRunner{}).Run(context.Background(), "/bin/sh", "-c", "true"); e == nil {
		t.Fatal("shell runner accepted")
	}
}
func TestReadonlyReconcileNeverRepeatsMutation(t *testing.T) {
	m, f, task := newFixture(t)
	f.fail = "start"
	if r := submit(t, m, task); r.Status != "uncertain" {
		t.Fatal(r)
	}
	f.fail = ""
	f.states["aster-"+task.InstanceID] = "running"
	beforeDefine, beforeStart := f.count(" define "), f.count(" start ")
	r, e := m.Reconcile(context.Background(), task.OperationID)
	if e != nil || r.Status != "succeeded" {
		t.Fatal(r, e)
	}
	if f.count(" define ") != beforeDefine || f.count(" start ") != beforeStart {
		t.Fatal("reconcile executed write")
	}
	reboot := next(task, "4", "reboot")
	if r := submit(t, m, reboot); r.Status != "uncertain" {
		t.Fatal(r)
	}
	if _, e = m.Reconcile(context.Background(), reboot.OperationID); e == nil {
		t.Fatal("running does not prove reboot")
	}
}

func TestPowerClaimQuarantinesInstanceBeforeExecAndBlocksOtherOperations(t *testing.T) {
	m, f, task := newFixture(t)
	if r := submit(t, m, task); r.Status != "succeeded" {
		t.Fatal(r)
	}
	gate := make(chan struct{})
	entered := make(chan struct{}, 1)
	// Only hold the mutating command. Blocking dumpxml instead makes Shutdown
	// race ownership preflight, where rejection is correct and not evidence of
	// an uncertain power command. The handshake pins the intended test phase.
	f.block, f.blockVerb, f.blocked = gate, "destroy", entered
	beforeXML, beforeState := f.count(" dumpxml "), f.count(" domstate ")
	off := next(task, "4", "force_off")
	raw, _, _ := off.BytesAndDigest()
	if r, e := m.Accept(off, raw); e != nil || r.Status != "accepted" {
		t.Fatal(r, e)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not reach the blocked destroy command")
	}
	if f.count(" dumpxml ") != beforeXML+1 || f.count(" domstate ") != beforeState+1 || f.count(" destroy ") != 0 {
		t.Fatal("power gate did not follow successful live preflight")
	}
	i, _ := m.Ledger.Instance(task.InstanceID)
	if i.State != "uncertain" {
		t.Fatal("power claim not durably quarantined", i)
	}
	m.Shutdown()
	op, _ := m.Ledger.Query(off.OperationID)
	if op.Result.Status != "uncertain" || op.ErrorCode != "POWER_OUTCOME_UNCERTAIN" {
		t.Fatal(op)
	}
	// Simulate process restart, not an automatic retry of the original operation.
	_ = m.Ledger.Close()
	l, e := OpenLedger(m.Config.StateDirectory, m.Config.NodeID)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	restarted := &Manager{Config: m.Config, Ledger: l, Runner: f}
	defer restarted.Shutdown()
	before := f.count(" destroy ")
	f.block = nil
	other := next(task, "5", "start")
	if r := submit(t, restarted, other); r.Status != "rejected" {
		t.Fatal(r)
	}
	if f.count(" destroy ") != before {
		t.Fatal("unknown power mutation retried")
	}
}

func TestAlreadyDesiredLiveStateCorrectsStaleLedgerWithoutPowerCommand(t *testing.T) {
	for _, action := range []string{"start", "shutdown", "force_off"} {
		t.Run(action, func(t *testing.T) {
			m, f, task := newFixture(t)
			if r := submit(t, m, task); r.Status != "succeeded" {
				t.Fatal(r)
			}
			i, _ := m.Ledger.Instance(task.InstanceID)
			live, stale := "shut off", "running"
			if action == "start" {
				live, stale = "running", "shut off"
			}
			i.State = stale
			if _, e := m.Ledger.Finish(task.OperationID, "succeeded", "TEST_STALE_LEDGER", &i); e != nil {
				t.Fatal(e)
			}
			f.states[i.Domain] = live
			before := f.count(" start ") + f.count(" shutdown ") + f.count(" destroy ")
			if r := submit(t, m, next(task, "4", action)); r.Status != "succeeded" {
				t.Fatal(r)
			}
			i, _ = m.Ledger.Instance(task.InstanceID)
			if i.State != live {
				t.Fatal("stale persisted state", i.State, live)
			}
			after := f.count(" start ") + f.count(" shutdown ") + f.count(" destroy ")
			if before != after {
				t.Fatal("already desired state mutated")
			}
		})
	}
}

func fakeQcowBytes() []byte {
	header := make([]byte, 512)
	copy(header, "QFI\xfb")
	binary.BigEndian.PutUint32(header[4:8], 3)
	binary.BigEndian.PutUint32(header[20:24], 16)
	binary.BigEndian.PutUint64(header[24:32], 1<<30)
	binary.BigEndian.PutUint32(header[96:100], 4)
	binary.BigEndian.PutUint32(header[100:104], 104)
	return append(header, []byte("synthetic fake-runner payload; not a real valid qcow2")...)
}

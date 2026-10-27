package hypervisor

import (
	"aster/cloud/internal/fabric"
	"aster/cloud/internal/nodeproto"
	"aster/cloud/internal/overlayproto"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const Virsh = "/usr/bin/virsh"
const QemuImg = "/usr/bin/qemu-img"
const CloudLocalDS = "/usr/bin/cloud-localds"
const Emulator = "/usr/bin/qemu-system-x86_64"

type Runner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}
type OSRunner struct{}
type boundedOutput struct {
	bytes.Buffer
	limit int
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, errors.New("command output exceeds limit")
	}
	return b.Buffer.Write(p)
}
func (OSRunner) Run(ctx context.Context, binary string, args ...string) ([]byte, error) {
	if binary != Virsh && binary != QemuImg && binary != CloudLocalDS {
		return nil, errors.New("binary not approved")
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.WaitDelay = 2 * time.Second
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "LANG=C", "LC_ALL=C"}
	out := &boundedOutput{limit: 1 << 20}
	cmd.Stdout = out
	cmd.Stderr = out
	err := cmd.Run()
	return out.Bytes(), err
}

type Manager struct {
	readOverlaySnapshot func(fabric.OverlayConfig) (overlayproto.Snapshot, string, error)
	loadOVSConfig       func(string) (fabric.Config, error)  // nil in production
	ovsFactory          func(fabric.Config) (ovsGate, error) // deterministic test seam
	loadOverlayConfig   func(string) (fabric.OverlayConfig, error)
	overlayFactory      func(fabric.Config) (overlayGate, error)

	hostIPv4s       func() ([]string, error) // production nil: complete native interface address inventory
	Config          Config
	Ledger          *Ledger
	Runner          Runner
	admission       sync.Mutex
	active          bool
	activeOperation string
	stopping        bool
	cancel          context.CancelFunc
	workers         sync.WaitGroup
	bridgeReady     func(string) error
	capacityRead    func(string) (nodeproto.Capacity, error)
	storageFS       func(string) error
	beforeRelease   func() // deterministic test seam; production nil
}

func (m *Manager) virsh(ctx context.Context, args ...string) ([]byte, error) {
	return m.Runner.Run(ctx, Virsh, append([]string{"--connect", "qemu:///system"}, args...)...)
}

// Accept durably claims an operation before starting a single detached worker.
// HTTP cancellation never cancels an accepted host command. Busy work is rejected,
// never queued or silently retried. A process crash leaves accepted => uncertain.
func (m *Manager) Accept(task nodeproto.NodeTask, raw []byte) (nodeproto.NodeResult, error) {
	if !task.Valid() || task.NodeID != m.Config.NodeID {
		return nodeproto.NodeResult{}, nodeproto.ErrInvalid
	}
	decoded, err := nodeproto.DecodeTask(raw)
	if err != nil || decoded != task {
		return nodeproto.NodeResult{}, nodeproto.ErrInvalid
	}
	m.admission.Lock()
	defer m.admission.Unlock()
	result, fresh, err := m.Ledger.Claim(task, nodeproto.Digest(raw))
	if err != nil {
		return result, err
	}
	if !fresh {
		return m.visibleResultLocked(result), nil
	}
	reject := func(code string) (nodeproto.NodeResult, error) {
		r, e := m.Ledger.Finish(task.OperationID, "rejected", code, nil)
		m.logOutcome(task, r, code, e == nil)
		return r, e
	}
	if m.Ledger.HasPendingInstance(task.InstanceID, task.OperationID) {
		return reject("UNRESOLVED_INSTANCE_OPERATION")
	}
	if m.stopping || m.Config.Maintenance {
		return reject("MAINTENANCE")
	}
	if m.active {
		return reject("NODE_BUSY")
	}
	if m.Config.Network.RequirePublicLease && task.DirectPublic.IsZero() && task.Resources.NetworkType == "normal" && task.Resources.IPv4Count == 1 && (task.Action == "create" || task.Action == "start" || task.Action == "reboot") {
		return reject("DIRECT_PUBLIC_LEASE_REQUIRED")
	}
	if !task.Network.IsZero() && m.Ledger.HasPendingNetworkProfile(task.Network.ProfileID, task.OperationID) {
		return reject("UNRESOLVED_NETWORK_PROFILE_OPERATION")
	}
	if err := m.checkOverlayAdmission(task); err != nil {
		return reject("OVERLAY_ADMISSION_UNCONFIRMED")
	}
	var prepared *Instance
	if task.Action == "create" {
		instance, e := m.prepare(task)
		if e != nil {
			return reject(safeCode(e))
		}
		if e = m.Ledger.Reserve(instance); e != nil {
			return reject(safeCode(e))
		}
		prepared = &instance
	} else {
		instance, ok := m.Ledger.Instance(task.InstanceID)
		if !ok {
			return reject("INSTANCE_NOT_FOUND")
		}
		if instance.OwnerRef != task.OwnerRef || instance.Hostname != task.Hostname || instance.Resources != task.Resources || instance.Network != task.Network || !directTaskMatches(instance, task) || instance.State == "reserved" || instance.State == "uncertain" || instance.State == "deleted" || instance.PublicRetired || instance.SourceFence != nil || (instance.TargetBinding != nil && !instance.TargetBinding.Activated) {
			return reject("OWNERSHIP_OR_STATE_REJECTED")
		}
		if !task.DirectPublic.IsZero() && (task.Action == "start" || task.Action == "reboot" || task.Action == "public_adopt") && m.approvedDirect(task.DirectPublic) != nil {
			return reject("DIRECT_PUBLIC_APPROVAL_REJECTED")
		}
		if task.Action == "public_adopt" {
			for _, other := range m.Ledger.Instances() {
				if other.ID != instance.ID && other.State != "deleted" && !other.DirectPublicDetached && (other.IPv4 == instance.IPv4 || !other.DirectPublic.IsZero() && other.DirectPublic.LeaseID == task.DirectPublic.LeaseID) {
					return reject("DIRECT_PUBLIC_ADDRESS_CONFLICT")
				}
			}
		}
		if instance.DirectPublicDetached && task.Action != "public_adopt" && task.Action != "public_detach" && task.Action != "delete" {
			return reject("DIRECT_PUBLIC_DETACHED")
		}
		if task.Action == "delete" && (!m.Config.AllowDelete || task.ConfirmInstanceID != instance.ID) {
			return reject("DELETE_DISABLED_OR_UNCONFIRMED")
		}
		if !instance.Network.IsZero() && task.Action == "reboot" {
			return reject("OVS_REBOOT_REQUIRES_SHUTDOWN_START")
		}
		prepared = &instance
		quarantine := instance
		quarantine.State = "uncertain"
		if r, e := m.Ledger.Finish(task.OperationID, "accepted", "MUTATION_IN_FLIGHT", &quarantine); e != nil {
			return r, e
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	m.cancel = cancel
	m.active = true
	m.activeOperation = task.OperationID
	m.workers.Add(1)
	m.logOutcome(task, result, "DURABLE_CLAIM", true)
	go func() {
		defer m.workers.Done()
		defer cancel()
		_, _ = m.execute(ctx, task, result, prepared)
		if m.beforeRelease != nil {
			m.beforeRelease()
		}
		m.admission.Lock()
		m.active = false
		m.activeOperation = ""
		m.cancel = nil
		m.admission.Unlock()
	}()
	return result, nil
}

// visibleResultLocked prevents a completed ledger write from advertising a free
// worker slot before its executor cleanup has actually released admission. The
// durable result is never changed; only this externally visible copy is masked.
func (m *Manager) visibleResultLocked(result nodeproto.NodeResult) nodeproto.NodeResult {
	if m.active && m.activeOperation == result.OperationID {
		result.Status = "accepted"
	}
	return result
}

// Lookup is the public result read path. Together with Accept replay, admission
// locking makes terminal visibility and availability of the next slot coherent.
func (m *Manager) Lookup(id string) (nodeproto.NodeResult, bool) {
	if !nodeproto.ValidID(id) {
		return nodeproto.NodeResult{}, false
	}
	m.admission.Lock()
	defer m.admission.Unlock()
	op, ok := m.Ledger.Query(id)
	if !ok {
		return nodeproto.NodeResult{}, false
	}
	return m.visibleResultLocked(op.Result), true
}

// Shutdown stops admission, cancels the sole worker, and waits until its final
// uncertain/succeeded result has been journaled. It must run before Ledger.Close.
func (m *Manager) Shutdown() {
	m.admission.Lock()
	m.stopping = true
	if m.cancel != nil {
		m.cancel()
	}
	m.admission.Unlock()
	m.workers.Wait()
}

// Submit is a local synchronous convenience; production HTTP uses Accept.
// A cancelled waiter does not cancel the durable background operation.
func (m *Manager) Submit(ctx context.Context, task nodeproto.NodeTask, raw []byte) (nodeproto.NodeResult, error) {
	result, err := m.Accept(task, raw)
	if err != nil || result.Status != "accepted" {
		return result, err
	}
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		case <-ticker.C:
			result, ok := m.Lookup(task.OperationID)
			if ok && result.Status != "accepted" {
				return result, nil
			}
		}
	}
}
func (m *Manager) execute(ctx context.Context, task nodeproto.NodeTask, result nodeproto.NodeResult, prepared *Instance) (nodeproto.NodeResult, error) {
	finish := func(status, code string, inst *Instance) (nodeproto.NodeResult, error) {
		r, e := m.Ledger.Finish(task.OperationID, status, code, inst)
		m.logOutcome(task, r, code, e == nil)
		if e != nil {
			result.Status = "uncertain"
			return result, e
		}
		return r, nil
	}
	if ctx.Err() != nil {
		return finish("uncertain", "CANCELLED_AFTER_CLAIM", nil)
	}
	if m.Config.Maintenance {
		return finish("rejected", "MAINTENANCE", nil)
	}
	if task.Action == "create" {
		if prepared == nil {
			return finish("uncertain", "RESERVATION_MISSING", nil)
		}
		instance := *prepared
		var e error
		if e = m.create(ctx, instance, task, result.RequestSHA256); e != nil {
			instance.State = "uncertain"
			return finish("uncertain", "CREATE_OUTCOME_UNCERTAIN", &instance)
		}
		instance.State = "running"
		return finish("succeeded", "", &instance)
	}
	if prepared == nil {
		return finish("uncertain", "RESERVATION_MISSING", nil)
	}
	instance := *prepared
	if instance.OwnerRef != task.OwnerRef || instance.Hostname != task.Hostname || instance.Resources != task.Resources || instance.Network != task.Network || !directTaskMatches(instance, task) || instance.State == "reserved" || instance.State == "uncertain" || instance.State == "deleted" || instance.PublicRetired || instance.SourceFence != nil || (instance.TargetBinding != nil && !instance.TargetBinding.Activated) {
		return finish("rejected", "OWNERSHIP_OR_STATE_REJECTED", nil)
	}
	if !task.DirectPublic.IsZero() && (task.Action == "start" || task.Action == "reboot" || task.Action == "public_adopt") && m.approvedDirect(task.DirectPublic) != nil {
		return finish("rejected", "DIRECT_PUBLIC_APPROVAL_REJECTED", nil)
	}
	if instance.DirectPublicDetached && task.Action != "public_adopt" && task.Action != "public_detach" && task.Action != "delete" {
		return finish("rejected", "DIRECT_PUBLIC_DETACHED", nil)
	}
	if task.Action == "public_adopt" || task.Action == "public_detach" {
		if e := m.assertOwned(ctx, instance); e != nil {
			return finish("rejected", "LIVE_OWNERSHIP_UNCONFIRMED", &instance)
		}
		if state, e := m.state(ctx, instance.Domain); e != nil || state != "shut off" {
			return finish("rejected", "DIRECT_PUBLIC_REQUIRES_SHUT_OFF", &instance)
		}
		next, err := m.mutateDirect(ctx, instance, task)
		if err != nil {
			next.State = "uncertain"
			return finish("uncertain", "DIRECT_PUBLIC_CHANGE_UNCONFIRMED", &next)
		}
		return finish("succeeded", "", &next)
	}
	if task.Action == "delete" && (!m.Config.AllowDelete || task.ConfirmInstanceID != instance.ID) {
		return finish("rejected", "DELETE_DISABLED_OR_UNCONFIRMED", nil)
	}
	if e := m.assertOwned(ctx, instance); e != nil {
		return finish("rejected", "LIVE_OWNERSHIP_UNCONFIRMED", nil)
	}
	state, e := m.state(ctx, instance.Domain)
	if e != nil {
		return finish("uncertain", "DOMAIN_STATE_UNAVAILABLE", nil)
	}
	if !instance.Network.IsZero() && (task.Action == "start" || task.Action == "shutdown" || task.Action == "force_off") {
		var err error
		switch task.Action {
		case "start":
			if state == "running" {
				err = m.checkOVS(ctx, instance, task, result.RequestSHA256)
			} else if state == "shut off" {
				err = m.startOVS(ctx, instance, task, result.RequestSHA256)
			} else {
				return finish("rejected", "DOMAIN_STATE_REJECTED", nil)
			}
			if err == nil {
				instance.State = "running"
			}
		default:
			cmd := "shutdown"
			if task.Action == "force_off" {
				cmd = "destroy"
			}
			err = m.stopOVS(ctx, instance, task, result.RequestSHA256, cmd)
			if err == nil {
				instance.State = "shut off"
			}
		}
		if err != nil {
			instance.State = "uncertain"
			return finish("uncertain", "OVS_LIFECYCLE_UNCONFIRMED", &instance)
		}
		return finish("succeeded", "", &instance)
	}
	if !instance.DirectPublic.IsZero() && (task.Action == "start" || task.Action == "reboot") {
		if e := m.verifyNetwork(ctx); e != nil {
			return finish("rejected", "DIRECT_PUBLIC_LIVE_NETWORK_UNCONFIRMED", &instance)
		}
	}
	var command string
	switch task.Action {
	case "start":
		if state == "running" {
			instance.State = state
			return finish("succeeded", "", &instance)
		}
		if state != "shut off" {
			return finish("rejected", "DOMAIN_STATE_REJECTED", &instance)
		}
		command = "start"
	case "shutdown":
		if state == "shut off" {
			instance.State = state
			return finish("succeeded", "", &instance)
		}
		if state != "running" {
			return finish("rejected", "DOMAIN_STATE_REJECTED", &instance)
		}
		command = "shutdown"
	case "reboot":
		if state != "running" {
			return finish("rejected", "DOMAIN_STATE_REJECTED", &instance)
		}
		command = "reboot"
	case "force_off":
		if state == "shut off" {
			instance.State = state
			return finish("succeeded", "", &instance)
		}
		if state != "running" {
			return finish("rejected", "DOMAIN_STATE_REJECTED", &instance)
		}
		command = "destroy"
	case "delete":
		if state != "shut off" {
			return finish("rejected", "DELETE_REQUIRES_POWER_OFF", &instance)
		}
		if !instance.Network.IsZero() {
			if err := m.stopOVS(ctx, instance, task, result.RequestSHA256, "destroy"); err != nil {
				return finish("uncertain", "OVS_DETACH_UNCONFIRMED", nil)
			}
		}
		command = "undefine"
	default:
		return finish("rejected", "UNSUPPORTED_ACTION", nil)
	}
	var recoveryPaths []string
	if task.Action == "delete" {
		var preflightErr error
		recoveryPaths, preflightErr = m.deletePreflight(ctx, instance)
		if preflightErr != nil {
			return finish("rejected", "DELETE_MANAGED_FILES_UNCONFIRMED", &instance)
		}
	}
	if _, e = m.virsh(ctx, command, instance.Domain); e != nil {
		instance.State = "uncertain"
		return finish("uncertain", "POWER_OUTCOME_UNCERTAIN", &instance)
	}
	if task.Action == "reboot" {
		instance.State = "uncertain"
		return finish("uncertain", "REBOOT_ACK_NOT_COMPLETION", &instance)
	}
	if task.Action == "delete" {
		// Destructive disk removal only after verified ownership, explicit confirmation and undefine.
		paths := []string{instance.Disk, instance.Seed, filepath.Join(instance.Directory, "user-data"), filepath.Join(instance.Directory, "meta-data"), filepath.Join(instance.Directory, "network-config"), filepath.Join(instance.Directory, "domain.xml")}
		paths = append(paths, recoveryPaths...)
		for _, path := range paths {
			if path == "" {
				continue
			}
			if _, e = os.Lstat(path); os.IsNotExist(e) {
				continue
			}
			if e = NoSymlinkPath(path); e != nil {
				instance.State = "uncertain"
				return finish("uncertain", "DELETE_PATH_REJECTED", &instance)
			}
			if e = os.Remove(path); e != nil {
				instance.State = "uncertain"
				return finish("uncertain", "DELETE_DISK_UNCERTAIN", &instance)
			}
		}
		if e = os.Remove(instance.Directory); e != nil {
			instance.State = "uncertain"
			return finish("uncertain", "DELETE_DIRECTORY_NOT_EMPTY", &instance)
		}
		instance.State = "deleted"
		return finish("succeeded", "", &instance)
	}
	desired := "shut off"
	if task.Action == "start" {
		desired = "running"
	}
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	for {
		state, e = m.state(ctx, instance.Domain)
		if e == nil && state == desired {
			instance.State = desired
			return finish("succeeded", "", &instance)
		}
		select {
		case <-ctx.Done():
			instance.State = "uncertain"
			return finish("uncertain", "POWER_STATE_UNCONFIRMED", &instance)
		case <-deadline.C:
			instance.State = "uncertain"
			return finish("uncertain", "POWER_STATE_UNCONFIRMED", &instance)
		case <-time.After(200 * time.Millisecond):
		}
	}
}
func safeCode(err error) string {
	switch {
	case errors.Is(err, ErrUnsupported):
		return "UNSUPPORTED_RESOURCES"
	case errors.Is(err, ErrConflict):
		return "INSTANCE_OR_ADDRESS_CONFLICT"
	default:
		return "CONFIGURATION_OR_CAPACITY_REJECTED"
	}
}
func (m *Manager) prepare(t nodeproto.NodeTask) (Instance, error) {
	return m.prepareWithRetired(t, false)
}
func (m *Manager) prepareWithRetired(t nodeproto.NodeTask, allowRetired bool) (Instance, error) {
	r := t.Resources
	c := m.Config
	if c.Network.RequirePublicLease && t.DirectPublic.IsZero() && r.NetworkType == "normal" && r.IPv4Count == 1 {
		return Instance{}, ErrUnsupported
	}
	if old, ok := m.Ledger.Instance(t.InstanceID); ok && (!allowRetired || !old.PublicRetired || old.State != "retired" || t.DirectPublic.IsZero() || t.DirectPublic.Generation <= old.DirectPublic.Generation) {
		return Instance{}, ErrConflict
	}
	if r.ComputeNodeID != "" && r.ComputeNodeID != c.NodeID || r.DatacenterID != "" && r.DatacenterID != c.DatacenterID || r.NodeGroupID != "" && r.NodeGroupID != c.NodeGroupID {
		return Instance{}, ErrUnsupported
	}
	if r.CPUCores < 1 || r.CPUCores > c.CPUAllocationLimit || r.MemoryMiB < 128 || r.MemoryMiB%128 != 0 || r.MemoryMiB > c.MemoryAllocationLimitMiB || r.SystemDiskGiB < 1 || r.SystemDiskGiB > c.DiskAllocationLimitGiB {
		return Instance{}, ErrUnsupported
	}
	if _, ok := c.Images[r.ImageID]; !ok {
		return Instance{}, ErrUnsupported
	}
	if r.SystemStorageID != c.StorageID || r.DataDiskGiB != 0 || r.DataStorageID != "" || r.TransferGiB != 0 || r.IPv6Count != 0 || r.TrafficDirection != "all" {
		return Instance{}, ErrUnsupported
	}
	if !t.DirectPublic.IsZero() {
		if !t.DirectPublic.ValidFor(t) || m.approvedDirect(t.DirectPublic) != nil {
			return Instance{}, ErrUnsupported
		}
	}
	if !t.Network.IsZero() {
		if t.Protocol != nodeproto.NetworkProtocol || !t.Network.ValidFor(t) {
			return Instance{}, ErrUnsupported
		}
		if _, p, e := m.approvedOVS(t.Network); e != nil || len(p.SSHAuthorizedKeys) == 0 {
			return Instance{}, ErrUnsupported
		}
	} else {
		if r.NetworkType != "normal" || r.BandwidthMbps != 0 || r.InboundBandwidthMbps != 0 || !c.AllowUnmeteredDefault || r.IPv4Count != 0 && r.IPv4Count != 1 || r.IPv4Count == 0 && !c.AllowIsolatedNoNIC || r.IPv4Count == 1 && !c.Network.Enabled {
			return Instance{}, ErrUnsupported
		}
	}
	cpu, memory, disk := 0, 0, 0
	used := map[string]bool{}
	for _, i := range m.Ledger.Instances() {
		if i.State == "deleted" || i.PublicRetired {
			continue
		}
		cpu += i.Resources.CPUCores
		memory += i.Resources.MemoryMiB
		disk += i.Resources.SystemDiskGiB
		if !i.DirectPublicDetached {
			used[i.IPv4] = true
		}
		if !t.Network.IsZero() && !i.Network.IsZero() && (i.Network.LeaseID == t.Network.LeaseID || fabric.TAPName(i.ID) == fabric.TAPName(t.InstanceID)) {
			return Instance{}, ErrConflict
		}
	}
	if cpu+r.CPUCores > c.CPUAllocationLimit || memory+r.MemoryMiB > c.MemoryAllocationLimitMiB || disk+r.SystemDiskGiB > c.DiskAllocationLimitGiB {
		return Instance{}, errors.New("allocation budget exhausted")
	}
	readCapacity := m.capacityRead
	if readCapacity == nil {
		readCapacity = HostCapacity
	}
	capacity, err := readCapacity(c.StorageDirectory)
	if err != nil || capacity.MemoryAvailableMiB < int64(r.MemoryMiB)+256 || capacity.StorageAvailableGiB < int64(r.SystemDiskGiB) {
		return Instance{}, errors.New("host capacity reserve unavailable")
	}
	instance := Instance{ID: t.InstanceID, OwnerRef: t.OwnerRef, Hostname: t.Hostname, Domain: "aster-" + t.InstanceID, Directory: filepath.Join(c.StorageDirectory, "aster-"+t.InstanceID), Resources: r, State: "reserved"}
	instance.Disk = filepath.Join(instance.Directory, "system.qcow2")
	if !t.Network.IsZero() {
		if used[t.Network.IPv4] {
			return Instance{}, ErrConflict
		}
		instance.Network = t.Network
		instance.IPv4 = t.Network.IPv4
		instance.MAC = t.Network.MAC
		instance.Seed = filepath.Join(instance.Directory, "seed.iso")
	} else if !t.DirectPublic.IsZero() {
		if used[t.DirectPublic.IPv4] {
			return Instance{}, ErrConflict
		}
		instance.DirectPublic = t.DirectPublic
		instance.IPv4 = t.DirectPublic.IPv4
		instance.MAC = t.DirectPublic.MAC
		instance.Seed = filepath.Join(instance.Directory, "seed.iso")
	} else if r.IPv4Count == 1 {
		for _, ip := range c.Network.Addresses {
			if !used[ip] {
				instance.IPv4 = ip
				break
			}
		}
		if instance.IPv4 == "" {
			return Instance{}, errors.New("IPv4 pool exhausted")
		}
		h := sha256.Sum256([]byte(c.NodeID + ":" + t.InstanceID))
		instance.MAC = fmt.Sprintf("52:54:%02x:%02x:%02x:%02x", h[0], h[1], h[2], h[3])
		instance.Seed = filepath.Join(instance.Directory, "seed.iso")
	}
	return instance, nil
}
func (m *Manager) create(ctx context.Context, i Instance, task nodeproto.NodeTask, sha string) error {
	if err := ownedPath(m.Config.StorageDirectory, false, true); err != nil {
		return err
	}
	names, err := m.virsh(ctx, "list", "--all", "--name")
	if err != nil {
		return errors.New("domain inventory unavailable")
	}
	for _, name := range strings.Fields(string(names)) {
		if name == i.Domain {
			return errors.New("domain already exists; manual reconciliation required")
		}
	}
	image := m.Config.Images[i.Resources.ImageID]
	if err := ownedPath(image.Path, false, false); err != nil {
		return err
	}
	f, err := openApproved(image.Path, false)
	if err != nil {
		return err
	}
	before, err := f.Stat()
	if err != nil || before.Size() < 1 || before.Size() > (int64(i.Resources.SystemDiskGiB)+1)<<30 {
		f.Close()
		return errors.New("approved image physical size rejected")
	}
	h := sha256.New()
	_, err = io.CopyBuffer(h, contextReader{ctx, f}, make([]byte, 128<<10))
	after, statErr := f.Stat()
	pathInfo, pathErr := os.Stat(image.Path)
	f.Close()
	if statErr != nil || pathErr != nil || !os.SameFile(before, pathInfo) || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return errors.New("approved image changed during verification")
	}

	if err != nil || hex.EncodeToString(h.Sum(nil)) != image.SHA256 {
		return errors.New("approved image digest mismatch")
	}
	raw, err := m.Runner.Run(ctx, QemuImg, "info", "--output=json", "-f", "qcow2", image.Path)
	if err != nil {
		return err
	}
	var info struct {
		Format      string          `json:"format"`
		VirtualSize uint64          `json:"virtual-size"`
		Backing     string          `json:"backing-filename"`
		Specific    json.RawMessage `json:"format-specific"`
	}
	if json.Unmarshal(raw, &info) != nil || info.Format != "qcow2" || info.VirtualSize == 0 || info.VirtualSize > uint64(i.Resources.SystemDiskGiB)<<30 || info.Backing != "" || bytes.Contains(info.Specific, []byte("data-file")) {
		return errors.New("base image must be flat qcow2 and fit system disk")
	}
	if i.IPv4 != "" && i.Network.IsZero() {
		if err = m.verifyNetwork(ctx); err != nil {
			return err
		}
	}
	if err = NoSymlinkPath(i.Directory); err != nil {
		return err
	}
	if err = os.Mkdir(i.Directory, 0755); err != nil {
		return err
	}
	disk, err := os.OpenFile(i.Disk, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	disk.Close()
	if _, err = m.Runner.Run(ctx, QemuImg, "create", "-f", "qcow2", "-F", "qcow2", "-b", image.Path, i.Disk, fmt.Sprintf("%dG", i.Resources.SystemDiskGiB)); err != nil {
		return err
	}
	if err = os.Chmod(i.Disk, 0600); err != nil {
		return err
	}
	if i.IPv4 != "" {
		if !i.Network.IsZero() {
			err = m.seedOVS(ctx, i)
		} else {
			err = m.seed(ctx, i)
		}
		if err != nil {
			return err
		}
	}
	definition, err := m.domainXML(i)
	if err != nil {
		return err
	}
	xmlPath := filepath.Join(i.Directory, "domain.xml")
	if err = writeExclusive(xmlPath, definition); err != nil {
		return err
	}
	if err = m.requireDomainAbsent(ctx, i.Domain); err != nil {
		return err
	}
	if _, err = m.virsh(ctx, "define", xmlPath); err != nil {
		return err
	}
	if err = m.assertOwned(ctx, i); err != nil {
		return err
	}
	if !i.Network.IsZero() {
		return m.startOVS(ctx, i, task, sha)
	}
	if _, err = m.virsh(ctx, "start", i.Domain); err != nil {
		return err
	}
	state, err := m.state(ctx, i.Domain)
	if err != nil || state != "running" {
		return errors.New("domain running state unconfirmed")
	}
	return nil
}

type contextReader struct {
	ctx    context.Context
	source io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.source.Read(p)
}

func writeExclusive(path string, body []byte) error {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(body)
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	return e
}
func (m *Manager) verifyNetwork(ctx context.Context) error {
	n := m.Config.Network
	if !n.Enabled {
		return ErrUnsupported
	}
	raw, err := m.virsh(ctx, "nwfilter-dumpxml", n.Filter)
	if err != nil || nodeproto.Digest(raw) != n.FilterSHA256 {
		return errors.New("preapproved nwfilter missing or changed")
	}
	if n.RequirePublicLease {
		err = validateDirectFilter(raw, n.Filter)
	} else {
		err = validateFilter(raw, n.Filter)
	}
	if err != nil {
		return err
	}
	if m.bridgeReady != nil {
		return m.bridgeReady(n.Bridge)
	}
	if _, err = os.Stat(filepath.Join("/sys/class/net", n.Bridge, "bridge")); err != nil {
		return errors.New("preconfigured Linux bridge missing")
	}
	return nil
}
func (m *Manager) seed(ctx context.Context, i Instance) error {
	n := m.Config.Network
	prefix, _ := netip.ParsePrefix(n.CIDR)
	q := func(s string) string { raw, _ := json.Marshal(s); return string(raw) }
	network := fmt.Sprintf("version: 2\nethernets:\n  aster0:\n    match:\n      macaddress: %s\n    set-name: aster0\n    dhcp4: false\n    dhcp6: false\n    accept-ra: false\n    link-local: []\n    addresses: [%s]\n    routes:\n      - to: 0.0.0.0/0\n        via: %s\n", q(i.MAC), q(fmt.Sprintf("%s/%d", i.IPv4, prefix.Bits())), q(n.Gateway))
	if len(n.DNS) > 0 {
		network += "    nameservers:\n      addresses: ["
		for index, dns := range n.DNS {
			if index > 0 {
				network += ", "
			}
			network += q(dns)
		}
		network += "]\n"
	}
	return m.seedFiles(ctx, i, n.SSHAuthorizedKeys, network)
}
func (m *Manager) seedFiles(ctx context.Context, i Instance, keys []string, network string) error {
	q := func(s string) string { raw, _ := json.Marshal(s); return string(raw) }
	body := "#cloud-config\nssh_pwauth: false\ndisable_root: true\nusers:\n  - name: aster\n    lock_passwd: true\n    groups: [sudo]\n    sudo: ['ALL=(ALL) NOPASSWD:ALL']\n    shell: /bin/bash\n    ssh_authorized_keys:\n"
	for _, key := range keys {
		body += "      - " + q(key) + "\n"
	}
	for file, data := range map[string]string{"user-data": body, "meta-data": "instance-id: " + q(i.ID) + "\nlocal-hostname: " + q(i.Hostname) + "\n", "network-config": network} {
		if err := writeExclusive(filepath.Join(i.Directory, file), []byte(data)); err != nil {
			return err
		}
	}
	_, err := m.Runner.Run(ctx, CloudLocalDS, "--network-config", filepath.Join(i.Directory, "network-config"), i.Seed, filepath.Join(i.Directory, "user-data"), filepath.Join(i.Directory, "meta-data"))
	if err == nil {
		err = os.Chmod(i.Seed, 0600)
	}
	return err
}
func (m *Manager) state(ctx context.Context, domain string) (string, error) {
	out, err := m.virsh(ctx, "domstate", domain)
	return strings.TrimSpace(string(out)), err
}

type ownershipXML struct {
	DirectPublicSHA256 string   `xml:"direct_public_sha256,attr,omitempty"`
	NetworkSHA256      string   `xml:"network_sha256,attr,omitempty"`
	XMLName            xml.Name `xml:"urn:aster:node:1 instance"`
	InstanceID         string   `xml:"instance_id,attr"`
	OwnerRef           string   `xml:"owner_ref,attr"`
	NodeID             string   `xml:"node_id,attr"`
}
type diskXML struct {
	Device string `xml:"device,attr"`
	Type   string `xml:"type,attr"`
	Driver *struct {
		Name string `xml:"name,attr"`
		Type string `xml:"type,attr"`
	} `xml:"driver,omitempty"`
	Source struct {
		File string `xml:"file,attr"`
	} `xml:"source"`
	Target struct {
		Dev string `xml:"dev,attr"`
		Bus string `xml:"bus,attr"`
	} `xml:"target"`
	ReadOnly *struct{} `xml:"readonly,omitempty"`
}
type nicPortXML struct {
	Isolated string `xml:"isolated,attr"`
}
type nicFilterXML struct {
	Filter     string         `xml:"filter,attr"`
	Parameters []parameterXML `xml:"parameter"`
}
type nicVirtualPortXML struct {
	Type       string `xml:"type,attr"`
	Parameters struct {
		InterfaceID string `xml:"interfaceid,attr"`
	} `xml:"parameters"`
}
type nicTargetXML struct {
	Dev string `xml:"dev,attr"`
}
type nicLinkXML struct {
	State string `xml:"state,attr"`
}
type interfaceXML struct {
	MTU *struct {
		Size int `xml:"size,attr"`
	} `xml:"mtu,omitempty"`
	Type string `xml:"type,attr"`
	MAC  struct {
		Address string `xml:"address,attr"`
	} `xml:"mac"`
	Source struct {
		Bridge string `xml:"bridge,attr"`
	} `xml:"source"`
	Model struct {
		Type string `xml:"type,attr"`
	} `xml:"model"`
	Port        *nicPortXML        `xml:"port,omitempty"`
	Filter      *nicFilterXML      `xml:"filterref,omitempty"`
	VirtualPort *nicVirtualPortXML `xml:"virtualport,omitempty"`
	Target      *nicTargetXML      `xml:"target,omitempty"`
	Link        *nicLinkXML        `xml:"link,omitempty"`
}
type parameterXML struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}
type domainXML struct {
	UUID    string   `xml:"uuid,omitempty"`
	XMLName xml.Name `xml:"domain"`
	Type    string   `xml:"type,attr"`
	Name    string   `xml:"name"`
	Memory  struct {
		Unit  string `xml:"unit,attr"`
		Value int    `xml:",chardata"`
	} `xml:"memory"`
	VCPU     int `xml:"vcpu"`
	Metadata struct {
		Instance ownershipXML `xml:"instance"`
	} `xml:"metadata"`
	OS struct {
		Type struct {
			Arch  string `xml:"arch,attr"`
			Value string `xml:",chardata"`
		} `xml:"type"`
	} `xml:"os"`
	OnPoweroff string `xml:"on_poweroff"`
	OnReboot   string `xml:"on_reboot"`
	OnCrash    string `xml:"on_crash"`
	Devices    struct {
		Emulator   string         `xml:"emulator"`
		Disks      []diskXML      `xml:"disk"`
		Interfaces []interfaceXML `xml:"interface"`
		Serial     *struct {
			Type string `xml:"type,attr"`
		} `xml:"serial,omitempty"`
	} `xml:"devices"`
}

func (m *Manager) domainXML(i Instance) ([]byte, error) {
	var d domainXML
	d.Type = "kvm"
	d.Name = i.Domain
	d.Memory.Unit = "MiB"
	d.Memory.Value = i.Resources.MemoryMiB
	d.VCPU = i.Resources.CPUCores
	d.Metadata.Instance = ownershipXML{InstanceID: i.ID, OwnerRef: i.OwnerRef, NodeID: m.Config.NodeID}
	if !i.DirectPublic.IsZero() {
		d.Metadata.Instance.DirectPublicSHA256 = i.DirectPublic.Digest()
	}
	d.OS.Type.Arch = "x86_64"
	d.OS.Type.Value = "hvm"
	d.OnPoweroff = "destroy"
	d.OnReboot = "restart"
	d.OnCrash = "preserve"
	if !i.Network.IsZero() {
		d.UUID = fabric.DomainID(i.ID)
		d.OnReboot = "destroy"
		d.Metadata.Instance.NetworkSHA256 = i.Network.Digest()
	}
	d.Devices.Emulator = Emulator
	disk := diskXML{Type: "file", Device: "disk"}
	disk.Driver = &struct {
		Name string `xml:"name,attr"`
		Type string `xml:"type,attr"`
	}{"qemu", "qcow2"}
	disk.Source.File = i.Disk
	disk.Target.Dev = "vda"
	disk.Target.Bus = "virtio"
	d.Devices.Disks = append(d.Devices.Disks, disk)
	if i.Seed != "" {
		seed := diskXML{Type: "file", Device: "cdrom", ReadOnly: &struct{}{}}
		seed.Source.File = i.Seed
		seed.Target.Dev = "sda"
		seed.Target.Bus = "sata"
		d.Devices.Disks = append(d.Devices.Disks, seed)
	}
	if i.IPv4 != "" {
		var nic interfaceXML
		nic.Type = "bridge"
		nic.MAC.Address = i.MAC
		nic.Source.Bridge = m.Config.Network.Bridge
		nic.Model.Type = "virtio"
		if i.Network.IsZero() {
			if !i.DirectPublic.IsZero() {
				nic.Link = &nicLinkXML{State: "up"}
				if i.DirectPublicDetached || i.SourceFence != nil {
					nic.Link.State = "down"
				}
			}
			nic.Port = &nicPortXML{Isolated: "yes"}
			nic.Filter = &nicFilterXML{Filter: m.Config.Network.Filter, Parameters: []parameterXML{{"IP", i.IPv4}, {"MAC", i.MAC}, {"CTRL_IP_LEARNING", "none"}}}
			if !i.DirectPublic.IsZero() {
				ips, e := m.directHostIPv4s()
				if e != nil {
					return nil, e
				}
				nic.Filter.Parameters = append(nic.Filter.Parameters, parameterXML{"GATEWAY", i.DirectPublic.Gateway})
				for _, ip := range ips {
					nic.Filter.Parameters = append(nic.Filter.Parameters, parameterXML{"HOST_IPS", ip})
				}
			}
		} else {
			c, _, e := m.approvedOVS(i.Network)
			if e != nil {
				return nil, e
			}
			nic.Source.Bridge = c.Bridge
			nic.Target = &nicTargetXML{Dev: fabric.TAPName(i.ID)}
			nic.Link = &nicLinkXML{State: "down"}
			nic.VirtualPort = &nicVirtualPortXML{Type: "openvswitch"}
			nic.VirtualPort.Parameters.InterfaceID = i.Network.InterfaceID
			if m.Config.OVSProfiles[i.Network.ProfileID].OverlayConfig != "" {
				o, _, err := m.approvedOverlay(i.Network.ProfileID)
				if err != nil {
					return nil, err
				}
				nic.MTU = &struct {
					Size int `xml:"size,attr"`
				}{o.GuestMTU}
			}
		}
		d.Devices.Interfaces = []interfaceXML{nic}
	}
	return xml.MarshalIndent(d, "", "  ")
}
func (m *Manager) assertOwned(ctx context.Context, i Instance) error {
	if !nodeproto.ValidID(i.ID) || i.Domain != "aster-"+i.ID || i.Directory != filepath.Join(m.Config.StorageDirectory, i.Domain) || i.Disk != filepath.Join(i.Directory, "system.qcow2") {
		return ErrOwnership
	}
	if err := NoSymlinkPath(i.Directory); err != nil {
		return err
	}
	raw, err := m.virsh(ctx, "dumpxml", i.Domain)
	if err != nil {
		return err
	}
	var domain domainXML
	if xml.Unmarshal(raw, &domain) != nil || domain.Type != "kvm" || domain.Name != i.Domain || domain.Metadata.Instance.XMLName.Space != "urn:aster:node:1" || domain.Metadata.Instance.InstanceID != i.ID || domain.Metadata.Instance.OwnerRef != i.OwnerRef || domain.Metadata.Instance.NodeID != m.Config.NodeID {
		return ErrOwnership
	}
	if domain.VCPU != i.Resources.CPUCores || domain.Devices.Emulator != Emulator || domain.OS.Type.Arch != "x86_64" || domain.OS.Type.Value != "hvm" {
		return ErrOwnership
	}
	memory := domain.Memory.Value
	switch domain.Memory.Unit {
	case "MiB":
	case "KiB", "":
		if memory%1024 != 0 {
			return ErrOwnership
		}
		memory /= 1024
	default:
		return ErrOwnership
	}
	if memory != i.Resources.MemoryMiB {
		return ErrOwnership
	}
	if i.Seed != "" && i.Seed != filepath.Join(i.Directory, "seed.iso") {
		return ErrOwnership
	}
	expected := 1
	if i.Seed != "" {
		expected = 2
	}
	if len(domain.Devices.Disks) != expected {
		return ErrOwnership
	}
	seen := map[string]bool{}
	for _, disk := range domain.Devices.Disks {
		if seen[disk.Source.File] || disk.Type != "file" {
			return ErrOwnership
		}
		seen[disk.Source.File] = true
		switch disk.Source.File {
		case i.Disk:
			if disk.Device != "disk" || disk.Target.Dev != "vda" || disk.Target.Bus != "virtio" || disk.Driver == nil || disk.Driver.Name != "qemu" || disk.Driver.Type != "qcow2" {
				return ErrOwnership
			}
		case i.Seed:
			if i.Seed == "" || disk.Device != "cdrom" || disk.ReadOnly == nil {
				return ErrOwnership
			}
		default:
			return ErrOwnership
		}
	}
	if i.IPv4 == "" {
		if len(domain.Devices.Interfaces) != 0 {
			return ErrOwnership
		}
	} else if !i.Network.IsZero() {
		if e := m.assertOVSDomain(i, domain, false); e != nil {
			return e
		}
	} else {
		if len(domain.Devices.Interfaces) != 1 {
			return ErrOwnership
		}
		nic := domain.Devices.Interfaces[0]
		if nic.Type != "bridge" || nic.MAC.Address != i.MAC || nic.Source.Bridge != m.Config.Network.Bridge || nic.Port == nil || nic.Filter == nil || nic.VirtualPort != nil || nic.Port.Isolated != "yes" || nic.Model.Type != "virtio" || nic.Filter.Filter != m.Config.Network.Filter {
			return ErrOwnership
		}
		if !i.DirectPublic.IsZero() {
			if domain.Metadata.Instance.DirectPublicSHA256 != i.DirectPublic.Digest() || nic.Link == nil || nic.Link.State != "up" && !i.DirectPublicDetached && i.SourceFence == nil || (i.DirectPublicDetached || i.SourceFence != nil) && nic.Link.State != "down" {
				return ErrOwnership
			}
		} else if domain.Metadata.Instance.DirectPublicSHA256 != "" {
			return ErrOwnership
		}
		params := map[string]string{}
		hostIPs := map[string]bool{}
		for _, p := range nic.Filter.Parameters {
			if !i.DirectPublic.IsZero() && p.Name == "HOST_IPS" {
				if hostIPs[p.Value] {
					return ErrOwnership
				}
				hostIPs[p.Value] = true
				continue
			}
			if _, ok := params[p.Name]; ok {
				return ErrOwnership
			}
			params[p.Name] = p.Value
		}
		expectedParams := 3
		if !i.DirectPublic.IsZero() {
			expectedParams = 4
			if params["GATEWAY"] != i.DirectPublic.Gateway {
				return ErrOwnership
			}
			ips, e := m.directHostIPv4s()
			if e != nil || len(ips) != len(hostIPs) {
				return ErrOwnership
			}
			for _, ip := range ips {
				if !hostIPs[ip] {
					return ErrOwnership
				}
			}
		}
		if len(params) != expectedParams || params["IP"] != i.IPv4 || params["MAC"] != i.MAC || params["CTRL_IP_LEARNING"] != "none" {
			return ErrOwnership
		}
	}
	// Root-side XML tampering cannot extend our ownership to unrelated devices.
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	for {
		token, e := decoder.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return ErrOwnership
		}
		if start, ok := token.(xml.StartElement); ok {
			switch start.Name.Local {
			case "hostdev", "filesystem", "redirdev", "commandline", "shmem":
				return ErrOwnership
			}
		}
	}
	return nil
}

// Safe journald event metadata only; never log certificates, SSH keys, task bodies,
// raw subprocess output, seed contents or guest credentials.
func (m *Manager) logOutcome(task nodeproto.NodeTask, result nodeproto.NodeResult, code string, durable bool) {
	level := slog.LevelInfo
	if result.Status == "uncertain" || !durable {
		level = slog.LevelWarn
	}
	if !durable {
		result.Status = "uncertain"
		code = "JOURNAL_WRITE_UNCONFIRMED"
	}
	slog.Log(context.Background(), level, "aster_node_operation", "node_id", m.Config.NodeID, "operation_id", task.OperationID, "instance_id", task.InstanceID, "action", task.Action, "status", result.Status, "request_sha256", result.RequestSHA256, "code", code, "journal_write_confirmed", durable)
}

func (m *Manager) deletePreflight(ctx context.Context, i Instance) ([]string, error) {
	allowed := map[string]bool{"system.qcow2": true, "domain.xml": true}
	if i.Seed != "" {
		for _, name := range []string{"seed.iso", "user-data", "meta-data", "network-config"} {
			allowed[name] = true
		}
	}
	paths := []string{}
	for _, r := range m.Ledger.Recoveries(i.ID) {
		if !strings.HasPrefix(r.PreviousDiskName, "system.qcow2.before-") || !nodeproto.ValidID(strings.TrimPrefix(r.PreviousDiskName, "system.qcow2.before-")) {
			return nil, ErrOwnership
		}
		path := filepath.Join(i.Directory, r.PreviousDiskName)
		hash, size, e := m.hashDisk(ctx, path, (int64(i.Resources.SystemDiskGiB)+1)<<30)
		if e != nil || hash != r.PreviousDiskSHA256 || size != r.PreviousDiskBytes {
			return nil, ErrOwnership
		}
		allowed[r.PreviousDiskName] = true
		paths = append(paths, path)
	}
	entries, e := os.ReadDir(i.Directory)
	if e != nil {
		return nil, e
	}
	for _, entry := range entries {
		if !allowed[entry.Name()] || entry.IsDir() {
			return nil, ErrOwnership
		}
		if e = NoSymlinkPath(filepath.Join(i.Directory, entry.Name())); e != nil {
			return nil, e
		}
	}
	return paths, nil
}

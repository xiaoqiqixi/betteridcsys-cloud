package hypervisor

import (
	"aster/billing/serviceapi"
	"aster/cloud/internal/nodeproto"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type guestRunner struct {
	*fakeRunner
	inputCalls int
	password   string
	failInput  bool
}

func (r *guestRunner) Run(ctx context.Context, binary string, args ...string) ([]byte, error) {
	if binary == QemuImg && args[0] == "resize" {
		r.fakeRunner.mu.Lock()
		defer r.fakeRunner.mu.Unlock()
		r.commands = append(r.commands, binary+" "+strings.Join(args, " "))
		if r.fail == "resize" {
			return nil, errors.New("resize failed")
		}
		return nil, nil
	}
	return r.fakeRunner.Run(ctx, binary, args...)
}
func (r *guestRunner) RunInput(ctx context.Context, binary string, input []byte, args ...string) ([]byte, error) {
	r.inputCalls++
	r.password = string(input)
	if strings.Contains(strings.Join(args, " "), strings.TrimSpace(string(input))) {
		return nil, errors.New("secret in argv")
	}
	if r.failInput {
		return nil, errors.New("credential command failed")
	}
	if binary == OpenSSL {
		return []byte("$6$test$hash-not-plaintext\n"), nil
	}
	if binary == VirtCustomize {
		return nil, nil
	}
	return nil, ErrUnsupported
}
func guestFixture(t *testing.T) (*Manager, *guestRunner, nodeproto.NodeTask) {
	m, f, task := newFixture(t)
	m.Config.Guest = GuestConfig{Enabled: true, Families: map[string]string{"ubuntu22": "linux"}, RescueImages: []string{"ubuntu22"}}
	runner := &guestRunner{fakeRunner: f}
	m.Runner = runner
	if r := submit(t, m, task); r.Status != "succeeded" {
		t.Fatal(r)
	}
	return m, runner, task
}
func guestTask(m *Manager, t nodeproto.NodeTask, op, action string, p serviceapi.Params) nodeproto.NodeTask {
	t = next(t, op, action)
	i, _ := m.Ledger.Instance(t.InstanceID)
	t.Resources = i.Resources
	t.Guest = nodeproto.GuestParams{Params: p, PasswordRequired: p.Password != ""}
	if p.ImageID != "" {
		t.Guest.ImageSHA256 = m.Config.Images[p.ImageID].SHA256
	}
	return t
}
func TestGuestSuspendPersistsStartBlockAndUnsuspendIsExplicit(t *testing.T) {
	m, f, task := guestFixture(t)
	if r := submit(t, m, guestTask(m, task, "4", "suspend", serviceapi.Params{})); r.Status != "succeeded" {
		t.Fatal(r)
	}
	i, _ := m.Ledger.Instance(task.InstanceID)
	if !i.Suspended || i.State != "shut off" {
		t.Fatal(i)
	}
	if r := submit(t, m, next(task, "5", "start")); r.Status != "rejected" {
		t.Fatal(r)
	}
	starts := f.count(" start ")
	if r := submit(t, m, guestTask(m, task, "6", "unsuspend", serviceapi.Params{})); r.Status != "succeeded" || f.count(" start ") != starts {
		t.Fatal(r)
	}
	if r := submit(t, m, guestTask(m, task, "7", "unsuspend", serviceapi.Params{StartAfter: true})); r.Status != "succeeded" || f.count(" start ") != starts+1 {
		t.Fatal(r)
	}
}
func TestGuestReinstallRetainsOriginalUntilRunningAndChangesSeedIdentity(t *testing.T) {
	m, f, task := guestFixture(t)
	i, _ := m.Ledger.Instance(task.InstanceID)
	op := strings.Repeat("4", 32)
	seenOld := false
	f.before = func(cmd string) {
		if strings.Contains(cmd, " start ") {
			_, e := os.Stat(guestBackup(i.Disk, op))
			seenOld = e == nil
		}
	}
	r := submit(t, m, guestTask(m, task, "4", "reinstall", serviceapi.Params{ImageID: "ubuntu22", Password: "only-memory-guest-secret"}))
	if r.Status != "succeeded" || !seenOld {
		t.Fatal(r, seenOld)
	}
	if _, e := os.Stat(guestBackup(i.Disk, op)); !os.IsNotExist(e) {
		t.Fatal("old disk not retired after running")
	}
	meta, _ := os.ReadFile(filepath.Join(i.Directory, "meta-data"))
	if !strings.Contains(string(meta), op) {
		t.Fatal("cloud-init identity reused")
	}
	assertNoGuestSecret(t, m, "only-memory-guest-secret")
}
func assertNoGuestSecret(t *testing.T, m *Manager, secret string) {
	t.Helper()
	for _, root := range []string{m.Config.StateDirectory, m.Config.StorageDirectory} {
		e := filepath.WalkDir(root, func(p string, d os.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if !d.IsDir() {
				b, e := os.ReadFile(p)
				if e != nil {
					return e
				}
				if strings.Contains(string(b), secret) {
					t.Error("secret persisted in", p)
				}
			}
			return nil
		})
		if e != nil {
			t.Fatal(e)
		}
	}
}
func TestGuestReinstallFailureRollsBackWithoutDeletingOriginal(t *testing.T) {
	m, f, task := guestFixture(t)
	i, _ := m.Ledger.Instance(task.InstanceID)
	before, _ := os.Stat(i.Disk)
	f.fail = "create"
	r := submit(t, m, guestTask(m, task, "4", "reinstall", serviceapi.Params{ImageID: "ubuntu22", SSHPublicKey: m.Config.Network.SSHAuthorizedKeys[0]}))
	after, _ := os.Stat(i.Disk)
	restored, _ := m.Ledger.Instance(i.ID)
	if r.Status != "rejected" || r.Code != "REINSTALL_ROLLED_BACK" || !os.SameFile(before, after) || restored.State != "running" || restored.GuestChange != nil {
		t.Fatal(r, restored)
	}
}
func TestGuestRescuePersistsOriginalSecondDiskAcrossRestart(t *testing.T) {
	m, f, task := guestFixture(t)
	if r := submit(t, m, guestTask(m, task, "4", "rescue_enter", serviceapi.Params{ImageID: "ubuntu22"})); r.Status != "succeeded" {
		t.Fatal(r)
	}
	i, _ := m.Ledger.Instance(task.InstanceID)
	var d domainXML
	_ = xml.Unmarshal(f.domains[i.Domain], &d)
	if i.Rescue == nil || len(d.Devices.Disks) != 3 || d.Devices.Disks[0].Source.File != rescueDisk(i) || d.Devices.Disks[1].Source.File != i.Disk || d.Devices.Disks[1].ReadOnly == nil {
		t.Fatal("original disk not protected", d.Devices.Disks)
	}
	m.Ledger.Close()
	reopened, e := OpenLedger(m.Config.StateDirectory, m.Config.NodeID)
	if e != nil {
		t.Fatal(e)
	}
	m.Ledger = reopened
	defer reopened.Close()
	if r := submit(t, m, guestTask(m, task, "5", "rescue_exit", serviceapi.Params{})); r.Status != "succeeded" {
		t.Fatal(r)
	}
	i, _ = m.Ledger.Instance(i.ID)
	if i.Rescue != nil || i.State != "running" {
		t.Fatal(i)
	}
}
func TestGuestPasswordResetIsOfflineAndNeverPersisted(t *testing.T) {
	m, f, task := guestFixture(t)
	secret := "test-reset-password-not-on-disk"
	before := f.count(" destroy ")
	if r := submit(t, m, guestTask(m, task, "4", "reset_password", serviceapi.Params{Password: secret})); r.Status != "succeeded" || f.inputCalls != 1 || f.count(" destroy ") != before+1 {
		t.Fatal(r)
	}
	assertNoGuestSecret(t, m, secret)
	m.Config.Guest.Families[task.Resources.ImageID] = "windows"
	old, _ := m.Ledger.Instance(task.InstanceID)
	if r := submit(t, m, guestTask(m, task, "5", "reset_password", serviceapi.Params{Password: secret})); r.Status != "rejected" || r.Code != "UNSUPPORTED_GUEST" {
		t.Fatal(r)
	}
	after, _ := m.Ledger.Instance(task.InstanceID)
	if !reflect.DeepEqual(old, after) {
		t.Fatal("rejected reset changed instance")
	}
}
func TestGuestResizeStoppedOnlyAndGrowOnly(t *testing.T) {
	m, f, task := guestFixture(t)
	p := serviceapi.Params{CPUCores: 2, MemoryMB: 1024, DiskGB: 20}
	if r := submit(t, m, guestTask(m, task, "4", "resize", p)); r.Status != "rejected" {
		t.Fatal(r)
	}
	if r := submit(t, m, next(task, "5", "force_off")); r.Status != "succeeded" {
		t.Fatal(r)
	}
	if r := submit(t, m, guestTask(m, task, "6", "resize", p)); r.Status != "succeeded" || f.count(" resize ") != 1 {
		t.Fatal(r)
	}
	i, _ := m.Ledger.Instance(task.InstanceID)
	if i.Resources.SystemDiskGiB != 20 || i.Resources.CPUCores != 2 || i.Resources.MemoryMiB != 1024 {
		t.Fatal(i)
	}
	p.DiskGB = 10
	if r := submit(t, m, guestTask(m, task, "7", "resize", p)); r.Status != "rejected" || r.Code != "DISK_SHRINK_FORBIDDEN" {
		t.Fatal(r)
	}
}
func TestGuestFailuresAreUncertainAndReplayNeverExecutes(t *testing.T) {
	for _, action := range []string{"suspend", "unsuspend", "resize", "reinstall", "reset_password", "rescue_enter", "rescue_exit"} {
		t.Run(action, func(t *testing.T) {
			m, f, task := guestFixture(t)
			p := serviceapi.Params{}
			switch action {
			case "resize":
				_ = submit(t, m, next(task, "3", "force_off"))
				p = serviceapi.Params{CPUCores: 2, MemoryMB: 1024, DiskGB: 20}
				f.fail = "resize"
			case "unsuspend":
				_ = submit(t, m, guestTask(m, task, "3", "suspend", p))
				p.StartAfter = true
				f.fail = "start"
			case "rescue_exit":
				_ = submit(t, m, guestTask(m, task, "3", "rescue_enter", serviceapi.Params{ImageID: "ubuntu22"}))
				f.fail = "destroy"
			case "reinstall":
				p = serviceapi.Params{ImageID: "ubuntu22", SSHPublicKey: m.Config.Network.SSHAuthorizedKeys[0]}
				f.fail = "start"
			case "rescue_enter":
				p.ImageID = "ubuntu22"
				f.fail = "define"
			case "reset_password":
				p.Password = "secret-to-discard"
				f.failInput = true
			default:
				f.fail = "destroy"
			}
			tsk := guestTask(m, task, "4", action, p)
			result := submit(t, m, tsk)
			if result.Status != "uncertain" {
				t.Fatal(result)
			}
			commands := len(f.commands)
			_ = submit(t, m, tsk)
			if len(f.commands) != commands {
				t.Fatal("uncertain operation retried")
			}
			i, _ := m.Ledger.Instance(task.InstanceID)
			if i.State != "uncertain" {
				t.Fatal("lost quarantine")
			}
			if _, e := os.Stat(i.Disk); e != nil {
				t.Fatal("customer disk lost")
			}
		})
	}
}
func TestGuestIntentCrashRedactsPasswordAndRefusesOldJournalSchema(t *testing.T) {
	m, _, task := guestFixture(t)
	tsk := guestTask(m, task, "4", "reset_password", serviceapi.Params{Password: "crash-secret"})
	raw, sha, _ := tsk.BytesAndDigest()
	if _, _, e := m.Ledger.Claim(tsk, sha); e != nil {
		t.Fatal(e)
	}
	_ = raw
	m.Ledger.Close()
	l, e := OpenLedger(m.Config.StateDirectory, m.Config.NodeID)
	if e != nil {
		t.Fatal(e)
	}
	m.Ledger = l
	op, _ := l.Query(tsk.OperationID)
	if op.Result.Status != "uncertain" || op.Task.Guest.Params.Password != "" {
		t.Fatal(op.Result)
	}
	l.Close()
	assertNoGuestSecret(t, m, "crash-secret")
	path := filepath.Join(m.Config.StateDirectory, "journal.json")
	data, _ := os.ReadFile(path)
	var j journal
	_ = json.Unmarshal(data, &j)
	if j.Schema != 7 {
		t.Fatal(j.Schema)
	}
	j.Schema = 6
	data, _ = json.Marshal(j)
	_ = os.WriteFile(path, data, 0600)
	if bad, e := OpenLedger(m.Config.StateDirectory, m.Config.NodeID); e == nil {
		bad.Close()
		t.Fatal("old schema accepted guest state")
	}
}

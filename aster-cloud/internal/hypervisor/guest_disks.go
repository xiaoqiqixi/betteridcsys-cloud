package hypervisor

import (
	"aster/billing/serviceapi"
	"aster/cloud/internal/nodeproto"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const VirtCustomize = "/usr/bin/virt-customize"
const OpenSSL = "/usr/bin/openssl"

// InputRunner passes a credential through a pipe, never argv, environment or a
// host temporary file. Raw subprocess diagnostics are discarded for secrets.
type InputRunner interface {
	RunInput(context.Context, string, []byte, ...string) ([]byte, error)
}

func (OSRunner) RunInput(ctx context.Context, binary string, input []byte, args ...string) ([]byte, error) {
	if binary != VirtCustomize && binary != OpenSSL {
		return nil, errors.New("binary not approved for secret input")
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.WaitDelay = 2 * time.Second
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "LANG=C", "LC_ALL=C", "LIBGUESTFS_BACKEND=direct"}
	cmd.Stdin = bytes.NewReader(input)
	out := &boundedOutput{limit: 8192}
	cmd.Stdout = out
	cmd.Stderr = io.Discard
	if cmd.Run() != nil {
		return nil, errors.New("guest credential command failed")
	}
	return out.Bytes(), nil
}
func (m *Manager) resetGuestPassword(ctx context.Context, i Instance, password string) error {
	runner, ok := m.Runner.(InputRunner)
	if !ok {
		return ErrUnsupported
	}
	if e := ownedPath(i.Disk, true, false); e != nil {
		return e
	}
	if e := validateQcowHeader(i.Disk, m.Config.Images[i.Resources.ImageID].Path); e != nil {
		return e
	}
	_, e := runner.RunInput(ctx, VirtCustomize, []byte(password+"\n"), "--no-network", "--no-logfile", "--format", "qcow2", "-a", i.Disk, "--root-password", "file:/dev/stdin", "--password-crypto", "sha512")
	return e
}
func (m *Manager) verifyGuestImage(ctx context.Context, id, sha string, diskGB int) error {
	image, ok := m.Config.Images[id]
	if !ok || image.SHA256 != sha {
		return ErrUnsupported
	}
	f, e := openApproved(image.Path, false)
	if e != nil {
		return e
	}
	defer f.Close()
	before, e := f.Stat()
	if e != nil || before.Size() < 1 || before.Size() > (int64(diskGB)+1)<<30 {
		return ErrUnsupported
	}
	h := sha256.New()
	_, e = io.CopyBuffer(h, contextReader{ctx, f}, make([]byte, 128<<10))
	after, statErr := f.Stat()
	current, pathErr := os.Stat(image.Path)
	if e != nil || statErr != nil || pathErr != nil || !os.SameFile(before, after) || !os.SameFile(before, current) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || hex.EncodeToString(h.Sum(nil)) != sha {
		return ErrOwnership
	}
	raw, e := m.Runner.Run(ctx, QemuImg, "info", "--output=json", "-f", "qcow2", image.Path)
	var info struct {
		Format   string          `json:"format"`
		Size     uint64          `json:"virtual-size"`
		Backing  string          `json:"backing-filename"`
		Specific json.RawMessage `json:"format-specific"`
	}
	if e != nil || json.Unmarshal(raw, &info) != nil || info.Format != "qcow2" || info.Size == 0 || info.Size > uint64(diskGB)<<30 || info.Backing != "" || bytes.Contains(info.Specific, []byte("data-file")) {
		return ErrUnsupported
	}
	return nil
}
func (m *Manager) newGuestDisk(ctx context.Context, path, imageID string, gb int) error {
	if e := NoSymlinkPath(path); e != nil {
		return e
	}
	if e := writeExclusive(path, nil); e != nil {
		return e
	}
	_, e := m.Runner.Run(ctx, QemuImg, "create", "-f", "qcow2", "-F", "qcow2", "-b", m.Config.Images[imageID].Path, path, fmt.Sprintf("%dG", gb))
	if e != nil {
		return e
	}
	return os.Chmod(path, 0600)
}
func guestSeedNames() []string {
	return []string{"seed.iso", "user-data", "meta-data", "network-config"}
}
func guestBackup(path, op string) string { return path + ".before-" + op }
func syncGuestDir(dir string) error {
	f, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func (m *Manager) reinstall(ctx context.Context, t nodeproto.NodeTask, i Instance) (Instance, error) {
	if e := m.guestStop(ctx, t, i); e != nil {
		return i, e
	}
	if e := m.guestCheckpoint(t, i, "REPLACE_DISK"); e != nil {
		return i, e
	}
	backup := guestBackup(i.Disk, t.OperationID)
	if _, e := os.Lstat(backup); !os.IsNotExist(e) {
		return i, ErrConflict
	}
	if e := ownedPath(i.Disk, true, false); e != nil {
		return i, e
	}
	if e := os.Rename(i.Disk, backup); e != nil {
		return i, e
	}
	if i.Seed != "" {
		for _, name := range guestSeedNames() {
			path := filepath.Join(i.Directory, name)
			if e := ownedPath(path, false, false); e != nil {
				return i, e
			}
			target := guestBackup(path, t.OperationID)
			if _, e := os.Lstat(target); !os.IsNotExist(e) {
				return i, ErrConflict
			}
			if e := os.Rename(path, target); e != nil {
				return i, e
			}
		}
	}
	if e := syncGuestDir(i.Directory); e != nil {
		return i, e
	}
	i.Resources.ImageID = t.Guest.Params.ImageID
	if e := m.newGuestDisk(ctx, i.Disk, i.Resources.ImageID, i.Resources.SystemDiskGiB); e != nil {
		return i, e
	}
	i.Seed = filepath.Join(i.Directory, "seed.iso")
	if e := m.seedGuest(ctx, t, i); e != nil {
		return i, e
	}
	if e := m.guestCheckpoint(t, i, "DEFINE_NEW"); e != nil {
		return i, e
	}
	if e := m.redefineGuest(ctx, i); e != nil {
		return i, e
	}
	if e := m.guestStart(ctx, t, i); e != nil {
		return i, e
	}
	i.State = "running"
	if e := m.guestCheckpoint(t, i, "NEW_RUNNING"); e != nil {
		return i, e
	}
	// The old disk survives every uncertain start, and is removed only after
	// both running observation and its durable checkpoint.
	if e := os.Remove(backup); e != nil {
		return i, e
	}
	if i.GuestChange.PreviousSeed {
		for _, name := range guestSeedNames() {
			if e := os.Remove(guestBackup(filepath.Join(i.Directory, name), t.OperationID)); e != nil {
				return i, e
			}
		}
	}
	return i, syncGuestDir(i.Directory)
}
func (m *Manager) rollbackReinstall(ctx context.Context, t nodeproto.NodeTask, i Instance) (Instance, bool) {
	change := i.GuestChange
	if change == nil {
		return i, false
	}
	backup := guestBackup(i.Disk, t.OperationID)
	if ownedPath(backup, true, false) != nil {
		return i, false
	}
	state, e := m.state(ctx, i.Domain)
	if e != nil || state != "shut off" {
		return i, false
	}
	old := i
	old.Resources = change.PreviousResources
	old.Rescue = nil
	if change.PreviousSeed {
		old.Seed = filepath.Join(old.Directory, "seed.iso")
	} else {
		old.Seed = ""
	}
	// The only admissible definitions are the saved preimage or the new one.
	if m.assertOwned(ctx, i) != nil && m.assertOwned(ctx, old) != nil {
		return i, false
	}
	if m.guestCheckpoint(t, i, "ROLLBACK") != nil {
		return i, false
	}
	failed := i.Disk + ".failed-" + t.OperationID
	if _, e = os.Lstat(i.Disk); e == nil {
		if NoSymlinkPath(i.Disk) != nil {
			return i, false
		}
		if e = os.Rename(i.Disk, failed); e != nil {
			return i, false
		}
	} else if !os.IsNotExist(e) {
		return i, false
	}
	if e = os.Rename(backup, i.Disk); e != nil {
		return i, false
	}
	for _, name := range guestSeedNames() {
		path := filepath.Join(i.Directory, name)
		before := guestBackup(path, t.OperationID)
		if _, e = os.Lstat(before); e == nil {
			if NoSymlinkPath(path) != nil || os.Rename(before, path) != nil {
				return i, false
			}
		} else if !os.IsNotExist(e) {
			return i, false
		} else if !change.PreviousSeed {
			if e = os.Remove(path); e != nil && !os.IsNotExist(e) {
				return i, false
			}
		}
	}
	if e = m.redefineGuest(ctx, old); e != nil {
		return i, false
	}
	old.State = "shut off"
	if change.WasRunning {
		if e = m.guestStart(ctx, t, old); e != nil {
			return i, false
		}
		old.State = "running"
	}
	// The replacement is discarded only once the original is restored and its
	// intended power state is observed. It never contains the original disk.
	if e = os.Remove(failed); e != nil && !os.IsNotExist(e) {
		return i, false
	}
	old.GuestChange = nil
	return old, syncGuestDir(old.Directory) == nil
}
func (m *Manager) seedGuest(ctx context.Context, t nodeproto.NodeTask, i Instance) error {
	// Reuse the existing approved network generator, then replace only cloud-init
	// identity and credentials before any domain can start.
	var seedErr error
	if i.IPv4 == "" {
		seedErr = m.seedFiles(ctx, i, nil, "version: 2\nethernets: {}\n")
	} else {
		seedErr = m.seed(ctx, i)
	}
	if e := seedErr; e != nil {
		return e
	}
	quote := func(s string) string { b, _ := json.Marshal(s); return string(b) }
	body := "#cloud-config\ndisable_root: false\ngrowpart:\n  mode: auto\n  devices: ['/']\nresize_rootfs: true\nusers:\n  - name: root\n    lock_passwd: false\n"
	// SSH keys and a password may both be set. Authorize every provided key;
	// password auth is enabled only when a password (or its hash) is set.
	keys := t.Guest.Params.Keys()
	if len(keys) > 0 {
		body += "    ssh_authorized_keys:\n"
		for _, key := range keys {
			body += "      - " + quote(key) + "\n"
		}
	}
	if t.Guest.Params.PasswordHash != "" {
		if !serviceapi.ValidPasswordHash(t.Guest.Params.PasswordHash) {
			return ErrUnsupported
		}
		body += "    hashed_passwd: " + quote(t.Guest.Params.PasswordHash) + "\nssh_pwauth: true\n"
	} else if t.Guest.Params.Password != "" {
		runner, ok := m.Runner.(InputRunner)
		if !ok {
			return ErrUnsupported
		}
		hash, e := runner.RunInput(ctx, OpenSSL, []byte(t.Guest.Params.Password+"\n"), "passwd", "-6", "-stdin")
		if e != nil {
			return e
		}
		value := strings.TrimSpace(string(hash))
		if !strings.HasPrefix(value, "$6$") || len(value) > 256 || strings.ContainsAny(value, "\n\r") {
			return ErrUnsupported
		}
		body += "    hashed_passwd: " + quote(value) + "\nssh_pwauth: true\n"
	} else {
		body += "ssh_pwauth: false\n"
	}
	for name, value := range map[string]string{"user-data": body, "meta-data": "instance-id: " + quote(i.ID+"-"+t.OperationID) + "\nlocal-hostname: " + quote(i.Hostname) + "\n"} {
		path := filepath.Join(i.Directory, name)
		if e := ownedPath(path, true, false); e != nil {
			return e
		}
		if e := os.WriteFile(path, []byte(value), 0600); e != nil {
			return e
		}
	}
	_, e := m.Runner.Run(ctx, CloudLocalDS, "--network-config", filepath.Join(i.Directory, "network-config"), i.Seed, filepath.Join(i.Directory, "user-data"), filepath.Join(i.Directory, "meta-data"))
	if e != nil {
		return e
	}
	return os.Chmod(i.Seed, 0644)
}

// A private customer disk needs libvirt's DAC relabel while attached read-only.
// libvirt does not restore read-only source ownership on stop. After the owned
// domain is observed shut off, return only its exact private, singly-linked
// system disk to the node user. Base images and seeds are never relabelled.
func restoreRescueDiskOwner(i Instance) error {
	if i.Rescue == nil || i.Rescue.Writable {
		return nil
	}
	if i.Disk != filepath.Join(i.Directory, "system.qcow2") || ownedPath(i.Directory, false, true) != nil {
		return ErrOwnership
	}
	f, e := os.OpenFile(i.Disk, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return e
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Nlink != 1 || info.Mode().Perm() != 0600 {
		return ErrOwnership
	}
	if e = f.Chown(os.Geteuid(), os.Getegid()); e != nil {
		return e
	}
	return f.Sync()
}
func rescueDisk(i Instance) string {
	return filepath.Join(i.Directory, "rescue-"+i.Rescue.OperationID+".qcow2")
}
func (m *Manager) enterRescue(ctx context.Context, t nodeproto.NodeTask, i Instance) (Instance, error) {
	if e := m.guestStop(ctx, t, i); e != nil {
		return i, e
	}
	i.Rescue = &RescueState{t.OperationID, t.Guest.Params.ImageID, t.Guest.ImageSHA256, m.Config.Guest.RescueWritable}
	if e := m.guestCheckpoint(t, i, "RESCUE_DISK"); e != nil {
		return i, e
	}
	if e := m.newGuestDisk(ctx, rescueDisk(i), i.Rescue.ImageID, i.Resources.SystemDiskGiB); e != nil {
		return i, e
	}
	if e := m.redefineGuest(ctx, i); e != nil {
		return i, e
	}
	if e := m.guestStart(ctx, t, i); e != nil {
		return i, e
	}
	i.State = "running"
	return i, nil
}
func (m *Manager) exitRescue(ctx context.Context, t nodeproto.NodeTask, i Instance) (Instance, error) {
	if e := m.guestStop(ctx, t, i); e != nil {
		return i, e
	}
	disk := rescueDisk(i)
	if e := m.guestCheckpoint(t, i, "RESTORE_ORIGINAL"); e != nil {
		return i, e
	}
	i.Rescue = nil
	if e := m.redefineGuest(ctx, i); e != nil {
		return i, e
	}
	if e := m.guestStart(ctx, t, i); e != nil {
		return i, e
	}
	i.State = "running"
	if e := m.guestCheckpoint(t, i, "ORIGINAL_RUNNING"); e != nil {
		return i, e
	}
	if e := NoSymlinkPath(disk); e != nil {
		return i, e
	}
	if e := os.Remove(disk); e != nil {
		return i, e
	}
	return i, syncGuestDir(i.Directory)
}

func guestSystemDevice(i Instance) string {
	if i.Rescue != nil {
		return "vdb"
	}
	return "vda"
}

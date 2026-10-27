//go:build linux

package controllerhost

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"syscall"
	"time"
)

var controllerName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
var operationName = regexp.MustCompile(`^[a-f0-9]{32}$`)
var digestName = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Host struct {
	dir, control  *os.File
	id, configSHA string
}

type intent struct {
	Schema       int    `json:"schema"`
	ControllerID string `json:"controller_id"`
	OperationID  string `json:"operation_id"`
	ConfigSHA    string `json:"configuration_sha256"`
	CreatedAt    string `json:"created_at"`
	Phase        string `json:"phase"`
}

// Open has no path or owner override. The fixed host-local directory cannot be
// placed on a shared filesystem: this guard must not be mistaken for HA fencing.
func Open(id, configSHA string) (*Host, error) {
	if os.Geteuid() != 0 || !controllerName.MatchString(id) || !digestName.MatchString(configSHA) {
		return nil, ErrInvalid
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	for index, part := range []string{"var", "lib", "aster-controller", id} {
		if index >= 2 {
			if e := syscall.Mkdirat(fd, part, 0700); e != nil && !errors.Is(e, syscall.EEXIST) {
				syscall.Close(fd)
				return nil, ErrUnavailable
			}
			if syscall.Fsync(fd) != nil {
				syscall.Close(fd)
				return nil, ErrUnavailable
			}
		}
		next, e := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		syscall.Close(fd)
		if e != nil {
			return nil, ErrUnavailable
		}
		fd = next
		var st syscall.Stat_t
		mode := uint32(0022)
		if index >= 2 {
			mode = 0077
		}
		if syscall.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&mode != 0 {
			syscall.Close(fd)
			return nil, ErrUnavailable
		}
	}
	var fs syscall.Statfs_t
	if syscall.Fstatfs(fd, &fs) != nil {
		syscall.Close(fd)
		return nil, ErrUnavailable
	}
	switch uint64(fs.Type) {
	case 0xef53, 0x58465342, 0x9123683e: // persistent local ext4, XFS or Btrfs, never tmpfs/NFS/overlay
	default:
		syscall.Close(fd)
		return nil, ErrUnavailable
	}
	h := &Host{dir: os.NewFile(uintptr(fd), "controller-host-state"), id: id, configSHA: configSHA}
	h.control, err = h.file("control.lock", true)
	if err != nil {
		h.Close()
		return nil, err
	}
	return h, nil
}

func (h *Host) Close() {
	if h.control != nil {
		_ = h.control.Close()
	}
	if h.dir != nil {
		_ = h.dir.Close()
	}
}

func (h *Host) file(name string, create bool) (*os.File, error) {
	flags := syscall.O_RDWR | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC
	if create {
		flags |= syscall.O_CREAT
	}
	fd, e := syscall.Openat(int(h.dir.Fd()), name, flags, 0600)
	if e != nil {
		return nil, e
	}
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Uid != 0 || st.Nlink != 1 || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Mode&0777 != 0600 || st.Size > 4096 {
		syscall.Close(fd)
		return nil, ErrUnavailable
	}
	return os.NewFile(uintptr(fd), "controller-host-record"), nil
}

func (h *Host) lock() error {
	if syscall.Flock(int(h.control.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return ErrBusy
	}
	return nil
}
func (h *Host) unlock() { _ = syscall.Flock(int(h.control.Fd()), syscall.LOCK_UN) }

// Admit retains a raw, CLOEXEC descriptor until process exit. Do not wrap it in
// os.File, defer its close, or release it when HTTP Shutdown begins: background
// workers may still be settling an uncertain result. Only OS process exit is
// the end of this lease. CLI commands call Admit once, before any DB/node work.
func (h *Host) Admit() error {
	if e := h.lock(); e != nil {
		return e
	}
	defer h.unlock()
	if e := h.Check(); e != nil {
		return e
	}
	f, e := h.file("runtime.lock", true)
	if e != nil {
		return ErrUnavailable
	}
	defer f.Close()
	duplicate, _, errno := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), syscall.F_DUPFD_CLOEXEC, 0)
	if errno != 0 {
		return ErrUnavailable
	}
	fd := int(duplicate)
	if syscall.Flock(fd, syscall.LOCK_SH|syscall.LOCK_NB) != nil {
		syscall.Close(fd)
		return ErrBusy
	}
	return nil
}

// Any fence inode (including an incomplete/corrupt one) blocks admission.
func (h *Host) Check() error {
	for _, name := range []string{"fence.json", "host-migration.json"} {
		f, e := h.file(name, false)
		if errors.Is(e, syscall.ENOENT) {
			continue
		}
		if f != nil {
			f.Close()
		}
		if e != nil {
			return ErrUnavailable
		}
		return ErrFenced
	}
	return nil
}

func (h *Host) read(name string) (intent, error) {
	f, e := h.file(name, false)
	if e != nil {
		return intent{}, e
	}
	defer f.Close()
	raw, e := io.ReadAll(io.LimitReader(f, 4097))
	if e != nil || len(raw) > 4096 {
		return intent{}, ErrUnavailable
	}
	var v intent
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil || d.Decode(new(any)) != io.EOF || v.Schema != 1 || v.ControllerID != h.id ||
		!operationName.MatchString(v.OperationID) || !digestName.MatchString(v.ConfigSHA) || v.Phase != "fenced" {
		return intent{}, ErrUnavailable
	}
	if _, e := time.Parse(time.RFC3339Nano, v.CreatedAt); e != nil {
		return intent{}, ErrUnavailable
	}
	return v, nil
}

// Immutable files are never overwritten, even after a partial write. Failure
// leaves a fail-closed record requiring diagnosis, not an automatic retry reset.
func (h *Host) writeNew(name string, v intent) error {
	raw, e := json.Marshal(v)
	if e != nil {
		return ErrUnavailable
	}
	fd, e := syscall.Openat(int(h.dir.Fd()), name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if e != nil {
		return ErrUnavailable
	}
	f := os.NewFile(uintptr(fd), "controller-host-record")
	defer f.Close()
	if _, e = f.Write(append(raw, '\n')); e != nil {
		return ErrUnavailable
	}
	if f.Sync() != nil || h.dir.Sync() != nil {
		return ErrUnavailable
	}
	return nil
}

func (h *Host) drained() (bool, error) {
	f, e := h.file("runtime.lock", true)
	if e != nil {
		return false, ErrUnavailable
	}
	defer f.Close()
	e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(e, syscall.EWOULDBLOCK) {
		return false, nil
	}
	if e != nil {
		return false, ErrUnavailable
	}
	return true, nil // close releases the exclusive probe while control.lock is held
}

func (h *Host) statusLocked() (Status, error) {
	s := Status{Schema: 1, ControllerID: h.id, Phase: "active"}
	v, e := h.read("fence.json")
	if errors.Is(e, syscall.ENOENT) {
		if h.Check() != nil {
			return Status{}, ErrUnavailable
		}
		return s, nil
	}
	if e != nil {
		return Status{}, ErrUnavailable
	}
	s.OperationID, s.Phase, s.AdmissionBlocked = v.OperationID, "draining", true
	s.GuardedDrained, e = h.drained()
	if s.GuardedDrained {
		s.Phase = "fenced"
	}
	// No claim about old binaries, systemd masks, remote processes, or a target.
	return s, e
}

func (h *Host) Status() (Status, error) {
	if e := h.lock(); e != nil {
		return Status{}, e
	}
	defer h.unlock()
	return h.statusLocked()
}

// WithSealedSource excludes admission, cancel and host-seal changes for the
// entire export. It does not claim systemd isolation: the coordinator and the
// export reader must additionally validate their durable host receipts.
func (h *Host) WithSealedSource(operation string, action func() error) error {
	if !operationName.MatchString(operation) || action == nil {
		return ErrInvalid
	}
	if e := h.lock(); e != nil {
		return e
	}
	defer h.unlock()
	v, e := h.read("fence.json")
	if e != nil || v.OperationID != operation || v.ConfigSHA != h.configSHA {
		return ErrInvalid
	}
	f, e := h.file("host-migration.json", false)
	if e != nil {
		return ErrInvalid
	}
	f.Close()
	drained, e := h.drained()
	if e != nil || !drained {
		return ErrBusy
	}
	return action()
}

func (h *Host) Fence(operation string) (Status, error) {
	if !operationName.MatchString(operation) {
		return Status{}, ErrInvalid
	}
	if e := h.lock(); e != nil {
		return Status{}, e
	}
	defer h.unlock()
	if _, e := h.read(operation + ".cancelled.json"); !errors.Is(e, syscall.ENOENT) {
		return Status{}, ErrInvalid
	}
	v, e := h.read("fence.json")
	if e == nil {
		if v.OperationID != operation || v.ConfigSHA != h.configSHA {
			return Status{}, ErrInvalid
		}
		return h.statusLocked()
	}
	if !errors.Is(e, syscall.ENOENT) {
		return Status{}, ErrUnavailable
	}
	v, e = h.read(operation + ".intent.json")
	if errors.Is(e, syscall.ENOENT) {
		v = intent{1, h.id, operation, h.configSHA, time.Now().UTC().Format(time.RFC3339Nano), "fenced"}
		if e = h.writeNew(operation+".intent.json", v); e != nil {
			return Status{}, e
		}
	} else if e != nil || v.ConfigSHA != h.configSHA || v.OperationID != operation {
		return Status{}, ErrInvalid
	}
	if e = h.writeNew("fence.json", v); e != nil {
		return Status{}, e
	}
	return h.statusLocked()
}

// Cancel is only a pre-export abort. Future sealing/export phases must not use
// this operation. It cannot thaw while any admitted local process is alive.
func (h *Host) Cancel(operation string) (Status, error) {
	if !operationName.MatchString(operation) {
		return Status{}, ErrInvalid
	}
	if e := h.lock(); e != nil {
		return Status{}, e
	}
	defer h.unlock()
	seal, sealError := h.file("host-migration.json", false)
	if seal != nil {
		seal.Close()
	}
	if !errors.Is(sealError, syscall.ENOENT) {
		return Status{}, ErrInvalid
	}
	v, e := h.read("fence.json")
	if errors.Is(e, syscall.ENOENT) {
		old, e := h.read(operation + ".cancelled.json")
		if e != nil || old.ConfigSHA != h.configSHA || old.OperationID != operation {
			return Status{}, ErrInvalid
		}
		return h.statusLocked()
	}
	if e != nil || v.OperationID != operation || v.ConfigSHA != h.configSHA {
		return Status{}, ErrInvalid
	}
	drained, e := h.drained()
	if e != nil {
		return Status{}, e
	}
	if !drained {
		return Status{}, ErrBusy
	}
	old, e := h.read(operation + ".cancelled.json")
	if errors.Is(e, syscall.ENOENT) {
		if e = h.writeNew(operation+".cancelled.json", v); e != nil {
			return Status{}, e
		}
	} else if e != nil || old != v {
		return Status{}, ErrInvalid
	}
	if syscall.Unlinkat(int(h.dir.Fd()), "fence.json") != nil || h.dir.Sync() != nil {
		return Status{}, ErrUnavailable
	}
	return h.statusLocked()
}

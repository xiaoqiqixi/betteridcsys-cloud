//go:build linux

package controllerhost

import (
	"errors"
	"os"
	"syscall"
)

// PrepareVerificationRuntime runs the caller's complete approval under the
// original target's exclusive control lock, then reserves a verification-only
// process lifetime. It does NOT clear the target seal or admit ordinary workers.
//
// Use only in a dedicated, short-lived root coordinator process. A successful
// call deliberately retains a raw CLOEXEC parent descriptor until OS exit,
// including when a later exec/handshake/archive-cleanup step fails. The returned
// file is a SECOND open-file description; pass it explicitly to the verification
// child and close the parent's copy after exec. Neither child's LOCK_UN nor the
// parent's exit can release the other process's independent guard.
//
// This is host exclusion, not proof of archive/account/data/TLS/UID approval or
// SQL drain. The caller must supply those checks, finish plaintext cleanup before
// admitting HTTP, and independently wait for actual child exit and SQL drain.
func (h *Host) PrepareVerificationRuntime(operation, planSHA string, approve func() error) (*os.File, error) {
	if os.Geteuid() != 0 || !operationName.MatchString(operation) || !digestName.MatchString(planSHA) || approve == nil {
		return nil, ErrInvalid
	}
	if err := h.lock(); err != nil {
		return nil, err
	}
	defer h.unlock()
	sealed := func() (targetIntent, error) {
		v, err := h.readTarget()
		if err != nil || v.OperationID != operation || v.ConfigSHA != h.configSHA || v.PlanSHA != planSHA {
			return targetIntent{}, ErrInvalid
		}
		for _, name := range []string{"fence.json", "host-migration.json"} {
			file, err := h.file(name, false)
			if file != nil {
				file.Close()
			}
			if !errors.Is(err, syscall.ENOENT) {
				return targetIntent{}, ErrInvalid
			}
		}
		return v, nil
	}
	before, err := sealed()
	if err != nil {
		return nil, err
	}
	drained, err := h.drained()
	if err != nil {
		return nil, err
	}
	if !drained {
		return nil, ErrBusy
	}
	if err := approve(); err != nil {
		return nil, err
	}
	if after, err := sealed(); err != nil || after != before {
		return nil, ErrInvalid
	}
	parent, err := h.file("runtime.lock", true)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer parent.Close()
	child, err := h.file("runtime.lock", false) // open again, NEVER dup the parent OFD
	if err != nil {
		return nil, ErrUnavailable
	}
	retained := false
	defer func() {
		if !retained {
			child.Close()
		}
	}()
	var parentStat, childStat syscall.Stat_t
	if syscall.Fstat(int(parent.Fd()), &parentStat) != nil || syscall.Fstat(int(child.Fd()), &childStat) != nil ||
		parentStat.Dev != childStat.Dev || parentStat.Ino != childStat.Ino {
		return nil, ErrUnavailable
	}
	for _, file := range []*os.File{parent, child} {
		if syscall.Flock(int(file.Fd()), syscall.LOCK_SH|syscall.LOCK_NB) != nil {
			return nil, ErrBusy
		}
	}
	// A raw descriptor has no os.File finalizer and is not released by Host.Close
	// or HTTP cancellation. CLOEXEC prevents accidental inheritance by helpers.
	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, parent.Fd(), syscall.F_DUPFD_CLOEXEC, 0)
	if errno != 0 {
		return nil, ErrUnavailable
	}
	retained = true
	return child, nil
}

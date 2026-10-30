//go:build linux

package verificationprocess

import (
	"aster/cloud/internal/control"
	"aster/cloud/internal/identity"
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// prctl(PDEATHSIG) belongs to the creating task. Keep the exec/main thread for
// checking it before any private bootstrap is read; ordinary commands unchanged.
func init() {
	if len(os.Args) == 2 && os.Args[1] == ChildCommand {
		runtime.LockOSThread()
	}
}

type bootstrap struct {
	Schema int    `json:"schema"`
	Nonce  string `json:"nonce"`
	Config Config `json:"config"`
}

func fileStat(f *os.File) (unix.Stat_t, error) {
	var st unix.Stat_t
	if f == nil || unix.Fstat(int(f.Fd()), &st) != nil {
		return st, ErrRefused
	}
	return st, nil
}
func guardValid(f *os.File) bool {
	st, err := fileStat(f)
	return err == nil && st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&07777 == 0600 && st.Uid == 0 && st.Nlink == 1
}

func serve(ctx context.Context, guard *os.File, cfg Config) error {
	if os.Getuid() != 0 || os.Geteuid() != 0 || !guardValid(guard) {
		return ErrRefused
	}
	// Match the inherited guard to the ORIGINAL root-owned state. Opening this
	// file does not grant approval; the caller retains the independently held OFD.
	path := filepath.Join("/var/lib/aster-controller", cfg.Controller.ControllerID, "runtime.lock")
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrRefused
	}
	original := os.NewFile(uintptr(fd), "original-verification-guard")
	a, ea := fileStat(original)
	b, eb := fileStat(guard)
	original.Close()
	if ea != nil || eb != nil || a.Dev != b.Dev || a.Ino != b.Ino {
		return ErrRefused
	}
	executable, err := os.Executable()
	if err != nil {
		return ErrRefused
	}
	if _, err = control.ReadProtected(executable, false, 128<<20); err != nil {
		return ErrRefused
	}
	lifetime, cancel := context.WithDeadline(ctx, cfg.ExpiresAt)
	defer cancel()
	listener, err := net.Listen("tcp", cfg.Controller.Listen)
	if err != nil {
		return ErrRefused
	}
	defer listener.Close()
	tcp, ok := listener.(*net.TCPListener)
	if !ok || listener.Addr().String() != cfg.Controller.Listen {
		return ErrRefused
	}
	inherited, err := tcp.File()
	if err != nil {
		return ErrRefused
	}
	defer inherited.Close()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return ErrRefused
	}
	parentFile := os.NewFile(uintptr(pair[0]), "verification-parent-control")
	childFile := os.NewFile(uintptr(pair[1]), "verification-child-control")
	defer childFile.Close()
	connection, err := net.FileConn(parentFile)
	parentFile.Close()
	if err != nil {
		return ErrRefused
	}
	defer connection.Close()
	nonce := make([]byte, 32)
	if _, err = rand.Read(nonce); err != nil {
		return ErrRefused
	}
	message, err := json.Marshal(bootstrap{1, hex.EncodeToString(nonce), cfg})
	if err != nil || len(message) > 4<<20 {
		return ErrRefused
	}
	// A new locked goroutine owns the creating OS thread until actual Wait. Do
	// not unlock/reuse the irreversibly restricted thread for unrelated root work.
	finished := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != nil {
			finished <- ErrRefused
			return
		}
		child := exec.Command(executable, ChildCommand)
		child.Dir = "/"
		child.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
		child.ExtraFiles = []*os.File{guard, childFile, inherited}
		child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: cfg.UID, Gid: cfg.GID, Groups: []uint32{}}, Pdeathsig: syscall.SIGKILL, Cloneflags: unix.CLONE_NEWNET}
		// No child-controlled output, stack traces or private bootstrap can enter logs.
		child.Stdin = nil
		child.Stdout = nil
		child.Stderr = nil
		if child.Start() != nil {
			finished <- ErrRefused
			return
		}
		childFile.Close()
		inherited.Close()
		listener.Close()
		guard.Close()
		exited := make(chan error, 1)
		go func() { exited <- child.Wait() }()
		stop := func() {
			connection.Close()
			timer := time.NewTimer(5 * time.Second)
			defer timer.Stop()
			select {
			case <-exited:
				return
			case <-timer.C:
			}
			_ = child.Process.Kill()
			<-exited // never report drained while a real process still exists
		}
		handshake := time.Now().Add(10 * time.Second)
		if cfg.ExpiresAt.Before(handshake) {
			handshake = cfg.ExpiresAt
		}
		_ = connection.SetDeadline(handshake)
		if _, err := connection.Write(append(message, '\n')); err != nil {
			stop()
			finished <- ErrRefused
			return
		}
		ack, err := bufio.NewReader(io.LimitReader(connection, 128)).ReadString('\n')
		if err != nil || ack != "verified "+hex.EncodeToString(nonce)+"\n" {
			stop()
			finished <- ErrRefused
			return
		}
		_ = connection.SetDeadline(time.Time{})
		select {
		case <-lifetime.Done():
			stop()
			finished <- lifetime.Err()
		case err := <-exited:
			// Both processes enforce the same absolute cutoff. Either timer
			// may win; a normally exited child at/after that cutoff is not an
			// unexpected crash. Never accept an early exit as a clean stop.
			if err == nil && !time.Now().Before(cfg.ExpiresAt) {
				finished <- context.DeadlineExceeded
			} else {
				finished <- ErrRefused
			}
		}
	}()
	return <-finished
}

// Child has no flags, files, ports or DSNs supplied on the command line. It
// accepts only a root-parent anonymous channel and fixed inherited descriptors.
func Child() error {
	if len(os.Args) != 2 || os.Args[1] != ChildCommand || os.Getuid() < 100 || os.Getuid() >= 65534 || os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() {
		return ErrRefused
	}
	groups, err := os.Getgroups()
	var signal int32
	// This operation writes through arg2; it does not return the signal value.
	// Keep the pointer conversion at the actual syscall boundary.
	_, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, unix.PR_GET_PDEATHSIG, uintptr(unsafe.Pointer(&signal)), 0, 0, 0, 0)
	if err != nil || len(groups) != 0 || errno != 0 || signal != int32(syscall.SIGKILL) {
		return ErrRefused
	}
	peer, err := unix.GetsockoptUcred(4, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil || peer.Uid != 0 || peer.Pid <= 1 || int(peer.Pid) != os.Getppid() || !threadsRestricted() {
		return ErrRefused
	}
	guard := os.NewFile(3, "verification-guard")
	defer guard.Close()
	if !guardValid(guard) {
		return ErrRefused
	}
	controlFile := os.NewFile(4, "verification-control")
	connection, err := net.FileConn(controlFile)
	controlFile.Close()
	if err != nil {
		return ErrRefused
	}
	defer connection.Close()
	_ = connection.SetReadDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(io.LimitReader(connection, (4<<20)+1))
	raw, err := reader.ReadBytes('\n')
	if err != nil || len(raw) > 4<<20 || len(raw) < 2 || int(peer.Pid) != os.Getppid() {
		return ErrRefused
	}
	var boot bootstrap
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&boot) != nil || boot.Schema != 1 || len(boot.Nonce) != 64 || !boot.Config.valid() || uint32(os.Getuid()) != boot.Config.UID || uint32(os.Getgid()) != boot.Config.GID {
		return ErrRefused
	}
	canonical, err := json.Marshal(boot)
	if err != nil || !bytes.Equal(raw, append(canonical, '\n')) {
		return ErrRefused
	}
	if decoded, err := hex.DecodeString(boot.Nonce); err != nil || len(decoded) != 32 {
		return ErrRefused
	}
	_ = connection.SetReadDeadline(time.Time{})
	listenerFile := os.NewFile(5, "verification-listener")
	listener, err := net.FileListener(listenerFile)
	listenerFile.Close()
	if err != nil {
		return ErrRefused
	}
	defer listener.Close()
	if _, ok := listener.(*net.TCPListener); !ok || listener.Addr().String() != boot.Config.Controller.Listen {
		return ErrRefused
	}
	ctx, cancel := context.WithDeadline(context.Background(), boot.Config.ExpiresAt)
	defer cancel()
	// Any EOF, additional byte or error closes admission. The parent sends exactly
	// one bounded bootstrap; no channel message can extend the original approval.
	go func() { var b [1]byte; _, _ = reader.Read(b[:]); cancel() }()
	store, err := control.OpenDSN(boot.Config.DSN)
	if err != nil {
		return ErrRefused
	}
	defer store.DB.Close()
	if _, err = identity.CheckVerificationSQLIdentity(ctx, store.DB, boot.Config.Operation); err != nil {
		return ErrRefused
	}
	if ctx.Err() != nil || int(peer.Pid) != os.Getppid() || !threadsRestricted() {
		return ErrRefused
	}
	if _, err = io.WriteString(connection, "verified "+boot.Nonce+"\n"); err != nil {
		return ErrRefused
	}
	cfg := control.VerificationServiceConfig{Controller: boot.Config.Controller, Identity: identity.Config{Origin: boot.Config.Origin}, Operation: boot.Config.Operation, ExpiresAt: boot.Config.ExpiresAt, CertificatePEM: boot.Config.CertificatePEM, PrivateKeyPEM: boot.Config.PrivateKeyPEM}
	err = control.ServeVerificationConsole(ctx, listener, store, cfg)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil
	}
	return ErrRefused
}

func threadsRestricted() bool {
	entries, err := os.ReadDir("/proc/self/task")
	if err != nil || len(entries) == 0 {
		return false
	}
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			return false
		}
		raw, err := os.ReadFile(filepath.Join("/proc/self/task", entry.Name(), "status"))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return false
		}
		fields := map[string]string{}
		for _, line := range strings.Split(string(raw), "\n") {
			key, value, ok := strings.Cut(line, ":")
			if ok {
				fields[key] = strings.TrimSpace(value)
			}
		}
		if fields["NoNewPrivs"] != "1" || fields["Groups"] != "" {
			return false
		}
		for _, key := range []string{"CapInh", "CapPrm", "CapEff", "CapAmb"} {
			if fields[key] != "0000000000000000" {
				return false
			}
		}
		for key, want := range map[string]int{"Uid": os.Getuid(), "Gid": os.Getgid()} {
			values := strings.Fields(fields[key])
			if len(values) != 4 {
				return false
			}
			for _, value := range values {
				if value != strconv.Itoa(want) {
					return false
				}
			}
		}
	}
	return true
}

//go:build linux

package fabric

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// RunNamespace pins the root-approved namespace by an open descriptor. A later
// rename/replacement of /run/netns/NAME cannot redirect a command into the host.
func (OSRunner) RunNamespace(ctx context.Context, p NATProfile, binary string, args ...string) ([]byte, error) {
	if !natBinary(binary) {
		return nil, ErrInvalid
	}
	if _, err := canonicalNATProfile(p); err != nil {
		return nil, err
	}
	fd, err := syscall.Open("/run/netns/"+p.Namespace, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	var fs syscall.Statfs_t
	if syscall.Fstatfs(fd, &fs) != nil || fs.Type != 0x6e736673 {
		syscall.Close(fd)
		return nil, ErrUnavailable
	}
	f := os.NewFile(uintptr(fd), p.Namespace)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, ErrUnavailable
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok || s.Uid != 0 || st.Mode().Perm()&0022 != 0 || uint64(s.Dev) != p.NamespaceDevice || s.Ino != p.NamespaceInode {
		return nil, ErrUnavailable
	}
	for _, path := range []string{"/proc/self/ns/net", "/proc/1/ns/net"} {
		h, e := os.Stat(path)
		if e != nil {
			return nil, ErrUnavailable
		}
		v, ok := h.Sys().(*syscall.Stat_t)
		if !ok || v.Dev == s.Dev && v.Ino == s.Ino {
			return nil, ErrUnavailable
		}
	}
	argv := append([]string{"--net=/proc/self/fd/3", "--", binary}, args...)
	cmd := exec.CommandContext(ctx, "/usr/bin/nsenter", argv...)
	cmd.ExtraFiles = []*os.File{f}
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/nonexistent", "LANG=C", "LC_ALL=C"}
	cmd.WaitDelay = 2 * time.Second
	out := &limitedOutput{}
	cmd.Stdout = out
	cmd.Stderr = out
	if cmd.Run() != nil {
		return nil, ErrUnavailable
	}
	return out.Bytes(), nil
}

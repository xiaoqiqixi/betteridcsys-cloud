package controllerbackup

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Archive cannot be constructed by a caller. It is valid only inside the
// WithVerifiedArchive callback, after every entry and age's final tag passed.
// This capability authorizes reading staged bytes, NOT activating a target.
type Archive struct {
	manifest Manifest
	files    map[string]string
	valid    bool
}

// WithVerifiedArchive stages to generated private filenames. Unauthenticated
// plaintext can exist only inside this operation's 0700 directory; it is never
// supplied to the callback or written to a caller's destination paths. Cleanup
// failure is a failure, not a successful restore receipt.
func WithVerifiedArchive(input, key, controller, operation, parent string, action func(*Archive) error) (err error) {
	if action == nil || !filepath.IsAbs(parent) || filepath.Clean(parent) != parent || strings.ContainsAny(parent, "\x00\r\n") {
		return ErrInvalid
	}
	owner := uint32(os.Geteuid())
	for path := parent; ; path = filepath.Dir(path) {
		st, e := os.Lstat(path)
		if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return ErrInvalid
		}
		native, ok := st.Sys().(*syscall.Stat_t)
		if !ok || native.Uid != 0 && native.Uid != owner || st.Mode().Perm()&0022 != 0 && !(native.Uid == 0 && st.Mode()&os.ModeSticky != 0) {
			return ErrInvalid
		}
		if path == parent && (native.Uid != owner || st.Mode().Perm() != 0700) {
			return ErrInvalid
		}
		if path == "/" {
			break
		}
	}
	dir, e := os.MkdirTemp(parent, ".restore-verify-")
	if e != nil {
		return ErrInvalid
	}
	defer func() {
		if os.RemoveAll(dir) != nil {
			err = ErrInvalid
		}
	}()
	verified := &Archive{files: map[string]string{}}
	defer func() { verified.valid = false; verified.files = nil }()
	stage := func(entry Entry) (io.WriteCloser, error) {
		if len(verified.files) >= 256 {
			return nil, ErrInvalid
		}
		f, e := os.CreateTemp(dir, "record-")
		if e != nil {
			return nil, ErrInvalid
		}
		verified.files[entry.Name] = f.Name()
		return f, nil
	}
	_, e = inspectFiles(input, key, controller, operation, stage, func(m Manifest) { verified.manifest = m })
	if e != nil {
		return ErrInvalid
	}
	verified.valid = true
	return action(verified)
}

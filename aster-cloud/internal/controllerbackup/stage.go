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
	files    map[string]*os.File
	valid    bool
}

// plaintextFile unlinks the empty file before any plaintext is written. Even
// SIGKILL leaves no named plaintext behind; the kernel releases the storage
// when the last descriptor closes. A crash before unlink can leave only an
// empty file. Callers supply a validated private directory and retain the FD.
func plaintextFile(dir string) (*os.File, error) {
	f, err := os.CreateTemp(dir, "record-")
	if err != nil {
		return nil, ErrInvalid
	}
	if err = os.Remove(f.Name()); err != nil {
		f.Close()
		return nil, ErrInvalid
	}
	return f, nil
}

// inspect closes each entry writer; the owning Archive retains its descriptor
// until the authenticated callback returns, including on failure or panic.
type retainedWriter struct{ io.Writer }

func (retainedWriter) Close() error { return nil }

func (a *Archive) reader(name string) (*io.SectionReader, error) {
	if a == nil || !a.valid || a.files[name] == nil {
		return nil, ErrInvalid
	}
	f := a.files[name]
	info, err := f.Stat()
	if err != nil {
		return nil, ErrInvalid
	}
	// Independent offsets allow repeated or concurrent reads without reopening
	// a path, sharing a Seek offset, or exposing an inherited descriptor.
	return io.NewSectionReader(f, 0, info.Size()), nil
}

// WithVerifiedArchive stages only in unlinked files. Unauthenticated plaintext
// is never supplied to the callback or written to a caller's destination paths.
// Cleanup failure is a failure, not a successful restore receipt.
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
	verified := &Archive{files: map[string]*os.File{}}
	defer func() {
		verified.valid = false
		for _, f := range verified.files {
			if f.Close() != nil {
				err = ErrInvalid
			}
		}
		verified.files = nil
	}()
	stage := func(entry Entry) (io.WriteCloser, error) {
		if len(verified.files) >= 256 {
			return nil, ErrInvalid
		}
		f, e := plaintextFile(dir)
		if e != nil {
			return nil, ErrInvalid
		}
		verified.files[entry.Name] = f
		return retainedWriter{f}, nil
	}
	_, e = inspectFiles(input, key, controller, operation, stage, func(m Manifest) { verified.manifest = m })
	if e != nil {
		return ErrInvalid
	}
	verified.valid = true
	return action(verified)
}

//go:build linux

package controllerbackup

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
)

func publishNew(source, target string) error {
	if unix.Renameat2(unix.AT_FDCWD, source, unix.AT_FDCWD, target, unix.RENAME_NOREPLACE) != nil {
		return ErrInvalid
	}
	for _, path := range []string{filepath.Dir(source), filepath.Dir(target)} {
		d, e := os.Open(path)
		if e != nil {
			return ErrInvalid
		}
		e = d.Sync()
		d.Close()
		if e != nil {
			return ErrInvalid
		}
	}
	return nil
}

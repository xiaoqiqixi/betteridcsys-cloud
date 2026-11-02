//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

func TestVerificationSocketPair(t *testing.T) {
	for _, kind := range []int{unix.SOCK_STREAM, unix.SOCK_DGRAM, unix.SOCK_SEQPACKET} {
		pair, err := unix.Socketpair(unix.AF_UNIX, kind|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, fd := range pair {
			defer unix.Close(fd)
			if got := unnamedVerificationSocket(fd); got != (kind == unix.SOCK_STREAM) {
				t.Errorf("socket type %d: unnamed stream admission = %v", kind, got)
			}
		}
	}
	if unnamedVerificationSocket(-1) {
		t.Fatal("invalid descriptor admitted")
	}
}

func TestVerificationSocketNames(t *testing.T) {
	nonce := strconv.Itoa(os.Getpid())
	for _, name := range []string{filepath.Join(t.TempDir(), "s"), "@aster-verify-" + nonce, "@\x00aster-verify-" + nonce} {
		t.Run(strconv.Itoa(len(name)), func(t *testing.T) {
			listener, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(listener)
			address := &unix.SockaddrUnix{Name: name}
			if err := unix.Bind(listener, address); err != nil {
				t.Fatal(err)
			}
			if err := unix.Listen(listener, 1); err != nil {
				t.Fatal(err)
			}
			client, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(client)
			if err := unix.Connect(client, address); err != nil {
				t.Fatal(err)
			}
			server, _, err := unix.Accept4(listener, unix.SOCK_CLOEXEC)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(server)
			for _, fd := range []int{client, server} {
				if unnamedVerificationSocket(fd) {
					t.Fatal("named endpoint admitted as an anonymous channel")
				}
			}
		})
	}
}

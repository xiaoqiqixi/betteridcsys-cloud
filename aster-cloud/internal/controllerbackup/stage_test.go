package controllerbackup

import (
	"aster/cloud/migrations"
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
)

const crashOperation = "0123456789abcdef0123456789abcdef"
const crashPlaintext = "private migration plaintext sentinel"

// Exercise export's real encryptor with unlinked files and restore's real age
// authentication, without requiring SQL or granting target restore authority.
func scratchArchive(t *testing.T) (string, string, string) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	files := map[string]*os.File{}
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	manifest := Manifest{Schema: 1, Protocol: Protocol, ControllerID: "crash-test", OperationID: crashOperation,
		SourceCommit: strings.Repeat("a", 40), SchemaVersion: len(migrations.All()), SourcePlanSHA256: digestBytes([]byte(crashPlaintext))}
	for name := range requiredFiles() {
		f, err := plaintextFile(dir)
		if err != nil {
			t.Fatal(err)
		}
		files[name] = f
		if _, err = io.WriteString(f, crashPlaintext); err != nil {
			t.Fatal(err)
		}
		info, err := f.Stat()
		if err != nil || info.Sys().(*syscall.Stat_t).Nlink != 0 {
			t.Fatal("plaintext must be unlinked before writing", err)
		}
		manifest.Files = append(manifest.Files, Entry{name, int64(len(crashPlaintext)), digestBytes([]byte(crashPlaintext))})
	}
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Name < manifest.Files[j].Name })
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	key := KeyPrefix + strings.Repeat("71", 32)
	var encrypted bytes.Buffer
	if err = encryptContainer(&encrypted, key, raw, manifest.Files, files); err != nil {
		t.Fatal(err)
	}
	archive, keyPath := filepath.Join(dir, "backup.age"), filepath.Join(dir, "recovery.key")
	if os.WriteFile(archive, encrypted.Bytes(), 0600) != nil || os.WriteFile(keyPath, []byte(key+"\n"), 0600) != nil {
		t.Fatal("cannot write encrypted fixture")
	}
	return dir, archive, keyPath
}

func TestArchiveUnlinkedLifetimeAndAuthentication(t *testing.T) {
	dir, archive, key := scratchArchive(t)
	for _, callbackError := range []error{nil, errors.New("callback failed")} {
		var retained *Archive
		var handles []*os.File
		err := WithVerifiedArchive(archive, key, "crash-test", crashOperation, dir, func(a *Archive) error {
			retained = a
			for name, f := range a.files {
				handles = append(handles, f)
				info, err := f.Stat()
				if err != nil || info.Sys().(*syscall.Stat_t).Nlink != 0 {
					t.Fatal("restored plaintext has a directory entry", err)
				}
				for range 2 {
					raw, err := a.readSmall(name, 1024)
					if err != nil || string(raw) != crashPlaintext {
						t.Fatal("independent read offset lost", err)
					}
				}
			}
			return callbackError
		})
		if err != callbackError || retained == nil {
			t.Fatal("callback result lost", err)
		}
		if _, err := retained.readSmall("controller/config.json", 1024); err != ErrInvalid {
			t.Fatal("archive escaped callback")
		}
		for _, f := range handles {
			if _, err := f.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatal("plaintext descriptor leaked", err)
			}
		}
	}
	raw, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 1 // age's final authentication tag must still gate callbacks.
	if err = os.WriteFile(archive, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = WithVerifiedArchive(archive, key, "crash-test", crashOperation, dir, func(*Archive) error {
		t.Fatal("unauthenticated archive reached callback")
		return nil
	}); err != ErrInvalid {
		t.Fatal("corrupt archive accepted", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 2 {
		t.Fatal("failed restore left scratch files", err)
	}
}

func TestArchiveSIGKILLLeavesNoPlaintext(t *testing.T) {
	if dir := os.Getenv("ASTER_ARCHIVE_CRASH_CHILD"); dir != "" {
		// An export may be killed while still writing, before encryption starts.
		f, err := plaintextFile(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err = io.WriteString(f, crashPlaintext); err != nil {
			t.Fatal(err)
		}
		err = WithVerifiedArchive(filepath.Join(dir, "backup.age"), filepath.Join(dir, "recovery.key"),
			"crash-test", crashOperation, dir, func(a *Archive) error {
				if raw, err := a.readSmall("controller/config.json", 1024); err != nil || string(raw) != crashPlaintext {
					t.Fatal("plaintext was not staged", err)
				}
				fmt.Println("ready")
				// Parent kills us while both export and restore plaintext are open.
				time.Sleep(time.Minute)
				return errors.New("parent did not kill child")
			})
		t.Fatal(err)
	}
	dir, _, _ := scratchArchive(t)
	child := exec.Command(os.Args[0], "-test.run=^TestArchiveSIGKILLLeavesNoPlaintext$")
	child.Env = append(os.Environ(), "ASTER_ARCHIVE_CRASH_CHILD="+dir)
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	child.Stderr = &stderr
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	ready := make(chan bool, 1)
	go func() {
		line, err := bufio.NewReader(stdout).ReadString('\n')
		ready <- err == nil && line == "ready\n"
	}()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("child did not stage plaintext")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("child timed out")
	}
	if err = child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err = child.Wait(); err == nil {
		t.Fatal("child unexpectedly exited normally")
	}
	err = filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && entry.Name() != "backup.age" && entry.Name() != "recovery.key" {
			return fmt.Errorf("crash left named scratch file: %s", entry.Name())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

package hypervisor

import (
	"context"
	"encoding/binary"
	"encoding/xml"
	"os"
	"strings"
	"syscall"
	"testing"
)

func withBacking(raw []byte, path string) []byte {
	binary.BigEndian.PutUint64(raw[8:16], 256)
	binary.BigEndian.PutUint32(raw[16:20], uint32(len(path)))
	copy(raw[256:], path)
	return raw
}

func TestGuestDirectoriesRemainTraversableUnderNodeUmask(t *testing.T) {
	// Match aster-node's private umask. This test must remain non-parallel.
	previous := syscall.Umask(0077)
	defer syscall.Umask(previous)
	source, _, task, export, receipt := exportFixture(t)
	check := func(m *Manager) {
		t.Helper()
		i, _ := m.Ledger.Instance(task.InstanceID)
		for path, mode := range map[string]os.FileMode{i.Directory: 0755, i.Disk: 0600, i.Seed: 0644, m.Config.StateDirectory: 0700} {
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != mode {
				t.Fatalf("incorrect mode for %s: want %o, got %v (%v)", path, mode, info, err)
			}
		}
	}
	check(source)
	target, _, _ := newStorageFixture(t, "node-b")
	imp := handoffFixture(t, source, target, export, receipt)
	if err := target.approveInbox(context.Background(), imp.ArtifactID, imp.FenceToken); err != nil {
		t.Fatal(err)
	}
	assertStorageStatus(t, target, imp, "succeeded")
	check(target)
}
func TestDiskDACLabelsProtectOnlyReadOnlySources(t *testing.T) {
	m, _, task := newFixture(t)
	if r := submit(t, m, task); r.Status != "succeeded" {
		t.Fatal(r)
	}
	i, _ := m.Ledger.Instance(task.InstanceID)
	base := m.Config.Images[i.Resources.ImageID].Path
	for _, backed := range []bool{true, false} {
		raw := fakeQcowBytes()
		if backed {
			raw = withBacking(raw, base)
		}
		if err := os.WriteFile(i.Disk, raw, 0600); err != nil {
			t.Fatal(err)
		}
		body, err := m.domainXML(i)
		if err != nil {
			t.Fatal(err)
		}
		var d domainXML
		if err = xml.Unmarshal(body, &d); err != nil {
			t.Fatal(err)
		}
		disk, seed := d.Devices.Disks[0], d.Devices.Disks[1]
		if disk.Source.SecurityLabel != nil {
			t.Fatal("writable overlay lost QEMU relabeling")
		}
		if seed.Source.SecurityLabel == nil || *seed.Source.SecurityLabel != (diskSecurityLabelXML{Model: "dac", Relabel: "no"}) || seed.ReadOnly == nil {
			t.Fatal("seed ownership not protected", string(body))
		}
		if disk.BackingStore == nil {
			t.Fatal("missing explicit chain")
		}
		if backed {
			b := disk.BackingStore
			if b.Type != "file" || b.Format == nil || b.Format.Type != "qcow2" || b.Source == nil || b.Source.File != base || b.Source.SecurityLabel == nil || *b.Source.SecurityLabel != (diskSecurityLabelXML{Model: "dac", Relabel: "no"}) || b.BackingStore == nil || b.BackingStore.Source != nil {
				t.Fatal("approved base not protected", string(body))
			}
		} else if disk.BackingStore.Source != nil || strings.Contains(string(body), base) {
			t.Fatal("flat restore attached base", string(body))
		}
	}
	info, err := os.Stat(i.Seed)
	if err != nil || info.Mode().Perm() != 0644 {
		t.Fatal("QEMU cannot read root-owned seed", err)
	}
	if err = ownedPath(i.Seed, false, false); err != nil {
		t.Fatal("seed trust changed", err)
	}
	if err = os.WriteFile(i.Disk, withBacking(fakeQcowBytes(), "/unapproved/base.qcow2"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = m.domainXML(i); err == nil {
		t.Fatal("unapproved backing source accepted")
	}
}

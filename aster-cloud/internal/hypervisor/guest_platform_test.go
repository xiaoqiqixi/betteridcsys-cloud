package hypervisor

import (
	"aster/billing/serviceapi"
	"context"
	"encoding/xml"
	"testing"
)

func TestGuestPlatformSupportsPowerManagementAndSerialBootConsole(t *testing.T) {
	for _, emulation := range []bool{false, true} {
		t.Run(map[bool]string{false: "kvm", true: "tcg"}[emulation], func(t *testing.T) {
			m, _, task := newFixture(t)
			m.Config.AllowSoftwareEmulation = emulation
			if out := submit(t, m, task); out.Status != "succeeded" {
				t.Fatal(out)
			}
			i, _ := m.Ledger.Instance(task.InstanceID)
			raw, err := m.virsh(context.Background(), "dumpxml", i.Domain)
			var actual struct {
				ACPI   *struct{} `xml:"features>acpi"`
				APIC   *struct{} `xml:"features>apic"`
				Serial *struct {
					Type string `xml:"type,attr"`
				} `xml:"devices>serial"`
			}
			if err != nil || xml.Unmarshal(raw, &actual) != nil || actual.ACPI == nil || actual.APIC == nil || actual.Serial == nil || actual.Serial.Type != "pty" {
				t.Fatalf("guest lacks ACPI shutdown, interrupt routing, or a cloud-image serial console: %s (%v)", raw, err)
			}
		})
	}
}

func TestNoCloudSeedUsesReadOnlyVirtioWithoutCollidingWithRescueDisk(t *testing.T) {
	for _, rescue := range []bool{false, true} {
		t.Run(map[bool]string{false: "normal", true: "rescue"}[rescue], func(t *testing.T) {
			m, f, task := guestFixture(t)
			if rescue {
				if out := submit(t, m, guestTask(m, task, "4", "rescue_enter", serviceapi.Params{ImageID: "ubuntu22"})); out.Status != "succeeded" {
					t.Fatal(out)
				}
			}
			i, _ := m.Ledger.Instance(task.InstanceID)
			var d domainXML
			if err := xml.Unmarshal(f.domains[i.Domain], &d); err != nil {
				t.Fatal(err)
			}
			seen := map[string]bool{}
			found := false
			for _, disk := range d.Devices.Disks {
				if seen[disk.Target.Dev] {
					t.Fatal("seed collides with guest disk", disk.Target.Dev)
				}
				seen[disk.Target.Dev] = true
				if disk.Source.File == i.Seed {
					found = true
					if disk.Device != "disk" || disk.Target.Bus != "virtio" || disk.ReadOnly == nil || disk.Driver == nil || disk.Driver.Name != "qemu" || disk.Driver.Type != "raw" {
						t.Fatal("NoCloud seed does not use the boot-time virtio block driver", disk)
					}
				}
			}
			if !found || m.assertOwned(context.Background(), i) != nil {
				t.Fatal("seed missing or rejected by ownership validation")
			}
		})
	}
}

func TestNoCloudSeedOwnershipAcceptsLegacyMediaAndRejectsWritableOrAliasedDisks(t *testing.T) {
	for _, mode := range []string{"legacy", "writable", "system-target", "wrong-format", "wrong-bus"} {
		t.Run(mode, func(t *testing.T) {
			m, f, task := guestFixture(t)
			i, _ := m.Ledger.Instance(task.InstanceID)
			var d domainXML
			if err := xml.Unmarshal(f.domains[i.Domain], &d); err != nil {
				t.Fatal(err)
			}
			for n := range d.Devices.Disks {
				seed := &d.Devices.Disks[n]
				if seed.Source.File != i.Seed {
					continue
				}
				switch mode {
				case "legacy":
					seed.Device, seed.Target.Dev, seed.Target.Bus = "cdrom", "sda", "sata"
				case "writable":
					seed.ReadOnly = nil
				case "system-target":
					seed.Target.Dev = "vda"
				case "wrong-format":
					seed.Driver.Type = "qcow2"
				case "wrong-bus":
					seed.Target.Bus = "sata"
				}
			}
			f.domains[i.Domain], _ = xml.Marshal(d)
			if err := m.assertOwned(context.Background(), i); (err == nil) != (mode == "legacy") {
				t.Fatal("unexpected seed ownership result", err)
			}
		})
	}
}

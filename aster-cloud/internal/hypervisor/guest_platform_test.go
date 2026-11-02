package hypervisor

import (
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

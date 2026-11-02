package hypervisor

import (
	"context"
	"encoding/xml"
	"testing"
)

func TestSoftwareEmulationSelectsDomainAndRetainsOwnership(t *testing.T) {
	m, _, task := newFixture(t)
	m.Config.AllowSoftwareEmulation = true
	if result := submit(t, m, task); result.Status != "succeeded" {
		t.Fatalf("create: %s / %s", result.Status, result.Code)
	}
	i, ok := m.Ledger.Instance(task.InstanceID)
	if !ok {
		t.Fatal("missing durable instance")
	}
	raw, err := m.virsh(context.Background(), "dumpxml", i.Domain)
	var domain domainXML
	if err != nil || xml.Unmarshal(raw, &domain) != nil || domain.Type != "qemu" {
		t.Fatal("approved emulation did not reach libvirt domain definition")
	}
	if err := m.assertOwned(context.Background(), i); err != nil {
		t.Fatal(err)
	}
	m.Config.AllowSoftwareEmulation = false
	if err := m.assertOwned(context.Background(), i); err == nil {
		t.Fatal("KVM configuration accepted a QEMU domain")
	}
}

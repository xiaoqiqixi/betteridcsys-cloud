package control

import (
	"testing"
	"time"
)

func TestSoftwareEmulationRequiresNodeProfileApproval(t *testing.T) {
	node := testProfile()
	caps := testCapabilities(node, time.Now())
	resources := testResources(node)
	caps.Hypervisor = "libvirt-qemu"
	if caps.Supports(resources, node) {
		t.Fatal("software emulation accepted without root profile approval")
	}
	node.AllowSoftwareEmulation = true
	if !caps.Supports(resources, node) {
		t.Fatal("approved QEMU node cannot provision its approved resources")
	}
	caps.Hypervisor = "unknown"
	if caps.Supports(resources, node) {
		t.Fatal("emulation approval accepted an unknown hypervisor")
	}
	caps.Hypervisor = "libvirt-kvm"
	if !caps.Supports(resources, node) {
		t.Fatal("emulation approval disabled hardware acceleration")
	}
}

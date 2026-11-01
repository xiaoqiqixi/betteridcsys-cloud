package hypervisor

import (
	"aster/billing/serviceapi"
	"context"
	"encoding/xml"
	"os"
	"path/filepath"
	"testing"
)

func TestBandwidthDecimalMbpsToLibvirtKiB(t *testing.T) {
	for _, test := range []struct {
		mbps int
		want uint64
	}{{0, 0}, {1, 122}, {8, 976}, {100, 12207}, {1024, 125000}, {100000, 12207031}} {
		if got := bandwidthKiB(test.mbps); got != test.want {
			t.Fatal(test, got)
		}
	}
}

func TestCreateEnforcesDirectionalBandwidthAndPersistsVersion(t *testing.T) {
	m, f, task := newFixture(t)
	m.Config.AllowBandwidthLimits = true
	task.Resources.InboundBandwidthMbps = 100
	task.Resources.BandwidthMbps = 8
	if result := submit(t, m, task); result.Status != "succeeded" {
		t.Fatal(result)
	}
	i, _ := m.Ledger.Instance(task.InstanceID)
	var domain domainXML
	if err := xml.Unmarshal(f.domains[i.Domain], &domain); err != nil {
		t.Fatal(err)
	}
	nic := domain.Devices.Interfaces[0]
	if nic.Bandwidth == nil || nic.Bandwidth.Inbound.Average != 12207 || nic.Bandwidth.Outbound.Average != 976 {
		t.Fatal("direction or conversion", nic.Bandwidth)
	}
	raw, err := os.ReadFile(filepath.Join(m.Config.StateDirectory, "journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	if m.Ledger.state.Schema != bandwidthJournalSchema {
		t.Fatal("old binary could load shaped instance", string(raw))
	}
	nic.Bandwidth.Inbound.Average++
	domain.Devices.Interfaces[0] = nic
	f.domains[i.Domain], _ = xml.Marshal(domain)
	if err = m.assertOwned(context.Background(), i); err != ErrOwnership {
		t.Fatal("bandwidth drift accepted", err)
	}
	m.Shutdown()
	m.Ledger.Close()
	l, err := OpenLedger(m.Config.StateDirectory, m.Config.NodeID)
	if err != nil {
		t.Fatal("bandwidth journal did not reopen", err)
	}
	l.Close()
}

func TestResizeReappliesAndUpdatesBandwidth(t *testing.T) {
	m, f, task := guestFixture(t)
	m.Config.AllowBandwidthLimits = true
	if r := submit(t, m, next(task, "8", "shutdown")); r.Status != "succeeded" {
		t.Fatal(r)
	}
	p := serviceapi.Params{CPUCores: task.Resources.CPUCores, MemoryMB: task.Resources.MemoryMiB, DiskGB: task.Resources.SystemDiskGiB, SetBandwidth: true, InboundBandwidthMbps: 100, BandwidthMbps: 8}
	if r := submit(t, m, guestTask(m, task, "9", "resize", p)); r.Status != "succeeded" {
		t.Fatal(r)
	}
	i, _ := m.Ledger.Instance(task.InstanceID)
	var xmlDomain domainXML
	if e := xml.Unmarshal(f.domains[i.Domain], &xmlDomain); e != nil {
		t.Fatal(e)
	}
	if !bandwidthMatches(xmlDomain.Devices.Interfaces[0].Bandwidth, bandwidthFor(i.Resources)) || i.Resources.BandwidthMbps != 8 || i.Resources.InboundBandwidthMbps != 100 {
		t.Fatal("resize lost requested rates", i.Resources)
	}
	p.SetBandwidth = false
	p.BandwidthMbps = 0
	p.InboundBandwidthMbps = 0
	if r := submit(t, m, guestTask(m, task, "a", "resize", p)); r.Status != "succeeded" {
		t.Fatal(r)
	}
	if e := m.assertOwned(context.Background(), i); e != nil {
		t.Fatal("size-only resize lost bandwidth", e)
	}
}

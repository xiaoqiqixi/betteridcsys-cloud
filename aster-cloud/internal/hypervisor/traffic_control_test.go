package hypervisor

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"encoding/xml"
	"errors"
	"strings"
	"testing"
)

type trafficRunner struct {
	*fakeRunner
	manager    *Manager
	calls      int
	loseACK    bool
	intentSeen bool
}

func (r *trafficRunner) Run(ctx context.Context, binary string, args ...string) ([]byte, error) {
	if binary == Virsh && len(args) > 2 {
		switch args[2] {
		case "domid":
			return []byte("7\n"), nil
		case "domifstat":
			return []byte(args[4] + " rx_bytes 100\n" + args[4] + " tx_bytes 200\n"), nil
		case "domiftune":
			r.calls++
			i, _ := r.manager.Ledger.Instance(strings.TrimPrefix(args[3], "aster-"))
			r.intentSeen = i.State == "uncertain"
			var domain domainXML
			if e := xml.Unmarshal(r.domains[args[3]], &domain); e != nil {
				return nil, e
			}
			domain.Devices.Interfaces[0].Bandwidth = bandwidthFor(effectiveBandwidth(i))
			raw, _ := xml.Marshal(domain)
			r.domains[args[3]] = raw
			if r.loseACK {
				return nil, errors.New("lost acknowledgement")
			}
			return nil, nil
		}
	}
	return r.fakeRunner.Run(ctx, binary, args...)
}
func trafficFixture(t *testing.T) (*Manager, *trafficRunner, nodeproto.NodeTask) {
	m, f, task := newFixture(t)
	m.Config.AllowBandwidthLimits = true
	task.Resources.InboundBandwidthMbps = 100
	task.Resources.BandwidthMbps = 20
	if v := submit(t, m, task); v.Status != "succeeded" {
		t.Fatal(v)
	}
	r := &trafficRunner{fakeRunner: f, manager: m}
	m.Runner = r
	m.Config.AllowTrafficAccounting = true
	m.readTrafficBootID = func() ([]byte, error) { return []byte("11111111-1111-1111-1111-111111111111"), nil }
	return m, r, task
}
func TestTrafficThrottleIntentBeforeActionAndUncertainNeverRetries(t *testing.T) {
	m, r, task := trafficFixture(t)
	throttle := next(task, "4", nodeproto.TrafficControlAction)
	throttle.TrafficControl = nodeproto.TrafficControl{ThrottleMbps: 8}
	if v := submit(t, m, throttle); v.Status != "succeeded" || r.calls != 1 || !r.intentSeen {
		t.Fatal(v, r.calls, r.intentSeen)
	}
	i, _ := m.Ledger.Instance(task.InstanceID)
	if effectiveBandwidth(i).BandwidthMbps != 8 || i.Resources.BandwidthMbps != 20 {
		t.Fatal("product rates changed", i)
	}
	clear := next(task, "5", nodeproto.TrafficControlAction)
	r.loseACK = true
	if v := submit(t, m, clear); v.Status != "uncertain" {
		t.Fatal(v)
	}
	calls := r.calls
	if v := submit(t, m, clear); v.Status != "uncertain" || r.calls != calls {
		t.Fatal("uncertain policy retried", v, r.calls)
	}
	if v := submit(t, m, next(task, "6", "start")); v.Status != "rejected" {
		t.Fatal("quarantine bypass", v)
	}
}
func TestTrafficSuspensionClearsWithoutClearingBillingOrStarting(t *testing.T) {
	m, r, task := trafficFixture(t)
	i, _ := m.Ledger.Instance(task.InstanceID)
	i.Suspended = true
	if _, e := m.Ledger.Finish(task.OperationID, "succeeded", "", &i); e != nil {
		t.Fatal(e)
	}
	suspend := next(task, "4", nodeproto.TrafficControlAction)
	suspend.TrafficControl.Suspended = true
	if v := submit(t, m, suspend); v.Status != "succeeded" {
		t.Fatal(v)
	}
	i, _ = m.Ledger.Instance(task.InstanceID)
	if !i.TrafficControl.Suspended || !i.Suspended || i.State != "shut off" {
		t.Fatal(i)
	}
	starts := r.count(" start ")
	if v := submit(t, m, next(task, "5", nodeproto.TrafficControlAction)); v.Status != "succeeded" {
		t.Fatal(v)
	}
	i, _ = m.Ledger.Instance(task.InstanceID)
	if i.TrafficControl.Suspended || !i.Suspended || i.State != "shut off" || r.count(" start ") != starts {
		t.Fatal("clearing traffic released billing hold", i)
	}
}

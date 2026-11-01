package hypervisor

import (
	"aster/billing/controllerapi"
	"aster/cloud/internal/nodeproto"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const trafficJournalSchema = 9

type trafficRecord struct {
	StreamID   string                          `json:"stream_id"`
	Runtime    string                          `json:"runtime"`
	ObservedAt string                          `json:"observed_at"`
	RX         uint64                          `json:"rx"`
	TX         uint64                          `json:"tx"`
	Revision   uint64                          `json:"revision"`
	Days       map[string]nodeproto.TrafficDay `json:"days"`
}

// Treat only a near-uint64-boundary decrease as wrap. Ordinary decreases and
// domain/host restarts are reset counters whose current value is the new delta.
func trafficDelta(previous, current uint64, restarted bool) uint64 {
	if restarted {
		return current
	}
	if current >= previous {
		return current - previous
	}
	if previous > math.MaxUint64-(1<<40) && current < (1<<40) {
		return current - previous
	}
	return current
}
func parseDomifstat(raw []byte, mac string) (uint64, uint64, error) {
	if len(raw) == 0 || len(raw) > 65536 {
		return 0, 0, ErrOwnership
	}
	values := map[string]uint64{}
	for _, line := range strings.Split(string(raw), "\n") {
		p := strings.Fields(line)
		if len(p) == 0 {
			continue
		}
		if len(p) != 3 || p[0] != mac {
			return 0, 0, ErrOwnership
		}
		if _, ok := values[p[1]]; ok {
			return 0, 0, ErrOwnership
		}
		if p[2] == "-1" && p[1] != "rx_bytes" && p[1] != "tx_bytes" {
			continue
		}
		v, e := strconv.ParseUint(p[2], 10, 64)
		if e != nil {
			return 0, 0, ErrOwnership
		}
		values[p[1]] = v
	}
	rx, a := values["rx_bytes"]
	tx, b := values["tx_bytes"]
	if !a || !b {
		return 0, 0, ErrOwnership
	}
	return rx, tx, nil
}
func (l *Ledger) recordTraffic(i Instance, runtime string, rx, tx uint64, now time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.poisoned {
		return ErrConflict
	}
	current, ok := l.state.Instances[i.ID]
	if !ok || current.OwnerRef != i.OwnerRef {
		return ErrOwnership
	}
	v, exists := l.state.Traffic[i.ID]
	if exists {
		before, e := time.Parse(time.RFC3339Nano, v.ObservedAt)
		if e != nil {
			return ErrOwnership
		}
		if !now.After(before) {
			return nil
		}
	}
	if !exists {
		var b [16]byte
		if _, e := rand.Read(b[:]); e != nil {
			return e
		}
		v = trafficRecord{StreamID: hex.EncodeToString(b[:]), Days: map[string]nodeproto.TrafficDay{}}
	}
	var dr, dt uint64
	if exists {
		dr = trafficDelta(v.RX, rx, runtime != v.Runtime)
		dt = trafficDelta(v.TX, tx, runtime != v.Runtime)
	}
	// Attribute the interval to its observed UTC day. Keep 62 days so a monthly
	// billing period can be replayed after an extended controller outage.
	day := now.UTC().Format("2006-01-02")
	d := v.Days[day]
	oldRX, _ := strconv.ParseUint(d.RXBytes, 10, 64)
	oldTX, _ := strconv.ParseUint(d.TXBytes, 10, 64)
	if math.MaxUint64-oldRX < dr || math.MaxUint64-oldTX < dt || v.Revision == math.MaxUint64 {
		return errors.New("traffic journal overflow")
	}
	v.Revision++
	d = nodeproto.TrafficDay{Day: day, Revision: v.Revision, RXBytes: strconv.FormatUint(oldRX+dr, 10), TXBytes: strconv.FormatUint(oldTX+dt, 10)}
	v.Days[day] = d
	cutoff := now.UTC().Add(-62 * 24 * time.Hour).Format("2006-01-02")
	for day := range v.Days {
		if day < cutoff {
			delete(v.Days, day)
		}
	}
	v.Runtime = runtime
	v.RX = rx
	v.TX = tx
	v.ObservedAt = now.UTC().Format(time.RFC3339Nano)
	if l.state.Traffic == nil {
		l.state.Traffic = map[string]trafficRecord{}
	}
	l.state.Traffic[i.ID] = v
	if l.state.Schema < trafficJournalSchema {
		l.state.Schema = trafficJournalSchema
	}
	return l.save()
}
func (l *Ledger) Traffic(id string) (nodeproto.InstanceTraffic, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.poisoned {
		return nodeproto.InstanceTraffic{}, ErrConflict
	}
	i, ok := l.state.Instances[id]
	v, has := l.state.Traffic[id]
	if !ok || !has {
		return nodeproto.InstanceTraffic{}, ErrNotFound
	}
	out := trafficView(l.state.NodeID, i, v)
	if !out.Valid() {
		return out, ErrOwnership
	}
	return out, nil
}
func trafficView(node string, i Instance, v trafficRecord) nodeproto.InstanceTraffic {
	out := nodeproto.InstanceTraffic{Protocol: nodeproto.TrafficProtocol, NodeID: node, InstanceID: i.ID, OwnerRef: i.OwnerRef, StreamID: v.StreamID, ObservedAt: v.ObservedAt, Days: []nodeproto.TrafficDay{}}
	for _, day := range v.Days {
		out.Days = append(out.Days, day)
	}
	sort.Slice(out.Days, func(a, b int) bool { return out.Days[a].Day < out.Days[b].Day })
	return out
}
func (m *Manager) sampleTrafficInstance(ctx context.Context, i Instance) error {
	if i.MAC == "" {
		return nil
	}
	if e := m.assertOwned(ctx, i); e != nil {
		return e
	}
	state, e := m.state(ctx, i.Domain)
	if e != nil {
		return e
	}
	if state == "shut off" {
		return nil
	}
	readBoot := m.readTrafficBootID
	if readBoot == nil {
		readBoot = func() ([]byte, error) { return os.ReadFile("/proc/sys/kernel/random/boot_id") }
	}
	boot, e := readBoot()
	if e != nil {
		return e
	}
	if len(strings.TrimSpace(string(boot))) != 36 {
		return ErrOwnership
	}
	before, e := m.virsh(ctx, "domid", i.Domain)
	if e != nil {
		return e
	}
	number, e := strconv.ParseUint(strings.TrimSpace(string(before)), 10, 32)
	if e != nil || number == 0 {
		return ErrOwnership
	}
	raw, e := m.virsh(ctx, "domifstat", i.Domain, i.MAC)
	if e != nil {
		return e
	}
	rx, tx, e := parseDomifstat(raw, i.MAC)
	if e != nil {
		return e
	}
	after, e := m.virsh(ctx, "domid", i.Domain)
	if e != nil || string(before) != string(after) {
		return ErrOwnership
	}
	return m.Ledger.recordTraffic(i, strings.TrimSpace(string(boot))+":"+strconv.FormatUint(number, 10), rx, tx, time.Now().UTC())
}
func (m *Manager) SampleTraffic(ctx context.Context, id string) error {
	m.admission.Lock()
	defer m.admission.Unlock()
	if !m.Config.AllowTrafficAccounting {
		return ErrUnsupported
	}
	if m.active || m.stopping || m.Ledger.HasPendingInstance(id, "") {
		return ErrConflict
	}
	i, ok := m.Ledger.Instance(id)
	if !ok || i.State == "deleted" || i.PublicRetired {
		return ErrNotFound
	}
	if i.State == "uncertain" || i.State == "reserved" {
		return ErrConflict
	}
	return m.sampleTrafficInstance(ctx, i)
}
func (m *Manager) RunTraffic(ctx context.Context) {
	if !m.Config.AllowTrafficAccounting {
		return
	}
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		for _, i := range m.Ledger.Instances() {
			if ctx.Err() != nil {
				return
			}
			sample, cancel := context.WithTimeout(ctx, 10*time.Second)
			_ = m.SampleTraffic(sample, i.ID)
			cancel()
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (c Config) allowsTraffic(r controllerapi.Resources) bool {
	if r.TransferGiB == 0 && r.TrafficDirection == "all" {
		return true
	}
	return c.AllowTrafficAccounting && r.IPv4Count == 1 && r.TransferGiB >= 0 && r.TransferGiB <= 1073741824 && (r.TrafficDirection == "in" || r.TrafficDirection == "out" || r.TrafficDirection == "all")
}

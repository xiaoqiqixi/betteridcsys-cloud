package hypervisor

import (
	"aster/cloud/internal/fabric"
	"aster/cloud/internal/nodeproto"
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var errMetrics = errors.New("live instance metrics unconfirmed")
var metricKey = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
var metricInterface = regexp.MustCompile(`^vnet[0-9]{1,10}$`)

// ObserveMetrics serializes with mutation and inbox workers and samples only an
// explicitly owned domain. Reads never finish/retry operations or save journals.
func (m *Manager) ObserveMetrics(ctx context.Context, id string) (nodeproto.InstanceMetrics, error) {
	if !nodeproto.ValidID(id) {
		return nodeproto.InstanceMetrics{}, ErrNotFound
	}
	m.admission.Lock()
	defer m.admission.Unlock()
	if m.active || m.stopping {
		return nodeproto.InstanceMetrics{}, ErrConflict
	}
	i, ok := m.Ledger.Instance(id)
	if !ok || i.State == "deleted" || i.PublicRetired {
		return nodeproto.InstanceMetrics{}, ErrNotFound
	}
	if i.State == "uncertain" || i.State == "reserved" || m.Ledger.HasPendingInstance(id, "") {
		return nodeproto.InstanceMetrics{}, ErrConflict
	}
	if err := m.assertOwned(ctx, i); err != nil {
		return nodeproto.InstanceMetrics{}, err
	}
	state, err := m.state(ctx, i.Domain)
	if err != nil {
		return nodeproto.InstanceMetrics{}, err
	}
	state = strings.ReplaceAll(state, " ", "_")
	if state == "shut_off" {
		state = "shutoff"
	}
	raw, err := m.virsh(ctx, "domstats", i.Domain, "--raw", "--cpu-total", "--balloon", "--block", "--interface")
	if err != nil {
		return nodeproto.InstanceMetrics{}, err
	}
	now := time.Now().UTC()
	metrics, err := parseInstanceMetrics(raw, i, now)
	if err != nil {
		return nodeproto.InstanceMetrics{}, err
	}
	metrics.Protocol = nodeproto.MetricsProtocol
	metrics.NodeID = m.Config.NodeID
	metrics.InstanceID = i.ID
	metrics.OwnerRef = i.OwnerRef
	metrics.Hostname = i.Hostname
	metrics.State = state
	metrics.ObservedAt = now.Format(time.RFC3339Nano)
	metrics.VCPUs = i.Resources.CPUCores
	if !metrics.Validate() {
		return nodeproto.InstanceMetrics{}, errMetrics
	}
	return metrics, nil
}

type metricValue struct {
	value string
	text  bool
}

func metricUint(s string) (uint64, bool) {
	if len(s) == 0 || len(s) > 20 || len(s) > 1 && s[0] == '0' {
		return 0, false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	v, err := strconv.ParseUint(s, 10, 64)
	return v, err == nil
}

// parseInstanceMetrics consumes only bounded raw domstats output. Unknown
// numeric fields in the four requested libvirt groups are validated but not
// exposed, allowing libvirt to add counters without leaking paths or names.
// See https://www.libvirt.org/manpages/virsh.html#domstats for units and missing
// fields. Libvirt interface statistics are from the domain's point of view:
// RX is guest receive, TX guest transmit (we only own managed bridge NICs).
// https://www.libvirt.org/html/libvirt-libvirt-domain.html#virConnectGetAllDomainStats
// Ubuntu 22 / libvirt 8 prints typed strings without outer quotes: the record
// printer writes the string returned unchanged by vshGetTypedParamValue.
// https://github.com/libvirt/libvirt/blob/v8.0.0/tools/virsh-domain-monitor.c
// https://github.com/libvirt/libvirt/blob/v8.0.0/tools/vsh.c
func parseInstanceMetrics(raw []byte, i Instance, now time.Time) (nodeproto.InstanceMetrics, error) {
	var result nodeproto.InstanceMetrics
	if len(raw) == 0 || len(raw) > 65536 || strings.ContainsAny(string(raw), "\x00\r") {
		return result, errMetrics
	}
	fields := map[string]metricValue{}
	header := false
	for _, line := range strings.Split(string(raw), "\n") {
		if len(line) > 4096 {
			return result, errMetrics
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		// Strip indentation only. Trailing whitespace is part of a typed value,
		// not a licence to turn malformed numeric output into a valid counter.
		line = strings.TrimLeft(line, " \t")
		if !header {
			if line != "Domain: '"+i.Domain+"'" {
				return result, errMetrics
			}
			header = true
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || !metricKey.MatchString(key) || len(value) == 0 || len(fields) >= 256 {
			return result, errMetrics
		}
		if _, duplicate := fields[key]; duplicate {
			return result, errMetrics
		}
		if !strings.HasPrefix(key, "cpu.") && !strings.HasPrefix(key, "balloon.") && !strings.HasPrefix(key, "block.") && !strings.HasPrefix(key, "net.") {
			return result, errMetrics
		}
		stringField := strings.HasSuffix(key, ".name") || strings.HasSuffix(key, ".path") || strings.HasPrefix(key, "cpu.cache.monitor.") && strings.HasSuffix(key, ".vcpus")
		v := metricValue{value: value, text: stringField}
		if stringField {
			for _, c := range v.value {
				if c < 32 || c == 127 || c == '\'' || c == '\\' {
					return result, errMetrics
				}
			}
		} else if _, ok := metricUint(value); !ok {
			return result, errMetrics
		}
		fields[key] = v
	}
	if !header {
		return result, errMetrics
	}
	var err error
	read := func(key string) *string {
		v, present := fields[key]
		if !present {
			return nil
		}
		if v.text {
			err = errMetrics
			return nil
		}
		value := v.value
		return &value
	}
	result.CPUTimeNS = read("cpu.time")
	result.MemoryRSSKiB = read("balloon.rss")
	result.MemoryActualKiB = read("balloon.current")
	// libvirt may retain guest balloon reports indefinitely. A new HTTP sample
	// time does not make that cached guest memory statistic fresh. Never enable
	// polling on this GET: absent/zero/stale/future guest timestamps mean null.
	if last := read("balloon.last-update"); last != nil {
		seconds, _ := metricUint(*last)
		if now.Unix() >= 0 && seconds > 0 && seconds <= uint64(now.Add(5*time.Second).Unix()) {
			at := time.Unix(int64(seconds), 0)
			if !at.Before(now.Add(-60*time.Second)) && !at.After(now.Add(5*time.Second)) {
				result.MemoryUnusedKiB = read("balloon.unused")
			}
		}
	}
	if err != nil {
		return result, err
	}
	// Only vda is a customer system disk. The seed CD-ROM may be reported but
	// must never inflate disk I/O. No backing-chain flag is requested.
	if err = validateMetricDevices(fields, "block", 2); err != nil {
		return result, err
	}
	seen := map[string]bool{}
	if v, present := fields["block.count"]; present {
		count, _ := metricUint(v.value)
		for index := uint64(0); index < count; index++ {
			prefix := fmt.Sprintf("block.%d.", index)
			name, ok := fields[prefix+"name"]
			if !ok || !name.text || seen[name.value] {
				return result, errMetrics
			}
			seen[name.value] = true
			path := ""
			switch name.value {
			case "vda":
				path = i.Disk
				result.BlockReadBytes = read(prefix + "rd.bytes")
				result.BlockWriteBytes = read(prefix + "wr.bytes")
			case "sda":
				if i.Seed == "" {
					return result, errMetrics
				}
				path = i.Seed
			default:
				return result, errMetrics
			}
			if p, present := fields[prefix+"path"]; present && (!p.text || p.value != path) {
				return result, errMetrics
			}
		}
	}
	if err = validateMetricDevices(fields, "net", 1); err != nil {
		return result, err
	}
	if v, present := fields["net.count"]; present && v.value == "1" {
		name, ok := fields["net.0.name"]
		validName := metricInterface.MatchString(name.value)
		if !i.Network.IsZero() {
			validName = name.value == fabric.TAPName(i.ID)
		}
		if i.IPv4 == "" || !ok || !name.text || !validName {
			return result, errMetrics
		}
		result.NetworkReceiveBytes = read("net.0.rx.bytes")
		result.NetworkTransmitBytes = read("net.0.tx.bytes")
	}
	if err != nil {
		return result, err
	}
	return result, nil
}

// Array fields cannot exist without their bounded count, use noncanonical
// indexes, or point outside the declared list. This is deliberately stricter
// than collecting every matching *.bytes field into an unowned aggregate.
func validateMetricDevices(fields map[string]metricValue, kind string, maximum uint64) error {
	count := uint64(0)
	if v, present := fields[kind+".count"]; present {
		var ok bool
		count, ok = metricUint(v.value)
		if !ok || v.text || count > maximum {
			return errMetrics
		}
	}
	for key := range fields {
		if !strings.HasPrefix(key, kind+".") || key == kind+".count" {
			continue
		}
		index, suffix, ok := strings.Cut(strings.TrimPrefix(key, kind+"."), ".")
		n, valid := metricUint(index)
		if !ok || !valid || n >= count || suffix == "" {
			return errMetrics
		}
	}
	return nil
}

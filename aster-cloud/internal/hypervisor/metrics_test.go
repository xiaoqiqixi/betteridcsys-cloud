package hypervisor

import (
	"aster/cloud/internal/nodeproto"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type metricsRunner struct {
	base Runner
	mu   sync.Mutex
	raw  []byte
	err  error
	args [][]string
}

func (r *metricsRunner) Run(ctx context.Context, binary string, args ...string) ([]byte, error) {
	if binary != Virsh || len(args) < 3 || args[2] != "domstats" {
		return r.base.Run(ctx, binary, args...)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.args = append(r.args, append([]string{}, args...))
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return append([]byte{}, r.raw...), r.err
}

func (r *metricsRunner) calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.args)
}

func sampleMetrics(i Instance) []byte {
	// Format derived from libvirt v8.0.0 (Ubuntu 22): only Domain is quoted;
	// virshDomainStatsPrintRecord and vshGetTypedParamValue print strings raw.
	// https://github.com/libvirt/libvirt/blob/v8.0.0/tools/virsh-domain-monitor.c
	// https://github.com/libvirt/libvirt/blob/v8.0.0/tools/vsh.c
	return []byte(fmt.Sprintf("Domain: '%s'\n  cpu.time=18446744073709551615\n  cpu.user=123\n  balloon.current=524288\n  balloon.rss=600000\n  balloon.unused=123456\n  balloon.last-update=%d\n  block.count=2\n  block.0.name=sda\n  block.0.path=%s\n  block.0.rd.bytes=9999\n  block.0.wr.bytes=8888\n  block.1.name=vda\n  block.1.path=%s\n  block.1.rd.bytes=9007199254740993\n  block.1.wr.bytes=0\n  net.count=1\n  net.0.name=vnet7\n  net.0.rx.bytes=42\n  net.0.tx.bytes=43\n\n", i.Domain, time.Now().Unix(), i.Seed, i.Disk))
}

func TestMetricsLibvirt8RawStringFormat(t *testing.T) {
	// This regression uses the official v8 printer's literal unquoted format,
	// not an observed KVM capture and not a quoted fake-runner abstraction.
	// Changing numeric validation to accept strings would NOT fix this case:
	// device names and approved absolute paths have their own exact bindings.
	const raw = `Domain: 'aster-22222222222222222222222222222222'
  cpu.time=1234567890
  balloon.current=524288
  block.count=2
  block.0.name=vda
  block.0.path=/srv/aster/vm/system.qcow2
  block.0.rd.bytes=9007199254740993
  block.0.wr.bytes=321
  block.1.name=sda
  block.1.path=/srv/aster/vm/seed.iso
  block.1.rd.bytes=999999
  net.count=1
  net.0.name=vnet0
  net.0.rx.bytes=42
  net.0.tx.bytes=43
`
	i := Instance{Domain: "aster-22222222222222222222222222222222", Disk: "/srv/aster/vm/system.qcow2", Seed: "/srv/aster/vm/seed.iso", IPv4: "192.0.2.10"}
	got, err := parseInstanceMetrics([]byte(raw), i, time.Now().UTC())
	if err != nil {
		t.Fatal("Ubuntu22/libvirt8 raw typed-string format rejected", err)
	}
	assertCounter(t, got.CPUTimeNS, "1234567890")
	assertCounter(t, got.MemoryActualKiB, "524288")
	assertCounter(t, got.BlockReadBytes, "9007199254740993")
	assertCounter(t, got.BlockWriteBytes, "321")
	assertCounter(t, got.NetworkReceiveBytes, "42")
	assertCounter(t, got.NetworkTransmitBytes, "43")
	if got.MemoryRSSKiB != nil || got.MemoryUnusedKiB != nil {
		t.Fatal("unsupported memory fields invented")
	}
}

func newMetricsFixture(t *testing.T) (*Manager, *fakeRunner, *metricsRunner, nodeproto.NodeTask, Instance) {
	t.Helper()
	m, f, task := newFixture(t)
	if r := submit(t, m, task); r.Status != "succeeded" {
		t.Fatal(r)
	}
	i, ok := m.Ledger.Instance(task.InstanceID)
	if !ok {
		t.Fatal("fixture instance absent")
	}
	r := &metricsRunner{base: f, raw: sampleMetrics(i)}
	m.Runner = r
	return m, f, r, task, i
}

func assertCounter(t *testing.T, got *string, want string) {
	t.Helper()
	if got == nil || *got != want {
		t.Fatalf("counter %v, want %q", got, want)
	}
}

func TestMetricsReadOnlyOwnedDomainExactCommandAndUnits(t *testing.T) {
	m, f, r, task, i := newMetricsFixture(t)
	before, err := os.ReadFile(filepath.Join(m.Config.StateDirectory, "journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	// A stale journal state is not a metrics observation.
	f.mu.Lock()
	f.states[i.Domain] = "shut off"
	f.mu.Unlock()
	got, err := m.ObserveMetrics(context.Background(), i.ID)
	if err != nil || !got.Validate() || got.State != "shutoff" || got.InstanceID != i.ID || got.OwnerRef != task.OwnerRef || got.Hostname != task.Hostname || got.NodeID != m.Config.NodeID || got.VCPUs != 1 {
		t.Fatal(got, err)
	}
	assertCounter(t, got.CPUTimeNS, "18446744073709551615")
	assertCounter(t, got.MemoryActualKiB, "524288")
	assertCounter(t, got.MemoryRSSKiB, "600000")
	assertCounter(t, got.MemoryUnusedKiB, "123456")
	assertCounter(t, got.BlockReadBytes, "9007199254740993")
	assertCounter(t, got.BlockWriteBytes, "0")
	assertCounter(t, got.NetworkReceiveBytes, "42")
	assertCounter(t, got.NetworkTransmitBytes, "43")
	want := []string{"--connect", "qemu:///system", "domstats", i.Domain, "--raw", "--cpu-total", "--balloon", "--block", "--interface"}
	if r.calls() != 1 || !reflect.DeepEqual(r.args[0], want) {
		t.Fatal("unexpected command", r.args)
	}
	after, _ := os.ReadFile(filepath.Join(m.Config.StateDirectory, "journal.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("metrics wrote journal/state")
	}
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), i.Domain) || strings.Contains(string(raw), i.Disk) || strings.Contains(string(raw), "vnet7") || strings.Contains(string(raw), i.Seed) {
		t.Fatal("private domain/path/interface leaked", string(raw))
	}
	if _, err = nodeproto.DecodeInstanceMetrics(raw); err != nil {
		t.Fatal("node output did not satisfy wire contract", err)
	}
}

func TestMetricsUnsupportedCountersRemainNullNotZero(t *testing.T) {
	m, _, r, _, i := newMetricsFixture(t)
	r.raw = []byte("Domain: '" + i.Domain + "'\n")
	got, err := m.ObserveMetrics(context.Background(), i.ID)
	if err != nil || !got.Validate() {
		t.Fatal(got, err)
	}
	for _, v := range []*string{got.CPUTimeNS, got.MemoryRSSKiB, got.MemoryActualKiB, got.MemoryUnusedKiB, got.BlockReadBytes, got.BlockWriteBytes, got.NetworkReceiveBytes, got.NetworkTransmitBytes} {
		if v != nil {
			t.Fatal("missing statistic invented", *v)
		}
	}
	raw, _ := json.Marshal(got)
	if bytes.Count(raw, []byte(":null")) != 8 {
		t.Fatal("missing counters not emitted as null", string(raw))
	}
}

func TestMetricsGuestUnusedRequiresFreshBalloonTimestamp(t *testing.T) {
	i := Instance{Domain: "aster-22222222222222222222222222222222"}
	now := time.Date(2026, 10, 23, 1, 2, 3, 0, time.UTC)
	for _, tc := range []struct {
		name    string
		last    string
		at      time.Time
		present bool
	}{
		{"missing", "", now, false},
		{"zero", "0", now, false},
		{"now", fmt.Sprint(now.Unix()), now, true},
		{"old_inside", fmt.Sprint(now.Unix() - 59), now, true},
		{"old_exact_60", fmt.Sprint(now.Unix() - 60), now, true},
		{"old_61", fmt.Sprint(now.Unix() - 61), now, false},
		{"old_60_plus_ns", fmt.Sprint(now.Unix() - 60), now.Add(time.Nanosecond), false},
		{"future_inside", fmt.Sprint(now.Unix() + 4), now, true},
		{"future_exact_5", fmt.Sprint(now.Unix() + 5), now, true},
		{"future_6", fmt.Sprint(now.Unix() + 6), now, false},
		{"future_5_plus_ns", fmt.Sprint(now.Unix() + 5), now.Add(-time.Nanosecond), false},
		{"future_uint64_max", "18446744073709551615", now, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := "Domain: '" + i.Domain + "'\n  cpu.time=99\n  balloon.rss=600\n  balloon.current=512\n  balloon.unused=7\n"
			if tc.last != "" {
				raw += "  balloon.last-update=" + tc.last + "\n"
			}
			got, err := parseInstanceMetrics([]byte(raw), i, tc.at)
			if err != nil {
				t.Fatal("unavailable guest memory should not discard independent host statistics", err)
			}
			if tc.present {
				assertCounter(t, got.MemoryUnusedKiB, "7")
			} else if got.MemoryUnusedKiB != nil {
				t.Fatal("stale/missing/future guest report disguised as current", *got.MemoryUnusedKiB)
			}
			assertCounter(t, got.CPUTimeNS, "99")
			assertCounter(t, got.MemoryRSSKiB, "600")
			assertCounter(t, got.MemoryActualKiB, "512")
		})
	}
	raw := fmt.Sprintf("Domain: '%s'\n  balloon.last-update=%d\n", i.Domain, now.Unix())
	got, err := parseInstanceMetrics([]byte(raw), i, now)
	if err != nil || got.MemoryUnusedKiB != nil {
		t.Fatal("fresh timestamp invented absent guest statistic", got, err)
	}
}

func TestMetricsStaleGuestMemoryNeverEnablesPolling(t *testing.T) {
	m, f, r, _, i := newMetricsFixture(t)
	r.raw = []byte("Domain: '" + i.Domain + "'\n  cpu.time=99\n  balloon.unused=7\n  balloon.last-update=0\n")
	got, err := m.ObserveMetrics(context.Background(), i.ID)
	if err != nil || got.MemoryUnusedKiB != nil || r.calls() != 1 {
		t.Fatal("stale guest report not withheld", got, err)
	}
	if f.count("dommemstat") != 0 || f.count("setmem") != 0 || f.count("--period") != 0 {
		t.Fatal("GET enabled or modified guest polling")
	}
	assertCounter(t, got.CPUTimeNS, "99")
}

func TestMetricsRejectBusyPendingReservedAndUnknownWithoutSampling(t *testing.T) {
	for _, name := range []string{"active", "stopping", "reserved", "uncertain", "pending_power", "pending_storage", "deleted", "absent", "bad_id"} {
		t.Run(name, func(t *testing.T) {
			m, f, r, task, i := newMetricsFixture(t)
			id := i.ID
			want := ErrConflict
			switch name {
			case "active":
				m.active = true
			case "stopping":
				m.stopping = true
			case "reserved", "uncertain", "deleted":
				i.State = name
				if _, err := m.Ledger.Finish(task.OperationID, "succeeded", "TEST_METRICS", &i); err != nil {
					t.Fatal(err)
				}
				if name == "deleted" {
					want = ErrNotFound
				}
			case "pending_power":
				if _, err := m.Ledger.Finish(task.OperationID, "uncertain", "TEST_METRICS", nil); err != nil {
					t.Fatal(err)
				}
			case "pending_storage":
				task := storageTask(task, 0x77, "backup_create", 0x88)
				raw, sha, _ := task.BytesAndDigest()
				if len(raw) == 0 {
					t.Fatal("invalid fixture")
				}
				if _, _, err := m.Ledger.ClaimStorage(task, sha); err != nil {
					t.Fatal(err)
				}
			case "absent":
				id, want = strings.Repeat("9", 32), ErrNotFound
			case "bad_id":
				id, want = "../../host", ErrNotFound
			}
			before := len(f.commands)
			if _, err := m.ObserveMetrics(context.Background(), id); !errors.Is(err, want) {
				t.Fatal("unexpected error", err, "want", want)
			}
			if r.calls() != 0 || len(f.commands) != before {
				t.Fatal("unconfirmed resource touched libvirt")
			}
			m.active, m.stopping = false, false
		})
	}
}

func TestMetricsRequireOwnershipAndRejectCommandFailures(t *testing.T) {
	for _, name := range []string{"domain_path", "symlink", "owner", "node", "disk_xml", "extra_nic", "nic_address", "dumpxml_error", "state_error", "stats_error", "context_cancelled", "unknown_live_state"} {
		t.Run(name, func(t *testing.T) {
			m, f, r, task, i := newMetricsFixture(t)
			ctx := context.Background()
			switch name {
			case "domain_path":
				i.Directory = "/etc"
				_, _ = m.Ledger.Finish(task.OperationID, "succeeded", "TEST_METRICS", &i)
			case "symlink":
				if err := os.Rename(i.Directory, i.Directory+"-real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(i.Directory+"-real", i.Directory); err != nil {
					t.Fatal(err)
				}
			case "owner":
				f.domains[i.Domain] = bytes.ReplaceAll(f.domains[i.Domain], []byte(i.OwnerRef), []byte(strings.Repeat("9", 32)))
			case "node":
				f.domains[i.Domain] = bytes.ReplaceAll(f.domains[i.Domain], []byte(`node_id="node-a"`), []byte(`node_id="node-b"`))
			case "disk_xml":
				f.domains[i.Domain] = bytes.ReplaceAll(f.domains[i.Domain], []byte(i.Disk), []byte("/etc/secret"))
			case "extra_nic":
				f.domains[i.Domain] = bytes.Replace(f.domains[i.Domain], []byte("</devices>"), []byte(`<interface type="bridge"></interface></devices>`), 1)
			case "nic_address":
				f.domains[i.Domain] = bytes.ReplaceAll(f.domains[i.Domain], []byte(i.IPv4), []byte("192.0.2.199"))
			case "dumpxml_error":
				f.fail = "dumpxml"
			case "state_error":
				f.fail = "domstate"
			case "stats_error":
				r.err = errors.New("injected libvirt error containing private path")
			case "context_cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "unknown_live_state":
				f.states[i.Domain] = "unknown"
			}
			before, _ := os.ReadFile(filepath.Join(m.Config.StateDirectory, "journal.json"))
			if _, err := m.ObserveMetrics(ctx, i.ID); err == nil {
				t.Fatal("unconfirmed metrics accepted")
			}
			if name != "stats_error" && name != "unknown_live_state" && r.calls() != 0 {
				t.Fatal("failed ownership/state reached sampling")
			}
			after, _ := os.ReadFile(filepath.Join(m.Config.StateDirectory, "journal.json"))
			if !bytes.Equal(before, after) {
				t.Fatal("failure wrote journal")
			}
		})
	}
}

func TestMetricsParserRejectMalformedAmbiguousOrForeignData(t *testing.T) {
	_, _, _, _, i := newMetricsFixture(t)
	s := string(sampleMetrics(i))
	cases := map[string]string{
		"empty": "", "nul": s + "\x00", "cr": strings.Replace(s, "\n", "\r\n", 1),
		"different_domain":  strings.Replace(s, i.Domain, "host", 1),
		"second_domain":     s + "Domain: 'host'\n  cpu.time=12\n",
		"missing_header":    strings.TrimPrefix(s, "Domain: '"+i.Domain+"'\n"),
		"duplicate_counter": s + "  cpu.time=1\n", "duplicate_name": s + "  net.0.name=vnet7\n",
		"negative":            strings.Replace(s, "cpu.time=18446744073709551615", "cpu.time=-1", 1),
		"overflow":            strings.Replace(s, "cpu.time=18446744073709551615", "cpu.time=18446744073709551616", 1),
		"leading_zero":        strings.Replace(s, "net.0.rx.bytes=42", "net.0.rx.bytes=042", 1),
		"float":               strings.Replace(s, "net.0.rx.bytes=42", "net.0.rx.bytes=42.0", 1),
		"plus":                strings.Replace(s, "net.0.rx.bytes=42", "net.0.rx.bytes=+42", 1),
		"space":               strings.Replace(s, "net.0.rx.bytes=42", "net.0.rx.bytes= 42", 1),
		"trailing_space":      strings.Replace(s, "net.0.rx.bytes=42", "net.0.rx.bytes=42 ", 1),
		"quoted_number":       strings.Replace(s, "net.0.rx.bytes=42", "net.0.rx.bytes='42'", 1),
		"quoted_seed_counter": strings.Replace(s, "block.0.rd.bytes=9999", "block.0.rd.bytes='9999'", 1),
		"numeric_nic_name":    strings.Replace(s, "net.0.name=vnet7", "net.0.name=7", 1),
		"outer_quote_nic":     strings.Replace(s, "net.0.name=vnet7", "net.0.name='vnet7'", 1),
		"outer_quote_disk":    strings.Replace(s, "block.1.name=vda", "block.1.name='vda'", 1),
		"outer_quote_path":    strings.Replace(s, "block.1.path="+i.Disk, "block.1.path='"+i.Disk+"'", 1),
		"unsafe_name":         strings.Replace(s, "net.0.name=vnet7", "net.0.name=eth0", 1),
		"control_in_name":     strings.Replace(s, "net.0.name=vnet7", "net.0.name=vnet\t7", 1),
		"unknown_group":       s + "  host.time=1\n", "malformed": s + "  cpu.time\n",
		"uppercase":           strings.Replace(s, "cpu.time=", "CPU.time=", 1),
		"no_net_count":        strings.Replace(s, "  net.count=1\n", "", 1),
		"wrong_net_count":     strings.Replace(s, "net.count=1", "net.count=0", 1),
		"many_nics":           strings.Replace(s, "net.count=1", "net.count=2", 1),
		"no_nic_name":         strings.Replace(s, "  net.0.name=vnet7\n", "", 1),
		"net_out_of_range":    s + "  net.1.rx.bytes=1\n",
		"noncanonical_index":  strings.Replace(s, "net.0.rx.bytes", "net.00.rx.bytes", 1),
		"no_block_count":      strings.Replace(s, "  block.count=2\n", "", 1),
		"many_disks":          strings.Replace(s, "block.count=2", "block.count=3", 1),
		"missing_disk_name":   strings.Replace(s, "  block.1.name=vda\n", "", 1),
		"wrong_disk":          strings.Replace(s, "block.1.name=vda", "block.1.name=vdb", 1),
		"duplicate_disk":      strings.Replace(s, "block.0.name=sda", "block.0.name=vda", 1),
		"wrong_disk_path":     strings.Replace(s, i.Disk, "/host/other.qcow2", 1),
		"wrong_seed_path":     strings.Replace(s, i.Seed, "/host/other.iso", 1),
		"missing_array_index": s + "  block.path=/etc/private\n",
		"backing_chain":       s + "  block.2.name=vda\n",
		"long_line":           s + "  cpu.extra=" + strings.Repeat("1", 4097) + "\n",
		"large_payload":       s + strings.Repeat("\n", 65536),
	}
	var many strings.Builder
	many.WriteString("Domain: '" + i.Domain + "'\n")
	for n := 0; n < 257; n++ {
		fmt.Fprintf(&many, "  cpu.extra%d=1\n", n)
	}
	cases["too_many_fields"] = many.String()
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseInstanceMetrics([]byte(raw), i, time.Now().UTC()); err == nil {
				t.Fatal("unsafe stats accepted")
			}
		})
	}
}

func TestMetricsParserNoNICOrSeedAndPartialStats(t *testing.T) {
	_, _, _, _, i := newMetricsFixture(t)
	i.IPv4, i.MAC, i.Seed = "", "", ""
	good := "Domain: '" + i.Domain + "'\n  block.count=1\n  block.0.name=vda\n  block.0.rd.bytes=0\n  net.count=0\n"
	got, err := parseInstanceMetrics([]byte(good), i, time.Now().UTC())
	if err != nil || got.NetworkReceiveBytes != nil || got.BlockWriteBytes != nil || got.MemoryActualKiB != nil {
		t.Fatal(got, err)
	}
	assertCounter(t, got.BlockReadBytes, "0")
	for _, raw := range []string{strings.Replace(good, "name=vda", "name=sda", 1), strings.Replace(good, "net.count=0", "net.count=1\n net.0.name=vnet1\n net.0.rx.bytes=1", 1)} {
		if _, err := parseInstanceMetrics([]byte(raw), i, time.Now().UTC()); err == nil {
			t.Fatal("unowned seed/NIC accepted")
		}
	}
}

func TestMetricsHTTPRequiresPinnedMTLSReadOnlyAndExactResource(t *testing.T) {
	m, _, runner, _, i := newMetricsFixture(t)
	certs := certificates(t)
	m.Config.ExpectedControllerCertificateSHA256 = nodeproto.Digest(certs.goodLeaf.Raw)
	base := "/v1/instances/" + i.ID + "/metrics"
	for _, tc := range []struct {
		name, method, path string
		code               int
		auth               string
	}{
		{"read", "GET", base, 200, "good"},
		{"no_tls", "GET", base, 403, "none"},
		{"unverified", "GET", base, 403, "unverified"},
		{"other_leaf", "GET", base, 403, "other"},
		{"post", "POST", base, 405, "good"},
		{"put", "PUT", base, 405, "good"},
		{"delete", "DELETE", base, 405, "good"},
		{"head", "HEAD", base, 405, "good"},
		{"query", "GET", base + "?retry=1", 400, "good"},
		{"empty_query", "GET", base + "?", 400, "good"},
		{"bad_id", "GET", "/v1/instances/host/metrics", 404, "good"},
		{"unknown_id", "GET", "/v1/instances/" + strings.Repeat("9", 32) + "/metrics", 404, "good"},
		{"extra_path", "GET", "/v1/instances/" + i.ID + "/extra/metrics", 404, "good"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := authorizedRequest(m, tc.method, tc.path, nil, certs.goodLeaf)
			switch tc.auth {
			case "none":
				r.TLS = nil
			case "unverified":
				r.TLS.VerifiedChains = nil
			case "other":
				r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Raw: []byte("other")}}, VerifiedChains: [][]*x509.Certificate{{certs.goodLeaf}}}
			}
			before := runner.calls()
			w := httptest.NewRecorder()
			m.Handler().ServeHTTP(w, r)
			if w.Code != tc.code || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal(w.Code, w.Body.String())
			}
			if tc.code == 200 {
				if _, err := nodeproto.DecodeInstanceMetrics(w.Body.Bytes()); err != nil || runner.calls() != before+1 {
					t.Fatal("invalid live response", err)
				}
			} else if runner.calls() != before {
				t.Fatal("non-read/rejected request sampled")
			}
			if tc.code == 405 && w.Header().Get("Allow") != http.MethodGet {
				t.Fatal("missing GET method hint")
			}
		})
	}
	m.active = true
	r := authorizedRequest(m, "GET", base, nil, certs.goodLeaf)
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, r)
	if w.Code != 409 || !strings.Contains(w.Body.String(), "LIVE_INSTANCE_METRICS_UNCONFIRMED") {
		t.Fatal(w.Code, w.Body.String())
	}
	m.active = false
	runner.err = errors.New("private host details")
	w = httptest.NewRecorder()
	m.Handler().ServeHTTP(w, r)
	if w.Code != 409 || strings.Contains(w.Body.String(), "private host") {
		t.Fatal("command error leaked or reported success", w.Code, w.Body.String())
	}
}

package hypervisor

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLegacyRejectedQuotaAndBandwidthJournalRemainsReadable(t *testing.T) {
	for _, quota := range []bool{false, true} {
		m, _, task := newFixture(t)
		if quota {
			task.Resources.TransferGiB = 10
		} else {
			task.Resources.BandwidthMbps = 10
		}
		if result := submit(t, m, task); result.Status != "rejected" {
			t.Fatal(result)
		}
		m.Shutdown()
		m.Ledger.Close()
		path := filepath.Join(m.Config.StateDirectory, "journal.json")
		raw, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		var old journal
		if e = json.Unmarshal(raw, &old); e != nil {
			t.Fatal(e)
		}
		old.Schema = 1
		raw, _ = json.Marshal(old)
		if e = os.WriteFile(path, raw, 0600); e != nil {
			t.Fatal(e)
		}
		ledger, e := OpenLedger(m.Config.StateDirectory, m.Config.NodeID)
		if e != nil {
			t.Fatal("old unsupported resource receipt became unreadable", e)
		}
		ledger.Close()
	}
}

func TestTrafficDeltaWrapAndRestartReset(t *testing.T) {
	for _, v := range []struct {
		old, next uint64
		restart   bool
		want      uint64
	}{{100, 200, false, 100}, {math.MaxUint64 - 4, 7, false, 12}, {1000, 7, false, 7}, {100, 900, true, 900}, {math.MaxUint64 - 4, 7, true, 7}} {
		if got := trafficDelta(v.old, v.next, v.restart); got != v.want {
			t.Fatal(v, got)
		}
	}
}
func TestTrafficJournalSurvivesRestartAndKeepsCumulativeDailyRevision(t *testing.T) {
	m, _, task := newFixture(t)
	if r := submit(t, m, task); r.Status != "succeeded" {
		t.Fatal(r)
	}
	i, _ := m.Ledger.Instance(task.InstanceID)
	now := time.Now().UTC().Truncate(24 * time.Hour).Add(12 * time.Hour)
	if e := m.Ledger.recordTraffic(i, "boot:1", 1000, 2000, now); e != nil {
		t.Fatal(e)
	}
	if e := m.Ledger.recordTraffic(i, "boot:1", 1100, 2300, now.Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
	if e := m.Ledger.recordTraffic(i, "boot:2", 50, 70, now.Add(2*time.Minute)); e != nil {
		t.Fatal(e)
	}
	v, e := m.Ledger.Traffic(i.ID)
	if e != nil || len(v.Days) != 1 || v.Days[0].RXBytes != "150" || v.Days[0].TXBytes != "370" || v.Days[0].Revision != 3 {
		t.Fatal(v, e)
	}
	m.Shutdown()
	m.Ledger.Close()
	ledger, e := OpenLedger(m.Config.StateDirectory, m.Config.NodeID)
	if e != nil {
		t.Fatal(e)
	}
	defer ledger.Close()
	got, e := ledger.Traffic(i.ID)
	if e != nil || got.StreamID != v.StreamID || got.Days[0] != v.Days[0] {
		t.Fatal("reopen changed cumulative stream", got, e)
	}
	if e = ledger.recordTraffic(i, "boot:2", 80, 100, now.Add(3*time.Minute)); e != nil {
		t.Fatal(e)
	}
	got, e = ledger.Traffic(i.ID)
	if e != nil || got.Days[0].RXBytes != "180" || got.Days[0].TXBytes != "400" {
		t.Fatal(got, e)
	}
}
func TestDomifstatRejectsMissingForeignAndDuplicateCounters(t *testing.T) {
	mac := "52:54:00:00:00:01"
	good := mac + " rx_bytes 10\n" + mac + " tx_bytes 20\n"
	if rx, tx, e := parseDomifstat([]byte(good), mac); e != nil || rx != 10 || tx != 20 {
		t.Fatal(rx, tx, e)
	}
	for _, raw := range []string{mac + " rx_bytes 10\n", good + mac + " rx_bytes 11\n", "other rx_bytes 10\n" + mac + " tx_bytes 20\n", mac + " rx_bytes -1\n" + mac + " tx_bytes 20\n"} {
		if _, _, e := parseDomifstat([]byte(raw), mac); e == nil {
			t.Fatal("invalid counter accepted", raw)
		}
	}
}

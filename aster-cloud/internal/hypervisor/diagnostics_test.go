package hypervisor

import (
	"aster/cloud/internal/diagnostics"
	"aster/cloud/internal/nodeproto"
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestUnconfirmedJournalNeverLogsStorageOrPowerSuccess(t *testing.T) {
	for _, storage := range []bool{false, true} {
		var out bytes.Buffer
		previous := slog.Default()
		slog.SetDefault(diagnostics.New(&out, "node"))
		m := &Manager{Config: Config{NodeID: "node-a"}}
		id := strings.Repeat("a", 32)
		if storage {
			m.logStorageOutcome(context.Background(), nodeproto.TypedStorageTask{OperationID: id, InstanceID: id, Action: "backup_create"}, "succeeded", "", false)
		} else {
			m.logOutcome(nodeproto.NodeTask{OperationID: id, InstanceID: id, Action: "force_off"}, nodeproto.NodeResult{Status: "succeeded"}, "", false)
		}
		slog.SetDefault(previous)
		var event map[string]any
		if e := json.Unmarshal(out.Bytes(), &event); e != nil || event["status"] != "uncertain" || event["level"] != "WARN" || event["code"] != "JOURNAL_WRITE_UNCONFIRMED" || event["journal_write_confirmed"] != false || event["action"] == nil {
			t.Fatal(event, e)
		}
	}
}

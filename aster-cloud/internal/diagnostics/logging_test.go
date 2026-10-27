package diagnostics

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestJSONEventsAreUTCStructuredAndAllowlisted(t *testing.T) {
	var out bytes.Buffer
	logger := New(&out, "node")
	logger.Warn("aster_node_operation", "operation_id", strings.Repeat("a", 32), "state", "uncertain", "journal_write_confirmed", false, "code", "JOURNAL_UNCONFIRMED")
	var event map[string]any
	if err := json.Unmarshal(out.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	if event["component"] != "node" || event["level"] != "WARN" || event["state"] != "uncertain" || event["journal_write_confirmed"] != false || !strings.HasSuffix(event["time"].(string), "Z") {
		t.Fatal(event)
	}
}

func TestUntrustedMessagesValuesAndFieldsNeverReachJSON(t *testing.T) {
	var out bytes.Buffer
	secret := "password=PRIVATE-SENTINEL\nforged line"
	logger := New(&out, "controller")
	logger.Error(secret, "password", secret, "dsn", secret, "error", secret, "operation_id", secret, "node_id", secret, "code", secret, "status", "arbitrary-secret", "request_sha256", secret, slog.Group("nested", "operation_id", strings.Repeat("c", 32)))
	if strings.Contains(out.String(), "PRIVATE-SENTINEL") || strings.Contains(out.String(), "arbitrary-secret") || strings.Contains(out.String(), "nested") || strings.Contains(out.String(), strings.Repeat("c", 32)) {
		t.Fatal("private or unsupported fields reached log")
	}
	var event map[string]any
	if err := json.Unmarshal(out.Bytes(), &event); err != nil || event["msg"] != "aster_event_redacted" || len(event) != 4 {
		t.Fatal(event, err)
	}
}

func TestTransportLoggerDoesNotEchoGoTLSErrorOrRemoteData(t *testing.T) {
	var out bytes.Buffer
	logger := TransportLog(New(&out, "controller"))
	logger.Print("TLS handshake error from PRIVATE-IP: certificate PRIVATE-CERT /private/key.pem")
	if strings.Contains(out.String(), "PRIVATE") || strings.Contains(out.String(), "key.pem") {
		t.Fatal("raw server error leaked")
	}
	var event map[string]any
	if err := json.Unmarshal(out.Bytes(), &event); err != nil || event["msg"] != "aster_http_transport_error" || event["level"] != "WARN" {
		t.Fatal(event, err)
	}
}

type privateStringer struct{ Private string }

func (privateStringer) String() string { return "accepted" }

func TestUnsupportedTypesCannotMasqueradeAsAllowedStrings(t *testing.T) {
	var out bytes.Buffer
	logger := New(&out, "controller")
	logger.Info("aster_controller_operation", "status", privateStringer{Private: "SECRET-SENTINEL"}, "time", "SECRET-SENTINEL", "action", privateStringer{Private: "SECRET-SENTINEL"})
	if strings.Contains(out.String(), "SECRET-SENTINEL") || strings.Contains(out.String(), "Private") {
		t.Fatal("arbitrary structured value was logged")
	}
}

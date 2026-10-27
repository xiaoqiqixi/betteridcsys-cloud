// Package diagnostics writes operational metadata, never authoritative audit or
// recovery state. Its closed vocabulary deliberately excludes free-form errors,
// request bodies, credentials, paths, guest data and subprocess output.
package diagnostics

import (
	"io"
	"log"
	"log/slog"
	"regexp"
)

var word = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$`)
var id = regexp.MustCompile(`^[a-f0-9]{32}$`)
var digest = regexp.MustCompile(`^[a-f0-9]{64}$`)
var code = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,79}$`)

func New(out io.Writer, component string) *slog.Logger {
	if component != "controller" && component != "node" {
		component = "unknown"
	}
	return slog.New(slog.NewJSONHandler(out, &slog.HandlerOptions{ReplaceAttr: safeAttribute})).With("component", component)
}

func safeAttribute(groups []string, attr slog.Attr) slog.Attr {
	if len(groups) != 0 {
		return slog.Attr{}
	}
	switch attr.Key {
	case slog.TimeKey:
		if attr.Value.Kind() == slog.KindTime {
			return slog.Time(slog.TimeKey, attr.Value.Time().UTC())
		}
	case slog.LevelKey:
		if _, ok := attr.Value.Any().(slog.Level); ok {
			return attr
		}
	case slog.MessageKey:
		if attr.Value.Kind() != slog.KindString {
			return slog.Attr{}
		}
		switch attr.Value.String() {
		case "aster_node_operation", "aster_node_storage_operation", "aster_controller_transfer", "aster_controller_operation", "aster_controller_provisioning", "aster_service_starting", "aster_service_stopped", "aster_command_failed", "aster_http_transport_error":
			return attr
		}
		return slog.String(slog.MessageKey, "aster_event_redacted")
	case "component":
		if attr.Value.Kind() == slog.KindString && (attr.Value.String() == "controller" || attr.Value.String() == "node" || attr.Value.String() == "unknown") {
			return attr
		}
	case "operation_id", "instance_id":
		if attr.Value.Kind() == slog.KindString && id.MatchString(attr.Value.String()) {
			return attr
		}
	case "node_id":
		if attr.Value.Kind() == slog.KindString && word.MatchString(attr.Value.String()) {
			return attr
		}
	case "request_sha256":
		if attr.Value.Kind() == slog.KindString && digest.MatchString(attr.Value.String()) {
			return attr
		}
	case "code":
		if attr.Value.Kind() == slog.KindString && code.MatchString(attr.Value.String()) {
			return attr
		}
	case "action", "command":
		if attr.Value.Kind() != slog.KindString {
			return slog.Attr{}
		}
		switch attr.Value.String() {
		case "create", "start", "shutdown", "reboot", "force_off", "delete", "dispatch", "reconcile", "init", "migrate", "check", "bootstrap-admin", "operation-dispatch", "operation-reconcile", "register-nodes", "heartbeat", "maintenance", "serve", "doctor", "approve-storage-import", "snapshot_create", "snapshot_restore", "snapshot_delete", "backup_create", "backup_verify", "backup_restore", "backup_delete", "migrate_prepare", "migrate_transfer", "migrate_import", "migrate_activate":
			return attr
		}
	case "state", "status":
		if attr.Value.Kind() != slog.KindString {
			return slog.Attr{}
		}
		switch attr.Value.String() {
		case "accepted", "sending", "dispatched", "succeeded", "rejected", "uncertain":
			return attr
		}
	case "result":
		if attr.Value.Kind() == slog.KindString && (attr.Value.String() == "confirmed" || attr.Value.String() == "inspect_original_operation") {
			return attr
		}
	case "journal_write_confirmed":
		if attr.Value.Kind() == slog.KindBool {
			return attr
		}
	}
	return slog.Attr{}
}

type transportWriter struct{ logger *slog.Logger }

func (w transportWriter) Write(raw []byte) (int, error) {
	// net/http may include remote addresses, certificate subjects and peer input.
	// Keep the fact of a transport failure, never its untrusted free-form text.
	w.logger.Warn("aster_http_transport_error")
	return len(raw), nil
}

func TransportLog(logger *slog.Logger) *log.Logger {
	return log.New(transportWriter{logger}, "", 0)
}

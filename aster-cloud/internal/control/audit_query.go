package control

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const auditCursorPrefix = "a1."

var auditExactValue = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]*$`)
var auditTimestamp = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?(Z|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$`)

// Filters are exact, case-sensitive, ANDed, and independent of authorization.
// Canonical UTC timestamps preserve MySQL DATETIME(6) precision, never round.
type auditFilters struct {
	Source string `json:"source"`
	Action string `json:"action"`
	Actor  string `json:"actor"`
	Target string `json:"target"`
	From   string `json:"from"`
	Until  string `json:"until"`
}

type auditPageCursor struct {
	At      string `json:"at"`
	Source  string `json:"source"`
	ID      int64  `json:"id"`
	Filters string `json:"filters_sha256"`
}

type auditQuery struct {
	Filters auditFilters
	Cursor  *auditPageCursor
}

func parseAuditTime(raw string) (time.Time, error) {
	if !auditTimestamp.MatchString(raw) {
		return time.Time{}, ErrInput
	}
	t, e := time.Parse(time.RFC3339Nano, raw)
	if e != nil || t.UTC().Year() < 1000 || t.UTC().Year() > 9999 {
		return time.Time{}, ErrInput
	}
	return t.UTC(), nil
}

func (f auditFilters) digest() string {
	raw, _ := json.Marshal(f)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

func parseAuditQuery(raw string) (auditQuery, error) {
	q := auditQuery{}
	if len(raw) > 4096 {
		return q, ErrInput
	}
	values, e := url.ParseQuery(raw)
	if e != nil {
		return q, ErrInput
	}
	allowed := map[string]int{"source": 8, "action": 64, "actor": 80, "target": 128, "from": 32, "until": 32, "cursor": 1024}
	for k, vs := range values {
		maximum, ok := allowed[k]
		if !ok || len(vs) != 1 || len(vs[0]) == 0 || len(vs[0]) > maximum {
			return q, ErrInput
		}
	}
	q.Filters = auditFilters{Source: values.Get("source"), Action: values.Get("action"), Actor: values.Get("actor"), Target: values.Get("target")}
	if q.Filters.Source != "" && q.Filters.Source != "resource" && q.Filters.Source != "identity" {
		return q, ErrInput
	}
	for _, s := range []string{q.Filters.Action, q.Filters.Actor, q.Filters.Target} {
		if s != "" && !auditExactValue.MatchString(s) {
			return q, ErrInput
		}
	}
	for _, item := range []struct {
		key   string
		value *string
	}{{"from", &q.Filters.From}, {"until", &q.Filters.Until}} {
		if v := values.Get(item.key); v != "" {
			t, e := parseAuditTime(v)
			if e != nil {
				return q, ErrInput
			}
			*item.value = t.Format(time.RFC3339Nano)
		}
	}
	if q.Filters.From != "" && q.Filters.Until != "" {
		from, _ := parseAuditTime(q.Filters.From)
		until, _ := parseAuditTime(q.Filters.Until)
		if !from.Before(until) {
			return q, ErrInput
		}
	}
	if cursor := values.Get("cursor"); cursor != "" {
		v := auditPageCursor{}
		if strings.HasPrefix(cursor, auditCursorPrefix) {
			encoded := strings.TrimPrefix(cursor, auditCursorPrefix)
			b, e := base64.RawURLEncoding.Strict().DecodeString(encoded)
			if e != nil || base64.RawURLEncoding.EncodeToString(b) != encoded || !strict(b, &v) || v.Filters != q.Filters.digest() {
				return q, ErrInput
			}
		} else {
			// Legacy unfiltered timestamp~source~id cursors remain readable only
			// for an unfiltered request; never widen or discard new predicates.
			parts := strings.Split(cursor, "~")
			if q.Filters != (auditFilters{}) || len(parts) != 3 {
				return q, ErrInput
			}
			v.At, v.Source = parts[0], parts[1]
			v.ID, e = strconv.ParseInt(parts[2], 10, 64)
			if e != nil || strconv.FormatInt(v.ID, 10) != parts[2] {
				return q, ErrInput
			}
			v.Filters = q.Filters.digest()
		}
		at, e := parseAuditTime(v.At)
		if e != nil || v.ID < 1 || (v.Source != "resource" && v.Source != "identity") || (q.Filters.Source != "" && q.Filters.Source != v.Source) {
			return q, ErrInput
		}
		v.At = at.Format(time.RFC3339Nano)
		q.Cursor = &v
	}
	return q, nil
}

func (q auditQuery) next(v ConsoleAudit) string {
	b, _ := json.Marshal(auditPageCursor{At: v.CreatedAt.UTC().Format(time.RFC3339Nano), Source: v.Source, ID: v.ID, Filters: q.Filters.digest()})
	return auditCursorPrefix + base64.RawURLEncoding.EncodeToString(b)
}

func (q auditQuery) sql() (string, []any) {
	branches := []string{}
	args := []any{}
	for _, source := range []string{"resource", "identity"} {
		if q.Filters.Source != "" && q.Filters.Source != source {
			continue
		}
		table := "controller_audit"
		if source == "identity" {
			table = "controller_identity_audit"
		}
		where := []string{"1=1"}
		for _, item := range []struct{ column, value string }{{"action", q.Filters.Action}, {"actor", q.Filters.Actor}, {"target", q.Filters.Target}} {
			if item.value != "" {
				// The first predicate is index-sargable even under a case-insensitive
				// database default; the second enforces exact bytes in either table.
				where = append(where, item.column+"=? AND BINARY "+item.column+"=BINARY ?")
				args = append(args, item.value, item.value)
			}
		}
		for _, item := range []struct{ op, value string }{{">=", q.Filters.From}, {"<", q.Filters.Until}} {
			if item.value != "" {
				at, _ := parseAuditTime(item.value)
				where = append(where, "created_at"+item.op+"?")
				args = append(args, at)
			}
		}
		if q.Cursor != nil {
			at, _ := parseAuditTime(q.Cursor.At)
			switch {
			case source == q.Cursor.Source:
				where = append(where, "(created_at<? OR (created_at=? AND id<?))")
				args = append(args, at, at, q.Cursor.ID)
			case source < q.Cursor.Source:
				where = append(where, "created_at<=?")
				args = append(args, at)
			default:
				where = append(where, "created_at<?")
				args = append(args, at)
			}
		}
		branches = append(branches, "SELECT id,'"+source+"' AS source,actor,action,target,created_at FROM "+table+" WHERE "+strings.Join(where, " AND ")+" ORDER BY created_at DESC,id DESC LIMIT 101")
	}
	if len(branches) == 1 {
		return branches[0], args
	}
	// At most 101 rows per source enter the global merge, never the whole audit
	// history. Within each source its constant name does not alter keyset order.
	return "SELECT id,source,actor,action,target,created_at FROM ((" + strings.Join(branches, ") UNION ALL (") + ")) events ORDER BY created_at DESC,source DESC,id DESC LIMIT 101", args
}

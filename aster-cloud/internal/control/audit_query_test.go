package control

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAuditQueryStrictExactFiltersAndCanonicalUTC(t *testing.T) {
	q, e := parseAuditQuery(url.Values{"source": {"resource"}, "action": {"Node.Heartbeat"}, "actor": {"user:AbC"}, "target": {"node-A"}, "from": {"2026-10-23T09:00:00.123400+08:00"}, "until": {"2026-10-23T01:00:00.123401Z"}}.Encode())
	if e != nil || q.Filters != (auditFilters{Source: "resource", Action: "Node.Heartbeat", Actor: "user:AbC", Target: "node-A", From: "2026-10-23T01:00:00.1234Z", Until: "2026-10-23T01:00:00.123401Z"}) {
		t.Fatal("exact filters/UTC precision changed", e)
	}
	if edge, e := parseAuditQuery(url.Values{"from": {"0999-12-31T23:59:59-00:01"}}.Encode()); e != nil || edge.Filters.From != "1000-01-01T00:00:59Z" {
		t.Fatal("time bounds were checked before UTC normalization", e)
	}
	for _, raw := range []string{
		"source=RESOURCE", "source=", "action=", "actor=", "target=", "from=", "until=", "cursor=", "limit=100", "owner_ref=a", "instance_id=a", "Action=a",
		"action=a&action=b", "source=identity&source=identity", "actor=a&actor=a", "from=a&from=b", "cursor=a&cursor=a", "cursor=a&until=x&until=y",
		"action=%00", "actor=%0A", "target=%20a", "target=a%20", "action=a%25", "target=%27OR1%3D1", "actor=%E4%B8%AD", "action=a+b", "actor=%FF", "action=%", "action=a;target=b",
		"action=" + strings.Repeat("a", 65), "actor=" + strings.Repeat("a", 81), "target=" + strings.Repeat("a", 129), "cursor=" + strings.Repeat("a", 1025), strings.Repeat("a", 4097),
	} {
		t.Run(raw[:min(70, len(raw))], func(t *testing.T) {
			if _, e := parseAuditQuery(raw); e == nil {
				t.Fatal("invalid/ambiguous query accepted")
			}
		})
	}
	for _, raw := range []string{"0999-12-31T23:59:59Z", "1000-01-01T00:00:00+00:01", "9999-12-31T23:59:59-00:01", "2026-10-23T01:02:03.1234567Z", "2026-10-23T01:02:03", "2026-10-23t01:02:03Z", "2026-10-23T01:02:03z", "2026-10-23T01:02:03+24:00", "2026-10-23T01:02:03+00:60", "2026-02-30T01:02:03Z", "2026-10-23T24:02:03Z", "2026-10-23T01:02:60Z", "2026-10-23T01:02:03,1Z"} {
		t.Run(raw, func(t *testing.T) {
			if _, e := parseAuditQuery(url.Values{"from": {raw}}.Encode()); e == nil {
				t.Fatal("invalid time/precision accepted")
			}
		})
	}
	for _, until := range []string{"2026-10-23T01:00:00Z", "2026-10-23T00:59:59Z"} {
		if _, e = parseAuditQuery(url.Values{"from": {"2026-10-23T01:00:00Z"}, "until": {until}}.Encode()); e == nil {
			t.Fatal("empty/reversed time interval accepted")
		}
	}
	for k, n := range map[string]int{"action": 64, "actor": 80, "target": 128} {
		if _, e = parseAuditQuery(url.Values{k: {strings.Repeat("A", n)}}.Encode()); e != nil {
			t.Fatal("legal exact length rejected", k)
		}
	}
}

func TestAuditCursorBindsNormalizedFiltersAndRetainsUnfilteredLegacy(t *testing.T) {
	q, e := parseAuditQuery(url.Values{"action": {"node.heartbeat"}, "from": {"2026-10-23T09:00:00.100000+08:00"}}.Encode())
	if e != nil {
		t.Fatal(e)
	}
	at := time.Date(2026, 10, 23, 2, 0, 0, 123000, time.UTC)
	cursor := q.next(ConsoleAudit{ID: 99, Source: "identity", CreatedAt: at})
	params := url.Values{"action": {"node.heartbeat"}, "from": {"2026-10-23T01:00:00.1Z"}, "cursor": {cursor}}
	parsed, e := parseAuditQuery(params.Encode())
	if e != nil || parsed.Cursor == nil || parsed.Cursor.ID != 99 || parsed.Cursor.At != "2026-10-23T02:00:00.000123Z" || parsed.Filters != q.Filters {
		t.Fatal("equivalent query cursor did not roundtrip", e)
	}
	for k, v := range map[string]string{"action": "Node.Heartbeat", "actor": "someone", "target": "node-x", "from": "2026-10-23T01:00:00.100001Z", "until": "2026-10-23T23:00:00Z", "source": "identity"} {
		changed, _ := url.ParseQuery(params.Encode())
		changed.Set(k, v)
		if _, e = parseAuditQuery(changed.Encode()); e == nil {
			t.Fatal("changed query accepted old cursor", k)
		}
	}
	legacy := "2026-10-23T02:00:00.000123Z~resource~99"
	if v, e := parseAuditQuery(url.Values{"cursor": {legacy}}.Encode()); e != nil || v.Cursor == nil || v.Cursor.ID != 99 {
		t.Fatal("unfiltered old cursor compatibility lost", e)
	}
	if _, e = parseAuditQuery(url.Values{"action": {"node.heartbeat"}, "cursor": {legacy}}.Encode()); e == nil {
		t.Fatal("legacy cursor widened a filtered request")
	}
	if _, e = parseAuditQuery(url.Values{"cursor": {cursor}}.Encode()); e == nil {
		t.Fatal("dropping filter accepted old cursor")
	}
	for _, value := range []string{"invalid", legacy + "~extra", strings.Replace(legacy, "~99", "~0", 1), strings.Replace(legacy, "~99", "~099", 1), strings.Replace(legacy, "~99", "~9223372036854775808", 1), strings.Replace(legacy, "resource", "other", 1), cursor + "=", cursor + "!", "a1.e30", "a1.____"} {
		if _, e = parseAuditQuery(url.Values{"cursor": {value}}.Encode()); e == nil {
			t.Fatal("malformed cursor accepted")
		}
	}
	// Exact shape, duplicate keys, time/id bounds and a source contradiction are
	// rejected even if the public (non-secret) filter fingerprint is correct.
	for _, raw := range []string{
		`{"at":"2026-10-23T02:00:00Z","source":"identity","id":1,"filters_sha256":"` + q.Filters.digest() + `","extra":1}`,
		`{"at":"2026-10-23T02:00:00Z","source":"identity","id":1,"id":2,"filters_sha256":"` + q.Filters.digest() + `"}`,
		`{"at":"2026-10-23T02:00:00Z","source":"identity","id":null,"filters_sha256":"` + q.Filters.digest() + `"}`,
	} {
		p, _ := url.ParseQuery(params.Encode())
		p.Set("cursor", auditCursorPrefix+base64.RawURLEncoding.EncodeToString([]byte(raw)))
		if _, e = parseAuditQuery(p.Encode()); e == nil {
			t.Fatal("invalid cursor JSON accepted")
		}
	}
	for _, change := range []func(*auditPageCursor){
		func(v *auditPageCursor) { v.ID = 0 },
		func(v *auditPageCursor) { v.ID = -1 },
		func(v *auditPageCursor) { v.Source = "other" },
		func(v *auditPageCursor) { v.At = "0999-01-01T00:00:00Z" },
		func(v *auditPageCursor) { v.Filters = strings.Repeat("0", 64) },
	} {
		v := *parsed.Cursor
		change(&v)
		b, _ := json.Marshal(v)
		p, _ := url.ParseQuery(params.Encode())
		p.Set("cursor", auditCursorPrefix+base64.RawURLEncoding.EncodeToString(b))
		if _, e = parseAuditQuery(p.Encode()); e == nil {
			t.Fatal("invalid cursor tuple accepted")
		}
	}
}

func TestAuditSQLIsReadOnlyParameterizedAndMergeBounded(t *testing.T) {
	q, _ := parseAuditQuery(url.Values{"action": {"node.heartbeat"}, "actor": {"user:ABC"}, "target": {"node-a"}, "from": {"2026-10-23T00:00:00Z"}, "until": {"2026-10-24T00:00:00Z"}}.Encode())
	query, args := q.sql()
	if strings.Count(query, "LIMIT 101") != 3 || strings.Count(query, "actor=? AND BINARY actor=BINARY ?") != 2 || strings.Count(query, "created_at>=?") != 2 || !strings.HasSuffix(query, "ORDER BY created_at DESC,source DESC,id DESC LIMIT 101") || len(args) != 16 {
		t.Fatal("predicates/limits not pushed into each source")
	}
	for _, literal := range []string{"node.heartbeat", "user:ABC", "node-a", "2026-10-23", "INSERT", "UPDATE", "DELETE", "FOR UPDATE"} {
		if strings.Contains(query, literal) {
			t.Fatal("query interpolated input or mutates state")
		}
	}
	for _, source := range []string{"resource", "identity"} {
		q.Filters.Source = source
		query, _ := q.sql()
		if strings.Contains(query, "UNION") || strings.Count(query, "LIMIT 101") != 1 {
			t.Fatal("source selection did not eliminate unrelated branch")
		}
	}
	q.Filters.Source = ""
	for _, source := range []string{"identity", "resource"} {
		q.Cursor = &auditPageCursor{At: "2026-10-23T12:00:00Z", Source: source, ID: 10}
		query, _ := q.sql()
		if strings.Count(query, "(created_at<? OR (created_at=? AND id<?))") != 1 {
			t.Fatal("same-source keyset tuple not pushed down")
		}
	}
	// Literal quotes supplied by an internal caller still remain parameters.
	q.Filters.Actor = "'OR 1=1--"
	query, args = q.sql()
	if strings.Contains(query, q.Filters.Actor) {
		t.Fatal("SQL interpolation")
	}
	if _, e := json.Marshal(args); e != nil {
		t.Fatal(e)
	}
}

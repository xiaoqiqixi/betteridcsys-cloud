package control

import (
	"aster/cloud/internal/identity"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func auditDataDigest(t *testing.T, s *SQLStore, tables map[string]string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for table, order := range tables {
		// Only fixed test-owned table/column constants reach this helper.
		rows, e := s.DB.Query("SELECT * FROM " + table + " ORDER BY " + order)
		if e != nil {
			t.Fatal("cannot inspect private test table", table)
		}
		columns, e := rows.Columns()
		if e != nil {
			rows.Close()
			t.Fatal(e)
		}
		h := sha256.New()
		encoder := json.NewEncoder(h)
		encoder.Encode(columns)
		for rows.Next() {
			values := make([]any, len(columns))
			pointers := make([]any, len(columns))
			for i := range values {
				pointers[i] = &values[i]
			}
			if e = rows.Scan(pointers...); e != nil {
				rows.Close()
				t.Fatal(e)
			}
			if e = encoder.Encode(values); e != nil {
				rows.Close()
				t.Fatal(e)
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			t.Fatal(e)
		}
		out[table] = hex.EncodeToString(h.Sum(nil))
	}
	return out
}

func auditExpectedRows(t *testing.T, s *SQLStore) []ConsoleAudit {
	t.Helper()
	out := []ConsoleAudit{}
	for table, source := range map[string]string{"controller_audit": "resource", "controller_identity_audit": "identity"} {
		rows, e := s.DB.Query("SELECT id,actor,action,target,created_at FROM " + table)
		if e != nil {
			t.Fatal(e)
		}
		for rows.Next() {
			v := ConsoleAudit{Source: source}
			if e = rows.Scan(&v.ID, &v.Actor, &v.Action, &v.Target, &v.CreatedAt); e != nil {
				rows.Close()
				t.Fatal(e)
			}
			out = append(out, v)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			t.Fatal(e)
		}
	}
	// Expected optional identity details come directly from the persisted test
	// operation facts, independently of the production page enrichment helper.
	proofRows, e := s.DB.Query("SELECT audit_id,operation_id,base_revision,result_revision,reason FROM controller_identity_operations")
	if e != nil {
		t.Fatal(e)
	}
	proofs := map[int64]IdentityAuditDetail{}
	for proofRows.Next() {
		var id int64
		var p IdentityAuditDetail
		if e = proofRows.Scan(&id, &p.OperationID, &p.BaseRevision, &p.ResultRevision, &p.Reason); e != nil {
			proofRows.Close()
			t.Fatal(e)
		}
		proofs[id] = p
	}
	e = proofRows.Err()
	proofRows.Close()
	if e != nil {
		t.Fatal(e)
	}
	for i := range out {
		if p, ok := proofs[out[i].ID]; ok && out[i].Source == "identity" {
			copy := p
			out[i].IdentityDetail = &copy
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		if out[i].Source != out[j].Source {
			return out[i].Source > out[j].Source
		}
		return out[i].ID > out[j].ID
	})
	return out
}

func TestMySQLAuditQueryRealTLSExactFiltersAndReadOnly(t *testing.T) {
	s := consoleHTTPStore(t) // Creates/drops a random independent _test database.
	ctx := context.Background()
	server := httptest.NewUnstartedServer(nil)
	origin := "https://" + server.Listener.Addr().String()
	auth, e := identity.New(s.DB, identity.Config{Origin: origin})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = auth.Bootstrap(ctx, "audit-admin@example.invalid", "Audit fixture administrator", []byte(consoleHTTPPassword)); e != nil {
		t.Fatal("private bootstrap failed", e)
	}
	var rpcCalls atomic.Int32
	worker := &OperationWorker{Store: s, RPC: func(context.Context, NodeProfile) (NodeRPC, error) {
		rpcCalls.Add(1)
		return nil, ErrUnavailable
	}, StorageRPC: func(context.Context, NodeProfile) (StorageRPC, error) {
		rpcCalls.Add(1)
		return nil, ErrUnavailable
	}}
	server.Config.Handler = (Console{Store: s, Identity: auth, Worker: worker}).Handler()
	server.StartTLS()
	t.Cleanup(server.Close)
	admin := newConsoleHTTPBrowser(t, server)
	admin.login(t, "audit-admin@example.invalid")
	admin.createUser(t, "audit-viewer@example.invalid", "viewer", nil)
	admin.createUser(t, "audit-operator@example.invalid", "operator", nil)
	viewer, operator := newConsoleHTTPBrowser(t, server), newConsoleHTTPBrowser(t, server)
	viewer.login(t, "audit-viewer@example.invalid")
	operator.login(t, "audit-operator@example.invalid")

	// Deliberately exercise a case-insensitive *resource* table default. Identity
	// uses ascii_bin; both branches must still implement the same exact contract.
	for _, column := range []struct {
		name string
		size int
	}{{"actor", 80}, {"action", 64}, {"target", 128}} {
		if _, e = s.DB.Exec(fmt.Sprintf("ALTER TABLE controller_audit MODIFY %s VARCHAR(%d) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL", column.name, column.size)); e != nil {
			t.Fatal("cannot prepare independent collation fixture", e)
		}
	}
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, table := range []string{"controller_audit", "controller_identity_audit"} {
		for i := range 240 {
			action := "node.heartbeat"
			if table == "controller_identity_audit" {
				action = "identity.login"
			}
			actor, target := "user:"+strings.Repeat("a", 32), "node-a"
			if i%2 != 0 {
				actor, action = strings.ToUpper(actor), strings.ToUpper(action)
			}
			if i%3 != 0 {
				target = "NODE-A"
			}
			at := base.Add(time.Duration(i%3) * time.Microsecond)
			if _, e = s.DB.Exec("INSERT INTO "+table+"(actor,action,target,created_at) VALUES(?,?,?,?)", actor, action, target, at); e != nil {
				t.Fatal(e)
			}
		}
		for _, at := range []time.Time{base.Add(-time.Microsecond), base.Add(3 * time.Microsecond)} {
			if _, e = s.DB.Exec("INSERT INTO "+table+"(actor,action,target,created_at) VALUES(?,?,?,?)", "edge-actor", "edge.action", "edge-target", at); e != nil {
				t.Fatal(e)
			}
		}
		if _, e = s.DB.Exec("INSERT INTO "+table+"(actor,action,target,created_at) VALUES(?,?,?,?)", "RareActor", "rare.action", "rare-target", base); e != nil {
			t.Fatal(e)
		}
	}

	t.Run("optimizer_uses_exact_filter_indexes_despite_binary_guard", func(t *testing.T) {
		for _, table := range []string{"controller_audit", "controller_identity_audit"} {
			if _, e := s.DB.Exec("ANALYZE TABLE " + table); e != nil {
				t.Fatal(e)
			}
		}
		var hasKey func(any, string) bool
		hasKey = func(v any, wanted string) bool {
			switch x := v.(type) {
			case map[string]any:
				if x["key"] == wanted {
					return true
				}
				for _, child := range x {
					if hasKey(child, wanted) {
						return true
					}
				}
			case []any:
				for _, child := range x {
					if hasKey(child, wanted) {
						return true
					}
				}
			}
			return false
		}
		for _, index := range auditQueryIndexes {
			source := "resource"
			if index.Table == "controller_identity_audit" {
				source = "identity"
			}
			value := map[string]string{"actor": "RareActor", "action": "rare.action", "target": "rare-target"}[index.Field]
			q, e := parseAuditQuery(url.Values{"source": {source}, index.Field: {value}}.Encode())
			if e != nil {
				t.Fatal(e)
			}
			query, args := q.sql()
			var raw string
			if e = s.DB.QueryRow("EXPLAIN FORMAT=JSON "+query, args...).Scan(&raw); e != nil {
				t.Fatal("real optimizer explain failed", e)
			}
			var plan any
			if json.Unmarshal([]byte(raw), &plan) != nil || !hasKey(plan, index.Name) {
				t.Fatal("exact filter failed to use its selective index", index.Name)
			}
			t.Log("real MySQL EXPLAIN selected", index.Name)
		}
	})

	all := auditExpectedRows(t, s)
	tables := map[string]string{"controller_schema": "version", "controller_lock": "id", "controller_identity_lock": "id", "controller_nodes": "id", "controller_instances": "id", "controller_jobs": "operation_id", "controller_reservations": "operation_id", "controller_operations": "id", "controller_artifacts": "id", "controller_migrations": "id", "controller_audit": "id", "controller_identity_audit": "id", "controller_console_users": "id", "controller_console_sessions": "token_hash", "controller_console_login_limits": "bucket"}
	before := auditDataDigest(t, s, tables)
	requestPage := func(b *consoleHTTPBrowser, params url.Values) ([]ConsoleAudit, *string) {
		t.Helper()
		path := "/console/v1/audit"
		if len(params) > 0 {
			path += "?" + params.Encode()
		}
		status, raw := b.request(t, "GET", path, "", consoleHTTPOptions{})
		var page struct {
			Items []ConsoleAudit `json:"items"`
			Next  *string        `json:"next_cursor"`
		}
		if status != 200 || json.Unmarshal(raw, &page) != nil || page.Items == nil || len(page.Items) > 100 {
			t.Fatal("audit page contract", status)
		}
		for _, private := range []string{"password", "token_hash", "request_json", "fence_token", "node_profile", "dsn_file"} {
			if strings.Contains(string(raw), private) {
				t.Fatal("audit response leaks a private field")
			}
		}
		return page.Items, page.Next
	}
	cases := []struct {
		name   string
		params url.Values
		match  func(ConsoleAudit) bool
	}{
		{"all_sources_tied_times_over_100", url.Values{}, func(ConsoleAudit) bool { return true }},
		{"source", url.Values{"source": {"identity"}}, func(v ConsoleAudit) bool { return v.Source == "identity" }},
		{"action_exact_case", url.Values{"action": {"node.heartbeat"}}, func(v ConsoleAudit) bool { return v.Action == "node.heartbeat" }},
		{"actor_exact_case", url.Values{"actor": {"user:" + strings.Repeat("a", 32)}}, func(v ConsoleAudit) bool { return v.Actor == "user:"+strings.Repeat("a", 32) }},
		{"target_exact_case", url.Values{"target": {"node-a"}}, func(v ConsoleAudit) bool { return v.Target == "node-a" }},
		{"from_inclusive_until_exclusive", url.Values{"from": {base.Format(time.RFC3339Nano)}, "until": {base.Add(2 * time.Microsecond).Format(time.RFC3339Nano)}}, func(v ConsoleAudit) bool {
			return !v.CreatedAt.Before(base) && v.CreatedAt.Before(base.Add(2*time.Microsecond))
		}},
		{"all_AND", url.Values{"source": {"resource"}, "action": {"node.heartbeat"}, "actor": {"user:" + strings.Repeat("a", 32)}, "target": {"node-a"}, "from": {base.Format(time.RFC3339Nano)}, "until": {base.Add(time.Microsecond).Format(time.RFC3339Nano)}}, func(v ConsoleAudit) bool {
			return v.Source == "resource" && v.Action == "node.heartbeat" && v.Actor == "user:"+strings.Repeat("a", 32) && v.Target == "node-a" && !v.CreatedAt.Before(base) && v.CreatedAt.Before(base.Add(time.Microsecond))
		}},
		{"unmatched_is_real_empty", url.Values{"action": {"not.a.real.action"}}, func(ConsoleAudit) bool { return false }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wanted := []ConsoleAudit{}
			for _, v := range all {
				if tc.match(v) {
					wanted = append(wanted, v)
				}
			}
			params, _ := url.ParseQuery(tc.params.Encode())
			got := []ConsoleAudit{}
			seen := map[string]bool{}
			for page := 0; ; page++ {
				if page > 20 {
					t.Fatal("audit cursor did not terminate")
				}
				items, next := requestPage(admin, params)
				for _, v := range items {
					key := fmt.Sprintf("%s:%d", v.Source, v.ID)
					if seen[key] {
						t.Fatal("audit pagination duplicated a source/id")
					}
					seen[key] = true
					got = append(got, v)
				}
				if next == nil {
					break
				}
				params.Set("cursor", *next)
			}
			if !reflect.DeepEqual(got, wanted) {
				t.Fatal("exact filtering or stable cross-source keyset lost rows", len(got), len(wanted))
			}
		})
	}
	t.Run("real_TLS_live_permissions_invalid_input_and_bound_cursor", func(t *testing.T) {
		for _, tc := range []struct {
			browser *consoleHTTPBrowser
			status  int
		}{{newConsoleHTTPBrowser(t, server), 401}, {viewer, 403}} {
			status, _ := tc.browser.request(t, "GET", "/console/v1/audit?action=node.heartbeat", "", consoleHTTPOptions{})
			if status != tc.status {
				t.Fatal("audit authorization bypass", status)
			}
		}
		requestPage(operator, url.Values{"action": {"node.heartbeat"}})
		for _, raw := range []string{"action=a&action=a", "actor=%27%20OR%201%3D1", "action=", "source=other", "limit=101", "from=2026-01-01", "cursor=bad", "target=" + strings.Repeat("x", 129)} {
			status, body := admin.request(t, "GET", "/console/v1/audit?"+raw, "", consoleHTTPOptions{})
			if status != 400 || consoleHTTPError(t, body) != "INVALID_QUERY" {
				t.Fatal("unsafe/ambiguous filter not rejected", status)
			}
		}
		_, cursor := requestPage(admin, url.Values{"actor": {"user:" + strings.Repeat("a", 32)}})
		if cursor == nil {
			t.Fatal("fixture did not cover filtered pagination")
		}
		status, raw := admin.request(t, "GET", "/console/v1/audit?"+url.Values{"action": {"node.heartbeat"}, "cursor": {*cursor}}.Encode(), "", consoleHTTPOptions{})
		if status != 400 || consoleHTTPError(t, raw) != "INVALID_QUERY" {
			t.Fatal("changed predicate reused a cursor")
		}
		items, next := requestPage(admin, url.Values{})
		if next == nil || len(items) != 100 {
			t.Fatal("legacy fixture page missing")
		}
		last := items[99]
		legacy := last.CreatedAt.Format(time.RFC3339Nano) + "~" + last.Source + "~" + fmt.Sprint(last.ID)
		oldItems, _ := requestPage(admin, url.Values{"cursor": {legacy}})
		newItems, _ := requestPage(admin, url.Values{"cursor": {*next}})
		if !reflect.DeepEqual(oldItems, newItems) {
			t.Fatal("unfiltered legacy cursor changed next page")
		}
	})
	if after := auditDataDigest(t, s, tables); !reflect.DeepEqual(before, after) || rpcCalls.Load() != 0 {
		t.Fatal("read-only audit changed persistent data or invoked node RPC")
	}
}

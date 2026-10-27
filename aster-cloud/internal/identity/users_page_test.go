package identity

import (
	"database/sql"
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUsersCursorHTTPReadOnlyContract(t *testing.T) {
	db, err := sql.Open("mysql", "unused:unused@unix(/nonexistent)/aster_cloud_test")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s, err := New(db, Config{Origin: "https://console.example.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	cursor := "u1." + base64.RawURLEncoding.EncodeToString([]byte(`{"at":"2026-10-25T00:00:00.123456Z","id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`))
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{"GET", "/users?cursor=" + cursor, 401},
		{"GET", "/users?cursor=", 400},
		{"GET", "/users?cursor=x", 400},
		{"GET", "/users?cursor=" + cursor + "&cursor=" + cursor, 400},
		{"GET", "/users?cursor=" + cursor + "&limit=1", 400},
		{"GET", "/users?limit=1", 400},
		{"GET", "/users?%zz=x", 400},
		{"GET", "/users?cursor=" + strings.Repeat("a", 513), 400},
		{"GET", "/users?", 400},
		{"POST", "/users?cursor=" + cursor, 400},
		{"PATCH", "/users/" + strings.Repeat("a", 32) + "?cursor=" + cursor, 400},
		{"GET", "/roles?cursor=" + cursor, 400},
		{"GET", "/auth/me?cursor=" + cursor, 400},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, s.origin+"/console/v1"+tc.path, nil)
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tc.want, w.Body.String())
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("identity response cacheable")
			}
		})
	}
}

func TestUsersCursorCanonicalPosition(t *testing.T) {
	valid := `{"at":"2026-10-25T00:00:00.123456Z","id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
	enc := func(raw string) string { return "u1." + base64.RawURLEncoding.EncodeToString([]byte(raw)) }
	for _, raw := range []string{
		strings.Replace(valid, "2026-10-25", "2026-02-30", 1),
		strings.Replace(valid, "2026-10-25", "0999-12-31", 1),
		strings.Replace(valid, ".123456Z", "Z", 1),
		strings.Replace(valid, ".123456Z", ".1234567Z", 1),
		strings.Replace(valid, "Z", "+00:00", 1),
		strings.Replace(valid, "aaaa", "AAAA", 1),
		strings.Replace(valid, `"at":`, `"At":`, 1),
		strings.Replace(valid, `"id":`, `"id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","id":`, 1),
		strings.Replace(valid, `"id":`, `"extra":true,"id":`, 1),
		strings.Replace(valid, `"at":"2026-10-25T00:00:00.123456Z"`, `"at":null`, 1),
		valid + " ", " " + valid, "null", "[]", valid + valid,
	} {
		if _, err := decodeUsersCursor(enc(raw)); err == nil {
			t.Fatalf("invalid cursor accepted: %q", raw)
		}
	}
	for _, raw := range []string{enc(valid) + "=", enc(valid) + "\n", strings.Replace(enc(valid), "u1.", "u2.", 1), "u1.", "u1." + strings.Repeat("a", 513)} {
		if _, err := decodeUsersCursor(raw); err == nil {
			t.Fatal("invalid encoding accepted")
		}
	}
	p, err := decodeUsersCursor(enc(valid))
	if err != nil || p.ID != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" || p.At != "2026-10-25T00:00:00.123456Z" {
		t.Fatal("canonical cursor rejected", err)
	}
}

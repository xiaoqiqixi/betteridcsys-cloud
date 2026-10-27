package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"
)

func usersRequest(t *testing.T, s *Service, token, cursor string, want int) usersPage {
	t.Helper()
	path := s.origin + "/console/v1/users"
	if cursor != "" {
		path += "?cursor=" + url.QueryEscape(cursor)
	}
	r := httptest.NewRequest("GET", path, nil)
	r.AddCookie(&http.Cookie{Name: CookieName, Value: token})
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want {
		t.Fatalf("users status=%d want=%d body=%s", w.Code, want, w.Body.String())
	}
	var page usersPage
	if want == 200 {
		if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
	}
	return page
}

// Log in through the real production HTTP handler and CSRF/cookie exchange;
// this must not manufacture a DB session merely to exercise the page query.
func loginUsersPageHTTP(t *testing.T, s *Service, user User) string {
	t.Helper()
	request := httptest.NewRequest("GET", s.origin+"/console/v1/auth/csrf", nil)
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, request)
	var csrf struct {
		Token string `json:"csrf_token"`
	}
	cookies := response.Result().Cookies()
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &csrf) != nil || csrf.Token == "" || len(cookies) != 1 {
		t.Fatal("HTTP anonymous CSRF exchange failed")
	}
	body, err := json.Marshal(map[string]string{"email": user.Email, "password": testPassword})
	if err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest("POST", s.origin+"/console/v1/auth/login", bytes.NewReader(body))
	request.Header.Set("Origin", s.origin)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrf.Token)
	request.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	s.Handler().ServeHTTP(response, request)
	var logged struct {
		User User `json:"user"`
	}
	cookies = response.Result().Cookies()
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &logged) != nil || logged.User.ID != user.ID || len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly {
		t.Fatal("HTTP authenticated session exchange failed")
	}
	return cookies[0].Value
}

func TestMySQLUsersPagination(t *testing.T) {
	for _, count := range []int{0, 1, 99, 100, 101, 205} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			s, db := mysqlIdentity(t)
			if count == 0 {
				page, err := s.listUsers(context.Background(), nil)
				if err != nil || page.Items == nil || len(page.Items) != 0 || page.NextCursor != nil || page.TruncatedPossible || page.Limit != 100 {
					t.Fatal("empty store contract", err, page)
				}
				return
			}
			admin := bootstrap(t, s)
			token := loginUsersPageHTTP(t, s, admin)
			at := time.Date(2026, 10, 25, 0, 0, 0, 123456000, time.UTC)
			if _, err := db.Exec("UPDATE controller_console_users SET created_at=? WHERE id=?", at, admin.ID); err != nil {
				t.Fatal(err)
			}
			tx, err := db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			for i := 1; i < count; i++ {
				// Deliberately many equal microsecond timestamps. Reuse the non-verifiable
				// dummy hash for list-only members; no password hashing or login bypass.
				if _, err := insertUser(context.Background(), tx, fmt.Sprintf("member-%03d@example.invalid", i), fmt.Sprintf("Member %03d", i), dummyPasswordHash, "viewer", nil, at.Add(time.Duration(i/37)*time.Microsecond)); err != nil {
					t.Fatal(err)
				}
			}
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
			rows, err := db.Query("SELECT id FROM controller_console_users ORDER BY created_at,id")
			if err != nil {
				t.Fatal(err)
			}
			want := []string{}
			for rows.Next() {
				var id string
				if err = rows.Scan(&id); err != nil {
					t.Fatal(err)
				}
				want = append(want, id)
			}
			if err = rows.Err(); err != nil {
				t.Fatal(err)
			}
			rows.Close()
			got := []string{}
			cursor := ""
			firstCursor := ""
			for pageNumber := 0; pageNumber < 4; pageNumber++ {
				page := usersRequest(t, s, token, cursor, 200)
				expected := min(100, count-len(got))
				if len(page.Items) != expected || page.Limit != 100 || page.TruncatedPossible != (len(got)+expected < count) || (page.NextCursor != nil) != page.TruncatedPossible {
					t.Fatalf("page contract %#v", page)
				}
				for _, u := range page.Items {
					got = append(got, u.ID)
				}
				if page.NextCursor == nil {
					break
				}
				if *page.NextCursor == cursor {
					t.Fatal("cursor loop")
				}
				cursor = *page.NextCursor
				if firstCursor == "" {
					firstCursor = cursor
				}
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatal("pagination skipped, duplicated or reordered users")
			}
			if count == 205 {
				var seekAt time.Time
				if err := db.QueryRow("SELECT created_at FROM controller_console_users WHERE id=?", want[190]).Scan(&seekAt); err != nil {
					t.Fatal(err)
				}
				var rawPlan []byte
				if err := db.QueryRow("EXPLAIN FORMAT=JSON SELECT "+userColumns+",created_at FROM controller_console_users WHERE (created_at>? OR (created_at=? AND id>?)) ORDER BY created_at ASC,id ASC LIMIT 101", seekAt, seekAt, want[190]).Scan(&rawPlan); err != nil {
					t.Fatal(err)
				}
				var plan any
				if err := json.Unmarshal(rawPlan, &plan); err != nil {
					t.Fatal(err)
				}
				var usesSeekIndex func(any) bool
				usesSeekIndex = func(value any) bool {
					switch v := value.(type) {
					case map[string]any:
						if v["key"] == "controller_console_users_created_id" {
							return true
						}
						for _, child := range v {
							if usesSeekIndex(child) {
								return true
							}
						}
					case []any:
						for _, child := range v {
							if usesSeekIndex(child) {
								return true
							}
						}
					}
					return false
				}
				if !usesSeekIndex(plan) {
					t.Fatal("deep member seek query did not choose its pagination index")
				}
			}
			if firstCursor != "" {
				again := usersRequest(t, s, token, firstCursor, 200)
				if again.Items[0].ID != want[100] {
					t.Fatal("seek token unstable")
				}
				// A cursor supplies no authority: anonymous and current viewer are denied.
				usersRequest(t, s, "", firstCursor, 401)
				viewer := create(t, s, admin, "viewer-login@example.invalid", "viewer", nil)
				viewerToken := loginUsersPageHTTP(t, s, viewer)
				usersRequest(t, s, viewerToken, firstCursor, 403)
				manager := create(t, s, admin, "manager-login@example.invalid", "custom", []string{"users.manage"})
				managerToken := loginUsersPageHTTP(t, s, manager)
				usersRequest(t, s, managerToken, firstCursor, 200)
				// Next page must re-evaluate the real session after a role change.
				role := "viewer"
				if _, err := updateAs(t, s, admin.ID, manager.ID, UpdateUser{Role: &role}); err != nil {
					t.Fatal(err)
				}
				usersRequest(t, s, managerToken, firstCursor, 401)
			}
		})
	}
}

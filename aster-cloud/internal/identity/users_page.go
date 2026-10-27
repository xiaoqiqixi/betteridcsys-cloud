package identity

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"time"
)

const usersPageLimit = 100
const usersCursorTime = "2006-01-02T15:04:05.000000Z"

type usersPosition struct {
	At string `json:"at"`
	ID string `json:"id"`
}

type usersPage struct {
	Items      []User  `json:"items"`
	Limit      int     `json:"limit"`
	NextCursor *string `json:"next_cursor"`
	// Retained for existing consumers, now reflects actual extra rows.
	TruncatedPossible bool `json:"truncated_possible"`
}

// This cursor is an untrusted seek position, never an authorization credential.
// The caller must pass the existing current-session users.manage middleware.
func parseUsersQuery(u *url.URL) (*usersPosition, error) {
	if u.RawQuery == "" {
		if u.ForceQuery {
			return nil, ErrInput
		}
		return nil, nil
	}
	if len(u.RawQuery) > 600 || strings.Contains(u.RawQuery, "&") {
		return nil, ErrInput
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil || len(q) != 1 || len(q["cursor"]) != 1 {
		return nil, ErrInput
	}
	return decodeUsersCursor(q.Get("cursor"))
}
func decodeUsersCursor(raw string) (*usersPosition, error) {
	if len(raw) > 512 || !strings.HasPrefix(raw, "u1.") {
		return nil, ErrInput
	}
	encoded := strings.TrimPrefix(raw, "u1.")
	b, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(b) != encoded {
		return nil, ErrInput
	}
	var p usersPosition
	if json.Unmarshal(b, &p) != nil || !validID(p.ID) {
		return nil, ErrInput
	}
	at, err := time.Parse(usersCursorTime, p.At)
	if err != nil || at.Year() < 1000 || at.Year() > 9999 || at.Format(usersCursorTime) != p.At {
		return nil, ErrInput
	}
	canonical, _ := json.Marshal(p)
	// Exact canonical fields reject duplicates, unknown fields, aliases and nulls.
	if !bytes.Equal(b, canonical) {
		return nil, ErrInput
	}
	return &p, nil
}
func encodeUsersCursor(at time.Time, id string) string {
	b, _ := json.Marshal(usersPosition{At: at.UTC().Format(usersCursorTime), ID: id})
	return "u1." + base64.RawURLEncoding.EncodeToString(b)
}
func (s *Service) listUsers(ctx context.Context, position *usersPosition) (usersPage, error) {
	page := usersPage{Items: []User{}, Limit: usersPageLimit}
	query := "SELECT " + userColumns + ",created_at FROM controller_console_users"
	args := []any{}
	if position != nil {
		at, err := time.Parse(usersCursorTime, position.At)
		if err != nil || !validID(position.ID) {
			return usersPage{}, ErrInput
		}
		query += " WHERE (created_at>? OR (created_at=? AND id>?))"
		args = append(args, at, at, position.ID)
	}
	query += " ORDER BY created_at ASC,id ASC LIMIT 101"
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return usersPage{}, err
	}
	defer rows.Close()
	var lastAt time.Time
	for rows.Next() {
		var at time.Time
		u, err := scanUser(rows, &at)
		if err != nil {
			return usersPage{}, err
		}
		if len(page.Items) == usersPageLimit {
			next := encodeUsersCursor(lastAt, page.Items[len(page.Items)-1].ID)
			page.NextCursor = &next
			page.TruncatedPossible = true
		} else {
			page.Items = append(page.Items, u)
			lastAt = at
		}
	}
	if err = rows.Err(); err != nil {
		return usersPage{}, err
	}
	return page, nil
}

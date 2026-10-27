// Package identity provides persistent console sessions and server-enforced RBAC.
// It does not authenticate billing or node protocol requests.
package identity

import (
	"context"
	"database/sql"
	"errors"
	"net/mail"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	ErrInput          = errors.New("invalid identity input")
	ErrConflict       = errors.New("identity conflict")
	ErrForbidden      = errors.New("identity forbidden")
	ErrNotFound       = errors.New("identity not found")
	ErrAuthentication = errors.New("authentication required")
	ErrRateLimited    = errors.New("login rate limited")
	ErrRevision       = errors.New("identity revision conflict")
	ErrRevisionLimit  = errors.New("identity revision exhausted")
	ErrOperationUsed  = errors.New("identity operation already used")
	ErrStoredState    = errors.New("invalid stored identity state")
)

var allPermissions = []string{"audit.read", "instances.dangerous", "instances.manage", "instances.read", "migration.manage", "nodes.manage", "nodes.read", "settings.manage", "storage.manage", "storage.read", "storage.restore", "users.manage"}
var operatorPermissions = []string{"audit.read", "instances.manage", "instances.read", "nodes.read", "storage.manage", "storage.read"}
var viewerPermissions = []string{"instances.read", "nodes.read", "storage.read"}

type User struct {
	ID          string   `json:"id"`
	Email       string   `json:"email"`
	Name        string   `json:"name"`
	Role        string   `json:"role"`
	Enabled     bool     `json:"enabled"`
	Permissions []string `json:"permissions"`
	Revision    uint64   `json:"revision"`
}

func (u User) Can(permission string) bool {
	if !u.Enabled {
		return false
	}
	for _, p := range u.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}

type actorKey struct{}

func Actor(ctx context.Context) (User, bool) { u, ok := ctx.Value(actorKey{}).(User); return u, ok }

type Role struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
}

func Roles() []Role {
	return []Role{{"admin", "Administrator", append([]string{}, allPermissions...)}, {"operator", "Operator", append([]string{}, operatorPermissions...)}, {"viewer", "Viewer", append([]string{}, viewerPermissions...)}, {"custom", "Custom", []string{}}}
}

type Config struct {
	Origin     string
	SessionTTL time.Duration
	Now        func() time.Time
}
type Service struct {
	db     *sql.DB
	origin string
	host   string
	ttl    time.Duration
	nowFn  func() time.Time
}

func New(db *sql.DB, cfg Config) (*Service, error) {
	u, err := url.Parse(cfg.Origin)
	if db == nil || err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, ErrInput
	}
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = 8 * time.Hour
	}
	if cfg.SessionTTL < 5*time.Minute || cfg.SessionTTL > 24*time.Hour {
		return nil, ErrInput
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Service{db: db, origin: "https://" + u.Host, host: u.Host, ttl: cfg.SessionTTL, nowFn: cfg.Now}, nil
}
func (s *Service) now() time.Time { return s.nowFn().UTC().Truncate(time.Microsecond) }
func normalizeEmail(v string) (string, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	if len(v) > 254 || len(v) < 3 {
		return "", ErrInput
	}
	for _, c := range v {
		if c <= 32 || c >= 127 {
			return "", ErrInput
		}
	}
	a, err := mail.ParseAddress(v)
	if err != nil || a.Address != v || a.Name != "" {
		return "", ErrInput
	}
	return v, nil
}
func validName(v string) bool {
	return strings.TrimSpace(v) == v && utf8.ValidString(v) && utf8.RuneCountInString(v) >= 1 && utf8.RuneCountInString(v) <= 100 && !strings.ContainsAny(v, "\x00\r\n")
}
func permissions(role string, custom []string) ([]string, error) {
	var p []string
	switch role {
	case "admin":
		p = allPermissions
	case "operator":
		p = operatorPermissions
	case "viewer":
		p = viewerPermissions
	case "custom":
		if custom == nil {
			return nil, ErrInput
		}
		p = custom
	default:
		return nil, ErrInput
	}
	if role != "custom" && custom != nil {
		return nil, ErrInput
	}
	out := append([]string{}, p...)
	sort.Strings(out)
	for i, v := range out {
		n := sort.SearchStrings(allPermissions, v)
		if n == len(allPermissions) || allPermissions[n] != v || (i > 0 && out[i-1] == v) {
			return nil, ErrInput
		}
	}
	return out, nil
}

type CreateUser struct {
	Email       string   `json:"email"`
	Name        string   `json:"name"`
	Password    string   `json:"password"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions,omitempty"`
	Reason      string   `json:"reason"`
}
type UpdateUser struct {
	Revision    uint64    `json:"revision"`
	Reason      string    `json:"reason"`
	Email       *string   `json:"email,omitempty"`
	Name        *string   `json:"name,omitempty"`
	Password    *string   `json:"password,omitempty"`
	Role        *string   `json:"role,omitempty"`
	Enabled     *bool     `json:"enabled,omitempty"`
	Permissions *[]string `json:"permissions,omitempty"`
}

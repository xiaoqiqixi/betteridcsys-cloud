package identity

import (
	"bytes"
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"reflect"
	"strings"
	"time"
)

const CookieName = "__Host-aster-cloud-session"

func output(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}
func failure(w http.ResponseWriter, status int, code string) {
	output(w, status, map[string]any{"error": map[string]string{"code": code}})
}
func identityError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrRevision):
		failure(w, 409, "REVISION_CONFLICT")
	case errors.Is(err, ErrRevisionLimit):
		failure(w, 409, "REVISION_LIMIT")
	case errors.Is(err, ErrOperationUsed):
		failure(w, 409, "OPERATION_USED")
	case errors.Is(err, ErrInput):
		failure(w, 400, "INVALID_INPUT")
	case errors.Is(err, ErrConflict):
		failure(w, 409, "CONFLICT")
	case errors.Is(err, ErrNotFound):
		failure(w, 404, "NOT_FOUND")
	case errors.Is(err, ErrForbidden):
		failure(w, 403, "FORBIDDEN")
	case errors.Is(err, ErrAuthentication):
		failure(w, 401, "AUTH_REQUIRED")
	case errors.Is(err, ErrRateLimited):
		w.Header().Set("Retry-After", "900")
		failure(w, 429, "RATE_LIMITED")
	default:
		failure(w, 503, "IDENTITY_UNAVAILABLE")
	}
}
func (s *Service) secure(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	if r.TLS == nil {
		failure(w, 426, "TLS_REQUIRED")
		return false
	}
	if !strings.EqualFold(r.Host, s.host) {
		failure(w, 403, "ORIGIN_INVALID")
		return false
	}
	if origin := r.Header.Values("Origin"); len(origin) > 1 || (len(origin) == 1 && origin[0] != s.origin) {
		failure(w, 403, "ORIGIN_INVALID")
		return false
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		failure(w, 403, "ORIGIN_INVALID")
		return false
	}
	return true
}
func sessionCookie(r *http.Request) (string, error) {
	raw := ""
	for _, c := range r.Cookies() {
		if c.Name == CookieName {
			if raw != "" || !validToken(c.Value) {
				return "", ErrAuthentication
			}
			raw = c.Value
		}
	}
	if raw == "" {
		return "", ErrAuthentication
	}
	return raw, nil
}
func (s *Service) setCookie(w http.ResponseWriter, raw string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: raw, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: int(ttl.Seconds()), Expires: s.now().Add(ttl)})
}
func (s *Service) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1, Expires: time.Unix(1, 0)})
}
func unsafe(method string) bool { return method != "GET" && method != "HEAD" && method != "OPTIONS" }
func (s *Service) checkCSRF(w http.ResponseWriter, r *http.Request, raw string) bool {
	if r.Header.Get("Origin") != s.origin {
		failure(w, 403, "ORIGIN_INVALID")
		return false
	}
	values := r.Header.Values("X-CSRF-Token")
	want := csrfToken(raw)
	if len(values) != 1 || len(values[0]) != len(want) || subtle.ConstantTimeCompare([]byte(values[0]), []byte(want)) != 1 {
		failure(w, 403, "CSRF_INVALID")
		return false
	}
	if _, err := s.lookupSession(r.Context(), raw); err != nil {
		identityError(w, err)
		return false
	}
	return true
}

// Require performs TLS/origin, live session, permission and unsafe-method CSRF
// checks. Actor contains current DB grants; callers must still check ownership
// and the separate dangerous/restore permissions for their concrete operation.
func (s *Service) Require(permission string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.secure(w, r) {
			return
		}
		// Resource GET handlers may implement validated pagination/filter queries.
		// Never interpret query parameters as mutation input.
		if unsafe(r.Method) && r.URL.RawQuery != "" {
			failure(w, 400, "INVALID_QUERY")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		r = r.WithContext(ctx)
		raw, err := sessionCookie(r)
		if err != nil {
			identityError(w, err)
			return
		}
		u, err := s.authenticate(r.Context(), raw)
		if err != nil {
			identityError(w, err)
			return
		}
		if permission != "" && !u.Can(permission) {
			failure(w, 403, "FORBIDDEN")
			return
		}
		if unsafe(r.Method) && !s.checkCSRF(w, r, raw) {
			return
		}
		ctx = context.WithValue(r.Context(), actorKey{}, u)
		ctx = context.WithValue(ctx, managerSessionKey{}, managerSessionProof{hash: tokenHash(raw), userID: u.ID})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
func decode(r *http.Request, out any) error {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return ErrInput
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, 16385))
	if err != nil || len(b) > 16384 {
		return ErrInput
	}
	// Reject duplicate top-level fields instead of accepting ambiguous credentials.
	d := json.NewDecoder(bytes.NewReader(b))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return ErrInput
	}
	seen := map[string]bool{}
	typ := reflect.TypeOf(out)
	if typ == nil || typ.Kind() != reflect.Pointer || typ.Elem().Kind() != reflect.Struct {
		return ErrInput
	}
	allowed := map[string]bool{}
	for field := range typ.Elem().NumField() {
		tag := strings.Split(typ.Elem().Field(field).Tag.Get("json"), ",")[0]
		if tag != "" && tag != "-" {
			allowed[tag] = true
		}
	}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return ErrInput
		}
		k, ok := key.(string)
		if !ok || seen[k] || !allowed[k] {
			return ErrInput
		}
		seen[k] = true
		var discard json.RawMessage
		if d.Decode(&discard) != nil || bytes.Equal(bytes.TrimSpace(discard), []byte("null")) {
			return ErrInput
		}
	}
	if _, err = d.Token(); err != nil {
		return ErrInput
	}
	if _, err = d.Token(); err != io.EOF {
		return ErrInput
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrInput
	}
	return nil
}

func (s *Service) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.secure(w, r) {
			return
		}
		// Only the exact members GET route accepts its bounded cursor query.
		// All identity writes and other reads retain their no-query contract.
		if (r.URL.RawQuery != "" || r.URL.ForceQuery) && !(r.Method == "GET" && r.URL.Path == "/console/v1/users") {
			failure(w, 400, "INVALID_QUERY")
			return
		}
		if r.Method == "GET" && r.URL.Path == "/console/v1/users" {
			if _, err := parseUsersQuery(r.URL); err != nil {
				failure(w, 400, "INVALID_QUERY")
				return
			}
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		r = r.WithContext(ctx)
		path := r.URL.Path
		switch path {
		case "/console/v1/auth/csrf":
			if r.Method != "GET" {
				failure(w, 405, "METHOD_NOT_ALLOWED")
				return
			}
			raw, err := sessionCookie(r)
			if err == nil {
				_, err = s.lookupSession(ctx, raw)
			}
			if err != nil {
				if !errors.Is(err, ErrAuthentication) {
					identityError(w, err)
					return
				}
				raw, err = s.anonymousSession(ctx, r.RemoteAddr)
				if err != nil {
					identityError(w, err)
					return
				}
				s.setCookie(w, raw, 10*time.Minute)
			}
			output(w, 200, map[string]string{"csrf_token": csrfToken(raw)})
		case "/console/v1/auth/login":
			if r.Method != "POST" {
				failure(w, 405, "METHOD_NOT_ALLOWED")
				return
			}
			raw, err := sessionCookie(r)
			if err != nil {
				identityError(w, err)
				return
			}
			if !s.checkCSRF(w, r, raw) {
				return
			}
			var in struct {
				Email    string `json:"email"`
				Password string `json:"password"`
			}
			if decode(r, &in) != nil {
				failure(w, 400, "INVALID_INPUT")
				return
			}
			u, token, err := s.login(ctx, in.Email, in.Password, raw, r.RemoteAddr)
			if errors.Is(err, ErrRateLimited) {
				w.Header().Set("Retry-After", "900")
				failure(w, 429, "LOGIN_FAILED")
				return
			}
			if errors.Is(err, ErrAuthentication) {
				failure(w, 401, "LOGIN_FAILED")
				return
			}
			if err != nil {
				identityError(w, err)
				return
			}
			s.setCookie(w, token, s.ttl)
			output(w, 200, map[string]any{"user": u, "csrf_token": csrfToken(token)})
		case "/console/v1/auth/me":
			if r.Method != "GET" {
				failure(w, 405, "METHOD_NOT_ALLOWED")
				return
			}
			s.Require("", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				u, _ := Actor(r.Context())
				raw, _ := sessionCookie(r)
				output(w, 200, map[string]any{"user": u, "csrf_token": csrfToken(raw)})
			})).ServeHTTP(w, r)
		case "/console/v1/auth/logout":
			if r.Method != "POST" {
				failure(w, 405, "METHOD_NOT_ALLOWED")
				return
			}
			s.Require("", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := sessionCookie(r)
				if err := s.logout(ctx, raw); err != nil {
					identityError(w, err)
					return
				}
				s.clearCookie(w)
				w.WriteHeader(204)
			})).ServeHTTP(w, r)
		case "/console/v1/roles":
			if r.Method != "GET" {
				failure(w, 405, "METHOD_NOT_ALLOWED")
				return
			}
			s.Require("", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { output(w, 200, map[string]any{"items": Roles()}) })).ServeHTTP(w, r)
		case "/console/v1/users":
			if r.Method != "GET" && r.Method != "POST" {
				failure(w, 405, "METHOD_NOT_ALLOWED")
				return
			}
			s.Require("users.manage", http.HandlerFunc(s.users)).ServeHTTP(w, r)
		default:
			if strings.HasPrefix(path, "/console/v1/identity-operations/") && validID(strings.TrimPrefix(path, "/console/v1/identity-operations/")) {
				if r.Method != "GET" {
					failure(w, 405, "METHOD_NOT_ALLOWED")
					return
				}
				s.Require("users.manage", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					v, err := s.readIdentityOperation(r.Context(), strings.TrimPrefix(r.URL.Path, "/console/v1/identity-operations/"))
					if err != nil {
						identityError(w, err)
						return
					}
					output(w, 200, map[string]any{"operation": v})
				})).ServeHTTP(w, r)
				return
			}
			if strings.HasPrefix(path, "/console/v1/users/") && strings.HasSuffix(path, "/revoke-sessions") {
				target := strings.TrimSuffix(strings.TrimPrefix(path, "/console/v1/users/"), "/revoke-sessions")
				if !validID(target) {
					failure(w, 404, "NOT_FOUND")
					return
				}
				if r.Method != "POST" {
					failure(w, 405, "METHOD_NOT_ALLOWED")
					return
				}
				s.Require("users.manage", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					var in RevokeSessions
					if decode(r, &in) != nil {
						failure(w, 400, "INVALID_INPUT")
						return
					}
					ctx, err := operationRequest(r)
					if err != nil {
						identityError(w, err)
						return
					}
					a, _ := Actor(ctx)
					u, err := s.revokeSessions(ctx, a.ID, target, in)
					if err != nil {
						identityError(w, err)
						return
					}
					if a.ID == u.ID {
						s.clearCookie(w)
					}
					s.identityWriteOutput(w, ctx, u, 200)
				})).ServeHTTP(w, r)
				return
			}
			if strings.HasPrefix(path, "/console/v1/users/") && validID(strings.TrimPrefix(path, "/console/v1/users/")) {
				if r.Method == "GET" {
					s.Require("users.manage", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						u, err := scanUser(s.db.QueryRowContext(r.Context(), "SELECT "+userColumns+" FROM controller_console_users WHERE id=?", strings.TrimPrefix(r.URL.Path, "/console/v1/users/")))
						if errors.Is(err, sql.ErrNoRows) {
							err = ErrNotFound
						}
						if err != nil {
							identityError(w, err)
							return
						}
						output(w, 200, map[string]any{"user": u})
					})).ServeHTTP(w, r)
					return
				}
				if r.Method != "PATCH" {
					failure(w, 405, "METHOD_NOT_ALLOWED")
					return
				}
				s.Require("users.manage", http.HandlerFunc(s.update)).ServeHTTP(w, r)
				return
			}
			failure(w, 404, "NOT_FOUND")
		}
	})
}
func (s *Service) users(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		position, err := parseUsersQuery(r.URL)
		if err != nil {
			failure(w, 400, "INVALID_QUERY")
			return
		}
		page, err := s.listUsers(r.Context(), position)
		if err != nil {
			identityError(w, err)
			return
		}
		output(w, 200, page)
		return
	}
	var in CreateUser
	if decode(r, &in) != nil {
		failure(w, 400, "INVALID_INPUT")
		return
	}
	actor, _ := Actor(r.Context())
	ctx, err := operationRequest(r)
	if err != nil {
		identityError(w, err)
		return
	}
	u, err := s.createUser(ctx, actor.ID, in)
	if err != nil {
		identityError(w, err)
		return
	}
	s.identityWriteOutput(w, ctx, u, 201)
}
func (s *Service) update(w http.ResponseWriter, r *http.Request) {
	var in UpdateUser
	if decode(r, &in) != nil {
		failure(w, 400, "INVALID_INPUT")
		return
	}
	actor, _ := Actor(r.Context())
	ctx, err := operationRequest(r)
	if err != nil {
		identityError(w, err)
		return
	}
	u, err := s.updateUser(ctx, actor.ID, strings.TrimPrefix(r.URL.Path, "/console/v1/users/"), in)
	if err != nil {
		identityError(w, err)
		return
	}
	s.identityWriteOutput(w, ctx, u, 200)
}

func (s *Service) identityWriteOutput(w http.ResponseWriter, ctx context.Context, u User, status int) {
	k, err := identityKey(ctx)
	if err != nil {
		identityError(w, err)
		return
	}
	op, err := s.operationByID(ctx, k)
	if err != nil {
		identityError(w, err)
		return
	}
	output(w, status, map[string]any{"user": u, "operation": op})
}

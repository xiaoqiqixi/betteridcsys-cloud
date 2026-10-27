package identity

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
)

const userColumns = "id,email,name,role,enabled,permissions,revision"

type scanner interface{ Scan(...any) error }

func scanUser(row scanner, extra ...any) (User, error) {
	var u User
	var raw []byte
	fields := append([]any{&u.ID, &u.Email, &u.Name, &u.Role, &u.Enabled, &raw, &u.Revision}, extra...)
	if err := row.Scan(fields...); err != nil {
		return User{}, err
	}
	if u.Revision < 1 || u.Revision > maxIdentityRevision {
		return User{}, ErrStoredState
	}
	var stored []string
	if err := json.Unmarshal(raw, &stored); err != nil {
		return User{}, ErrInput
	}
	var err error
	if u.Role == "custom" {
		u.Permissions, err = permissions(u.Role, stored)
	} else {
		u.Permissions, err = permissions(u.Role, nil)
	}
	if err != nil {
		return User{}, err
	}
	// Persisted fixed-role grants must also match, so corrupt role data fails closed.
	a, _ := json.Marshal(stored)
	b, _ := json.Marshal(u.Permissions)
	if string(a) != string(b) {
		return User{}, ErrInput
	}
	return u, nil
}
func identityLock(ctx context.Context, tx *sql.Tx) error {
	var n int
	return tx.QueryRowContext(ctx, "SELECT id FROM controller_identity_lock WHERE id=1 FOR UPDATE").Scan(&n)
}
func audit(ctx context.Context, tx *sql.Tx, actor, action, target string, now time.Time) error {
	_, err := tx.ExecContext(ctx, "INSERT INTO controller_identity_audit(actor,action,target,created_at) VALUES(?,?,?,?)", actor, action, target, now)
	return err
}
func conflict(err error) error {
	var e *mysql.MySQLError
	if errors.As(err, &e) && e.Number == 1062 {
		return ErrConflict
	}
	return err
}

// Bootstrap creates the first administrator only. Callers must read passwords
// from a private terminal/stdin, never flags/environment/logs, and clear the buffer.
// The identity singleton lock makes two concurrent bootstrap attempts exclusive.
func (s *Service) Bootstrap(ctx context.Context, email, name string, password []byte) (User, error) {
	var err error
	email, err = normalizeEmail(email)
	if err != nil || !validName(name) {
		return User{}, ErrInput
	}
	hash, err := hashPassword(password)
	if err != nil {
		return User{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()
	if err = identityLock(ctx, tx); err != nil {
		return User{}, err
	}
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM controller_console_users").Scan(&count); err != nil {
		return User{}, err
	}
	if count != 0 {
		return User{}, ErrConflict
	}
	u, err := insertUser(ctx, tx, email, name, hash, "admin", nil, s.now())
	if err != nil {
		return User{}, err
	}
	if err = audit(ctx, tx, "root-cli", "identity.bootstrap", u.ID, s.now()); err != nil {
		return User{}, err
	}
	return u, tx.Commit()
}
func insertUser(ctx context.Context, tx *sql.Tx, email, name, hash, role string, custom []string, now time.Time) (User, error) {
	p, err := permissions(role, custom)
	if err != nil {
		return User{}, err
	}
	token, err := randomToken()
	if err != nil {
		return User{}, err
	}
	u := User{ID: token[:32], Email: email, Name: name, Role: role, Enabled: true, Permissions: p, Revision: 1}
	raw, _ := json.Marshal(p)
	_, err = tx.ExecContext(ctx, "INSERT INTO controller_console_users(id,email,name,password_hash,role,enabled,permissions,created_at,updated_at) VALUES(?,?,?,?,?,TRUE,?,?,?)", u.ID, u.Email, u.Name, hash, u.Role, raw, now, now)
	return u, conflict(err)
}
func (s *Service) authorizedManager(ctx context.Context, tx *sql.Tx, actorID string) (User, error) {
	if err := s.checkManagerSession(ctx, tx, actorID); err != nil {
		return User{}, err
	}
	u, err := scanUser(tx.QueryRowContext(ctx, "SELECT "+userColumns+" FROM controller_console_users WHERE id=?", actorID))
	if err != nil || !u.Can("users.manage") {
		return User{}, ErrForbidden
	}
	return u, nil
}

// users.manage grants bounded delegation, not an implicit escalation to admin.
// Non-admin managers may neither control an administrator nor edit an account
// whose existing or proposed grants exceed their own current DB grants.
func mayManage(actor User, existing *User, proposed User) bool {
	if !actor.Can("users.manage") {
		return false
	}
	if actor.Role == "admin" {
		return true
	}
	if proposed.Role == "admin" || (existing != nil && existing.Role == "admin") {
		return false
	}
	for _, u := range []*User{existing, &proposed} {
		if u == nil {
			continue
		}
		for _, p := range u.Permissions {
			if !actor.Can(p) {
				return false
			}
		}
	}
	return true
}
func (s *Service) createUser(ctx context.Context, actorID string, in CreateUser) (User, error) {
	if _, err := managerSession(ctx, actorID); err != nil {
		return User{}, err
	}
	if _, err := identityKey(ctx); err != nil || !validIdentityReason(in.Reason) {
		return User{}, ErrInput
	}
	if identityIntentContainsPassword(createIdentityIntent(in), in.Password) {
		return User{}, ErrInput
	}
	email, err := normalizeEmail(in.Email)
	if err != nil || !validName(in.Name) {
		return User{}, ErrInput
	}
	if _, err = permissions(in.Role, in.Permissions); err != nil {
		return User{}, err
	}
	hash, err := hashPassword([]byte(in.Password))
	if err != nil {
		return User{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()
	if err = identityLock(ctx, tx); err != nil {
		return User{}, err
	}
	actor, err := s.authorizedManager(ctx, tx, actorID)
	if err != nil {
		return User{}, err
	}
	if err = unusedIdentityKey(ctx, tx); err != nil {
		return User{}, err
	}
	p, _ := permissions(in.Role, in.Permissions)
	if !mayManage(actor, nil, User{Role: in.Role, Permissions: p}) {
		return User{}, ErrForbidden
	}
	u, err := insertUser(ctx, tx, email, in.Name, hash, in.Role, in.Permissions, s.now())
	if err != nil {
		return User{}, err
	}
	if err = finishIdentityOperation(ctx, tx, actorID, u, "identity.user_created", 0, createIdentityIntent(in), s.now()); err != nil {
		return User{}, err
	}
	return u, tx.Commit()
}
func validID(id string) bool {
	b, e := hex.DecodeString(id)
	return e == nil && len(b) == 16 && id == strings.ToLower(id)
}
func (s *Service) updateUser(ctx context.Context, actorID, target string, in UpdateUser) (User, error) {
	if _, err := managerSession(ctx, actorID); err != nil {
		return User{}, err
	}
	if _, err := identityKey(ctx); err != nil || !validIdentityReason(in.Reason) || in.Revision < 1 || in.Revision > maxIdentityRevision {
		return User{}, ErrInput
	}
	if in.Password != nil && identityIntentContainsPassword(updateIdentityIntent(in), *in.Password) {
		return User{}, ErrInput
	}
	if !validID(target) || (in.Email == nil && in.Name == nil && in.Password == nil && in.Role == nil && in.Enabled == nil && in.Permissions == nil) {
		return User{}, ErrInput
	}
	var hash string
	var err error
	if in.Password != nil {
		hash, err = hashPassword([]byte(*in.Password))
		if err != nil {
			return User{}, err
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()
	if err = identityLock(ctx, tx); err != nil {
		return User{}, err
	}
	actor, err := s.authorizedManager(ctx, tx, actorID)
	if err != nil {
		return User{}, err
	}
	if err = unusedIdentityKey(ctx, tx); err != nil {
		return User{}, err
	}
	u, err := scanUser(tx.QueryRowContext(ctx, "SELECT "+userColumns+" FROM controller_console_users WHERE id=?", target))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	original := u
	if in.Email != nil {
		u.Email, err = normalizeEmail(*in.Email)
		if err != nil {
			return User{}, err
		}
	}
	if in.Name != nil {
		if !validName(*in.Name) {
			return User{}, ErrInput
		}
		u.Name = *in.Name
	}
	if in.Role != nil {
		u.Role = *in.Role
	}
	if in.Enabled != nil {
		u.Enabled = *in.Enabled
	}
	var custom []string
	if u.Role == "custom" && original.Role == "custom" {
		custom = original.Permissions
	}
	if in.Permissions != nil {
		custom = *in.Permissions
	}
	u.Permissions, err = permissions(u.Role, custom)
	if err != nil {
		return User{}, err
	}
	if !mayManage(actor, &original, u) {
		return User{}, ErrForbidden
	}
	origP, _ := json.Marshal(original.Permissions)
	nextP, _ := json.Marshal(u.Permissions)
	securityChanged := original.Role != u.Role || original.Enabled != u.Enabled || string(origP) != string(nextP)
	if actorID == target && (securityChanged || !u.Enabled) {
		return User{}, ErrForbidden
	}
	if original.Revision != in.Revision {
		return User{}, ErrRevision
	}
	if original.Revision == maxIdentityRevision {
		return User{}, ErrRevisionLimit
	}
	u.Revision++
	if original.Role == "admin" && original.Enabled && (u.Role != "admin" || !u.Enabled) {
		var count int
		if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM controller_console_users WHERE role='admin' AND enabled=TRUE").Scan(&count); err != nil {
			return User{}, err
		}
		if count <= 1 {
			return User{}, ErrForbidden
		}
	}
	var result sql.Result
	if in.Password == nil {
		result, err = tx.ExecContext(ctx, "UPDATE controller_console_users SET email=?,name=?,role=?,enabled=?,permissions=?,updated_at=?,revision=? WHERE id=? AND revision=?", u.Email, u.Name, u.Role, u.Enabled, nextP, s.now(), u.Revision, u.ID, original.Revision)
	} else {
		result, err = tx.ExecContext(ctx, "UPDATE controller_console_users SET email=?,name=?,role=?,enabled=?,permissions=?,password_hash=?,updated_at=?,revision=? WHERE id=? AND revision=?", u.Email, u.Name, u.Role, u.Enabled, nextP, hash, s.now(), u.Revision, u.ID, original.Revision)
	}
	if err != nil {
		return User{}, conflict(err)
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		return User{}, ErrRevision
	}
	// A security or credential change invalidates every session immediately.
	if securityChanged || in.Password != nil || original.Email != u.Email {
		if _, err = tx.ExecContext(ctx, "DELETE FROM controller_console_sessions WHERE user_id=?", u.ID); err != nil {
			return User{}, err
		}
	}
	if err = finishIdentityOperation(ctx, tx, actorID, u, "identity.user_updated", original.Revision, updateIdentityIntent(in), s.now()); err != nil {
		return User{}, err
	}
	return u, tx.Commit()
}

type session struct {
	hash    [32]byte
	userID  sql.NullString
	expires time.Time
}

func (s *Service) lookupSession(ctx context.Context, raw string) (session, error) {
	if !validToken(raw) {
		return session{}, ErrAuthentication
	}
	v := session{hash: tokenHash(raw)}
	err := s.db.QueryRowContext(ctx, "SELECT user_id,expires_at FROM controller_console_sessions WHERE token_hash=? AND expires_at>?", v.hash[:], s.now()).Scan(&v.userID, &v.expires)
	if errors.Is(err, sql.ErrNoRows) {
		return session{}, ErrAuthentication
	}
	return v, err
}
func (s *Service) authenticate(ctx context.Context, raw string) (User, error) {
	v, err := s.lookupSession(ctx, raw)
	if err != nil {
		return User{}, err
	}
	if !v.userID.Valid {
		return User{}, ErrAuthentication
	}
	u, err := scanUser(s.db.QueryRowContext(ctx, "SELECT "+userColumns+" FROM controller_console_users WHERE id=?", v.userID.String))
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !u.Enabled) {
		return User{}, ErrAuthentication
	}
	return u, err
}
func insertSession(ctx context.Context, tx *sql.Tx, userID any, now time.Time, ttl time.Duration) (string, error) {
	raw, err := randomToken()
	if err != nil {
		return "", err
	}
	h := tokenHash(raw)
	_, err = tx.ExecContext(ctx, "INSERT INTO controller_console_sessions(token_hash,user_id,created_at,expires_at) VALUES(?,?,?,?)", h[:], userID, now, now.Add(ttl))
	return raw, err
}
func (s *Service) anonymousSession(ctx context.Context, peer string) (string, error) {
	if err := s.reserveAnonymous(ctx, peer); err != nil {
		return "", err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if err = identityLock(ctx, tx); err != nil {
		return "", err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM controller_console_sessions WHERE expires_at<=? LIMIT 100", s.now()); err != nil {
		return "", err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM controller_console_login_limits WHERE window_at<=? LIMIT 100", s.now().Add(-24*time.Hour)); err != nil {
		return "", err
	}
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM controller_console_sessions WHERE user_id IS NULL AND expires_at>?", s.now()).Scan(&count); err != nil {
		return "", err
	}
	if count >= 4096 {
		return "", ErrRateLimited
	}
	raw, err := insertSession(ctx, tx, nil, s.now(), 10*time.Minute)
	if err != nil {
		return "", err
	}
	return raw, tx.Commit()
}
func loginIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}
	return ip.String()
}
func (s *Service) reserveLogin(ctx context.Context, email, addr string) error {
	if loginIP(addr) == "" {
		return ErrRateLimited
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, b := range []struct {
		key string
		max int
	}{{"ip:" + loginIP(addr), 40}, {"email:" + email, 10}} {
		h := tokenHash(b.key)
		// ON DUPLICATE KEY UPDATE acquires an exclusive record lock. INSERT
		// IGNORE + SELECT FOR UPDATE would first take shared duplicate locks and
		// deadlock concurrent attempts while upgrading them.
		if _, err = tx.ExecContext(ctx, "INSERT INTO controller_console_login_limits(bucket,window_at,attempts) VALUES(?,?,0) ON DUPLICATE KEY UPDATE bucket=controller_console_login_limits.bucket", h[:], s.now()); err != nil {
			return err
		}
		var start time.Time
		var attempts int
		if err = tx.QueryRowContext(ctx, "SELECT window_at,attempts FROM controller_console_login_limits WHERE bucket=? FOR UPDATE", h[:]).Scan(&start, &attempts); err != nil {
			return err
		}
		if !s.now().Before(start.Add(15 * time.Minute)) {
			start = s.now()
			attempts = 0
		}
		if attempts >= b.max {
			return ErrRateLimited
		}
		if _, err = tx.ExecContext(ctx, "UPDATE controller_console_login_limits SET window_at=?,attempts=? WHERE bucket=?", start, attempts+1, h[:]); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Service) reserveAnonymous(ctx context.Context, peer string) error {
	ip := loginIP(peer)
	if ip == "" {
		return ErrRateLimited
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// A global ceiling also bounds distributed fresh-cookie insertion, while a
	// normalized direct-peer bucket stops one client bypassing cookie reuse.
	for _, b := range []struct {
		key string
		max int
	}{{"anonymous:global", 4096}, {"anonymous:ip:" + ip, 40}} {
		h := tokenHash(b.key)
		if _, err = tx.ExecContext(ctx, "INSERT INTO controller_console_login_limits(bucket,window_at,attempts) VALUES(?,?,0) ON DUPLICATE KEY UPDATE bucket=controller_console_login_limits.bucket", h[:], s.now()); err != nil {
			return err
		}
		var at time.Time
		var attempts int
		if err = tx.QueryRowContext(ctx, "SELECT window_at,attempts FROM controller_console_login_limits WHERE bucket=? FOR UPDATE", h[:]).Scan(&at, &attempts); err != nil {
			return err
		}
		if !s.now().Before(at.Add(15 * time.Minute)) {
			at = s.now()
			attempts = 0
		}
		if attempts >= b.max {
			return ErrRateLimited
		}
		if _, err = tx.ExecContext(ctx, "UPDATE controller_console_login_limits SET window_at=?,attempts=? WHERE bucket=?", at, attempts+1, h[:]); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (s *Service) login(ctx context.Context, email, password, oldToken, addr string) (User, string, error) {
	normalized, err := normalizeEmail(email)
	if err != nil {
		normalized = "invalid"
	}
	if err = s.reserveLogin(ctx, normalized, addr); err != nil {
		return User{}, "", err
	}
	var uid, hash string
	var revision uint64
	err = s.db.QueryRowContext(ctx, "SELECT id,password_hash,revision FROM controller_console_users WHERE email=?", normalized).Scan(&uid, &hash, &revision)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return User{}, "", err
	}
	if err != nil {
		hash = dummyPasswordHash
	}
	valid := verifyPassword(hash, []byte(password))
	// Serialize login issuance with disable/password/role changes to avoid issuing
	// a new session from a credential snapshot that was concurrently revoked.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, "", err
	}
	defer tx.Rollback()
	if err = identityLock(ctx, tx); err != nil {
		return User{}, "", err
	}
	u, lookupErr := scanUser(tx.QueryRowContext(ctx, "SELECT "+userColumns+" FROM controller_console_users WHERE id=?", uid))
	var currentHash string
	if lookupErr == nil {
		err = tx.QueryRowContext(ctx, "SELECT password_hash FROM controller_console_users WHERE id=?", uid).Scan(&currentHash)
		if err != nil {
			return User{}, "", err
		}
	}
	if !valid || lookupErr != nil || !u.Enabled || currentHash != hash || revision < 1 || u.Revision != revision {
		target := tokenHash(normalized)
		if err = audit(ctx, tx, "anonymous", "identity.login_failed", hex.EncodeToString(target[:]), s.now()); err != nil {
			return User{}, "", err
		}
		if err = tx.Commit(); err != nil {
			return User{}, "", err
		}
		return User{}, "", ErrAuthentication
	}
	old := tokenHash(oldToken)
	res, err := tx.ExecContext(ctx, "DELETE FROM controller_console_sessions WHERE token_hash=? AND expires_at>?", old[:], s.now())
	if err != nil {
		return User{}, "", err
	}
	n, err := res.RowsAffected()
	if err != nil || n != 1 {
		return User{}, "", ErrAuthentication
	}
	raw, err := insertSession(ctx, tx, u.ID, s.now(), s.ttl)
	if err != nil {
		return User{}, "", err
	}
	if err = audit(ctx, tx, u.ID, "identity.login", u.ID, s.now()); err != nil {
		return User{}, "", err
	}
	return u, raw, tx.Commit()
}
func (s *Service) logout(ctx context.Context, raw string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = identityLock(ctx, tx); err != nil {
		return err
	}
	h := tokenHash(raw)
	var uid sql.NullString
	err = tx.QueryRowContext(ctx, "SELECT user_id FROM controller_console_sessions WHERE token_hash=? FOR UPDATE", h[:]).Scan(&uid)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrAuthentication
	}
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM controller_console_sessions WHERE token_hash=?", h[:]); err != nil {
		return err
	}
	if uid.Valid {
		if err = audit(ctx, tx, uid.String, "identity.logout", uid.String, s.now()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

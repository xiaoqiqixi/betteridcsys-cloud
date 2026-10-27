package identity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const maxIdentityRevision uint64 = 9007199254740991

type identityKeyContext struct{}

func identityKey(ctx context.Context) (string, error) {
	k, ok := ctx.Value(identityKeyContext{}).(string)
	if !ok || !validID(k) {
		return "", ErrInput
	}
	return k, nil
}
func operationRequest(r *http.Request) (context.Context, error) {
	v := r.Header.Values("Idempotency-Key")
	if len(v) != 1 || !validID(v[0]) {
		return nil, ErrInput
	}
	return context.WithValue(r.Context(), identityKeyContext{}, v[0]), nil
}
func validIdentityReason(s string) bool {
	if !utf8.ValidString(s) || s == "" || strings.TrimSpace(s) != s || utf8.RuneCountInString(s) > 500 {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return false
		}
	}
	return true
}

// Exact non-secret input projection. No password or password digest is kept.
type IdentityIntent struct {
	Email           *string   `json:"email,omitempty"`
	Name            *string   `json:"name,omitempty"`
	Role            *string   `json:"role,omitempty"`
	Enabled         *bool     `json:"enabled,omitempty"`
	Permissions     *[]string `json:"permissions,omitempty"`
	Revision        uint64    `json:"revision"`
	Reason          string    `json:"reason"`
	PasswordChanged bool      `json:"password_changed"`
}
type IdentityOperation struct {
	ID             string         `json:"id"`
	ActorID        string         `json:"actor_id"`
	TargetID       string         `json:"target_id"`
	Action         string         `json:"action"`
	BaseRevision   uint64         `json:"base_revision"`
	ResultRevision uint64         `json:"result_revision"`
	Intent         IdentityIntent `json:"intent"`
	RequestSHA256  string         `json:"request_sha256"`
	Reason         string         `json:"reason"`
	AuditID        string         `json:"audit_id"`
	CompletedAt    time.Time      `json:"completed_at"`
}

func createIdentityIntent(in CreateUser) IdentityIntent {
	p := IdentityIntent{Email: &in.Email, Name: &in.Name, Role: &in.Role, Reason: in.Reason, PasswordChanged: true}
	if in.Permissions != nil {
		v := append([]string{}, in.Permissions...)
		p.Permissions = &v
	}
	return p
}
func updateIdentityIntent(in UpdateUser) IdentityIntent {
	return IdentityIntent{Email: in.Email, Name: in.Name, Role: in.Role, Enabled: in.Enabled, Permissions: in.Permissions, Revision: in.Revision, Reason: in.Reason, PasswordChanged: in.Password != nil}
}

// Do not copy a known supplied new password into an otherwise public field.
func identityIntentContainsPassword(v IdentityIntent, password string) bool {
	if password == "" {
		return false
	}
	for _, s := range []*string{v.Email, v.Name, v.Role, &v.Reason} {
		if s != nil && strings.Contains(*s, password) {
			return true
		}
	}
	return false
}
func unusedIdentityKey(ctx context.Context, tx *sql.Tx) error {
	k, err := identityKey(ctx)
	if err != nil {
		return err
	}
	var n int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM controller_identity_operations WHERE operation_id=?", k).Scan(&n); err != nil {
		return err
	}
	if n != 0 {
		return ErrOperationUsed
	}
	return nil
}
func finishIdentityOperation(ctx context.Context, tx *sql.Tx, actor string, u User, action string, base uint64, intent IdentityIntent, now time.Time) error {
	k, err := identityKey(ctx)
	if err != nil {
		return err
	}
	b, err := json.Marshal(intent)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(b)
	r, err := tx.ExecContext(ctx, "INSERT INTO controller_identity_audit(actor,action,target,created_at) VALUES(?,?,?,?)", actor, action, u.ID, now)
	if err != nil {
		return err
	}
	auditID, err := r.LastInsertId()
	if err != nil || auditID <= 0 {
		return ErrConflict
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO controller_identity_operations(operation_id,actor_id,target_id,action,base_revision,result_revision,intent_json,request_sha256,reason,audit_id,completed_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)", k, actor, u.ID, action, base, u.Revision, b, hex.EncodeToString(hash[:]), intent.Reason, auditID, now)
	if errors.Is(conflict(err), ErrConflict) {
		return ErrOperationUsed
	}
	return err
}

const identityOperationColumns = "operation_id,actor_id,target_id,action,base_revision,result_revision,intent_json,request_sha256,reason,audit_id,completed_at"

func scanIdentityOperation(row scanner) (IdentityOperation, error) {
	var v IdentityOperation
	var raw []byte
	if err := row.Scan(&v.ID, &v.ActorID, &v.TargetID, &v.Action, &v.BaseRevision, &v.ResultRevision, &raw, &v.RequestSHA256, &v.Reason, &v.AuditID, &v.CompletedAt); err != nil {
		return v, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&v.Intent) != nil || d.Decode(new(any)) != io.EOF {
		return IdentityOperation{}, ErrStoredState
	}
	b, err := json.Marshal(v.Intent)
	if err != nil {
		return IdentityOperation{}, err
	}
	hash := sha256.Sum256(b)
	a, err := strconv.ParseInt(v.AuditID, 10, 64)
	if !validID(v.ID) || !validID(v.ActorID) || !validID(v.TargetID) || !validIdentityReason(v.Reason) || v.Reason != v.Intent.Reason || v.RequestSHA256 != hex.EncodeToString(hash[:]) || err != nil || a <= 0 || v.AuditID != strconv.FormatInt(a, 10) || v.CompletedAt.IsZero() {
		return IdentityOperation{}, ErrStoredState
	}
	if v.Action == "identity.user_created" {
		if v.BaseRevision != 0 || v.ResultRevision != 1 || v.Intent.Revision != 0 || !v.Intent.PasswordChanged || v.Intent.Email == nil || v.Intent.Name == nil || v.Intent.Role == nil || v.Intent.Enabled != nil {
			return IdentityOperation{}, ErrStoredState
		}
	} else if v.Action == "identity.user_updated" || v.Action == "identity.sessions_revoked" {
		if v.BaseRevision < 1 || v.BaseRevision >= maxIdentityRevision || v.ResultRevision != v.BaseRevision+1 || v.Intent.Revision != v.BaseRevision {
			return IdentityOperation{}, ErrStoredState
		}
		if v.Action == "identity.sessions_revoked" && (v.Intent.Email != nil || v.Intent.Name != nil || v.Intent.Role != nil || v.Intent.Enabled != nil || v.Intent.Permissions != nil || v.Intent.PasswordChanged) {
			return IdentityOperation{}, ErrStoredState
		}
	} else {
		return IdentityOperation{}, ErrStoredState
	}
	return v, nil
}
func (s *Service) operationByID(ctx context.Context, k string) (IdentityOperation, error) {
	if !validID(k) {
		return IdentityOperation{}, ErrInput
	}
	v, err := scanIdentityOperation(s.db.QueryRowContext(ctx, "SELECT "+identityOperationColumns+" FROM controller_identity_operations WHERE operation_id=?", k))
	if errors.Is(err, sql.ErrNoRows) {
		return IdentityOperation{}, ErrNotFound
	}
	return v, err
}
func (s *Service) readIdentityOperation(ctx context.Context, k string) (IdentityOperation, error) {
	a, ok := Actor(ctx)
	if !ok || !a.Can("users.manage") {
		return IdentityOperation{}, ErrForbidden
	}
	v, err := s.operationByID(ctx, k)
	if err != nil {
		return v, err
	}
	if v.ActorID != a.ID {
		return IdentityOperation{}, ErrNotFound
	}
	u, err := scanUser(s.db.QueryRowContext(ctx, "SELECT "+userColumns+" FROM controller_console_users WHERE id=?", v.TargetID))
	if err != nil {
		return IdentityOperation{}, err
	}
	if !mayManage(a, &u, u) {
		return IdentityOperation{}, ErrForbidden
	}
	return v, nil
}

type RevokeSessions struct {
	Revision uint64 `json:"revision"`
	Reason   string `json:"reason"`
}

func (s *Service) revokeSessions(ctx context.Context, actorID, target string, in RevokeSessions) (User, error) {
	if _, err := managerSession(ctx, actorID); err != nil {
		return User{}, err
	}
	if _, err := identityKey(ctx); err != nil || !validID(target) || !validIdentityReason(in.Reason) || in.Revision < 1 || in.Revision > maxIdentityRevision {
		return User{}, ErrInput
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()
	if err = identityLock(ctx, tx); err != nil {
		return User{}, err
	}
	a, err := s.authorizedManager(ctx, tx, actorID)
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
	if !mayManage(a, &u, u) {
		return User{}, ErrForbidden
	}
	if u.Revision != in.Revision {
		return User{}, ErrRevision
	}
	if u.Revision == maxIdentityRevision {
		return User{}, ErrRevisionLimit
	}
	u.Revision++
	r, err := tx.ExecContext(ctx, "UPDATE controller_console_users SET revision=?,updated_at=? WHERE id=? AND revision=?", u.Revision, s.now(), u.ID, in.Revision)
	if err != nil {
		return User{}, err
	}
	if n, e := r.RowsAffected(); e != nil || n != 1 {
		return User{}, ErrRevision
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM controller_console_sessions WHERE user_id=?", u.ID); err != nil {
		return User{}, err
	}
	if err = finishIdentityOperation(ctx, tx, actorID, u, "identity.sessions_revoked", in.Revision, IdentityIntent{Revision: in.Revision, Reason: in.Reason}, s.now()); err != nil {
		return User{}, err
	}
	return u, tx.Commit()
}

package identity

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Only Require supplies this unexported proof after live authentication and
// CSRF validation. Never put the bearer cookie in a DTO, log or persisted job.
type managerSessionKey struct{}
type managerSessionProof struct {
	hash   [32]byte
	userID string
}

func managerSession(ctx context.Context, actorID string) (managerSessionProof, error) {
	proof, ok := ctx.Value(managerSessionKey{}).(managerSessionProof)
	if !ok || !validID(actorID) || proof.userID != actorID || proof.hash == ([32]byte{}) {
		return managerSessionProof{}, ErrAuthentication
	}
	return proof, nil
}

// Caller already owns identity_lock. A locking current read cannot accept a
// snapshot from before logout/password change. Hold the session until commit;
// evaluate expiry after any row-lock wait, not at the HTTP entry point.
func (s *Service) checkManagerSession(ctx context.Context, tx *sql.Tx, actorID string) error {
	proof, err := managerSession(ctx, actorID)
	if err != nil {
		return err
	}
	var owner sql.NullString
	var expires time.Time
	err = tx.QueryRowContext(ctx, "SELECT user_id,expires_at FROM controller_console_sessions WHERE token_hash=? FOR UPDATE", proof.hash[:]).Scan(&owner, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrAuthentication
	}
	if err != nil {
		return err
	}
	if !owner.Valid || owner.String != actorID || !expires.After(s.now()) {
		return ErrAuthentication
	}
	return nil
}

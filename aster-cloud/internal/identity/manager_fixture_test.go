package identity

import (
	"context"
	"testing"
)

// Store-level tests seed a real persisted session, then clean only that token.
// This is test code, not a production bypass. HTTP regressions instead obtain
// their Cookie and CSRF through the unmodified production login handler.
func managerFixture(t *testing.T, s *Service, actorID string) (context.Context, func()) {
	t.Helper()
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	raw, err := insertSession(ctx, tx, actorID, s.now(), s.ttl)
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	proof := managerSessionProof{hash: tokenHash(raw), userID: actorID}
	key, err := randomToken()
	if err != nil {
		t.Fatal(err)
	}
	ctx = context.WithValue(ctx, identityKeyContext{}, key[:32])
	return context.WithValue(ctx, managerSessionKey{}, proof), func() {
		if _, err := s.db.ExecContext(context.Background(), "DELETE FROM controller_console_sessions WHERE token_hash=?", proof.hash[:]); err != nil {
			t.Error("cannot clean the owned manager test session")
		}
	}
}

func createAs(t *testing.T, s *Service, actorID string, in CreateUser) (User, error) {
	t.Helper()
	ctx, cleanup := managerFixture(t, s, actorID)
	defer cleanup()
	if in.Reason == "" {
		in.Reason = "Isolated Store fixture creation"
	}
	return s.createUser(ctx, actorID, in)
}

func updateAs(t *testing.T, s *Service, actorID, target string, in UpdateUser) (User, error) {
	t.Helper()
	ctx, cleanup := managerFixture(t, s, actorID)
	defer cleanup()
	if in.Reason == "" {
		in.Reason = "Isolated Store fixture update"
	}
	if in.Revision == 0 {
		if err := s.db.QueryRow("SELECT revision FROM controller_console_users WHERE id=?", target).Scan(&in.Revision); err != nil {
			in.Revision = 1
		}
	}
	return s.updateUser(ctx, actorID, target, in)
}

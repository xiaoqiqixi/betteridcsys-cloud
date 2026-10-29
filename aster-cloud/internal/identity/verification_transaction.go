package identity

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"time"
)

// Authentication keeps the ordinary exclusive row-lock protocol unchanged.
// Verification cannot have UPDATE/DELETE/LOCK TABLES on the identity sentinel.
// A per-database named lock serializes verification authentication transactions,
// and a shared row lock conflicts with every ordinary identity writer's FOR
// UPDATE. Both are held until commit/rollback; no session-limit race is opened.
func (s *Service) authenticationTransaction(ctx context.Context) (*sql.Tx, func(), error) {
	if s.verificationLock == "" {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return nil, nil, err
		}
		if err = identityLock(ctx, tx); err != nil {
			tx.Rollback()
			return nil, nil, err
		}
		return tx, func() { _ = tx.Rollback() }, nil
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, nil, err
	}
	var tx *sql.Tx
	acquired := false
	cleanup := func() {
		if tx != nil {
			_ = tx.Rollback()
		}
		if acquired {
			release, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, _ = conn.ExecContext(release, "DO RELEASE_LOCK(?)", s.verificationLock)
			cancel()
		}
		// GET_LOCK survives commit and is reentrant. Never return this connection to
		// the pool, including an uncertain/cancelled acquisition or release.
		_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		_ = conn.Close()
	}
	fail := func(err error) (*sql.Tx, func(), error) { cleanup(); return nil, nil, err }
	var locked int
	if err = conn.QueryRowContext(ctx, "SELECT GET_LOCK(?,5)", s.verificationLock).Scan(&locked); err != nil {
		return fail(err)
	}
	if locked != 1 {
		return fail(ErrStoredState)
	}
	acquired = true
	// Closing a cancelled client does not immediately interrupt a MySQL query
	// blocked on an InnoDB row lock. Bound that server-side wait as well, or a
	// disconnected request can retain GET_LOCK for the default 50 seconds.
	// This is session-local on a disposable verification connection only.
	if _, err = conn.ExecContext(ctx, "SET SESSION innodb_lock_wait_timeout=2"); err != nil {
		return fail(err)
	}
	tx, err = conn.BeginTx(ctx, nil)
	if err != nil {
		return fail(err)
	}
	var sentinel int
	if err = tx.QueryRowContext(ctx, "SELECT id FROM controller_identity_lock WHERE id=1 FOR SHARE").Scan(&sentinel); err != nil {
		return fail(err)
	}
	if sentinel != 1 {
		return fail(ErrStoredState)
	}
	return tx, cleanup, nil
}

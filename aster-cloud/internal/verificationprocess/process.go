// Package verificationprocess owns the isolated verification HTTP child, not
// migration approval. Its root caller must finish the original archive, account,
// data-phase and plaintext-cleanup checks before calling Serve.
package verificationprocess

import (
	"aster/cloud/internal/control"
	"aster/cloud/internal/identity"
	"context"
	"errors"
	"os"
	"time"

	"github.com/go-sql-driver/mysql"
)

const ChildCommand = "migration-verification-child"

var ErrRefused = errors.New("verification process refused")

// Config is the complete private bootstrap allowlist. No billing/admin token,
// migration DSN, recovery key or node private-key bytes can be included. Paths
// in Controller are read-side metadata; the child MUST NOT call LoadConfig.
type Config struct {
	Controller     control.Config `json:"controller"`
	Operation      string         `json:"operation"`
	Origin         string         `json:"origin"`
	ExpiresAt      time.Time      `json:"expires_at"`
	UID            uint32         `json:"uid"`
	GID            uint32         `json:"gid"`
	DSN            string         `json:"dsn"`
	CertificatePEM []byte         `json:"certificate_pem"`
	PrivateKeyPEM  []byte         `json:"private_key_pem"`
}

func (c Config) valid() bool {
	now := time.Now().UTC()
	_, zone := c.ExpiresAt.Zone()
	policy, err := identity.VerificationDatabasePolicy("aster_cloud_restore_"+c.Operation, c.Operation)
	dsn, parseErr := mysql.ParseDSN(c.DSN)
	return c.Controller.Valid() && err == nil && parseErr == nil && c.UID >= 100 && c.UID < 65534 && c.GID >= 100 && c.GID < 65534 &&
		zone == 0 && c.ExpiresAt.Nanosecond()%1000 == 0 && now.Before(c.ExpiresAt) && c.ExpiresAt.Sub(now) <= time.Hour &&
		dsn.User == policy.User && dsn.DBName == policy.Database && dsn.Net == "unix" && dsn.Addr == "/run/mysqld/mysqld.sock" &&
		len(dsn.Passwd) >= 16 && len(dsn.Passwd) <= 1024 && c.DSN == dsn.User+":"+dsn.Passwd+"@unix(/run/mysqld/mysqld.sock)/"+dsn.DBName &&
		len(c.CertificatePEM) > 0 && len(c.CertificatePEM) <= 64<<10 && len(c.PrivateKeyPEM) > 0 && len(c.PrivateKeyPEM) <= 64<<10
}

// Serve consumes the child's independent guard, including on error. The root
// coordinator's separate raw guard remains until its OS exit. Return means the
// child has actually exited; it is NOT proof of MySQL drain or migration success.
func Serve(ctx context.Context, guard *os.File, cfg Config) error {
	if guard != nil {
		defer guard.Close()
	}
	if ctx == nil || ctx.Err() != nil || guard == nil || !cfg.valid() {
		return ErrRefused
	}
	return serve(ctx, guard, cfg)
}

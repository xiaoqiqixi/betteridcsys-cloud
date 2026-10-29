package control

import (
	"aster/cloud/internal/diagnostics"
	"aster/cloud/internal/identity"
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// VerificationServiceConfig carries only the read-side configuration and TLS
// identity. It contains no billing token, node credentials or migration DSN.
// The caller must separately authorize the host process under the target seal.
type VerificationServiceConfig struct {
	Controller     Config
	Identity       identity.Config
	Operation      string
	ExpiresAt      time.Time
	CertificatePEM []byte
	PrivateKeyPEM  []byte
}

// ServeVerificationConsole consumes the listener and the dedicated SQL pool,
// including on failure. It creates neither App nor any resource/overlay runner.
// Returning is not a host lease release or a claim of server-side SQL drain:
// the coordinator must observe actual process exit and MySQL inventory too.
func ServeVerificationConsole(ctx context.Context, listener net.Listener, store *SQLStore, cfg VerificationServiceConfig) error {
	if listener != nil {
		defer listener.Close()
	}
	if store != nil && store.DB != nil {
		defer store.DB.Close()
	}
	now := time.Now()
	_, offset := cfg.ExpiresAt.Zone()
	if ctx == nil || listener == nil || store == nil || store.DB == nil || !cfg.Controller.Valid() ||
		listener.Addr().String() != cfg.Controller.Listen || !now.Before(cfg.ExpiresAt) || cfg.ExpiresAt.Sub(now) > time.Hour ||
		offset != 0 || cfg.ExpiresAt.Nanosecond()%1000 != 0 || cfg.Identity.Now != nil {
		return ErrInput
	}
	pair, err := tls.X509KeyPair(cfg.CertificatePEM, cfg.PrivateKeyPEM)
	if err != nil {
		return ErrInput
	}
	origin, err := url.Parse(cfg.Identity.Origin)
	if err != nil || origin.Hostname() == "" {
		return ErrInput
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || leaf.VerifyHostname(origin.Hostname()) != nil || now.Before(leaf.NotBefore) || leaf.NotAfter.Before(cfg.ExpiresAt) {
		return ErrInput
	}
	serverPurpose := len(leaf.ExtKeyUsage) == 0
	for _, purpose := range leaf.ExtKeyUsage {
		serverPurpose = serverPurpose || purpose == x509.ExtKeyUsageServerAuth || purpose == x509.ExtKeyUsageAny
	}
	if !serverPurpose {
		return ErrInput
	}
	lifetime, cancel := context.WithDeadline(ctx, cfg.ExpiresAt)
	defer cancel()
	handler, err := NewVerificationConsole(lifetime, store, cfg.Controller, cfg.Identity, cfg.Operation)
	if err != nil {
		return ErrInput
	}
	var gate sync.Mutex
	var requests sync.WaitGroup
	stopped := false
	guarded := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gate.Lock()
		if stopped || lifetime.Err() != nil || !time.Now().Before(cfg.ExpiresAt) {
			gate.Unlock()
			failure(w, http.StatusServiceUnavailable, "MIGRATION_VERIFICATION_UNAVAILABLE")
			return
		}
		requests.Add(1)
		gate.Unlock()
		defer requests.Done()
		handler.ServeHTTP(w, r)
	})
	server := &http.Server{
		Handler: guarded, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}},
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 12 * time.Second, WriteTimeout: 15 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
		BaseContext: func(net.Listener) context.Context { return lifetime },
		ErrorLog:    diagnostics.TransportLog(slog.Default()),
	}
	serving := make(chan error, 1)
	go func() { serving <- server.ServeTLS(listener, "", "") }()
	var cause error
	returned := false
	select {
	case <-lifetime.Done():
		cause = lifetime.Err()
	case <-serving:
		returned = true
		cause = ErrUnavailable
	}
	// Close admission before waiting. The gate prevents a concurrent Add after
	// Wait starts; lifetime cancellation also cancels the real SQL transactions.
	gate.Lock()
	stopped = true
	gate.Unlock()
	cancel()
	_ = server.Close()
	if !returned {
		<-serving
	}
	drained := make(chan struct{})
	go func() { requests.Wait(); close(drained) }()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-drained:
		return cause
	case <-timer.C:
		return ErrUnavailable // never claim that an unfinished handler drained
	}
}

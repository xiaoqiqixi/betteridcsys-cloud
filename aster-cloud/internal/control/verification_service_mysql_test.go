package control

import (
	"aster/cloud/internal/identity"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/cookiejar"
	"reflect"
	"testing"
	"time"
)

func TestMySQLVerificationServiceStopsAndClosesOwnedConnections(t *testing.T) {
	admin := consoleHTTPStore(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	origin := "https://" + listener.Addr().String()
	auth, err := identity.New(admin.DB, identity.Config{Origin: origin})
	if err != nil {
		t.Fatal(err)
	}
	user, err := auth.Bootstrap(context.Background(), "lifetime@example.invalid", "Verification", []byte(consoleHTTPPassword))
	if err != nil {
		t.Fatal(err)
	}
	operation := id()
	limited := verificationSQLStore(t, admin, operation)
	policy, err := identity.CheckVerificationSQLIdentity(context.Background(), limited.DB, operation)
	if err != nil {
		t.Fatal(err)
	}
	ca, key, _ := authority(t)
	certificate := issue(t, ca, key, false)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}
	t.Cleanup(transport.CloseIdleConnections)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	browser := &consoleHTTPBrowser{origin: origin, client: &http.Client{Transport: transport, Jar: jar, Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	config := testConfig(testProfile())
	config.Listen = listener.Addr().String()
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	finished := make(chan error, 1)
	go func() {
		finished <- ServeVerificationConsole(ctx, listener, limited, VerificationServiceConfig{Controller: config,
			Identity: identity.Config{Origin: origin}, Operation: operation, ExpiresAt: time.Now().UTC().Add(time.Minute).Truncate(time.Microsecond),
			CertificatePEM: certificate.certPEM, PrivateKeyPEM: certificate.keyPEM})
	}()
	browser.login(t, user.Email)
	status, raw := browser.request(t, "GET", "/console/v1/migration-verification", "", consoleHTTPOptions{})
	if status != 200 {
		t.Fatal("verification service did not admit authenticated read", status)
	}
	consoleHTTPPrivateCheck(t, raw, browser, config)
	status, raw = browser.request(t, "POST", "/console/v1/users", `{}`, consoleHTTPOptions{idempotency: id()})
	if status != 403 || consoleHTTPError(t, raw) != "MIGRATION_VERIFICATION_READ_ONLY" {
		t.Fatal("verification service admitted ordinary write", status)
	}
	before := verificationDatabaseImage(t, admin)
	stop()
	select {
	case err = <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected service stop result: %T", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("stopped service did not drain")
	}
	// A stopped listener, closed owned pool and actual server-side absence are
	// different observations. Neither a cancelled client nor a Close call alone
	// counts as SQL drain proof.
	response, err := browser.client.Get(origin + "/console/v1/auth/csrf")
	if response != nil {
		response.Body.Close()
	}
	if err == nil || limited.DB.Ping() == nil {
		t.Fatal("stopped service retained HTTP admission or its SQL pool")
	}
	deadline := time.Now().Add(6 * time.Second)
	for {
		var n int
		if admin.DB.QueryRow("SELECT COUNT(*) FROM performance_schema.threads WHERE PROCESSLIST_USER=?", policy.User).Scan(&n) != nil {
			t.Fatal("actual SQL connection observation failed")
		}
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("stopped service retained actual SQL connections")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !reflect.DeepEqual(before, verificationDatabaseImage(t, admin)) {
		t.Fatal("shutdown or post-stop request changed database")
	}
}

func TestMySQLVerificationServiceRefusesWrongCertificateOrigin(t *testing.T) {
	admin := consoleHTTPStore(t)
	op := id()
	limited := verificationSQLStore(t, admin, op)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ca, key, _ := authority(t)
	certificate := issue(t, ca, key, false) // valid only for the loopback IPs
	config := testConfig(testProfile())
	config.Listen = listener.Addr().String()
	before := verificationDatabaseImage(t, admin)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err = ServeVerificationConsole(ctx, listener, limited, VerificationServiceConfig{Controller: config,
		Identity: identity.Config{Origin: "https://unapproved.example.invalid"}, Operation: op,
		ExpiresAt:      time.Now().UTC().Add(time.Minute).Truncate(time.Microsecond),
		CertificatePEM: certificate.certPEM, PrivateKeyPEM: certificate.keyPEM})
	if !errors.Is(err, ErrInput) {
		t.Fatalf("wrong TLS identity was not rejected before serving: %T", err)
	}
	if limited.DB.Ping() == nil || !reflect.DeepEqual(before, verificationDatabaseImage(t, admin)) {
		t.Fatal("rejected service retained SQL pool or changed database")
	}
}

func TestMySQLVerificationServiceRefusesUnboundedOrInvalidLifetime(t *testing.T) {
	admin := consoleHTTPStore(t)
	ca, key, _ := authority(t)
	certificate := issue(t, ca, key, false)
	changeCertificate := func(cfg *VerificationServiceConfig, change func(*x509.Certificate)) {
		leaf, err := x509.ParseCertificate(certificate.der)
		if err != nil {
			t.Fatal(err)
		}
		change(leaf)
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, leaf.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		cfg.CertificatePEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	for _, tc := range []struct {
		name   string
		change func(*VerificationServiceConfig)
	}{
		{"expired_approval", func(c *VerificationServiceConfig) { c.ExpiresAt = time.Now().Add(-time.Minute) }},
		{"approval_over_hour", func(c *VerificationServiceConfig) { c.ExpiresAt = time.Now().Add(2 * time.Hour) }},
		{"non_utc_approval", func(c *VerificationServiceConfig) { c.ExpiresAt = c.ExpiresAt.In(time.FixedZone("nonUTC", 3600)) }},
		{"nanosecond_approval", func(c *VerificationServiceConfig) { c.ExpiresAt = c.ExpiresAt.Add(time.Nanosecond) }},
		{"clock_override", func(c *VerificationServiceConfig) { c.Identity.Now = func() time.Time { return time.Unix(0, 0) } }},
		{"expired_certificate", func(c *VerificationServiceConfig) {
			changeCertificate(c, func(x *x509.Certificate) { x.NotAfter = time.Now().Add(-time.Second) })
		}},
		{"future_certificate", func(c *VerificationServiceConfig) {
			changeCertificate(c, func(x *x509.Certificate) { x.NotBefore = time.Now().Add(time.Minute) })
		}},
		{"certificate_shorter_than_approval", func(c *VerificationServiceConfig) {
			changeCertificate(c, func(x *x509.Certificate) { x.NotAfter = time.Now().Add(30 * time.Second) })
		}},
		{"client_only_certificate", func(c *VerificationServiceConfig) {
			changeCertificate(c, func(x *x509.Certificate) { x.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} })
		}},
		{"different_listener", func(c *VerificationServiceConfig) { c.Controller.Listen = "127.0.0.1:1" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			op := id()
			limited := verificationSQLStore(t, admin, op)
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			config := testConfig(testProfile())
			config.Listen = listener.Addr().String()
			cfg := VerificationServiceConfig{Controller: config, Operation: op, Identity: identity.Config{Origin: "https://" + config.Listen},
				ExpiresAt:      time.Now().UTC().Add(time.Minute).Truncate(time.Microsecond),
				CertificatePEM: certificate.certPEM, PrivateKeyPEM: certificate.keyPEM}
			tc.change(&cfg)
			before := verificationDatabaseImage(t, admin)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err = ServeVerificationConsole(ctx, listener, limited, cfg); !errors.Is(err, ErrInput) {
				t.Fatalf("invalid authority was not refused before serving: %T", err)
			}
			if limited.DB.Ping() == nil || !reflect.DeepEqual(before, verificationDatabaseImage(t, admin)) {
				t.Fatal("rejected service retained SQL pool or changed database")
			}
		})
	}
}

type verificationServiceFixture struct {
	admin, limited *SQLStore
	listener       net.Listener
	browser        *consoleHTTPBrowser
	user           string
	expires        time.Time
	stop           context.CancelFunc
	done           chan struct{}
	err            error // published by closing done
}

func startVerificationServiceFixture(t *testing.T, lifetime time.Duration) *verificationServiceFixture {
	t.Helper()
	f := &verificationServiceFixture{admin: consoleHTTPStore(t), done: make(chan struct{})}
	op := id()
	f.limited = verificationSQLStore(t, f.admin, op)
	policy, err := identity.CheckVerificationSQLIdentity(context.Background(), f.limited.DB, op)
	if err != nil {
		t.Fatal(err)
	}
	f.user = policy.User
	f.listener, err = net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ca, key, _ := authority(t)
	certificate := issue(t, ca, key, false)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	transport := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}
	t.Cleanup(transport.CloseIdleConnections)
	jar, err := cookiejar.New(nil)
	if err != nil {
		f.listener.Close()
		t.Fatal(err)
	}
	f.browser = &consoleHTTPBrowser{origin: "https://" + f.listener.Addr().String(),
		client: &http.Client{Transport: transport, Jar: jar, Timeout: 15 * time.Second}}
	config := testConfig(testProfile())
	config.Listen = f.listener.Addr().String()
	ctx, stop := context.WithCancel(context.Background())
	f.stop = stop
	f.expires = time.Now().UTC().Add(lifetime).Truncate(time.Microsecond)
	t.Cleanup(func() {
		stop()
		select {
		case <-f.done:
		case <-time.After(10 * time.Second):
			t.Error("verification service fixture failed to stop")
		}
		f.listener.Close()
	})
	go func() {
		f.err = ServeVerificationConsole(ctx, f.listener, f.limited, VerificationServiceConfig{Controller: config,
			Identity: identity.Config{Origin: f.browser.origin}, Operation: op, ExpiresAt: f.expires,
			CertificatePEM: certificate.certPEM, PrivateKeyPEM: certificate.keyPEM})
		close(f.done)
	}()
	response, err := f.browser.client.Get(f.browser.origin + "/console/v1/auth/me")
	if err != nil {
		t.Fatal("verification HTTP/2 readiness failed")
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized || response.ProtoMajor != 2 {
		t.Fatal("verification service did not provide actual authenticated HTTP/2 boundary", response.StatusCode, response.ProtoMajor)
	}
	return f
}

func requireVerificationServiceDrain(t *testing.T, f *verificationServiceFixture) {
	t.Helper()
	if f.limited.DB.Ping() == nil {
		t.Fatal("verification service retained owned SQL pool")
	}
	deadline := time.Now().Add(6 * time.Second)
	for {
		var n int
		if f.admin.DB.QueryRow("SELECT COUNT(*) FROM performance_schema.threads WHERE PROCESSLIST_USER=?", f.user).Scan(&n) != nil {
			t.Fatal("server-side SQL connection observation failed")
		}
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("verification service retained actual SQL connection")
		}
		time.Sleep(10 * time.Millisecond)
	}
	response, err := f.browser.client.Get(f.browser.origin + "/console/v1/auth/csrf")
	if response != nil {
		response.Body.Close()
	}
	if err == nil {
		t.Fatal("verification listener still accepted requests")
	}
}

func TestMySQLVerificationServiceExpiryClosesListenerAndPool(t *testing.T) {
	f := startVerificationServiceFixture(t, 5*time.Second)
	status, _ := f.browser.request(t, "GET", "/console/v1/auth/csrf", "", consoleHTTPOptions{})
	if status != 200 {
		t.Fatal("valid service failed before expiry", status)
	}
	before := verificationDatabaseImage(t, f.admin)
	select {
	case <-f.done:
		if !errors.Is(f.err, context.DeadlineExceeded) || time.Now().Before(f.expires) {
			t.Fatalf("unexpected service expiry result: %T", f.err)
		}
	case <-time.After(time.Until(f.expires) + 10*time.Second):
		t.Fatal("expired service continued running")
	}
	requireVerificationServiceDrain(t, f)
	if !reflect.DeepEqual(before, verificationDatabaseImage(t, f.admin)) {
		t.Fatal("expiry or post-expiry request changed SQL image")
	}
}

func TestMySQLVerificationServiceStopCancelsRealAuthenticationWait(t *testing.T) {
	f := startVerificationServiceFixture(t, time.Minute)
	tx, err := f.admin.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var n int
	if tx.QueryRow("SELECT id FROM controller_identity_lock WHERE id=1 FOR UPDATE").Scan(&n) != nil {
		t.Fatal("fixture identity writer lock unavailable")
	}
	before := verificationDatabaseImage(t, f.admin)
	var limitName, limitDDL string
	if f.admin.DB.QueryRow("SHOW CREATE TABLE controller_console_login_limits").Scan(&limitName, &limitDDL) != nil ||
		f.admin.DB.QueryRow("SELECT COUNT(*) FROM controller_console_login_limits").Scan(&n) != nil || n != 0 {
		t.Fatal("fixture must start with empty limiter table")
	}
	requestAt := time.Now().UTC().Truncate(time.Microsecond)
	clientDone := make(chan int, 1)
	go func() {
		response, _ := f.browser.client.Get(f.browser.origin + "/console/v1/auth/csrf")
		status := 0
		if response != nil {
			status = response.StatusCode
			response.Body.Close()
		}
		clientDone <- status
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		err = f.admin.DB.QueryRow("SELECT COUNT(*) FROM performance_schema.data_lock_waits w JOIN performance_schema.data_locks l ON w.REQUESTING_ENGINE_LOCK_ID=l.ENGINE_LOCK_ID AND w.ENGINE=l.ENGINE WHERE l.OBJECT_SCHEMA=DATABASE() AND l.OBJECT_NAME='controller_identity_lock'").Scan(&n)
		if err != nil {
			t.Fatal("actual authentication wait observation failed")
		}
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("authentication did not enter actual SQL wait")
		}
		select {
		case <-clientDone:
			t.Fatal("authentication completed before observed SQL wait")
		case <-time.After(5 * time.Millisecond):
		}
	}
	// Anonymous admission commits the global and peer rate reservations BEFORE
	// waiting on the identity lock. Cancellation must not refund that attempt.
	// Require the precise two expected buckets rather than ignoring this table.
	var count, valid int
	if f.admin.DB.QueryRow("SELECT COUNT(*),SUM(bucket IN (UNHEX('133c37c2afdbce09f06f89cb452e47e0f775399ab8c04b22cbb781fd9534ac30'),UNHEX('71e9fc725378d3ec341a5dbd702c88190b89bef7cb6b3ab6819eddd06c33e4bf')) AND attempts=1 AND window_at>=? AND window_at<=?) FROM controller_console_login_limits", requestAt, time.Now().UTC()).Scan(&count, &valid) != nil || count != 2 || valid != 2 {
		t.Fatal("authentication did not preserve the exact rate reservation")
	}
	waiting := verificationDatabaseImage(t, f.admin)
	for table, digest := range before {
		if table != "controller_console_login_limits" && waiting[table] != digest {
			t.Fatal("authentication changed data before obtaining identity lock", table)
		}
	}
	var waitingName, waitingDDL string
	if len(waiting) != len(before) || f.admin.DB.QueryRow("SHOW CREATE TABLE controller_console_login_limits").Scan(&waitingName, &waitingDDL) != nil || waitingName != limitName || waitingDDL != limitDDL {
		t.Fatal("authentication changed schema before obtaining identity lock")
	}
	before = waiting // exact proven image immediately before stopping, not a new trust baseline
	f.stop()
	select {
	case <-f.done:
		if !errors.Is(f.err, context.Canceled) {
			t.Fatalf("unexpected stopped service result: %T", f.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("service failed to cancel active authentication")
	}
	select {
	case status := <-clientDone:
		if status >= 200 && status < 300 {
			t.Fatal("stopped authentication issued success", status)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("stopped authentication client remained active")
	}
	requireVerificationServiceDrain(t, f)
	if f.admin.DB.QueryRow("SELECT COUNT(*) FROM performance_schema.metadata_locks l JOIN performance_schema.threads t ON t.THREAD_ID=l.OWNER_THREAD_ID WHERE l.OBJECT_TYPE='USER LEVEL LOCK' AND t.PROCESSLIST_USER=?", f.user).Scan(&n) != nil || n != 0 {
		t.Fatal("stopped authentication retained named SQL lock")
	}
	after := verificationDatabaseImage(t, f.admin)
	if !reflect.DeepEqual(before, after) {
		var changed []string
		for table, digest := range before {
			if after[table] != digest {
				changed = append(changed, table)
			}
		}
		t.Fatal("stopped authentication changed SQL image", changed)
	}
}

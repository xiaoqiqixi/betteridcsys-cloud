package main

import (
	"aster/cloud/internal/control"
	"aster/cloud/internal/controllerbackup"
	"aster/cloud/internal/controllerhost"
	"aster/cloud/internal/diagnostics"
	"aster/cloud/internal/identity"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

func main() {
	slog.SetDefault(diagnostics.New(os.Stderr, "controller"))
	if err := run(os.Args[1:]); err != nil {
		code := "COMMAND_FAILED"
		exitCode := 1
		if errors.Is(err, controllerhost.ErrFenced) {
			code = "CONTROLLER_MIGRATION_FENCED"
			exitCode = 78 // a durable fence must not cause a systemd restart loop
		}
		if errors.Is(err, controllerhost.ErrBusy) {
			code = "CONTROLLER_MIGRATION_BUSY"
		}
		slog.Error("aster_command_failed", "code", code)
		os.Exit(exitCode)
	}
}
func run(args []string) error {
	if len(args) < 1 {
		return control.ErrInput
	}
	command := args[0]
	if command == "migration-target-verification-credential-check" || command == "migration-target-verification-plan" || command == "migration-target-configuration-plan" || command == "migration-target-configuration-publish" || command == "migration-target-configuration-status" || command == "migration-target-configuration-resume" {
		return targetArchive(command, args[1:])
	}
	if command == "migration-target-plan" || command == "migration-target-seal" || command == "migration-target-status" || command == "migration-target-database-plan" || command == "migration-target-provision-check" || command == "migration-target-import" || command == "migration-target-data-status" || command == "migration-target-materials" || command == "migration-target-material-status" || command == "migration-target-revoke-sessions" || command == "migration-target-session-status" || command == "migration-target-session-resume" {
		return targetArchive(command, args[1:])
	}
	if command == "migration-inspect" {
		return inspectArchive(args[1:])
	}
	if command == "migration-validate-source" {
		return validateArchiveSource(args[1:])
	}
	if command == "migration-capabilities" && len(args) == 1 {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{
			"schema": 1, "protocol": "aster.controller-host/1", "runtime_fence": runtime.GOOS == "linux",
			"host_migration_seal":     runtime.GOOS == "linux",
			"target_preparation_seal": runtime.GOOS == "linux",
			"migration_ready":         false, "export_restore": false,
		})
	}
	flags := flag.NewFlagSet("aster-controller "+command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "/etc/aster-controller/config.json", "root protected configuration")
	operation := flags.String("operation", "", "exact operation ID")
	node := flags.String("node", "", "approved node ID")
	on := flags.Bool("on", true, "maintenance enabled")
	consoleOrigin := flags.String("console-origin", "", "fixed HTTPS console origin (explicitly enables staff sessions)")
	uiDirectory := flags.String("ui-dir", "", "reviewed root-owned built console directory")
	email := flags.String("email", "", "bootstrap administrator email")
	name := flags.String("name", "Administrator", "bootstrap administrator name")
	passwordStdin := flags.Bool("password-stdin", false, "read bootstrap password from stdin, never arguments")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		return control.ErrInput
	}
	if command == "init" {
		return initialize(*configPath)
	}
	switch command {
	case "migrate", "bootstrap-admin", "operation-dispatch", "operation-reconcile", "check", "register-nodes", "heartbeat", "maintenance", "dispatch", "reconcile", "serve":
	case "migration-status", "migration-fence", "migration-cancel", "migration-export":
		invalid := false
		flags.Visit(func(f *flag.Flag) {
			if f.Name != "config" && !(f.Name == "operation" && command != "migration-status") {
				invalid = true
			}
		})
		if invalid {
			return control.ErrInput
		}
	default:
		return control.ErrInput
	}
	config, secrets, err := control.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	canonical, err := json.Marshal(config)
	if err != nil {
		return control.ErrInput
	}
	digest := sha256.Sum256(canonical)
	host, err := controllerhost.Open(config.ControllerID, hex.EncodeToString(digest[:]))
	if err != nil {
		return err
	}
	defer host.Close()
	write := func(v any) error { return json.NewEncoder(os.Stdout).Encode(v) }
	if command == "migration-export" {
		// Only the fixed managed installation can export. A custom config flag
		// must not redirect the protected coordinator's source identity.
		if *configPath != "/etc/aster-controller/config.json" {
			return control.ErrInput
		}
		var report controllerbackup.ExportReport
		err = host.WithSealedSource(*operation, func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
			defer cancel()
			var e error
			report, e = controllerbackup.ExportSealedSource(ctx, config, *operation)
			return e
		})
		if err != nil {
			return err
		}
		return write(report)
	}
	if strings.HasPrefix(command, "migration-") {
		var status controllerhost.Status
		switch command {
		case "migration-status":
			status, err = host.Status()
		case "migration-fence":
			status, err = host.Fence(*operation)
		case "migration-cancel":
			status, err = host.Cancel(*operation)
		}
		if err != nil {
			return err
		}
		return write(status)
	}
	if err = host.Admit(); err != nil {
		return err
	}
	raw, err := control.ReadProtected(config.DSNFile, true, 4096)
	if err != nil {
		return err
	}
	store, err := control.OpenDSN(strings.TrimSpace(string(raw)))
	if err != nil {
		return err
	}
	defer store.DB.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if command == "migrate" {
		if err = store.Migrate(ctx); err != nil {
			return err
		}
		return write(map[string]string{"status": "migrated"})
	}
	if err = store.Check(ctx); err != nil {
		return err
	}
	switch command {
	case "bootstrap-admin":
		if !*passwordStdin || *consoleOrigin == "" || *email == "" {
			return control.ErrInput
		}
		auth, e := identity.New(store.DB, identity.Config{Origin: *consoleOrigin})
		if e != nil {
			return e
		}
		password, e := io.ReadAll(io.LimitReader(os.Stdin, 1026))
		if e != nil || len(password) > 1025 {
			return control.ErrInput
		}
		password = []byte(strings.TrimSuffix(strings.TrimSuffix(string(password), "\n"), "\r"))
		defer clear(password)
		user, e := auth.Bootstrap(ctx, *email, *name, password)
		if e != nil {
			return e
		}
		return write(map[string]any{"user": user})
	case "operation-dispatch", "operation-reconcile":
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		worker := control.OperationWorker{Store: store, Config: config}
		action := strings.TrimPrefix(command, "operation-")
		if err = store.AuditOperationRequest(ctx, "host-operator", *operation, action, time.Now().UTC()); err != nil {
			return err
		}
		var op control.Operation
		if command == "operation-dispatch" {
			op, err = worker.Dispatch(ctx, *operation)
		} else {
			op, err = worker.Reconcile(ctx, *operation)
		}
		if op.ID != "" {
			if e := write(map[string]any{"operation": op}); e != nil {
				return e
			}
		}
		return err
	case "check":
		return write(map[string]string{"status": "ready", "controller_id": config.ControllerID})
	case "register-nodes":
		for _, n := range config.Nodes {
			if err = store.RegisterNode(ctx, n); err != nil {
				return err
			}
		}
		return write(map[string]string{"status": "registered_in_maintenance"})
	case "heartbeat":
		p, ok := config.Node(*node)
		if !ok {
			return control.ErrInput
		}
		client, e := control.NewNodeClient(ctx, p)
		if e != nil {
			return e
		}
		caps, e := client.Capabilities(ctx)
		if e != nil {
			return e
		}
		if e = store.Heartbeat(ctx, p, caps, time.Now().UTC(), time.Duration(config.HeartbeatTTLSeconds)*time.Second); e != nil {
			return e
		}
		return write(map[string]string{"status": "heartbeat_recorded"})
	case "maintenance":
		if _, ok := config.Node(*node); !ok {
			return control.ErrInput
		}
		if err = store.Maintenance(ctx, *node, *on); err != nil {
			return err
		}
		return write(map[string]any{"status": "updated", "maintenance": *on})
	case "dispatch", "reconcile":
		w := control.Worker{Store: store, Config: config}
		var job control.Job
		if command == "dispatch" {
			job, err = w.Dispatch(ctx, *operation)
		} else {
			job, err = w.Reconcile(ctx, *operation)
		}
		if job.OperationID != "" {
			if e := write(job); e != nil {
				return e
			}
		}
		return err
	case "serve":
		cert, e1 := control.ReadProtected(config.TLSCertFile, false, 65536)
		key, e2 := control.ReadProtected(config.TLSKeyFile, true, 65536)
		pair, e3 := tls.X509KeyPair(cert, key)
		if e1 != nil || e2 != nil || e3 != nil {
			return control.ErrUnavailable
		}
		app := control.App{Store: store, Config: config, Secrets: secrets}
		overlayWorker := control.OverlayWorker{Store: store, Config: config}
		overlayRunner := control.NewOverlayRunner(overlayWorker)
		overlayContext, stopOverlay := context.WithCancel(context.Background())
		defer func() { stopOverlay(); overlayRunner.Close() }()
		go overlayRunner.Run(overlayContext)
		var handler http.Handler = app.Handler()
		if *consoleOrigin != "" {
			auth, e := identity.New(store.DB, identity.Config{Origin: *consoleOrigin})
			if e != nil {
				return e
			}
			mux := http.NewServeMux()
			mux.Handle("/v1/", app.Handler())
			worker := control.OperationWorker{Store: store, Config: config}
			runner := control.NewOperationRunner(worker)
			defer runner.Close()
			mux.Handle("/console/v1/", (control.Console{Store: store, Config: config, Identity: auth, Worker: &worker, Runner: runner, OverlayWorker: &overlayWorker, OverlayRunner: overlayRunner}).Handler())
			if *uiDirectory != "" {
				web, e := control.Web(*uiDirectory)
				if e != nil {
					return e
				}
				mux.Handle("/", web)
			}
			handler = mux
		} else if *uiDirectory != "" {
			return control.ErrInput
		}
		guarded := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if host.Check() != nil {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Cache-Control", "no-store")
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = io.WriteString(w, `{"error":{"code":"CONTROLLER_MAINTENANCE","message":"控制台正在维护，请稍后再试。"}}`)
				return
			}
			handler.ServeHTTP(w, r)
		})
		server := &http.Server{Addr: config.Listen, Handler: guarded, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 12 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
		server.ErrorLog = diagnostics.TransportLog(slog.Default())
		sigCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
		defer stop()
		shutdownDone := make(chan struct{})
		go func() {
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-sigCtx.Done():
					return
				case <-ticker.C:
					if host.Check() != nil {
						stop()
						return
					}
				}
			}
		}()
		go func() {
			defer close(shutdownDone)
			<-sigCtx.Done()
			stopOverlay()
			c, done := context.WithTimeout(context.Background(), 10*time.Second)
			defer done()
			_ = server.Shutdown(c)
		}()
		slog.Info("aster_service_starting")
		err = server.ListenAndServeTLS("", "")
		if err == http.ErrServerClosed {
			<-shutdownDone // Shutdown closes listeners before active handlers finish.
			slog.Info("aster_service_stopped")
			return nil
		}
		return err
	default:
		return control.ErrInput
	}
}
func initialize(path string) error {
	if os.Geteuid() != 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\r\n\x00") {
		return control.ErrInput
	}
	dir := filepath.Dir(path)
	// Create only one private leaf under an already protected root-owned chain.
	parent := filepath.Dir(dir)
	for p := parent; ; p = filepath.Dir(p) {
		info, e := os.Lstat(p)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return control.ErrInput
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return control.ErrInput
		}
		if p == "/" {
			break
		}
	}
	if e := os.Mkdir(dir, 0700); e != nil && !os.IsExist(e) {
		return e
	}
	info, e := os.Lstat(dir)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return control.ErrInput
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 {
		return control.ErrInput
	}
	writeNew := func(path string, raw []byte) error {
		f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return e
		}
		defer f.Close()
		if _, e = f.Write(raw); e != nil {
			return e
		}
		return f.Sync()
	}
	c := control.Config{Schema: 1, ControllerID: "aster-main", Listen: "127.0.0.1:9443", TLSCertFile: filepath.Join(dir, "server.crt"), TLSKeyFile: filepath.Join(dir, "server.key"), DSNFile: filepath.Join(dir, "mysql-dsn"), BillingTokenFile: filepath.Join(dir, "billing.token"), AdminReadTokenFile: filepath.Join(dir, "admin-read.token"), AdminWriteTokenFile: filepath.Join(dir, "admin-write.token"), HeartbeatTTLSeconds: 60, Nodes: []control.NodeProfile{}, Presets: []control.Preset{}}
	// Existing files are never overwritten, including partial initialization.
	if _, e = os.Lstat(path); !os.IsNotExist(e) {
		return control.ErrConflict
	}
	for _, p := range []string{c.BillingTokenFile, c.AdminReadTokenFile, c.AdminWriteTokenFile} {
		var secret [32]byte
		if _, e = rand.Read(secret[:]); e != nil {
			return e
		}
		if e = writeNew(p, []byte(hex.EncodeToString(secret[:])+"\n")); e != nil {
			return e
		}
	}
	raw, e := json.MarshalIndent(c, "", "  ")
	if e != nil {
		return e
	}
	if e = writeNew(path, append(raw, '\n')); e != nil {
		return e
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]string{"status": "initialized_configuration_only", "next": "supply private database DSN, TLS files and approved nodes; migrate explicitly"})
}

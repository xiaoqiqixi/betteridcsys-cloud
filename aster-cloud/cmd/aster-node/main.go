// aster-node is a local KVM/libvirt host executor, not an SSH command relay.
package main

import (
	"aster/cloud/internal/diagnostics"
	"aster/cloud/internal/hypervisor"
	"aster/cloud/internal/nodeproto"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
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
	slog.SetDefault(diagnostics.New(os.Stderr, "node"))
	if err := run(); err != nil {
		slog.Error("aster_command_failed", "code", "COMMAND_FAILED")
		os.Exit(1)
	}
}

type options struct {
	printPublicFilter         string
	printPublicFilterProvided bool
	networkStatus             string
	recoverNetwork            string
	networkStatusProvided     bool
	recoverNetworkProvided    bool
	config                    string
	doctor                    bool
	reconcile                 string
	reconcileProvided         bool
	approveImport             string
	reviewedFence             string
	approveProvided           bool
}

// parseArgs is side-effect free. An explicitly empty/invalid reconcile flag may
// never be reinterpreted as default serve mode or reach configuration/I/O.
func parseArgs(args []string) (options, error) {
	var o options
	flags := flag.NewFlagSet("aster-node", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&o.printPublicFilter, "print-public-network-filter", "", "print a self-contained direct-public nwfilter without reading config or accessing libvirt")
	flags.StringVar(&o.networkStatus, "network-recovery-status", "", "root-only read-only fabric recovery expectation for a profile")
	flags.StringVar(&o.recoverNetwork, "recover-network", "", "root-owned canonical recovery approval JSON; service must be stopped")
	flags.StringVar(&o.config, "config", "/etc/aster-node/node.json", "root-owned 0600 configuration")
	flags.StringVar(&o.reconcile, "reconcile-operation", "", "root-only read-only original-domain observation; service must be stopped")
	flags.StringVar(&o.approveImport, "approve-storage-import", "", "root approval of a protected offline handoff artifact")
	flags.StringVar(&o.reviewedFence, "reviewed-source-fence", "", "exact source fence token independently verified by root")
	flags.BoolVar(&o.doctor, "doctor", false, "read-only host readiness check; no mutation")
	if err := flags.Parse(args); err != nil {
		return o, err
	}
	doctorProvided := false
	reviewedProvided := false
	visited := 0
	flags.Visit(func(f *flag.Flag) {
		visited++
		if f.Name == "print-public-network-filter" {
			o.printPublicFilterProvided = true
		}
		if f.Name == "network-recovery-status" {
			o.networkStatusProvided = true
		}
		if f.Name == "recover-network" {
			o.recoverNetworkProvided = true
		}
		if f.Name == "reconcile-operation" {
			o.reconcileProvided = true
		}
		if f.Name == "approve-storage-import" {
			o.approveProvided = true
		}
		if f.Name == "reviewed-source-fence" {
			reviewedProvided = true
		}
		if f.Name == "doctor" {
			doctorProvided = true
		}
	})
	if o.printPublicFilterProvided {
		if visited != 1 || flags.NArg() != 0 || !strings.HasPrefix(o.printPublicFilter, "aster-") || !nodeproto.ValidNodeID(o.printPublicFilter) {
			return o, fmt.Errorf("standalone public filter requires safe aster-prefixed filter name")
		}
		return o, nil
	}
	if o.networkStatusProvided || o.recoverNetworkProvided {
		if o.networkStatusProvided && o.recoverNetworkProvided || doctorProvided || o.reconcileProvided || o.approveProvided || reviewedProvided {
			return o, fmt.Errorf("network recovery modes are exclusive")
		}
		if o.networkStatusProvided && !nodeproto.ValidNodeID(o.networkStatus) {
			return o, fmt.Errorf("invalid network profile")
		}
		if o.recoverNetworkProvided && (!filepath.IsAbs(o.recoverNetwork) || filepath.Clean(o.recoverNetwork) != o.recoverNetwork) {
			return o, fmt.Errorf("canonical absolute recovery file required")
		}
	}
	if flags.NArg() != 0 {
		return o, fmt.Errorf("unexpected arguments")
	}
	if o.approveProvided && (doctorProvided || o.reconcileProvided) {
		return o, fmt.Errorf("approval, doctor and reconcile are mutually exclusive")
	}
	if o.approveProvided {
		if !nodeproto.ValidID(o.approveImport) || !reviewedProvided || len(o.reviewedFence) != 64 {
			return o, fmt.Errorf("approval requires artifact ID and reviewed 64hex source fence")
		}
		for _, v := range o.reviewedFence {
			if !((v >= '0' && v <= '9') || (v >= 'a' && v <= 'f')) {
				return o, fmt.Errorf("invalid reviewed source fence")
			}
		}
	} else if reviewedProvided {
		return o, fmt.Errorf("reviewed source fence requires approval mode")
	}
	if o.reconcileProvided && doctorProvided {
		return o, fmt.Errorf("doctor and reconcile are mutually exclusive")
	}
	if o.reconcileProvided && !nodeproto.ValidID(o.reconcile) {
		return o, fmt.Errorf("reconcile requires a 32 lowercase hex operation ID")
	}
	return o, nil
}
func run() error {
	o, err := parseArgs(os.Args[1:])
	if err != nil {
		return err
	}
	if o.printPublicFilterProvided {
		_, err = os.Stdout.Write(hypervisor.DirectApprovedFilterXML(o.printPublicFilter))
		return err
	}
	cfg, err := hypervisor.LoadConfig(o.config)
	if err != nil {
		return fmt.Errorf("configuration rejected")
	}
	manager := &hypervisor.Manager{Config: cfg, Runner: hypervisor.OSRunner{}}
	if o.doctor {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		report := manager.Doctor(ctx)
		_ = json.NewEncoder(os.Stdout).Encode(report)
		if !report.Ready {
			return fmt.Errorf("host doctor prerequisites not ready")
		}
		return nil
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0 {
		return fmt.Errorf("serve requires native x86_64 Linux root for the approved local libvirt system")
	}
	syscall.Umask(0077)
	ledger, err := hypervisor.OpenLedger(cfg.StateDirectory, cfg.NodeID)
	if err != nil {
		return fmt.Errorf("private journal unavailable")
	}
	defer ledger.Close()
	defer manager.Shutdown()
	manager.Ledger = ledger
	if o.networkStatusProvided {
		result, e := manager.NetworkRecoveryStatus(o.networkStatus)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	}
	if o.recoverNetworkProvided {
		request, e := hypervisor.LoadNetworkRecoveryRequest(o.recoverNetwork)
		if e != nil {
			return e
		}
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		result, e := manager.RecoverNetwork(ctx, request)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	}
	if o.approveProvided {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if e := manager.ApproveInbox(ctx, o.approveImport, o.reviewedFence); e != nil {
			return fmt.Errorf("protected import approval rejected")
		}
		fmt.Fprintln(os.Stdout, "root import approval durably recorded; no VM was defined or started")
		return nil
	}
	if o.reconcileProvided {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		result, e := manager.Reconcile(ctx, o.reconcile)
		_ = json.NewEncoder(os.Stdout).Encode(result)
		return e
	}
	tlsConfig, err := hypervisor.ServerTLS(cfg)
	if err != nil {
		return fmt.Errorf("mTLS configuration rejected")
	}
	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	server := &http.Server{Handler: manager.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 120 * time.Second, IdleTimeout: 30 * time.Second, TLSConfig: tlsConfig}
	server.ErrorLog = diagnostics.TransportLog(slog.Default())
	signals, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-signals.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()
	slog.Info("aster_service_starting")
	err = server.Serve(tls.NewListener(listener, tlsConfig))
	if err == http.ErrServerClosed {
		slog.Info("aster_service_stopped")
		return nil
	}
	return err
}

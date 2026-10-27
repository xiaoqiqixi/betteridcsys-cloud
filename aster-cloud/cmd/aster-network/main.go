package main

import (
	"aster/cloud/internal/fabric"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"
)

func run(args []string, out, stderr io.Writer) int {
	if len(args) < 1 {
		return 2
	}
	command := args[0]
	if command != "plan" && command != "status" && command != "apply" && command != "verify" && command != "fingerprint" && command != "overlay-fingerprint" {
		return 2
	}
	f := flag.NewFlagSet("aster-network", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	config := f.String("config", "", "private root config")
	topology := f.String("topology", "", "topology JSON")
	confirm := f.String("confirm-bridge", "", "exact approved bridge")
	revision := f.Int64("revision", 0, "receipt revision")
	if f.Parse(args[1:]) != nil || f.NArg() != 0 {
		return 2
	}
	failure := func(code string) int {
		_ = json.NewEncoder(stderr).Encode(map[string]any{"error": map[string]string{"code": code}})
		return 1
	}
	if command == "verify" || command == "fingerprint" || command == "overlay-fingerprint" {
		invalid := false
		f.Visit(func(option *flag.Flag) {
			if option.Name != "config" {
				invalid = true
			}
		})
		if invalid {
			return failure("INVALID_ARGUMENTS")
		}
	}
	// Read and validate the root-approved canonical overlay contract only. This
	// command neither opens a fabric journal nor touches a bridge or guest.
	if command == "overlay-fingerprint" {
		c, err := fabric.LoadOverlayConfig(*config)
		if err != nil || os.Geteuid() != 0 {
			return failure("OVERLAY_CONFIG_REJECTED")
		}
		sha, err := fabric.OverlayConfigSHA256(c)
		if err != nil {
			return failure("OVERLAY_CONFIG_REJECTED")
		}
		if json.NewEncoder(out).Encode(map[string]string{"protocol": "aster.overlay.config/1", "node_id": c.Base.NodeID, "sha256": sha}) != nil {
			return 1
		}
		return 0
	}
	c, e := fabric.LoadConfig(*config)
	if e != nil {
		return failure("FABRIC_CONFIG_REJECTED")
	}
	if command == "fingerprint" {
		if os.Geteuid() != 0 {
			return failure("FABRIC_CONFIG_REJECTED")
		}
		raw, _ := json.Marshal(c)
		sum := sha256.Sum256(raw)
		if json.NewEncoder(out).Encode(map[string]string{"protocol": "aster.fabric.config/1", "node_id": c.NodeID, "sha256": hex.EncodeToString(sum[:])}) != nil {
			return 1
		}
		return 0
	}
	if command == "verify" {
		executor, err := fabric.NewExecutor(c, fabric.OSRunner{})
		if err != nil {
			return failure("FABRIC_CONFIG_REJECTED")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		result, err := executor.VerifyLive(ctx)
		cancel()
		if err != nil {
			return failure("FABRIC_LIVE_STATE_UNCONFIRMED")
		}
		if json.NewEncoder(out).Encode(result) != nil {
			return 1
		}
		return 0
	}
	var r fabric.Receipt
	if command == "status" {
		if *topology != "" || *confirm != "" || *revision < 0 {
			return failure("INVALID_ARGUMENTS")
		}
		r, e = fabric.Status(c, *revision)
	} else {
		if *revision != 0 {
			return failure("INVALID_ARGUMENTS")
		}
		t, err := fabric.LoadTopology(*topology)
		if err != nil || t.NodeID != c.NodeID {
			return failure("TOPOLOGY_REJECTED")
		}
		if command == "plan" {
			if *confirm != "" {
				return failure("INVALID_ARGUMENTS")
			}
			p, _ := fabric.Compile(t)
			r = fabric.Receipt{Schema: 1, NodeID: t.NodeID, Revision: t.Revision, Digest: p.Digest, State: "planned", Stage: "compiled", UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
		} else {
			executor, err := fabric.NewExecutor(c, fabric.OSRunner{})
			if err != nil {
				return failure("FABRIC_CONFIG_REJECTED")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			r, e = executor.Apply(ctx, t, *confirm)
			cancel()
		}
	}
	if r.Schema != 0 {
		if json.NewEncoder(out).Encode(r) != nil {
			return 1
		}
	}
	if e != nil {
		return failure("FABRIC_OPERATION_UNCONFIRMED")
	}
	return 0
}
func main() {
	code := run(os.Args[1:], os.Stdout, os.Stderr)
	if code == 2 {
		fmt.Fprintln(os.Stderr, "usage: aster-network plan|status|verify|fingerprint|overlay-fingerprint|apply --config FILE [--topology FILE] [--confirm-bridge BRIDGE] [--revision N]")
	}
	os.Exit(code)
}

package main

import (
	"aster/cloud/internal/fabric"
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestCLIInvalidArgumentsNeverEchoSecrets(t *testing.T) {
	for _, args := range [][]string{{}, {"destroy"}, {"apply", "--password", "secret-token"}, {"apply", "--config", "/private/secret-token"}, {"status", "--config", "/private/secret-token"}} {
		var out, err bytes.Buffer
		code := run(args, &out, &err)
		if code == 0 || strings.Contains(out.String()+err.String(), "secret-token") {
			t.Fatal(code, out.String(), err.String())
		}
	}
}

func TestVerifyAcceptsOnlyFixedPrivateConfigNotTopologyRevisionOrBridge(t *testing.T) {
	for _, args := range [][]string{{"verify", "--config", "/missing", "--topology", "/private/secret-token"}, {"verify", "--config", "/missing", "--topology", ""}, {"verify", "--config", "/missing", "--revision", "1"}, {"verify", "--config", "/missing", "--revision", "0"}, {"verify", "--config", "/missing", "--confirm-bridge", "aster-vpc"}} {
		var out, err bytes.Buffer
		if code := run(args, &out, &err); code != 1 || out.Len() != 0 || !strings.Contains(err.String(), "INVALID_ARGUMENTS") || strings.Contains(err.String(), "secret-token") {
			t.Fatal(code, out.String(), err.String())
		}
	}
	var out, err bytes.Buffer
	if code := run([]string{"verify", "--config", "/private/secret-token"}, &out, &err); code != 1 || out.Len() != 0 || strings.Contains(err.String(), "secret-token") || !strings.Contains(err.String(), "FABRIC_CONFIG_REJECTED") {
		t.Fatal(code, out.String(), err.String())
	}
}

func TestFingerprintAcceptsOnlyPrivateConfigAndDoesNotEchoPaths(t *testing.T) {
	for _, args := range [][]string{{"fingerprint", "--config", "/private/secret-token", "--topology", ""}, {"fingerprint", "--config", "/private/secret-token", "--revision", "0"}, {"fingerprint", "--config", "/private/secret-token", "--confirm-bridge", "aster-vpc"}} {
		var out, stderr bytes.Buffer
		if code := run(args, &out, &stderr); code != 1 || out.Len() != 0 || !strings.Contains(stderr.String(), "INVALID_ARGUMENTS") || strings.Contains(stderr.String(), "secret-token") {
			t.Fatal(code, out.String(), stderr.String())
		}
	}
}

func TestOverlayFingerprintOnlyAcceptsPrivateConfigAndNeverEchoesPaths(t *testing.T) {
	for _, extra := range [][]string{{"--topology", ""}, {"--revision", "0"}, {"--confirm-bridge", "aster-vpc"}} {
		args := append([]string{"overlay-fingerprint", "--config", "/private/secret-token"}, extra...)
		var out, stderr bytes.Buffer
		if code := run(args, &out, &stderr); code != 1 || out.Len() != 0 || !strings.Contains(stderr.String(), "INVALID_ARGUMENTS") || strings.Contains(stderr.String(), "secret-token") {
			t.Fatal(code, out.String(), stderr.String())
		}
	}
	var out, stderr bytes.Buffer
	if code := run([]string{"overlay-fingerprint", "--config", "/private/secret-token"}, &out, &stderr); code != 1 || out.Len() != 0 || !strings.Contains(stderr.String(), "OVERLAY_CONFIG_REJECTED") || strings.Contains(stderr.String(), "secret-token") {
		t.Fatal(code, out.String(), stderr.String())
	}
}

func TestOverlayExampleFailsClosedUntilOperatorApproval(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/overlay-private.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fabric.DecodeOverlayConfig(raw); err == nil {
		t.Fatal("unreviewed deployment example was executable")
	}
	var cfg fabric.OverlayConfig
	if err = json.Unmarshal(raw, &cfg); err != nil || cfg.Base.DedicatedAck || cfg.UnderlayTrustedAck {
		t.Fatal("example silently approves host mutation", err)
	}
	cfg.Base.DedicatedAck = true
	cfg.UnderlayTrustedAck = true
	raw, _ = json.Marshal(cfg)
	approved, err := fabric.DecodeOverlayConfig(raw)
	if err != nil {
		t.Fatal("example contains invalid fields in addition to explicit approvals", err)
	}
	sha, err := fabric.OverlayConfigSHA256(approved)
	if err != nil || len(sha) != 64 {
		t.Fatal("approved config cannot be fingerprinted", err)
	}
	pretty, _ := json.MarshalIndent(approved, "", "  ")
	decoded, err := fabric.DecodeOverlayConfig(pretty)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := fabric.OverlayConfigSHA256(decoded)
	if sha != other {
		t.Fatal("whitespace changed root object fingerprint")
	}
}

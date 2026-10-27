package main

import (
	"strings"
	"testing"
)

func TestParseArgsRejectsExplicitEmptyOrMalformedReconcileBeforeIO(t *testing.T) {
	for name, args := range map[string][]string{
		"empty_separate":        {"--reconcile-operation", ""},
		"empty_equal":           {"--reconcile-operation="},
		"short":                 {"--reconcile-operation", "0"},
		"traversal":             {"--reconcile-operation", "../../domain"},
		"uppercase":             {"--reconcile-operation", strings.Repeat("A", 32)},
		"whitespace":            {"--reconcile-operation", strings.Repeat("a", 32) + " "},
		"doctor_empty":          {"--doctor", "--reconcile-operation="},
		"doctor_valid":          {"--doctor", "--reconcile-operation", strings.Repeat("a", 32)},
		"explicit_doctor_false": {"--doctor=false", "--reconcile-operation", strings.Repeat("a", 32)},
		"positional":            {"serve"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := parseArgs(args); e == nil {
				t.Fatal("unsafe mode parsed as serve", args)
			}
		})
	}
}
func TestParseArgsPreservesExplicitModes(t *testing.T) {
	o, e := parseArgs(nil)
	if e != nil || o.doctor || o.reconcileProvided || o.config != "/etc/aster-node/node.json" {
		t.Fatal(o, e)
	}
	o, e = parseArgs([]string{"--doctor", "--config", "/absolute/config.json"})
	if e != nil || !o.doctor || o.reconcileProvided || o.config != "/absolute/config.json" {
		t.Fatal(o, e)
	}
	id := strings.Repeat("a", 32)
	o, e = parseArgs([]string{"--reconcile-operation", id})
	if e != nil || !o.reconcileProvided || o.reconcile != id || o.doctor {
		t.Fatal(o, e)
	}
}

func TestRootImportApprovalModeRequiresExactPairedFlags(t *testing.T) {
	id := strings.Repeat("a", 32)
	token := strings.Repeat("b", 64)
	for _, args := range [][]string{{"--approve-storage-import="}, {"--approve-storage-import", id}, {"--reviewed-source-fence", token}, {"--approve-storage-import", id, "--reviewed-source-fence", ""}, {"--approve-storage-import", id, "--reviewed-source-fence", strings.Repeat("G", 64)}, {"--approve-storage-import", id, "--reviewed-source-fence", token, "--doctor"}, {"--approve-storage-import", id, "--reviewed-source-fence", token, "--reconcile-operation", id}} {
		if _, e := parseArgs(args); e == nil {
			t.Fatal("unsafe approval entered serve", args)
		}
	}
	o, e := parseArgs([]string{"--approve-storage-import", id, "--reviewed-source-fence", token})
	if e != nil || !o.approveProvided || o.approveImport != id || o.reviewedFence != token {
		t.Fatal(o, e)
	}
}

func TestNetworkRecoveryModesRejectAmbiguityBeforeIO(t *testing.T) {
	for _, args := range [][]string{{"--network-recovery-status="}, {"--recover-network="}, {"--recover-network", "relative.json"}, {"--recover-network", "/etc/../tmp/approval.json"}, {"--network-recovery-status", "private-v1", "--doctor=false"}, {"--recover-network", "/root/recovery.json", "--network-recovery-status", "private-v1"}, {"--recover-network", "/root/recovery.json", "--reconcile-operation", strings.Repeat("a", 32)}, {"--recover-network", "/root/recovery.json", "--reviewed-source-fence", strings.Repeat("a", 64)}} {
		if _, e := parseArgs(args); e == nil {
			t.Fatal("unsafe recovery parsed", args)
		}
	}
	for _, args := range [][]string{{"--network-recovery-status", "private-v1"}, {"--recover-network", "/root/recovery.json"}} {
		if _, e := parseArgs(args); e != nil {
			t.Fatal(e)
		}
	}
}

func TestPublicFilterPrintIsStandaloneAndNeverFallsBackToServe(t *testing.T) {
	for _, args := range [][]string{{"--print-public-network-filter="}, {"--print-public-network-filter", "../../../filter"}, {"--print-public-network-filter", "filter"}, {"--print-public-network-filter", "aster-public", "--doctor=false"}, {"--print-public-network-filter", "aster-public", "--config", "/etc/node.json"}, {"--print-public-network-filter", "aster-public", "serve"}} {
		if _, e := parseArgs(args); e == nil {
			t.Fatal("unsafe print mode reached config or serve", args)
		}
	}
	o, e := parseArgs([]string{"--print-public-network-filter", "aster-public-ipv4"})
	if e != nil || !o.printPublicFilterProvided || o.printPublicFilter != "aster-public-ipv4" {
		t.Fatal(o, e)
	}
}

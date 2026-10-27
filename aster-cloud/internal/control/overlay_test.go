package control

import (
	"aster/cloud/internal/overlayproto"
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
)

func TestOverlayBarrierNeverUsesQuorumOrUnknownAsSuccess(t *testing.T) {
	for _, phase := range []string{"prepare", "program", "release"} {
		for _, bad := range []string{"pending", "sending", "uncertain", "rejected"} {
			next, state, e := overlayBarrier(phase, []string{"succeeded", bad})
			if e != nil || next != phase || state == "succeeded" {
				t.Fatalf("%s/%s advanced: %s %s %v", phase, bad, next, state, e)
			}
		}
		next, state, e := overlayBarrier(phase, []string{"succeeded", "succeeded"})
		if e != nil {
			t.Fatal(e)
		}
		if phase == "release" && state != "succeeded" || phase != "release" && next == phase {
			t.Fatal(next, state)
		}
	}
	if _, _, e := overlayBarrier("program", []string{"unknown"}); e == nil {
		t.Fatal("foreign state accepted")
	}
}
func TestOverlayClusterRootApprovalIsExplicitAndNonAliased(t *testing.T) {
	p := testProfile()
	c := testConfig(p)
	c.OverlayClusters = []OverlayCluster{{ClusterID: "test-cluster", Profiles: []overlayproto.ProfilePin{{NodeID: p.ID, ProfileID: "vpc-profile", ProfileSHA256: strings.Repeat("1", 64)}}}}
	if !c.Valid() {
		t.Fatal("approved cluster invalid")
	}
	c.OverlayClusters = append(c.OverlayClusters, OverlayCluster{ClusterID: "other", Profiles: c.OverlayClusters[0].Profiles})
	if c.Valid() {
		t.Fatal("same node/profile acquired independent cluster executor")
	}
	c.OverlayClusters = c.OverlayClusters[:1]
	c.OverlayClusters[0].Profiles[0].ProfileSHA256 = ""
	if c.Valid() {
		t.Fatal("unpinned overlay accepted")
	}
}

func TestOverlayRunnerDuplicateStartAndShutdownFence(t *testing.T) {
	r := NewOverlayRunner(OverlayWorker{})
	entered := make(chan struct{})
	var count atomic.Int32
	r.run = func(ctx context.Context, _ string) error {
		count.Add(1)
		close(entered)
		<-ctx.Done()
		return ctx.Err()
	}
	op := strings.Repeat("1", 32)
	if e := r.Start(op); e != nil {
		t.Fatal(e)
	}
	<-entered
	for i := 0; i < 10; i++ {
		if e := r.Start(op); e != nil {
			t.Fatal(e)
		}
	}
	if count.Load() != 1 {
		t.Fatal("duplicate worker")
	}
	r.Close()
	if e := r.Start(op); !errors.Is(e, ErrUnavailable) {
		t.Fatal("restart after closing", e)
	}
}

func TestOverlayRecoveryReplacementStrictCanonicalIntent(t *testing.T) {
	sha := strings.Repeat("a", 64)
	valid := `{"expected_snapshot_sha256":"` + sha + `","replacement":{"members":[],"gateways":[]}}`
	var in OverlayRecoveryInput
	if !strict([]byte(valid), &in) || in.Replacement == nil {
		t.Fatal("complete replacement rejected")
	}
	for _, bad := range []string{
		`{"expected_snapshot_sha256":"` + sha + `","replacement":null}`,
		`{"expected_snapshot_sha256":"` + sha + `","replacement":{}}`,
		`{"expected_snapshot_sha256":"` + sha + `","replacement":{"members":null,"gateways":[]}}`,
		`{"expected_snapshot_sha256":"` + sha + `","replacement":{"members":[],"gateways":null}}`,
		`{"expected_snapshot_sha256":"` + sha + `","replacement":{"members":[],"members":[],"gateways":[]}}`,
		`{"expected_snapshot_sha256":"` + sha + `","replacement":{"members":[],"gateways":[],"cluster_id":"other"}}`,
		`{"expected_snapshot_sha256":"` + sha + `","replacement":{"Members":[],"gateways":[]}}`,
		strings.TrimSuffix(valid, "}") + `,"replacement":{"members":[],"gateways":[]}}`,
	} {
		var out OverlayRecoveryInput
		if strict([]byte(bad), &out) {
			t.Fatalf("invalid replacement accepted: %s", bad)
		}
	}
	in.Replacement.Members = []OverlayMemberInput{{InstanceID: strings.Repeat("2", 32), VPCID: strings.Repeat("3", 32), Enabled: true}, {InstanceID: strings.Repeat("1", 32), VPCID: strings.Repeat("3", 32), Enabled: true}}
	a, e := canonicalOverlayRecoveryInput(in)
	if e != nil || in.Replacement.Members[0].InstanceID != strings.Repeat("2", 32) {
		t.Fatal("canonicalization mutated caller", e)
	}
	b := in
	b.Replacement = &OverlayReplacementInput{Members: []OverlayMemberInput{in.Replacement.Members[1], in.Replacement.Members[0]}, Gateways: []overlayproto.Gateway{}}
	b, e = canonicalOverlayRecoveryInput(b)
	if e != nil || overlayRecoveryDigest("original", a) != overlayRecoveryDigest("original", b) {
		t.Fatal("array order changed intent", e)
	}
	b.Replacement.Members[0].Enabled = false
	if overlayRecoveryDigest("original", a) == overlayRecoveryDigest("original", b) {
		t.Fatal("changed intent retained request SHA")
	}
	if _, e = canonicalOverlayRecoveryInput(OverlayRecoveryInput{ExpectedSnapshotSHA256: sha, Replacement: &OverlayReplacementInput{Gateways: []overlayproto.Gateway{}}}); !errors.Is(e, ErrInput) {
		t.Fatal("nil members accepted", e)
	}
}
func TestOverlayMappingMustBeExplicitAndExact(t *testing.T) {
	c := OverlayCluster{Mappings: []OverlayMapping{{NodeID: "node-a", LocalVPCID: strings.Repeat("1", 32), VPCID: strings.Repeat("2", 32)}}}
	if !overlayMappingMatches(c, "node-a", strings.Repeat("1", 32), strings.Repeat("2", 32)) {
		t.Fatal("approved mapping rejected")
	}
	for _, m := range []OverlayMapping{{NodeID: "node-b", LocalVPCID: strings.Repeat("1", 32), VPCID: strings.Repeat("2", 32)}, {NodeID: "node-a", LocalVPCID: strings.Repeat("2", 32), VPCID: strings.Repeat("2", 32)}, {NodeID: "node-a", LocalVPCID: strings.Repeat("1", 32), VPCID: strings.Repeat("3", 32)}} {
		if overlayMappingMatches(c, m.NodeID, m.LocalVPCID, m.VPCID) {
			t.Fatal("unapproved mapping accepted")
		}
	}
}

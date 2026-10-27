package fabric

import (
	"aster/cloud/internal/overlayproto"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func migrationFixture(t *testing.T) (*Executor, *overlayFake, OverlayConfig, overlayproto.Snapshot, overlayproto.Task) {
	t.Helper()
	e, f, c, s := overlayFixture(t)
	overlayRun(t, e, c, s)
	old, snapshotSHA, _ := overlayproto.CanonicalSnapshot(s)
	oldPin, _ := OverlayConfigSHA256(c)
	c.PreviousProfileSHA256 = oldPin
	c.TrustReference = "new-root-approved-network-profile"
	newPin, err := OverlayConfigSHA256(c)
	if err != nil {
		t.Fatal(err)
	}
	s.Epoch++
	s.PreviousSHA256 = snapshotSHA
	s.Profiles[0].ProfileSHA256 = newPin
	t0 := overlayTask(t, s, "prepare")
	t0.Recovery = &overlayproto.Recovery{Epoch: old.Epoch, SnapshotSHA256: snapshotSHA, Heads: []overlayproto.Head{{NodeID: c.Base.NodeID, ClusterID: s.ClusterID, Epoch: old.Epoch, SnapshotSHA256: snapshotSHA}, {NodeID: "node-b", ClusterID: s.ClusterID, Epoch: old.Epoch, SnapshotSHA256: snapshotSHA}}}
	f.config = c
	return e, f, c, s, t0
}
func TestOverlayProfileMigrationOnlyExplicitApprovedRecovery(t *testing.T) {
	for _, name := range []string{"success", "ordinary-prepare", "missing-approval", "wrong-pin", "wrong-head", "foreign-node"} {
		t.Run(name, func(t *testing.T) {
			e, f, c, s, task := migrationFixture(t)
			switch name {
			case "ordinary-prepare":
				task.Recovery = nil
			case "missing-approval":
				c.PreviousProfileSHA256 = ""
			case "wrong-pin":
				c.PreviousProfileSHA256 = strings.Repeat("d", 64)
			case "wrong-head":
				task.Recovery.Heads[0].SnapshotSHA256 = strings.Repeat("e", 64)
			case "foreign-node":
				task.NodeID = "node-b"
			}
			if name == "missing-approval" || name == "wrong-pin" {
				sha, _ := OverlayConfigSHA256(c)
				task.Snapshot.Profiles[0].ProfileSHA256 = sha
				task.Snapshot, task.SnapshotSHA256, _ = overlayproto.CanonicalSnapshot(task.Snapshot)
			}
			calls := f.calls
			r, err := e.PrepareOverlay(context.Background(), c, task, func(context.Context) error { return nil })
			if name != "success" {
				if err == nil || f.calls != calls {
					t.Fatal("unapproved migration changed data plane", r, err)
				}
				return
			}
			if err != nil {
				t.Fatal(r, err)
			}
			evidence, err := readPrivate(filepath.Join(c.Base.StateDirectory, "overlay-profile-migration-"+task.OperationID+".json"), uint32(os.Geteuid()), 4096)
			if err != nil {
				t.Fatal(err)
			}
			var proof overlayProfileMigration
			if json.Unmarshal(evidence, &proof) != nil || proof.PreviousProfileSHA256 != c.PreviousProfileSHA256 || proof.OperationID != task.OperationID {
				t.Fatal("missing exact migration proof")
			}
			for _, phase := range []string{"program", "release"} {
				next := overlayTask(t, s, phase)
				next.Recovery = task.Recovery
				var err error
				if phase == "program" {
					_, err = e.ProgramOverlay(context.Background(), c, next)
				} else {
					_, err = e.ReleaseOverlay(context.Background(), c, next, func(context.Context) error { return nil })
				}
				if err != nil {
					t.Fatal(phase, err)
				}
			}
			if _, err = e.CheckOverlay(context.Background(), c); err != nil {
				t.Fatal(err)
			}
			old := c
			old.PreviousProfileSHA256 = ""
			if _, err = e.CheckOverlay(context.Background(), old); err == nil {
				t.Fatal("removed approval silently changed profile")
			}
		})
	}
}
func TestOverlayProfileMigrationDurableFailuresNeverReexecute(t *testing.T) {
	for _, stage := range []string{"before_write", "before_sync", "before_rename", "after_rename", "after_dir_sync"} {
		for _, target := range []string{"overlay-op-", "overlay-profile-migration-", "journal.json"} {
			t.Run(stage+"/"+target, func(t *testing.T) {
				e, f, c, _, task := migrationFixture(t)
				fired := false
				e.fault = func(event string) error {
					if !fired && strings.Contains(event, target) && strings.HasSuffix(event, ":"+stage) {
						fired = true
						return ErrUnavailable
					}
					return nil
				}
				calls := f.calls
				_, err := e.PrepareOverlay(context.Background(), c, task, func(context.Context) error { return nil })
				if !fired {
					t.Fatal("fault hook not exercised", stage, target)
				}
				if err == nil || f.calls != calls {
					t.Fatal("uncertain migration changed hosts", err)
				}
				e.fault = nil
				// Reopen with exact durable files: no successful receipt is fabricated, and
				// an existing unknown operation never gets replayed after process restart.
				raw, _, te := task.BytesAndDigest()
				if te != nil {
					t.Fatal(te)
				}
				again, te := overlayproto.DecodeTask(raw)
				if te != nil {
					t.Fatal(te)
				}
				calls = f.calls
				if _, staterr := os.Stat(filepath.Join(c.Base.StateDirectory, overlayOpName(task.OperationID))); staterr == nil {
					if _, err = e.PrepareOverlay(context.Background(), c, again, func(context.Context) error { return nil }); err == nil || f.calls != calls {
						t.Fatal("unknown migration was retried", err)
					}
				}
			})
		}
	}
}

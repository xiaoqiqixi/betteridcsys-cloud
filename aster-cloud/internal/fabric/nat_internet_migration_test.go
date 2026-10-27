package fabric

import (
	"aster/cloud/internal/overlayproto"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNATInternetCapabilityUpgradeRequiresExplicitRecovery(t *testing.T) {
	for _, name := range []string{"ordinary-prepare", "missing-old-NAT-approval", "explicit-recovery"} {
		t.Run(name, func(t *testing.T) {
			e, f, c, s := internetNATFixture(t)
			// Prepare the real previous state first, using the same public-syntax
			// interface addresses but no Internet permission and no prefix route.
			c.NATProfiles[0].AllowInternetEgress = false
			c.GuestNetworks[0].AllowInternetEgress = false
			s.NATPolicies[0].InternetEgressEnabled = false
			oldFullSHA, err := OverlayConfigSHA256(c)
			if err != nil {
				t.Fatal(err)
			}
			oldNATSHA, err := NATProfileSHA256(c.NATProfiles[0])
			if err != nil {
				t.Fatal(err)
			}
			s.Profiles[0].ProfileSHA256 = oldFullSHA
			s.NATPolicies[0].ProfileSHA256 = oldNATSHA
			f.config, f.profile, f.snapshot = c, c.NATProfiles[0], s
			overlayRun(t, e, c, s)
			oldSnapshot, oldSnapshotSHA, err := overlayproto.CanonicalSnapshot(s)
			if err != nil {
				t.Fatal(err)
			}
			oldSnapshotBytes, _ := json.Marshal(oldSnapshot)
			oldMemberBindings := map[string]string{}
			for _, m := range oldSnapshot.Members {
				oldMemberBindings[m.InstanceID] = m.NetworkSHA256
			}
			read := func(name string) []byte {
				t.Helper()
				raw, err := os.ReadFile(filepath.Join(c.Base.StateDirectory, name))
				if err != nil {
					t.Fatal(name, err)
				}
				return raw
			}
			// Each immutable operation file includes both the original task's
			// snapshot and its receipt; the mutable overlay.owner is the live head,
			// not historical evidence to be silently reclassified as immutable.
			oldFiles := map[string][]byte{}
			for _, phase := range []string{"prepare", "program", "release"} {
				file := overlayOpName(overlayTask(t, oldSnapshot, phase).OperationID)
				oldFiles[file] = read(file)
			}
			oldOwnerBytes := read(natOwnerName(c.NATProfiles[0]))
			oldRules, _ := json.Marshal(f.rules)
			oldFlows, oldForward, oldCalls, oldNATCalls := f.base.flows, f.forward, f.calls, f.callsNAT
			if strings.Contains(string(oldRules), "internet_") {
				t.Fatal("disabled previous state already had public rules")
			}

			// Both permissions change together, but neither a controller epoch nor
			// a new full profile pin can authorize the old namespace owner's upgrade
			// without its exact previous NAT SHA and explicit recovery heads.
			c.PreviousProfileSHA256 = oldFullSHA
			c.NATProfiles[0].AllowInternetEgress = true
			c.NATProfiles[0].PreviousProfileSHA256 = oldNATSHA
			c.GuestNetworks[0].AllowInternetEgress = true
			if name == "missing-old-NAT-approval" {
				c.NATProfiles[0].PreviousProfileSHA256 = ""
			}
			newFullSHA, err := OverlayConfigSHA256(c)
			if err != nil {
				t.Fatal(err)
			}
			newNATSHA, err := NATProfileSHA256(c.NATProfiles[0])
			if err != nil {
				t.Fatal(err)
			}
			s.Epoch++
			s.PreviousSHA256 = oldSnapshotSHA
			s.Profiles[0].ProfileSHA256 = newFullSHA
			s.NATPolicies[0].ProfileSHA256 = newNATSHA
			s.NATPolicies[0].InternetEgressEnabled = true
			recovery := &overlayproto.Recovery{Epoch: oldSnapshot.Epoch, SnapshotSHA256: oldSnapshotSHA, Heads: []overlayproto.Head{
				{NodeID: c.Base.NodeID, ClusterID: s.ClusterID, Epoch: oldSnapshot.Epoch, SnapshotSHA256: oldSnapshotSHA},
				{NodeID: "node-b", ClusterID: s.ClusterID, Epoch: oldSnapshot.Epoch, SnapshotSHA256: oldSnapshotSHA},
			}}
			task := overlayTask(t, s, "prepare")
			if name != "ordinary-prepare" {
				task.Recovery = recovery
			}
			f.config, f.profile, f.snapshot = c, c.NATProfiles[0], s
			ctx := context.Background()
			r, err := e.PrepareOverlay(ctx, c, task, func(context.Context) error { return nil })
			if name != "explicit-recovery" {
				if err == nil || r.Status == "succeeded" {
					t.Fatal("unapproved public capability upgrade succeeded", r, err)
				}
				if name == "ordinary-prepare" {
					rules, _ := json.Marshal(f.rules)
					if f.calls != oldCalls || f.callsNAT != oldNATCalls || f.base.flows != oldFlows || f.forward != oldForward || !bytes.Equal(rules, oldRules) {
						t.Fatal("ordinary prepare mutated data plane while changing root capabilities")
					}
				} else if f.forward != "0" {
					t.Fatal("missing old NAT approval did not retain namespace isolation")
				}
				if !bytes.Equal(read(natOwnerName(c.NATProfiles[0])), oldOwnerBytes) {
					t.Fatal("rejected upgrade changed the old NAT owner")
				}
			} else {
				if err != nil || r.Status != "succeeded" {
					t.Fatal("explicit public recovery prepare", r, err)
				}
				for _, phase := range []string{"program", "release"} {
					next := overlayTask(t, s, phase)
					next.Recovery = recovery
					if phase == "program" {
						r, err = e.ProgramOverlay(ctx, c, next)
					} else {
						r, err = e.ReleaseOverlay(ctx, c, next, func(context.Context) error { return nil })
					}
					if err != nil || r.Status != "succeeded" {
						t.Fatal("public recovery "+phase, r, err)
					}
				}
				if _, err := e.CheckOverlay(ctx, c); err != nil {
					t.Fatal("upgraded public capability readiness", err)
				}
				if f.forward != "1" {
					t.Fatal("public recovery was not released")
				}
				raw, _ := json.Marshal(f.rules)
				if !strings.Contains(string(raw), "internet_out") || !strings.Contains(f.base.flows, "priority=190,") {
					t.Fatal("successful recovery did not install public namespace and OVS paths")
				}
				var owner natOwnership
				if json.Unmarshal(read(natOwnerName(c.NATProfiles[0])), &owner) != nil || owner.ProfileSHA256 != newNATSHA || !owner.Profile.AllowInternetEgress || owner.Profile.PreviousProfileSHA256 != oldNATSHA {
					t.Fatal("exact upgraded NAT owner was not persisted")
				}
				// Evidence files are mandatory, not just a new journal pin.
				read("overlay-profile-migration-" + task.OperationID + ".json")
				read("nat-profile-migration-" + c.NATProfiles[0].ID + "-" + task.OperationID + ".json")
				live, state, err := ReadOverlaySnapshot(c)
				if err != nil || state != "applied" || !live.NATPolicies[0].InternetEgressEnabled {
					t.Fatal("public head not applied", state, err)
				}
				for _, m := range live.Members {
					if m.NetworkSHA256 != oldMemberBindings[m.InstanceID] {
						t.Fatal("upgrade rewrote original node/2 network binding", m.InstanceID)
					}
				}
			}
			for file, original := range oldFiles {
				if !bytes.Equal(read(file), original) {
					t.Fatal("old task/snapshot/receipt bytes rewritten", file)
				}
				var op overlayOperation
				if json.Unmarshal(read(file), &op) != nil {
					t.Fatal("old operation became unreadable", file)
				}
				got, _ := json.Marshal(op.Task.Snapshot)
				if !bytes.Equal(got, oldSnapshotBytes) {
					t.Fatal("original operation snapshot changed", file)
				}
			}
		})
	}
}

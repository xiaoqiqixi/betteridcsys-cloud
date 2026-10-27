package hypervisor

import (
	"aster/cloud/internal/fabric"
	"aster/cloud/internal/nodeproto"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"testing"
)

func TestOVSEarlyNetworkFailuresIndependentlyFenceOwnedGuest(t *testing.T) {
	for _, action := range []string{"start", "shutdown", "force_off"} {
		for _, failure := range []string{"gate-construction", "gate-before-callback", "boot-policy", "link-observation"} {
			if action != "start" && (failure == "boot-policy" || failure == "link-observation") {
				continue
			}
			t.Run(action+"/"+failure, func(t *testing.T) {
				m, r, g, task := newOVSFixture(t)
				requireOVSSuccess(t, m, task)
				i, _ := m.Ledger.Instance(task.InstanceID)
				switch failure {
				case "gate-construction":
					m.ovsFactory = func(fabric.Config) (ovsGate, error) { return nil, errors.New("unavailable network gate") }
				case "gate-before-callback":
					if action == "start" {
						g.fail = "check"
					} else {
						g.fail = "stop"
					}
				case "boot-policy":
					r.autostart = true
				case "link-observation":
					r.linkOutput = "invalid"
				}
				q := next(task, "e", action)
				result := submit(t, m, q)
				if result.Status != "uncertain" || r.states[i.Domain] != "paused" || r.links[i.Domain] != "down" {
					t.Fatalf("network failure left a live guest: status=%s power=%s link=%s", result.Status, r.states[i.Domain], r.links[i.Domain])
				}
				if r.count(" destroy ") != 0 || r.count(" shutdown ") != 0 || r.count(" start ") != 1 || r.count(" resume ") != 1 {
					t.Fatal("safety fence retried/destructively stopped", r.commands)
				}
				before := len(r.commands)
				if again := submit(t, m, q); again != result || len(r.commands) != before {
					t.Fatal("unknown operation retried", again)
				}
				if _, err := m.Reconcile(context.Background(), q.OperationID); err == nil {
					t.Fatal("fence mistaken for confirmed operation")
				}
			})
		}
	}
}

func TestOVSEarlySafetyFenceDoesNotTouchForeignOrOfflineGuest(t *testing.T) {
	for _, state := range []string{"foreign", "offline"} {
		t.Run(state, func(t *testing.T) {
			m, r, g, task := newOVSFixture(t)
			requireOVSSuccess(t, m, task)
			if state == "offline" {
				requireOVSSuccess(t, m, next(task, "d", "force_off"))
			}
			i, _ := m.Ledger.Instance(task.InstanceID)
			if state == "foreign" {
				var d domainXML
				if err := xml.Unmarshal(r.domains[i.Domain], &d); err != nil {
					t.Fatal(err)
				}
				d.Metadata.Instance.OwnerRef = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
				raw, err := xml.Marshal(d)
				if err != nil {
					t.Fatal(err)
				}
				r.domains[i.Domain] = raw
			}
			g.fail = "stop"
			beforeLink, beforeSuspend, beforeDestroy := r.count(" domif-setlink "), r.count(" suspend "), r.count(" destroy ")
			q := next(task, "e", "force_off")
			raw, err := json.Marshal(q)
			if err != nil {
				t.Fatal(err)
			}
			sha := nodeproto.Digest(raw)
			if err = m.stopOVS(context.Background(), i, q, sha, "destroy"); err == nil {
				t.Fatal("failed gate became success")
			}
			if r.count(" domif-setlink ") != beforeLink || r.count(" suspend ") != beforeSuspend || r.count(" destroy ") != beforeDestroy {
				t.Fatal("fence mutated foreign/offline domain", r.commands)
			}
		})
	}
}

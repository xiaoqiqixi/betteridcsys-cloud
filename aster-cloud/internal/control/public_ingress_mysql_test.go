package control

import (
	"aster/cloud/internal/identity"
	"aster/cloud/internal/networking"
	"aster/cloud/internal/nodeproto"
	"aster/cloud/internal/overlayproto"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

type ingressFixture struct {
	overlayFixture
	worker   OverlayWorker
	rpc      *overlayFakeRPC
	resource PublicIPResource
}

func mysqlIngressFixture(t *testing.T) ingressFixture {
	t.Helper()
	f, g, _, poolIn := mysqlPublicIPFixture(t)
	ctx := context.Background()
	f.config.OverlayClusters[0].NATProfiles[0].AllowFloatingIP = true
	pool, _, _, e := f.store.CreatePublicIPPool(ctx, f.config, f.actor, id(), poolIn, f.now)
	if e != nil {
		t.Fatal(e)
	}
	none := []overlayproto.NATPolicy{}
	initial, _, e := f.store.PlanOverlayEpoch(ctx, f.config, f.actor, id(), OverlayEpochInput{ClusterID: f.vpc.ClusterID, Members: f.members, Gateways: []overlayproto.Gateway{g}, NATPolicies: &none}, f.now)
	if e != nil {
		t.Fatal(e)
	}
	rpc := &overlayFakeRPC{}
	w := f.worker(rpc)
	advanceOverlayFixture(t, w, initial.ID)
	root := f.config.OverlayClusters[0].NATProfiles[0]
	r, _, _, e := f.store.AllocatePublicIPResource(ctx, f.config, f.actor, id(), PublicIPResourceInput{PoolID: pool.ID, OwnerRef: f.vpc.OwnerRef, Mode: "floating", NodeID: root.NodeID, ProfileID: root.ProfileID, VPCID: f.vpc.ID, Address: "8.8.8.9"}, f.now)
	if e != nil {
		t.Fatal(e)
	}
	return ingressFixture{f, w, rpc, r}
}
func ingressRevision(n uint64) *uint64 { return &n }
func ingressRule(port int) overlayproto.PublicIngressRule {
	return overlayproto.PublicIngressRule{ID: id(), Protocol: "tcp", SourceCIDR: "9.9.9.9/32", PortStart: port, PortEnd: port}
}
func (f ingressFixture) view(t *testing.T, instance string) PublicIngressView {
	t.Helper()
	v, e := f.store.PublicIngress(context.Background(), f.config, instance, f.now)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func (f ingressFixture) bind(t *testing.T, instance string, generation, revision uint64) PublicIPResource {
	t.Helper()
	r, _, _, e := f.store.BindPublicIPResourceWithIngress(context.Background(), f.config, f.actor, id(), f.resource.ID, instance, false, generation, &revision, f.now)
	if e != nil {
		t.Fatal("bind", e)
	}
	return r
}
func TestMySQLPublicIngressDefaultBindPolicyMoveAndRevoke(t *testing.T) {
	f := mysqlIngressFixture(t)
	ctx := context.Background()
	vm0, vm1 := f.members[0].InstanceID, f.members[1].InstanceID
	v := f.view(t, vm0)
	if !v.Supported || v.State != "default" || v.Revision != 0 || v.EffectiveRevision == nil || *v.EffectiveRevision != 0 || v.Rules == nil || len(v.Rules) != 0 || v.LegacyUnrestricted {
		t.Fatal("default policy", v)
	}
	r := f.bind(t, vm0, 0, 0)
	epoch, e := f.store.OverlayEpoch(ctx, r.EpochID)
	if e != nil {
		t.Fatal(e)
	}
	oldBytes, _ := json.Marshal(epoch.Snapshot)
	if p := epoch.Snapshot.FloatingIPs[0].Ingress; p == nil || p.Revision != 0 || len(p.Rules) != 0 || p.InstanceID != vm0 {
		t.Fatal("new bind did not freeze default deny", p)
	}
	if v = f.view(t, vm0); v.State != "pending" || v.EffectiveRevision != nil {
		t.Fatal("bind ACK became effective", v)
	}
	advanceOverlayFixture(t, f.worker, r.EpochID)
	if v = f.view(t, vm0); v.State != "active" || v.EffectiveRevision == nil || *v.EffectiveRevision != 0 {
		t.Fatal("default deny release", v)
	}
	key := id()
	rules := []overlayproto.PublicIngressRule{ingressRule(443)}
	pending, op, replay, e := f.store.SetPublicIngress(ctx, f.config, f.actor, vm0, key, PublicIngressInput{ExpectedRevision: ingressRevision(0), Rules: rules}, f.now)
	if e != nil || replay || pending.State != "pending" || pending.Revision != 1 || pending.EffectiveRevision != nil {
		t.Fatal("policy ACK", pending, e)
	}
	if current, e := f.store.PublicIPResource(ctx, f.config, r.ID); e != nil || current.BindingGeneration != 2 || current.BindingState != "pending" {
		t.Fatal("policy did not fence binding edit", current, e)
	}
	if _, _, _, e = f.store.SetPublicIngress(ctx, f.config, f.actor, vm0, id(), PublicIngressInput{ExpectedRevision: ingressRevision(1), Rules: []overlayproto.PublicIngressRule{}}, f.now); !errors.Is(e, ErrState) {
		t.Fatal("new key bypassed pending", e)
	}
	for i := 0; i < 5; i++ {
		if _, e = f.worker.Advance(ctx, pending.EpochID); e != nil {
			t.Fatal(e)
		}
	}
	if v = f.view(t, vm0); v.State != "pending" || v.EffectiveRevision != nil {
		t.Fatal("partial release became active", v)
	}
	if _, e = f.worker.Advance(ctx, pending.EpochID); e != nil {
		t.Fatal(e)
	}
	if v = f.view(t, vm0); v.State != "active" || v.EffectiveRevision == nil || *v.EffectiveRevision != 1 || !reflect.DeepEqual(v.Rules, rules) {
		t.Fatal("confirmed policy", v)
	}
	r = f.bind(t, vm1, 2, 0)
	moved, e := f.store.OverlayEpoch(ctx, r.EpochID)
	if e != nil {
		t.Fatal(e)
	}
	if p := moved.Snapshot.FloatingIPs[0].Ingress; p == nil || p.InstanceID != vm1 || p.Revision != 0 || len(p.Rules) != 0 {
		t.Fatal("EIP moved source VM policy to target", p)
	}
	advanceOverlayFixture(t, f.worker, r.EpochID)
	if source := f.view(t, vm0); source.Revision != 1 || source.BoundResourceID != "" || source.State != "active" {
		t.Fatal("source policy disappeared", source)
	}
	if _, _, _, e = f.store.BindPublicIPResource(ctx, f.config, f.actor, id(), r.ID, vm0, false, 3, f.now); !errors.Is(e, ErrState) {
		t.Fatal("omitted ingress revision guessed nonzero target", e)
	}
	if _, _, _, e = f.store.BindPublicIPResourceWithIngress(ctx, f.config, f.actor, id(), r.ID, vm0, false, 3, ingressRevision(0), f.now); !errors.Is(e, ErrState) {
		t.Fatal("stale target policy accepted", e)
	}
	allowed, _, _, e := f.store.SetPublicIngress(ctx, f.config, f.actor, vm1, id(), PublicIngressInput{ExpectedRevision: ingressRevision(0), Rules: []overlayproto.PublicIngressRule{ingressRule(8443)}}, f.now)
	if e != nil {
		t.Fatal(e)
	}
	advanceOverlayFixture(t, f.worker, allowed.EpochID)
	revoked, _, _, e := f.store.SetPublicIngress(ctx, f.config, f.actor, vm1, id(), PublicIngressInput{ExpectedRevision: ingressRevision(1), Rules: []overlayproto.PublicIngressRule{}}, f.now)
	if e != nil {
		t.Fatal(e)
	}
	advanceOverlayFixture(t, f.worker, revoked.EpochID)
	if v = f.view(t, vm1); v.State != "active" || v.Revision != 2 || len(v.Rules) != 0 || v.LegacyUnrestricted {
		t.Fatal("revocation not confirmed", v)
	}
	again, e := f.store.PublicIngressOperation(ctx, f.actor, key)
	if e != nil || !reflect.DeepEqual(again, op) || again.Result.Policy.State != "pending" {
		t.Fatal("fixed ACK changed with current policy", e)
	}
	original, e := f.store.OverlayEpoch(ctx, epoch.ID)
	if e != nil {
		t.Fatal(e)
	}
	bytes, _ := json.Marshal(original.Snapshot)
	if string(bytes) != string(oldBytes) {
		t.Fatal("original immutable snapshot rewritten")
	}
}
func TestMySQLPublicIngressUnknownRecoveryAndFixedReplay(t *testing.T) {
	f := mysqlIngressFixture(t)
	ctx := context.Background()
	vm := f.members[0].InstanceID
	r := f.bind(t, vm, 0, 0)
	advanceOverlayFixture(t, f.worker, r.EpochID)
	key := id()
	input := PublicIngressInput{ExpectedRevision: ingressRevision(0), Rules: []overlayproto.PublicIngressRule{ingressRule(22)}}
	pending, op, _, e := f.store.SetPublicIngress(ctx, f.config, f.actor, vm, key, input, f.now)
	if e != nil {
		t.Fatal(e)
	}
	original, e := f.store.OverlayEpoch(ctx, pending.EpochID)
	if e != nil {
		t.Fatal(e)
	}
	f.rpc.lose = "prepare"
	if _, e = f.worker.Advance(ctx, pending.EpochID); !errors.Is(e, ErrUnavailable) {
		t.Fatal("fixture did not lose node ACK", e)
	}
	before := len(f.rpc.posts)
	fixed, again, replay, e := f.store.SetPublicIngress(ctx, f.config, f.actor, vm, key, input, f.now)
	if e != nil || !replay || !reflect.DeepEqual(again, op) || fixed.State != "pending" || len(f.rpc.posts) != before {
		t.Fatal("unknown replay sent again or changed ACK", e)
	}
	if _, _, _, e = f.store.SetPublicIngress(ctx, f.config, f.actor, vm, id(), PublicIngressInput{ExpectedRevision: ingressRevision(1), Rules: []overlayproto.PublicIngressRule{}}, f.now); !errors.Is(e, ErrState) {
		t.Fatal("new key bypassed unknown", e)
	}
	cleaned, _, _, e := f.worker.RecoverPublicIPResource(ctx, f.actor, id(), r.ID, 2, original.SnapshotSHA256)
	if e != nil {
		t.Fatal("policy unknown recovery detach", e)
	}
	advanceOverlayFixture(t, f.worker, cleaned.EpochID)
	view := f.view(t, vm)
	if view.State != "active" || view.Revision != 1 || view.BoundResourceID != "" || !reflect.DeepEqual(view.Rules, input.Rules) {
		t.Fatal("recovery discarded desired policy", view)
	}
	rebound := f.bind(t, vm, 3, 1)
	next, e := f.store.OverlayEpoch(ctx, rebound.EpochID)
	if e != nil {
		t.Fatal(e)
	}
	if p := next.Snapshot.FloatingIPs[0].Ingress; p == nil || p.Revision != 1 || !reflect.DeepEqual(p.Rules, input.Rules) {
		t.Fatal("rebind lost saved target rules", p)
	}
	tasks, e := f.store.OverlayTasks(ctx, original.ID)
	if e != nil {
		t.Fatal(e)
	}
	unknown := 0
	for _, task := range tasks {
		if task.State == "uncertain" {
			unknown++
		}
	}
	if unknown != 1 {
		t.Fatal("old unknown receipt relabelled", unknown)
	}
}
func TestMySQLPublicIngressAuditFailureRollsBackVersionEpochAndResourceCAS(t *testing.T) {
	f := mysqlIngressFixture(t)
	ctx := context.Background()
	vm := f.members[0].InstanceID
	r := f.bind(t, vm, 0, 0)
	advanceOverlayFixture(t, f.worker, r.EpochID)
	if _, e := f.store.DB.Exec("CREATE TRIGGER ingress_audit_refusal BEFORE INSERT ON controller_audit FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='fixture refusal'"); e != nil {
		t.Fatal(e)
	}
	key := id()
	if _, _, _, e := f.store.SetPublicIngress(ctx, f.config, f.actor, vm, key, PublicIngressInput{ExpectedRevision: ingressRevision(0), Rules: []overlayproto.PublicIngressRule{ingressRule(443)}}, f.now); e == nil {
		t.Fatal("audit failure accepted")
	}
	for _, q := range []string{"SELECT COUNT(*) FROM controller_public_ingress_operations WHERE id=?", "SELECT COUNT(*) FROM controller_public_ingress_versions WHERE operation_id=?", "SELECT COUNT(*) FROM controller_public_ip_bindings WHERE id=?"} {
		var n int
		if e := f.store.DB.QueryRow(q, key).Scan(&n); e != nil || n != 0 {
			t.Fatal("partial mutation", q, n, e)
		}
	}
	var epochs int
	if e := f.store.DB.QueryRow("SELECT COUNT(*) FROM controller_overlay_epochs").Scan(&epochs); e != nil || epochs != 2 {
		t.Fatal("epoch committed without audit", epochs, e)
	}
	current, e := f.store.PublicIPResource(ctx, f.config, r.ID)
	if e != nil || current.BindingGeneration != 1 || current.BindingState != "bound" {
		t.Fatal("resource CAS changed", current, e)
	}
}
func TestMySQLPublicIngressAllParticipantCapabilityAndDispatchWithdrawal(t *testing.T) {
	for _, kind := range []string{"old_remote", "maintenance_remote", "stale_remote", "dispatch_withdrawal", "bound_withdrawal", "bound_root_pin_drift", "bound_root_grant_withdrawal"} {
		t.Run(kind, func(t *testing.T) {
			f := mysqlIngressFixture(t)
			ctx := context.Background()
			vm := f.members[0].InstanceID
			remote := f.config.Nodes[1]
			now := f.now
			caps := vpcTestCapabilities(remote, f.now)
			caps.OVSNetworkProfiles = []string{f.config.OverlayClusters[0].Profiles[1].ProfileID}
			rootDrift := kind == "bound_root_pin_drift" || kind == "bound_root_grant_withdrawal"
			var policyACK PublicIngressOperation
			if rootDrift {
				_, op, _, e := f.store.SetPublicIngress(ctx, f.config, f.actor, vm, id(), PublicIngressInput{ExpectedRevision: ingressRevision(0), Rules: []overlayproto.PublicIngressRule{ingressRule(443)}}, f.now)
				if e != nil {
					t.Fatal(e)
				}
				policyACK = op
			}
			if kind == "dispatch_withdrawal" || kind == "bound_withdrawal" || rootDrift {
				revision := uint64(0)
				if rootDrift {
					revision = 1
				}
				f.resource = f.bind(t, vm, 0, revision)
				if kind != "dispatch_withdrawal" {
					advanceOverlayFixture(t, f.worker, f.resource.EpochID)
				}
			}
			if rootDrift {
				before := f.view(t, vm)
				if !before.Supported || before.State != "active" || before.EffectiveRevision == nil || *before.EffectiveRevision != 1 {
					t.Fatal("pre-drift release not active", before)
				}
				bindingACK, e := f.store.PublicIPResourceOperation(ctx, f.actor, f.resource.OperationID)
				if e != nil {
					t.Fatal(e)
				}
				digests := map[string]string{}
				for _, node := range f.config.Nodes {
					digests[node.ID] = node.Digest()
				}
				f.config.OverlayClusters = append([]OverlayCluster{}, f.config.OverlayClusters...)
				if kind == "bound_root_pin_drift" {
					f.config.OverlayClusters[0].Profiles = append([]overlayproto.ProfilePin{}, f.config.OverlayClusters[0].Profiles...)
					f.config.OverlayClusters[0].Profiles[1].ProfileSHA256 = strings.Repeat("c", 64)
				} else {
					f.config.OverlayClusters[0].NATProfiles = append([]OverlayNATProfile{}, f.config.OverlayClusters[0].NATProfiles...)
					f.config.OverlayClusters[0].NATProfiles[0].AllowFloatingIP = false
				}
				if !f.config.Valid() {
					t.Fatal("root drift must remain a valid current configuration")
				}
				for _, node := range f.config.Nodes {
					if node.Digest() != digests[node.ID] {
						t.Fatal("test accidentally changed node transport digest")
					}
				}
				view := f.view(t, vm)
				if view.Supported || view.UnsupportedReason != "NODE_NOT_READY" || view.State != "blocked" || view.EffectiveRevision != nil || view.BoundResourceID != f.resource.ID || !reflect.DeepEqual(publicIngressWire(view), publicIngressWire(before)) || view.LegacyUnrestricted != before.LegacyUnrestricted {
					t.Fatal("historical receipt pretended current root approval", kind, view)
				}
				fixed, e := f.store.PublicIngressOperation(ctx, f.actor, policyACK.ID)
				if e != nil || !reflect.DeepEqual(fixed, policyACK) {
					t.Fatal("root drift rewrote immutable policy ACK", e)
				}
				bindingFixed, e := f.store.PublicIPResourceOperation(ctx, f.actor, bindingACK.ID)
				if e != nil || !reflect.DeepEqual(bindingFixed, bindingACK) {
					t.Fatal("root drift rewrote immutable binding ACK", e)
				}
				return
			}
			switch kind {
			case "old_remote", "dispatch_withdrawal", "bound_withdrawal":
				values := []string{}
				for _, s := range caps.NetworkProfiles {
					if s != nodeproto.PublicIngressCapability {
						values = append(values, s)
					}
				}
				caps.NetworkProfiles = values
				if e := f.store.Heartbeat(ctx, remote, caps, f.now, time.Minute); e != nil {
					t.Fatal(e)
				}
			case "maintenance_remote":
				if e := f.store.Maintenance(ctx, remote.ID, true); e != nil {
					t.Fatal(e)
				}
			case "stale_remote":
				now = now.Add(time.Duration(f.config.HeartbeatTTLSeconds+1) * time.Second)
			}
			if kind == "dispatch_withdrawal" {
				before := len(f.rpc.posts)
				if _, e := f.worker.Advance(ctx, f.resource.EpochID); !errors.Is(e, ErrState) || len(f.rpc.posts) != before {
					t.Fatal("old participant dispatched new policy", e)
				}
				return
			}
			view, e := f.store.PublicIngress(ctx, f.config, vm, now)
			if e != nil || view.Supported {
				t.Fatal("missing enforcement advertised support", view, e)
			}
			if (kind == "old_remote" || kind == "bound_withdrawal") && view.UnsupportedReason != "UPGRADE_REQUIRED" {
				t.Fatal(view)
			}
			if kind == "bound_withdrawal" && (view.State != "blocked" || view.EffectiveRevision != nil || view.Revision != 0 || view.BoundResourceID != f.resource.ID) {
				t.Fatal("old release receipt claimed active after capability withdrawal", view)
			}
			if _, _, _, e = f.store.BindPublicIPResourceWithIngress(ctx, f.config, f.actor, id(), f.resource.ID, vm, false, 0, ingressRevision(0), now); !errors.Is(e, ErrState) {
				t.Fatal("new bind bypassed remote capability/health", kind, e)
			}
		})
	}
}
func TestMySQLPublicIngressConsoleRBACStrictInputAndImmutableOperation(t *testing.T) {
	f := mysqlIngressFixture(t)
	ctx := context.Background()
	vm := f.members[0].InstanceID
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	ident, e := identity.New(f.store.DB, identity.Config{Origin: server.URL})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ident.Bootstrap(ctx, "ingress-admin@example.invalid", "ingress", []byte(consoleHTTPPassword)); e != nil {
		t.Fatal(e)
	}
	mux.Handle("/", (Console{Store: f.store, Config: f.config, Identity: ident}).Handler())
	admin := newConsoleHTTPBrowser(t, server)
	admin.login(t, "ingress-admin@example.invalid")
	admin.createUser(t, "ingress-reader@example.invalid", "custom", []string{"instances.read", "nodes.read"})
	reader := newConsoleHTTPBrowser(t, server)
	reader.login(t, "ingress-reader@example.invalid")
	path := "/console/v1/instances/" + vm + "/public-ingress"
	key := id()
	input := PublicIngressInput{ExpectedRevision: ingressRevision(0), Rules: []overlayproto.PublicIngressRule{ingressRule(443)}}
	body := consoleHTTPJSON(t, input)
	grants := []string{"instances.read", "nodes.read", "instances.manage", "nodes.manage"}
	for i, missing := range grants {
		limited := []string{}
		for _, grant := range grants {
			if grant != missing {
				limited = append(limited, grant)
			}
		}
		email := fmt.Sprintf("ingress-partial-%d@example.invalid", i)
		admin.createUser(t, email, "custom", limited)
		browser := newConsoleHTTPBrowser(t, server)
		browser.login(t, email)
		if status, _ := browser.request(t, "POST", path, body, consoleHTTPOptions{idempotency: id()}); status != 403 {
			t.Fatal("missing required write/read grant", missing, status)
		}
		want := 200
		if missing == "instances.read" || missing == "nodes.read" {
			want = 403
		}
		if status, _ := browser.request(t, "GET", path, "", consoleHTTPOptions{}); status != want {
			t.Fatal("read permission combination", missing, status)
		}
	}
	if status, _ := reader.request(t, "GET", path, "", consoleHTTPOptions{}); status != 200 {
		t.Fatal("read policy", status)
	}
	if status, _ := reader.request(t, "POST", path, body, consoleHTTPOptions{idempotency: key}); status != 403 {
		t.Fatal("reader wrote policy", status)
	}
	for _, opts := range []consoleHTTPOptions{{idempotency: key, csrf: ptr("")}, {idempotency: key, origin: ptr("https://evil.invalid")}} {
		if status, _ := admin.request(t, "POST", path, body, opts); status != 403 {
			t.Fatal("CSRF/origin", status)
		}
	}
	for _, bad := range []string{`{}`, `{"expected_revision":null,"rules":[]}`, `{"expected_revision":0,"rules":null}`, `{"Expected_Revision":0,"rules":[]}`, `{"expected_revision":0,"expected_revision":0,"rules":[]}`, `{"expected_revision":0,"rules":[],"owner_ref":"` + f.vpc.OwnerRef + `"}`} {
		if status, _ := admin.request(t, "POST", path, bad, consoleHTTPOptions{idempotency: id()}); status != 400 {
			t.Fatal("loose policy JSON", bad, status)
		}
	}
	status, raw := admin.request(t, "POST", path, body, consoleHTTPOptions{idempotency: key})
	var ack struct {
		Policy    PublicIngressView      `json:"policy"`
		Operation PublicIngressOperation `json:"operation"`
		Replay    bool                   `json:"replay"`
	}
	if status != 202 || json.Unmarshal(raw, &ack) != nil || ack.Policy.State != "active" || ack.Policy.Revision != 1 || ack.Operation.ID != key {
		t.Fatal("unbound policy ACK", status, string(raw))
	}
	if status, _ = reader.request(t, "GET", "/console/v1/public-ingress-operations/"+key, "", consoleHTTPOptions{}); status != 404 {
		t.Fatal("cross actor operation leak", status)
	}
	status, raw = admin.request(t, "POST", path, body, consoleHTTPOptions{idempotency: key})
	var replay struct {
		Operation PublicIngressOperation `json:"operation"`
		Replay    bool                   `json:"replay"`
	}
	if status != 200 || json.Unmarshal(raw, &replay) != nil || !replay.Replay || !reflect.DeepEqual(ack.Operation, replay.Operation) {
		t.Fatal("fixed policy replay", status)
	}
	if status, _ = admin.request(t, "GET", "/console/v1/public-ingress-operations/"+key, "", consoleHTTPOptions{}); status != 200 {
		t.Fatal("read original policy operation", status)
	}
	if status, _ = admin.request(t, "POST", path, body, consoleHTTPOptions{idempotency: id()}); status != 409 {
		t.Fatal("stale policy editor", status)
	}
	if _, _, e = f.store.CreateOverlayVPC(ctx, f.config, f.actor, key, OverlayVPCInput{ClusterID: f.vpc.ClusterID, OwnerRef: f.vpc.OwnerRef, Name: "collision", CIDR: "10.26.0.0/24", VNI: 502}, f.now); !errors.Is(e, ErrConflict) {
		t.Fatal("old overlay namespace stole policy key", e)
	}
	root := f.config.OverlayClusters[0].NATProfiles[0]
	if _, _, _, e = f.store.AllocatePublicIPResource(ctx, f.config, f.actor, key, PublicIPResourceInput{PoolID: f.resource.PoolID, OwnerRef: f.vpc.OwnerRef, Mode: "floating", NodeID: root.NodeID, ProfileID: root.ProfileID, VPCID: f.vpc.ID, Address: "8.8.8.10"}, f.now); !errors.Is(e, ErrConflict) {
		t.Fatal("old resource namespace stole policy key", e)
	}
	for _, oldKey := range []string{f.vpc.ID, f.jobs[0].OperationID, f.resource.ID, f.resource.PoolID} {
		if _, _, _, e = f.store.SetPublicIngress(ctx, f.config, f.actor, vm, oldKey, PublicIngressInput{ExpectedRevision: ingressRevision(1), Rules: []overlayproto.PublicIngressRule{}}, f.now); !errors.Is(e, ErrConflict) {
			t.Fatal("policy namespace stole existing object key", oldKey, e)
		}
	}
	private := &networking.Store{DB: f.store.DB}
	if _, _, e = private.CreateVPC(ctx, f.actor, key, networking.CreateVPCInput{OwnerRef: f.vpc.OwnerRef, NodeID: f.config.Nodes[0].ID, Name: "collision", CIDR: "10.26.0.0/24", VLANID: 26}, f.now); !errors.Is(e, networking.ErrConflict) {
		t.Fatal("private IPAM stole policy operation key", e)
	}
	if _, _, _, e = f.store.CreatePublicIPPool(ctx, f.config, f.actor, key, PublicIPPoolInput{ClusterID: f.vpc.ClusterID, Name: "collision", CIDR: "8.8.8.0/24", Addresses: []string{"8.8.8.10"}, Enabled: true}, f.now); !errors.Is(e, ErrConflict) {
		t.Fatal("NAT pool namespace stole policy key", e)
	}
	req := mysqlVPCRequest(f.config.Nodes[0], f.vpc.OwnerRef)
	req.OperationID = key
	if _, _, e = f.store.Admit(ctx, req, f.config.Candidates(req), f.now, time.Minute); !errors.Is(e, ErrConflict) {
		t.Fatal("financial provisioning namespace stole policy key", e)
	}
	admin.createUser(t, "ingress-other-full@example.invalid", "custom", grants)
	other := newConsoleHTTPBrowser(t, server)
	other.login(t, "ingress-other-full@example.invalid")
	if status, _ = other.request(t, "POST", path, body, consoleHTTPOptions{idempotency: key}); status != 409 {
		t.Fatal("other full actor reused original key", status)
	}
	if status, _ = admin.request(t, "GET", path+"?ignored=1", "", consoleHTTPOptions{}); status != 400 {
		t.Fatal("policy query loosened", status)
	}
}
func TestMySQLPublicIngressSchemaReentryAndDrift(t *testing.T) {
	f := mysqlIngressFixture(t)
	ctx := context.Background()
	if e := f.store.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	if _, e := f.store.DB.Exec("DROP INDEX controller_public_ingress_version_operation ON controller_public_ingress_versions"); e != nil {
		t.Fatal(e)
	}
	if e := f.store.Check(ctx); e == nil {
		t.Fatal("ingress schema drift accepted")
	}
}

// Construct an original pre-ingress binding, rather than rewriting a modern
// snapshot to look old. The nil contract deliberately predates policy support.
func (f ingressFixture) legacyBinding(t *testing.T) (PublicIPResource, PublicIPResourceOperation, OverlayEpoch) {
	t.Helper()
	ctx := context.Background()
	tx, e := f.store.locked(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	r := f.resource
	latest, e := scanOverlayEpoch(tx.QueryRowContext(ctx, "SELECT "+overlayEpochColumns+" FROM controller_overlay_epochs WHERE cluster_id=? ORDER BY epoch DESC LIMIT 1", r.ClusterID))
	if e != nil {
		t.Fatal(e)
	}
	root := f.config.OverlayClusters[0].NATProfiles[0]
	member := latest.Snapshot.Members[0]
	legacy := overlayproto.FloatingIP{ResourceID: r.ID, NodeID: r.NodeID, VPCID: r.VPCID, OwnerRef: r.OwnerRef, ProfileID: r.ProfileID, ProfileSHA256: root.ProfileSHA256, GatewayInstanceID: root.GatewayInstanceID, InstanceID: member.InstanceID, TargetIPv4: member.IPv4, PublicIPv4: r.Address}
	floats := []overlayproto.FloatingIP{legacy}
	in := OverlayEpochInput{ClusterID: r.ClusterID, ExpectedEpoch: latest.Epoch, Members: f.members, Gateways: latest.Snapshot.Gateways, FloatingIPs: &floats}
	cluster, _ := f.config.OverlayCluster(r.ClusterID)
	snapshot, sha, e := buildOverlaySnapshot(ctx, tx, f.config, cluster, latest, in, f.now, false)
	if e != nil {
		t.Fatal(e)
	}
	key := id()
	epoch := OverlayEpoch{ID: overlayproto.Digest([]byte("aster.public-ip.binding/1:" + key))[:32], ClusterID: r.ClusterID, Epoch: snapshot.Epoch, ActorID: f.actor, RequestSHA256: overlayproto.Digest(marshalPublicBinding(in)), SnapshotSHA256: sha, Snapshot: snapshot, Phase: "prepare", State: "pending", CreatedAt: f.now, UpdatedAt: f.now}
	if e = insertPublicResourceEpochTx(ctx, tx, f.config, epoch); e != nil {
		t.Fatal(e)
	}
	if e = insertPublicBindingTx(ctx, tx, PublicIPBindingIntent{ID: key, ResourceID: r.ID, Action: "floating.bind", InstanceID: member.InstanceID, EpochID: epoch.ID, RequestSHA256: sha, Binding: marshalPublicBinding(legacy), CreatedAt: f.now}); e != nil {
		t.Fatal(e)
	}
	r.BindingGeneration, r.InstanceID, r.EpochID, r.OperationID, r.BindingState, r.Releasable, r.ReleaseReason = 1, member.InstanceID, epoch.ID, key, "pending", false, "NETWORK_OPERATION_PENDING"
	// This body intentionally has exactly the original two fields.
	raw := marshalPublicBinding(struct {
		InstanceID         string `json:"instance_id"`
		ExpectedGeneration uint64 `json:"expected_generation"`
	}{member.InstanceID, 0})
	op, e := insertPublicResourceOperation(ctx, tx, f.actor, key, "resource.bind", r.ID, r, raw, f.now)
	if e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	return r, op, epoch
}
func TestMySQLPublicIngressLegacyUpgradePreservesHistoricalBytesAndACK(t *testing.T) {
	f := mysqlIngressFixture(t)
	ctx := context.Background()
	r, oldACK, oldEpoch := f.legacyBinding(t)
	advanceOverlayFixture(t, f.worker, oldEpoch.ID)
	original, _ := json.Marshal(oldEpoch.Snapshot)
	v := f.view(t, r.InstanceID)
	if !v.LegacyUnrestricted || v.Revision != 0 || v.EffectiveRevision != nil || v.State != "default" {
		t.Fatal("legacy mapping disguised as deny", v)
	}
	upgrade, _, _, e := f.store.SetPublicIngress(ctx, f.config, f.actor, r.InstanceID, id(), PublicIngressInput{ExpectedRevision: ingressRevision(0), Rules: []overlayproto.PublicIngressRule{}}, f.now)
	if e != nil || upgrade.State != "pending" || !upgrade.LegacyUnrestricted || upgrade.EffectiveRevision != nil {
		t.Fatal("legacy upgrade ACK", upgrade, e)
	}
	if v = f.view(t, r.InstanceID); !v.LegacyUnrestricted || v.EffectiveRevision != nil {
		t.Fatal("pending upgrade pretended legacy closed", v)
	}
	next, e := f.store.OverlayEpoch(ctx, upgrade.EpochID)
	if e != nil || next.Snapshot.FloatingIPs[0].Ingress == nil || len(next.Snapshot.FloatingIPs[0].Ingress.Rules) != 0 {
		t.Fatal("upgrade did not freeze explicit deny", e)
	}
	advanceOverlayFixture(t, f.worker, next.ID)
	if v = f.view(t, r.InstanceID); v.LegacyUnrestricted || v.State != "active" || v.EffectiveRevision == nil || *v.EffectiveRevision != 1 {
		t.Fatal("upgrade release", v)
	}
	if _, _, _, e = f.store.BindPublicIPResource(ctx, f.config, f.actor, id(), r.ID, "", true, 1, f.now); !errors.Is(e, ErrState) {
		t.Fatal("pre-policy stale generation detached address", e)
	}
	got, replayed, replay, e := f.store.BindPublicIPResource(ctx, f.config, f.actor, oldACK.ID, r.ID, r.InstanceID, false, 0, f.now)
	if e != nil || !replay || !reflect.DeepEqual(replayed, oldACK) || got.OperationID != oldACK.ID {
		t.Fatal("old body ACK broken by nonzero current policy", e)
	}
	history, e := f.store.OverlayEpoch(ctx, oldEpoch.ID)
	bytes, _ := json.Marshal(history.Snapshot)
	if e != nil || string(bytes) != string(original) || history.Snapshot.FloatingIPs[0].Ingress != nil {
		t.Fatal("legacy bytes rewritten", e)
	}
}
func TestMySQLPublicIngressOrdinaryRecoveryPreservesFrozenPolicy(t *testing.T) {
	for _, replacement := range []bool{false, true} {
		t.Run(fmt.Sprint(replacement), func(t *testing.T) {
			f := mysqlIngressFixture(t)
			ctx := context.Background()
			vm := f.members[0].InstanceID
			_, _, _, e := f.store.SetPublicIngress(ctx, f.config, f.actor, vm, id(), PublicIngressInput{ExpectedRevision: ingressRevision(0), Rules: []overlayproto.PublicIngressRule{ingressRule(443)}}, f.now)
			if e != nil {
				t.Fatal(e)
			}
			r := f.bind(t, vm, 0, 1)
			f.rpc.lose = "prepare"
			if _, e = f.worker.Advance(ctx, r.EpochID); !errors.Is(e, ErrUnavailable) {
				t.Fatal(e)
			}
			old, e := f.store.OverlayEpoch(ctx, r.EpochID)
			if e != nil {
				t.Fatal(e)
			}
			in := OverlayRecoveryInput{ExpectedSnapshotSHA256: old.SnapshotSHA256}
			if replacement {
				in.Replacement = &OverlayReplacementInput{Members: f.members, Gateways: old.Snapshot.Gateways}
			}
			next, _, e := f.worker.Recover(ctx, f.actor, old.ID, id(), in)
			if e != nil || !reflect.DeepEqual(next.Snapshot.FloatingIPs, old.Snapshot.FloatingIPs) {
				t.Fatal("ordinary recovery changed instance rules", e)
			}
			advanceOverlayFixture(t, f.worker, next.ID)
			if v := f.view(t, vm); v.State != "active" || v.EffectiveRevision == nil || *v.EffectiveRevision != 1 {
				t.Fatal(v)
			}
		})
	}
}

func TestMySQLPublicIngressCreationCarriesRealAdmissionTTL(t *testing.T) {
	for _, kind := range []string{"staff_fresh", "billing_fresh", "staff_expired_remote", "billing_expired_remote"} {
		t.Run(kind, func(t *testing.T) {
			f := mysqlIngressFixture(t)
			ctx := context.Background()
			r := f.bind(t, f.members[0].InstanceID, 0, 0)
			advanceOverlayFixture(t, f.worker, r.EpochID)
			previous, e := f.store.OverlayEpoch(ctx, r.EpochID)
			if e != nil {
				t.Fatal(e)
			}
			oldTask, e := nodeproto.DecodeTask(f.jobs[0].NodeRequest)
			if e != nil {
				t.Fatal(e)
			}
			addresses, _ := json.Marshal([]string{oldTask.Network.IPv4, "10.25.0.30"})
			if _, e = f.store.DB.Exec("UPDATE controller_network_pools SET addresses=? WHERE id=?", addresses, oldTask.Network.PoolID); e != nil {
				t.Fatal(e)
			}
			now := f.now.Add(time.Second)
			if strings.Contains(kind, "expired") {
				now = f.now.Add(time.Duration(f.config.HeartbeatTTLSeconds+1) * time.Second)
				// Keep the selected launch node fresh. It is the independently stale
				// remote ACL participant, not scheduler capacity, that must fence admission.
				p, _ := f.config.Node(oldTask.NodeID)
				caps := vpcTestCapabilities(p, now)
				for _, pin := range f.config.OverlayClusters[0].Profiles {
					if pin.NodeID == p.ID {
						caps.OVSNetworkProfiles = []string{pin.ProfileID}
					}
				}
				if e = f.store.Heartbeat(ctx, p, caps, now, time.Minute); e != nil {
					t.Fatal(e)
				}
			}
			key := id()
			if strings.HasPrefix(kind, "billing") {
				p, _ := f.config.Node(oldTask.NodeID)
				req := mysqlVPCRequest(p, oldTask.OwnerRef)
				req.OperationID = key
				before, _, _ := req.BytesAndDigest()
				job, _, err := f.store.Admit(ctx, req, f.config.Candidates(req), now, time.Minute)
				e = err
				if !strings.Contains(kind, "expired") && (job.State != "accepted" || string(job.RequestJSON) != string(before)) {
					t.Fatal("financial bytes/admission changed", job.State, err)
				}
			} else {
				preset := ""
				for _, p := range f.config.Presets {
					if p.NodeID == oldTask.NodeID {
						preset = p.ID
					}
				}
				_, _, e = f.store.CreateInstance(ctx, f.config, f.actor, key, CreateInstanceInput{OwnerRef: oldTask.OwnerRef, Hostname: "public-ingress-new-vm", PresetID: preset}, now)
			}
			if strings.Contains(kind, "expired") {
				if !errors.Is(e, ErrState) {
					t.Fatal("stale remote participant did not fence new VM", e)
				}
				var count int
				if e = f.store.DB.QueryRow("SELECT COUNT(*) FROM controller_instances WHERE id=?", key).Scan(&count); e != nil || count != 0 {
					t.Fatal("rejected admission left partial instance", count, e)
				}
				return
			}
			if e != nil {
				t.Fatal("valid heartbeat was checked with zero-TTL reconstruction", e)
			}
			next, e := f.store.OverlayEpoch(ctx, overlayproto.Digest([]byte("aster.overlay.admission/1:" + key))[:32])
			if e != nil || !reflect.DeepEqual(next.Snapshot.FloatingIPs, previous.Snapshot.FloatingIPs) {
				t.Fatal("new VM changed existing exact ingress", e)
			}
		})
	}
}

package control

import (
	"aster/billing/serviceapi"
	"aster/cloud/internal/nodeproto"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type serviceFixture struct {
	*resourceViewFixture
	receipts        map[string]ServiceReceipt
	ops             map[string]Operation
	writes          int
	caps            Capability
	consoleAudits   []Instance
	consoleAuditErr error
}

func (f *serviceFixture) RecordConsoleGrant(_ context.Context, v Instance, _ time.Time) error {
	if f.consoleAuditErr != nil {
		return f.consoleAuditErr
	}
	f.consoleAudits = append(f.consoleAudits, v)
	return nil
}

func (f *serviceFixture) ServiceFlags(context.Context, string) (ServiceFlags, error) {
	return ServiceFlags{}, nil
}
func (f *serviceFixture) ServiceCapability(context.Context, Config, string, time.Time) (Capability, error) {
	return f.caps, nil
}
func (f *serviceFixture) ServiceReceipt(_ context.Context, op string) (ServiceReceipt, error) {
	v, ok := f.receipts[op]
	if !ok {
		return v, ErrNotFound
	}
	return v, nil
}
func (f *serviceFixture) Operation(_ context.Context, op string) (Operation, error) {
	v, ok := f.ops[op]
	if !ok {
		return v, ErrNotFound
	}
	return v, nil
}
func (f *serviceFixture) ServiceSnapshots(_ context.Context, _ string, limit int) (serviceapi.Snapshots, error) {
	return serviceapi.Snapshots{Items: []serviceapi.Snapshot{}, Limit: limit, RequiresStopped: true}, nil
}
func (f *serviceFixture) AdmitService(_ context.Context, _ Config, instance string, r serviceapi.ActionRequest, now time.Time) (ServiceReceipt, bool, error) {
	_, h, _ := r.BytesAndDigest()
	v := ServiceReceipt{OperationID: r.OperationID, InstanceID: instance, OwnerRef: r.OwnerRef, Action: r.Action, Digest: h, Status: "accepted", Code: "ACCEPTED", CreatedAt: now}
	if p, ok := f.receipts[r.OperationID]; ok {
		return p, true, bindServiceReceipt(p, v)
	}
	f.writes++
	f.receipts[r.OperationID] = v
	f.ops[r.OperationID] = Operation{ID: r.OperationID, State: "accepted"}
	return v, false, nil
}

type serviceLaunch struct {
	calls    int
	password string
}

func (l *serviceLaunch) StartService(_ string, password string) error {
	l.calls++
	l.password = password
	return nil
}
func serviceApp() (App, *serviceFixture, *serviceLaunch) {
	app, base := resourceViewApp()
	f := &serviceFixture{resourceViewFixture: base, receipts: map[string]ServiceReceipt{}, ops: map[string]Operation{}, caps: testCapabilities(testProfile(), time.Now())}
	launch := &serviceLaunch{}
	f.caps.Actions = append(f.caps.Actions, "reinstall", "reset_password", "rescue_enter", "rescue_exit", "resize", "snapshot_create", "snapshot_restore", "snapshot_delete")
	f.caps.GuestImages = map[string]nodeproto.GuestImageApproval{"ubuntu22": {SHA256: strings.Repeat("a", 64), Family: "linux"}}
	app.Config.Service = ServiceConfig{SnapshotLimit: 3, Images: []CatalogImage{{ID: "ubuntu22", Name: "Ubuntu", Version: "22.04", Family: "linux", SHA256: strings.Repeat("a", 64), MinDiskGB: 1, NodeIDs: []string{testProfile().ID}}}}
	app.Services = &Services{Store: f, Config: app.Config, Runner: launch, Observe: func(context.Context, NodeProfile, string) (nodeproto.InstanceObservation, error) {
		v := f.value
		return nodeproto.InstanceObservation{InstanceID: v.ID, OwnerRef: v.OwnerRef, NodeID: v.NodeID, Hostname: v.Hostname, State: "running", IPv4: "192.0.2.10"}, nil
	}, IssueConsole: func(context.Context, Instance) (serviceapi.Console, error) {
		return serviceapi.Console{URL: "https://cloud.example/console/#ticket", ExpiresAt: time.Now().Add(time.Minute)}, nil
	}}
	return app, f, launch
}
func TestServiceEveryRouteOwnerAuthAndReadonlyBoundaries(t *testing.T) {
	app, f, _ := serviceApp()
	base := "/v1/services/" + f.value.ID
	op := strings.Repeat("a", 32)
	f.receipts[op] = ServiceReceipt{OperationID: op, InstanceID: f.value.ID, OwnerRef: f.value.OwnerRef, Action: "start", Status: "accepted"}
	f.ops[op] = Operation{ID: op, State: "uncertain"}
	for _, tc := range []struct{ method, path string }{{"GET", "/v1/images"}, {"GET", base}, {"GET", base + "/actions/" + op}, {"POST", base + "/console"}, {"GET", base + "/metrics?range=1h"}, {"GET", base + "/snapshots"}} {
		for _, owner := range []string{f.value.OwnerRef, strings.Repeat("f", 32), ""} {
			response := requestHTTP(app, tc.method, tc.path, app.Secrets.Billing, nil, map[string]string{"X-Aster-Owner-Ref": owner}, true)
			want := 200
			if owner == "" || owner != f.value.OwnerRef && tc.path != "/v1/images" {
				want = 404
			}
			if response.Code != want {
				t.Fatalf("%s %s status=%d body=%s", tc.method, tc.path, response.Code, response.Body.String())
			}
		}
		for _, token := range []string{app.Secrets.AdminRead, app.Secrets.AdminWrite, ""} {
			response := requestHTTP(app, tc.method, tc.path, token, nil, map[string]string{"X-Aster-Owner-Ref": f.value.OwnerRef}, true)
			if response.Code != 403 && response.Code != 401 {
				t.Fatal("nonbilling token admitted")
			}
		}
	}
	if f.writes != 0 {
		t.Fatal("read route admitted work")
	}
	for _, query := range []string{"", "?range=1h&range=24h", "?range=invalid", "?range=1h&url=https://evil.invalid"} {
		r := requestHTTP(app, "GET", base+"/metrics"+query, app.Secrets.Billing, nil, map[string]string{"X-Aster-Owner-Ref": f.value.OwnerRef}, true)
		if r.Code != 400 {
			t.Fatal("query accepted", query)
		}
	}
}
func TestServiceActionBindsDigestAndReplaysFirstReceiptWithoutSecrets(t *testing.T) {
	app, f, launch := serviceApp()
	path := "/v1/services/" + f.value.ID + "/actions"
	req := serviceapi.ActionRequest{Protocol: serviceapi.Protocol, OperationID: strings.Repeat("a", 32), OwnerRef: f.value.OwnerRef, Action: "reset_password", Params: serviceapi.Params{Password: "ephemeral-secret"}}
	raw, h, _ := req.BytesAndDigest()
	headers := map[string]string{"X-Aster-Owner-Ref": req.OwnerRef, "Idempotency-Key": req.OperationID, "X-Aster-Request-SHA256": h, "Content-Type": "application/json"}
	first := requestHTTP(app, "POST", path, app.Secrets.Billing, raw, headers, true)
	if first.Code != 202 {
		t.Fatal(first.Code, first.Body.String())
	}
	f.ops[req.OperationID] = Operation{ID: req.OperationID, State: "succeeded", UpdatedAt: time.Now()}
	replay := requestHTTP(app, "POST", path, app.Secrets.Billing, raw, headers, true)
	if replay.Code != 409 || replay.Body.String() != first.Body.String() || launch.calls != 1 || launch.password != "ephemeral-secret" || f.writes != 1 {
		t.Fatal("receipt replay dispatched again")
	}
	saved, _ := json.Marshal(f.receipts)
	if strings.Contains(string(saved), req.Params.Password) {
		t.Fatal("receipt stored password")
	}
	req.Params.Password = "changed-secret"
	raw, h, _ = req.BytesAndDigest()
	headers["X-Aster-Request-SHA256"] = h
	conflict := requestHTTP(app, "POST", path, app.Secrets.Billing, raw, headers, true)
	if conflict.Code != 409 || !strings.Contains(conflict.Body.String(), "IDEMPOTENCY_CONFLICT") {
		t.Fatal("changed body reused key")
	}
	headers["X-Aster-Request-SHA256"] = strings.Repeat("0", 64)
	bad := requestHTTP(app, "POST", path, app.Secrets.Billing, raw, headers, true)
	if bad.Code != 400 {
		t.Fatal("digest ignored")
	}
}
func TestServiceCapabilitiesReflectNodeImageAndNetwork(t *testing.T) {
	app, f, _ := serviceApp()
	path := "/v1/services/" + f.value.ID
	headers := map[string]string{"X-Aster-Owner-Ref": f.value.OwnerRef}
	r := requestHTTP(app, "GET", path, app.Secrets.Billing, nil, headers, true)
	var v serviceapi.Service
	if json.Unmarshal(r.Body.Bytes(), &v) != nil || !v.Capabilities.Reinstall || !v.Capabilities.Snapshots || !v.Capabilities.ResetPassword || v.Capabilities.Console || v.Capabilities.Metrics {
		t.Fatal(r.Body.String())
	}
	f.value.Resources.NetworkType = "vpc"
	r = requestHTTP(app, "GET", path, app.Secrets.Billing, nil, headers, true)
	_ = json.Unmarshal(r.Body.Bytes(), &v)
	if v.Capabilities.Reinstall || v.Capabilities.Snapshots || v.Capabilities.Upgrade || v.Capabilities.ResetPassword {
		t.Fatal("OVS disk capabilities overstated")
	}
	f.value.Resources.NetworkType = "normal"
	f.caps.Actions = []string{}
	r = requestHTTP(app, "GET", path, app.Secrets.Billing, nil, headers, true)
	_ = json.Unmarshal(r.Body.Bytes(), &v)
	if v.Capabilities != (serviceapi.Capabilities{}) {
		t.Fatal("unavailable node advertised mutations")
	}
}

func TestServiceImageCapabilitiesRequireMatchingNodeApproval(t *testing.T) {
	for _, missing := range []string{"matching", "catalog", "digest", "family", "rescue"} {
		t.Run(missing, func(t *testing.T) {
			app, f, _ := serviceApp()
			im := app.Services.Config.Service.Images[0]
			app.Services.Config.Service.Images = append(app.Services.Config.Service.Images, CatalogImage{ID: "rescue", Family: "linux", Name: "Rescue", Version: "1", SHA256: im.SHA256, MinDiskGB: 1, NodeIDs: im.NodeIDs, Rescue: true})
			f.caps.ImageIDs = append(f.caps.ImageIDs, "rescue")
			f.caps.GuestImages["rescue"] = nodeproto.GuestImageApproval{SHA256: im.SHA256, Family: "linux", Rescue: true}
			if missing == "catalog" {
				f.caps.GuestImages = nil
			} else {
				for id, approval := range f.caps.GuestImages {
					switch missing {
					case "digest":
						approval.SHA256 = strings.Repeat("b", 64)
					case "family":
						approval.Family = "windows"
					case "rescue":
						approval.Rescue = false
					}
					f.caps.GuestImages[id] = approval
				}
			}
			r := requestHTTP(app, "GET", "/v1/services/"+f.value.ID, app.Secrets.Billing, nil, map[string]string{"X-Aster-Owner-Ref": f.value.OwnerRef}, true)
			var v serviceapi.Service
			if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &v) != nil || v.Capabilities.Rescue != (missing == "matching") {
				t.Fatal(r.Body.String())
			}
			if missing != "matching" && missing != "rescue" && (v.Capabilities.Reinstall || v.Capabilities.ResetPassword) {
				t.Fatal("mismatched image approval advertised", v.Capabilities)
			}
			if (missing == "matching" || missing == "rescue") && (!v.Capabilities.Reinstall || !v.Capabilities.ResetPassword) {
				t.Fatal("unrelated supported image actions removed", v.Capabilities)
			}
		})
	}
}

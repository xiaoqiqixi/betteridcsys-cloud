package control

import (
	"aster/billing/serviceapi"
	"aster/cloud/internal/nodeproto"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type guestRPC struct {
	consoleRPC
	password string
}

func (r *guestRPC) SendGuest(ctx context.Context, raw []byte, sha, password string) (nodeproto.NodeResult, error) {
	r.password = password
	return r.Send(ctx, raw, sha)
}
func readyService(t *testing.T) (*SQLStore, Config, NodeProfile, Instance, time.Time) {
	t.Helper()
	s, _ := mysqlTestStore(t)
	c, p, v, now := readyConsoleInstance(t, s)
	c.Service = ServiceConfig{SnapshotLimit: 1, Images: []CatalogImage{{ID: v.Resources.ImageID, Family: "linux", Name: "Ubuntu", Version: "22.04", MinDiskGB: 1, SHA256: strings.Repeat("a", 64), NodeIDs: []string{p.ID}}}}
	caps := testCapabilities(p, now)
	caps.GuestImages = map[string]nodeproto.GuestImageApproval{v.Resources.ImageID: {SHA256: strings.Repeat("a", 64), Family: "linux"}}
	caps.Actions = append(caps.Actions, "reinstall", "reset_password", "rescue_enter", "rescue_exit", "suspend", "unsuspend", "resize", "snapshot_create", "snapshot_restore", "snapshot_delete")
	if e := s.Heartbeat(context.Background(), p, caps, now, time.Minute); e != nil {
		t.Fatal(e)
	}
	return s, c, p, v, now
}
func TestMySQLServiceDurableReceiptsRedactedTasksAndLostSecrets(t *testing.T) {
	s, c, _, v, now := readyService(t)
	ctx := context.Background()
	secret := "persisted-state-must-never-contain-this-password"
	req := serviceapi.ActionRequest{Protocol: serviceapi.Protocol, OperationID: id(), OwnerRef: v.OwnerRef, Action: "reset_password", Params: serviceapi.Params{Password: secret}}
	receipt, replay, e := s.AdmitService(ctx, c, v.ID, req, now)
	if e != nil || replay || receipt.Status != "accepted" {
		t.Fatal(receipt, replay, e)
	}
	op, e := s.Operation(ctx, req.OperationID)
	if e != nil || strings.Contains(string(op.Request), secret) {
		t.Fatal("secret persisted", e)
	}
	task, e := nodeproto.DecodeTask(op.Request)
	if e != nil || !task.Guest.PasswordRequired || task.Guest.Params.Password != "" || task.Guest.SecretSHA256 != nodeproto.Digest([]byte(req.OperationID+":"+secret)) {
		t.Fatal("secret commitment missing", e)
	}
	if e = s.QuarantineServiceSecrets(ctx, now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	op, _ = s.Operation(ctx, req.OperationID)
	if op.State != "uncertain" {
		t.Fatal("lost secret remained dispatchable")
	}
	again, replay, e := s.AdmitService(ctx, c, v.ID, req, now)
	if e != nil || !replay || again.Result() != receipt.Result() {
		t.Fatal("first receipt changed", e)
	}
	req.Params.Password = "different"
	if _, _, e = s.AdmitService(ctx, c, v.ID, req, now); !errors.Is(e, ErrConflict) {
		t.Fatal("digest mismatch accepted", e)
	}
	req.OwnerRef = id()
	if _, _, e = s.AdmitService(ctx, c, v.ID, req, now); !errors.Is(e, ErrNotFound) {
		t.Fatal("owner mismatch exposed instance", e)
	}
	for _, query := range []string{"SELECT request_json FROM controller_operations WHERE id=?", "SELECT CONCAT(action,receipt_code,request_sha256,snapshot_name) FROM controller_service_operations WHERE operation_id=?", "SELECT CONCAT(actor,action,target) FROM controller_audit WHERE target=?"} {
		rows, e := s.DB.QueryContext(ctx, query, receipt.OperationID)
		if e != nil {
			t.Fatal(e)
		}
		for rows.Next() {
			var raw []byte
			if e = rows.Scan(&raw); e != nil {
				t.Fatal(e)
			}
			if strings.Contains(string(raw), secret) {
				t.Fatal("password persisted")
			}
		}
		rows.Close()
	}
}
func TestMySQLServiceDispatchUsesOneEphemeralSecretAndReadOnlyReconciliation(t *testing.T) {
	s, c, _, v, now := readyService(t)
	ctx := context.Background()
	req := serviceapi.ActionRequest{Protocol: serviceapi.Protocol, OperationID: id(), OwnerRef: v.OwnerRef, Action: "reset_password", Params: serviceapi.Params{Password: "one-send-only"}}
	if _, _, e := s.AdmitService(ctx, c, v.ID, req, now); e != nil {
		t.Fatal(e)
	}
	rpc := &guestRPC{}
	w := OperationWorker{Store: s, Config: c, GuestPassword: req.Params.Password, RPC: func(context.Context, NodeProfile) (NodeRPC, error) { return rpc, nil }, Now: func() time.Time { return now }}
	o, e := w.Dispatch(ctx, req.OperationID)
	if e != nil || o.State != "dispatched" || rpc.password != req.Params.Password {
		t.Fatal(o, e)
	}
	if _, e = w.Dispatch(ctx, req.OperationID); e == nil || rpc.posts.Load() != 1 {
		t.Fatal("duplicate POST")
	}
	rpc.Status = "succeeded"
	w.GuestPassword = ""
	o, e = w.Reconcile(ctx, req.OperationID)
	if e != nil || o.State != "succeeded" || rpc.posts.Load() != 1 {
		t.Fatal(o, e)
	}
}
func TestMySQLServiceRejectionsAreDurableAndSnapshotQuotaIsLocked(t *testing.T) {
	s, c, _, v, now := readyService(t)
	ctx := context.Background()
	c.Service.Images[0].Family = "windows"
	req := serviceapi.ActionRequest{Protocol: serviceapi.Protocol, OperationID: id(), OwnerRef: v.OwnerRef, Action: "reset_password", Params: serviceapi.Params{Password: "windows-refused"}}
	first, replay, e := s.AdmitService(ctx, c, v.ID, req, now)
	if e != nil || replay || first.Status != "rejected" || first.Code != "UNSUPPORTED_GUEST" {
		t.Fatal(first, e)
	}
	second, replay, e := s.AdmitService(ctx, c, v.ID, req, now)
	if e != nil || !replay || first.Result() != second.Result() {
		t.Fatal("rejection replay changed", e)
	}
	if _, e = s.DB.ExecContext(ctx, "UPDATE controller_instances SET state='shutoff' WHERE id=?", v.ID); e != nil {
		t.Fatal(e)
	}
	req = serviceapi.ActionRequest{Protocol: serviceapi.Protocol, OperationID: id(), OwnerRef: v.OwnerRef, Action: "snapshot_create", Params: serviceapi.Params{Name: "before"}}
	if receipt, _, e := s.AdmitService(ctx, c, v.ID, req, now); e != nil || receipt.Status != "accepted" {
		t.Fatal(receipt, e)
	}
	if _, e = s.DB.ExecContext(ctx, "UPDATE controller_operations SET state='succeeded' WHERE id=?", req.OperationID); e != nil {
		t.Fatal(e)
	}
	req.OperationID = id()
	receipt, _, e := s.AdmitService(ctx, c, v.ID, req, now)
	if e != nil || receipt.Code != "SNAPSHOT_LIMIT" {
		t.Fatal(receipt, e)
	}
	list, e := s.ServiceSnapshots(ctx, v.ID, 1)
	if e != nil || len(list.Items) != 1 || list.Items[0].Name != "before" || !list.RequiresStopped {
		t.Fatal(list, e)
	}
}

func TestMySQLServiceRunnerQuarantinesWhenDispatchCannotStart(t *testing.T) {
	for _, action := range []string{"start", "reset_password"} {
		t.Run(action, func(t *testing.T) {
			s, c, _, v, now := readyService(t)
			req := serviceapi.ActionRequest{Protocol: serviceapi.Protocol, OperationID: id(), OwnerRef: v.OwnerRef, Action: action}
			if action == "reset_password" {
				req.Params.Password = "lost-on-runner-capacity"
			}
			if _, _, e := s.AdmitService(context.Background(), c, v.ID, req, now); e != nil {
				t.Fatal(e)
			}
			r := NewOperationRunner(OperationWorker{Store: s, Config: c})
			r.Close()
			if e := r.StartService(req.OperationID, req.Params.Password); !errors.Is(e, ErrUnavailable) {
				t.Fatal(e)
			}
			o, e := s.Operation(context.Background(), req.OperationID)
			if e != nil || o.State != "uncertain" {
				t.Fatal(o, e)
			}
		})
	}
}

func TestMySQLServicePowerIntentRemainsReadOnlyAndUncertainIsUnknown(t *testing.T) {
	s, c, _, v, now := readyService(t)
	ctx := context.Background()
	r := serviceapi.ActionRequest{Protocol: serviceapi.Protocol, OperationID: id(), OwnerRef: v.OwnerRef, Action: "start"}
	if receipt, _, e := s.AdmitService(ctx, c, v.ID, r, now); e != nil || receipt.Status != "accepted" {
		t.Fatal(receipt, e)
	}
	if power, e := s.ServicePowerTransition(ctx, v.ID); e != nil || power != "starting" {
		t.Fatal(power, e)
	}
	if e := s.QuarantineServiceDispatch(ctx, r.OperationID, now); e != nil {
		t.Fatal(e)
	}
	if power, e := s.ServicePowerTransition(ctx, v.ID); e != nil || power != "unknown" {
		t.Fatal(power, e)
	}
	if o, e := s.Operation(ctx, r.OperationID); e != nil || o.State != "uncertain" {
		t.Fatal(o, e)
	}
}

func TestMySQLServiceRejectsMismatchedImageApprovalBeforeDispatch(t *testing.T) {
	s, c, _, v, now := readyService(t)
	ctx := context.Background()
	c.Service.Images[0].SHA256 = strings.Repeat("b", 64)
	r := serviceapi.ActionRequest{Protocol: serviceapi.Protocol, OperationID: id(), OwnerRef: v.OwnerRef, Action: "reinstall", Params: serviceapi.Params{ImageID: v.Resources.ImageID, Password: "unused-unapproved-image-secret"}}
	receipt, replay, e := s.AdmitService(ctx, c, v.ID, r, now)
	if e != nil || replay || receipt.Status != "rejected" || receipt.Code != "IMAGE_NOT_APPROVED" {
		t.Fatal(receipt, replay, e)
	}
	if _, e = s.Operation(ctx, r.OperationID); !errors.Is(e, ErrNotFound) {
		t.Fatal("unapproved image created dispatchable work", e)
	}
	c.Service.Images[0].SHA256 = strings.Repeat("a", 64)
	again, replay, e := s.AdmitService(ctx, c, v.ID, r, now)
	if e != nil || !replay || receipt.Result() != again.Result() {
		t.Fatal("approval change replaced the first receipt", again, replay, e)
	}
}

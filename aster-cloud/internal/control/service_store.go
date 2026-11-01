package control

import (
	"aster/billing/serviceapi"
	"aster/cloud/internal/nodeproto"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
)

var serviceCodePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

type ServiceReceipt struct {
	OperationID, InstanceID, OwnerRef, Action, Digest, Status, Code, SnapshotName string
	RequiresSecret                                                                bool
	CreatedAt                                                                     time.Time
}

func (r ServiceReceipt) Result() serviceapi.ActionResult {
	return serviceapi.ActionResult{OperationID: r.OperationID, Status: r.Status, Code: r.Code}
}

type serviceIntent struct {
	Receipt ServiceReceipt
	Params  serviceapi.Params
}
type ServiceFlags struct{ Suspended, RescueActive bool }
type ServiceStore interface {
	Instance(context.Context, string) (Instance, error)
	ServiceFlags(context.Context, string) (ServiceFlags, error)
	ServiceCapability(context.Context, Config, string, time.Time) (Capability, error)
	AdmitService(context.Context, Config, string, serviceapi.ActionRequest, time.Time) (ServiceReceipt, bool, error)
	ServiceReceipt(context.Context, string) (ServiceReceipt, error)
	Operation(context.Context, string) (Operation, error)
	ServiceSnapshots(context.Context, string, int) (serviceapi.Snapshots, error)
}

const serviceReceiptColumns = "operation_id,instance_id,owner_ref,action,request_sha256,receipt_status,receipt_code,requires_secret,snapshot_name,created_at"

func scanServiceReceipt(row interface{ Scan(...any) error }) (ServiceReceipt, error) {
	var r ServiceReceipt
	e := row.Scan(&r.OperationID, &r.InstanceID, &r.OwnerRef, &r.Action, &r.Digest, &r.Status, &r.Code, &r.RequiresSecret, &r.SnapshotName, &r.CreatedAt)
	if errors.Is(e, sql.ErrNoRows) {
		e = ErrNotFound
	}
	return r, e
}
func (s *SQLStore) ServiceReceipt(ctx context.Context, op string) (ServiceReceipt, error) {
	return scanServiceReceipt(s.DB.QueryRowContext(ctx, "SELECT "+serviceReceiptColumns+" FROM controller_service_operations WHERE operation_id=?", op))
}
func (s *SQLStore) ServiceFlags(ctx context.Context, instance string) (ServiceFlags, error) {
	var v ServiceFlags
	e := s.DB.QueryRowContext(ctx, "SELECT suspended,rescue_active FROM controller_service_state WHERE instance_id=?", instance).Scan(&v.Suspended, &v.RescueActive)
	if errors.Is(e, sql.ErrNoRows) {
		e = nil
	}
	return v, e
}
func (s *SQLStore) ServiceCapability(ctx context.Context, c Config, node string, now time.Time) (Capability, error) {
	return serviceCapability(ctx, s.DB, c, node, now)
}

type serviceQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func serviceCapability(ctx context.Context, q serviceQuerier, c Config, node string, now time.Time) (Capability, error) {
	var caps Capability
	var raw []byte
	var heartbeat sql.NullTime
	var maintenance bool
	var profile string
	p, ok := c.Node(node)
	if !ok {
		return caps, ErrState
	}
	e := q.QueryRowContext(ctx, "SELECT capabilities,heartbeat_at,maintenance,profile_sha256 FROM controller_nodes WHERE id=?", node).Scan(&raw, &heartbeat, &maintenance, &profile)
	if e != nil {
		return caps, e
	}
	if !strict(raw, &caps) || !heartbeat.Valid || maintenance || profile != p.Digest() || !heartbeatFresh(&heartbeat.Time, now, time.Duration(c.HeartbeatTTLSeconds)*time.Second) || caps.NodeID != node || caps.Maintenance {
		return Capability{}, ErrCapacity
	}
	return caps, nil
}
func serviceReceiptTx(ctx context.Context, tx *sql.Tx, r ServiceReceipt) error {
	_, e := tx.ExecContext(ctx, "INSERT INTO controller_service_operations("+serviceReceiptColumns+") VALUES(?,?,?,?,?,?,?,?,?,?)", r.OperationID, r.InstanceID, r.OwnerRef, r.Action, r.Digest, r.Status, r.Code, r.RequiresSecret, r.SnapshotName, r.CreatedAt)
	return e
}
func (s *SQLStore) AdmitService(ctx context.Context, c Config, instance string, r serviceapi.ActionRequest, now time.Time) (ServiceReceipt, bool, error) {
	_, digest, e := r.BytesAndDigest()
	if e != nil || !nodeproto.ValidID(instance) {
		return ServiceReceipt{}, false, ErrInput
	}
	receipt := ServiceReceipt{OperationID: r.OperationID, InstanceID: instance, OwnerRef: r.OwnerRef, Action: r.Action, Digest: digest, Status: "accepted", Code: "ACCEPTED", RequiresSecret: r.Params.Password != "", SnapshotName: r.Params.Name, CreatedAt: now}
	if r.Params.SSHPublicKey != "" && !nodeproto.ValidGuestSSHKey(r.Params.SSHPublicKey) {
		receipt.Status, receipt.Code = "rejected", "INVALID_SSH_PUBLIC_KEY"
		return s.rejectService(ctx, receipt)
	}
	if r.Action == "terminate" && r.Params.Confirmation != instance {
		receipt.Status, receipt.Code = "rejected", "CONFIRMATION_REQUIRED"
		return s.rejectService(ctx, receipt)
	}
	in := OperationInput{Action: r.Action, Confirmation: instance, ArtifactID: r.Params.SnapshotID}
	if in.Action == "stop" {
		in.Action = "shutdown"
	}
	if in.Action == "terminate" {
		in.Action = "delete"
	}
	if nodeproto.GuestAction(in.Action) {
		in.Guest = nodeproto.GuestParams{Params: r.Params.Redacted(), PasswordRequired: receipt.RequiresSecret}
		if receipt.RequiresSecret {
			in.Guest.SecretSHA256 = nodeproto.Digest([]byte(r.OperationID + ":" + r.Params.Password))
		}
		if r.Params.ImageID != "" {
			for _, im := range c.Service.Images {
				if im.ID == r.Params.ImageID {
					in.Guest.ImageSHA256 = im.SHA256
				}
			}
		}
	}
	in.service = &serviceIntent{Receipt: receipt, Params: r.Params.Redacted()}
	_, replay, e := s.createOperation(ctx, c, r.OwnerRef, instance, r.OperationID, in, now, nil)
	if e == nil {
		saved, e := s.ServiceReceipt(ctx, r.OperationID)
		return saved, replay, e
	}
	if !errors.Is(e, ErrState) && !errors.Is(e, ErrCapacity) && !errors.Is(e, ErrInput) {
		var rejection *serviceRejection
		if !errors.As(e, &rejection) {
			return ServiceReceipt{}, false, e
		}
	}
	receipt.Status = "rejected"
	receipt.Code = "STATE_CONFLICT"
	switch {
	case errors.Is(e, ErrCapacity):
		receipt.Code = "NODE_NOT_READY"
	case errors.Is(e, ErrInput):
		receipt.Code = "UNSUPPORTED_ACTION"
	}
	var rejection *serviceRejection
	if errors.As(e, &rejection) {
		receipt.Code = rejection.Code
	}
	return s.rejectService(ctx, receipt)
}

type serviceRejection struct{ Code string }

func (e *serviceRejection) Error() string { return e.Code }
func serviceReject(code string) error     { return &serviceRejection{code} }
func supportsServiceImage(c Capability, im CatalogImage) bool {
	node, ok := c.GuestImages[im.ID]
	return ok && contains(c.ImageIDs, im.ID) && node.SHA256 == im.SHA256 && node.Family == im.Family && (!im.Rescue || node.Rescue)
}
func bindServiceReceipt(prior, wanted ServiceReceipt) error {
	if prior.InstanceID != wanted.InstanceID || prior.OwnerRef != wanted.OwnerRef || prior.Digest != wanted.Digest {
		return ErrConflict
	}
	return nil
}
func checkServiceOwnerTx(ctx context.Context, tx *sql.Tx, r ServiceReceipt) error {
	var owner string
	e := tx.QueryRowContext(ctx, "SELECT owner_ref FROM controller_instances WHERE id=?", r.InstanceID).Scan(&owner)
	if e != nil || owner != r.OwnerRef {
		return ErrNotFound
	}
	return nil
}
func (s *SQLStore) rejectService(ctx context.Context, r ServiceReceipt) (ServiceReceipt, bool, error) {
	tx, e := s.locked(ctx)
	if e != nil {
		return r, false, e
	}
	defer tx.Rollback()
	if e = checkServiceOwnerTx(ctx, tx, r); e != nil {
		return r, false, e
	}
	prior, e := scanServiceReceipt(tx.QueryRowContext(ctx, "SELECT "+serviceReceiptColumns+" FROM controller_service_operations WHERE operation_id=?", r.OperationID))
	if e == nil {
		if e = bindServiceReceipt(prior, r); e != nil {
			return r, false, e
		}
		return prior, true, tx.Commit()
	}
	if !errors.Is(e, ErrNotFound) {
		return r, false, e
	}
	var used int
	if e = tx.QueryRowContext(ctx, "SELECT (SELECT COUNT(*) FROM controller_operations WHERE id=?)+(SELECT COUNT(*) FROM controller_jobs WHERE operation_id=?)", r.OperationID, r.OperationID).Scan(&used); e != nil {
		return r, false, e
	}
	if used != 0 {
		return r, false, ErrConflict
	}
	if e = publicResourceIDUnusedTx(ctx, tx, r.OperationID); e != nil {
		return r, false, e
	}
	if e = serviceReceiptTx(ctx, tx, r); e != nil {
		return r, false, e
	}
	if e = audit(ctx, tx, "billing", "service.rejected", r.OperationID, r.CreatedAt); e != nil {
		return r, false, e
	}
	return r, false, tx.Commit()
}
func serviceGateTx(ctx context.Context, tx *sql.Tx, c Config, v Instance, in OperationInput, now time.Time) error {
	caps, e := serviceCapability(ctx, tx, c, v.NodeID, now)
	if e != nil {
		return e
	}
	if !contains(caps.Actions, in.Action) {
		return serviceReject("UNSUPPORTED_ACTION")
	}
	flags := ServiceFlags{}
	e = tx.QueryRowContext(ctx, "SELECT suspended,rescue_active FROM controller_service_state WHERE instance_id=?", v.ID).Scan(&flags.Suspended, &flags.RescueActive)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	if flags.Suspended && (in.Action == "start" || in.Action == "reboot" || in.Action == "reinstall" || in.Action == "reset_password" || in.Action == "rescue_enter" || in.Action == "rescue_exit") {
		return serviceReject("INSTANCE_SUSPENDED")
	}
	if flags.RescueActive && (strings.HasPrefix(in.Action, "snapshot_") || in.Action == "reinstall" || in.Action == "reset_password" || in.Action == "resize") {
		return serviceReject("RESCUE_ACTIVE")
	}
	if v.Resources.NetworkType != "normal" && nodeproto.GuestAction(in.Action) && in.Action != "suspend" && in.Action != "unsuspend" {
		return serviceReject("UNSUPPORTED_NETWORK")
	}
	if in.Action == "reset_password" {
		im, ok := c.serviceImage(v.Resources.ImageID, v.NodeID)
		if !ok || im.Family != "linux" {
			return serviceReject("UNSUPPORTED_GUEST")
		}
		if !supportsServiceImage(caps, im) {
			return serviceReject("IMAGE_NOT_APPROVED")
		}
	}
	if in.Action == "reinstall" || in.Action == "rescue_enter" {
		im, ok := c.serviceImage(in.Guest.Params.ImageID, v.NodeID)
		if !ok || im.SHA256 != in.Guest.ImageSHA256 || !supportsServiceImage(caps, im) || im.MinDiskGB > v.Resources.SystemDiskGiB || in.Action == "rescue_enter" && !im.Rescue {
			return serviceReject("IMAGE_NOT_APPROVED")
		}
		if im.Family != "linux" {
			return serviceReject("UNSUPPORTED_GUEST")
		}
	}
	if in.Action == "resize" && in.Guest.Params.SetBandwidth {
		proposed := v.Resources
		proposed.BandwidthMbps = in.Guest.Params.BandwidthMbps
		proposed.InboundBandwidthMbps = in.Guest.Params.InboundBandwidthMbps
		if !supportsNormalBandwidth(caps, proposed) {
			return serviceReject("UNSUPPORTED_BANDWIDTH")
		}
	}
	if in.Action == "resize" && in.Guest.Params.DiskGB < v.Resources.SystemDiskGiB {
		return serviceReject("DISK_SHRINK_FORBIDDEN")
	}
	if in.Action == "snapshot_create" {
		var count int
		e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM controller_artifacts WHERE instance_id=? AND kind='snapshot' AND state<>'deleted'", v.ID).Scan(&count)
		if e != nil {
			return e
		}
		if count >= c.Service.SnapshotLimit {
			return serviceReject("SNAPSHOT_LIMIT")
		}
	}
	return nil
}
func (s *SQLStore) ServiceSnapshots(ctx context.Context, instance string, limit int) (serviceapi.Snapshots, error) {
	result := serviceapi.Snapshots{Items: []serviceapi.Snapshot{}, Limit: limit, RequiresStopped: true}
	rows, e := s.DB.QueryContext(ctx, `SELECT a.id,COALESCE(s.snapshot_name,''),a.state,a.created_at FROM controller_artifacts a LEFT JOIN controller_service_operations s ON s.operation_id=a.id WHERE a.instance_id=? AND a.kind='snapshot' AND a.state<>'deleted' ORDER BY a.created_at,a.id`, instance)
	if e != nil {
		return result, e
	}
	defer rows.Close()
	for rows.Next() {
		var item serviceapi.Snapshot
		if e = rows.Scan(&item.ID, &item.Name, &item.Status, &item.CreatedAt); e != nil {
			return result, e
		}
		result.Items = append(result.Items, item)
	}
	return result, rows.Err()
}

// Startup cannot recover credentials. This changes no node state and cannot
// retry a POST; accepted secret work is quarantined for an explicit decision.
func (s *SQLStore) QuarantineServiceSecrets(ctx context.Context, now time.Time) error {
	_, e := s.DB.ExecContext(ctx, `UPDATE controller_operations o JOIN controller_service_operations s ON s.operation_id=o.id SET o.state='uncertain',o.updated_at=? WHERE s.requires_secret=TRUE AND o.state='accepted'`, now)
	return e
}

// If an explicitly launched dispatch cannot claim its intent, quarantine it.
// An unavailable in-memory worker must not leave accepted work stranded.
func (s *SQLStore) QuarantineServiceDispatch(ctx context.Context, op string, now time.Time) error {
	_, e := s.DB.ExecContext(ctx, `UPDATE controller_operations o JOIN controller_service_operations s ON s.operation_id=o.id SET o.state='uncertain',o.updated_at=? WHERE o.id=? AND o.state='accepted'`, now, op)
	return e
}
func completeServiceTx(ctx context.Context, tx *sql.Tx, o Operation, now time.Time) error {
	if !nodeproto.GuestAction(o.Action) {
		return nil
	}
	t, e := nodeproto.DecodeTask(o.Request)
	if e != nil {
		return e
	}
	switch o.Action {
	case "suspend", "unsuspend":
		_, e = tx.ExecContext(ctx, "INSERT INTO controller_service_state(instance_id,suspended) VALUES(?,?) ON DUPLICATE KEY UPDATE suspended=VALUES(suspended)", o.InstanceID, o.Action == "suspend")
	case "rescue_enter", "rescue_exit":
		_, e = tx.ExecContext(ctx, "INSERT INTO controller_service_state(instance_id,rescue_active) VALUES(?,?) ON DUPLICATE KEY UPDATE rescue_active=VALUES(rescue_active)", o.InstanceID, o.Action == "rescue_enter")
	case "resize", "reinstall":
		resources := t.Resources
		if o.Action == "reinstall" {
			resources.ImageID = t.Guest.Params.ImageID
		} else {
			resources.CPUCores = t.Guest.Params.CPUCores
			resources.MemoryMiB = t.Guest.Params.MemoryMB
			resources.SystemDiskGiB = t.Guest.Params.DiskGB
			if t.Guest.Params.SetBandwidth {
				resources.BandwidthMbps = t.Guest.Params.BandwidthMbps
				resources.InboundBandwidthMbps = t.Guest.Params.InboundBandwidthMbps
			}
		}
		raw, _ := json.Marshal(resources)
		_, e = tx.ExecContext(ctx, "UPDATE controller_instances SET resources=?,updated_at=? WHERE id=?", raw, now, o.InstanceID)
	}
	return e
}

func (s *SQLStore) ServiceOperationCode(ctx context.Context, op string) (string, error) {
	var code string
	e := s.DB.QueryRowContext(ctx, "SELECT result_code FROM controller_service_operations WHERE operation_id=?", op).Scan(&code)
	return code, e
}

// ServicePowerTransition reports durable intent, without dispatch or reconcile.
func (s *SQLStore) ServicePowerTransition(ctx context.Context, instance string) (string, error) {
	var action, state string
	var raw []byte
	e := s.DB.QueryRowContext(ctx, "SELECT action,state,request_json FROM controller_operations WHERE instance_id=? AND state IN ('accepted','sending','dispatched','uncertain') ORDER BY seq DESC LIMIT 1", instance).Scan(&action, &state, &raw)
	if errors.Is(e, sql.ErrNoRows) {
		return "", nil
	}
	if e != nil {
		return "", e
	}
	if state == "uncertain" {
		return "unknown", nil
	}
	switch action {
	case "start", "rescue_enter", "rescue_exit":
		return "starting", nil
	case "shutdown", "force_off", "suspend":
		return "stopping", nil
	case "reboot":
		return "rebooting", nil
	case "reinstall":
		return "reinstalling", nil
	case "unsuspend":
		if task, e := nodeproto.DecodeTask(raw); e == nil && task.Guest.Params.StartAfter {
			return "starting", nil
		}
	}
	return "", nil
}
func (s *SQLStore) recordServiceCode(ctx context.Context, op, code string) {
	if code != "" && serviceCodePattern.MatchString(code) {
		_, _ = s.DB.ExecContext(ctx, "UPDATE controller_service_operations SET result_code=? WHERE operation_id=?", code, op)
	}
}

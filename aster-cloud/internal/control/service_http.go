package control

import (
	"aster/billing/serviceapi"
	"aster/cloud/internal/nodeproto"
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"sort"
	"strings"
	"time"
)

type ServiceLauncher interface{ StartService(string, string) error }
type Services struct {
	Store        ServiceStore
	Config       Config
	Runner       ServiceLauncher
	Observe      func(context.Context, NodeProfile, string) (nodeproto.InstanceObservation, error)
	IssueConsole func(context.Context, Instance) (serviceapi.Console, error)
}

func (s *Services) Handle(w http.ResponseWriter, r *http.Request, now time.Time) {
	if s == nil || s.Store == nil {
		failure(w, 503, "SERVICE_UNAVAILABLE")
		return
	}
	owner := r.Header.Values("X-Aster-Owner-Ref")
	if len(owner) != 1 || !serviceapi.ValidID(owner[0]) {
		failure(w, 404, "NOT_FOUND")
		return
	}
	if r.URL.Path == "/v1/images" {
		if r.Method != "GET" {
			failure(w, 405, "METHOD_NOT_ALLOWED")
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			failure(w, 400, "INVALID_QUERY")
			return
		}
		images := []serviceapi.Image{}
		for _, im := range s.Config.Service.Images {
			images = append(images, im.Public())
		}
		sort.Slice(images, func(i, j int) bool { return images[i].ID < images[j].ID })
		output(w, 200, images)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/services/"), "/")
	if len(parts) < 1 || len(parts) > 3 || !serviceapi.ValidID(parts[0]) {
		failure(w, 404, "NOT_FOUND")
		return
	}
	v, e := s.Store.Instance(r.Context(), parts[0])
	if e != nil || v.OwnerRef != owner[0] {
		failure(w, 404, "NOT_FOUND")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		if len(parts) != 2 || parts[1] != "metrics" {
			failure(w, 400, "INVALID_QUERY")
			return
		}
	}
	if len(parts) == 1 {
		if r.Method != "GET" {
			failure(w, 405, "METHOD_NOT_ALLOWED")
			return
		}
		s.view(w, r, v, now)
		return
	}
	if len(parts) == 3 {
		if parts[1] != "actions" || !serviceapi.ValidID(parts[2]) {
			failure(w, 404, "NOT_FOUND")
			return
		}
		if r.Method != "GET" {
			failure(w, 405, "METHOD_NOT_ALLOWED")
			return
		}
		s.operation(w, r, v, parts[2])
		return
	}
	switch parts[1] {
	case "actions":
		if r.Method != "POST" {
			failure(w, 405, "METHOD_NOT_ALLOWED")
			return
		}
		s.action(w, r, v, now)
	case "snapshots":
		if r.Method != "GET" {
			failure(w, 405, "METHOD_NOT_ALLOWED")
			return
		}
		items, e := s.Store.ServiceSnapshots(r.Context(), v.ID, s.Config.Service.SnapshotLimit)
		if e != nil {
			failure(w, 503, "STORAGE_UNAVAILABLE")
			return
		}
		output(w, 200, items)
	case "metrics":
		if r.Method != "GET" {
			failure(w, 405, "METHOD_NOT_ALLOWED")
			return
		}
		q := r.URL.Query()
		if len(q) != 1 || len(q["range"]) != 1 || !serviceapi.ValidRange(q.Get("range")) || r.URL.RawQuery != "range="+q.Get("range") {
			failure(w, 400, "INVALID_RANGE")
			return
		}
		if reader, ok := s.Store.(interface {
			ServiceMetrics(context.Context, string, string, time.Time) (serviceapi.Metrics, error)
		}); ok {
			v, e := reader.ServiceMetrics(r.Context(), v.ID, q.Get("range"), now)
			if e != nil {
				failure(w, 503, "METRICS_UNAVAILABLE")
				return
			}
			output(w, 200, v)
		} else {
			output(w, 200, serviceapi.Metrics{StepSeconds: 300, Points: []serviceapi.MetricPoint{}})
		}
	case "console":
		if r.Method != "POST" {
			failure(w, 405, "METHOD_NOT_ALLOWED")
			return
		}
		if s.IssueConsole == nil || v.State == "deleted" {
			failure(w, 409, "CONSOLE_UNAVAILABLE")
			return
		}
		ticket, e := s.IssueConsole(r.Context(), v)
		if e != nil {
			failure(w, 409, "CONSOLE_UNAVAILABLE")
			return
		}
		output(w, 200, ticket)
	default:
		failure(w, 404, "NOT_FOUND")
	}
}
func (s *Services) action(w http.ResponseWriter, r *http.Request, v Instance, now time.Time) {
	media, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || media != "application/json" {
		failure(w, 415, "JSON_REQUIRED")
		return
	}
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 65536))
	var request serviceapi.ActionRequest
	if e != nil || !strict(raw, &request) || !request.Valid() {
		failure(w, 400, "INVALID_SERVICE_REQUEST")
		return
	}
	if request.OwnerRef != v.OwnerRef {
		failure(w, 404, "NOT_FOUND")
		return
	}
	_, digest, e := request.BytesAndDigest()
	if e != nil || len(r.Header.Values("Idempotency-Key")) != 1 || len(r.Header.Values("X-Aster-Request-SHA256")) != 1 || r.Header.Get("Idempotency-Key") != request.OperationID || r.Header.Get("X-Aster-Request-SHA256") != digest {
		failure(w, 400, "REQUEST_BINDING_REQUIRED")
		return
	}
	receipt, replay, e := s.Store.AdmitService(r.Context(), s.Config, v.ID, request, now)
	switch {
	case errors.Is(e, ErrConflict):
		failure(w, 409, "IDEMPOTENCY_CONFLICT")
		return
	case errors.Is(e, ErrNotFound):
		failure(w, 404, "NOT_FOUND")
		return
	case e != nil:
		failure(w, 503, "STORAGE_UNAVAILABLE")
		return
	}
	if !replay && receipt.Status == "accepted" && s.Runner != nil {
		_ = s.Runner.StartService(receipt.OperationID, request.Params.Password)
	}
	status := 202
	if replay {
		status = 409
	}
	output(w, status, receipt.Result())
}
func (s *Services) operation(w http.ResponseWriter, r *http.Request, v Instance, id string) {
	receipt, e := s.Store.ServiceReceipt(r.Context(), id)
	if e != nil || receipt.InstanceID != v.ID || receipt.OwnerRef != v.OwnerRef {
		failure(w, 404, "NOT_FOUND")
		return
	}
	result := serviceapi.Operation{OperationID: id, Action: receipt.Action, Status: "failed", Code: receipt.Code, FinishedAt: &receipt.CreatedAt}
	if receipt.Status == "accepted" {
		op, e := s.Store.Operation(r.Context(), id)
		if e != nil {
			failure(w, 503, "STORAGE_UNAVAILABLE")
			return
		}
		result.Status = map[string]string{"accepted": "accepted", "sending": "running", "dispatched": "running", "succeeded": "succeeded", "rejected": "failed", "uncertain": "uncertain", "resolved": "uncertain"}[op.State]
		if result.Status == "" {
			result.Status = "uncertain"
		}
		result.Code = strings.ToUpper(result.Status)
		result.FinishedAt = nil
		if result.Status == "succeeded" || result.Status == "failed" {
			result.FinishedAt = &op.UpdatedAt
		}
	}
	if codes, ok := s.Store.(interface {
		ServiceOperationCode(context.Context, string) (string, error)
	}); ok {
		if code, e := codes.ServiceOperationCode(r.Context(), id); e == nil && code != "" {
			result.Code = code
		}
	}
	output(w, 200, result)
}
func (s *Services) observe(ctx context.Context, v Instance) (nodeproto.InstanceObservation, error) {
	p, ok := s.Config.Node(v.NodeID)
	if !ok {
		return nodeproto.InstanceObservation{}, ErrState
	}
	if s.Observe != nil {
		return s.Observe(ctx, p, v.ID)
	}
	c, e := NewNodeClient(ctx, p)
	if e != nil {
		return nodeproto.InstanceObservation{}, e
	}
	return c.Observe(ctx, v.ID)
}
func (s *Services) view(w http.ResponseWriter, r *http.Request, v Instance, now time.Time) {
	flags, e := s.Store.ServiceFlags(r.Context(), v.ID)
	if e != nil {
		failure(w, 503, "STORAGE_UNAVAILABLE")
		return
	}
	caps, _ := s.Store.ServiceCapability(r.Context(), s.Config, v.NodeID, now)
	result := serviceapi.Service{Protocol: serviceapi.Protocol, ResourceID: v.ID, OwnerRef: v.OwnerRef, Power: "unknown", Suspended: flags.Suspended, RescueActive: flags.RescueActive, IPv4: []string{}, IPv6: []string{}, OSImageID: v.Resources.ImageID, Specs: serviceapi.Specs{CPUCores: v.Resources.CPUCores, MemoryMB: v.Resources.MemoryMiB, DiskGB: v.Resources.SystemDiskGiB, BandwidthMbps: v.Resources.BandwidthMbps}}
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	result.Traffic = serviceapi.Traffic{PeriodStart: start, PeriodEnd: start.AddDate(0, 1, 0)}
	if reader, ok := s.Store.(interface {
		ServiceTraffic(context.Context, string, time.Time) (serviceapi.Traffic, error)
	}); ok {
		traffic, e := reader.ServiceTraffic(r.Context(), v.ID, now)
		if e != nil {
			failure(w, 503, "TRAFFIC_UNAVAILABLE")
			return
		}
		result.Traffic = traffic
	}
	if observed, e := s.observe(r.Context(), v); e == nil && observed.InstanceID == v.ID && observed.OwnerRef == v.OwnerRef && observed.NodeID == v.NodeID && observed.Hostname == v.Hostname {
		switch observed.State {
		case "running":
			result.Power = "running"
		case "shutoff", "shut off":
			result.Power = "stopped"
		case "in_shutdown":
			result.Power = "stopping"
		}
		result.Suspended = observed.Suspended
		result.RescueActive = observed.RescueActive
		if observed.IPv4 != "" {
			result.IPv4 = append(result.IPv4, observed.IPv4)
		}
	}
	im, linux := s.Config.serviceImage(v.Resources.ImageID, v.NodeID)
	linux = linux && im.Family == "linux"
	normal := v.Resources.NetworkType == "normal"
	approved, rescue := false, false
	for _, im := range s.Config.Service.Images {
		if contains(im.NodeIDs, v.NodeID) && contains(caps.ImageIDs, im.ID) && im.Family == "linux" && im.MinDiskGB <= v.Resources.SystemDiskGiB {
			if im.Rescue {
				rescue = true
			} else {
				approved = true
			}
		}
	}
	_, metrics := s.Store.(interface {
		ServiceMetrics(context.Context, string, string, time.Time) (serviceapi.Metrics, error)
	})
	result.Capabilities = serviceapi.Capabilities{Power: contains(caps.Actions, "start") && contains(caps.Actions, "shutdown") && contains(caps.Actions, "force_off"), Reinstall: normal && approved && contains(caps.Actions, "reinstall"), ResetPassword: normal && linux && contains(caps.Actions, "reset_password"), Console: s.IssueConsole != nil && contains(caps.Actions, "console"), Rescue: normal && rescue && contains(caps.Actions, "rescue_enter") && contains(caps.Actions, "rescue_exit"), Snapshots: normal && s.Config.Service.SnapshotLimit > 0 && contains(caps.Actions, "snapshot_create") && contains(caps.Actions, "snapshot_restore") && contains(caps.Actions, "snapshot_delete"), Metrics: metrics && contains(caps.Actions, "metrics"), Upgrade: normal && contains(caps.Actions, "resize")}
	if v.State == "deleted" {
		result.Capabilities = serviceapi.Capabilities{}
	}
	// Revalidate ownership/placement after the remote observation.
	latest, e := s.Store.Instance(r.Context(), v.ID)
	if e != nil || latest.OwnerRef != v.OwnerRef || latest.NodeID != v.NodeID || latest.Resources != v.Resources {
		failure(w, 404, "NOT_FOUND")
		return
	}
	output(w, 200, result)
}

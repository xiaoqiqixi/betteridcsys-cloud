package control

import (
	"aster/cloud/internal/identity"
	"aster/cloud/internal/nodeproto"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (c Console) publicIPResources(w http.ResponseWriter, r *http.Request) {
	actor, ok := identity.Actor(r.Context())
	if !ok || !actor.Enabled || !actor.Can("nodes.read") {
		failure(w, 403, "FORBIDDEN")
		return
	}
	if r.URL.RawPath != "" || r.URL.ForceQuery {
		failure(w, 400, "INVALID_REQUEST")
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/console/v1/public-ips/"), "/")
	query, e := url.ParseQuery(r.URL.RawQuery)
	if e != nil {
		failure(w, 400, "INVALID_QUERY")
		return
	}
	for k, values := range query {
		if len(values) != 1 || values[0] == "" || len(parts) != 1 || k != "cursor" && k != "cluster_id" && k != "pool_id" && k != "owner_ref" && k != "instance_id" || parts[0] == "resource-operations" && k != "cursor" {
			failure(w, 400, "INVALID_QUERY")
			return
		}
	}
	if r.Method == http.MethodGet {
		switch {
		case len(parts) == 1 && parts[0] == "resources":
			items, next, e := c.Store.PublicIPResourcesFor(r.Context(), c.Config, query.Get("cluster_id"), query.Get("pool_id"), query.Get("owner_ref"), query.Get("instance_id"), query.Get("cursor"))
			if e != nil {
				publicIPError(w, e)
				return
			}
			output(w, 200, map[string]any{"items": items, "next_cursor": publicIPCursor(next)})
			return
		case len(parts) == 2 && parts[0] == "resources" && nodeproto.ValidID(parts[1]):
			v, e := c.Store.PublicIPResource(r.Context(), c.Config, parts[1])
			if e != nil {
				publicIPError(w, e)
				return
			}
			output(w, 200, map[string]any{"resource": v})
			return
		case len(parts) == 1 && parts[0] == "resource-operations":
			items, next, e := c.Store.PublicIPResourceOperations(r.Context(), actor.ID, query.Get("cursor"))
			if e != nil {
				publicIPError(w, e)
				return
			}
			output(w, 200, map[string]any{"items": items, "next_cursor": publicIPCursor(next)})
			return
		case len(parts) == 2 && parts[0] == "resource-operations" && nodeproto.ValidID(parts[1]):
			v, e := c.Store.PublicIPResourceOperation(r.Context(), actor.ID, parts[1])
			if e != nil {
				publicIPError(w, e)
				return
			}
			output(w, 200, map[string]any{"operation": v})
			return
		}
		failure(w, 404, "NOT_FOUND")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		failure(w, 405, "METHOD_NOT_ALLOWED")
		return
	}
	if !actor.Can("nodes.manage") || !actor.Can("instances.manage") {
		failure(w, 403, "FORBIDDEN")
		return
	}
	if r.URL.RawQuery != "" {
		failure(w, 400, "INVALID_QUERY")
		return
	}
	keys := r.Header.Values("Idempotency-Key")
	if len(keys) != 1 || !nodeproto.ValidID(keys[0]) {
		failure(w, 400, "IDEMPOTENCY_KEY_REQUIRED")
		return
	}
	op := keys[0]
	now := time.Now().UTC()
	var resource PublicIPResource
	var operation PublicIPResourceOperation
	var replay bool
	switch {
	case len(parts) == 1 && parts[0] == "resources":
		var in PublicIPResourceInput
		if !readPublicIPJSON(w, r, &in) {
			return
		}
		resource, operation, replay, e = c.Store.AllocatePublicIPResource(r.Context(), c.Config, actor.ID, op, in, now)
	case len(parts) == 3 && parts[0] == "resources" && nodeproto.ValidID(parts[1]) && parts[2] == "binding":
		var in publicResourceBindingInput
		if !readPublicIPJSON(w, r, &in) {
			return
		}
		if in.ExpectedGeneration == nil {
			failure(w, 400, "INVALID_REQUEST")
			return
		}
		resource, operation, replay, e = c.Store.BindPublicIPResourceWithIngress(r.Context(), c.Config, actor.ID, op, parts[1], in.InstanceID, false, *in.ExpectedGeneration, in.ExpectedIngressRevision, now)
	case len(parts) == 3 && parts[0] == "resources" && nodeproto.ValidID(parts[1]) && parts[2] == "recover":
		var in struct {
			ExpectedGeneration     *uint64 `json:"expected_generation"`
			ExpectedSnapshotSHA256 string  `json:"expected_snapshot_sha256"`
		}
		if !readPublicIPJSON(w, r, &in) {
			return
		}
		if in.ExpectedGeneration == nil {
			failure(w, 400, "INVALID_REQUEST")
			return
		}
		resource, operation, replay, e = c.overlayWorker().RecoverPublicIPResource(r.Context(), actor.ID, op, parts[1], *in.ExpectedGeneration, in.ExpectedSnapshotSHA256)
	case len(parts) == 3 && parts[0] == "resources" && nodeproto.ValidID(parts[1]) && (parts[2] == "unbind" || parts[2] == "release"):
		var in struct {
			ExpectedGeneration *uint64 `json:"expected_generation"`
		}
		if !readPublicIPJSON(w, r, &in) {
			return
		}
		if in.ExpectedGeneration == nil {
			failure(w, 400, "INVALID_REQUEST")
			return
		}
		if parts[2] == "unbind" {
			resource, operation, replay, e = c.Store.BindPublicIPResource(r.Context(), c.Config, actor.ID, op, parts[1], "", true, *in.ExpectedGeneration, now)
		} else {
			resource, operation, replay, e = c.Store.ReleasePublicIPResource(r.Context(), c.Config, actor.ID, op, parts[1], *in.ExpectedGeneration, now)
		}
	default:
		failure(w, 404, "NOT_FOUND")
		return
	}
	if e != nil {
		publicIPError(w, e)
		return
	}
	status := 200
	if !replay && len(parts) == 3 && (parts[2] == "binding" || parts[2] == "unbind" || parts[2] == "recover") {
		status = 202
	}
	if len(parts) == 1 && !replay {
		status = 201
	}
	output(w, status, map[string]any{"resource": resource, "operation": operation, "replay": replay})
}

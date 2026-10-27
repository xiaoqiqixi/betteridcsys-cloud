package control

import (
	"aster/cloud/internal/identity"
	"aster/cloud/internal/nodeproto"
	"bytes"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (c Console) publicIPs(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/console/v1/public-ips/resources") || strings.HasPrefix(r.URL.Path, "/console/v1/public-ips/resource-operations") {
		c.publicIPResources(w, r)
		return
	}

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
	if len(parts) < 1 || len(parts) > 3 {
		failure(w, 404, "NOT_FOUND")
		return
	}
	query, e := url.ParseQuery(r.URL.RawQuery)
	if e != nil {
		failure(w, 400, "INVALID_QUERY")
		return
	}
	for key, values := range query {
		if len(values) != 1 || values[0] == "" || len(parts) != 1 || (key != "cursor" && key != "cluster_id" && key != "pool_id") || parts[0] != "pools" && parts[0] != "leases" && parts[0] != "operations" || key == "pool_id" && parts[0] != "leases" || key == "cluster_id" && parts[0] == "operations" {
			failure(w, 400, "INVALID_QUERY")
			return
		}
	}
	if r.Method == http.MethodGet {
		switch {
		case len(parts) == 1 && parts[0] == "options" && r.URL.RawQuery == "":
			v, e := c.Store.PublicIPOptions(r.Context(), c.Config)
			if e != nil {
				publicIPError(w, e)
				return
			}
			output(w, 200, v)
			return
		case len(parts) == 1 && parts[0] == "pools":
			items, next, e := c.Store.PublicIPPools(r.Context(), query.Get("cluster_id"), query.Get("cursor"))
			if e != nil {
				publicIPError(w, e)
				return
			}
			output(w, 200, map[string]any{"items": items, "next_cursor": publicIPCursor(next)})
			return
		case len(parts) == 2 && parts[0] == "pools" && nodeproto.ValidID(parts[1]):
			v, e := c.Store.PublicIPPool(r.Context(), parts[1])
			if e != nil {
				publicIPError(w, e)
				return
			}
			output(w, 200, map[string]any{"pool": v})
			return
		case len(parts) == 1 && parts[0] == "leases":
			items, next, e := c.Store.PublicIPLeases(r.Context(), c.Config, query.Get("cluster_id"), query.Get("pool_id"), query.Get("cursor"))
			if e != nil {
				publicIPError(w, e)
				return
			}
			output(w, 200, map[string]any{"items": items, "next_cursor": publicIPCursor(next)})
			return
		case len(parts) == 2 && parts[0] == "leases" && nodeproto.ValidID(parts[1]):
			v, e := c.Store.PublicIPLease(r.Context(), c.Config, parts[1])
			if e != nil {
				publicIPError(w, e)
				return
			}
			output(w, 200, map[string]any{"lease": v})
			return
		case len(parts) == 1 && parts[0] == "operations":
			items, next, e := c.Store.PublicIPOperations(r.Context(), actor.ID, query.Get("cursor"))
			if e != nil {
				publicIPError(w, e)
				return
			}
			output(w, 200, map[string]any{"items": items, "next_cursor": publicIPCursor(next)})
			return
		case len(parts) == 2 && parts[0] == "operations" && nodeproto.ValidID(parts[1]):
			v, e := c.Store.PublicIPOperation(r.Context(), actor.ID, parts[1])
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
	key := keys[0]
	now := time.Now().UTC()
	switch {
	case len(parts) == 1 && parts[0] == "pools":
		var in PublicIPPoolInput
		if !readPublicIPJSON(w, r, &in) {
			return
		}
		v, op, replay, e := c.Store.CreatePublicIPPool(r.Context(), c.Config, actor.ID, key, in, now)
		if e != nil {
			publicIPError(w, e)
			return
		}
		status := 201
		if replay {
			status = 200
		}
		output(w, status, map[string]any{"pool": v, "operation": op, "replay": replay})
		return
	case len(parts) == 3 && parts[0] == "pools" && nodeproto.ValidID(parts[1]) && parts[2] == "addresses":
		var in struct {
			Addresses []string `json:"addresses"`
		}
		if !readPublicIPJSON(w, r, &in) {
			return
		}
		v, op, replay, e := c.Store.ExtendPublicIPPool(r.Context(), c.Config, actor.ID, key, parts[1], in.Addresses, now)
		if e != nil {
			publicIPError(w, e)
			return
		}
		output(w, 200, map[string]any{"pool": v, "operation": op, "replay": replay})
		return
	case len(parts) == 3 && parts[0] == "pools" && nodeproto.ValidID(parts[1]) && parts[2] == "state":
		var in struct {
			Enabled *bool `json:"enabled"`
		}
		if !readPublicIPJSON(w, r, &in) {
			return
		}
		if in.Enabled == nil {
			failure(w, 400, "INVALID_REQUEST")
			return
		}
		v, op, replay, e := c.Store.SetPublicIPPoolState(r.Context(), c.Config, actor.ID, key, parts[1], *in.Enabled, now)
		if e != nil {
			publicIPError(w, e)
			return
		}
		output(w, 200, map[string]any{"pool": v, "operation": op, "replay": replay})
		return
	case len(parts) == 1 && parts[0] == "leases":
		var in PublicIPLeaseInput
		if !readPublicIPJSON(w, r, &in) {
			return
		}
		v, op, replay, e := c.Store.AllocatePublicIP(r.Context(), c.Config, actor.ID, key, in, now)
		if e != nil {
			publicIPError(w, e)
			return
		}
		status := 201
		if replay {
			status = 200
		}
		output(w, status, map[string]any{"lease": v, "operation": op, "replay": replay})
		return
	case len(parts) == 3 && parts[0] == "leases" && nodeproto.ValidID(parts[1]) && parts[2] == "release":
		var in struct{}
		if !readPublicIPJSON(w, r, &in) {
			return
		}
		v, op, replay, e := c.Store.ReleasePublicIP(r.Context(), c.Config, actor.ID, key, parts[1], now)
		if e != nil {
			publicIPError(w, e)
			return
		}
		output(w, 200, map[string]any{"lease": v, "operation": op, "replay": replay})
		return
	}
	failure(w, 404, "NOT_FOUND")
}

func publicIPCursor(next string) any {
	if next == "" {
		return nil
	}
	return next
}
func readPublicIPJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		failure(w, 415, "JSON_REQUIRED")
		return false
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 131072))
	trimmed := bytes.TrimSpace(raw)
	if err != nil || len(trimmed) < 2 || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' || !strictPublicIP(raw, v) {
		failure(w, 400, "INVALID_REQUEST")
		return false
	}
	return true
}

func publicIPError(w http.ResponseWriter, e error) {
	if errors.Is(e, ErrPublicIPCapacity) {
		failure(w, 409, "PUBLIC_IP_EXHAUSTED")
		return
	}
	consoleError(w, e)
}

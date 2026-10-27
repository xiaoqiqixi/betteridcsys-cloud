package control

import (
	"aster/cloud/internal/identity"
	"aster/cloud/internal/nodeproto"
	"net/http"
	"strings"
	"time"
)

func (c Console) publicIngress(w http.ResponseWriter, r *http.Request) {
	actor, ok := identity.Actor(r.Context())
	if !ok || !actor.Enabled || !actor.Can("nodes.read") || !actor.Can("instances.read") {
		failure(w, 403, "FORBIDDEN")
		return
	}
	if r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery {
		failure(w, 400, "INVALID_REQUEST")
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/console/v1/"), "/")
	if len(parts) == 2 && parts[0] == "public-ingress-operations" && nodeproto.ValidID(parts[1]) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			failure(w, 405, "METHOD_NOT_ALLOWED")
			return
		}
		op, e := c.Store.PublicIngressOperation(r.Context(), actor.ID, parts[1])
		if e != nil {
			consoleError(w, e)
			return
		}
		output(w, 200, map[string]any{"operation": op})
		return
	}
	if len(parts) != 3 || parts[0] != "instances" || parts[2] != "public-ingress" || !nodeproto.ValidID(parts[1]) {
		failure(w, 404, "NOT_FOUND")
		return
	}
	if r.Method == http.MethodGet {
		p, e := c.Store.PublicIngress(r.Context(), c.Config, parts[1], time.Now().UTC())
		if e != nil {
			consoleError(w, e)
			return
		}
		output(w, 200, map[string]any{"policy": p})
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
	keys := r.Header.Values("Idempotency-Key")
	if len(keys) != 1 || !nodeproto.ValidID(keys[0]) {
		failure(w, 400, "IDEMPOTENCY_KEY_REQUIRED")
		return
	}
	var in PublicIngressInput
	if !readConsoleJSON(w, r, &in) {
		return
	}
	p, op, replay, e := c.Store.SetPublicIngress(r.Context(), c.Config, actor.ID, parts[1], keys[0], in, time.Now().UTC())
	if e != nil {
		consoleError(w, e)
		return
	}
	status := 202
	if replay {
		status = 200
	}
	output(w, status, map[string]any{"policy": p, "operation": op, "replay": replay})
}

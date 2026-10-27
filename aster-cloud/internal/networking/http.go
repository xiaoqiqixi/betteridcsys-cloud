package networking

import (
	"aster/cloud/internal/identity"
	"aster/cloud/internal/nodeproto"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

const APIBase = "/console/v1/networks/"
const maxBodyBytes = 128 << 10

func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func failure(w http.ResponseWriter, e error) {
	status, code := 503, "NETWORK_UNAVAILABLE"
	switch {
	case errors.Is(e, ErrInput):
		status, code = 400, "INVALID_REQUEST"
	case errors.Is(e, ErrConflict):
		status, code = 409, "REQUEST_CONFLICT"
	case errors.Is(e, ErrForbidden):
		status, code = 403, "FORBIDDEN"
	case errors.Is(e, ErrNotFound):
		status, code = 404, "NOT_FOUND"
	case errors.Is(e, ErrCapacity):
		status, code = 409, "IP_POOL_EXHAUSTED"
	case errors.Is(e, ErrState):
		status, code = 409, "NETWORK_STATE_CONFLICT"
	}
	respond(w, status, map[string]any{"error": map[string]string{"code": code}})
}

// NewHandler requires an identity.Require-protected parent route: that wrapper
// enforces live TLS/origin/session/CSRF. This handler independently checks Actor
// and grants, and approves every write's concrete node against a copied list.
// It cannot create a node, configure a URL/certificate or execute host commands.
func NewHandler(store *Store, approvedNodeIDs []string) http.Handler {
	approved := map[string]bool{}
	for _, node := range approvedNodeIDs {
		if !nodeproto.ValidNodeID(node) || approved[node] {
			approved = map[string]bool{}
			break
		}
		approved[node] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		actor, ok := identity.Actor(r.Context())
		if !ok || !actor.Enabled {
			respond(w, 401, map[string]any{"error": map[string]string{"code": "AUTH_REQUIRED"}})
			return
		}
		permission := "nodes.read"
		if r.Method == http.MethodPost {
			permission = "nodes.manage"
		}
		if !actor.Can(permission) {
			failure(w, ErrForbidden)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			w.Header().Set("Allow", "GET, POST")
			respond(w, 405, map[string]any{"error": map[string]string{"code": "METHOD_NOT_ALLOWED"}})
			return
		}
		if !strings.HasPrefix(r.URL.Path, APIBase) || r.URL.RawPath != "" {
			failure(w, ErrNotFound)
			return
		}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, APIBase), "/")
		if len(parts) > 2 || parts[0] != "vpcs" && parts[0] != "pools" && parts[0] != "leases" || len(parts) == 2 && !nodeproto.ValidID(parts[1]) {
			failure(w, ErrNotFound)
			return
		}
		cursor, e := parseQuery(r.URL, r.Method == http.MethodGet && len(parts) == 1)
		if e != nil {
			failure(w, e)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		if r.Method == http.MethodGet {
			var result any
			if len(parts) == 2 {
				switch parts[0] {
				case "vpcs":
					v, err := store.GetVPC(ctx, parts[1])
					e = err
					result = map[string]any{"vpc": v}
				case "pools":
					v, err := store.GetPool(ctx, parts[1])
					e = err
					result = map[string]any{"pool": v}
				case "leases":
					v, err := store.GetLease(ctx, parts[1])
					e = err
					result = map[string]any{"lease": v}
				}
			} else {
				switch parts[0] {
				case "vpcs":
					result, e = store.ListVPCs(ctx, cursor)
				case "pools":
					result, e = store.ListPools(ctx, cursor)
				case "leases":
					result, e = store.ListLeases(ctx, cursor)
				}
			}
			if e != nil {
				failure(w, e)
				return
			}
			respond(w, 200, result)
			return
		}
		if len(parts) != 1 {
			failure(w, ErrNotFound)
			return
		}
		keys := r.Header.Values("Idempotency-Key")
		if len(keys) != 1 || !nodeproto.ValidID(keys[0]) {
			failure(w, ErrInput)
			return
		}
		id := keys[0]
		var result any
		var replay bool
		now := time.Now().UTC()
		switch parts[0] {
		case "vpcs":
			var in CreateVPCInput
			if !readInput(w, r, &in, []string{"owner_ref", "node_id", "name", "cidr", "vlan_id"}) {
				return
			}
			if !approved[in.NodeID] {
				failure(w, ErrForbidden)
				return
			}
			var v VPC
			v, replay, e = store.CreateVPC(ctx, actor.ID, id, in, now)
			result = map[string]any{"vpc": v, "replay": replay}
		case "pools":
			var in CreatePoolInput
			if !readInput(w, r, &in, []string{"node_id", "vpc_id", "name", "cidr", "gateway", "addresses", "enabled"}) {
				return
			}
			if !approved[in.NodeID] {
				failure(w, ErrForbidden)
				return
			}
			var v IPPool
			v, replay, e = store.CreatePool(ctx, actor.ID, id, in, now)
			result = map[string]any{"pool": v, "replay": replay}
		case "leases":
			var in ReserveInput
			if !readInput(w, r, &in, []string{"pool_id", "instance_id", "owner_ref", "address"}) {
				return
			}
			if !in.Valid() {
				failure(w, ErrInput)
				return
			}
			pool, err := store.GetPool(ctx, in.PoolID)
			if err != nil {
				failure(w, err)
				return
			}
			if !approved[pool.NodeID] {
				failure(w, ErrForbidden)
				return
			}
			var v Lease
			v, replay, e = store.Reserve(ctx, actor.ID, id, in, now)
			result = map[string]any{"lease": v, "replay": replay}
		}
		if e != nil {
			failure(w, e)
			return
		}
		status := 201
		if replay {
			status = 200
		}
		respond(w, status, result)
	})
}
func parseQuery(u *url.URL, allowCursor bool) (string, error) {
	if u.ForceQuery || len(u.RawQuery) > 128 {
		return "", ErrInput
	}
	if u.RawQuery == "" {
		return "", nil
	}
	if !allowCursor {
		return "", ErrInput
	}
	v, e := url.ParseQuery(u.RawQuery)
	if e != nil || len(v) != 1 || len(v["cursor"]) != 1 || !nodeproto.ValidID(v.Get("cursor")) {
		return "", ErrInput
	}
	return v.Get("cursor"), nil
}
func readInput(w http.ResponseWriter, r *http.Request, out any, fields []string) bool {
	media, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || media != "application/json" {
		respond(w, 415, map[string]any{"error": map[string]string{"code": "JSON_REQUIRED"}})
		return false
	}
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if e != nil || !decodeInput(raw, out, fields) {
		failure(w, ErrInput)
		return false
	}
	return true
}
func decodeInput(raw []byte, out any, fields []string) bool {
	if len(raw) == 0 || len(raw) > maxBodyBytes || !utf8.Valid(raw) {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) bool
	walk = func(depth int) bool {
		if depth > 8 {
			return false
		}
		t, e := d.Token()
		if e != nil || t == nil {
			return false
		}
		switch t {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				s, ok := k.(string)
				if e != nil || !ok || seen[s] || !walk(depth+1) {
					return false
				}
				seen[s] = true
			}
			end, e := d.Token()
			return e == nil && end == json.Delim('}')
		case json.Delim('['):
			for d.More() {
				if !walk(depth + 1) {
					return false
				}
			}
			end, e := d.Token()
			return e == nil && end == json.Delim(']')
		}
		_, delim := t.(json.Delim)
		return !delim
	}
	if !walk(0) || d.Decode(new(any)) != io.EOF {
		return false
	}
	var top map[string]json.RawMessage
	if json.Unmarshal(raw, &top) != nil || len(top) != len(fields) {
		return false
	}
	for _, name := range fields {
		if _, ok := top[name]; !ok {
			return false
		}
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(out) == nil && d.Decode(new(any)) == io.EOF
}

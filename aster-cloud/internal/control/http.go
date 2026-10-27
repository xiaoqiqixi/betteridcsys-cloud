package control

import (
	"aster/billing/controllerapi"
	"aster/cloud/internal/nodeproto"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
)

type App struct {
	Store   Store
	Config  Config
	Secrets Secrets
	Now     func() time.Time
}

func (a App) now() time.Time {
	if a.Now != nil {
		return a.Now().UTC()
	}
	return time.Now().UTC()
}
func output(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func failure(w http.ResponseWriter, status int, code string) {
	output(w, status, map[string]any{"error": map[string]string{"code": code}})
}
func tokenEqual(got, want string) bool {
	return len(want) >= 32 && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}
func (a App) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.TLS == nil {
			failure(w, 426, "TLS_REQUIRED")
			return
		}
		if r.Header.Get("Origin") != "" {
			failure(w, 403, "BROWSER_ACCESS_UNAVAILABLE")
			return
		}
		if r.URL.RawQuery != "" {
			failure(w, 400, "INVALID_QUERY")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		r = r.WithContext(ctx)
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			failure(w, 401, "AUTH_REQUIRED")
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		billing := tokenEqual(token, a.Secrets.Billing)
		read := tokenEqual(token, a.Secrets.AdminRead)
		write := tokenEqual(token, a.Secrets.AdminWrite)
		if !billing && !read && !write {
			failure(w, 401, "AUTH_REQUIRED")
			return
		}
		path := r.URL.Path
		if strings.HasPrefix(path, "/v1/resources/") {
			if !billing {
				failure(w, 403, "FORBIDDEN")
				return
			}
			a.resourceView(w, r)
			return
		}
		if path == "/v1/provisioning" || strings.HasPrefix(path, "/v1/provisioning/") {
			if !billing {
				failure(w, 403, "FORBIDDEN")
				return
			}
			a.provisioning(w, r)
			return
		}
		if !read && !write {
			failure(w, 403, "FORBIDDEN")
			return
		}
		if r.Method != "GET" {
			failure(w, 405, "METHOD_NOT_ALLOWED")
			return
		}
		var items any
		var e error
		switch path {
		case "/v1/health":
			if a.Store.Ping(ctx) != nil {
				failure(w, 503, "NOT_READY")
				return
			}
			output(w, 200, map[string]string{"status": "ready", "controller_id": a.Config.ControllerID, "protocol": controllerapi.Protocol})
			return
		case "/v1/nodes":
			var nodes []NodeView
			nodes, e = a.Store.Nodes(ctx)
			for i := range nodes {
				_, configured := a.Config.Node(nodes[i].ID)
				nodes[i].Online = configured && !nodes[i].Maintenance && heartbeatFresh(nodes[i].HeartbeatAt, a.now(), time.Duration(a.Config.HeartbeatTTLSeconds)*time.Second)
			}
			items = nodes
		case "/v1/instances":
			items, e = a.Store.Instances(ctx)
		case "/v1/tasks":
			items, e = a.Store.Jobs(ctx)
		case "/v1/audit":
			items, e = a.Store.Audits(ctx)
		default:
			failure(w, 404, "NOT_FOUND")
			return
		}
		if e != nil {
			failure(w, 503, "STORAGE_UNAVAILABLE")
			return
		}
		output(w, 200, map[string]any{"items": items, "limit": 100, "truncated_possible": true})
	})
}
func (a App) provisioning(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/v1/provisioning" {
		if r.Method != "GET" {
			failure(w, 405, "METHOD_NOT_ALLOWED")
			return
		}
		op := strings.TrimPrefix(r.URL.Path, "/v1/provisioning/")
		if !nodeproto.ValidID(op) {
			failure(w, 404, "NOT_FOUND")
			return
		}
		job, e := a.Store.Lookup(r.Context(), op)
		if errors.Is(e, ErrNotFound) {
			failure(w, 404, "NOT_FOUND")
			return
		}
		if e != nil {
			failure(w, 503, "STORAGE_UNAVAILABLE")
			return
		}
		if job.ControllerID != a.Config.ControllerID {
			failure(w, 404, "NOT_FOUND")
			return
		}
		if r.Header.Get("X-Aster-Request-SHA256") != job.RequestSHA || r.Header.Get("Idempotency-Key") != op {
			failure(w, 409, "IDEMPOTENCY_CONFLICT")
			return
		}
		output(w, 200, job.Result())
		return
	}
	if r.Method != "POST" {
		failure(w, 405, "METHOD_NOT_ALLOWED")
		return
	}
	media, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || media != "application/json" {
		failure(w, 415, "JSON_REQUIRED")
		return
	}
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 65536))
	var request controllerapi.Request
	if e != nil || !strict(raw, &request) || !request.Valid() || request.Product.ControllerID != a.Config.ControllerID {
		failure(w, 400, "INVALID_PROVISIONING_REQUEST")
		return
	}
	_, digest, e := request.BytesAndDigest()
	if e != nil || r.Header.Get("X-Aster-Request-SHA256") != digest || r.Header.Get("Idempotency-Key") != request.OperationID {
		failure(w, 400, "REQUEST_BINDING_REQUIRED")
		return
	}
	job, replay, e := a.Store.Admit(r.Context(), request, a.Config.Candidates(request), a.now(), time.Duration(a.Config.HeartbeatTTLSeconds)*time.Second)
	switch {
	case errors.Is(e, ErrConflict):
		failure(w, 409, "IDEMPOTENCY_CONFLICT")
		return
	case errors.Is(e, ErrCapacity):
		failure(w, 503, "NO_HEALTHY_CAPACITY")
		return
	case e != nil:
		failure(w, 503, "STORAGE_UNAVAILABLE")
		return
	}
	status := 202
	if replay || job.State == "rejected" {
		status = 409
	}
	output(w, status, job.Result())
}

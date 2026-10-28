package control

import (
	"aster/cloud/internal/identity"
	"aster/cloud/internal/nodeproto"
	"context"
	"net/http"
	"strings"
	"time"
)

// NewVerificationConsole constructs only the restricted HTTP surface. It does
// not admit a process, waive the target seal, create SQL credentials, or start
// background workers. Its caller must hold independently verified host authority.
func NewVerificationConsole(store *SQLStore, config Config, auth *identity.Service, operation string) (http.Handler, error) {
	if store == nil || store.DB == nil || auth == nil || !nodeproto.ValidID(operation) {
		return nil, ErrInput
	}
	console := Console{Store: store, Config: config, Identity: auth}
	normal := console.Handler()
	status := auth.Require("", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			failure(w, http.StatusBadRequest, "INVALID_QUERY")
			return
		}
		output(w, http.StatusOK, map[string]any{"operation_id": operation, "phase": "verification", "business_writes": false, "node_contacts": false})
	}))
	nodes := auth.Require("nodes.read", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			failure(w, http.StatusBadRequest, "INVALID_QUERY")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		items, err := store.Nodes(ctx)
		if err != nil {
			consoleError(w, err)
			return
		}
		for i := range items {
			// A restored timestamp is historical evidence, not a successful contact by
			// this verification process. Do not erase the timestamp or refresh it.
			items[i].Online = false
		}
		output(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
	}))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		// No path cleaning/redirects or encoded aliases at this authority boundary.
		if r.URL.RawPath != "" || r.URL.ForceQuery {
			failure(w, http.StatusForbidden, "MIGRATION_VERIFICATION_READ_ONLY")
			return
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /console/v1/auth/csrf", "GET /console/v1/auth/me", "POST /console/v1/auth/login", "POST /console/v1/auth/logout":
			normal.ServeHTTP(w, r)
			return
		case "GET /console/v1/migration-verification":
			status.ServeHTTP(w, r)
			return
		case "GET /console/v1/nodes":
			nodes.ServeHTTP(w, r)
			return
		}
		if r.Method == http.MethodGet && verificationLocalRead(r.URL.Path) {
			// Existing handlers retain current grants, object scope and query parsing.
			// An allowlisted GET must stay local/read-only; future routes fail closed.
			normal.ServeHTTP(w, r)
			return
		}
		failure(w, http.StatusForbidden, "MIGRATION_VERIFICATION_READ_ONLY")
	}), nil
}

func verificationLocalRead(path string) bool {
	const prefix = "/console/v1/"
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(path, prefix), "/")
	if len(parts) == 1 {
		switch parts[0] {
		case "users", "roles", "presets", "instances", "operations", "audit":
			return true
		}
	}
	if len(parts) == 2 && nodeproto.ValidID(parts[1]) {
		switch parts[0] {
		case "users", "identity-operations", "instances", "operations", "public-ingress-operations":
			return true
		}
	}
	if len(parts) == 3 && parts[0] == "instances" && nodeproto.ValidID(parts[1]) && parts[2] == "public-ingress" {
		return true
	}
	if len(parts) < 2 || len(parts) > 3 || len(parts) == 3 && !nodeproto.ValidID(parts[2]) {
		return false
	}
	switch parts[0] {
	case "networks":
		return parts[1] == "vpcs" || parts[1] == "pools" || parts[1] == "leases"
	case "overlays":
		return parts[1] == "vpcs" || parts[1] == "epochs" || len(parts) == 2 && (parts[1] == "options" || parts[1] == "clusters")
	case "public-ips":
		return parts[1] == "pools" || parts[1] == "leases" || parts[1] == "operations" || parts[1] == "resources" || parts[1] == "resource-operations" || len(parts) == 2 && parts[1] == "options"
	}
	return false
}

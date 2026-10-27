package hypervisor

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
)

func ServerTLS(c Config) (*tls.Config, error) {
	for _, path := range []string{c.Certificate, c.ControllerCA} {
		if err := ownedPath(path, false, false); err != nil {
			return nil, err
		}
	}
	if err := ownedPath(c.PrivateKey, true, false); err != nil {
		return nil, err
	}
	certBytes, err := readApproved(c.Certificate, false, 1<<20)
	if err != nil {
		return nil, err
	}
	keyBytes, err := readApproved(c.PrivateKey, true, 1<<20)
	if err != nil {
		return nil, err
	}
	certificate, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return nil, err
	}
	raw, err := readApproved(c.ControllerCA, false, 1<<20)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(raw) {
		return nil, errors.New("invalid controller CA")
	}
	pin, err := hex.DecodeString(c.ExpectedControllerCertificateSHA256)
	if err != nil || len(pin) != 32 {
		return nil, errors.New("invalid controller certificate pin")
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, VerifyConnection: func(cs tls.ConnectionState) error {
		if len(cs.VerifiedChains) == 0 || len(cs.PeerCertificates) == 0 {
			return errors.New("controller identity required")
		}
		h := sha256.Sum256(cs.PeerCertificates[0].Raw)
		if subtle.ConstantTimeCompare(h[:], pin) != 1 {
			return errors.New("controller certificate not approved")
		}
		return nil
	}}, nil
}
func (m *Manager) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 || nodeproto.Digest(r.TLS.PeerCertificates[0].Raw) != m.Config.ExpectedControllerCertificateSHA256 {
			respond(w, 403, map[string]any{"error": map[string]string{"code": "CONTROLLER_IDENTITY_REQUIRED"}})
			return
		}
		if m.serveStorageTransport(w, r) {
			return
		}
		if m.serveOverlay(w, r) {
			return
		}
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/instances/") && strings.HasSuffix(r.URL.Path, "/metrics"):
			if r.Method != http.MethodGet {
				w.Header().Set("Allow", http.MethodGet)
				respond(w, 405, errorBody("METHOD_NOT_ALLOWED"))
				return
			}
			if r.URL.RawQuery != "" || r.URL.ForceQuery {
				respond(w, 400, errorBody("INVALID_QUERY"))
				return
			}
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/instances/"), "/metrics")
			ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
			defer cancel()
			metrics, err := m.ObserveMetrics(ctx, id)
			if err != nil {
				status := 409
				if errors.Is(err, ErrNotFound) {
					status = 404
				}
				respond(w, status, errorBody("LIVE_INSTANCE_METRICS_UNCONFIRMED"))
				return
			}
			respond(w, 200, metrics)
		case strings.HasPrefix(r.URL.Path, "/v1/instances/") && r.Method == "GET":
			id := strings.TrimPrefix(r.URL.Path, "/v1/instances/")
			ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
			defer cancel()
			observed, err := m.ObserveInstance(ctx, id)
			if err != nil {
				status := 409
				if errors.Is(err, ErrNotFound) {
					status = 404
				}
				respond(w, status, errorBody("LIVE_INSTANCE_OBSERVATION_UNCONFIRMED"))
				return
			}
			respond(w, 200, observed)
		case r.URL.Path == "/healthz" && r.Method == "GET":
			respond(w, 200, map[string]string{"status": "ok", "protocol": nodeproto.Protocol, "node_id": m.Config.NodeID})
		case r.URL.Path == "/v1/capabilities" && r.Method == "GET":
			ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
			defer cancel()
			respond(w, 200, m.Capabilities(ctx))
		case r.URL.Path == "/v1/storage-tasks" && r.Method == "POST":
			media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil || media != "application/json" {
				respond(w, 415, errorBody("JSON_REQUIRED"))
				return
			}
			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 65536))
			if err != nil {
				respond(w, 400, errorBody("INVALID_STORAGE_TASK"))
				return
			}
			task, err := nodeproto.DecodeStorageTask(body)
			if err != nil || task.NodeID != m.Config.NodeID || nodeproto.Digest(body) != r.Header.Get("X-Request-SHA256") {
				respond(w, 400, errorBody("INVALID_STORAGE_TASK_OR_DIGEST"))
				return
			}
			result, err := m.AcceptStorage(task, body)
			if errors.Is(err, ErrConflict) {
				respond(w, 409, errorBody("OPERATION_CONFLICT"))
				return
			}
			if err != nil {
				respond(w, 503, errorBody("OUTCOME_UNCERTAIN_QUERY_OPERATION"))
				return
			}
			status := 200
			if result.Status == "accepted" {
				status = 202
			}
			respond(w, status, result)
		case strings.HasPrefix(r.URL.Path, "/v1/storage-tasks/") && r.Method == "GET":
			id := strings.TrimPrefix(r.URL.Path, "/v1/storage-tasks/")
			result, ok := m.LookupStorage(id)
			if !ok {
				respond(w, 404, errorBody("NOT_FOUND"))
				return
			}
			respond(w, 200, result)
		case r.URL.Path == "/v1/tasks" && r.Method == "POST":
			media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil || media != "application/json" {
				respond(w, 415, errorBody("JSON_REQUIRED"))
				return
			}
			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 65536))
			if err != nil {
				respond(w, 400, errorBody("INVALID_TASK"))
				return
			}
			task, err := nodeproto.DecodeTask(body)
			if err != nil || task.NodeID != m.Config.NodeID || nodeproto.Digest(body) != r.Header.Get("X-Request-SHA256") {
				respond(w, 400, errorBody("INVALID_TASK_OR_DIGEST"))
				return
			}
			result, err := m.Accept(task, body)
			if errors.Is(err, ErrConflict) {
				respond(w, 409, errorBody("OPERATION_CONFLICT"))
				return
			}
			if err != nil {
				respond(w, 503, errorBody("OUTCOME_UNCERTAIN_QUERY_OPERATION"))
				return
			}
			status := 200
			if result.Status == "accepted" {
				status = 202
			}
			respond(w, status, result)
		case strings.HasPrefix(r.URL.Path, "/v1/tasks/") && r.Method == "GET":
			id := strings.TrimPrefix(r.URL.Path, "/v1/tasks/")
			if !nodeproto.ValidID(id) {
				respond(w, 404, errorBody("NOT_FOUND"))
				return
			}
			result, ok := m.Lookup(id)
			if !ok {
				respond(w, 404, errorBody("NOT_FOUND"))
				return
			}
			respond(w, 200, result)
		default:
			respond(w, 404, errorBody("NOT_FOUND"))
		}
	})
}
func errorBody(code string) map[string]any {
	return map[string]any{"error": map[string]string{"code": code}}
}
func respond(w http.ResponseWriter, status int, body any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

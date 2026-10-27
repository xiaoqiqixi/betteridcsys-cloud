package control

import (
	"aster/cloud/internal/identity"
	"aster/cloud/internal/networking"
	"aster/cloud/internal/nodeproto"
	"context"
	"database/sql"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Console struct {
	Store         *SQLStore
	Config        Config
	Identity      *identity.Service
	Worker        *OperationWorker
	Runner        *OperationRunner
	OverlayWorker *OverlayWorker
	OverlayRunner *OverlayRunner
	// MetricsRPC is an internal dependency seam, never request configuration.
	// Production uses only root-approved, pinned-mTLS NodeClient destinations.
	MetricsRPC func(context.Context, NodeProfile) (MetricsReader, error)
}

func (c Console) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		if c.Identity == nil || c.Store == nil {
			failure(w, 503, "CONSOLE_UNAVAILABLE")
			return
		}
		path := r.URL.Path
		if strings.HasPrefix(path, "/console/v1/auth/") || path == "/console/v1/users" || strings.HasPrefix(path, "/console/v1/users/") || strings.HasPrefix(path, "/console/v1/identity-operations/") || path == "/console/v1/roles" {
			c.Identity.Handler().ServeHTTP(w, r)
			return
		}
		permission := "instances.read"
		if path == "/console/v1/nodes" || strings.HasPrefix(path, "/console/v1/nodes/") || strings.HasPrefix(path, "/console/v1/networks/") || strings.HasPrefix(path, "/console/v1/overlays/") || strings.HasPrefix(path, "/console/v1/public-ips/") {
			permission = "nodes.read"
		}
		if path == "/console/v1/audit" {
			permission = "audit.read"
		}
		c.Identity.Require(permission, http.HandlerFunc(c.resource)).ServeHTTP(w, r)
	})
}
func readConsoleJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	media, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || media != "application/json" {
		failure(w, 415, "JSON_REQUIRED")
		return false
	}
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 65536))
	if e != nil || !strict(raw, v) {
		failure(w, 400, "INVALID_REQUEST")
		return false
	}
	return true
}
func consoleError(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, ErrInput):
		failure(w, 400, "INVALID_REQUEST")
	case errors.Is(e, ErrNotFound), errors.Is(e, sql.ErrNoRows):
		failure(w, 404, "NOT_FOUND")
	case errors.Is(e, ErrConflict):
		failure(w, 409, "IDEMPOTENCY_CONFLICT")
	case errors.Is(e, ErrState):
		failure(w, 409, "STATE_CONFLICT")
	case errors.Is(e, ErrCapacity):
		failure(w, 409, "NODE_NOT_READY")
	default:
		failure(w, 503, "DEPENDENCY_UNAVAILABLE")
	}
}
func (c Console) worker() OperationWorker {
	if c.Worker != nil {
		return *c.Worker
	}
	return OperationWorker{Store: c.Store, Config: c.Config}
}
func (c Console) resource(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	user, ok := identity.Actor(ctx)
	if !ok {
		failure(w, 401, "AUTH_REQUIRED")
		return
	}
	if strings.HasPrefix(r.URL.Path, "/console/v1/public-ingress-operations/") || strings.HasPrefix(r.URL.Path, "/console/v1/instances/") && strings.HasSuffix(r.URL.Path, "/public-ingress") {
		c.publicIngress(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/console/v1/public-ips/") {
		c.publicIPs(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/console/v1/overlays/") {
		c.overlays(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/console/v1/networks/") {
		nodes := make([]string, 0, len(c.Config.Nodes))
		for _, n := range c.Config.Nodes {
			nodes = append(nodes, n.ID)
		}
		networking.NewHandler(&networking.Store{DB: c.Store.DB}, nodes).ServeHTTP(w, r)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/console/v1/"), "/")
	if r.Method == http.MethodGet && len(parts) == 1 && parts[0] == "audit" {
		c.audits(w, r)
		return
	}
	if _, err := url.ParseQuery(r.URL.RawQuery); err != nil {
		failure(w, 400, "INVALID_QUERY")
		return
	}
	if r.URL.Query().Get("instance_id") != "" && !(len(parts) == 1 && parts[0] == "operations") {
		failure(w, 400, "INVALID_QUERY")
		return
	}
	if r.URL.RawQuery != "" && !(len(parts) == 1 && (parts[0] == "instances" || parts[0] == "operations" || parts[0] == "audit")) {
		failure(w, 400, "INVALID_QUERY")
		return
	}
	for _, key := range []string{"cursor", "instance_id"} {
		if len(r.URL.Query()[key]) > 1 {
			failure(w, 400, "INVALID_QUERY")
			return
		}
	}
	for key := range r.URL.Query() {
		if key != "cursor" && key != "instance_id" {
			failure(w, 400, "INVALID_QUERY")
			return
		}
	}
	if r.Method != "GET" && r.URL.RawQuery != "" {
		failure(w, 400, "INVALID_QUERY")
		return
	}
	if r.Method == "GET" {
		switch {
		case len(parts) == 1 && parts[0] == "presets":
			if r.URL.RawQuery != "" {
				failure(w, 400, "INVALID_QUERY")
				return
			}
			output(w, 200, map[string]any{"items": publicPresetsWithConfig(c.Config)})
			return
		case len(parts) == 1 && parts[0] == "instances":
			c.instances(w, r)
			return
		case len(parts) == 3 && parts[0] == "instances" && parts[2] == "metrics" && nodeproto.ValidID(parts[1]):
			c.instanceMetrics(w, r, parts[1])
			return
		case len(parts) == 3 && parts[0] == "instances" && parts[2] == "observation" && nodeproto.ValidID(parts[1]):
			v, e := c.Store.Instance(ctx, parts[1])
			if e != nil {
				consoleError(w, e)
				return
			}
			p, ok := c.Config.Node(v.NodeID)
			if !ok {
				consoleError(w, ErrState)
				return
			}
			client, e := NewNodeClient(ctx, p)
			if e != nil {
				consoleError(w, e)
				return
			}
			observed, e := client.Observe(ctx, v.ID)
			if e != nil {
				consoleError(w, e)
				return
			}
			if observed.OwnerRef != v.OwnerRef || observed.Hostname != v.Hostname {
				consoleError(w, ErrUnavailable)
				return
			}
			// This is a read, not resolution of any unknown operation or payment.
			output(w, 200, map[string]any{"observation": observed})
			return
		case len(parts) == 3 && parts[0] == "instances" && nodeproto.ValidID(parts[1]) && parts[2] == "migration-targets":
			if !user.Can("migration.manage") || !user.Can("nodes.read") {
				failure(w, 403, "FORBIDDEN")
				return
			}
			targets, e := c.Store.MigrationTargets(ctx, c.Config, parts[1], time.Now().UTC())
			if e != nil {
				consoleError(w, e)
				return
			}
			output(w, 200, targets)
			return
		case len(parts) == 2 && parts[0] == "instances" && nodeproto.ValidID(parts[1]):
			v, e := c.Store.Instance(ctx, parts[1])
			if e != nil {
				consoleError(w, e)
				return
			}
			operations, _, e := c.operationList(ctx, "", v.ID)
			if e != nil {
				consoleError(w, e)
				return
			}
			artifacts, e := c.artifacts(ctx, v.ID)
			if e != nil {
				consoleError(w, e)
				return
			}
			migrations, e := c.migrations(ctx, v.ID)
			if e != nil {
				consoleError(w, e)
				return
			}
			if !user.Can("storage.read") {
				artifacts = []Artifact{}
			}
			if !user.Can("migration.manage") {
				migrations = []Migration{}
			}
			output(w, 200, map[string]any{"instance": v, "operations": operations, "artifacts": artifacts, "migrations": migrations})
			return
		case len(parts) == 1 && parts[0] == "operations":
			items, next, e := c.operationList(ctx, r.URL.Query().Get("cursor"), r.URL.Query().Get("instance_id"))
			if e != nil {
				consoleError(w, e)
				return
			}
			output(w, 200, map[string]any{"items": items, "next_cursor": next})
			return
		case len(parts) == 2 && parts[0] == "operations" && nodeproto.ValidID(parts[1]):
			o, e := c.Store.Operation(ctx, parts[1])
			if e != nil {
				consoleError(w, e)
				return
			}
			output(w, 200, map[string]any{"operation": o})
			return
		case len(parts) == 1 && parts[0] == "nodes":
			if r.URL.RawQuery != "" {
				failure(w, 400, "INVALID_QUERY")
				return
			}
			nodes, e := c.Store.Nodes(ctx)
			if e != nil {
				consoleError(w, e)
				return
			}
			for i := range nodes {
				_, configured := c.Config.Node(nodes[i].ID)
				nodes[i].Online = configured && !nodes[i].Maintenance && heartbeatFresh(nodes[i].HeartbeatAt, time.Now().UTC(), time.Duration(c.Config.HeartbeatTTLSeconds)*time.Second)
			}
			output(w, 200, map[string]any{"items": nodes, "next_cursor": nil})
			return
		case len(parts) == 1 && parts[0] == "audit":
			c.audits(w, r)
			return
		}
		failure(w, 404, "NOT_FOUND")
		return
	}
	if r.Method != "POST" {
		failure(w, 405, "METHOD_NOT_ALLOWED")
		return
	}
	if len(parts) == 1 && parts[0] == "instances" {
		if !user.Can("instances.manage") {
			failure(w, 403, "FORBIDDEN")
			return
		}
		var in CreateInstanceInput
		if !readConsoleJSON(w, r, &in) {
			return
		}
		if in.PublicIPResourceID != "" && !user.Can("nodes.manage") {
			failure(w, 403, "FORBIDDEN")
			return
		}
		op := r.Header.Get("Idempotency-Key")
		if !nodeproto.ValidID(op) {
			failure(w, 400, "IDEMPOTENCY_KEY_REQUIRED")
			return
		}
		operation, _, e := c.Store.CreateInstance(ctx, c.Config, user.ID, op, in, time.Now().UTC())
		if e != nil {
			consoleError(w, e)
			return
		}
		output(w, 202, map[string]any{"operation": operation})
		return
	}
	if len(parts) == 3 && parts[0] == "instances" && parts[2] == "operations" && nodeproto.ValidID(parts[1]) {
		var input OperationInput
		if !readConsoleJSON(w, r, &input) {
			return
		}
		permission := OperationPermission(input.Action)
		if permission == "" || !user.Can(permission) {
			failure(w, 403, "FORBIDDEN")
			return
		}
		if strings.HasPrefix(input.Action, "migrate_") {
			v, err := c.Store.Instance(ctx, parts[1])
			if err != nil {
				consoleError(w, err)
				return
			}
			var known int
			if err = c.Store.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM controller_public_ip_bindings WHERE epoch_id='' AND (instance_id=? OR previous_instance_id=?)", v.ID, v.ID).Scan(&known); err != nil {
				consoleError(w, err)
				return
			}
			if (c.Config.directRequired(v.NodeID) || known > 0) && (!user.Can("nodes.manage") || !user.Can("instances.manage")) {
				failure(w, 403, "FORBIDDEN")
				return
			}
		}
		op := r.Header.Get("Idempotency-Key")
		if !nodeproto.ValidID(op) {
			failure(w, 400, "IDEMPOTENCY_KEY_REQUIRED")
			return
		}
		var operation Operation
		var e error
		if input.Action == "migrate_retire_source" {
			operation, _, e = c.worker().CreateRetireSource(ctx, user.ID, parts[1], op, input)
		} else {
			operation, _, e = c.Store.CreateOperation(ctx, c.Config, user.ID, parts[1], op, input, time.Now().UTC())
		}
		if e != nil {
			consoleError(w, e)
			return
		}
		output(w, 202, map[string]any{"operation": operation})
		return
	}
	if len(parts) == 3 && parts[0] == "operations" && (parts[2] == "dispatch" || parts[2] == "reconcile") && nodeproto.ValidID(parts[1]) {
		var empty struct{}
		if !readConsoleJSON(w, r, &empty) {
			return
		}
		if r.Header.Get("Idempotency-Key") != parts[1] {
			failure(w, 400, "IDEMPOTENCY_KEY_REQUIRED")
			return
		}
		o, e := c.Store.Operation(ctx, parts[1])
		if e != nil {
			consoleError(w, e)
			return
		}
		permission := OperationPermission(o.Action)
		if permission == "" || !user.Can(permission) || publicIPBindingAction(o.Action) && (!user.Can("nodes.read") || !user.Can("nodes.manage")) {
			failure(w, 403, "FORBIDDEN")
			return
		}
		if e = c.Store.AuditOperationRequest(ctx, "user:"+user.ID, o.ID, parts[2], time.Now().UTC()); e != nil {
			consoleError(w, e)
			return
		}
		if parts[2] == "dispatch" && o.Protocol == TransferProtocol {
			if c.Runner == nil {
				failure(w, 503, "TRANSFER_WORKER_UNAVAILABLE")
				return
			}
			if o.State != "accepted" {
				consoleError(w, ErrState)
				return
			}
			if e = c.Runner.Start(o.ID); e != nil {
				consoleError(w, e)
				return
			}
			output(w, 202, map[string]any{"operation": o})
			return
		}
		if parts[2] == "reconcile" && o.Protocol == TransferProtocol {
			if c.Runner == nil {
				failure(w, 503, "TRANSFER_WORKER_UNAVAILABLE")
				return
			}
			if c.Runner.Active(o.ID) {
				consoleError(w, ErrState)
				return
			}
			if o.State != "sending" && o.State != "dispatched" && o.State != "uncertain" {
				consoleError(w, ErrState)
				return
			}
			if e = c.Runner.StartReconcile(o.ID); e != nil {
				consoleError(w, e)
				return
			}
			output(w, 202, map[string]any{"operation": o})
			return
		}
		worker := c.worker()
		if parts[2] == "dispatch" {
			o, e = worker.Dispatch(ctx, o.ID)
		} else {
			o, e = worker.Reconcile(ctx, o.ID)
		}
		if e != nil {
			// Return the persisted intent on an indeterminate network outcome. It is
			// still not success and the client must use only GET/reconcile afterwards.
			if o.ID != "" && (o.State == "sending" || o.State == "uncertain" || o.State == "dispatched") {
				output(w, 202, map[string]any{"operation": o})
				return
			}
			consoleError(w, e)
			return
		}
		output(w, 202, map[string]any{"operation": o})
		return
	}
	if len(parts) == 3 && parts[0] == "nodes" && parts[2] == "maintenance" && nodeproto.ValidNodeID(parts[1]) {
		if !user.Can("nodes.manage") {
			failure(w, 403, "FORBIDDEN")
			return
		}
		if _, ok := c.Config.Node(parts[1]); !ok {
			failure(w, 404, "NOT_FOUND")
			return
		}
		var in struct {
			Enabled bool `json:"enabled"`
		}
		if !readConsoleJSON(w, r, &in) {
			return
		}
		if e := c.maintenanceAs(ctx, user.ID, parts[1], in.Enabled); e != nil {
			consoleError(w, e)
			return
		}
		output(w, 200, map[string]any{"maintenance": in.Enabled})
		return
	}
	failure(w, 404, "NOT_FOUND")
}
func (c Console) instances(w http.ResponseWriter, r *http.Request) {
	cursor := r.URL.Query().Get("cursor")
	if cursor != "" && !nodeproto.ValidID(cursor) || r.URL.Query().Get("instance_id") != "" {
		failure(w, 400, "INVALID_QUERY")
		return
	}
	query := "SELECT id,owner_ref,node_id,hostname,state,resources,created_at,updated_at FROM controller_instances"
	args := []any{}
	if cursor != "" {
		query += " WHERE id<?"
		args = append(args, cursor)
	}
	query += " ORDER BY id DESC LIMIT 101"
	rows, e := c.Store.DB.QueryContext(r.Context(), query, args...)
	if e != nil {
		consoleError(w, e)
		return
	}
	defer rows.Close()
	items := []Instance{}
	for rows.Next() {
		v, e := scanInstance(rows)
		if e != nil {
			consoleError(w, e)
			return
		}
		items = append(items, v)
	}
	if e = rows.Err(); e != nil {
		consoleError(w, e)
		return
	}
	var next any
	if len(items) > 100 {
		items = items[:100]
		next = items[len(items)-1].ID
	}
	output(w, 200, map[string]any{"items": items, "next_cursor": next})
}
func (c Console) operationList(ctx context.Context, cursor, instance string) ([]Operation, any, error) {
	var seq int64
	var e error
	if cursor != "" {
		seq, e = strconv.ParseInt(cursor, 10, 64)
		if e != nil || seq < 1 {
			return nil, nil, ErrInput
		}
	}
	if instance != "" && !nodeproto.ValidID(instance) {
		return nil, nil, ErrInput
	}
	query := "SELECT " + operationColumns + " FROM controller_operations WHERE 1=1"
	args := []any{}
	if seq > 0 {
		query += " AND seq<?"
		args = append(args, seq)
	}
	if instance != "" {
		query += " AND instance_id=?"
		args = append(args, instance)
	}
	query += " ORDER BY seq DESC LIMIT 101"
	rows, e := c.Store.DB.QueryContext(ctx, query, args...)
	if e != nil {
		return nil, nil, e
	}
	defer rows.Close()
	items := []Operation{}
	for rows.Next() {
		v, e := scanOperation(rows)
		if e != nil {
			return nil, nil, e
		}
		items = append(items, v)
	}
	if e = rows.Err(); e != nil {
		return nil, nil, e
	}
	var next any
	if len(items) > 100 {
		items = items[:100]
		next = strconv.FormatInt(items[len(items)-1].Seq, 10)
	}
	return items, next, nil
}
func (c Console) artifacts(ctx context.Context, instance string) ([]Artifact, error) {
	rows, e := c.Store.DB.QueryContext(ctx, "SELECT id,instance_id,node_id,kind,state,manifest_sha256,created_at,updated_at FROM controller_artifacts WHERE instance_id=? ORDER BY created_at DESC,id DESC LIMIT 100", instance)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Artifact{}
	for rows.Next() {
		var a Artifact
		if e = rows.Scan(&a.ID, &a.InstanceID, &a.NodeID, &a.Kind, &a.State, &a.ManifestSHA, &a.CreatedAt, &a.UpdatedAt); e != nil {
			return nil, e
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
func (c Console) migrations(ctx context.Context, instance string) ([]Migration, error) {
	rows, e := c.Store.DB.QueryContext(ctx, "SELECT "+migrationColumns+" FROM controller_migrations WHERE instance_id=? ORDER BY created_at DESC,id DESC LIMIT 100", instance)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Migration{}
	for rows.Next() {
		v, e := scanMigration(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	if e = rows.Err(); e != nil {
		return nil, e
	}
	rows.Close()
	for i := range out {
		if e = c.retirementView(ctx, &out[i]); e != nil {
			return nil, e
		}
	}
	return out, nil
}
func (c Console) maintenanceAs(ctx context.Context, actor, node string, on bool) error {
	tx, e := c.Store.locked(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var raw []byte
	var seen sql.NullTime
	if e = tx.QueryRowContext(ctx, "SELECT capabilities,heartbeat_at FROM controller_nodes WHERE id=?", node).Scan(&raw, &seen); e != nil {
		return e
	}
	var caps Capability
	if !on && (!strict(raw, &caps) || caps.Maintenance || !seen.Valid || !heartbeatFresh(&seen.Time, time.Now().UTC(), time.Duration(c.Config.HeartbeatTTLSeconds)*time.Second)) {
		return ErrState
	}
	if _, e = tx.ExecContext(ctx, "UPDATE controller_nodes SET maintenance=?,updated_at=? WHERE id=?", on, time.Now().UTC(), node); e != nil {
		return e
	}
	action := "node.maintenance_off"
	if on {
		action = "node.maintenance_on"
	}
	if e = audit(ctx, tx, "user:"+actor, action, node, time.Now().UTC()); e != nil {
		return e
	}
	return tx.Commit()
}

type ConsoleAudit struct {
	ID             int64                `json:"id"`
	Source         string               `json:"source"`
	Actor          string               `json:"actor"`
	Action         string               `json:"action"`
	Target         string               `json:"target"`
	CreatedAt      time.Time            `json:"created_at"`
	IdentityDetail *IdentityAuditDetail `json:"identity_detail,omitempty"`
}

type IdentityAuditDetail struct {
	OperationID    string `json:"operation_id"`
	BaseRevision   uint64 `json:"base_revision"`
	ResultRevision uint64 `json:"result_revision"`
	Reason         string `json:"reason"`
}

func (c Console) audits(w http.ResponseWriter, r *http.Request) {
	q, e := parseAuditQuery(r.URL.RawQuery)
	if e != nil {
		failure(w, 400, "INVALID_QUERY")
		return
	}
	query, args := q.sql()
	rows, e := c.Store.DB.QueryContext(r.Context(), query, args...)
	if e != nil {
		consoleError(w, e)
		return
	}
	defer rows.Close()
	out := []ConsoleAudit{}
	for rows.Next() {
		var v ConsoleAudit
		if e = rows.Scan(&v.ID, &v.Source, &v.Actor, &v.Action, &v.Target, &v.CreatedAt); e != nil {
			consoleError(w, e)
			return
		}
		out = append(out, v)
	}
	if e = rows.Err(); e != nil {
		consoleError(w, e)
		return
	}
	var next any
	if len(out) > 100 {
		out = out[:100]
		v := out[len(out)-1]
		next = q.next(v)
	}
	if e = c.Store.attachIdentityAuditDetails(r.Context(), out); e != nil {
		consoleError(w, e)
		return
	}
	output(w, 200, map[string]any{"items": out, "next_cursor": next})
}

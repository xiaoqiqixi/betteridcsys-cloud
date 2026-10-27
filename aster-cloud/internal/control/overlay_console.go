package control

import (
	"aster/cloud/internal/identity"
	"aster/cloud/internal/nodeproto"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func (c Console) overlayWorker() OverlayWorker {
	if c.OverlayWorker != nil {
		return *c.OverlayWorker
	}
	return OverlayWorker{Store: c.Store, Config: c.Config}
}
func (c Console) overlays(w http.ResponseWriter, r *http.Request) {
	actor, ok := identity.Actor(r.Context())
	if !ok || !actor.Enabled || !actor.Can("nodes.read") {
		failure(w, 403, "FORBIDDEN")
		return
	}
	if r.URL.RawPath != "" || r.URL.ForceQuery {
		failure(w, 400, "INVALID_REQUEST")
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/console/v1/overlays/"), "/")
	if len(parts) < 1 || len(parts) > 3 {
		failure(w, 404, "NOT_FOUND")
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query) > 2 || len(query["cluster_id"]) > 1 || len(query["before_epoch"]) > 1 {
		failure(w, 400, "INVALID_QUERY")
		return
	}
	if values, ok := query["before_epoch"]; ok && values[0] == "" {
		failure(w, 400, "INVALID_QUERY")
		return
	}
	for k := range query {
		if k != "cluster_id" && !(k == "before_epoch" && len(parts) == 1 && parts[0] == "epochs" && r.Method == http.MethodGet) {
			failure(w, 400, "INVALID_QUERY")
			return
		}
	}
	if r.Method == http.MethodGet {
		if len(parts) == 1 && parts[0] == "options" {
			options, e := c.Store.OverlayOptions(r.Context(), c.Config, query.Get("cluster_id"))
			if e != nil {
				consoleError(w, e)
				return
			}
			output(w, 200, options)
			return
		}
		if len(parts) == 2 && parts[0] == "vpcs" && nodeproto.ValidID(parts[1]) && r.URL.RawQuery == "" {
			vpc, e := c.Store.OverlayVPC(r.Context(), parts[1])
			if e != nil {
				consoleError(w, e)
				return
			}
			output(w, 200, map[string]any{"vpc": vpc})
			return
		}
		if len(parts) == 1 && parts[0] == "clusters" && r.URL.RawQuery == "" {
			items := []map[string]any{}
			for _, cluster := range c.Config.OverlayClusters {
				nodes := []string{}
				for _, p := range cluster.Profiles {
					nodes = append(nodes, p.NodeID)
				}
				items = append(items, map[string]any{"id": cluster.ClusterID, "node_ids": nodes})
			}
			output(w, 200, map[string]any{"items": items})
			return
		}
		if len(parts) == 1 && parts[0] == "vpcs" {
			cluster := query.Get("cluster_id")
			if _, ok := c.Config.OverlayCluster(cluster); !ok {
				failure(w, 400, "INVALID_CLUSTER")
				return
			}
			items, e := c.Store.OverlayVPCs(r.Context(), cluster)
			if e != nil {
				consoleError(w, e)
				return
			}
			output(w, 200, map[string]any{"items": items})
			return
		}
		if len(parts) == 1 && parts[0] == "epochs" {
			cluster := query.Get("cluster_id")
			if !nodeproto.ValidNodeID(cluster) {
				failure(w, 400, "INVALID_CLUSTER")
				return
			}
			before := int64(0)
			if v := query.Get("before_epoch"); v != "" {
				n, e := strconv.ParseInt(v, 10, 64)
				if e != nil || n < 1 || strconv.FormatInt(n, 10) != v {
					failure(w, 400, "INVALID_QUERY")
					return
				}
				before = n
			}
			items, next, e := c.Store.ListOverlayEpochs(r.Context(), cluster, before)
			if e != nil {
				consoleError(w, e)
				return
			}
			output(w, 200, map[string]any{"items": items, "next_before_epoch": next})
			return
		}
		if len(parts) == 2 && parts[0] == "epochs" && nodeproto.ValidID(parts[1]) && r.URL.RawQuery == "" {
			epoch, e := c.Store.OverlayEpoch(r.Context(), parts[1])
			if e != nil {
				consoleError(w, e)
				return
			}
			tasks, e := c.Store.OverlayTasks(r.Context(), parts[1])
			if e != nil {
				consoleError(w, e)
				return
			}
			output(w, 200, map[string]any{"epoch": epoch, "tasks": tasks})
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
	if !actor.Can("nodes.manage") {
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
	if len(parts) == 1 && parts[0] == "vpcs" {
		var in OverlayVPCInput
		if !readConsoleJSON(w, r, &in) {
			return
		}
		v, replay, e := c.Store.CreateOverlayVPC(r.Context(), c.Config, actor.ID, key, in, time.Now().UTC())
		if e != nil {
			consoleError(w, e)
			return
		}
		status := 201
		if replay {
			status = 200
		}
		output(w, status, map[string]any{"vpc": v, "replay": replay})
		return
	}
	if !actor.Can("instances.manage") {
		failure(w, 403, "FORBIDDEN")
		return
	}
	if len(parts) == 1 && parts[0] == "epochs" {
		var in OverlayEpochInput
		if !readConsoleJSON(w, r, &in) {
			return
		}
		epoch, replay, e := c.Store.PlanOverlayEpoch(r.Context(), c.Config, actor.ID, key, in, time.Now().UTC())
		if e != nil {
			consoleError(w, e)
			return
		}
		output(w, 202, map[string]any{"epoch": epoch, "replay": replay})
		return
	}
	if len(parts) == 3 && parts[0] == "epochs" && nodeproto.ValidID(parts[1]) && parts[2] == "recover" {
		var in OverlayRecoveryInput
		if !readConsoleJSON(w, r, &in) {
			return
		}
		epoch, replay, e := c.overlayWorker().Recover(r.Context(), actor.ID, parts[1], key, in)
		if e != nil {
			consoleError(w, e)
			return
		}
		output(w, 202, map[string]any{"epoch": epoch, "replay": replay})
		return
	}
	if len(parts) == 3 && parts[0] == "epochs" && nodeproto.ValidID(parts[1]) && (parts[2] == "advance" || parts[2] == "reconcile") {
		if key != parts[1] {
			failure(w, 400, "IDEMPOTENCY_KEY_REQUIRED")
			return
		}
		var empty struct{}
		if !readConsoleJSON(w, r, &empty) {
			return
		}
		if e := c.Store.auditOverlayRequest(r.Context(), actor.ID, key, parts[2], time.Now().UTC()); e != nil {
			consoleError(w, e)
			return
		}
		if parts[2] == "advance" && c.OverlayRunner != nil {
			epoch, e := c.Store.OverlayEpoch(r.Context(), key)
			if e != nil {
				consoleError(w, e)
				return
			}
			if e = c.OverlayRunner.Start(key); e != nil {
				consoleError(w, e)
				return
			}
			output(w, 202, map[string]any{"epoch": epoch})
			return
		}
		worker := c.overlayWorker()
		var epoch OverlayEpoch
		var e error
		if parts[2] == "advance" {
			epoch, e = worker.Advance(r.Context(), key)
		} else {
			epoch, e = worker.Reconcile(r.Context(), key)
		}
		if e != nil {
			consoleError(w, e)
			return
		}
		output(w, 202, map[string]any{"epoch": epoch})
		return
	}
	failure(w, 404, "NOT_FOUND")
}
func (s *SQLStore) ListOverlayEpochs(ctx context.Context, cluster string, before int64) ([]OverlayEpoch, *int64, error) {
	if !nodeproto.ValidNodeID(cluster) || before < 0 {
		return nil, nil, ErrInput
	}
	q := "SELECT " + overlayEpochColumns + " FROM controller_overlay_epochs WHERE cluster_id=?"
	args := []any{cluster}
	if before > 0 {
		q += " AND epoch<?"
		args = append(args, before)
	}
	q += " ORDER BY epoch DESC LIMIT 21"
	rows, e := s.DB.QueryContext(ctx, q, args...)
	if e != nil {
		return nil, nil, e
	}
	defer rows.Close()
	out := []OverlayEpoch{}
	budget := 0
	for rows.Next() {
		v, e := scanOverlayEpoch(rows)
		if e != nil {
			return nil, nil, e
		}
		raw, _ := json.Marshal(v.Snapshot)
		if len(out) == 20 || len(out) > 0 && budget+len(raw) > 1<<20 {
			next := out[len(out)-1].Epoch
			return out, &next, nil
		}
		budget += len(raw)
		out = append(out, v)
	}
	return out, nil, rows.Err()
}
func (s *SQLStore) auditOverlayRequest(ctx context.Context, actor, id, action string, now time.Time) error {
	if !nodeproto.ValidID(actor) || !nodeproto.ValidID(id) || (action != "advance" && action != "reconcile") {
		return ErrInput
	}
	tx, e := s.locked(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = scanOverlayEpoch(tx.QueryRowContext(ctx, "SELECT "+overlayEpochColumns+" FROM controller_overlay_epochs WHERE id=?", id)); e != nil {
		return e
	}
	if e = audit(ctx, tx, "user:"+actor, "overlay."+action+".requested", id, now); e != nil {
		return e
	}
	return tx.Commit()
}

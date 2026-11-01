package control

import (
	"aster/cloud/internal/identity"
	"aster/cloud/internal/nodeproto"
	"context"
	"database/sql"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"
)

type RegionPlacement struct {
	RegionID string `json:"region_id"`
	Policy   string `json:"policy"`
}

func validPlacement(policy string) bool {
	return policy == "least_instances" || policy == "most_free_memory" || policy == "fill_first"
}
func (c Config) hasRegion(region string) bool {
	for _, n := range c.Nodes {
		if n.DatacenterID == region {
			return true
		}
	}
	return false
}

func placementPolicy(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, region string) (string, error) {
	var policy string
	err := q.QueryRowContext(ctx, "SELECT policy FROM controller_region_placement WHERE region_id=?", region).Scan(&policy)
	if errors.Is(err, sql.ErrNoRows) {
		return "least_instances", nil
	}
	if err != nil {
		return "", err
	}
	if !validPlacement(policy) {
		return "", ErrState
	}
	return policy, nil
}

func (s *SQLStore) Placement(ctx context.Context, c Config) ([]RegionPlacement, error) {
	regions := map[string]bool{}
	for _, n := range c.Nodes {
		regions[n.DatacenterID] = true
	}
	out := []RegionPlacement{}
	for region := range regions {
		policy, err := placementPolicy(ctx, s.DB, region)
		if err != nil {
			return nil, err
		}
		out = append(out, RegionPlacement{region, policy})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RegionID < out[j].RegionID })
	return out, nil
}

func (s *SQLStore) SetPlacement(ctx context.Context, c Config, actor, region, policy string, now time.Time) error {
	if !nodeproto.ValidID(actor) || !c.hasRegion(region) || !validPlacement(policy) {
		return ErrInput
	}
	tx, err := s.locked(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "INSERT INTO controller_region_placement(region_id,policy,updated_at) VALUES(?,?,?) ON DUPLICATE KEY UPDATE policy=VALUES(policy),updated_at=VALUES(updated_at)", region, policy, now); err != nil {
		return err
	}
	if err = audit(ctx, tx, "user:"+actor, "placement."+policy, region, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLStore) SetAllocationDisabled(ctx context.Context, c Config, actor, node string, disabled bool, now time.Time) error {
	if _, ok := c.Node(node); !ok || !nodeproto.ValidID(actor) {
		return ErrInput
	}
	tx, err := s.locked(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists string
	if err = tx.QueryRowContext(ctx, "SELECT id FROM controller_nodes WHERE id=?", node).Scan(&exists); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO controller_node_allocation(node_id,allocation_disabled,updated_at) VALUES(?,?,?) ON DUPLICATE KEY UPDATE allocation_disabled=VALUES(allocation_disabled),updated_at=VALUES(updated_at)", node, disabled, now); err != nil {
		return err
	}
	action := "node.allocation_enabled"
	if disabled {
		action = "node.allocation_disabled"
	}
	if err = audit(ctx, tx, "user:"+actor, action, node, now); err != nil {
		return err
	}
	return tx.Commit()
}

func allocationAllowed(ctx context.Context, tx *sql.Tx, node string) (bool, error) {
	var disabled bool
	err := tx.QueryRowContext(ctx, "SELECT allocation_disabled FROM controller_node_allocation WHERE node_id=?", node).Scan(&disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil
	}
	return !disabled, err
}

func selectCapacityCandidate(ctx context.Context, tx *sql.Tx, candidates []Candidate, now time.Time, ttl time.Duration) (Candidate, error) {
	ranked, err := rankCandidates(ctx, tx, candidates)
	if err != nil {
		return Candidate{}, err
	}
	for _, c := range ranked {
		var profile string
		var maintenance bool
		var seen sql.NullTime
		var raw []byte
		var cpu, mem, disk, rc, rm, rd int64
		err = tx.QueryRowContext(ctx, "SELECT profile_sha256,maintenance,heartbeat_at,free_cpu,free_memory_mib,free_disk_gib,capabilities FROM controller_nodes WHERE id=?", c.Node.ID).Scan(&profile, &maintenance, &seen, &cpu, &mem, &disk, &raw)
		if err != nil {
			return Candidate{}, err
		}
		var caps Capability
		if maintenance || !seen.Valid || !heartbeatFresh(&seen.Time, now, ttl) || profile != c.ProfileSHA || !strict(raw, &caps) || !caps.SupportsNetwork(c.Resources, c.Node, c.NetworkProfileID) {
			continue
		}
		err = tx.QueryRowContext(ctx, "SELECT COALESCE(SUM(cpu),0),COALESCE(SUM(memory_mib),0),COALESCE(SUM(disk_gib),0) FROM controller_reservations WHERE node_id=? AND released=FALSE", c.Node.ID).Scan(&rc, &rm, &rd)
		if err != nil {
			return Candidate{}, err
		}
		if int64(c.Resources.CPUCores) <= cpu-rc && int64(c.Resources.MemoryMiB) <= mem-rm && int64(c.Resources.SystemDiskGiB) <= disk-rd {
			return c, nil
		}
	}
	return Candidate{}, ErrCapacity
}

// Ranking, admission checks and reservation writes all run while holding
// controller_lock. Never choose from a browser's stale capacity snapshot.
func rankCandidates(ctx context.Context, tx *sql.Tx, in []Candidate) ([]Candidate, error) {
	type ranked struct {
		candidate         Candidate
		policy            string
		instances, memory int64
	}
	values := []ranked{}
	for _, c := range in {
		allowed, err := allocationAllowed(ctx, tx, c.Node.ID)
		if err != nil {
			return nil, err
		}
		if !allowed {
			continue
		}
		policy, err := placementPolicy(ctx, tx, c.Node.DatacenterID)
		if err != nil {
			return nil, err
		}
		var instances, memory int64
		err = tx.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM controller_instances WHERE node_id=n.id AND CAST(state AS BINARY) NOT IN ('deleted','rejected')), n.free_memory_mib-(SELECT COALESCE(SUM(memory_mib),0) FROM controller_reservations WHERE node_id=n.id AND released=FALSE) FROM controller_nodes n WHERE n.id=?`, c.Node.ID).Scan(&instances, &memory)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		values = append(values, ranked{c, policy, instances, memory})
	}
	sort.SliceStable(values, func(i, j int) bool {
		a, b := values[i], values[j]
		if a.candidate.Node.DatacenterID != b.candidate.Node.DatacenterID {
			return a.candidate.Node.DatacenterID < b.candidate.Node.DatacenterID
		}
		if a.policy == "least_instances" && a.instances != b.instances {
			return a.instances < b.instances
		}
		if a.policy == "most_free_memory" && a.memory != b.memory {
			return a.memory > b.memory
		}
		return a.candidate.Node.ID < b.candidate.Node.ID
	})
	out := make([]Candidate, len(values))
	for i, v := range values {
		out[i] = v.candidate
	}
	return out, nil
}

func (c Console) placement(w http.ResponseWriter, r *http.Request) {
	user, ok := identity.Actor(r.Context())
	if !ok {
		failure(w, 401, "AUTH_REQUIRED")
		return
	}
	if r.URL.RawQuery != "" {
		failure(w, 400, "INVALID_QUERY")
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/console/v1/"), "/")
	if r.Method == "GET" && len(parts) == 1 && parts[0] == "placement" {
		values, err := c.Store.Placement(r.Context(), c.Config)
		if err != nil {
			consoleError(w, err)
			return
		}
		output(w, 200, map[string]any{"items": values})
		return
	}
	if r.Method != "POST" {
		failure(w, 405, "METHOD_NOT_ALLOWED")
		return
	}
	if !user.Can("nodes.manage") {
		failure(w, 403, "FORBIDDEN")
		return
	}
	if len(parts) == 2 && parts[0] == "placement" {
		var in struct {
			Policy string `json:"policy"`
		}
		if !readConsoleJSON(w, r, &in) {
			return
		}
		err := c.Store.SetPlacement(r.Context(), c.Config, user.ID, parts[1], in.Policy, time.Now().UTC())
		if err != nil {
			consoleError(w, err)
			return
		}
		output(w, 200, RegionPlacement{parts[1], in.Policy})
		return
	}
	if len(parts) == 3 && parts[0] == "nodes" && parts[2] == "allocation" {
		var in struct {
			Disabled bool `json:"allocation_disabled"`
		}
		if !readConsoleJSON(w, r, &in) {
			return
		}
		err := c.Store.SetAllocationDisabled(r.Context(), c.Config, user.ID, parts[1], in.Disabled, time.Now().UTC())
		if err != nil {
			consoleError(w, err)
			return
		}
		output(w, 200, in)
		return
	}
	failure(w, 404, "NOT_FOUND")
}

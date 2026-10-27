package control

import (
	"aster/cloud/internal/nodeproto"
	"aster/cloud/internal/overlayproto"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const publicPoolColumns = "id,cluster_id,name,cidr,addresses,enabled,created_at,updated_at"
const publicLeaseColumns = "id,cluster_id,pool_id,owner_ref,vpc_id,node_id,profile_id,address,state,created_at,updated_at"
const publicOperationColumns = "id,actor_id,action,target_resource_id,resource_id,request_sha256,request,result,created_at"

func effectivePublicIPAddress(p OverlayNATProfile, selected string) string {
	if selected != "" {
		return selected
	}
	return p.PublicIPv4
}
func approvedPublicIPAddress(p OverlayNATProfile, address string) bool {
	if !overlayproto.PublicInternetIPv4(address) {
		return false
	}
	if address == p.PublicIPv4 {
		return true
	}
	for _, a := range p.PublicIPv4s {
		if a == address {
			return true
		}
	}
	return false
}
func validPublicIPApprovalAddresses(p OverlayNATProfile) bool {
	if len(p.PublicIPv4s) > 64 {
		return false
	}
	seen := map[string]bool{p.PublicIPv4: true}
	for _, a := range p.PublicIPv4s {
		if seen[a] || !overlayproto.PublicInternetIPv4(a) {
			return false
		}
		seen[a] = true
	}
	return true
}
func publicPoolValid(in PublicIPPoolInput) bool {
	p, err := netip.ParsePrefix(in.CIDR)
	if err != nil || !p.Addr().Is4() || p.String() != in.CIDR || p.Masked() != p || p.Bits() < 1 || !nodeproto.ValidNodeID(in.ClusterID) || !utf8.ValidString(in.Name) || strings.TrimSpace(in.Name) != in.Name || utf8.RuneCountInString(in.Name) < 1 || utf8.RuneCountInString(in.Name) > 80 || in.Addresses == nil || len(in.Addresses) < 1 || len(in.Addresses) > 4096 {
		return false
	}
	for _, r := range in.Name {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	seen := map[string]bool{}
	for _, a := range in.Addresses {
		ip, e := netip.ParseAddr(a)
		if e != nil || !overlayproto.PublicInternetIPv4(a) || !p.Contains(ip) || seen[a] {
			return false
		}
		seen[a] = true
	}
	return true
}
func publicLeaseInputValid(in PublicIPLeaseInput) bool {
	return nodeproto.ValidID(in.PoolID) && nodeproto.ValidID(in.OwnerRef) && nodeproto.ValidID(in.VPCID) && nodeproto.ValidNodeID(in.NodeID) && nodeproto.ValidNodeID(in.ProfileID) && (in.Address == "" || overlayproto.PublicInternetIPv4(in.Address))
}
func scanPublicPool(row interface{ Scan(...any) error }) (PublicIPPool, error) {
	var v PublicIPPool
	var raw []byte
	err := row.Scan(&v.ID, &v.ClusterID, &v.Name, &v.CIDR, &raw, &v.Enabled, &v.CreatedAt, &v.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return v, ErrNotFound
	}
	if err != nil {
		return v, err
	}
	if !strictPublicIP(raw, &v.Addresses) || !nodeproto.ValidID(v.ID) || !publicPoolValid(PublicIPPoolInput{v.ClusterID, v.Name, v.CIDR, v.Addresses, v.Enabled}) || !validOverlayTime(v.CreatedAt) || !validOverlayTime(v.UpdatedAt) {
		return v, ErrState
	}
	return v, nil
}
func scanPublicLease(row interface{ Scan(...any) error }) (PublicIPLease, error) {
	var v PublicIPLease
	err := row.Scan(&v.ID, &v.ClusterID, &v.PoolID, &v.OwnerRef, &v.VPCID, &v.NodeID, &v.ProfileID, &v.Address, &v.State, &v.CreatedAt, &v.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return v, ErrNotFound
	}
	if err != nil {
		return v, err
	}
	if !nodeproto.ValidID(v.ID) || !nodeproto.ValidNodeID(v.ClusterID) || !publicLeaseInputValid(PublicIPLeaseInput{v.PoolID, v.OwnerRef, v.VPCID, v.NodeID, v.ProfileID, v.Address}) || !overlayproto.PublicInternetIPv4(v.Address) || (v.State != "reserved" && v.State != "released") || !validOverlayTime(v.CreatedAt) || !validOverlayTime(v.UpdatedAt) {
		return v, ErrState
	}
	return v, nil
}
func scanPublicOperation(row interface{ Scan(...any) error }) (PublicIPOperation, error) {
	var v PublicIPOperation
	var result []byte
	err := row.Scan(&v.ID, &v.ActorID, &v.Action, &v.TargetResourceID, &v.ResourceID, &v.RequestSHA256, &v.Request, &result, &v.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return v, ErrNotFound
	}
	if err != nil {
		return v, err
	}
	if !nodeproto.ValidID(v.ID) || !nodeproto.ValidID(v.ActorID) || !nodeproto.ValidID(v.ResourceID) || v.TargetResourceID != "" && !nodeproto.ValidID(v.TargetResourceID) || !strictPublicIP(result, &v.Result) || !validOverlayTime(v.CreatedAt) || v.RequestSHA256 != publicOperationDigest(v.Action, v.TargetResourceID, v.Request) || !json.Valid(v.Request) {
		return v, ErrState
	}
	switch v.Action {
	case "pool.create", "pool.state", "pool.extend":
		if v.Result.Pool == nil || v.Result.Lease != nil || v.Result.Pool.ID != v.ResourceID {
			return v, ErrState
		}
	case "lease.allocate", "lease.release":
		if v.Result.Lease == nil || v.Result.Pool != nil || v.Result.Lease.ID != v.ResourceID {
			return v, ErrState
		}
	default:
		return v, ErrState
	}
	if !publicOperationResultValid(v) {
		return v, ErrState
	}
	return v, nil
}
func publicOperationDigest(action, target string, request json.RawMessage) string {
	raw, _ := json.Marshal(struct {
		Action  string          `json:"action"`
		Target  string          `json:"target_resource_id"`
		Request json.RawMessage `json:"request"`
	}{action, target, request})
	return overlayproto.Digest(raw)
}
func publicReplay(ctx context.Context, tx *sql.Tx, actor, op, action, target string, request json.RawMessage) (PublicIPOperation, bool, error) {
	if e := publicResourceIDUnusedTx(ctx, tx, op); e != nil {
		return PublicIPOperation{}, false, e
	}
	v, err := scanPublicOperation(tx.QueryRowContext(ctx, "SELECT "+publicOperationColumns+" FROM controller_public_ip_operations WHERE id=?", op))
	if err == nil {
		if v.ActorID != actor || v.Action != action || v.TargetResourceID != target || v.RequestSHA256 != publicOperationDigest(action, target, request) {
			return v, false, ErrConflict
		}
		return v, true, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return v, false, err
	}
	return v, false, nil
}
func insertPublicOperation(ctx context.Context, tx *sql.Tx, actor, op, action, target, resource string, request json.RawMessage, result PublicIPResult, now time.Time) (PublicIPOperation, error) {
	v := PublicIPOperation{op, actor, action, target, resource, publicOperationDigest(action, target, request), request, result, now}
	raw, _ := json.Marshal(result)
	if _, err := tx.ExecContext(ctx, "INSERT INTO controller_public_ip_operations("+publicOperationColumns+") VALUES(?,?,?,?,?,?,?,?,?)", v.ID, v.ActorID, v.Action, v.TargetResourceID, v.ResourceID, v.RequestSHA256, []byte(v.Request), raw, v.CreatedAt); err != nil {
		return v, err
	}
	if err := audit(ctx, tx, "user:"+actor, "public_ip."+action, resource, now); err != nil {
		return v, err
	}
	return v, nil
}
func publicMutationValid(actor, op string, now time.Time) bool {
	return nodeproto.ValidID(actor) && nodeproto.ValidID(op) && validOverlayTime(now)
}
func publicPoolApproved(c Config, in PublicIPPoolInput) bool {
	cluster, ok := c.OverlayCluster(in.ClusterID)
	if !c.validOverlayClusters() || !c.validDirectPublicProfiles() {
		return false
	}
	if !ok {
		cluster = OverlayCluster{}
	}
	for _, a := range in.Addresses {
		found := false
		for _, p := range cluster.NATProfiles {
			found = found || approvedPublicIPAddress(p, a)
		}
		for _, p := range c.DirectPublicProfiles {
			if p.ClusterID == in.ClusterID {
				found = found || directPublicAddressApproved(p, a)
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func publicLeaseRootProfileTx(ctx context.Context, tx *sql.Tx, c Config, v PublicIPLease) (OverlayNATProfile, error) {
	cluster, ok := c.OverlayCluster(v.ClusterID)
	if !ok || !c.validOverlayClusters() {
		return OverlayNATProfile{}, ErrState
	}
	global, e := scanOverlayVPC(tx.QueryRowContext(ctx, "SELECT "+overlayVPCColumns+" FROM controller_overlay_vpcs WHERE id=?", v.VPCID))
	if e != nil || global.ClusterID != v.ClusterID || global.OwnerRef != v.OwnerRef {
		return OverlayNATProfile{}, ErrState
	}
	for _, p := range cluster.NATProfiles {
		if p.NodeID == v.NodeID && p.VPCID == v.VPCID && p.ProfileID == v.ProfileID {
			for _, g := range cluster.Gateways {
				if g.InstanceID == p.GatewayInstanceID && g.VPCID == v.VPCID && g.NodeID == v.NodeID && g.OwnerRef == v.OwnerRef {
					return p, nil
				}
			}
		}
	}
	return OverlayNATProfile{}, ErrState
}
func publicLeaseApprovedTx(ctx context.Context, tx *sql.Tx, c Config, v PublicIPLease) error {
	if err := publicLeaseInventoryTx(ctx, tx, v); err != nil {
		return err
	}
	root, err := publicLeaseRootProfileTx(ctx, tx, c, v)
	if err != nil {
		return err
	}
	if !approvedPublicIPAddress(root, v.Address) {
		return ErrState
	}
	return nil
}

func (s *SQLStore) CreatePublicIPPool(ctx context.Context, c Config, actor, op string, in PublicIPPoolInput, now time.Time) (PublicIPPool, PublicIPOperation, bool, error) {
	if !publicMutationValid(actor, op, now) || !publicPoolValid(in) {
		return PublicIPPool{}, PublicIPOperation{}, false, ErrInput
	}
	in.Addresses = append([]string{}, in.Addresses...)
	sort.Strings(in.Addresses)
	raw, _ := json.Marshal(in)
	tx, e := s.locked(ctx)
	if e != nil {
		return PublicIPPool{}, PublicIPOperation{}, false, e
	}
	defer tx.Rollback()
	if !publicPoolApproved(c, in) {
		return PublicIPPool{}, PublicIPOperation{}, false, ErrState
	}
	operation, replay, e := publicReplay(ctx, tx, actor, op, "pool.create", "", raw)
	if e != nil {
		return PublicIPPool{}, operation, false, e
	}
	if replay {
		return *operation.Result.Pool, operation, true, nil
	}
	rows, e := tx.QueryContext(ctx, "SELECT "+publicPoolColumns+" FROM controller_public_ip_pools ORDER BY id")
	if e != nil {
		return PublicIPPool{}, operation, false, e
	}
	newPrefix, _ := netip.ParsePrefix(in.CIDR)
	for rows.Next() {
		old, err := scanPublicPool(rows)
		if err != nil {
			rows.Close()
			return PublicIPPool{}, operation, false, err
		}
		prefix, _ := netip.ParsePrefix(old.CIDR)
		if prefix.Contains(newPrefix.Addr()) || newPrefix.Contains(prefix.Addr()) {
			rows.Close()
			return PublicIPPool{}, operation, false, ErrConflict
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return PublicIPPool{}, operation, false, e
	}
	now = now.UTC().Truncate(time.Microsecond)
	v := PublicIPPool{op, in.ClusterID, in.Name, in.CIDR, in.Addresses, in.Enabled, now, now}
	addresses, _ := json.Marshal(v.Addresses)
	if _, e = tx.ExecContext(ctx, "INSERT INTO controller_public_ip_pools("+publicPoolColumns+") VALUES(?,?,?,?,?,?,?,?)", v.ID, v.ClusterID, v.Name, v.CIDR, addresses, v.Enabled, v.CreatedAt, v.UpdatedAt); e != nil {
		return v, operation, false, e
	}
	baselines, e := publicLegacyBaselinesTx(ctx, tx, c)
	if e != nil {
		return v, operation, false, e
	}
	for _, a := range v.Addresses {
		baseline := baselines[a]
		if _, e = tx.ExecContext(ctx, "INSERT INTO controller_public_ip_inventory(address,pool_id,legacy_epoch_id) VALUES(?,?,?)", a, v.ID, baseline); e != nil {
			return v, operation, false, ErrConflict
		}
	}
	operation, e = insertPublicOperation(ctx, tx, actor, op, "pool.create", "", v.ID, raw, PublicIPResult{Pool: &v}, now)
	if e != nil {
		return v, operation, false, e
	}
	return v, operation, false, tx.Commit()
}
func (s *SQLStore) SetPublicIPPoolState(ctx context.Context, c Config, actor, op, pool string, enabled bool, now time.Time) (PublicIPPool, PublicIPOperation, bool, error) {
	if !publicMutationValid(actor, op, now) || !nodeproto.ValidID(pool) {
		return PublicIPPool{}, PublicIPOperation{}, false, ErrInput
	}
	raw, _ := json.Marshal(struct {
		Enabled bool `json:"enabled"`
	}{enabled})
	tx, e := s.locked(ctx)
	if e != nil {
		return PublicIPPool{}, PublicIPOperation{}, false, e
	}
	defer tx.Rollback()
	v, e := scanPublicPool(tx.QueryRowContext(ctx, "SELECT "+publicPoolColumns+" FROM controller_public_ip_pools WHERE id=?", pool))
	if e != nil {
		return v, PublicIPOperation{}, false, e
	}
	// Turning admission off is always allowed, even after root withdrawal. Turning
	// it on requires every original immutable inventory address to remain approved.
	if enabled && !publicPoolApproved(c, PublicIPPoolInput{v.ClusterID, v.Name, v.CIDR, v.Addresses, true}) {
		return v, PublicIPOperation{}, false, ErrState
	}
	operation, replay, e := publicReplay(ctx, tx, actor, op, "pool.state", pool, raw)
	if e != nil {
		return v, operation, false, e
	}
	if replay {
		return *operation.Result.Pool, operation, true, nil
	}
	v.Enabled = enabled
	v.UpdatedAt = now.UTC().Truncate(time.Microsecond)
	if _, e = tx.ExecContext(ctx, "UPDATE controller_public_ip_pools SET enabled=?,updated_at=? WHERE id=?", enabled, v.UpdatedAt, pool); e != nil {
		return v, operation, false, e
	}
	operation, e = insertPublicOperation(ctx, tx, actor, op, "pool.state", pool, pool, raw, PublicIPResult{Pool: &v}, v.UpdatedAt)
	if e != nil {
		return v, operation, false, e
	}
	return v, operation, false, tx.Commit()
}

var ErrPublicIPCapacity = errors.New("public IP inventory exhausted")

func (s *SQLStore) AllocatePublicIP(ctx context.Context, c Config, actor, op string, in PublicIPLeaseInput, now time.Time) (PublicIPLease, PublicIPOperation, bool, error) {
	if !publicMutationValid(actor, op, now) || !publicLeaseInputValid(in) {
		return PublicIPLease{}, PublicIPOperation{}, false, ErrInput
	}
	raw, _ := json.Marshal(in)
	tx, e := s.locked(ctx)
	if e != nil {
		return PublicIPLease{}, PublicIPOperation{}, false, e
	}
	defer tx.Rollback()
	pool, e := scanPublicPool(tx.QueryRowContext(ctx, "SELECT "+publicPoolColumns+" FROM controller_public_ip_pools WHERE id=?", in.PoolID))
	if e != nil {
		return PublicIPLease{}, PublicIPOperation{}, false, e
	}
	now = now.UTC().Truncate(time.Microsecond)
	v := PublicIPLease{ID: op, ClusterID: pool.ClusterID, PoolID: pool.ID, OwnerRef: in.OwnerRef, VPCID: in.VPCID, NodeID: in.NodeID, ProfileID: in.ProfileID, Address: in.Address, State: "reserved", CreatedAt: now, UpdatedAt: now, BindingState: "reserved", Releasable: true}
	operation, replay, e := publicReplay(ctx, tx, actor, op, "lease.allocate", "", raw)
	if e != nil {
		return v, operation, false, e
	}
	if replay {
		prior := *operation.Result.Lease
		if e = publicLeaseApprovedTx(ctx, tx, c, prior); e != nil {
			return v, operation, false, e
		}
		return prior, operation, true, nil
	}
	root, e := publicLeaseRootProfileTx(ctx, tx, c, v)
	if e != nil {
		return v, operation, false, e
	}
	if !pool.Enabled {
		return v, operation, false, ErrState
	}
	active, e := publicIPActiveMapTx(ctx, tx)
	if e != nil {
		return v, operation, false, e
	}
	proof, e := readPublicIPReleaseProofTx(ctx, tx, c)
	if e != nil {
		return v, operation, false, e
	}
	candidates := pool.Addresses
	if in.Address != "" {
		present := false
		for _, address := range candidates {
			present = present || address == in.Address
		}
		if !present || !approvedPublicIPAddress(root, in.Address) {
			return v, operation, false, ErrState
		}
		candidates = []string{in.Address}
	}
	selected := ""
	eligible := false
	for _, address := range candidates {
		if !approvedPublicIPAddress(root, address) {
			continue
		}
		eligible = true
		if active[address] != "" {
			if in.Address != "" {
				return v, operation, false, ErrConflict
			}
			continue
		}
		e = proof.detached(ctx, tx, address, "")
		if e != nil {
			if in.Address != "" || !errors.Is(e, ErrState) {
				return v, operation, false, e
			}
			continue
		}
		selected = address
		break
	}
	if selected == "" {
		if !eligible {
			return v, operation, false, ErrState
		}
		return v, operation, false, ErrPublicIPCapacity
	}
	v.Address = selected
	if e = publicLeaseInventoryTx(ctx, tx, v); e != nil {
		return v, operation, false, e
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO controller_public_ip_active(address,lease_id) VALUES(?,?)", v.Address, v.ID); e != nil {
		return v, operation, false, ErrConflict
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO controller_public_ip_leases("+publicLeaseColumns+") VALUES(?,?,?,?,?,?,?,?,?,?,?)", v.ID, v.ClusterID, v.PoolID, v.OwnerRef, v.VPCID, v.NodeID, v.ProfileID, v.Address, v.State, v.CreatedAt, v.UpdatedAt); e != nil {
		return v, operation, false, e
	}
	operation, e = insertPublicOperation(ctx, tx, actor, op, "lease.allocate", "", v.ID, raw, PublicIPResult{Lease: &v}, now)
	if e != nil {
		return v, operation, false, e
	}
	return v, operation, false, tx.Commit()
}

func (s *SQLStore) ReleasePublicIP(ctx context.Context, c Config, actor, op, lease string, now time.Time) (PublicIPLease, PublicIPOperation, bool, error) {
	if !publicMutationValid(actor, op, now) || !nodeproto.ValidID(lease) {
		return PublicIPLease{}, PublicIPOperation{}, false, ErrInput
	}
	raw := json.RawMessage(`{}`)
	tx, e := s.locked(ctx)
	if e != nil {
		return PublicIPLease{}, PublicIPOperation{}, false, e
	}
	defer tx.Rollback()
	v, e := scanPublicLease(tx.QueryRowContext(ctx, "SELECT "+publicLeaseColumns+" FROM controller_public_ip_leases WHERE id=?", lease))
	if e != nil {
		return v, PublicIPOperation{}, false, e
	}
	operation, replay, e := publicReplay(ctx, tx, actor, op, "lease.release", lease, raw)
	if e != nil {
		return v, operation, false, e
	}
	if replay {
		return *operation.Result.Lease, operation, true, nil
	}
	if v.State != "reserved" {
		return v, operation, false, ErrState
	}
	if e = PublicIPSafeToReleaseTx(ctx, tx, c, v); e != nil {
		return v, operation, false, e
	}
	result, e := tx.ExecContext(ctx, "DELETE FROM controller_public_ip_active WHERE address=? AND lease_id=?", v.Address, v.ID)
	if e != nil {
		return v, operation, false, e
	}
	count, e := result.RowsAffected()
	if e != nil || count != 1 {
		return v, operation, false, ErrState
	}
	v.State = "released"
	v.BindingState = "released"
	v.Releasable = false
	v.ReleaseReason = ""
	v.UpdatedAt = now.UTC().Truncate(time.Microsecond)
	if _, e = tx.ExecContext(ctx, "UPDATE controller_public_ip_leases SET state='released',updated_at=? WHERE id=? AND state='reserved'", v.UpdatedAt, v.ID); e != nil {
		return v, operation, false, e
	}
	operation, e = insertPublicOperation(ctx, tx, actor, op, "lease.release", lease, lease, raw, PublicIPResult{Lease: &v}, v.UpdatedAt)
	if e != nil {
		return v, operation, false, e
	}
	return v, operation, false, tx.Commit()
}

func publicLeaseInventoryTx(ctx context.Context, tx *sql.Tx, v PublicIPLease) error {
	pool, err := scanPublicPool(tx.QueryRowContext(ctx, "SELECT "+publicPoolColumns+" FROM controller_public_ip_pools WHERE id=?", v.PoolID))
	if err != nil || pool.ClusterID != v.ClusterID {
		return ErrState
	}
	present := false
	for _, a := range pool.Addresses {
		present = present || a == v.Address
	}
	if !present {
		return ErrState
	}
	var stock string
	if err = tx.QueryRowContext(ctx, "SELECT pool_id FROM controller_public_ip_inventory WHERE address=?", v.Address).Scan(&stock); err != nil || stock != v.PoolID {
		return ErrState
	}
	return nil
}

func publicOperationResultValid(v PublicIPOperation) bool {
	if v.Result.Pool != nil {
		p := v.Result.Pool
		if !nodeproto.ValidID(p.ID) || !publicPoolValid(PublicIPPoolInput{p.ClusterID, p.Name, p.CIDR, p.Addresses, p.Enabled}) || !validOverlayTime(p.CreatedAt) || !validOverlayTime(p.UpdatedAt) || p.UpdatedAt.Before(p.CreatedAt) || !p.UpdatedAt.Equal(v.CreatedAt) {
			return false
		}
	}
	if v.Result.Lease != nil {
		l := v.Result.Lease
		if !nodeproto.ValidID(l.ID) || !nodeproto.ValidNodeID(l.ClusterID) || !publicLeaseInputValid(PublicIPLeaseInput{l.PoolID, l.OwnerRef, l.VPCID, l.NodeID, l.ProfileID, l.Address}) || !overlayproto.PublicInternetIPv4(l.Address) || !validOverlayTime(l.CreatedAt) || !validOverlayTime(l.UpdatedAt) || l.UpdatedAt.Before(l.CreatedAt) || !l.UpdatedAt.Equal(v.CreatedAt) {
			return false
		}
	}
	switch v.Action {
	case "pool.create":
		var in PublicIPPoolInput
		if !strictPublicIP(v.Request, &in) || v.TargetResourceID != "" || v.ResourceID != v.ID || !publicPoolValid(in) || !v.Result.Pool.CreatedAt.Equal(v.CreatedAt) {
			return false
		}
		p := v.Result.Pool
		raw1, _ := json.Marshal(in)
		raw2, _ := json.Marshal(PublicIPPoolInput{p.ClusterID, p.Name, p.CIDR, p.Addresses, p.Enabled})
		return string(raw1) == string(raw2)
	case "pool.extend":
		var in struct {
			Addresses []string `json:"addresses"`
		}
		if !strictPublicIP(v.Request, &in) || len(in.Addresses) < 1 || v.TargetResourceID != v.ResourceID {
			return false
		}
		present := map[string]bool{}
		for _, a := range v.Result.Pool.Addresses {
			present[a] = true
		}
		seen := map[string]bool{}
		for _, a := range in.Addresses {
			if !present[a] || seen[a] || !overlayproto.PublicInternetIPv4(a) {
				return false
			}
			seen[a] = true
		}
		return true
	case "pool.state":
		var in struct {
			Enabled *bool `json:"enabled"`
		}
		return strictPublicIP(v.Request, &in) && in.Enabled != nil && v.TargetResourceID == v.ResourceID && v.Result.Pool.Enabled == *in.Enabled
	case "lease.allocate":
		var in PublicIPLeaseInput
		if !strictPublicIP(v.Request, &in) || v.TargetResourceID != "" || v.ResourceID != v.ID {
			return false
		}
		l := v.Result.Lease
		actual := PublicIPLeaseInput{l.PoolID, l.OwnerRef, l.VPCID, l.NodeID, l.ProfileID, l.Address}
		if in.Address == "" {
			actual.Address = ""
		}
		return in == actual && overlayproto.PublicInternetIPv4(l.Address) && l.State == "reserved" && l.BindingState == "reserved" && l.Releasable && l.ReleaseReason == "" && l.CreatedAt.Equal(v.CreatedAt)
	case "lease.release":
		var in struct{}
		l := v.Result.Lease
		return strictPublicIP(v.Request, &in) && v.TargetResourceID == v.ResourceID && l.State == "released" && l.BindingState == "released" && !l.Releasable && l.ReleaseReason == ""
	}
	return false
}

func (s *SQLStore) ExtendPublicIPPool(ctx context.Context, c Config, actor, op, poolID string, addresses []string, now time.Time) (PublicIPPool, PublicIPOperation, bool, error) {
	if !publicMutationValid(actor, op, now) || !nodeproto.ValidID(poolID) || addresses == nil || len(addresses) < 1 || len(addresses) > 4096 {
		return PublicIPPool{}, PublicIPOperation{}, false, ErrInput
	}
	addresses = append([]string{}, addresses...)
	sort.Strings(addresses)
	for i, address := range addresses {
		if !overlayproto.PublicInternetIPv4(address) || i > 0 && addresses[i-1] == address {
			return PublicIPPool{}, PublicIPOperation{}, false, ErrInput
		}
	}
	raw, _ := json.Marshal(struct {
		Addresses []string `json:"addresses"`
	}{addresses})
	tx, e := s.locked(ctx)
	if e != nil {
		return PublicIPPool{}, PublicIPOperation{}, false, e
	}
	defer tx.Rollback()
	pool, e := scanPublicPool(tx.QueryRowContext(ctx, "SELECT "+publicPoolColumns+" FROM controller_public_ip_pools WHERE id=?", poolID))
	if e != nil {
		return pool, PublicIPOperation{}, false, e
	}
	// The new addresses, not unrelated withdrawn historical inventory, need fresh
	// root permission. Existing stock is immutable and cannot be stolen/rewritten.
	check := PublicIPPoolInput{ClusterID: pool.ClusterID, Name: pool.Name, CIDR: pool.CIDR, Addresses: addresses, Enabled: pool.Enabled}
	if !publicPoolValid(check) {
		return pool, PublicIPOperation{}, false, ErrInput
	}
	if !publicPoolApproved(c, check) {
		return pool, PublicIPOperation{}, false, ErrState
	}
	operation, replay, e := publicReplay(ctx, tx, actor, op, "pool.extend", poolID, raw)
	if e != nil {
		return pool, operation, false, e
	}
	if replay {
		return *operation.Result.Pool, operation, true, nil
	}
	if len(pool.Addresses)+len(addresses) > 4096 {
		return pool, operation, false, ErrCapacity
	}
	existing := map[string]bool{}
	for _, a := range pool.Addresses {
		existing[a] = true
	}
	for _, a := range addresses {
		if existing[a] {
			return pool, operation, false, ErrConflict
		}
	}
	baselines, e := publicLegacyBaselinesTx(ctx, tx, c)
	if e != nil {
		return pool, operation, false, e
	}
	for _, a := range addresses {
		if _, e = tx.ExecContext(ctx, "INSERT INTO controller_public_ip_inventory(address,pool_id,legacy_epoch_id) VALUES(?,?,?)", a, poolID, baselines[a]); e != nil {
			return pool, operation, false, ErrConflict
		}
	}
	pool.Addresses = append(pool.Addresses, addresses...)
	sort.Strings(pool.Addresses)
	pool.UpdatedAt = now.UTC().Truncate(time.Microsecond)
	stock, _ := json.Marshal(pool.Addresses)
	if _, e = tx.ExecContext(ctx, "UPDATE controller_public_ip_pools SET addresses=?,updated_at=? WHERE id=?", stock, pool.UpdatedAt, poolID); e != nil {
		return pool, operation, false, e
	}
	operation, e = insertPublicOperation(ctx, tx, actor, op, "pool.extend", poolID, poolID, raw, PublicIPResult{Pool: &pool}, pool.UpdatedAt)
	if e != nil {
		return pool, operation, false, e
	}
	return pool, operation, false, tx.Commit()
}

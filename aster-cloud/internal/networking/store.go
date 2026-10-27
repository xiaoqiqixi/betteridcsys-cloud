package networking

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
)

type Store struct{ DB *sql.DB }
type scanner interface{ Scan(...any) error }

const vpcColumns = "id,owner_ref,node_id,name,cidr,vlan_id,state,created_at"
const poolColumns = "id,node_id,vpc_id,name,cidr,gateway,addresses,enabled"
const leaseColumns = "id,pool_id,vpc_id,node_id,instance_id,owner_ref,address,state,created_at"

func scanVPC(row scanner) (VPC, error) {
	var v VPC
	e := row.Scan(&v.ID, &v.OwnerRef, &v.NodeID, &v.Name, &v.CIDR, &v.VLANID, &v.State, &v.CreatedAt)
	if errors.Is(e, sql.ErrNoRows) {
		return VPC{}, ErrNotFound
	}
	if e != nil || !v.valid() {
		return VPC{}, ErrUnavailable
	}
	v.CreatedAt = stamp(v.CreatedAt)
	return v, nil
}
func scanPool(row scanner) (IPPool, error) {
	var v IPPool
	var raw []byte
	e := row.Scan(&v.ID, &v.NodeID, &v.VPCID, &v.Name, &v.CIDR, &v.Gateway, &raw, &v.Enabled)
	if errors.Is(e, sql.ErrNoRows) {
		return IPPool{}, ErrNotFound
	}
	if e != nil || len(raw) > 128<<10 || json.Unmarshal(raw, &v.Addresses) != nil || !v.valid() {
		return IPPool{}, ErrUnavailable
	}
	return v, nil
}
func scanLease(row scanner) (Lease, error) {
	var v Lease
	e := row.Scan(&v.ID, &v.PoolID, &v.VPCID, &v.NodeID, &v.InstanceID, &v.OwnerRef, &v.Address, &v.State, &v.CreatedAt)
	if errors.Is(e, sql.ErrNoRows) {
		return Lease{}, ErrNotFound
	}
	if e != nil || !v.valid() {
		return Lease{}, ErrUnavailable
	}
	v.CreatedAt = stamp(v.CreatedAt)
	return v, nil
}
func (s *Store) locked(ctx context.Context) (*sql.Tx, error) {
	if s == nil || s.DB == nil {
		return nil, ErrUnavailable
	}
	tx, e := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if e != nil {
		return nil, ErrUnavailable
	}
	var one int
	if tx.QueryRowContext(ctx, "SELECT id FROM controller_lock WHERE id=1 FOR UPDATE").Scan(&one) != nil || one != 1 {
		tx.Rollback()
		return nil, ErrUnavailable
	}
	return tx, nil
}
func registeredNode(ctx context.Context, tx *sql.Tx, node string) error {
	var id string
	e := tx.QueryRowContext(ctx, "SELECT id FROM controller_nodes WHERE id=?", node).Scan(&id)
	if errors.Is(e, sql.ErrNoRows) {
		return ErrNotFound
	}
	if e != nil || id != node {
		return ErrUnavailable
	}
	return nil
}
func networkAudit(ctx context.Context, tx *sql.Tx, actor, action, target string, now time.Time) error {
	if _, e := tx.ExecContext(ctx, "INSERT INTO controller_audit(actor,action,target,created_at) VALUES(?,?,?,?)", "user:"+actor, action, target, stamp(now)); e != nil {
		return ErrUnavailable
	}
	return nil
}

func publicIngressNamespaceRow(row scanner) error {
	var used int
	if e := row.Scan(&used); e != nil {
		var mysqlError *mysql.MySQLError
		if errors.As(e, &mysqlError) && mysqlError.Number == 1146 {
			return nil
		}
		return ErrUnavailable
	}
	if used != 0 {
		return ErrConflict
	}
	return nil
}

// An idempotency key is bound to exactly one network resource kind and actor.
// No existing object is adopted, rewritten or freed by a replay.
func replay(ctx context.Context, tx *sql.Tx, kind, id, actor, digest string) (bool, error) {
	// Standalone schema-5 fixtures genuinely lack the newer namespace. Only a
	// direct MySQL 1146 proves that absence; invisible metadata, permissions and
	// failed database access never turn a conflicting key into an unused key.
	if e := publicIngressNamespaceRow(tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM controller_public_ingress_operations WHERE id=?", id)); e != nil {
		return false, e
	}
	for _, table := range []string{"controller_network_vpcs", "controller_network_pools", "controller_network_leases"} {
		var oldActor, oldSHA string
		e := tx.QueryRowContext(ctx, "SELECT actor_id,request_sha256 FROM "+table+" WHERE id=?", id).Scan(&oldActor, &oldSHA)
		if errors.Is(e, sql.ErrNoRows) {
			continue
		}
		if e != nil {
			return false, ErrUnavailable
		}
		if table != kind || oldActor != actor || oldSHA != digest {
			return false, ErrConflict
		}
		return true, nil
	}
	return false, nil
}
func commit(tx *sql.Tx) error {
	if tx.Commit() != nil {
		return ErrUnavailable
	}
	return nil
}

func (s *Store) CreateVPC(ctx context.Context, actor, id string, in CreateVPCInput, now time.Time) (VPC, bool, error) {
	if !validWrite(actor, id, now) || !in.Valid() {
		return VPC{}, false, ErrInput
	}
	tx, e := s.locked(ctx)
	if e != nil {
		return VPC{}, false, e
	}
	defer tx.Rollback()
	again, e := replay(ctx, tx, "controller_network_vpcs", id, actor, bodyDigest(in))
	if e != nil {
		return VPC{}, false, e
	}
	if again {
		v, e := scanVPC(tx.QueryRowContext(ctx, "SELECT "+vpcColumns+" FROM controller_network_vpcs WHERE id=?", id))
		if e != nil {
			return VPC{}, false, e
		}
		return v, true, commit(tx)
	}
	if e = registeredNode(ctx, tx, in.NodeID); e != nil {
		return VPC{}, false, e
	}
	rows, e := tx.QueryContext(ctx, "SELECT cidr,vlan_id FROM controller_network_vpcs WHERE node_id=?", in.NodeID)
	if e != nil {
		return VPC{}, false, ErrUnavailable
	}
	wanted, _ := netip.ParsePrefix(in.CIDR)
	for rows.Next() {
		var raw string
		var vlan int
		if rows.Scan(&raw, &vlan) != nil {
			rows.Close()
			return VPC{}, false, ErrUnavailable
		}
		p, ok := prefix(raw)
		if !ok {
			rows.Close()
			return VPC{}, false, ErrUnavailable
		}
		if vlan == in.VLANID || p.Overlaps(wanted) {
			rows.Close()
			return VPC{}, false, ErrConflict
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return VPC{}, false, ErrUnavailable
	}
	v := VPC{id, in.OwnerRef, in.NodeID, in.Name, in.CIDR, in.VLANID, "planned", stamp(now)}
	if _, e = tx.ExecContext(ctx, "INSERT INTO controller_network_vpcs("+vpcColumns+",request_sha256,actor_id) VALUES(?,?,?,?,?,?,?,?,?,?)", v.ID, v.OwnerRef, v.NodeID, v.Name, v.CIDR, v.VLANID, v.State, v.CreatedAt, bodyDigest(in), actor); e != nil {
		return VPC{}, false, ErrUnavailable
	}
	if e = networkAudit(ctx, tx, actor, "network.vpc.planned", id, now); e != nil {
		return VPC{}, false, e
	}
	return v, false, commit(tx)
}

func (s *Store) CreatePool(ctx context.Context, actor, id string, in CreatePoolInput, now time.Time) (IPPool, bool, error) {
	if !validWrite(actor, id, now) {
		return IPPool{}, false, ErrInput
	}
	in, e := in.Canonical()
	if e != nil {
		return IPPool{}, false, e
	}
	tx, e := s.locked(ctx)
	if e != nil {
		return IPPool{}, false, e
	}
	defer tx.Rollback()
	again, e := replay(ctx, tx, "controller_network_pools", id, actor, bodyDigest(in))
	if e != nil {
		return IPPool{}, false, e
	}
	if again {
		v, e := scanPool(tx.QueryRowContext(ctx, "SELECT "+poolColumns+" FROM controller_network_pools WHERE id=?", id))
		if e != nil {
			return IPPool{}, false, e
		}
		return v, true, commit(tx)
	}
	if e = registeredNode(ctx, tx, in.NodeID); e != nil {
		return IPPool{}, false, e
	}
	if in.VPCID != "" {
		v, e := scanVPC(tx.QueryRowContext(ctx, "SELECT "+vpcColumns+" FROM controller_network_vpcs WHERE id=?", in.VPCID))
		if e != nil {
			return IPPool{}, false, e
		}
		if v.NodeID != in.NodeID || v.CIDR != in.CIDR {
			return IPPool{}, false, ErrForbidden
		}
	}
	v := IPPool{id, in.NodeID, in.VPCID, in.Name, in.CIDR, in.Gateway, in.Addresses, in.Enabled}
	addresses, _ := json.Marshal(v.Addresses)
	if _, e = tx.ExecContext(ctx, "INSERT INTO controller_network_pools("+poolColumns+",request_sha256,actor_id,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)", v.ID, v.NodeID, v.VPCID, v.Name, v.CIDR, v.Gateway, addresses, v.Enabled, bodyDigest(in), actor, stamp(now)); e != nil {
		return IPPool{}, false, ErrUnavailable
	}
	if e = networkAudit(ctx, tx, actor, "network.pool.created", id, now); e != nil {
		return IPPool{}, false, e
	}
	return v, false, commit(tx)
}

func (s *Store) Reserve(ctx context.Context, actor, id string, in ReserveInput, now time.Time) (Lease, bool, error) {
	if !validWrite(actor, id, now) || !in.Valid() {
		return Lease{}, false, ErrInput
	}
	tx, e := s.locked(ctx)
	if e != nil {
		return Lease{}, false, e
	}
	defer tx.Rollback()
	v, again, e := reserveTx(ctx, tx, actor, id, in, now, "user:"+actor)
	if e != nil {
		return Lease{}, false, e
	}
	return v, again, commit(tx)
}

// ReserveTaskTx binds IPAM to a controller task in the caller's transaction. It
// never commits or opens a second connection. Re-taking the shared mutation gate
// in this same transaction is safe and prevents an unguarded internal caller.
// Task IDs, rather than fictitious users, identify the reservation audit actor.
func (s *Store) ReserveTaskTx(ctx context.Context, tx *sql.Tx, taskID string, in ReserveInput, now time.Time) (Lease, IPPool, VPC, error) {
	if tx == nil || !validWrite(taskID, taskID, now) || !in.Valid() {
		return Lease{}, IPPool{}, VPC{}, ErrInput
	}
	var one int
	if tx.QueryRowContext(ctx, "SELECT id FROM controller_lock WHERE id=1 FOR UPDATE").Scan(&one) != nil || one != 1 {
		return Lease{}, IPPool{}, VPC{}, ErrUnavailable
	}
	lease, _, e := reserveTx(ctx, tx, taskID, taskID, in, now, "task:"+taskID)
	if e != nil {
		return Lease{}, IPPool{}, VPC{}, e
	}
	pool, e := scanPool(tx.QueryRowContext(ctx, "SELECT "+poolColumns+" FROM controller_network_pools WHERE id=?", lease.PoolID))
	if e != nil {
		return Lease{}, IPPool{}, VPC{}, e
	}
	vpc, e := scanVPC(tx.QueryRowContext(ctx, "SELECT "+vpcColumns+" FROM controller_network_vpcs WHERE id=?", lease.VPCID))
	if e != nil {
		return Lease{}, IPPool{}, VPC{}, e
	}
	if !pool.Enabled || pool.VPCID == "" || pool.NodeID != lease.NodeID || pool.VPCID != vpc.ID || vpc.NodeID != lease.NodeID || vpc.OwnerRef != lease.OwnerRef || vpc.CIDR != pool.CIDR {
		return Lease{}, IPPool{}, VPC{}, ErrForbidden
	}
	return lease, pool, vpc, nil
}

// CheckTaskReservationTx is read-only and runs under the controller's mutation
// gate. Disabled pools cannot authorize activation but do not prevent a bound
// guest shutdown/deletion. Identity bindings are never repaired or reallocated.
func (s *Store) CheckTaskReservationTx(ctx context.Context, tx *sql.Tx, n nodeproto.NetworkBinding, requireEnabled bool) error {
	if tx == nil || !nodeproto.ValidID(n.LeaseID) {
		return ErrInput
	}
	l, e := scanLease(tx.QueryRowContext(ctx, "SELECT "+leaseColumns+" FROM controller_network_leases WHERE id=?", n.LeaseID))
	if e != nil {
		return e
	}
	p, e := scanPool(tx.QueryRowContext(ctx, "SELECT "+poolColumns+" FROM controller_network_pools WHERE id=?", n.PoolID))
	if e != nil {
		return e
	}
	v, e := scanVPC(tx.QueryRowContext(ctx, "SELECT "+vpcColumns+" FROM controller_network_vpcs WHERE id=?", n.VPCID))
	if e != nil {
		return e
	}
	if requireEnabled && !p.Enabled || l.PoolID != p.ID || l.VPCID != v.ID || p.VPCID != v.ID || l.NodeID != n.NodeID || p.NodeID != n.NodeID || v.NodeID != n.NodeID || l.InstanceID != n.InstanceID || l.OwnerRef != n.OwnerRef || v.OwnerRef != n.OwnerRef || l.Address != n.IPv4 || p.CIDR != n.CIDR || v.CIDR != n.CIDR || v.VLANID != n.VLANID {
		return ErrForbidden
	}
	return nil
}

func reserveTx(ctx context.Context, tx *sql.Tx, actor, id string, in ReserveInput, now time.Time, auditActor string) (Lease, bool, error) {
	again, e := replay(ctx, tx, "controller_network_leases", id, actor, bodyDigest(in))
	if e != nil {
		return Lease{}, false, e
	}
	if again {
		v, e := scanLease(tx.QueryRowContext(ctx, "SELECT "+leaseColumns+" FROM controller_network_leases WHERE id=?", id))
		if e != nil {
			return Lease{}, false, e
		}
		return v, true, nil
	}
	pool, e := scanPool(tx.QueryRowContext(ctx, "SELECT "+poolColumns+" FROM controller_network_pools WHERE id=?", in.PoolID))
	if e != nil {
		return Lease{}, false, e
	}
	if !pool.Enabled {
		return Lease{}, false, ErrState
	}
	if e = registeredNode(ctx, tx, pool.NodeID); e != nil {
		return Lease{}, false, e
	}
	var owner, node, state string
	e = tx.QueryRowContext(ctx, "SELECT owner_ref,node_id,state FROM controller_instances WHERE id=? FOR UPDATE", in.InstanceID).Scan(&owner, &node, &state)
	if errors.Is(e, sql.ErrNoRows) {
		return Lease{}, false, ErrNotFound
	}
	if e != nil {
		return Lease{}, false, ErrUnavailable
	}
	if owner != in.OwnerRef || node != pool.NodeID {
		return Lease{}, false, ErrForbidden
	}
	if state == "deleted" || state == "" {
		return Lease{}, false, ErrState
	}
	if pool.VPCID != "" {
		v, e := scanVPC(tx.QueryRowContext(ctx, "SELECT "+vpcColumns+" FROM controller_network_vpcs WHERE id=?", pool.VPCID))
		if e != nil {
			return Lease{}, false, e
		}
		if v.OwnerRef != in.OwnerRef || v.NodeID != pool.NodeID || v.CIDR != pool.CIDR {
			return Lease{}, false, ErrForbidden
		}
	}
	candidates := pool.Addresses
	if in.Address != "" {
		found := false
		for _, ip := range candidates {
			if ip == in.Address {
				found = true
				break
			}
		}
		if !found {
			return Lease{}, false, ErrInput
		}
		candidates = []string{in.Address}
	}
	args := make([]any, 0, len(candidates)+1)
	args = append(args, pool.NodeID)
	for _, ip := range candidates {
		args = append(args, ip)
	}
	q := "SELECT address FROM controller_network_leases WHERE node_id=? AND address IN (" + strings.TrimSuffix(strings.Repeat("?,", len(candidates)), ",") + ")"
	rows, e := tx.QueryContext(ctx, q, args...)
	if e != nil {
		return Lease{}, false, ErrUnavailable
	}
	used := map[string]bool{}
	for rows.Next() {
		var ip string
		if rows.Scan(&ip) != nil {
			rows.Close()
			return Lease{}, false, ErrUnavailable
		}
		used[ip] = true
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return Lease{}, false, ErrUnavailable
	}
	address := ""
	for _, ip := range candidates {
		if !used[ip] {
			address = ip
			break
		}
	}
	if address == "" {
		return Lease{}, false, ErrCapacity
	}
	v := Lease{id, pool.ID, pool.VPCID, pool.NodeID, in.InstanceID, in.OwnerRef, address, "reserved", stamp(now)}
	if _, e = tx.ExecContext(ctx, "INSERT INTO controller_network_leases("+leaseColumns+",request_sha256,actor_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)", v.ID, v.PoolID, v.VPCID, v.NodeID, v.InstanceID, v.OwnerRef, v.Address, v.State, v.CreatedAt, bodyDigest(in), actor); e != nil {
		return Lease{}, false, ErrUnavailable
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO controller_audit(actor,action,target,created_at) VALUES(?,?,?,?)", auditActor, "network.lease.reserved", id, stamp(now)); e != nil {
		return Lease{}, false, e
	}
	return v, false, nil
}

func (s *Store) GetVPC(ctx context.Context, id string) (VPC, error) {
	if !nodeproto.ValidID(id) {
		return VPC{}, ErrInput
	}
	if s == nil || s.DB == nil {
		return VPC{}, ErrUnavailable
	}
	return scanVPC(s.DB.QueryRowContext(ctx, "SELECT "+vpcColumns+" FROM controller_network_vpcs WHERE id=?", id))
}
func (s *Store) GetPool(ctx context.Context, id string) (IPPool, error) {
	if !nodeproto.ValidID(id) {
		return IPPool{}, ErrInput
	}
	if s == nil || s.DB == nil {
		return IPPool{}, ErrUnavailable
	}
	return scanPool(s.DB.QueryRowContext(ctx, "SELECT "+poolColumns+" FROM controller_network_pools WHERE id=?", id))
}
func (s *Store) GetLease(ctx context.Context, id string) (Lease, error) {
	if !nodeproto.ValidID(id) {
		return Lease{}, ErrInput
	}
	if s == nil || s.DB == nil {
		return Lease{}, ErrUnavailable
	}
	return scanLease(s.DB.QueryRowContext(ctx, "SELECT "+leaseColumns+" FROM controller_network_leases WHERE id=?", id))
}

func list[T any](ctx context.Context, s *Store, table, columns, cursor string, scan func(scanner) (T, error), budget int) (Page[T], error) {
	result := Page[T]{Items: []T{}}
	if cursor != "" && !nodeproto.ValidID(cursor) {
		return result, ErrInput
	}
	if s == nil || s.DB == nil {
		return result, ErrUnavailable
	}
	rows, e := s.DB.QueryContext(ctx, "SELECT "+columns+" FROM "+table+" WHERE id>? ORDER BY id ASC LIMIT 101", cursor)
	if e != nil {
		return result, ErrUnavailable
	}
	defer rows.Close()
	size := 128 // Includes the largest cursor and envelope, not just null.
	last := ""
	for rows.Next() {
		v, e := scan(rows)
		if e != nil {
			return Page[T]{Items: []T{}}, e
		}
		b, _ := json.Marshal(v)
		if len(result.Items) == PageLimit || budget > 0 && len(result.Items) > 0 && size+len(b)+1 > budget {
			result.NextCursor = &last
			break
		}
		result.Items = append(result.Items, v)
		size += len(b) + 1
		switch x := any(v).(type) {
		case VPC:
			last = x.ID
		case IPPool:
			last = x.ID
		case Lease:
			last = x.ID
		}
	}
	if rows.Err() != nil {
		return Page[T]{Items: []T{}}, ErrUnavailable
	}
	return result, nil
}
func (s *Store) ListVPCs(ctx context.Context, cursor string) (Page[VPC], error) {
	return list(ctx, s, "controller_network_vpcs", vpcColumns, cursor, scanVPC, 0)
}
func (s *Store) ListPools(ctx context.Context, cursor string) (Page[IPPool], error) {
	return list(ctx, s, "controller_network_pools", poolColumns, cursor, scanPool, PoolPageBudget)
}
func (s *Store) ListLeases(ctx context.Context, cursor string) (Page[Lease], error) {
	return list(ctx, s, "controller_network_leases", leaseColumns, cursor, scanLease, 0)
}

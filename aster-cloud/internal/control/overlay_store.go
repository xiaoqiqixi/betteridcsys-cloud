package control

import (
	"aster/cloud/internal/nodeproto"
	"aster/cloud/internal/overlayproto"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type OverlayVPCInput struct {
	ClusterID string `json:"cluster_id"`
	OwnerRef  string `json:"owner_ref"`
	Name      string `json:"name"`
	CIDR      string `json:"cidr"`
	VNI       int    `json:"vni"`
}
type OverlayVPC struct {
	ID        string    `json:"id"`
	ClusterID string    `json:"cluster_id"`
	OwnerRef  string    `json:"owner_ref"`
	Name      string    `json:"name"`
	CIDR      string    `json:"cidr"`
	VNI       int       `json:"vni"`
	CreatedAt time.Time `json:"created_at"`
}
type OverlayMemberInput struct {
	InstanceID string `json:"instance_id"`
	VPCID      string `json:"vpc_id"`
	Enabled    bool   `json:"enabled"`
	Reserved   bool   `json:"reserved"`
}
type OverlayEpochInput struct {
	ClusterID     string                 `json:"cluster_id"`
	ExpectedEpoch int64                  `json:"expected_epoch"`
	Members       []OverlayMemberInput   `json:"members"`
	Gateways      []overlayproto.Gateway `json:"gateways"`
	// nil preserves the preceding NAT intent; an explicit empty list removes it.
	// A pointer keeps these distinct in the idempotency digest.
	NATPolicies *[]overlayproto.NATPolicy  `json:"nat_policies,omitempty"`
	FloatingIPs *[]overlayproto.FloatingIP `json:"floating_ips,omitempty"`
}
type OverlayEpoch struct {
	ID             string                 `json:"id"`
	ClusterID      string                 `json:"cluster_id"`
	Epoch          int64                  `json:"epoch"`
	SnapshotSHA256 string                 `json:"snapshot_sha256"`
	Snapshot       overlayproto.Snapshot  `json:"snapshot"`
	Phase          string                 `json:"phase"`
	State          string                 `json:"state"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
	ActorID        string                 `json:"-"`
	RequestSHA256  string                 `json:"-"`
	Recovery       *overlayproto.Recovery `json:"recovery,omitempty"`
	SupersededBy   string                 `json:"superseded_by"`
}
type OverlayNodeTask struct {
	OperationID       string                `json:"operation_id"`
	EpochID           string                `json:"epoch_id"`
	NodeID            string                `json:"node_id"`
	Phase             string                `json:"phase"`
	State             string                `json:"state"`
	UpdatedAt         time.Time             `json:"updated_at"`
	NodeProfileSHA256 string                `json:"-"`
	RequestSHA256     string                `json:"request_sha256"`
	Receipt           []byte                `json:"-"`
	Result            *overlayproto.Receipt `json:"result,omitempty"`
}

const overlayVPCColumns = "id,cluster_id,owner_ref,name,cidr,vni,created_at"
const overlayEpochColumns = "id,cluster_id,epoch,actor_id,request_sha256,snapshot_sha256,snapshot,recovery,superseded_by,phase,state,created_at,updated_at"
const overlayTaskColumns = "operation_id,epoch_id,node_id,phase,node_profile_sha256,request_sha256,state,receipt,updated_at"

func validOverlayTime(t time.Time) bool { return !t.IsZero() && t.Year() >= 1000 && t.Year() <= 9999 }
func overlayVPCValid(in OverlayVPCInput) bool {
	p, ok := overlayproto.Prefix(in.CIDR)
	if !ok || !p.Addr().IsPrivate() || p.Bits() < 8 || p.Bits() > 30 || !nodeproto.ValidNodeID(in.ClusterID) || !nodeproto.ValidID(in.OwnerRef) || in.VNI < 1 || in.VNI > 16777215 || !utf8.ValidString(in.Name) || strings.TrimSpace(in.Name) != in.Name || utf8.RuneCountInString(in.Name) < 1 || utf8.RuneCountInString(in.Name) > 80 {
		return false
	}
	for _, r := range in.Name {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}
func scanOverlayVPC(row interface{ Scan(...any) error }) (OverlayVPC, error) {
	var v OverlayVPC
	e := row.Scan(&v.ID, &v.ClusterID, &v.OwnerRef, &v.Name, &v.CIDR, &v.VNI, &v.CreatedAt)
	if errors.Is(e, sql.ErrNoRows) {
		return v, ErrNotFound
	}
	if e != nil {
		return v, e
	}
	if !nodeproto.ValidID(v.ID) || !overlayVPCValid(OverlayVPCInput{v.ClusterID, v.OwnerRef, v.Name, v.CIDR, v.VNI}) || !validOverlayTime(v.CreatedAt) {
		return v, ErrState
	}
	return v, nil
}
func scanOverlayEpoch(row interface{ Scan(...any) error }) (OverlayEpoch, error) {
	var v OverlayEpoch
	var raw, recovery []byte
	e := row.Scan(&v.ID, &v.ClusterID, &v.Epoch, &v.ActorID, &v.RequestSHA256, &v.SnapshotSHA256, &raw, &recovery, &v.SupersededBy, &v.Phase, &v.State, &v.CreatedAt, &v.UpdatedAt)
	if errors.Is(e, sql.ErrNoRows) {
		return v, ErrNotFound
	}
	if e != nil {
		return v, e
	}
	if len(recovery) > 0 {
		var r overlayproto.Recovery
		if !strict(recovery, &r) {
			return v, ErrState
		}
		v.Recovery = &r
	}
	if v.SupersededBy != "" && !nodeproto.ValidID(v.SupersededBy) || v.State == "superseded" && v.SupersededBy == "" {
		return v, ErrState
	}
	v.Snapshot, e = overlayproto.DecodeSnapshot(raw)
	if e != nil || overlayproto.Digest(raw) != v.SnapshotSHA256 || v.Snapshot.ClusterID != v.ClusterID || v.Snapshot.Epoch != v.Epoch || !nodeproto.ValidID(v.ID) || !nodeproto.ValidID(v.ActorID) || !shaRE.MatchString(v.RequestSHA256) || !overlayproto.ValidPhase(v.Phase) || !(v.State == "pending" || v.State == "uncertain" || v.State == "rejected" || v.State == "succeeded" || v.State == "superseded") || !validOverlayTime(v.CreatedAt) || !validOverlayTime(v.UpdatedAt) {
		return v, ErrState
	}
	if _, _, e := overlayTask(v, v.Snapshot.Profiles[0].NodeID, v.Phase).BytesAndDigest(); e != nil {
		return v, ErrState
	}
	return v, nil
}
func scanOverlayTask(row interface{ Scan(...any) error }) (OverlayNodeTask, error) {
	var v OverlayNodeTask
	e := row.Scan(&v.OperationID, &v.EpochID, &v.NodeID, &v.Phase, &v.NodeProfileSHA256, &v.RequestSHA256, &v.State, &v.Receipt, &v.UpdatedAt)
	if errors.Is(e, sql.ErrNoRows) {
		return v, ErrNotFound
	}
	if e != nil {
		return v, e
	}
	if v.OperationID != overlayproto.PhaseOperationID(v.EpochID, v.NodeID, v.Phase) || !nodeproto.ValidID(v.EpochID) || !nodeproto.ValidNodeID(v.NodeID) || !overlayproto.ValidPhase(v.Phase) || !shaRE.MatchString(v.NodeProfileSHA256) || !shaRE.MatchString(v.RequestSHA256) || !(v.State == "pending" || v.State == "sending" || v.State == "uncertain" || v.State == "succeeded" || v.State == "rejected") || !validOverlayTime(v.UpdatedAt) {
		return v, ErrState
	}
	if len(v.Receipt) > 0 {
		receipt, err := overlayproto.DecodeReceipt(v.Receipt)
		if err != nil || receipt.OperationID != v.OperationID || receipt.NodeID != v.NodeID || receipt.Phase != v.Phase || receipt.RequestSHA256 != v.RequestSHA256 || receipt.Status != v.State {
			return v, ErrState
		}
		v.Result = &receipt
	} else if v.State == "succeeded" || v.State == "rejected" {
		return v, ErrState
	}
	return v, nil
}
func (s *SQLStore) CreateOverlayVPC(ctx context.Context, c Config, actor, id string, in OverlayVPCInput, now time.Time) (OverlayVPC, bool, error) {
	if !nodeproto.ValidID(actor) || !nodeproto.ValidID(id) || !overlayVPCValid(in) || !validOverlayTime(now) {
		return OverlayVPC{}, false, ErrInput
	}
	if _, ok := c.OverlayCluster(in.ClusterID); !ok {
		return OverlayVPC{}, false, ErrState
	}
	b, _ := json.Marshal(in)
	sha := overlayproto.Digest(b)
	tx, e := s.locked(ctx)
	if e != nil {
		return OverlayVPC{}, false, e
	}
	defer tx.Rollback()
	if e = publicIngressOperationIDUnusedTx(ctx, tx, id); e != nil {
		return OverlayVPC{}, false, e
	}
	var oldActor, oldSHA string
	e = tx.QueryRowContext(ctx, "SELECT actor_id,request_sha256 FROM controller_overlay_vpcs WHERE id=?", id).Scan(&oldActor, &oldSHA)
	if e == nil {
		if oldActor != actor || oldSHA != sha {
			return OverlayVPC{}, false, ErrConflict
		}
		v, e := scanOverlayVPC(tx.QueryRowContext(ctx, "SELECT "+overlayVPCColumns+" FROM controller_overlay_vpcs WHERE id=?", id))
		return v, true, e
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return OverlayVPC{}, false, e
	}
	var n int
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM controller_overlay_vpcs WHERE cluster_id=?", in.ClusterID).Scan(&n); e != nil {
		return OverlayVPC{}, false, e
	}
	if n >= 32 {
		return OverlayVPC{}, false, ErrCapacity
	}
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM controller_overlay_vpcs WHERE cluster_id=? AND vni=?", in.ClusterID, in.VNI).Scan(&n); e != nil {
		return OverlayVPC{}, false, e
	}
	if n != 0 {
		return OverlayVPC{}, false, ErrConflict
	}
	v := OverlayVPC{id, in.ClusterID, in.OwnerRef, in.Name, in.CIDR, in.VNI, now.UTC().Truncate(time.Microsecond)}
	if _, e = tx.ExecContext(ctx, "INSERT INTO controller_overlay_vpcs("+overlayVPCColumns+",request_sha256,actor_id) VALUES(?,?,?,?,?,?,?,?,?)", v.ID, v.ClusterID, v.OwnerRef, v.Name, v.CIDR, v.VNI, v.CreatedAt, sha, actor); e != nil {
		return OverlayVPC{}, false, e
	}
	if e = audit(ctx, tx, "user:"+actor, "overlay.vpc.created", id, now); e != nil {
		return OverlayVPC{}, false, e
	}
	return v, false, tx.Commit()
}
func (s *SQLStore) OverlayVPCs(ctx context.Context, cluster string) ([]OverlayVPC, error) {
	if !nodeproto.ValidNodeID(cluster) {
		return nil, ErrInput
	}
	rows, e := s.DB.QueryContext(ctx, "SELECT "+overlayVPCColumns+" FROM controller_overlay_vpcs WHERE cluster_id=? ORDER BY id LIMIT 33", cluster)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []OverlayVPC{}
	for rows.Next() {
		v, e := scanOverlayVPC(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	if len(out) > 32 {
		return nil, ErrState
	}
	return out, rows.Err()
}
func canonicalOverlayInput(in OverlayEpochInput) (OverlayEpochInput, string, error) {
	if !nodeproto.ValidNodeID(in.ClusterID) || in.ExpectedEpoch < 0 || in.ExpectedEpoch == math.MaxInt64 || in.Members == nil || len(in.Members) > 128 || in.Gateways == nil || len(in.Gateways) > 32 {
		return in, "", ErrInput
	}
	in.Members = append([]OverlayMemberInput{}, in.Members...)
	in.Gateways = append([]overlayproto.Gateway{}, in.Gateways...)
	sort.Slice(in.Members, func(i, j int) bool { return in.Members[i].InstanceID < in.Members[j].InstanceID })
	sort.Slice(in.Gateways, func(i, j int) bool { return in.Gateways[i].VPCID < in.Gateways[j].VPCID })
	for i, m := range in.Members {
		if !nodeproto.ValidID(m.InstanceID) || !nodeproto.ValidID(m.VPCID) || i > 0 && m.InstanceID == in.Members[i-1].InstanceID {
			return in, "", ErrInput
		}
	}
	for i, g := range in.Gateways {
		if g.AllowedPrefixes == nil {
			return in, "", ErrInput
		}
		g.AllowedPrefixes = append([]string{}, g.AllowedPrefixes...)
		sort.Strings(g.AllowedPrefixes)
		in.Gateways[i] = g
	}
	if in.NATPolicies != nil {
		if *in.NATPolicies == nil || len(*in.NATPolicies) > 32 {
			return in, "", ErrInput
		}
		policies := append([]overlayproto.NATPolicy{}, (*in.NATPolicies)...)
		sort.Slice(policies, func(i, j int) bool { return policies[i].ID < policies[j].ID })
		for i := range policies {
			if policies[i].Forwardings == nil || len(policies[i].Forwardings) > 128 {
				return in, "", ErrInput
			}
			policies[i].Forwardings = append([]overlayproto.NATForwarding{}, policies[i].Forwardings...)
			sort.Slice(policies[i].Forwardings, func(a, b int) bool { return policies[i].Forwardings[a].ID < policies[i].Forwardings[b].ID })
		}
		in.NATPolicies = &policies
	}

	if in.FloatingIPs != nil {
		if *in.FloatingIPs == nil || len(*in.FloatingIPs) > 128 {
			return in, "", ErrInput
		}
		values := append([]overlayproto.FloatingIP{}, (*in.FloatingIPs)...)
		sort.Slice(values, func(i, j int) bool { return values[i].ResourceID < values[j].ResourceID })
		in.FloatingIPs = &values
	}
	b, _ := json.Marshal(in)
	return in, overlayproto.Digest(b), nil
}
func (s *SQLStore) PlanOverlayEpoch(ctx context.Context, c Config, actor, op string, in OverlayEpochInput, now time.Time) (OverlayEpoch, bool, error) {
	if in.FloatingIPs != nil {
		return OverlayEpoch{}, false, ErrInput
	}
	if !nodeproto.ValidID(actor) || !nodeproto.ValidID(op) || !validOverlayTime(now) {
		return OverlayEpoch{}, false, ErrInput
	}
	in, digest, e := canonicalOverlayInput(in)
	if e != nil {
		return OverlayEpoch{}, false, e
	}
	cluster, ok := c.OverlayCluster(in.ClusterID)
	if !ok || !c.validOverlayClusters() {
		return OverlayEpoch{}, false, ErrState
	}
	tx, e := s.locked(ctx)
	if e != nil {
		return OverlayEpoch{}, false, e
	}
	defer tx.Rollback()
	if e = publicIngressOperationIDUnusedTx(ctx, tx, op); e != nil {
		return OverlayEpoch{}, false, e
	}
	prior, e := scanOverlayEpoch(tx.QueryRowContext(ctx, "SELECT "+overlayEpochColumns+" FROM controller_overlay_epochs WHERE id=?", op))
	if e == nil {
		if prior.ActorID != actor || prior.RequestSHA256 != digest {
			return OverlayEpoch{}, false, ErrConflict
		}
		return prior, true, nil
	}
	if !errors.Is(e, ErrNotFound) {
		return OverlayEpoch{}, false, e
	}
	previous, e := scanOverlayEpoch(tx.QueryRowContext(ctx, "SELECT "+overlayEpochColumns+" FROM controller_overlay_epochs WHERE cluster_id=? ORDER BY epoch DESC LIMIT 1", in.ClusterID))
	if e != nil && !errors.Is(e, ErrNotFound) {
		return OverlayEpoch{}, false, e
	}
	if previous.Epoch != in.ExpectedEpoch || previous.Epoch > 0 && (previous.State != "succeeded" || !overlayPinsMatch(c, previous)) {
		return OverlayEpoch{}, false, ErrState
	}
	snapshot, sha, e := buildOverlaySnapshot(ctx, tx, c, cluster, previous, in, now, false)
	if e != nil {
		return OverlayEpoch{}, false, e
	}
	if e = validatePublicIPSnapshotTx(ctx, tx, c, snapshot, now); e != nil {
		return OverlayEpoch{}, false, e
	}
	raw, _ := json.Marshal(snapshot)
	now = now.UTC().Truncate(time.Microsecond)
	epoch := OverlayEpoch{ID: op, ClusterID: in.ClusterID, Epoch: snapshot.Epoch, SnapshotSHA256: sha, Snapshot: snapshot, Phase: "prepare", State: "pending", CreatedAt: now, UpdatedAt: now, ActorID: actor, RequestSHA256: digest}
	if _, e = tx.ExecContext(ctx, "INSERT INTO controller_overlay_epochs("+overlayEpochColumns+") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", op, in.ClusterID, epoch.Epoch, actor, digest, sha, raw, []byte{}, "", epoch.Phase, epoch.State, now, now); e != nil {
		return OverlayEpoch{}, false, e
	}
	for _, phase := range []string{"prepare", "program", "release"} {
		for _, pin := range snapshot.Profiles {
			p, _ := c.Node(pin.NodeID)
			task := overlayTask(epoch, pin.NodeID, phase)
			_, requestSHA, e := task.BytesAndDigest()
			if e != nil {
				return OverlayEpoch{}, false, ErrInput
			}
			if _, e = tx.ExecContext(ctx, "INSERT INTO controller_overlay_tasks("+overlayTaskColumns+") VALUES(?,?,?,?,?,?,?,?,?)", task.OperationID, op, pin.NodeID, phase, p.Digest(), requestSHA, "pending", []byte{}, now); e != nil {
				return OverlayEpoch{}, false, e
			}
		}
	}
	if e = audit(ctx, tx, "user:"+actor, "overlay.epoch.planned", op, now); e != nil {
		return OverlayEpoch{}, false, e
	}
	return epoch, false, tx.Commit()
}

// buildOverlaySnapshot is shared by normal planning and explicitly approved
// recovery replacement. Original node/2, financial and IPAM records are read-only.
// The caller holds the global controller transaction lock.
func buildOverlaySnapshot(ctx context.Context, tx *sql.Tx, c Config, cluster OverlayCluster, previous OverlayEpoch, in OverlayEpochInput, now time.Time, recovery bool) (overlayproto.Snapshot, string, error) {
	snapshot := overlayproto.Snapshot{Protocol: overlayproto.Protocol, ClusterID: in.ClusterID, Epoch: in.ExpectedEpoch + 1, PreviousSHA256: previous.SnapshotSHA256, Profiles: append([]overlayproto.ProfilePin{}, cluster.Profiles...), VPCs: []overlayproto.VPC{}, Members: []overlayproto.Member{}, Gateways: in.Gateways}
	snapshot.NATPolicies = previous.Snapshot.NATPolicies
	snapshot.FloatingIPs = previous.Snapshot.FloatingIPs
	if in.FloatingIPs != nil {
		snapshot.FloatingIPs = *in.FloatingIPs
	}
	if recovery && in.FloatingIPs == nil {
		snapshot.FloatingIPs = recoveryFloatingPins(cluster, snapshot.FloatingIPs)
	}
	if in.NATPolicies != nil {
		snapshot.NATPolicies = *in.NATPolicies
	}
	if !overlayPoliciesApproved(cluster, snapshot) {
		return overlayproto.Snapshot{}, "", ErrState
	}
	rows, e := tx.QueryContext(ctx, "SELECT "+overlayVPCColumns+" FROM controller_overlay_vpcs WHERE cluster_id=? ORDER BY id LIMIT 33", in.ClusterID)
	if e != nil {
		return overlayproto.Snapshot{}, "", e
	}
	vpcs := map[string]overlayproto.VPC{}
	for rows.Next() {
		v, e := scanOverlayVPC(rows)
		if e != nil {
			rows.Close()
			return overlayproto.Snapshot{}, "", e
		}
		wire := overlayproto.VPC{ID: v.ID, OwnerRef: v.OwnerRef, CIDR: v.CIDR, VNI: v.VNI}
		snapshot.VPCs = append(snapshot.VPCs, wire)
		vpcs[v.ID] = wire
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return overlayproto.Snapshot{}, "", e
	}
	pins := map[string]overlayproto.ProfilePin{}
	for _, pin := range snapshot.Profiles {
		pins[pin.NodeID] = pin
		node, _ := c.Node(pin.NodeID)
		var have string
		if e = tx.QueryRowContext(ctx, "SELECT profile_sha256 FROM controller_nodes WHERE id=?", pin.NodeID).Scan(&have); e != nil || have != node.Digest() {
			return overlayproto.Snapshot{}, "", ErrState
		}
	}
	members := map[string]overlayproto.Member{}
	retained := map[string]overlayproto.Member{}
	for _, member := range previous.Snapshot.Members {
		retained[member.InstanceID] = member
	}
	for _, input := range in.Members {
		v, e := scanInstance(tx.QueryRowContext(ctx, "SELECT id,owner_ref,node_id,hostname,state,resources,created_at,updated_at FROM controller_instances WHERE id=?", input.InstanceID))
		if e != nil {
			return overlayproto.Snapshot{}, "", e
		}
		_, wasMember := retained[v.ID]
		recoveringMember := recovery && wasMember && v.State != "deleted"
		if !recoveringMember && v.State != "running" && v.State != "shutoff" && v.State != "created" && !(input.Reserved && v.State == "reserved") {
			return overlayproto.Snapshot{}, "", ErrState
		}
		network, e := instanceNetworkBinding(ctx, tx, v)
		if e != nil || network.IsZero() {
			return overlayproto.Snapshot{}, "", ErrState
		}
		pin, ok := pins[v.NodeID]
		global, gok := vpcs[input.VPCID]
		if !ok || !gok || pin.ProfileID != network.ProfileID || global.OwnerRef != v.OwnerRef || global.CIDR != network.CIDR || !overlayMappingMatches(cluster, v.NodeID, network.VPCID, global.ID) {
			return overlayproto.Snapshot{}, "", ErrState
		}
		// A replacement can repair an already-owned uncertain lifecycle, but it
		// cannot admit a new moving guest. Root recovery re-fences exact heads and
		// checks the original node ledger before allowing any member to resume.
		if !recoveringMember {
			var count int
			if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM controller_operations WHERE instance_id=? AND state NOT IN ('succeeded','rejected') AND NOT (?=TRUE AND action='create' AND state='accepted')", v.ID, input.Reserved).Scan(&count); e != nil || count != 0 {
				return overlayproto.Snapshot{}, "", ErrState
			}
			if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM controller_jobs WHERE instance_id=? AND state NOT IN ('succeeded','rejected') AND NOT (?=TRUE AND state='accepted')", v.ID, input.Reserved).Scan(&count); e != nil || count != 0 {
				return overlayproto.Snapshot{}, "", ErrState
			}
		}
		member := overlayproto.Member{NodeID: v.NodeID, InstanceID: v.ID, InterfaceID: network.InterfaceID, OwnerRef: v.OwnerRef, VPCID: global.ID, LocalVPCID: network.VPCID, LeaseID: network.LeaseID, PoolID: network.PoolID, NetworkSHA256: network.Digest(), IPv4: network.IPv4, MAC: network.MAC, InboundMbps: network.InboundMbps, OutboundMbps: network.OutboundMbps, Enabled: input.Enabled, Reserved: input.Reserved}
		if recoveringMember && retained[v.ID].Reserved && v.State == "reserved" && !member.Reserved {
			return overlayproto.Snapshot{}, "", ErrState
		}
		members[v.ID] = member
		snapshot.Members = append(snapshot.Members, member)
		var oldCluster, oldVPC, oldAddress, oldLease, oldSHA string
		e = tx.QueryRowContext(ctx, "SELECT cluster_id,vpc_id,address,lease_id,network_sha256 FROM controller_overlay_members WHERE instance_id=?", v.ID).Scan(&oldCluster, &oldVPC, &oldAddress, &oldLease, &oldSHA)
		if e == nil {
			if oldCluster != in.ClusterID || oldVPC != global.ID || oldAddress != network.IPv4 || oldLease != network.LeaseID || oldSHA != network.Digest() {
				return overlayproto.Snapshot{}, "", ErrConflict
			}
		} else if errors.Is(e, sql.ErrNoRows) {
			if _, e = tx.ExecContext(ctx, "INSERT INTO controller_overlay_members(instance_id,cluster_id,vpc_id,address,lease_id,network_sha256,created_at) VALUES(?,?,?,?,?,?,?)", v.ID, in.ClusterID, global.ID, network.IPv4, network.LeaseID, network.Digest(), now); e != nil {
				return overlayproto.Snapshot{}, "", ErrConflict
			}
		} else {
			return overlayproto.Snapshot{}, "", e
		}
	}
	if e = overlayCompleteInventory(ctx, tx, snapshot); e != nil {
		return overlayproto.Snapshot{}, "", e
	}
	// Omitted live identities are unsafe: disable explicitly, retain until deletion.
	for _, old := range previous.Snapshot.Members {
		if _, exists := members[old.InstanceID]; !exists {
			var state string
			if e = tx.QueryRowContext(ctx, "SELECT state FROM controller_instances WHERE id=?", old.InstanceID).Scan(&state); e != nil || state != "deleted" {
				return overlayproto.Snapshot{}, "", ErrState
			}
		}
	}
	snapshot, sha, e := overlayproto.CanonicalSnapshot(snapshot)
	if e != nil {
		return overlayproto.Snapshot{}, "", ErrInput
	}
	return snapshot, sha, nil
}

func overlayMappingMatches(cluster OverlayCluster, node, local, global string) bool {
	for _, m := range cluster.Mappings {
		if m.NodeID == node && m.LocalVPCID == local {
			return m.VPCID == global
		}
	}
	return false
}

func overlayTask(e OverlayEpoch, node, phase string) overlayproto.Task {
	return overlayproto.Task{Protocol: overlayproto.Protocol, OperationID: overlayproto.PhaseOperationID(e.ID, node, phase), NodeID: node, Phase: phase, SnapshotSHA256: e.SnapshotSHA256, Snapshot: e.Snapshot, Recovery: e.Recovery}
}
func (s *SQLStore) OverlayEpoch(ctx context.Context, id string) (OverlayEpoch, error) {
	if !nodeproto.ValidID(id) {
		return OverlayEpoch{}, ErrInput
	}
	return scanOverlayEpoch(s.DB.QueryRowContext(ctx, "SELECT "+overlayEpochColumns+" FROM controller_overlay_epochs WHERE id=?", id))
}
func (s *SQLStore) OverlayTasks(ctx context.Context, id string) ([]OverlayNodeTask, error) {
	if !nodeproto.ValidID(id) {
		return nil, ErrInput
	}
	rows, e := s.DB.QueryContext(ctx, "SELECT "+overlayTaskColumns+" FROM controller_overlay_tasks WHERE epoch_id=? ORDER BY phase,node_id", id)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []OverlayNodeTask{}
	for rows.Next() {
		v, e := scanOverlayTask(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
		if len(out) > 96 {
			return nil, ErrState
		}
	}
	return out, rows.Err()
}

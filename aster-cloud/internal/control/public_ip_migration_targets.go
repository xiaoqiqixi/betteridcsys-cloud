package control

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"database/sql"
	"time"
)

type MigrationTarget struct {
	NodeID   string `json:"node_id"`
	Eligible bool   `json:"eligible"`
	Reason   string `json:"reason"`
}
type MigrationTargets struct {
	Complete bool              `json:"complete"`
	Items    []MigrationTarget `json:"items"`
}

func directCapabilityMatches(c Capability, b nodeproto.DirectPublicBinding) bool {
	p := c.DirectPublicNetwork
	if p == nil || !contains(c.NetworkProfiles, nodeproto.DirectPublicCapability) || p.ProfileID != b.ProfileID || p.ProfileSHA256 != b.ProfileSHA256 || p.CIDR != b.CIDR || p.Gateway != b.Gateway || !contains(p.Addresses, b.IPv4) {
		return false
	}
	return true
}
func (s *SQLStore) MigrationTargets(ctx context.Context, c Config, instance string, now time.Time) (MigrationTargets, error) {
	out := MigrationTargets{Complete: true, Items: []MigrationTarget{}}
	if !nodeproto.ValidID(instance) {
		return out, ErrInput
	}
	tx, e := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	v, e := scanInstance(tx.QueryRowContext(ctx, "SELECT id,owner_ref,node_id,hostname,state,resources,created_at,updated_at FROM controller_instances WHERE id=?", instance))
	if e != nil {
		return out, e
	}
	b, e := instanceDirectPublicTx(ctx, tx, v)
	if e != nil {
		return out, e
	}
	for _, p := range c.Nodes {
		item := MigrationTarget{NodeID: p.ID, Reason: "NODE_NOT_READY"}
		switch {
		case p.ID == v.NodeID:
			item.Reason = "CURRENT_NODE"
		case v.Resources.NetworkType != "normal":
			item.Reason = "NETWORK_MIGRATION_UNSUPPORTED"
		case c.directRequired(v.NodeID) && b.IsZero():
			item.Reason = "PUBLIC_ADOPTION_REQUIRED"
		case v.State != "shutoff":
			item.Reason = "SOURCE_NOT_SHUTOFF"
		default:
			if e = publicInstanceIdleTx(ctx, tx, v.ID); e != nil {
				item.Reason = "MIGRATION_IN_PROGRESS"
				break
			}
			var profile string
			var maintenance bool
			var seen sql.NullTime
			var raw []byte
			var cpu, mem, disk, rc, rm, rd int64
			e = tx.QueryRowContext(ctx, "SELECT profile_sha256,maintenance,heartbeat_at,free_cpu,free_memory_mib,free_disk_gib,capabilities FROM controller_nodes WHERE id=?", p.ID).Scan(&profile, &maintenance, &seen, &cpu, &mem, &disk, &raw)
			if e != nil {
				break
			}
			var caps Capability
			if profile != p.Digest() || maintenance || !seen.Valid || !heartbeatFresh(&seen.Time, now, time.Duration(c.HeartbeatTTLSeconds)*time.Second) || !strict(raw, &caps) || len(caps.StorageIDs) != 1 {
				break
			}
			resources := v.Resources
			resources.ComputeNodeID = p.ID
			resources.DatacenterID = p.DatacenterID
			resources.NodeGroupID = p.GroupID
			resources.SystemStorageID = caps.StorageIDs[0]
			if !caps.Supports(resources, p) {
				break
			}
			if !b.IsZero() {
				target := b
				target.NodeID = p.ID
				target.Generation++
				resource, e := scanPublicResource(tx.QueryRowContext(ctx, "SELECT "+publicResourceColumns+" FROM controller_public_ip_resources WHERE id=?", b.LeaseID))
				if e != nil {
					return out, e
				}
				if !resourceDirectTargetApproved(c, resource, target) || !directCapabilityMatches(caps, target) {
					item.Reason = "PUBLIC_NETWORK_INCOMPATIBLE"
					break
				}
			}
			e = tx.QueryRowContext(ctx, "SELECT COALESCE(SUM(cpu),0),COALESCE(SUM(memory_mib),0),COALESCE(SUM(disk_gib),0) FROM controller_reservations WHERE node_id=? AND released=FALSE", p.ID).Scan(&rc, &rm, &rd)
			if e != nil {
				return out, e
			}
			if int64(resources.CPUCores) > cpu-rc || int64(resources.MemoryMiB) > mem-rm || int64(resources.SystemDiskGiB) > disk-rd {
				item.Reason = "CAPACITY_UNAVAILABLE"
				break
			}
			item.Eligible = true
			item.Reason = ""
		}
		out.Items = append(out.Items, item)
	}
	return out, tx.Commit()
}

package control

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"database/sql"
)

// Preserve guest identity across placement, detach and a newly allocated lease.
// The node still proves exact live IP/MAC before any adoption is acknowledged.
func directAdoptionIdentityTx(ctx context.Context, tx *sql.Tx, v Instance, r PublicIPResource, b nodeproto.DirectPublicBinding) (nodeproto.DirectPublicBinding, error) {
	rows, e := tx.QueryContext(ctx, "SELECT "+publicBindingColumns+" FROM controller_public_ip_bindings WHERE instance_id=? OR previous_instance_id=? ORDER BY resource_id,revision", v.ID, v.ID)
	if e != nil {
		return b, e
	}
	var known nodeproto.DirectPublicBinding
	var maxGeneration int64
	for rows.Next() {
		intent, e := scanPublicBinding(rows)
		if e != nil {
			rows.Close()
			return b, e
		}
		if intent.EpochID != "" {
			continue
		}
		var old nodeproto.DirectPublicBinding
		if !strictPublicIP(intent.Binding, &old) || !old.ValidIdentity() {
			rows.Close()
			return b, ErrState
		}
		if old.OwnerRef != v.OwnerRef || old.InstanceID != v.ID {
			rows.Close()
			return b, ErrState
		}
		if old.Generation > maxGeneration {
			maxGeneration = old.Generation
		}
		if old.NodeID == v.NodeID && old.IPv4 == r.Address && old.Generation >= known.Generation {
			if old.Generation == known.Generation && !known.IsZero() && old.MAC != known.MAC {
				rows.Close()
				return b, ErrState
			}
			known = old
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return b, e
	}
	if !known.IsZero() {
		b.MAC = known.MAC
	} else {
		rows, e = tx.QueryContext(ctx, "SELECT node_request FROM controller_jobs WHERE instance_id=? UNION ALL SELECT request_json FROM controller_operations WHERE instance_id=? AND action='create'", v.ID, v.ID)
		if e != nil {
			return b, e
		}
		count := 0
		for rows.Next() {
			var raw []byte
			if e = rows.Scan(&raw); e != nil {
				rows.Close()
				return b, e
			}
			original, e := nodeproto.DecodeTask(raw)
			if e != nil || original.InstanceID != v.ID || original.OwnerRef != v.OwnerRef || original.Resources.NetworkType != "normal" {
				rows.Close()
				return b, ErrState
			}
			count++
			if !original.DirectPublic.IsZero() {
				b.MAC = original.DirectPublic.MAC
			} else {
				b.MAC = nodeproto.NetworkMAC(v.NodeID, v.ID)
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return b, e
		}
		if count != 1 {
			return b, ErrState
		}
	}
	if maxGeneration >= 1<<63-1 {
		return b, ErrState
	}
	if b.Generation <= maxGeneration {
		b.Generation = maxGeneration + 1
	}
	if !b.ValidIdentity() {
		return b, ErrState
	}
	return b, nil
}

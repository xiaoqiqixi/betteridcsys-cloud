package control

import (
	"context"
	"database/sql"
	"errors"
)

type PublicIPResourceTarget struct {
	InstanceID string `json:"instance_id"`
	OwnerRef   string `json:"owner_ref"`
	NodeID     string `json:"node_id"`
	Mode       string `json:"mode"`
	VPCID      string `json:"vpc_id"`
	ClusterID  string `json:"cluster_id"`
	IPv4       string `json:"ipv4"`
	State      string `json:"state"`
}

func publicResourceTargetsTx(ctx context.Context, tx *sql.Tx, c Config) ([]PublicIPResourceTarget, error) {
	rows, e := tx.QueryContext(ctx, "SELECT id,owner_ref,node_id,hostname,state,resources,created_at,updated_at FROM controller_instances WHERE state IN ('created','running','shutoff') ORDER BY id LIMIT 4097")
	if e != nil {
		return nil, e
	}
	instances := []Instance{}
	for rows.Next() {
		v, e := scanInstance(rows)
		if e != nil {
			rows.Close()
			return nil, e
		}
		instances = append(instances, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	if len(instances) > 4096 {
		return nil, ErrCapacity
	}
	out := []PublicIPResourceTarget{}
	for _, v := range instances {
		if v.Resources.NetworkType == "normal" {
			for _, p := range c.DirectPublicProfiles {
				if p.NodeID == v.NodeID {
					ip := ""
					b, e := instanceDirectPublicTx(ctx, tx, v)
					if e != nil {
						return nil, e
					}
					if !b.IsZero() {
						ip = b.IPv4
					}
					out = append(out, PublicIPResourceTarget{v.ID, v.OwnerRef, v.NodeID, "direct", "", p.ClusterID, ip, v.State})
				}
			}
			continue
		}
		var cluster, vpc string
		e := tx.QueryRowContext(ctx, "SELECT cluster_id,vpc_id FROM controller_overlay_members WHERE instance_id=?", v.ID).Scan(&cluster, &vpc)
		if errors.Is(e, sql.ErrNoRows) {
			continue
		}
		if e != nil {
			return nil, e
		}
		binding, e := instanceNetworkBinding(ctx, tx, v)
		if e != nil {
			return nil, e
		}
		out = append(out, PublicIPResourceTarget{v.ID, v.OwnerRef, v.NodeID, "floating", vpc, cluster, binding.IPv4, v.State})
	}
	return out, nil
}

package control

import (
	"aster/cloud/internal/nodeproto"
	"context"
	"database/sql"
	"time"
)

// Reserve growth in the intent transaction. A shrink cannot release the old
// allocation until the node confirms it; uncertainty must retain both outcomes.
func reserveResizeTx(ctx context.Context, tx *sql.Tx, c Config, v Instance, op string, in OperationInput, now time.Time) error {
	if _, err := serviceCapability(ctx, tx, c, v.NodeID, now); err != nil {
		return err
	}
	p := in.Guest.Params
	if p.DiskGB < v.Resources.SystemDiskGiB {
		return ErrInput
	}
	cpu := max(0, p.CPUCores-v.Resources.CPUCores)
	mem := max(0, p.MemoryMB-v.Resources.MemoryMiB)
	disk := max(0, p.DiskGB-v.Resources.SystemDiskGiB)
	var freeCPU, freeMem, freeDisk, reservedCPU, reservedMem, reservedDisk int64
	if err := tx.QueryRowContext(ctx, "SELECT free_cpu,free_memory_mib,free_disk_gib FROM controller_nodes WHERE id=?", v.NodeID).Scan(&freeCPU, &freeMem, &freeDisk); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, "SELECT COALESCE(SUM(cpu),0),COALESCE(SUM(memory_mib),0),COALESCE(SUM(disk_gib),0) FROM controller_reservations WHERE node_id=? AND released=FALSE", v.NodeID).Scan(&reservedCPU, &reservedMem, &reservedDisk); err != nil {
		return err
	}
	if cpu > 0 && int64(cpu) > freeCPU-reservedCPU || mem > 0 && int64(mem) > freeMem-reservedMem || disk > 0 && int64(disk) > freeDisk-reservedDisk {
		return ErrCapacity
	}
	_, err := tx.ExecContext(ctx, "INSERT INTO controller_reservations(operation_id,node_id,cpu,memory_mib,disk_gib,released,created_at) VALUES(?,?,?,?,?,FALSE,?)", op, v.NodeID, cpu, mem, disk, now)
	return err
}

// Every allocation lineage is retained on its own node during migration. Only
// release the requested instance/node, including completed resize reservations.
func releaseInstanceReservationsTx(ctx context.Context, tx *sql.Tx, instance, node string) error {
	_, err := tx.ExecContext(ctx, "UPDATE controller_reservations SET released=TRUE WHERE node_id=? AND (operation_id IN (SELECT operation_id FROM controller_jobs WHERE instance_id=?) OR operation_id IN (SELECT id FROM controller_operations WHERE instance_id=? AND node_id=? AND action IN ('create','resize') AND state='succeeded') OR operation_id IN (SELECT source_operation_id FROM controller_migrations WHERE instance_id=? AND target_node_id=?))", node, instance, instance, node, instance, node)
	return err
}

func completeResizeReservationTx(ctx context.Context, tx *sql.Tx, o Operation, t nodeproto.NodeTask, now time.Time) error {
	if err := releaseInstanceReservationsTx(ctx, tx, o.InstanceID, o.NodeID); err != nil {
		return err
	}
	// Upsert also reconciles a successful resize admitted before this accounting
	// rule was deployed. Replays return before here and never reserve twice.
	p := t.Guest.Params
	_, err := tx.ExecContext(ctx, "INSERT INTO controller_reservations(operation_id,node_id,cpu,memory_mib,disk_gib,released,created_at) VALUES(?,?,?,?,?,FALSE,?) ON DUPLICATE KEY UPDATE cpu=VALUES(cpu),memory_mib=VALUES(memory_mib),disk_gib=VALUES(disk_gib),released=FALSE", o.ID, o.NodeID, p.CPUCores, p.MemoryMB, p.DiskGB, now)
	return err
}

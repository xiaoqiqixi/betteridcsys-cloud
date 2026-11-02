package hypervisor

// allocation includes both possible outcomes of every unfinished resize. The
// instance record can still contain the old sizes after disk growth, or the new
// sizes before a failed domain redefinition. Neither is sufficient on its own.
// Read the intent and instances under one lock so restart and heartbeat use the
// same conservative reservation as create and resize admission.
func (l *Ledger) allocation(exclude string) (cpu, memory, disk int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	reserved := make(map[string][3]int, len(l.state.Instances))
	for id, i := range l.state.Instances {
		if id != exclude && i.State != "deleted" && !i.PublicRetired {
			reserved[id] = [3]int{i.Resources.CPUCores, i.Resources.MemoryMiB, i.Resources.SystemDiskGiB}
		}
	}
	for _, op := range l.state.Operations {
		if op.Task.Action != "resize" || op.Result.Status == "succeeded" || op.Result.Status == "rejected" {
			continue
		}
		id := op.Task.InstanceID
		if r, ok := reserved[id]; ok {
			old, next := op.Task.Resources, op.Task.Guest.Params
			r[0] = max(r[0], old.CPUCores, next.CPUCores)
			r[1] = max(r[1], old.MemoryMiB, next.MemoryMB)
			r[2] = max(r[2], old.SystemDiskGiB, next.DiskGB)
			reserved[id] = r
		}
	}
	for _, r := range reserved {
		cpu += r[0]
		memory += r[1]
		disk += r[2]
	}
	return
}

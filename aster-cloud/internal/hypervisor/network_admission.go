package hypervisor

// A failed same-bridge operation is a profile fence, not merely a per-instance
// fence. Reject peers before reserve/uncertain state so an OVS outage does not
// manufacture a second ambiguous VM operation and a circular recovery block.
func (l *Ledger) HasPendingNetworkProfile(profile, except string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for id, op := range l.state.Operations {
		if id != except && op.Task.Network.ProfileID == profile && (op.Result.Status == "accepted" || op.Result.Status == "uncertain") {
			return true
		}
	}
	for _, op := range l.state.StorageOperations {
		if (op.Result.Status == "accepted" || op.Result.Status == "uncertain") && l.state.Instances[op.Task.InstanceID].Network.ProfileID == profile {
			return true
		}
	}
	return false
}

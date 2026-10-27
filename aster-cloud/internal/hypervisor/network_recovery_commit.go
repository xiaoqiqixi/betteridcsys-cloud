package hypervisor

import (
	"aster/cloud/internal/nodeproto"
	"errors"
	"strings"
)

// NetworkRecoveryCommit binds a NEW recovery to its durable root-private approval
// and result documents. It is saved in the same atomic node journal transaction
// as all recovered operations, not inferred from their pre-existing success.
// It is historical evidence only, never a permit to start/resume a guest.
type NetworkRecoveryCommit struct {
	OperationID   string `json:"operation_id"`
	ProfileID     string `json:"profile_id"`
	RequestSHA256 string `json:"request_sha256"`
	IntentSHA256  string `json:"intent_sha256"`
	ResultSHA256  string `json:"result_sha256"`
}

type networkRecoveryRecord struct {
	Commit                   NetworkRecoveryCommit  `json:"commit"`
	OriginalOperationsSHA256 string                 `json:"original_operations_sha256"`
	Outcomes                 []nodeproto.NodeResult `json:"outcomes"`
}

func (c NetworkRecoveryCommit) valid() bool {
	return nodeproto.ValidID(c.OperationID) && nodeproto.ValidNodeID(c.ProfileID) && hashString(c.RequestSHA256) && hashString(c.IntentSHA256) && hashString(c.ResultSHA256)
}

// NetworkRecoveryCommitted must be checked after reading and hashing the actual
// approval/result evidence. A poisoned live ledger cannot acknowledge a save it
// reported as uncertain. Reopening may find a complete atomic disk transaction;
// that proves historical completion only and never bypasses fresh live checks.
func (l *Ledger) NetworkRecoveryCommitted(c NetworkRecoveryCommit) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.poisoned || !c.valid() {
		return false
	}
	r, ok := l.state.NetworkRecoveries[c.OperationID]
	return ok && r.Commit == c
}

func (l *Ledger) validateNetworkRecoveries() error {
	// Schema 4 is deliberately incompatible with an older binary: it must not
	// silently ignore these receipts and rewrite away a completed recovery.
	if l.state.Schema < 4 && len(l.state.NetworkRecoveries) != 0 || l.state.Schema == 4 && len(l.state.NetworkRecoveries) == 0 {
		return errors.New("invalid recovery journal schema")
	}
	// The existing byte bound is authoritative; there is no 64-change lifetime
	// counter, truncation, or receipt eviction. This is an allocation sanity bound.
	if len(l.state.NetworkRecoveries) > maxJournalBytes/64 {
		return errors.New("invalid recovery receipt count")
	}
	for id, r := range l.state.NetworkRecoveries {
		if !r.Commit.valid() || r.Commit.OperationID != id || !hashString(r.OriginalOperationsSHA256) || r.Outcomes == nil || len(r.Outcomes) > 128 {
			return errors.New("invalid recovery receipt")
		}
		if _, collision := l.state.Operations[id]; collision {
			return errors.New("recovery operation ID collision")
		}
		if _, collision := l.state.StorageOperations[id]; collision {
			return errors.New("recovery storage ID collision")
		}
		previous := ""
		for _, result := range r.Outcomes {
			op, ok := l.state.Operations[result.OperationID]
			if !ok || result.OperationID <= previous || result.Status != "succeeded" || result != op.Result || op.Task.Network.IsZero() || op.Task.Network.ProfileID != r.Commit.ProfileID {
				return errors.New("invalid recovery outcome")
			}
			previous = result.OperationID
		}
	}
	for _, op := range l.state.Operations {
		const prefix = "EXPLICIT_NETWORK_RECOVERY_"
		if !strings.HasPrefix(op.ErrorCode, prefix) {
			continue
		}
		id := strings.TrimPrefix(op.ErrorCode, prefix)
		r, exists := l.state.NetworkRecoveries[id]
		found := false
		for _, outcome := range r.Outcomes {
			if outcome == op.Result {
				found = true
			}
		}
		if !exists || !found || op.Result.Status != "succeeded" {
			return errors.New("recovered operation lacks atomic completion")
		}
	}
	return nil
}

// Missing immutable intent is not permission to reuse a committed recovery ID.
func (l *Ledger) networkRecoveryIDAvailable(id string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.poisoned || !nodeproto.ValidID(id) {
		return ErrOwnership
	}
	if _, exists := l.state.NetworkRecoveries[id]; exists {
		return ErrConflict
	}
	if _, exists := l.state.Operations[id]; exists {
		return ErrConflict
	}
	if _, exists := l.state.StorageOperations[id]; exists {
		return ErrConflict
	}
	return nil
}

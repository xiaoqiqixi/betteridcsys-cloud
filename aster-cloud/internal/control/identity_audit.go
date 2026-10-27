package control

import (
	"aster/cloud/internal/identity"
	"context"
	"encoding/hex"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Only the already bounded, authorized audit page is enriched. Never fetch an
// entire history or reveal credentials/public request blobs through audit DTOs.
func (s *SQLStore) attachIdentityAuditDetails(ctx context.Context, page []ConsoleAudit) error {
	positions := map[int64]int{}
	args := []any{}
	marks := []string{}
	for i, v := range page {
		if v.Source == "identity" && (v.Action == "identity.user_created" || v.Action == "identity.user_updated" || v.Action == "identity.sessions_revoked") {
			positions[v.ID] = i
			args = append(args, v.ID)
			marks = append(marks, "?")
		}
	}
	if len(args) == 0 {
		return nil
	}
	rows, e := s.DB.QueryContext(ctx, "SELECT audit_id,operation_id,actor_id,target_id,action,base_revision,result_revision,reason FROM controller_identity_operations WHERE audit_id IN ("+strings.Join(marks, ",")+")", args...)
	if e != nil {
		return e
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var actor, target, action string
		var v IdentityAuditDetail
		if e = rows.Scan(&id, &v.OperationID, &actor, &target, &action, &v.BaseRevision, &v.ResultRevision, &v.Reason); e != nil {
			return e
		}
		i, ok := positions[id]
		if !ok || page[i].Actor != actor || page[i].Target != target || page[i].Action != action {
			return identity.ErrStoredState
		}
		decoded, idErr := hex.DecodeString(v.OperationID)
		validReason := utf8.ValidString(v.Reason) && v.Reason != "" && strings.TrimSpace(v.Reason) == v.Reason && utf8.RuneCountInString(v.Reason) <= 500
		for _, r := range v.Reason {
			if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
				validReason = false
			}
		}
		if idErr != nil || len(decoded) != 16 || strings.ToLower(v.OperationID) != v.OperationID || v.ResultRevision < 1 || v.ResultRevision > 9007199254740991 || v.ResultRevision != v.BaseRevision+1 || !validReason {
			return identity.ErrStoredState
		}
		page[i].IdentityDetail = &v
	}
	return rows.Err()
}

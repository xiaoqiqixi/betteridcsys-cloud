package control

import (
	"bytes"
	"encoding/json"
)

// nil pointer is omitted/preserve; null is not a valid substitute. Explicit []
// is a different intent that clears the previous policies and hashes differently.
func rejectsNullNAT(raw []byte) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return true
	}
	v, exists := fields["nat_policies"]
	if exists && bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
		return true
	}
	v, exists = fields["floating_ips"]
	return exists && bytes.Equal(bytes.TrimSpace(v), []byte("null"))
}
func (in *OverlayEpochInput) UnmarshalJSON(raw []byte) error {
	type wire OverlayEpochInput
	var value wire
	if rejectsNullNAT(raw) || !strict(raw, &value) {
		return ErrInput
	}
	*in = OverlayEpochInput(value)
	return nil
}
func (in *OverlayReplacementInput) UnmarshalJSON(raw []byte) error {
	type wire OverlayReplacementInput
	var value wire
	if rejectsNullNAT(raw) || !strict(raw, &value) {
		return ErrInput
	}
	*in = OverlayReplacementInput(value)
	return nil
}

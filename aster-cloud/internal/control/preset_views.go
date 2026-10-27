package control

import "aster/billing/controllerapi"

// Root approval selectors are not a new browser-editable DTO. Keep the existing
// three-field preset projection when private configuration gains policy fields.
type presetView struct {
	ID                   string                  `json:"id"`
	NodeID               string                  `json:"node_id"`
	Resources            controllerapi.Resources `json:"resources"`
	DirectPublicRequired bool                    `json:"direct_public_required,omitempty"`
}

func publicPresets(presets []Preset) []presetView {
	out := make([]presetView, len(presets))
	for i, p := range presets {
		out[i] = presetView{ID: p.ID, NodeID: p.NodeID, Resources: p.Resources}
	}
	return out
}

func publicPresetsWithConfig(c Config) []presetView {
	out := publicPresets(c.Presets)
	for i := range out {
		out[i].DirectPublicRequired = c.directRequired(out[i].NodeID) && out[i].Resources.NetworkType == "normal"
	}
	return out
}

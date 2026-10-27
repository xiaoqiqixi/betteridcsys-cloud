package control

import (
	"aster/cloud/internal/overlayproto"
	"encoding/json"
	"time"
)

const maxPublicIngressRevision uint64 = 9007199254740991

type PublicIngressInput struct {
	ExpectedRevision *uint64                          `json:"expected_revision"`
	Rules            []overlayproto.PublicIngressRule `json:"rules"`
}
type PublicIngressView struct {
	Schema             int                              `json:"schema"`
	InstanceID         string                           `json:"instance_id"`
	OwnerRef           string                           `json:"owner_ref"`
	Revision           uint64                           `json:"revision"`
	SHA256             string                           `json:"sha256"`
	Rules              []overlayproto.PublicIngressRule `json:"rules"`
	EffectiveRevision  *uint64                          `json:"effective_revision"`
	State              string                           `json:"state"`
	EpochID            string                           `json:"epoch_id"`
	OperationID        string                           `json:"operation_id"`
	BoundResourceID    string                           `json:"bound_resource_id"`
	LegacyUnrestricted bool                             `json:"legacy_unrestricted"`
	Supported          bool                             `json:"supported"`
	UnsupportedReason  string                           `json:"unsupported_reason"`
	UpdatedAt          *time.Time                       `json:"updated_at"`
}
type PublicIngressOperation struct {
	ID               string              `json:"id"`
	ActorID          string              `json:"actor_id"`
	Action           string              `json:"action"`
	TargetInstanceID string              `json:"target_instance_id"`
	RequestSHA256    string              `json:"request_sha256"`
	Request          json.RawMessage     `json:"request"`
	Result           PublicIngressResult `json:"result"`
	CreatedAt        time.Time           `json:"created_at"`
}
type PublicIngressResult struct {
	Policy PublicIngressView `json:"policy"`
}
type publicIngressVersion struct {
	Policy               overlayproto.PublicIngressPolicy
	OperationID, EpochID string
	CreatedAt            time.Time
}

func publicIngressWire(v PublicIngressView) overlayproto.PublicIngressPolicy {
	return overlayproto.PublicIngressPolicy{Schema: v.Schema, InstanceID: v.InstanceID, OwnerRef: v.OwnerRef, Revision: v.Revision, SHA256: v.SHA256, Rules: v.Rules}
}
func publicIngressView(p overlayproto.PublicIngressPolicy) PublicIngressView {
	return PublicIngressView{Schema: p.Schema, InstanceID: p.InstanceID, OwnerRef: p.OwnerRef, Revision: p.Revision, SHA256: p.SHA256, Rules: p.Rules, State: "default"}
}

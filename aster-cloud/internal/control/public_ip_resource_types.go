package control

import (
	"bytes"
	"encoding/json"
	"time"
)

// VM public resources never change the original NAT lease/result contract.
type PublicIPResourceInput struct {
	PoolID    string `json:"pool_id"`
	OwnerRef  string `json:"owner_ref"`
	Mode      string `json:"mode"`
	NodeID    string `json:"node_id"`
	ProfileID string `json:"profile_id"`
	VPCID     string `json:"vpc_id"`
	Address   string `json:"address"`
}
type PublicIPResource struct {
	ID                string    `json:"id"`
	ClusterID         string    `json:"cluster_id"`
	PoolID            string    `json:"pool_id"`
	OwnerRef          string    `json:"owner_ref"`
	Mode              string    `json:"mode"`
	NodeID            string    `json:"node_id"`
	ProfileID         string    `json:"profile_id"`
	VPCID             string    `json:"vpc_id"`
	Address           string    `json:"address"`
	State             string    `json:"state"`
	BindingState      string    `json:"binding_state"`
	BindingGeneration uint64    `json:"binding_generation"`
	InstanceID        string    `json:"instance_id"`
	EpochID           string    `json:"epoch_id"`
	OperationID       string    `json:"operation_id"`
	Releasable        bool      `json:"releasable"`
	ReleaseReason     string    `json:"release_reason"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}
type PublicIPResourceOperation struct {
	ID               string                 `json:"id"`
	ActorID          string                 `json:"actor_id"`
	Action           string                 `json:"action"`
	TargetResourceID string                 `json:"target_resource_id"`
	ResourceID       string                 `json:"resource_id"`
	RequestSHA256    string                 `json:"request_sha256"`
	Request          json.RawMessage        `json:"request"`
	Result           PublicIPResourceResult `json:"result"`
	CreatedAt        time.Time              `json:"created_at"`
}
type PublicIPResourceResult struct {
	Resource PublicIPResource `json:"resource"`
}
type PublicIPBindingIntent struct {
	Generation         uint64          `json:"binding_generation"`
	ID                 string          `json:"id"`
	ResourceID         string          `json:"resource_id"`
	Revision           int64           `json:"revision"`
	Action             string          `json:"action"`
	InstanceID         string          `json:"instance_id"`
	PreviousInstanceID string          `json:"previous_instance_id"`
	EpochID            string          `json:"epoch_id"`
	RequestSHA256      string          `json:"request_sha256"`
	Binding            json.RawMessage `json:"binding"`
	CreatedAt          time.Time       `json:"created_at"`
}

// DirectPublicProfile is a root-only safe projection of the node's approved
// dedicated normal bridge. HTTP callers never select a bridge or host path.
type DirectPublicProfile struct {
	ClusterID     string   `json:"cluster_id"`
	NodeID        string   `json:"node_id"`
	ProfileID     string   `json:"profile_id"`
	ProfileSHA256 string   `json:"profile_sha256"`
	CIDR          string   `json:"cidr"`
	GatewayIPv4   string   `json:"gateway_ipv4"`
	PublicIPv4s   []string `json:"public_ipv4s"`
}

// Missing ingress revision is retained only for revision-zero legacy bind bodies.
// Explicit null is not a second spelling of an absent field.
type publicResourceBindingInput struct {
	InstanceID              string  `json:"instance_id"`
	ExpectedGeneration      *uint64 `json:"expected_generation"`
	ExpectedIngressRevision *uint64 `json:"expected_ingress_revision,omitempty"`
}

func (in *publicResourceBindingInput) UnmarshalJSON(raw []byte) error {
	type wire publicResourceBindingInput
	var v wire
	if !strictPublicIP(raw, &v) {
		return ErrInput
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return ErrInput
	}
	if r, ok := fields["expected_ingress_revision"]; ok && bytes.Equal(bytes.TrimSpace(r), []byte("null")) {
		return ErrInput
	}
	*in = publicResourceBindingInput(v)
	return nil
}

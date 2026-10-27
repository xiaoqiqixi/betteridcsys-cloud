package control

import (
	"encoding/json"
	"time"
)

type PublicIPPoolInput struct {
	ClusterID string   `json:"cluster_id"`
	Name      string   `json:"name"`
	CIDR      string   `json:"cidr"`
	Addresses []string `json:"addresses"`
	Enabled   bool     `json:"enabled"`
}
type PublicIPPool struct {
	ID        string    `json:"id"`
	ClusterID string    `json:"cluster_id"`
	Name      string    `json:"name"`
	CIDR      string    `json:"cidr"`
	Addresses []string  `json:"addresses"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
type PublicIPLeaseInput struct {
	PoolID    string `json:"pool_id"`
	OwnerRef  string `json:"owner_ref"`
	VPCID     string `json:"vpc_id"`
	NodeID    string `json:"node_id"`
	ProfileID string `json:"profile_id"`
	Address   string `json:"address"`
}
type PublicIPLease struct {
	ID            string    `json:"id"`
	ClusterID     string    `json:"cluster_id"`
	PoolID        string    `json:"pool_id"`
	OwnerRef      string    `json:"owner_ref"`
	VPCID         string    `json:"vpc_id"`
	NodeID        string    `json:"node_id"`
	ProfileID     string    `json:"profile_id"`
	Address       string    `json:"address"`
	State         string    `json:"state"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	BindingState  string    `json:"binding_state"`
	Releasable    bool      `json:"releasable"`
	ReleaseReason string    `json:"release_reason"`
}
type PublicIPResult struct {
	Pool  *PublicIPPool  `json:"pool,omitempty"`
	Lease *PublicIPLease `json:"lease,omitempty"`
}
type PublicIPOperation struct {
	ID               string          `json:"id"`
	ActorID          string          `json:"actor_id"`
	Action           string          `json:"action"`
	TargetResourceID string          `json:"target_resource_id"`
	ResourceID       string          `json:"resource_id"`
	RequestSHA256    string          `json:"request_sha256"`
	Request          json.RawMessage `json:"request"`
	Result           PublicIPResult  `json:"result"`
	CreatedAt        time.Time       `json:"created_at"`
}
type PublicIPApproval struct {
	ClusterID           string   `json:"cluster_id"`
	NodeID              string   `json:"node_id"`
	VPCID               string   `json:"vpc_id"`
	OwnerRef            string   `json:"owner_ref"`
	ProfileID           string   `json:"profile_id"`
	ProfileSHA256       string   `json:"profile_sha256"`
	PublicIPv4s         []string `json:"public_ipv4s"`
	AllowInternetEgress bool     `json:"allow_internet_egress"`
	AllowFloatingIP     bool     `json:"allow_floating_ip"`
}
type PublicIPClusterOption struct {
	ID string `json:"id"`
}
type PublicIPOptions struct {
	ResourceTargets []PublicIPResourceTarget `json:"resource_targets"`
	DirectApprovals []DirectPublicProfile    `json:"direct_approvals"`
	Clusters        []PublicIPClusterOption  `json:"clusters"`
	Approvals       []PublicIPApproval       `json:"approvals"`
	VPCs            []OverlayVPC             `json:"vpcs"`
	Complete        bool                     `json:"complete"`
}

package control

import (
	"aster/billing/controllerapi"
	"aster/cloud/internal/nodeproto"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

var (
	ErrInput       = errors.New("invalid input")
	ErrConflict    = errors.New("request binding conflict")
	ErrNotFound    = errors.New("not found")
	ErrCapacity    = errors.New("no approved healthy node capacity")
	ErrState       = errors.New("operation state does not permit dispatch")
	ErrUnavailable = errors.New("controller dependency unavailable")
)

type Capability nodeproto.Capabilities

// Legacy support remains unchanged. VPC support requires an independently
// approved profile and explicit positive ingress/egress limits.
func (c Capability) Supports(r controllerapi.Resources, node NodeProfile) bool {
	return c.SupportsNetwork(r, node, "")
}
func vpcResources(r controllerapi.Resources) bool {
	return r.NetworkType == "vpc" && r.IPv4Count == 1 && r.IPv6Count == 0 && r.BandwidthMbps >= 1 && r.BandwidthMbps <= 100000 && r.InboundBandwidthMbps >= 1 && r.InboundBandwidthMbps <= 100000 && r.TransferGiB == 0 && r.TrafficDirection == "all"
}

func (c Capability) SupportsNetwork(r controllerapi.Resources, node NodeProfile, profileID string) bool {
	spec := controllerapi.ProductSpec{Mode: "custom", ControllerID: "check", Resources: &r}
	base := spec.Valid() && c.Protocol == nodeproto.Protocol && c.NodeID == node.ID && !c.Maintenance && c.Hypervisor == "libvirt-kvm" &&
		r.ComputeNodeID == node.ID && r.DatacenterID == node.DatacenterID && r.NodeGroupID == node.GroupID &&
		contains(c.ImageIDs, r.ImageID) && contains(c.StorageIDs, r.SystemStorageID) && r.DataDiskGiB == 0 && r.DataStorageID == "" && contains(c.Actions, "create")
	if !base || !c.validNetworkCapabilities() {
		return false
	}
	if profileID != "" {
		return vpcResources(r) && contains(c.NetworkProfiles, nodeproto.OVSNetworkCapability) && contains(c.OVSNetworkProfiles, profileID) && containsInt(c.IPv4Counts, 1) && containsInt(c.IPv6Counts, 0)
	}
	return r.NetworkType == "normal" && r.IPv4Count == 1 && r.IPv6Count == 0 && contains(c.NetworkProfiles, "normal-static-ipv4-dedicated-bridge") && r.BandwidthMbps == 0 && r.InboundBandwidthMbps == 0 && r.TransferGiB == 0 &&
		r.TrafficDirection == "all" && containsInt(c.IPv4Counts, r.IPv4Count) && containsInt(c.IPv6Counts, r.IPv6Count) &&
		containsInt(c.BandwidthMbps, 0) && containsInt(c.TransferGiB, 0) && contains(c.Actions, "create")
}

func (c Capability) validNetworkCapabilities() bool {
	// Feature markers are positive capabilities, not free-form execution hints.
	// A duplicate marker cannot strengthen a claim or hide an invalid OVS set.
	markers := map[string]bool{}
	for _, feature := range c.NetworkProfiles {
		if markers[feature] {
			return false
		}
		markers[feature] = true
	}
	if markers[nodeproto.PublicIngressCapability] && (!markers[nodeproto.OVSNetworkCapability] || len(c.OVSNetworkProfiles) == 0) {
		return false
	}
	if (c.DirectPublicNetwork != nil) != contains(c.NetworkProfiles, nodeproto.DirectPublicCapability) {
		return false
	}
	if p := c.DirectPublicNetwork; p != nil {
		if len(p.Addresses) < 1 || len(p.Addresses) > 4096 {
			return false
		}
		seen := map[string]bool{}
		for _, a := range p.Addresses {
			b := nodeproto.DirectPublicBinding{Schema: 1, Generation: 1, LeaseID: strings.Repeat("1", 32), PoolID: strings.Repeat("2", 32), NodeID: c.NodeID, OwnerRef: strings.Repeat("3", 32), InstanceID: strings.Repeat("4", 32), ProfileID: p.ProfileID, ProfileSHA256: p.ProfileSHA256, CIDR: p.CIDR, Gateway: p.Gateway, IPv4: a, MAC: "52:54:00:00:00:01"}
			if !b.ValidIdentity() || seen[a] {
				return false
			}
			seen[a] = true
		}
	}

	if len(c.OVSNetworkProfiles) > 256 || (len(c.OVSNetworkProfiles) > 0) != contains(c.NetworkProfiles, nodeproto.OVSNetworkCapability) {
		return false
	}
	seen := map[string]bool{}
	for _, profile := range c.OVSNetworkProfiles {
		if !nodeproto.ValidNodeID(profile) || seen[profile] {
			return false
		}
		seen[profile] = true
	}
	return true
}
func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
func containsInt(xs []int, s int) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
func id() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("secure random unavailable")
	}
	return hex.EncodeToString(b[:])
}

type OverlayAdmission struct {
	ControllerID string
	Cluster      OverlayCluster
	Nodes        []NodeProfile
	// RootClusters is controller-local admission context, never part of the
	// financial request, node task, network binding or persisted snapshot.
	// Public IP isolation must resolve legacy NAT in every approved cluster.
	RootClusters        []OverlayCluster `json:"-"`
	HeartbeatTTLSeconds int              `json:"-"`
}
type Candidate struct {
	DirectPublicRequired bool
	Overlay              *OverlayAdmission
	Node                 NodeProfile
	ProfileSHA           string
	Resources            controllerapi.Resources
	NetworkProfileID     string
	NetworkPoolID        string
	NetworkProfileSHA    string
	NetworkOwnerRef      string
}
type Job struct {
	OperationID    string    `json:"operation_id"`
	OrderID        string    `json:"order_id"`
	ControllerID   string    `json:"controller_id"`
	RequestSHA     string    `json:"request_sha256"`
	RequestJSON    []byte    `json:"-"`
	InstanceID     string    `json:"instance_id"`
	NodeID         string    `json:"node_id"`
	NodeProfileSHA string    `json:"-"`
	NodeRequestSHA string    `json:"-"`
	NodeRequest    []byte    `json:"-"`
	State          string    `json:"state"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

func (j Job) Result() controllerapi.Result {
	state, resource := "accepted", j.InstanceID
	if j.State == "succeeded" {
		state = "succeeded"
	}
	if j.State == "rejected" {
		state = "rejected"
		resource = ""
	}
	return controllerapi.Result{Protocol: controllerapi.Protocol, OperationID: j.OperationID, OrderID: j.OrderID, RequestSHA256: j.RequestSHA, Status: state, ResourceID: resource}
}

type NodeView struct {
	Online            bool       `json:"online"`
	ID                string     `json:"id"`
	DatacenterID      string     `json:"datacenter_id"`
	Maintenance       bool       `json:"maintenance"`
	HeartbeatAt       *time.Time `json:"heartbeat_at"`
	FreeCPU           int64      `json:"free_cpu"`
	FreeMemoryMiB     int64      `json:"free_memory_mib"`
	FreeDiskGiB       int64      `json:"free_disk_gib"`
	ReservedCPU       int64      `json:"reserved_cpu"`
	ReservedMemoryMiB int64      `json:"reserved_memory_mib"`
	ReservedDiskGiB   int64      `json:"reserved_disk_gib"`
}
type Instance struct {
	ID        string                  `json:"id"`
	OwnerRef  string                  `json:"owner_ref"`
	NodeID    string                  `json:"node_id"`
	Hostname  string                  `json:"hostname"`
	State     string                  `json:"state"`
	Resources controllerapi.Resources `json:"resources"`
	CreatedAt time.Time               `json:"created_at"`
	UpdatedAt time.Time               `json:"updated_at"`
}
type Audit struct {
	ID        int64     `json:"id"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Target    string    `json:"target"`
	CreatedAt time.Time `json:"created_at"`
}

type Store interface {
	Ping(context.Context) error
	Admit(context.Context, controllerapi.Request, []Candidate, time.Time, time.Duration) (Job, bool, error)
	Lookup(context.Context, string) (Job, error)
	Claim(context.Context, string, string, time.Time, time.Duration) (Job, error)
	Complete(context.Context, string, string, time.Time) (Job, error)
	Nodes(context.Context) ([]NodeView, error)
	Instances(context.Context) ([]Instance, error)
	Jobs(context.Context) ([]Job, error)
	Audits(context.Context) ([]Audit, error)
}

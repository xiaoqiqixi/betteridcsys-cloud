package nodeproto

type Capacity struct {
	CPUCoresTotal       int   `json:"cpu_cores_total"`
	CPUCoresAllocated   int   `json:"cpu_cores_allocated"`
	MemoryTotalMiB      int64 `json:"memory_total_mib"`
	MemoryAvailableMiB  int64 `json:"memory_available_mib"`
	MemoryAllocatedMiB  int64 `json:"memory_allocated_mib"`
	StorageTotalGiB     int64 `json:"storage_total_gib"`
	StorageAvailableGiB int64 `json:"storage_available_gib"`
	StorageAllocatedGiB int64 `json:"storage_allocated_gib"`
}
type DirectPublicApproval struct {
	ProfileID     string   `json:"profile_id"`
	ProfileSHA256 string   `json:"profile_sha256"`
	CIDR          string   `json:"cidr"`
	Gateway       string   `json:"gateway"`
	Addresses     []string `json:"addresses"`
}
type Capabilities struct {
	DirectPublicNetwork *DirectPublicApproval `json:"direct_public_network,omitempty"`
	OVSNetworkProfiles  []string              `json:"ovs_network_profiles,omitempty"`
	Protocol            string                `json:"protocol"`
	NodeID              string                `json:"node_id"`
	Hypervisor          string                `json:"hypervisor"`
	Maintenance         bool                  `json:"maintenance"`
	ObservedAt          string                `json:"observed_at"`
	Actions             []string              `json:"actions"`
	ImageIDs            []string              `json:"image_ids"`
	StorageIDs          []string              `json:"storage_ids"`
	NetworkProfiles     []string              `json:"network_profiles"`
	IPv4Counts          []int                 `json:"ipv4_counts"`
	IPv6Counts          []int                 `json:"ipv6_counts"`
	BandwidthMbps       []int                 `json:"bandwidth_mbps"`
	TransferGiB         []int                 `json:"transfer_gib"`
	Capacity            Capacity              `json:"capacity"`
	Limitations         []string              `json:"limitations"`
}

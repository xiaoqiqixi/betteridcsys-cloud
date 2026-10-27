package hypervisor

import (
	"aster/cloud/internal/fabric"
	"aster/cloud/internal/nodeproto"
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type DoctorReport struct {
	Protocol    string        `json:"protocol"`
	NodeID      string        `json:"node_id"`
	Ready       bool          `json:"ready"`
	OS          string        `json:"os"`
	Checks      []DoctorCheck `json:"checks"`
	Limitations []string      `json:"limitations"`
}
type DoctorCheck struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
}

func HostCapacity(storage string) (nodeproto.Capacity, error) {
	var c nodeproto.Capacity
	c.CPUCoresTotal = runtime.NumCPU()
	if runtime.GOOS != "linux" {
		return c, errors.New("Linux required")
	}
	raw, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return c, err
	}
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 {
			n, _ := strconv.ParseInt(fields[1], 10, 64)
			switch fields[0] {
			case "MemTotal:":
				c.MemoryTotalMiB = n / 1024
			case "MemAvailable:":
				c.MemoryAvailableMiB = n / 1024
			}
		}
	}
	var fs syscall.Statfs_t
	if err = syscall.Statfs(storage, &fs); err != nil {
		return c, err
	}
	c.StorageTotalGiB = int64(fs.Blocks) * int64(fs.Bsize) / (1 << 30)
	c.StorageAvailableGiB = int64(fs.Bavail) * int64(fs.Bsize) / (1 << 30)
	return c, nil
}
func (m *Manager) Doctor(ctx context.Context) DoctorReport {
	report := DoctorReport{Protocol: nodeproto.Protocol, NodeID: m.Config.NodeID, Ready: true, OS: runtime.GOOS, Checks: []DoctorCheck{}, Limitations: []string{"Read-only host inspection; no package installation, bridge change, VM mutation, or guest connectivity validation.", "Ubuntu 22.04 and later are policy targets, not proof that Ubuntu 24/26 or real KVM creation were tested."}}
	add := func(name string, pass bool) {
		report.Checks = append(report.Checks, DoctorCheck{name, pass})
		if !pass {
			report.Ready = false
		}
	}
	raw, e := os.ReadFile("/etc/os-release")
	fields := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		pair := strings.SplitN(line, "=", 2)
		if len(pair) == 2 {
			fields[pair[0]] = strings.Trim(pair[1], "\"")
		}
	}
	major, _ := strconv.Atoi(strings.Split(fields["VERSION_ID"], ".")[0])
	report.OS = fields["ID"] + " " + fields["VERSION_ID"]
	add("ubuntu_at_least_22", e == nil && runtime.GOOS == "linux" && fields["ID"] == "ubuntu" && major >= 22)
	cpu, e := os.ReadFile("/proc/cpuinfo")
	add("x86_64_host", runtime.GOARCH == "amd64")
	add("hardware_virtualization_flags", e == nil && (strings.Contains(string(cpu), " vmx ") || strings.Contains(string(cpu), " svm ")))
	kvm, e := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	add("dev_kvm_read_write", e == nil)
	if e == nil {
		kvm.Close()
	}
	for _, path := range []string{Virsh, QemuImg, Emulator} {
		s, e := os.Stat(path)
		add("binary:"+path, e == nil && s.Mode().IsRegular() && s.Mode().Perm()&0111 != 0)
	}
	add("storage_directory", ownedPath(m.Config.StorageDirectory, false, true) == nil)
	_, e = m.virsh(ctx, "list", "--all", "--name")
	add("libvirt_system_readonly_query", e == nil)
	if m.Config.Network.Enabled {
		s, e := os.Stat(CloudLocalDS)
		add("cloud_localds", e == nil && s.Mode().Perm()&0111 != 0)
		add("approved_static_ipv4_bridge_filter", m.verifyNetwork(ctx) == nil)
	}
	if len(m.Config.OVSProfiles) > 0 {
		st, err := os.Stat(CloudLocalDS)
		add("ovs_cloud_localds", err == nil && st.Mode().Perm()&0111 != 0)
		ids := make([]string, 0, len(m.Config.OVSProfiles))
		for id := range m.Config.OVSProfiles {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			p := m.Config.OVSProfiles[id]
			c, err := fabric.LoadConfig(p.FabricConfig)
			if err == nil && c.NodeID == m.Config.NodeID {
				e, ee := fabric.NewExecutor(c, fabric.OSRunner{})
				if ee != nil {
					err = ee
				} else if p.OverlayConfig != "" {
					oc, oe := fabric.LoadOverlayConfig(p.OverlayConfig)
					if oe != nil || oc.Base != c {
						err = ErrUnsupported
					} else {
						head, he := fabric.ReadOverlayHead(oc)
						if he != nil {
							err = he
						} else if head.Epoch == 0 {
							err = e.Inspect(ctx)
						} else {
							_, err = e.CheckOverlay(ctx, oc)
						}
					}
				} else {
					err = e.Inspect(ctx)
				}
			} else {
				err = ErrUnsupported
			}
			add("ovs_approved_profile:"+id, err == nil)
		}
	}
	return report
}
func (m *Manager) Capabilities(ctx context.Context) nodeproto.Capabilities {
	capacity, _ := HostCapacity(m.Config.StorageDirectory)
	for _, instance := range m.Ledger.Instances() {
		if instance.State == "deleted" || instance.PublicRetired {
			continue
		}
		capacity.CPUCoresAllocated += instance.Resources.CPUCores
		capacity.MemoryAllocatedMiB += int64(instance.Resources.MemoryMiB)
		capacity.StorageAllocatedGiB += int64(instance.Resources.SystemDiskGiB)
	}
	// Advertise root allocation ceilings, not all physical host resources.
	if int64(m.Config.CPUAllocationLimit) < int64(capacity.CPUCoresTotal) {
		capacity.CPUCoresTotal = m.Config.CPUAllocationLimit
	}
	if int64(m.Config.MemoryAllocationLimitMiB) < capacity.MemoryTotalMiB {
		capacity.MemoryTotalMiB = int64(m.Config.MemoryAllocationLimitMiB)
	}
	if int64(m.Config.DiskAllocationLimitGiB) < capacity.StorageTotalGiB {
		capacity.StorageTotalGiB = int64(m.Config.DiskAllocationLimitGiB)
	}
	if capacity.MemoryAvailableMiB > 256 {
		capacity.MemoryAvailableMiB -= 256
	} else {
		capacity.MemoryAvailableMiB = 0
	}
	c := nodeproto.Capabilities{Protocol: nodeproto.Protocol, NodeID: m.Config.NodeID, Hypervisor: "libvirt-kvm", Maintenance: m.Config.Maintenance, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), Actions: []string{}, ImageIDs: []string{}, StorageIDs: []string{m.Config.StorageID}, NetworkProfiles: []string{}, IPv4Counts: []int{}, IPv6Counts: []int{0}, BandwidthMbps: []int{0}, TransferGiB: []int{0}, Capacity: capacity, Limitations: []string{"OVS requires an explicit pinned profile and node/2 immutable IPAM binding. Cross-node/gateway forwarding requires a separate root-approved overlay contract and all-node epoch barrier. No IPv6, data disks, traffic accounting or queue shaping.", "Zero bandwidth/transfer means the explicitly root-approved unmetered default, not an enforced numeric quota.", "Static IPv4 requires operator-preconfigured dedicated routed bridge and pinned anti-spoof/default-deny nwfilter; not a tenant security group or complete host network isolation.", "Succeeded create confirms libvirt domain running, not guest boot, SSH, network connectivity or billing service activation.", "Reboot completion cannot be proved without guest lifecycle evidence and is retained uncertain after the command acknowledgement."}}
	for id := range m.Config.Images {
		c.ImageIDs = append(c.ImageIDs, id)
	}
	sort.Strings(c.ImageIDs)
	if m.Config.AllowIsolatedNoNIC {
		c.NetworkProfiles = append(c.NetworkProfiles, "normal-isolated-no-nic")
		c.IPv4Counts = append(c.IPv4Counts, 0)
	}
	if m.Config.Network.Enabled {
		c.NetworkProfiles = append(c.NetworkProfiles, "normal-static-ipv4-dedicated-bridge")
		c.IPv4Counts = append(c.IPv4Counts, 1)
	}
	if len(m.Config.OVSProfiles) > 0 {
		for id := range m.Config.OVSProfiles {
			c.OVSNetworkProfiles = append(c.OVSNetworkProfiles, id)
		}
		sort.Strings(c.OVSNetworkProfiles)
		c.NetworkProfiles = append(c.NetworkProfiles, nodeproto.OVSNetworkCapability)
		if !m.Config.Network.Enabled {
			c.IPv4Counts = append(c.IPv4Counts, 1)
		}
		c.Limitations = append(c.Limitations, "Base OVS is single-host private IPv4; separately approved overlay profiles add pinned VXLAN peers and gateway allowlists. Both use per-IP drop meters; restart is explicit shutdown then start. OVS backup/restore/migration requires a future bound storage contract.")
	}
	if sha, e := DirectNetworkSHA256(m.Config.Network); e == nil {
		approved := []string{}
		hostIPs, hostErr := m.directHostIPv4s()
		hostSet := map[string]bool{}
		for _, ip := range hostIPs {
			hostSet[ip] = true
		}
		for _, ip := range m.Config.Network.Addresses {
			b := nodeproto.DirectPublicBinding{Generation: 1, Schema: 1, LeaseID: strings.Repeat("1", 32), PoolID: strings.Repeat("2", 32), NodeID: m.Config.NodeID, OwnerRef: strings.Repeat("3", 32), InstanceID: strings.Repeat("4", 32), ProfileID: nodeproto.DirectPublicProfile, ProfileSHA256: sha, CIDR: m.Config.Network.CIDR, Gateway: m.Config.Network.Gateway, IPv4: ip, MAC: "52:54:00:00:00:01"}
			if b.ValidIdentity() && hostErr == nil && !hostSet[ip] {
				approved = append(approved, ip)
			}
		}
		if len(approved) > 0 {
			c.DirectPublicNetwork = &nodeproto.DirectPublicApproval{ProfileID: nodeproto.DirectPublicProfile, ProfileSHA256: sha, CIDR: m.Config.Network.CIDR, Gateway: m.Config.Network.Gateway, Addresses: approved}
			c.NetworkProfiles = append(c.NetworkProfiles, nodeproto.DirectPublicCapability)
		}
	}
	doctor := m.Doctor(ctx)
	advertisePublicIngressCapability(&c, doctor)
	if !doctor.Ready {
		c.Maintenance = true
		c.Limitations = append(c.Limitations, "Host doctor prerequisites are incomplete; no mutation is advertised.")
	} else if !c.Maintenance {
		c.Actions = []string{"create", "start", "shutdown", "reboot", "force_off"}
		if c.DirectPublicNetwork != nil {
			c.Actions = append(c.Actions, "public_adopt", "public_detach")
		}
		if m.Config.AllowDelete {
			c.Actions = append(c.Actions, "delete")
		}
	}
	return c
}

// Advertise the new policy only after the real read-only doctor has confirmed
// the approved OVS profiles and while the node is accepting mutations. Keeping
// this as a feature in the existing array preserves legacy capability JSON.
func advertisePublicIngressCapability(c *nodeproto.Capabilities, doctor DoctorReport) {
	if !doctor.Ready || c.Maintenance || len(c.OVSNetworkProfiles) == 0 {
		return
	}
	for _, feature := range c.NetworkProfiles {
		if feature == nodeproto.PublicIngressCapability {
			return
		}
	}
	for _, feature := range c.NetworkProfiles {
		if feature == nodeproto.OVSNetworkCapability {
			c.NetworkProfiles = append(c.NetworkProfiles, nodeproto.PublicIngressCapability)
			c.Limitations = append(c.Limitations, "Public ingress policy is scoped to instance-bound floating IPv4 traffic; it is not a full VPC security group, direct-public policy, IPv6 firewall or guest firewall manager.")
			return
		}
	}
}

func FormatDoctor(report DoctorReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s node=%s ready=%v os=%s\n", report.Protocol, report.NodeID, report.Ready, report.OS)
	for _, c := range report.Checks {
		fmt.Fprintf(&b, "%v %s\n", c.Passed, c.Name)
	}
	return b.String()
}

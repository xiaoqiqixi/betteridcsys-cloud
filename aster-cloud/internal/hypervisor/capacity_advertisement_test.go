package hypervisor

import (
	"aster/cloud/internal/nodeproto"
	"testing"
)

func TestCapabilitiesKeepAvailableCapacityWithinRootLimits(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		memory, disk         int64
		wantMemory, wantDisk int64
	}{
		{"root_limits", 60000, 4000, 4096, 32},
		{"physical_free_space", 1024, 7, 768, 7},
		{"host_memory_reserve", 128, 0, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, _, _ := newFixture(t)
			m.Config.CPUAllocationLimit = 8
			m.Config.MemoryAllocationLimitMiB = 4096
			m.Config.DiskAllocationLimitGiB = 32
			m.capacityRead = func(string) (nodeproto.Capacity, error) {
				return nodeproto.Capacity{CPUCoresTotal: 64, MemoryTotalMiB: 65536,
					MemoryAvailableMiB: tc.memory, StorageTotalGiB: 5000, StorageAvailableGiB: tc.disk}, nil
			}
			capacity := m.Capabilities(t.Context()).Capacity
			if capacity.CPUCoresTotal != 8 || capacity.MemoryTotalMiB != 4096 || capacity.StorageTotalGiB != 32 ||
				capacity.MemoryAvailableMiB != tc.wantMemory || capacity.StorageAvailableGiB != tc.wantDisk {
				t.Fatalf("capacity violates the root ceilings or physical reserve: %+v", capacity)
			}
		})
	}
}

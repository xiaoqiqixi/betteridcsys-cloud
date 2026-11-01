package control

import (
	"context"
	"errors"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMySQLRegionalPlacementConcurrentBillingAndConsoleCapacity(t *testing.T) {
	for _, policy := range []string{"least_instances", "most_free_memory", "fill_first"} {
		t.Run(policy, func(t *testing.T) {
			s, _ := mysqlTestStore(t)
			a, now := mysqlNode(t, s)
			b, _ := mysqlNode(t, s)
			ctx := context.Background()
			c := testConfig(a)
			c.Nodes = append(c.Nodes, b)
			c.PlacementRegions = []string{a.DatacenterID}
			resources := testResources(a)
			resources.ComputeNodeID = ""
			c.Presets = []Preset{{ID: "regional", Resources: resources}}
			if !c.Valid() {
				t.Fatal("regional preset invalid")
			}
			if err := s.SetPlacement(ctx, c, id(), a.DatacenterID, policy, now); err != nil {
				t.Fatal(err)
			}
			var accepted, failures atomic.Int32
			var wg sync.WaitGroup
			for index := range 32 {
				wg.Add(1)
				go func(index int) {
					defer wg.Done()
					var err error
					if index%2 == 0 {
						r := testRequest(a)
						r.Product.Resources = &resources
						r.ConfigurationSHA256, _ = r.Product.Digest()
						j, _, e := s.Admit(ctx, r, c.Candidates(r), now, time.Minute)
						err = e
						if err == nil && j.State != "accepted" {
							failures.Add(1)
							return
						}
					} else {
						_, _, err = s.CreateInstance(ctx, c, id(), id(), CreateInstanceInput{Hostname: "regional-vm", OwnerRef: id(), PresetID: "regional"}, now)
					}
					if err == nil {
						accepted.Add(1)
					} else if !errors.Is(err, ErrCapacity) {
						failures.Add(1)
					}
				}(index)
			}
			wg.Wait()
			if accepted.Load() != 8 || failures.Load() != 0 {
				t.Fatal("oversubscribed or lost capacity", accepted.Load(), failures.Load())
			}
			for _, node := range []string{a.ID, b.ID} {
				var count, cpu int
				if err := s.DB.QueryRow("SELECT COUNT(*),SUM(cpu) FROM controller_reservations WHERE node_id=? AND released=FALSE", node).Scan(&count, &cpu); err != nil || count != 4 || cpu != 8 {
					t.Fatal("node oversubscribed", count, cpu, err)
				}
			}
		})
	}
}

func TestMySQLPlacementRanksReservationsAndDisablesOnlyNewAllocations(t *testing.T) {
	s, _ := mysqlTestStore(t)
	a, now := mysqlNode(t, s)
	b, _ := mysqlNode(t, s)
	ctx := context.Background()
	nodes := []NodeProfile{a, b}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	a, b = nodes[0], nodes[1]
	c := testConfig(a)
	c.Nodes = nodes
	c.PlacementRegions = []string{a.DatacenterID}
	if _, err := s.DB.Exec("UPDATE controller_nodes SET free_memory_mib=4096 WHERE id=?", a.ID); err != nil {
		t.Fatal(err)
	}
	r := testRequest(a)
	r.Product.Resources.ComputeNodeID = ""
	r.ConfigurationSHA256, _ = r.Product.Digest()
	if err := s.SetPlacement(ctx, c, id(), a.DatacenterID, "most_free_memory", now); err != nil {
		t.Fatal(err)
	}
	j, _, err := s.Admit(ctx, r, c.Candidates(r), now, time.Minute)
	if err != nil || j.NodeID != b.ID {
		t.Fatal("memory placement", err, j.NodeID)
	}
	if err = s.SetPlacement(ctx, c, id(), a.DatacenterID, "least_instances", now); err != nil {
		t.Fatal(err)
	}
	r.OperationID, r.OrderID = id(), id()
	j, _, err = s.Admit(ctx, r, c.Candidates(r), now, time.Minute)
	if err != nil || j.NodeID != a.ID {
		t.Fatal("instance placement", err, j.NodeID)
	}
	if err = s.SetAllocationDisabled(ctx, c, id(), a.ID, true, now); err != nil {
		t.Fatal(err)
	}
	// An already accepted create remains dispatchable; allocation is not maintenance.
	if _, err = s.Claim(ctx, j.OperationID, a.Digest(), now, time.Minute); err != nil {
		t.Fatal("allocation toggle blocked accepted work", err)
	}
	if _, err = s.Complete(ctx, j.OperationID, "succeeded", now); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.CreateOperation(ctx, c, id(), j.InstanceID, id(), OperationInput{Action: "start"}, now); err != nil {
		t.Fatal("allocation toggle blocked existing instance", err)
	}
	r.OperationID, r.OrderID = id(), id()
	r.Product.Resources.ComputeNodeID = a.ID
	r.ConfigurationSHA256, _ = r.Product.Digest()
	if _, _, err = s.Admit(ctx, r, c.Candidates(r), now, time.Minute); !errors.Is(err, ErrCapacity) {
		t.Fatal("disabled node accepted create", err)
	}
	r.OperationID, r.OrderID = id(), id()
	r.Product.Resources.ComputeNodeID = ""
	r.ConfigurationSHA256, _ = r.Product.Digest()
	if err = s.SetPlacement(ctx, c, id(), a.DatacenterID, "fill_first", now); err != nil {
		t.Fatal(err)
	}
	next, _, err := s.Admit(ctx, r, c.Candidates(r), now, time.Minute)
	if err != nil || next.NodeID != b.ID {
		t.Fatal("disabled node ranked", err)
	}
	if err = s.SetAllocationDisabled(ctx, c, id(), a.ID, false, now); err != nil {
		t.Fatal(err)
	}
	r.OperationID, r.OrderID = id(), id()
	next, _, err = s.Admit(ctx, r, c.Candidates(r), now, time.Minute)
	if err != nil || next.NodeID != a.ID {
		t.Fatal("fill first order", err)
	}
}

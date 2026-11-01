package control

import "testing"

func TestRegionalCandidatesRequireRootApprovalAndKeepPinnedProducts(t *testing.T) {
	a := testProfile()
	b := a
	b.ID = "node-b"
	b.GroupID = "group-b"
	c := testConfig(a)
	c.Nodes = append(c.Nodes, b)
	r := testRequest(a)
	r.Product.Resources.ComputeNodeID = ""
	if len(c.Candidates(r)) != 0 {
		t.Fatal("unapproved regional placement")
	}
	c.PlacementRegions = []string{a.DatacenterID}
	candidates := c.Candidates(r)
	if len(candidates) != 2 || candidates[1].Resources.ComputeNodeID != b.ID || candidates[1].Resources.NodeGroupID != b.GroupID || r.Product.Resources.ComputeNodeID != "" {
		t.Fatal("regional binding or input mutated")
	}
	r.Product.Resources.ComputeNodeID = a.ID
	if candidates = c.Candidates(r); len(candidates) != 1 || candidates[0].Node.ID != a.ID {
		t.Fatal("pinned product moved")
	}
	r.Product.Resources.ComputeNodeID = ""
	r.Product.Resources.NodeGroupID = b.GroupID
	if candidates = c.Candidates(r); len(candidates) != 1 || candidates[0].Node.ID != b.ID {
		t.Fatal("group selector ignored")
	}
	r.Product.Resources.DatacenterID = "other"
	if len(c.Candidates(r)) != 0 {
		t.Fatal("cross-region placement")
	}
}

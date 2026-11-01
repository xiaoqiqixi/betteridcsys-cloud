package control

import "aster/billing/serviceapi"

type CatalogImage struct {
	ID        string   `json:"id"`
	Family    string   `json:"family"`
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	MinDiskGB int      `json:"min_disk_gb"`
	SHA256    string   `json:"sha256"`
	NodeIDs   []string `json:"node_ids"`
	Rescue    bool     `json:"rescue,omitempty"`
}

// ServiceConfig is part of the existing root-protected configuration. Neither
// image source paths nor download URLs are accepted from billing requests.
type ServiceConfig struct {
	Images        []CatalogImage `json:"images,omitempty"`
	SnapshotLimit int            `json:"snapshot_limit"`
}

func (c Config) validServiceConfig() bool {
	if len(c.Service.Images) > 256 || c.Service.SnapshotLimit < 0 || c.Service.SnapshotLimit > 100 {
		return false
	}
	seen := map[string]bool{}
	for _, im := range c.Service.Images {
		if !im.Public().Valid() || seen[im.ID] || len(im.NodeIDs) == 0 || len(im.NodeIDs) > 64 || im.Rescue && im.Family != "linux" {
			return false
		}
		seen[im.ID] = true
		nodes := map[string]bool{}
		for _, id := range im.NodeIDs {
			if _, ok := c.Node(id); !ok || nodes[id] {
				return false
			}
			nodes[id] = true
		}
	}
	return true
}
func (c Config) serviceImage(id, node string) (CatalogImage, bool) {
	for _, im := range c.Service.Images {
		if im.ID == id && contains(im.NodeIDs, node) {
			return im, true
		}
	}
	return CatalogImage{}, false
}

func (im CatalogImage) Public() serviceapi.Image {
	return serviceapi.Image{ID: im.ID, Family: im.Family, Name: im.Name, Version: im.Version, MinDiskGB: im.MinDiskGB, SHA256: im.SHA256}
}

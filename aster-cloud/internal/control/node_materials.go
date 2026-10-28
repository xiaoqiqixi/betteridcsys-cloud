package control

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
)

// NodeMaterialBinding relocates already approved identity bytes. It is part of
// root's configuration, never a customer/API field or a node-profile revision.
// Historical profile JSON (including the original paths) remains unchanged.
type NodeMaterialBinding struct {
	NodeID           string `json:"node_id"`
	ProfileSHA256    string `json:"profile_sha256"`
	CAFile           string `json:"ca_file"`
	CASHA256         string `json:"ca_sha256"`
	ClientCertFile   string `json:"client_cert_file"`
	ClientCertSHA256 string `json:"client_cert_sha256"`
	ClientKeyFile    string `json:"client_key_file"`
	ClientKeySHA256  string `json:"client_key_sha256"`
}

func (b NodeMaterialBinding) matches(p NodeProfile) bool {
	if b.NodeID != p.ID || b.ProfileSHA256 != p.Digest() {
		return false
	}
	for _, path := range []string{b.CAFile, b.ClientCertFile, b.ClientKeyFile} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n") {
			return false
		}
	}
	for _, sha := range []string{b.CASHA256, b.ClientCertSHA256, b.ClientKeySHA256} {
		if !shaRE.MatchString(sha) {
			return false
		}
	}
	return true
}

func (c Config) validNodeMaterials() bool {
	if len(c.NodeMaterials) > len(c.Nodes) {
		return false
	}
	seen := map[string]bool{}
	for _, b := range c.NodeMaterials {
		if seen[b.NodeID] {
			return false
		}
		seen[b.NodeID] = true
		found := false
		for _, p := range c.Nodes {
			if p.ID == b.NodeID && b.matches(p) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func (c Config) nodeWithMaterials(p NodeProfile) (NodeProfile, bool) {
	p.materials = nil
	for _, b := range c.NodeMaterials {
		if b.NodeID == p.ID {
			if p.materials != nil || !b.matches(p) {
				return NodeProfile{}, false
			}
			copy := b
			p.materials = &copy
		}
	}
	return p, true
}

func pinnedMaterial(raw []byte, expected string) bool {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]) == expected
}

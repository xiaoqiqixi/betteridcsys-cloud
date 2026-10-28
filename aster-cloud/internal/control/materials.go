package control

import "sort"

// RuntimeMaterial describes only references approved by the root-managed
// configuration. A reference does not authorize writing to its source path.
type RuntimeMaterial struct {
	Label, Path, ExpectedSHA256 string
	Private                     bool
	Maximum                     int64
}

// RuntimeMaterials shares the effective locations between TLS, export and
// offline source verification. Keep the legacy digest order (six fixed fields,
// then sorted node IDs) so existing source receipts remain verifiable.
func (c Config) RuntimeMaterials() ([]RuntimeMaterial, error) {
	if !c.Valid() {
		return nil, ErrInput
	}
	refs := []RuntimeMaterial{
		{"dsn_file", c.DSNFile, "", true, 4096},
		{"tls_cert_file", c.TLSCertFile, "", false, 65536},
		{"tls_key_file", c.TLSKeyFile, "", true, 65536},
		{"billing_token_file", c.BillingTokenFile, "", true, 4096},
		{"admin_read_token_file", c.AdminReadTokenFile, "", true, 4096},
		{"admin_write_token_file", c.AdminWriteTokenFile, "", true, 4096},
	}
	nodes := append([]NodeProfile(nil), c.Nodes...)
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	for _, node := range nodes {
		n, ok := c.Node(node.ID)
		if !ok {
			return nil, ErrInput
		}
		ca, cert, key := n.CAFile, n.ClientCertFile, n.ClientKeyFile
		caSHA, certSHA, keySHA := "", "", ""
		if b := n.materials; b != nil {
			ca, cert, key = b.CAFile, b.ClientCertFile, b.ClientKeyFile
			caSHA, certSHA, keySHA = b.CASHA256, b.ClientCertSHA256, b.ClientKeySHA256
		}
		refs = append(refs, RuntimeMaterial{n.ID + ":ca_file", ca, caSHA, false, 1 << 20},
			RuntimeMaterial{n.ID + ":client_cert_file", cert, certSHA, false, 1 << 20},
			RuntimeMaterial{n.ID + ":client_key_file", key, keySHA, true, 1 << 20})
	}
	return refs, nil
}

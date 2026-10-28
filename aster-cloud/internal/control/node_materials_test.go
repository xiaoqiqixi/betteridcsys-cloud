package control

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestConfigNodeMaterialBindingsAreExactAndPreserveLegacyIdentity(t *testing.T) {
	p := testProfile()
	legacy, err := json.Marshal(testConfig(p))
	if err != nil {
		t.Fatal(err)
	}
	base := testConfig(p)
	base.NodeMaterials = []NodeMaterialBinding{{NodeID: p.ID, ProfileSHA256: p.Digest(),
		CAFile: "/relocated/ca.pem", CASHA256: strings.Repeat("a", 64),
		ClientCertFile: "/relocated/client.pem", ClientCertSHA256: strings.Repeat("b", 64),
		ClientKeyFile: "/relocated/client.key", ClientKeySHA256: strings.Repeat("c", 64)}}
	valid, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{"legacy": legacy, "bound": valid} {
		loaded, err := ParseConfig(raw)
		if err != nil {
			t.Fatalf("%s config: %v", name, err)
		}
		roundTrip, err := json.Marshal(loaded)
		if err != nil || string(roundTrip) != string(raw) {
			t.Fatalf("%s round trip changed wire identity", name)
		}
		profile, ok := loaded.Node(p.ID)
		if !ok || profile.Digest() != p.Digest() {
			t.Fatalf("%s changed historical profile digest", name)
		}
		refs, err := loaded.RuntimeMaterials()
		if err != nil || len(refs) != 9 {
			t.Fatalf("%s runtime references: %v", name, err)
		}
		if name == "bound" && (refs[8].Path != "/relocated/client.key" || refs[8].ExpectedSHA256 != strings.Repeat("c", 64)) {
			t.Fatal("backup did not receive the approved effective key reference")
		}
	}
	for name, change := range map[string]func(map[string]any, map[string]any){
		"null collection":        func(d, b map[string]any) { d["node_materials"] = nil },
		"unknown node":           func(d, b map[string]any) { b["node_id"] = "other-node" },
		"duplicate node":         func(d, b map[string]any) { d["node_materials"] = []any{b, b} },
		"missing key hash":       func(d, b map[string]any) { delete(b, "client_key_sha256") },
		"null path":              func(d, b map[string]any) { b["ca_file"] = nil },
		"unknown property":       func(d, b map[string]any) { b["fallback"] = true },
		"wrong property case":    func(d, b map[string]any) { b["CA_file"] = b["ca_file"]; delete(b, "ca_file") },
		"stale profile hash":     func(d, b map[string]any) { b["profile_sha256"] = strings.Repeat("0", 64) },
		"uppercase content hash": func(d, b map[string]any) { b["ca_sha256"] = strings.Repeat("A", 64) },
		"short content hash":     func(d, b map[string]any) { b["ca_sha256"] = "abcd" },
		"relative path":          func(d, b map[string]any) { b["ca_file"] = "relocated/ca.pem" },
		"traversal path":         func(d, b map[string]any) { b["ca_file"] = "/relocated/../ca.pem" },
		"control in path":        func(d, b map[string]any) { b["ca_file"] = "/relocated/ca\n.pem" },
		"endpoint changed": func(d, b map[string]any) {
			d["nodes"].([]any)[0].(map[string]any)["endpoint"] = "https://other.invalid:9444"
		},
		"CIDR changed": func(d, b map[string]any) {
			d["nodes"].([]any)[0].(map[string]any)["allowed_cidrs"] = []string{"198.51.100.0/24"}
		},
		"server pin changed": func(d, b map[string]any) {
			d["nodes"].([]any)[0].(map[string]any)["server_certificate_sha256"] = strings.Repeat("b", 64)
		},
		"old path changed": func(d, b map[string]any) { d["nodes"].([]any)[0].(map[string]any)["ca_file"] = "/rewritten/ca.pem" },
	} {
		t.Run(name, func(t *testing.T) {
			var document map[string]any
			if err := json.Unmarshal(valid, &document); err != nil {
				t.Fatal(err)
			}
			binding := document["node_materials"].([]any)[0].(map[string]any)
			change(document, binding)
			raw, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = ParseConfig(raw); err == nil {
				t.Fatal("ambiguous or stale material mapping accepted")
			}
		})
	}
	t.Run("duplicate wire property", func(t *testing.T) {
		raw := strings.Replace(string(valid), `"ca_sha256":`, `"ca_sha256":"`+strings.Repeat("a", 64)+`","ca_sha256":`, 1)
		if _, err := ParseConfig([]byte(raw)); err == nil {
			t.Fatal("duplicate mapping property accepted")
		}
	})
}

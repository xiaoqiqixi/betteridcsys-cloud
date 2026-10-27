package fabric

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These are the actual unmodified nft -j -n list ruleset outputs from the
// isolated Ubuntu22/24 public NAT gate in GitHub run 40060108300. Only the log
// timestamp/tool prefix is removed; metainfo and kernel handles are retained.
// The addresses belong to temporary namespaces, not external test targets.
func TestNATInternetCompilerMatchesObservedNativeReadback(t *testing.T) {
	_, _, c, s := internetNATFixture(t)
	objects, err := compileNAT(c, s, c.NATProfiles[0], false)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(nftObject{"nftables": objects})
	want, _, err := normalizeNFT(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{"internet-nat-nft-1.0.2-ubuntu22.json", "internet-nat-nft-1.0.9-ubuntu24.json"} {
		t.Run(file, func(t *testing.T) {
			actual, err := os.ReadFile(filepath.Join("testdata", file))
			if err != nil {
				t.Fatal(err)
			}
			got, exists, err := normalizeNFT(actual)
			if err != nil || !exists || !bytes.Equal(got, want) {
				// Preserve the full comparison in the test failure, rather than
				// broadening normalization to erase required security guards.
				t.Fatalf("compiler differs from observed native nft JSON: %v\nwant=%s\ngot=%s", err, want, got)
			}
			for _, mutation := range []string{"tracked-return", "snat-status", "internet-exclusion", "ordinary-chain", "new-established", "icmp-protocol"} {
				t.Run(mutation, func(t *testing.T) {
					var doc struct {
						Objects []map[string]map[string]any `json:"nftables"`
					}
					if json.Unmarshal(actual, &doc) != nil {
						t.Fatal("observed JSON invalid")
					}
					changed := false
					for i, object := range doc.Objects {
						if mutation == "ordinary-chain" {
							if chain, ok := object["chain"]; ok && chain["name"] == "internet_in" {
								doc.Objects = append(doc.Objects[:i], doc.Objects[i+1:]...)
								changed = true
								break
							}
						}
						rule, ok := object["rule"]
						if !ok {
							continue
						}
						expr := rule["expr"].([]any)
						if mutation == "internet-exclusion" && rule["chain"] == "internet_out" {
							doc.Objects = append(doc.Objects[:i], doc.Objects[i+1:]...)
							changed = true
							break
						}
						for j, atom := range expr {
							body := atom.(map[string]any)
							m, ok := body["match"].(map[string]any)
							if !ok {
								continue
							}
							left := m["left"].(map[string]any)
							ct, hasCT := left["ct"].(map[string]any)
							remove := hasCT && ((mutation == "tracked-return" && rule["chain"] == "internet_in" && ct["key"] == "state") || (mutation == "snat-status" && ct["key"] == "status") || (mutation == "new-established" && rule["chain"] == "internet_out" && ct["key"] == "state"))
							if remove {
								rule["expr"] = append(expr[:j], expr[j+1:]...)
								changed = true
								break
							}
							if mutation == "icmp-protocol" {
								if p, ok := left["payload"].(map[string]any); ok && p["protocol"] == "icmp" {
									p["protocol"] = "tcp"
									changed = true
									break
								}
							}
						}
						if changed {
							break
						}
					}
					if !changed {
						t.Fatal("negative mutation did not hit observed native guard", mutation)
					}
					mutated, _ := json.Marshal(doc)
					got, _, err := normalizeNFT(mutated)
					if err == nil && bytes.Equal(got, want) {
						t.Fatal("security-relevant observed JSON mutation was hidden", mutation)
					}
				})
			}
			if !strings.Contains(string(got), `"right":[2,8]`) {
				t.Fatal("native tracked-state bit list lost")
			}
		})
	}
}

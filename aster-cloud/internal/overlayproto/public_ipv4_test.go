package overlayproto

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestNATPublicIPv4OptionalCanonicalContract(t *testing.T) {
	s := natSnapshot()
	old, oldSHA, err := CanonicalSnapshot(s)
	if err != nil {
		t.Fatal(err)
	}
	oldBytes, _ := json.Marshal(old)
	if bytes.Contains(oldBytes, []byte(`"public_ipv4"`)) {
		t.Fatal("legacy snapshot gained pool selection")
	}
	// This explicit zero value must not create a new historical task digest.
	s.NATPolicies[0].PublicIPv4 = ""
	zero, zeroSHA, err := CanonicalSnapshot(s)
	zeroBytes, _ := json.Marshal(zero)
	if err != nil || zeroSHA != oldSHA || !bytes.Equal(zeroBytes, oldBytes) {
		t.Fatal("empty selection changed old canonical bytes", err)
	}
	s.NATPolicies[0].PublicIPv4 = "8.8.4.3"
	selected, selectedSHA, err := CanonicalSnapshot(s)
	if err != nil || selectedSHA == oldSHA {
		t.Fatal("explicit selection lost", err)
	}
	raw, _ := json.Marshal(selected)
	decoded, err := DecodeSnapshot(raw)
	if err != nil || decoded.NATPolicies[0].PublicIPv4 != "8.8.4.3" {
		t.Fatal("selection did not survive strict wire", err)
	}
	for _, bad := range []string{"10.0.0.1", "192.0.2.1", "169.254.169.254", "::ffff:8.8.4.3", "8.8.4.3/32", "8.8.4.3 ", "0.0.0.0", "255.255.255.255"} {
		s.NATPolicies[0].PublicIPv4 = bad
		if _, _, err := CanonicalSnapshot(s); err == nil {
			t.Fatalf("nonpublic/noncanonical selection accepted %q", bad)
		}
	}
	for _, replacement := range []string{`"public_ipv4":null`, `"public_ipv4":8`, `"Public_IPv4":"8.8.4.3"`, `"public_ipv4":"8.8.4.3","public_ipv4":"8.8.4.4"`} {
		if _, err := DecodeSnapshot([]byte(strings.Replace(string(raw), `"public_ipv4":"8.8.4.3"`, replacement, 1))); err == nil {
			t.Fatalf("ambiguous public selection accepted %s", replacement)
		}
	}
}

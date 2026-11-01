package nodeproto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestGuestSSHKeyParsesEverySupportedWireFormat(t *testing.T) {
	ed := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, pub := range []any{ed.Public(), &ec.PublicKey, &r.PublicKey} {
		key, err := ssh.NewPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		authorized := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
		if !ValidGuestSSHKey(authorized + " customer@example") {
			t.Fatal("valid key refused", key.Type())
		}
		for _, bad := range []string{key.Type() + " AAAA", authorized + "\n" + authorized, "no-pty " + authorized, authorized + "\x00"} {
			if ValidGuestSSHKey(bad) {
				t.Fatal("malformed or option-bearing key accepted")
			}
		}
	}
}

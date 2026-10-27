package identity

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

const passwordIterations = 600000

func passwordValid(password []byte) bool { return len(password) >= 12 && len(password) <= 1024 }

func hashPassword(password []byte) (string, error) {
	if !passwordValid(password) {
		return "", ErrInput
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, string(password), salt, passwordIterations, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", passwordIterations, hex.EncodeToString(salt), hex.EncodeToString(key)), nil
}

func verifyPassword(encoded string, password []byte) bool {
	p := strings.Split(encoded, "$")
	if len(p) != 4 || p[0] != "pbkdf2-sha256" || len(password) > 1024 {
		return false
	}
	n, err := strconv.Atoi(p[1])
	if err != nil || n != passwordIterations {
		return false
	}
	salt, err := hex.DecodeString(p[2])
	if err != nil || len(salt) != 16 {
		return false
	}
	want, err := hex.DecodeString(p[3])
	if err != nil || len(want) != 32 {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, string(password), salt, n, 32)
	return err == nil && subtle.ConstantTimeCompare(got, want) == 1
}

// A syntactically valid fixed dummy hash ensures unknown accounts still run the KDF.
const dummyPasswordHash = "pbkdf2-sha256$600000$00000000000000000000000000000000$0000000000000000000000000000000000000000000000000000000000000000"

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
func tokenHash(raw string) [32]byte { return sha256.Sum256([]byte(raw)) }
func validToken(raw string) bool {
	b, err := hex.DecodeString(raw)
	return err == nil && len(b) == 32 && raw == strings.ToLower(raw)
}
func csrfToken(raw string) string {
	h := hmac.New(sha256.New, []byte(raw))
	h.Write([]byte("aster-cloud-console-csrf/v1"))
	return hex.EncodeToString(h.Sum(nil))
}

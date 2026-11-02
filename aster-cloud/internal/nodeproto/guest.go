package nodeproto

import (
	"aster/billing/serviceapi"
	"bytes"
	"strings"

	"golang.org/x/crypto/ssh"
)

// GuestParams extends only explicit lifecycle actions. Password is sent once
// over mTLS, then removed before either side writes its durable operation.
// PasswordRequired remains so restart cannot silently dispatch without it.
type GuestParams struct {
	SecretSHA256     string            `json:"secret_sha256,omitempty"`
	Params           serviceapi.Params `json:"params"`
	ImageSHA256      string            `json:"image_sha256,omitempty"`
	PasswordRequired bool              `json:"password_required,omitempty"`
}

func GuestAction(action string) bool {
	switch action {
	case "reinstall", "reset_password", "rescue_enter", "rescue_exit", "suspend", "unsuspend", "resize":
		return true
	}
	return false
}

// StartsGuest includes lifecycle actions that boot after their offline work.
// They must satisfy exactly the same network lease gates as an explicit start.
func StartsGuest(t NodeTask) bool {
	switch t.Action {
	case "create", "start", "reboot", "reinstall", "reset_password", "rescue_enter", "rescue_exit":
		return true
	case "unsuspend":
		return t.Guest.Params.StartAfter
	}
	return false
}

// Parse the actual SSH wire key before any destructive reinstall is admitted.
// The public SDK validates the request shape without importing SSH machinery.
func ValidGuestSSHKey(value string) bool {
	if len(value) > 8192 || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	key, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(value))
	if err != nil || len(options) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return false
	}
	switch key.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoRSA, ssh.KeyAlgoECDSA256:
		return true
	}
	return false
}
func (g GuestParams) Valid(action string) bool {
	if g.SecretSHA256 != "" && (!g.PasswordRequired || !digest.MatchString(g.SecretSHA256)) {
		return false
	}
	p := g.Params
	if g.PasswordRequired {
		if p.Password == "" {
			p.Password = "redacted"
		}
	} else if p.Password != "" {
		return false
	}
	if !p.Valid(action) {
		return false
	}
	for _, key := range p.Keys() {
		if !ValidGuestSSHKey(key) {
			return false
		}
	}
	if action == "reinstall" || action == "rescue_enter" {
		return digest.MatchString(g.ImageSHA256)
	}
	return g.ImageSHA256 == ""
}
func (t NodeTask) Redacted() NodeTask { t.Guest.Params = t.Guest.Params.Redacted(); return t }

// GuestParams holds a slice (Params.SSHPublicKeys) so it is not == comparable.
// IsZero and Equal preserve the exact checks the old == comparisons made.
func (g GuestParams) IsZero() bool { return g.Equal(GuestParams{}) }

func (g GuestParams) Equal(o GuestParams) bool {
	return g.SecretSHA256 == o.SecretSHA256 && g.ImageSHA256 == o.ImageSHA256 && g.PasswordRequired == o.PasswordRequired && g.Params.Equal(o.Params)
}

package nodeproto

import "aster/billing/serviceapi"

// GuestParams extends only explicit lifecycle actions. Password is sent once
// over mTLS, then removed before either side writes its durable operation.
// PasswordRequired remains so restart cannot silently dispatch without it.
type GuestParams struct {
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
func (g GuestParams) Valid(action string) bool {
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
	if action == "reinstall" || action == "rescue_enter" {
		return digest.MatchString(g.ImageSHA256)
	}
	return g.ImageSHA256 == ""
}
func (t NodeTask) Redacted() NodeTask { t.Guest.Params = t.Guest.Params.Redacted(); return t }

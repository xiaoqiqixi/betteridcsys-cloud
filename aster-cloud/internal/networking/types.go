// Package networking manages conservative, persistent network intent and IP
// reservations. It does not execute host networking or change billing resources.
package networking

import (
	"aster/cloud/internal/nodeproto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	ErrInput       = errors.New("invalid network input")
	ErrConflict    = errors.New("network intent conflict")
	ErrForbidden   = errors.New("network binding forbidden")
	ErrNotFound    = errors.New("network resource not found")
	ErrCapacity    = errors.New("IP pool exhausted")
	ErrState       = errors.New("network resource state conflict")
	ErrUnavailable = errors.New("network storage unavailable")
)

const PageLimit = 100
const MaxAddresses = 4096
const PoolPageBudget = 512 << 10

type VPC struct {
	ID        string    `json:"id"`
	OwnerRef  string    `json:"owner_ref"`
	NodeID    string    `json:"node_id"`
	Name      string    `json:"name"`
	CIDR      string    `json:"cidr"`
	VLANID    int       `json:"vlan_id"`
	State     string    `json:"state"`
	CreatedAt time.Time `json:"created_at"`
}
type IPPool struct {
	ID        string   `json:"id"`
	NodeID    string   `json:"node_id"`
	VPCID     string   `json:"vpc_id"`
	Name      string   `json:"name"`
	CIDR      string   `json:"cidr"`
	Gateway   string   `json:"gateway"`
	Addresses []string `json:"addresses"`
	Enabled   bool     `json:"enabled"`
}
type Lease struct {
	ID         string    `json:"id"`
	PoolID     string    `json:"pool_id"`
	VPCID      string    `json:"vpc_id"`
	NodeID     string    `json:"node_id"`
	InstanceID string    `json:"instance_id"`
	OwnerRef   string    `json:"owner_ref"`
	Address    string    `json:"address"`
	State      string    `json:"state"`
	CreatedAt  time.Time `json:"created_at"`
}
type Page[T any] struct {
	Items      []T     `json:"items"`
	NextCursor *string `json:"next_cursor"`
}
type CreateVPCInput struct {
	OwnerRef string `json:"owner_ref"`
	NodeID   string `json:"node_id"`
	Name     string `json:"name"`
	CIDR     string `json:"cidr"`
	VLANID   int    `json:"vlan_id"`
}
type CreatePoolInput struct {
	NodeID    string   `json:"node_id"`
	VPCID     string   `json:"vpc_id"`
	Name      string   `json:"name"`
	CIDR      string   `json:"cidr"`
	Gateway   string   `json:"gateway"`
	Addresses []string `json:"addresses"`
	Enabled   bool     `json:"enabled"`
}
type ReserveInput struct {
	PoolID     string `json:"pool_id"`
	InstanceID string `json:"instance_id"`
	OwnerRef   string `json:"owner_ref"`
	Address    string `json:"address"`
}

func validName(s string) bool {
	if !utf8.ValidString(s) || strings.TrimSpace(s) != s || utf8.RuneCountInString(s) < 1 || utf8.RuneCountInString(s) > 80 {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}
func validTime(t time.Time) bool {
	return !t.IsZero() && t.UTC().Year() >= 1000 && t.UTC().Year() <= 9999
}
func stamp(t time.Time) time.Time { return t.UTC().Truncate(time.Microsecond) }
func prefix(raw string) (netip.Prefix, bool) {
	p, e := netip.ParsePrefix(raw)
	return p, e == nil && p.Addr().Is4() && p.Bits() >= 8 && p.Bits() <= 30 && p == p.Masked() && p.String() == raw && p.Addr().IsGlobalUnicast()
}
func usableAddress(raw string, p netip.Prefix) (netip.Addr, bool) {
	a, e := netip.ParseAddr(raw)
	if e != nil || !a.Is4() || a.String() != raw || !a.IsGlobalUnicast() || !p.Contains(a) || a == p.Addr() {
		return a, false
	}
	last := p.Addr().As4()
	bits := uint32(last[0])<<24 | uint32(last[1])<<16 | uint32(last[2])<<8 | uint32(last[3])
	bits |= uint32(1)<<(32-p.Bits()) - 1
	broadcast := netip.AddrFrom4([4]byte{byte(bits >> 24), byte(bits >> 16), byte(bits >> 8), byte(bits)})
	return a, a != broadcast
}
func (in CreateVPCInput) Valid() bool {
	p, ok := prefix(in.CIDR)
	return nodeproto.ValidID(in.OwnerRef) && nodeproto.ValidNodeID(in.NodeID) && validName(in.Name) && ok && p.Bits() >= 16 && p.Addr().IsPrivate() && in.VLANID >= 1 && in.VLANID <= 4094
}

// Canonical sorts a copied address array numerically before hashing/storing it.
// Array order is not an allocation intent; a changed member or other field is.
func (in CreatePoolInput) Canonical() (CreatePoolInput, error) {
	p, ok := prefix(in.CIDR)
	if !ok || !nodeproto.ValidNodeID(in.NodeID) || in.VPCID != "" && !nodeproto.ValidID(in.VPCID) || !validName(in.Name) || len(in.Addresses) < 1 || len(in.Addresses) > MaxAddresses {
		return CreatePoolInput{}, ErrInput
	}
	gateway, ok := usableAddress(in.Gateway, p)
	if !ok {
		return CreatePoolInput{}, ErrInput
	}
	copy := in
	copy.Addresses = append([]string{}, in.Addresses...)
	seen := map[string]bool{}
	for _, raw := range copy.Addresses {
		a, ok := usableAddress(raw, p)
		if !ok || a == gateway || seen[raw] {
			return CreatePoolInput{}, ErrInput
		}
		seen[raw] = true
	}
	sort.Slice(copy.Addresses, func(i, j int) bool {
		a, _ := netip.ParseAddr(copy.Addresses[i])
		b, _ := netip.ParseAddr(copy.Addresses[j])
		return a.Less(b)
	})
	return copy, nil
}
func (in ReserveInput) Valid() bool {
	if !nodeproto.ValidID(in.PoolID) || !nodeproto.ValidID(in.InstanceID) || !nodeproto.ValidID(in.OwnerRef) {
		return false
	}
	if in.Address == "" {
		return true
	}
	a, e := netip.ParseAddr(in.Address)
	return e == nil && a.Is4() && a.String() == in.Address && a.IsGlobalUnicast()
}
func bodyDigest(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func validWrite(actor, id string, now time.Time) bool {
	return nodeproto.ValidID(actor) && nodeproto.ValidID(id) && validTime(now)
}
func (v VPC) valid() bool {
	return nodeproto.ValidID(v.ID) && (CreateVPCInput{v.OwnerRef, v.NodeID, v.Name, v.CIDR, v.VLANID}).Valid() && v.State == "planned" && validTime(v.CreatedAt)
}
func (p IPPool) valid() bool {
	c, e := (CreatePoolInput{p.NodeID, p.VPCID, p.Name, p.CIDR, p.Gateway, p.Addresses, p.Enabled}).Canonical()
	if e != nil || !nodeproto.ValidID(p.ID) {
		return false
	}
	for j, a := range c.Addresses {
		if p.Addresses[j] != a {
			return false
		}
	}
	return true
}
func (l Lease) valid() bool {
	return nodeproto.ValidID(l.ID) && (ReserveInput{l.PoolID, l.InstanceID, l.OwnerRef, l.Address}).Valid() && l.Address != "" && (l.VPCID == "" || nodeproto.ValidID(l.VPCID)) && nodeproto.ValidNodeID(l.NodeID) && l.State == "reserved" && validTime(l.CreatedAt)
}

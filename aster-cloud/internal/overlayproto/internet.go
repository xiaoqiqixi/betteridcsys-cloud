package overlayproto

import "net/netip"

// InternetReservedCIDRs is the conservative IPv4 exclusion floor for public
// egress. Explicit, separately approved prefix routes are not Internet intent.
// Operator management/underlay addresses and VPCs are additionally blocked by
// each node. This returns a copy so callers cannot weaken the common floor.
func InternetReservedCIDRs() []string {
	return []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
		"192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	}
}

// PublicInternetIPv4 checks a canonical public unicast IPv4 address, not actual
// ownership or reachability. Namespace/uplink ownership stays root-approved.
func PublicInternetIPv4(raw string) bool {
	a, err := netip.ParseAddr(raw)
	if err != nil || !a.Is4() || a.String() != raw || !a.IsGlobalUnicast() {
		return false
	}
	for _, rawPrefix := range InternetReservedCIDRs() {
		if netip.MustParsePrefix(rawPrefix).Contains(a) {
			return false
		}
	}
	return true
}

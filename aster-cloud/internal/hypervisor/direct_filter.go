package hypervisor

import (
	"aster/cloud/internal/overlayproto"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// DirectApprovedFilterXML keeps the legacy filter bytes intact while giving
// lease-required public guests an explicit non-public/metadata IPv4 destination
// floor. The dedicated uplink still requires independent management isolation.
func DirectApprovedFilterXML(name string) []byte {
	var rules strings.Builder
	rules.WriteString(`  <rule action="drop" direction="out" priority="-870"><ip dstipaddr="$HOST_IPS"/></rule>
`)
	for i, raw := range overlayproto.InternetReservedCIDRs() {
		p := netip.MustParsePrefix(raw)
		address, bits := p.Addr().String(), p.Bits()
		priority := -850 + i*2
		fmt.Fprintf(&rules, "  <rule action=\"drop\" direction=\"out\" priority=\"%d\"><ip dstipaddr=\"%s\" dstipmask=\"%d\"/></rule>\n", priority, address, bits)
		fmt.Fprintf(&rules, "  <rule action=\"drop\" direction=\"in\" priority=\"%d\"><ip srcipaddr=\"%s\" srcipmask=\"%d\"/></rule>\n", priority+1, address, bits)
	}
	base := strings.Replace(string(ApprovedFilterXML(name)), `  <rule action="accept" direction="inout" priority="500"><mac protocolid="arp"/></rule>`, `  <rule action="accept" direction="out" priority="450"><arp arpdstipaddr="$GATEWAY"/></rule>
  <rule action="accept" direction="out" priority="451"><arp arpdstipaddr="$IP"/></rule>
  <rule action="accept" direction="in" priority="452"><arp arpsrcipaddr="$GATEWAY" arpdstipaddr="$IP"/></rule>
  <rule action="drop" direction="inout" priority="453"><mac protocolid="arp"/></rule>`, 1)
	return []byte(strings.Replace(base, "  <rule action=\"accept\" direction=\"out\" priority=\"450\">", rules.String()+"  <rule action=\"accept\" direction=\"out\" priority=\"450\">", 1))
}
func validateDirectFilter(raw []byte, name string) error {
	got, e := canonicalFilter(raw)
	if e != nil {
		return e
	}
	want, _ := canonicalFilter(DirectApprovedFilterXML(name))
	if got != want {
		return errors.New("direct public filter must include exact anti-spoof and non-public/metadata isolation rules")
	}
	return nil
}

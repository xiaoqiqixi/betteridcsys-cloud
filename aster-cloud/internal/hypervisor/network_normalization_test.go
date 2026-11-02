package hypervisor

import (
	"strings"
	"testing"
)

// libvirt 10's macProtocolIDFormatter emits the name "vlan" for EtherType
// 0x8100 even when the operator defined the filter with the numeric spelling.
const libvirtStaticIPv4Filter = `<filter name='aster-static-ipv4' chain='root'>
  <uuid>9bc60d98-45ed-461c-a6a6-fb1e015c3285</uuid>
  <rule action='drop' direction='out' priority='-1000'><mac match='no' srcmacaddr='$MAC'/></rule>
  <rule action='drop' direction='inout' priority='-990'><mac protocolid='vlan'/></rule>
  <rule action='drop' direction='inout' priority='-980'><mac protocolid='0x88a8'/></rule>
  <rule action='drop' direction='inout' priority='-970'><mac protocolid='ipv6'/></rule>
  <rule action='drop' direction='out' priority='-900'><ip match='no' srcipaddr='$IP'/></rule>
  <rule action='drop' direction='out' priority='-890'><arp match='no' arpsrcmacaddr='$MAC'/></rule>
  <rule action='drop' direction='out' priority='-880'><arp match='no' arpsrcipaddr='$IP'/></rule>
  <rule action='accept' direction='inout' priority='500'><mac protocolid='arp'/></rule>
  <rule action='accept' direction='inout' priority='510'><mac protocolid='ipv4'/></rule>
  <rule action='drop' direction='inout' priority='1000'/>
</filter>`

func TestFilterAcceptsLibvirtVLANSpellingWithoutWeakeningPolicy(t *testing.T) {
	if err := validateFilter([]byte(libvirtStaticIPv4Filter), "aster-static-ipv4"); err != nil {
		t.Fatal("libvirt's equivalent VLAN spelling rejected:", err)
	}
	for _, changed := range []string{
		strings.Replace(libvirtStaticIPv4Filter, "protocolid='vlan'", "protocolid='0x8101'", 1),
		strings.Replace(libvirtStaticIPv4Filter, "action='drop' direction='inout' priority='-990'", "action='accept' direction='inout' priority='-990'", 1),
	} {
		if err := validateFilter([]byte(changed), "aster-static-ipv4"); err == nil {
			t.Fatal("changed VLAN rule accepted")
		}
	}
	for _, raw := range [][]byte{ApprovedFilterXML("aster-static-ipv4"), DirectApprovedFilterXML("aster-static-ipv4")} {
		before, err := canonicalFilter(raw)
		if err != nil {
			t.Fatal(err)
		}
		after, err := canonicalFilter([]byte(strings.Replace(string(raw), `protocolid="0x8100"`, `protocolid="vlan"`, 1)))
		if err != nil || before != after {
			t.Fatal("VLAN normalization changed approved semantics", err)
		}
	}
}

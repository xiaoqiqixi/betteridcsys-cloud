package hypervisor

import (
	"aster/cloud/internal/nodeproto"
	"aster/cloud/internal/overlayproto"
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

func TestDirectPublicFilterRequiresEveryIsolationRuleAndRejectsLegacy(t *testing.T) {
	name := "aster-public-ipv4"
	raw := DirectApprovedFilterXML(name)
	if e := validateDirectFilter(raw, name); e != nil {
		t.Fatal(e)
	}
	if e := validateDirectFilter(ApprovedFilterXML(name), name); e == nil {
		t.Fatal("legacy anti-spoof filter was falsely accepted as direct isolation")
	}
	for _, prefix := range overlayproto.InternetReservedCIDRs() {
		p := netip.MustParsePrefix(prefix)
		for _, field := range []string{"dstipaddr", "srcipaddr"} {
			needle := fmt.Sprintf(`%s="%s"`, field, p.Addr())
			if !strings.Contains(string(raw), needle) {
				t.Fatal("missing direct isolation floor", prefix, field)
			}
			bad := []byte(strings.Replace(string(raw), needle, field+`="8.8.8.8"`, 1))
			if validateDirectFilter(bad, name) == nil {
				t.Fatal("changed isolation floor accepted", prefix, field)
			}
		}
	}
	m, f, task := newFixture(t)
	_ = configureDirect(t, m, task)
	if e := m.verifyNetwork(context.Background()); e != nil {
		t.Fatal(e)
	}
	f.filter = ApprovedFilterXML(m.Config.Network.Filter)
	m.Config.Network.FilterSHA256 = nodeproto.Digest(f.filter)
	if e := m.verifyNetwork(context.Background()); e == nil {
		t.Fatal("root pin alone bypassed required direct isolation")
	}
}
func TestDirectPublicRootRejectsNonPublicGatewayDNSAndMixedAddressApproval(t *testing.T) {
	for _, kind := range []string{"gateway", "dns", "address", "disabled", "hostcidr"} {
		t.Run(kind, func(t *testing.T) {
			m, _, task := newFixture(t)
			_ = configureDirect(t, m, task)
			switch kind {
			case "gateway":
				m.Config.Network.Gateway = "8.8.8.255"
			case "dns":
				m.Config.Network.DNS = []string{"169.254.169.254"}
			case "address":
				m.Config.Network.Addresses = append(m.Config.Network.Addresses, "10.0.0.1")
			case "disabled":
				m.Config.Network.Enabled = false
			case "hostcidr":
				m.Config.Network.CIDR = "8.8.8.1/24"
			}
			if _, e := DirectNetworkSHA256(m.Config.Network); e == nil {
				t.Fatal("invalid public root network accepted")
			}
		})
	}
}

func TestDirectPublicHostManagementAddressInventoryIsFrozenAndReadBack(t *testing.T) {
	m, f, task := newFixture(t)
	task = configureDirect(t, m, task)
	if r := submit(t, m, task); r.Status != "succeeded" {
		t.Fatal(r)
	}
	i, _ := m.Ledger.Instance(task.InstanceID)
	raw := f.domains[i.Domain]
	if !strings.Contains(string(raw), `name="HOST_IPS" value="9.9.9.1"`) || !strings.Contains(string(DirectApprovedFilterXML(m.Config.Network.Filter)), `dstipaddr="$HOST_IPS"`) {
		t.Fatal("public host management address not protected")
	}
	m.hostIPv4s = func() ([]string, error) { return []string{"127.0.0.1", "9.9.9.1", "1.1.1.1"}, nil }
	if e := m.assertOwned(context.Background(), i); e == nil {
		t.Fatal("host management drift silently ignored")
	}
	if !strings.Contains(string(DirectApprovedFilterXML(m.Config.Network.Filter)), `arpdstipaddr="$GATEWAY"`) {
		t.Fatal("real public gateway ARP not admitted")
	}
	if strings.Contains(string(DirectApprovedFilterXML(m.Config.Network.Filter)), `priority="500"><mac protocolid="arp"`) {
		t.Fatal("unrestricted bridge ARP survived direct policy")
	}
}

func TestDirectPublicGuestAddressCannotAlreadyBelongToHost(t *testing.T) {
	m, f, task := newFixture(t)
	task = configureDirect(t, m, task)
	m.hostIPv4s = func() ([]string, error) { return []string{"127.0.0.1", task.DirectPublic.IPv4}, nil }
	if r := submit(t, m, task); r.Status != "rejected" {
		t.Fatal("host-owned address was assigned to a guest", r)
	}
	if f.count(" define ") != 0 {
		t.Fatal("conflicting host address defined a VM")
	}
}

package hypervisor

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"sort"
	"strings"
)

// ApprovedFilterXML is deliberately self-contained: no unpinned transitive
// clean-traffic references. The early Ethernet rules drop VLAN/QinQ/IPv6; final root-chain default
// drop permits only ARP/IPv4. Each rule has one protocol element (libvirt schema).
// It does NOT provide tenant firewall policies or isolate unisolated bridge peers.
func ApprovedFilterXML(name string) []byte {
	return []byte(`<filter name="` + name + `" chain="root">
  <rule action="drop" direction="out" priority="-1000"><mac match="no" srcmacaddr="$MAC"/></rule>
  <rule action="drop" direction="inout" priority="-990"><mac protocolid="0x8100"/></rule>
  <rule action="drop" direction="inout" priority="-980"><mac protocolid="0x88a8"/></rule>
  <rule action="drop" direction="inout" priority="-970"><mac protocolid="ipv6"/></rule>
  <rule action="drop" direction="out" priority="-900"><ip match="no" srcipaddr="$IP"/></rule>
  <rule action="drop" direction="out" priority="-890"><arp match="no" arpsrcmacaddr="$MAC"/></rule>
  <rule action="drop" direction="out" priority="-880"><arp match="no" arpsrcipaddr="$IP"/></rule>
  <rule action="accept" direction="inout" priority="500"><mac protocolid="arp"/></rule>
  <rule action="accept" direction="inout" priority="510"><mac protocolid="ipv4"/></rule>
  <rule action="drop" direction="inout" priority="1000"/>
</filter>
`)
}

// XML structural comparison permits only formatting/attribute-order differences
// and libvirt's generated root UUID. Extra accepts, references or namespace
// substitutions fail closed, even if an operator accidentally pins their hash.
func canonicalFilter(raw []byte) (string, error) {
	d := xml.NewDecoder(bytes.NewReader(raw))
	var b strings.Builder
	depth := 0
	skipped := false
	for {
		t, e := d.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return "", e
		}
		switch v := t.(type) {
		case xml.StartElement:
			if v.Name.Space != "" {
				return "", errors.New("filter namespace rejected")
			}
			if depth == 1 && v.Name.Local == "uuid" {
				if e = d.Skip(); e != nil {
					return "", e
				}
				skipped = true
				continue
			}
			if depth == 0 && v.Name.Local != "filter" {
				return "", errors.New("filter root required")
			}
			b.WriteString("<" + v.Name.Local)
			attrs := append([]xml.Attr(nil), v.Attr...)
			sort.Slice(attrs, func(i, j int) bool { return attrs[i].Name.Local < attrs[j].Name.Local })
			for _, a := range attrs {
				if a.Name.Space != "" {
					return "", errors.New("filter attribute namespace rejected")
				}
				b.WriteString(" " + a.Name.Local + "=" + a.Value)
			}
			b.WriteString(">")
			depth++
		case xml.EndElement:
			depth--
			b.WriteString("</" + v.Name.Local + ">")
		case xml.CharData:
			if strings.TrimSpace(string(v)) != "" {
				return "", errors.New("filter text rejected")
			}
		case xml.Directive, xml.ProcInst:
			return "", errors.New("filter directives rejected")
		}
	}
	_ = skipped
	if depth != 0 {
		return "", errors.New("incomplete filter")
	}
	return b.String(), nil
}
func validateFilter(raw []byte, name string) error {
	actual, e := canonicalFilter(raw)
	if e != nil {
		return e
	}
	expected, _ := canonicalFilter(ApprovedFilterXML(name))
	if actual != expected {
		return errors.New("filter does not match required self-contained IPv4 anti-spoof/default-deny policy")
	}
	return nil
}

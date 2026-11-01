package hypervisor

import (
	"context"
	"encoding/xml"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestGuestConsoleOnlyDialsOwnedRunningLoopbackGraphics(t *testing.T) {
	m, f, task := guestFixture(t)
	i, _ := m.Ledger.Instance(task.InstanceID)
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	if port < 5900 {
		t.Fatal("fixture port below VNC range")
	}
	go func() {
		c, e := listener.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("RFB 003.008\n"))
	}()
	var d domainXML
	_ = xml.Unmarshal(f.domains[i.Domain], &d)
	d.Devices.Graphics[0].Port = port
	f.domains[i.Domain], _ = xml.Marshal(d)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, e = m.Console(ctx, i.ID, strings.Repeat("f", 32)); e == nil {
		t.Fatal("foreign owner")
	}
	c, e := m.Console(ctx, i.ID, i.OwnerRef)
	if e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 12)
	_, e = io.ReadFull(c, b)
	c.Close()
	if e != nil || string(b) != "RFB 003.008\n" {
		t.Fatal(e)
	}
	d.Devices.Graphics[0].Listen = "0.0.0.0"
	f.domains[i.Domain], _ = xml.Marshal(d)
	if _, e = m.Console(ctx, i.ID, i.OwnerRef); e == nil {
		t.Fatal("public VNC accepted")
	}
	d.Devices.Graphics = nil
	f.domains[i.Domain], _ = xml.Marshal(d)
	if _, e = m.Console(ctx, i.ID, i.OwnerRef); e == nil {
		t.Fatal("missing VNC accepted")
	}
}

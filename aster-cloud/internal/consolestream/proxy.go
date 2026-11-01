// Package consolestream bridges bounded binary WebSocket streams and local VNC.
package consolestream

import (
	"context"
	"io"
	"net"
)

// Proxy returns after either peer closes or the session deadline expires. It
// never reconnects, buffers a full frame, or writes stream contents to logs.
func Proxy(ctx context.Context, a, b net.Conn) {
	done := make(chan struct{}, 2)
	copyOne := func(dst, src net.Conn) { _, _ = io.CopyBuffer(dst, src, make([]byte, 32<<10)); done <- struct{}{} }
	go copyOne(a, b)
	go copyOne(b, a)
	select {
	case <-ctx.Done():
	case <-done:
	}
	_ = a.Close()
	_ = b.Close()
}

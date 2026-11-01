# Guest console

Run the controller with its approved `--console-origin https://controller...`
to enable ticket issuance and the embedded `/console/` page. The billing token
and owner header are required only when issuing a ticket. The browser receives
a random, single-use 60-second ticket bound to the instance, owner and node.
The fragment is removed from browser history before opening WSS. A disconnect
requires a newly issued ticket; there is no automatic reconnect.

The WebSocket endpoint accepts only the exact configured browser Origin and
Host. It atomically consumes the ticket, revalidates ownership and placement,
then connects with the existing fixed-address, CIDR-checked, certificate-pinned
node mTLS identity. The node requires that controller certificate and matching
owner, checks the complete owned running domain and dials only its XML's
`127.0.0.1` VNC listener. No browser-supplied host, port, URL or XML is accepted.
Sessions last at most 30 minutes; the controller bounds concurrent sessions and
ticket inventory. Neither proxy records VNC contents or tickets.

Legacy domains without graphics report `console: false`. New domains use local
VNC; reinstall regenerates the definition. Console capability does not imply
guest boot or network readiness. Native CI uses a TCG-only test backend to run
the production lifecycle and WSS/mTLS/VNC path against real libvirtd; the shipped
node keeps its KVM requirement.

The noVNC source, licences and local CSP patches are embedded in the controller.
The page uses a self-only CSP, with no inline-script/style or data/blob URL
exceptions. Its keyboard escape sequence returns focus to native buttons. The
remote graphical guest remains subject to the guest operating system's own
accessibility support.

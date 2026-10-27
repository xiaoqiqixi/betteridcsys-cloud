> Optional root-approved namespace SNAT/DNAT now integrates with the overlay
> commit/recovery/lifecycle gate; see [NAT.md](NAT.md). The historical
> single-host baseline limitations below do not replace that explicit contract.

# Root-only OVS fabric executor (development)

**Current update:** the sections below describe the original single-host contract.
Explicit overlay lifecycle, gateway forwarding, multi-node barriers, durable
archival and recovery are now implemented separately. See
[network contract](../../docs/OVERLAY_DESIGN.md) and [recovery](RECOVERY.md).
The old 64-operation lifetime ceiling no longer applies. No real KVM/OVS
traffic acceptance is implied.


The base single-host contract supplies a native dataplane CLI and an **embedded
node lifecycle gate**. The separately approved overlay contract extends it with
VXLAN and gateway forwarding (see above). Neither is a real-host acceptance. The legacy node/1 Linux-bridge profile must never point at an OVS
bridge. New OVS VM operations must use the explicit network task/profile path;
CLI success alone never authorizes a VM start.

## Root approvals

Build `go build ./cmd/aster-network`. Prepare a dedicated, empty `aster-` bridge
and private config using an independent reviewed root procedure. The executable
does not create bridges, add/move interfaces, install packages, set controllers,
change bridge protocols or connect physical uplinks.

The already-prepared bridge must have:

- `fail_mode=secure`, no controller, OpenFlow14 explicitly enabled;
- `external_ids:aster-node-id=<node_id>` and `aster-dedicated=true`;
- no foreign flow cookies or `NORMAL` rules, no foreign meter IDs;
- only Linux TAP interfaces (verified using kernel `tun_flags`).

For standalone CLI operation, every existing guest Interface must be independently root-marked with
`external_ids:iface-id=<fabric.InterfaceID(instance_id)>`, `aster-node-id`,
`aster-owner`, `aster-instance`, and `aster-vpc`. If `iface-status` is present,
it must be `active`. `InterfaceID` is a deterministic SHA-256-derived UUIDv8.
OF port numbers are **not** identities. Exact stable labels and the live ofport
mapping are checked before and after programming. Unknown approved TAPs get no
allow flow. Physical interfaces, tunnels and patch ports are rejected.

Config (root-owned, 0600, no symlink or hardlink; parent directories trusted):

```json
{"schema":1,"node_id":"node-a","bridge":"aster-vpc","state_directory":"/var/lib/aster-network","dedicated_ack":true}
```

The state directory parent must already exist. Its leaf is created 0700 when
needed; pre-existing broad permissions are not repaired automatically. The
topology file is also a private 0600 regular file. `plan` compiles only and emits
a receipt summary, not private flow contents; `status` reads the durable receipt
without probing or changing OVS. Status is not a live isolation observation.

```sh
aster-network plan --config /etc/aster-network/config.json --topology /etc/aster-network/topology.json
aster-network apply --config /etc/aster-network/config.json --topology /etc/aster-network/topology.json --confirm-bridge aster-vpc
aster-network status --config /etc/aster-network/config.json
aster-network verify --config /etc/aster-network/config.json
aster-network fingerprint --config /etc/aster-network/config.json
```

`verify` is a separate **root-only live readback**, accepting only the fixed
private config (no alternate topology, revision, bridge or remote target). It
requires the journal's current final revision to be applied, with no unresolved
history, and compares its compiled plan with the private desired-flow file and
current bridge ownership, TAP/interface UUID mapping, exact flows and meters.
Before/middle/after identity snapshots must agree. All OpenFlow reads use
`--read-only`, backed by a second command/argument allowlist. Missing files,
lost flows/meters after an OVS restart, changed identities, read errors and any
uncertainty return failure with no populated live result. It never creates or
updates journals/files, applies flows, repairs meters or quarantines ports.

The returned `aster.fabric.live/1` observation binds the current revision,
topology digest and hashed identity map to its observation time. It is **not** a
signed attestation, durable lease, atomic cross-system snapshot, permanent VM
start permit, internet-connectivity test or billing success. Another root writer
can change the host after readback. Only the embedded quiescent admission gate, together with the node's explicit
network contract and ownership checks, may use it within a start/resume transition.


## Embedded lifecycle admission

`Executor.Inspect(ctx)` checks read-only bridge prerequisites without creating
a journal, including the first empty bridge. Existing unresolved journal state
blocks readiness; inspection does not prove applied rules or guest connectivity.

`Executor.Activate(ctx, ActivationIntent, bootstrap, release)` holds a single
exclusive cross-process flock across the **entire** transition. A schema-2
write-ahead activation record binds the exact operation/request hash and copied,
canonical full-node port intent. An interrupted/uncertain record blocks further
apply/activate/deactivate and live status verification. Older schema-1 binaries
reject schema 2 instead of silently discarding its admission fence. Existing
schema-1 CLI journals remain readable by the new executable.

The gate proves the configured dedicated bridge and flow ownership, installs
and reads back whole-bridge drop before `bootstrap`. The trusted compiled node
callback must independently verify its domain and start it paused with link down;
there is no shell callback. `TAPName(instance)` is a deterministic 15-byte `ast`
name (prefix collisions are rejected across the supplied inventory),
`DomainID(instance)` and `InterfaceID(instance)` are distinct name-derived
UUIDv8 values. The node must pin all three and the MAC in its domain XML.

After bootstrap the gate verifies real kernel TAP type, exact bridge membership,
name, libvirt `iface-id`, `attached-mac`, `vm-id` and active interface status.
Only the target's missing aster labels may be added with a fixed `set Interface`
command; conflicting labels are never adopted. No bridge/NIC is created or
moved. All current ofports are then freshly resolved under isolation. They are
not request identity or approval fields. Source/destination meters and flows
are applied, read back and checked against the full stable identity map before
`release` may set link up and resume the independently owned paused VM. The lock
remains held through the callback, a second live verification and durable
completion. No historical receipt skips this sequence; replay never reruns a
callback or yields a cached live permit.

`PortIntent.Enabled=false` retains exact identity validation for a present
uncertain/stopped peer but produces no allow flow or meter. Missing enabled
running peers fail closed. An invalid target, unknown TAP, foreign interface,
changed map, command/storage error or callback error/panic never triggers automatic
resume. After programming/possible release, failure attempts one bounded
whole-bridge safety quarantine, records uncertainty and returns no live proof.
The node must independently return its target to paused/link-down state on any
failure: the fabric does not issue hypervisor commands. Other guests on the
explicitly exclusive bridge are interrupted by quarantine too.

`Deactivate(ctx, intent, stop)` requires the target disabled, isolates before
its trusted stop/delete callback, then requires that target TAP **absent** and
rebuilds only remaining confirmed-running peers. This removes stale ofport
allow rules before shutdown/deletion can make an ofport reusable.
`Check(ctx, intent)` is a shared-lock, `--read-only` verification of the currently
applied exact bindings for an already-running target; it never applies or repairs.
`fingerprint` emits only canonical config SHA-256 (`json.Marshal(Config)`), node
ID and protocol, so separately root-approved node/controller profiles can pin the
same config without exposing its path. The local profile map, not network input,
selects the protected config file.

The original ActivationIntent contract provides single-host, static private IPv4 peer networking only. It does
not add gateway reachability, NAT, DHCP, Internet access, underlay/tunnel peers or
cross-node routing. The fake-runner tests are not real OVS/KVM traffic acceptance.

## Model and limits

Topology schema 1 contains `node_id`, positive monotonic int64 `revision`,
`vpcs`, and `ports`. VPC fields are `id`, `owner_ref` (32 lowercase hex), canonical
private IPv4 `cidr`, and globally unique `vlan_id` 1–4094. Each port has
`instance_id`, deterministic `interface_id`, `owner_ref`, `vpc_id`, `ipv4`, `mac`,
`ofport` 1–32767, and positive `inbound_mbps` / `outbound_mbps` (at most 100000).
One private IP per port; 32 VPCs / 128 ports per bridge. IP uniqueness is per VPC;
VPC ownership, unique instance/MAC/ofport and subnet/broadcast checks are strict.

The compiler permits only exact source IPv4/MAC and ARP sender tuples, then
uses a VPC-specific OpenFlow metadata label to direct packets to the same VPC's
exact target IP/MAC. ARP requests are directed to a known peer, never flooded.
Tagged frames, IPv6, unknown protocols, unknown IPs and LOCAL traffic drop.
OVSDB VLAN tags do **not** provide isolation for explicit OpenFlow outputs.

Each guest's source-egress and destination-ingress meter is a drop policer,
`Mbps * 1000` kilobits/second, **not a queued shaper or billing traffic quota**.
No gateway/router, NAT, DHCP, DNS service, IPv6, security-group statefulness,
cross-node overlay is supplied by topology schema 1 alone; explicit overlay
configuration and the embedded lifecycle integration provide separate contracts.

## Failure semantics

Exclusive flock and write-ahead intent precede dataplane mutation. Private
temporary file + file fsync + rename + directory fsync are used. The durable lock
inode also prevents silently reinitializing a missing first journal. First
replace the entire exclusive bridge with drop-only flows, then update meters,
then replace desired flows atomically; meters, flow differences and stable
identity maps are read back. Upstream OVS bundles require **OpenFlow14 transport**
even though these match/meter instructions use OpenFlow13 semantics. Bundle
commit acknowledgement supplies its completion barrier; no fictitious standalone
`ovs-ofctl barrier` command is issued.

Any failure is unconfirmed, not success. When a mapping changes after allow flows,
one bounded quarantine operation replaces them with drop-only rules; failed
quarantine is explicitly `isolation_unconfirmed`. That is a safety operation,
not a retry of the requested apply. Foreign rules/controllers are not adopted.
After the bridge's exclusive root approval is proven and flow ownership is
confirmed, `apply` may quarantine the **entire bridge**, including unknown TAP,
physical or tunnel interfaces discovered during later probing. This disrupts
every guest port on that bridge; an unknown port does not promise zero writes.
This disruptive policy is only for the explicitly confirmed dedicated bridge,
never host/public bridges. `verify` does not perform this quarantine.
The same revision/digest returns its original receipt without executing commands;
changed reuse conflicts. Any uncertain/interrupted record blocks new revisions.
There is no automatic retry, bridge cleanup or journal reset. Explicit new
recovery operations are described in RECOVERY.md; they retain original unknown results.
Keep the state directory and perform independent root investigation before any
manual recovery; never delete its journal as a retry technique.

Receipts use bounded active pages with hash-linked immutable historical archives;
no history is silently pruned. Real OVS/KVM
traffic, host reboot, drop/limit accuracy and hostile port-race acceptance remain
required. The gate cannot fence an unrelated root writer that bypasses its lock.

Official references actually read:

- [OVS VLAN FAQ](https://docs.openvswitch.org/en/latest/faq/vlan/)
- [ovs-ofctl manual](https://www.openvswitch.org/support/dist-docs/ovs-ofctl.8.txt)
- [OVSDB schema / Interface identifiers](https://www.openvswitch.org/support/dist-docs/ovs-vswitchd.conf.db.5.txt)
- [OVS v2.17.0 ofctl implementation: read-only command flag and diff-flows](https://raw.githubusercontent.com/openvswitch/ovs/v2.17.0/utilities/ovs-ofctl.c)
- [Upstream meter formatter](https://github.com/openvswitch/ovs/blob/main/lib/ofp-meter.c) and [older multiline test format](https://mail.openvswitch.org/pipermail/ovs-dev/2023-April/403605.html). The v2.17 meter formatter itself could not be fetched during this review; these source checks do not replace an installed Ubuntu22 package test.

Additional official bootstrap references actually read: [libvirt Domain XML](https://libvirt.org/formatdomain.html), [virsh start](https://www.libvirt.org/manpages/virsh.html#start), and [libvirt v8.0.0 OVS interface identity initialization](https://raw.githubusercontent.com/libvirt/libvirt/v8.0.0/src/util/virnetdevopenvswitch.c). A paused start may fall back to running with unsupported drivers: independent link-down plus bridge quarantine and an observed paused-state check are mandatory.

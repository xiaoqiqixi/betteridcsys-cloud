# Durable network history and explicit recovery

This is the **single-host** `ActivationIntent` recovery contract. The overlay
protocol has its own cluster-epoch recovery, under the same bridge lock. A
schema-3 journal field records the current root-approved overlay profile digest as a
mode tombstone, independently of `overlay.owner`. Deleting the overlay head
cannot enable old mutation/live-proof paths. Recovery never removes this pin.

## No 64-change lifetime limit

Schema 1 and 2 are read-compatible. Before the active journal reaches 32 complete
records or activations, the executor writes its canonical bytes into a private
`history-<sha256>.json`, fsyncs the file and directory, then atomically switches to
a schema-3 live journal with that hash as its archive head. The current applied
record is retained for live verification. Every previous page remains chained,
including full port identities, topology, request digests, timestamps and results.
The old 64-item check now protects each decoded page; it is not a lifetime count.

* Old revision replay returns the **exact historical receipt**, without host calls.
* Reusing an old activation or recovery ID fails before host commands, even after
  checkpoints and process restarts. A historical receipt is never a start permit.
* Pages are immutable; a missing, corrupted, nonprivate, linked or reordered page
  rejects the ledger. No history is pruned or assumed successful.
* Write/fsync/rename failures stop before a new network mutation. A crash-created
  orphan page can only be reused after an exact-byte, private-file check.
* The state directory must be backed up and restored **as one complete set**.
  Never remove history pages or restore only `journal.json`. Monitor free space;
  storage failure still fails closed rather than dropping replay protection.
* Validation currently walks the complete hash chain on open, so open cost and
  memory grow with retained history. This removes the arbitrary 64-change outage,
  not the need to capacity-plan storage and very long-lived journal validation.

## Explicit recovery API

1. Read `RecoveryStatus(config)`. It changes nothing and returns the canonical
   journal digest, most recent active operation/intent digest, and last topology
   revision/digest (zero/empty before a first topology).
2. Submit a **new** `RecoveryIntent.OperationID`, request digest, those exact
   expected values, and the complete independently approved same-bridge inventory
   as `RecoveryIntent.Intent`. Do not supply cached ofports. Changing any expected
   value or reusing any operation ID is a conflict, before a host-side effect.
3. `Executor.Recover(ctx, intent, fence, release)` takes the bridge's exclusive
   flock. It verifies root-approved bridge ownership, archives the old journal
   unchanged, writes a new pending recovery linked to that exact hash, and installs
   and reads back whole-bridge DROP.
4. The trusted compiled `fence` callback independently verifies every domain's
   ownership and persistent link-down/no-autostart/no-managed-save policy, disables
   NIC transmission and pauses all active guests. It must not rerun create/start,
   shutdown, destroy, payment or storage actions. Disabled members stay disabled.
5. The executor discovers current kernel TAPs and exact libvirt/owner identities,
   derives fresh ofports and a strictly higher revision, rebuilds meters/flows and
   verifies complete live readback. Only a target with exact libvirt identity may
   receive missing Aster labels left by a bootstrap crash; conflicting labels,
   foreign ports and missing enabled targets fail closed.
6. The trusted `release` callback may resume only the explicitly enabled, owned,
   fenced guests. A second live readback and durable completed recovery record are
   required before success. Every callback occurs at most once.

The old failed activation and topology receipts are **not rewritten as success**.
The new operation is the evidence that current networking was restored. A crash,
callback panic, lost acknowledgement or persistence failure leaves pending or
uncertain recovery and a bounded best-effort DROP; no live proof is returned.
After inspecting actual state, an operator can obtain a fresh expectation and
approve a new recovery operation. There is no automatic retry, hidden rollback,
VM recreation, bridge adoption or management/uplink reconfiguration.

Fake-runner tests cover more than 64 revisions and lifecycle transitions, restart
replay, archive corruption and storage boundaries, every recovery command failure,
callback panic/cancellation boundaries and dynamic ofport reconstruction. They do
not substitute for real Ubuntu22+/OVS/KVM traffic, interruption and recovery tests.

## Native OVS parser/encoder gate

`TestNativeOVSParserFlows` executes the installed distribution `ovs-ofctl` against
production-compiled single-host, cross-node, local/remote gateway and maximum
VNI/port fixtures. It requires successful OpenFlow14 parsing **and** encoding of
every flow, plus rejection of a malformed negative control. The upstream 2.17
[test command implementation](https://github.com/openvswitch/ovs/blob/v2.17.0/utilities/ovs-ofctl.c)
provides offline `parse-flows`; no switch or daemon is needed.

`TestNativeOVSParserMeters` invokes the real `ovs-ofctl add-meter` parser and
encoder, but connects it only to a private, temporary Unix test peer. That peer
validates the actual OpenFlow14 METER_MOD ID, kbps/stats flags, drop band, rate and
barrier completion. A connection failure or timeout is **not** success. This is
parser/encoder interoperability, not a claim that a real dataplane enforces the
meter. Wire fields are checked against the upstream
[OpenFlow 1.3/1.4 meter definitions](https://github.com/openvswitch/ovs/blob/v2.17.0/include/openflow/openflow-1.3.h).

The required Ubuntu22/24 `native-ovs-parser` CI matrix installs only
`openvswitch-common`, starts no OVS daemon and changes no host interfaces. It sets
`ASTER_NATIVE_OVS_PARSER=1` and rejects missing binaries and skipped tests. Ordinary
non-Linux unit runs explicitly skip these two native-only tests. An independently
unpacked native binary can be selected for isolated acceptance using
`ASTER_TEST_OVS_OFCTL=/absolute/path/to/ovs-ofctl`; production code cannot use this
test override.

## Node-ledger completion and rollback boundary

A fabric proof and a root-private `*.result.json` alone are not completion of the
node recovery. The node preserves the complete original operations/inventory in
immutable intent evidence and writes its result evidence with file and directory
fsync. It then atomically commits **one node journal transaction** containing:

* every explicitly resolved old operation and its exact final instance state;
* a distinct new recovery ID and profile, request/intent/result SHA-256 digests;
* the original operation-set digest and the complete resulting operation set.

This also happens when all original tasks were already successful (for example,
an OVS-restart repair), or an overlay recovery has no pending VM operations.
Pre-existing success cannot substitute for the new recovery's receipt. Failed
saves restore the old in-memory maps and poison admission. Missing completion,
changed evidence, ID collisions, ambiguous JSON and incomplete groups never
return recovery success or rerun old VM mutations; they require fresh inspection
and a newly approved operation. A successfully recovered task and its completion
receipt cannot be separated by a second "write marker" crash window.

The first such transaction upgrades the **node** journal to schema 4. Older
binaries accept only schemas 1–3 and deliberately refuse schema 4, rather than
silently dropping the new receipts. Back up node state, immutable recovery
intent/result evidence, fabric journal/archive pages, and approved configuration
as a consistent set. Do not downgrade or hand-edit the journal. A rollback to an
older binary requires its compatible full pre-upgrade backup, with guests fenced
and actual host state reconciled separately; restoring bookkeeping does not undo
OVS or VM side effects. Receipt capacity uses the existing explicit node-journal
byte bound; no receipt is silently evicted to make room.

A replay is an exact **historical** result, not evidence that a guest is currently
running or that current OVS forwarding is healthy. If a save/ack was interrupted
but a complete atomic transaction survives reopening, the stored receipt may be
read without repeating any host mutation. Starting or resuming guests still
requires the separate fresh live safety checks.

Root profile migrations (including namespace NAT approvals) require explicit
previous SHA approvals and an exact-head recovery prepare. See [NAT.md](NAT.md)
for immutable migration evidence, NAT ownership tombstones and inode replacement
requirements. Ordinary epochs cannot change the current full profile pin.

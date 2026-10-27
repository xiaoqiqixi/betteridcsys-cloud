# Aster native KVM node — development vertical slice

This is a **local libvirt/KVM host executor**, not an SSH/root-command relay. It
is separate from billing and the controller. No VM host, deployment or network
acceptance is claimed. The operator explicitly deferred real-host acceptance.

## Supported boundary

- Native **x86_64 Ubuntu 22.04+** policy target, Go standard library, no Docker,
  Redis, guest password, remote SSH command or shell execution. Ubuntu 24/26
  compatibility is a target, **not tested certification**. Other distributions /
  architectures are not advertised. The doctor reports actual prerequisites.
- Real fixed binaries: `/usr/bin/virsh`, `/usr/bin/qemu-img`,
  `/usr/bin/qemu-system-x86_64`, and, for static networking,
  `/usr/bin/cloud-localds`. Commands have fixed argument structure, bounded
  output/context and no shell. QEMU/libvirt distribution security updates,
  AppArmor storage policy, certificates and host routing remain operator duties.
- Flat SHA-approved qcow2 base image; no backing image/data-file chain; overlay
  virtual size must fit the requested system disk. Bases must remain immutable
  for the full lifetime of all backing overlays, not just during initial hashing.
- CPU, memory (128 MiB steps), system disk, configured image/storage, legacy
  normal network or separately pinned single-host OVS private IPv4 profile.
  No routed/cross-node VPC, data disks, IPv6, queue shaping or transfer metering.
  **Every unsupported resource is rejected**, never ignored or downgraded.
- Zero bandwidth/transfer is allowed **only** with `allow_unmetered_default=true`:
  it means an approved unmetered/default network, NOT an enforced quota of zero.
- Network disabled by default. Optional isolated no-NIC profile is separate from
  the real normal-static-ipv4 profile and is never advertised as one allocated IP.
- Positive static network profile: **exactly one IPv4 / zero IPv6**, durable pool
  reservation, approved dedicated preconfigured bridge, deterministic MAC,
  isolated bridge port, pinned self-contained anti-spoof/default-deny nwfilter,
  NoCloud ISO containing static network config and approved Ed25519 public keys.
  No host bridge/routing/firewall/filter is automatically created or changed.

## Security and lifecycle

Only mTLS (TLS >=1.2), verified CA **plus exact approved controller leaf DER
SHA256** can use any endpoint, including health. A certificate issued by the same
CA but not pinned is rejected. Loopback literal IP is default; non-loopback bind
requires explicit approval and operator firewall policy. There is no plaintext
HTTP public endpoint, HTTP proxy, SSH relay or arbitrary command option.

Node JSON configuration is private root-owned `0600`. State is root-owned `0700`;
keys/journal/lock `0600`; approved images and storage must not be group/other
writable. Every existing ancestor must be root/euid owned and non-writable to
others (a root-owned sticky temporary ancestor alone is permitted). Symlinks and
hardlinked ordinary files are refused. Approved file reads use O_NOFOLLOW and
opened-inode checks; certificate/config reads are bounded. Image hashing checks
size/identity, cancellation and root-approved digest; arbitrary root mutation of
approved paths is outside the isolation boundary.

All operations require 32 lowercase hex operation/instance/owner IDs. Domains are
named `aster-<instance_id>` and require namespace ownership metadata and matching
managed disks/NIC/filter. Domain `0` is never a target. Before any create disk or
libvirt define, a **successful full domain inventory** must confirm the derived
name is absent; a pre-existing domain is never adopted/redefined. Libvirt and the
node must not be independently writing the same names/storage concurrently.

POST `/v1/tasks` carries the exact JSON bytes and `X-Request-SHA256`. The journal
fsyncs the operation claim and create reservation **before returning 202 and
before executing any host command**. Power mutations durably quarantine the
instance before execution. Same operation/same raw bytes returns the saved
result without re-execution; any changed raw bytes (including whitespace) gives
HTTP 409. The controller must persist the raw body and, if a response is lost,
**only GET the original operation**. There are no automatic POST retries.

One detached worker runs at a time (10-minute upper bound). A different operation
while busy is durably rejected; there is no queue. HTTP disconnect/cancellation
does not cancel an accepted operation. Graceful shutdown cancels the worker and
waits for a conservative terminal journal update; crash/restart turns accepted
into uncertain and does not replay. This is intentionally a **single-process,
low-throughput node**. Exclusive flock prevents concurrent node processes. The
journal is atomically renamed and fsynced, bounded to 64 MiB on both save/load;
capacity/write failure stops further admission. No pruning/HA replication or
hot-state migration is implemented; retain the journal and alert on growth.

Unknown outcomes retain disk/address reservations, are never automatically
rolled back or retried, and block further mutations on that instance. Successful
create means **libvirt reports the owned domain running** (and, for OVS, the
exact gate completed), not that guest boot,
SSH, public networking or a billing-service activation succeeded. Reboot command
acknowledgement remains uncertain because state=running cannot prove a reboot.

Delete is disabled by default, additionally requires the exact confirmation ID,
verified owned live XML and shut-off state. It undefines without libvirt's bulk
storage deletion and removes only registered files; unknown contents are not
recursively deleted. Failure is uncertain; never remove the private journal to
"fix" it, nor release reservations without verifying the original resources.

Safe structured operation metadata (IDs, action/status, request digest, stable
error code and journal-write confirmation) is emitted for journald; full tasks,
certificates, SSH keys, seed content and subprocess output are not logged. The
private journal retains operation status/timestamps/error codes. Production log
shipping, retention, alerting and append-only external audit are **not supplied**.

## Native operator preparation (manual, no installer side effects)

Examples: `deploy/node-config.example.json`, `deploy/node-aster-node.service`,
`deploy/node-static-ipv4-filter.example.xml`. Placeholders deliberately fail
validation. Review and replace every approval; do not deploy the example IP pool
(192.0.2.0/24 is documentation space). Start in maintenance with networking off.
Use real root-owned directories such as `/var/lib/aster-node`,
`/var/lib/aster-instances` and `/var/lib/aster-images` (the state/storage directories
must be separate). Establish certificates out of band. Pin the client certificate
DER SHA256, not its PEM text or CA. Review server SAN and controller endpoint pins.

For networking, first configure and externally validate a **dedicated routed
bridge** with no unrelated/unisolated guests, routing, gateway, upstream return
routes, host access policy and address ownership. Review/define the supplied
filter manually in the host's libvirt system. Pin SHA256 of the **exact stdout** of
`virsh --connect qemu:///system nwfilter-dumpxml aster-static-ipv4`; generated UUID
and whitespace change that digest. The node also compares the parsed policy with
its self-contained required template, allowing only formatting and root UUID.
Every rule uses one protocol element, no transitive filters. Root checked the
current template against the official **libvirt 8.0.0 RelaxNG schema**; this proves
schema syntax only, **not packet filtering behavior**.

Libvirt's isolated bridge port only isolates other similarly isolated ports.
It does not isolate host services or unrelated bridge peers and is **not a tenant
security group**. The template explicitly drops VLAN/QinQ/IPv6, filters outgoing
MAC/IPv4/ARP spoofing, permits ARP/IPv4 and defaults other Ethernet traffic to drop.
Actual enforcement, ebtables/nft backend behavior, encapsulation, routed traffic,
ARP, intra-tenant/host access and upstream anti-spoofing **must still be validated
on a real host with packet captures** before enabling the profile for customers.
See [libvirt filter documentation](https://libvirt.org/formatnwfilter.html) and
[domain interface documentation](https://libvirt.org/formatdomain.html).

Read-only readiness (no package installation, VM or network mutation):

```sh
/usr/local/sbin/aster-node --config /etc/aster-node/node.json --doctor
```

Doctor checks Ubuntu version/architecture, CPU virtualization flags, /dev/kvm
permissions, fixed tools, storage, libvirt read-only inventory, and (if enabled)
bridge/filter/seed tooling. `ready=false` is a real failure, not a successful KVM
test. `/healthz` merely means the authenticated process responds, not host ready.
Capabilities have actual UTC sampling time and host capacity bounded by root
allocation ceilings; incomplete doctor checks advertise maintenance/no actions.

Only after reviewing doctor evidence and maintenance/capabilities, manually
install the reviewed systemd unit and binary. The example unit's filesystem and
libvirt/AppArmor compatibility, restart behavior and all distro variants remain
unverified. No `curl | bash`, automatic apt, Docker or host-network modification
is included.

### Recover an uncertain operation without repeating a write

Stop the node service first (exclusive journal). Back up its private journal.
The root-only command below reads owned XML and state, never defines/starts/
destroys/undefines a domain. It can mark original create/start/shutdown/force_off
succeeded only when ownership and the original target state are proved. It
updates only the original local operation/instance and records a reconciliation
code. On mismatch/missing domain it retains uncertainty; reboot/delete cannot be
proved by this command. Start service again; the controller then GETs the same
operation. No automatic operator command or HTTP reconciliation write is exposed.

```sh
/usr/local/sbin/aster-node --config /etc/aster-node/node.json \
  --reconcile-operation 0123456789abcdef0123456789abcdef
```

## Build / regression

From the `aster-cloud` module with its local `aster/billing` replace present:

Use the CI-pinned Go 1.27.3 toolchain for current builds and vulnerability
checks (`export GOTOOLCHAIN=go1.27.3`). The module language version does not
guarantee that an older Go standard library has received security patches.

```sh
GOCACHE=/private/tmp/aster-node-gocache go test -race -count=1 \
  ./internal/nodeproto ./internal/hypervisor ./cmd/aster-node
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
  GOCACHE=/private/tmp/aster-node-gocache go build -trimpath \
  -o /private/tmp/aster-node-linux-amd64 ./cmd/aster-node
```

Tests use synthetic image content and fake libvirt/qemu/seed commands. They cover
real JSON/exact hashing, journal persistence/lock/filesystem guards, async
admission, HTTP cancellation, concurrent duplicate suppression, failures,
unsupported resources, existing domains, owned-XML checks, delete/reconcile
and TLS handshakes over `net.Pipe` (real Go TLS without a listening socket).
`internal/nodeproto/testdata/capabilities-approved-static-ipv4.json` is explicitly
a synthetic controller-contract fixture, never evidence of a measured host.

**Not acceptance-tested:** actual QEMU/libvirt VM creation/boot, qemu file ownership
and AppArmor, cloud-init SSH/static address behavior, bridge/upstream routing,
packet isolation/anti-spoofing, real reboot lifecycle, delete/recovery failure
injection, capacity under load, systemd/TLS deployment, host backup/restore,
upgrade/rollback or a real customer provisioning/billing activation end-to-end.
No production release or production-grade KVM completion is asserted.

## Offline storage operations and cold migration (new development implementation)

The independent wire protocol is `aster.node.storage/1`; the existing
`aster.node/1` power/create contract and strict decoder are unchanged. The new
mTLS-only endpoints are `POST /v1/storage-tasks` and
`GET /v1/storage-tasks/<operation_id>`. Requests contain only typed IDs, exact
manifest/fence bindings and explicit destructive confirmations, never paths,
URLs, shell fragments, imported XML or a `source_fenced=true` assertion. Exact
raw-body SHA/idempotency, durable pre-execution claim, shared single worker slot,
terminal-visibility barrier, unknown-result retention and no automatic replays
apply across **both** protocols. File transport shares that admission slot and
releases it before exposing its completed receipt.

Implemented actions:

- `snapshot_create/list/restore/delete`: independent full qcow2 copies, **not**
  internal live QEMU snapshots, VM RAM snapshots or incremental snapshots.
- `backup_create/verify/restore/delete` and `backup_list`: offline full-copy
  backups, bound to the original node/instance/owner/hostname/resources/base
  image approval. Restore targets the **same existing, owned, shut-off VM**;
  creating a replacement VM after deleting its journal/domain is not implemented.
- `migrate_prepare/import/activate`: explicit cold migration stages described
  below; no hot migration, shared storage or running-guest disk copying.

All disk-affecting operations freshly check complete owned XML and libvirt
`shut off` before any qemu-img access. Snapshots/backups flatten the existing
approved system-disk chain using qemu-img convert. The manifest records SHA256,
physical byte length, virtual size, source identity/resources, approved image
SHA and timestamp, signed by the node TLS signing key. Verification requires
canonical complete metadata, expected private-journal manifest digest, exact
bytes/size, independent qcow2 geometry and qemu-img check. Missing metadata,
symlink/hardlink paths, unexpected backing/data files, owner mismatch and corrupt
content are rejected. Before invoking qemu-img on storage/inbox data, a bounded
parser of the [official qcow2 header](https://www.qemu.org/docs/master/interop/qcow2.html)
refuses backing references (except the exact approved source base), external
file/encryption/bitmap extensions and incompatible/dirty/corrupt features.
**qemu-img exit 0 alone is never a recovery claim.** Guest boot/app-data recovery
still needs real-VM acceptance.

Restore records its intent and previous-disk SHA/size in the private journal,
copies/verifies/fsyncs a replacement, durably hardlinks the previous inode, then
atomically renames the new disk onto the active name. There is no missing-active-
path window. Previous copies are retained and budgeted; failure at either side of
the swap is uncertain, retains recovery information, never auto-starts a VM and
never automatically deletes/retries/rolls back. Registered recovery copies are
verified before an explicitly permitted later VM deletion; unknown directory
contents cause rejection **before** undefine or disk removal. Full-copy artifact,
transfer and preserved-disk budgets are separate from financial disk quantities.
No retention scheduler, pruning, at-rest encryption or external backup storage is
claimed. Operators must provision protected storage, monitor usage and preserve
approved base images required by old retained overlays.

### Safe journal upgrade / no silent downgrade

The new node reads existing schema 1 journals. First durable storage or inbox use
upgrades to **schema 2**, fsynced before further effects. Old schema-1-only node
binaries refuse schema 2 instead of ignoring permanent source fences. Do not
roll an active storage node back to an old binary, delete its journal or edit the
schema number: that can discard fencing/ownership and permit double activation.
Preserve the entire private state alongside definitions, disks and immutable
bases. Downgrading or restoring an older state requires an independently reviewed
host-fencing/recovery plan; it is not an automatic supported rollback.

### Cold migration sequence and trust boundary

1. Shut the source VM off through its original power operation and verify outcome.
   Prepare requires owned inactive XML, successful read-only autostart inventory
   proving the VM is **not** set to autostart, and configured storage/migration
   approvals. The node durably records a permanent source fence/token **before**
   exporting. Its normal power/create/storage APIs cannot clear that fence or
   restart the source. A failed/interrupted export keeps the source fenced.
2. Prepare writes a self-contained flat disk and signed target-bound manifest.
   The signature covers source operation, instance/owner, full specifications,
   disk/image hashes, target node and fence token. No external XML is used.
3. Deliver to a target's protected inbox using one of the reviewed modes below.
   Merely copying/uploading data never defines or starts any VM.
4. Target independently verifies source certificate pin/signature, target/owner/
   instance/fence/manifest bindings, protected files and target root approval.
   Import reserves target CPU/RAM/disk/IP under its own approved profile, copies
   and verifies the disk, generates a target-local NoCloud seed, reconstructs XML
   from **target** configuration, defines the owned domain inactive and records
   the imported instance/target binding in the journal. Physical placement fields
   (node/DC/group/storage) become target-local; source history stays in the signed
   manifest. No finance amount/currency/historical snapshot is rewritten.
5. Activate is separate, confirmed and requires the same proof/approval, imported
   binding, fresh owned off state, exact disk hash/geometry and target network
   prerequisites. Only then may it start. An unknown activation blocks further
   starts and is not automatically retried. Source resources remain retained and
   fenced; target activation does not authorize deleting source disks.

Fencing here controls **this node's APIs** and checks source autostart. It is not
hardware power fencing against root, another orchestrator, journal rollback or
an operator manually running virsh. Dedicated operator ownership of these domain
names and storage is required. Root must not un-fence/start the source outside
this protocol. Real crash/reboot/dual-start prevention remains an acceptance item;
no distributed hardware-fencing certification is asserted.

### Protected offline handoff / root CLI approval (default)

`storage.enabled` and `storage.allow_migration` are explicit root configuration.
Artifacts and inbox roots must be separate private root-owned `0700` directories;
files are private `0600`. The source node TLS **leaf DER SHA256** must be mapped
under the source node ID in the target's `storage.source_certificate_pins`.
Choose unique node signing identities and preserve/plan certificate rotation.

After verifying source off state, permanent fence, no autostart and exclusive
operator ownership, an operator securely delivers only `manifest.json` and
`disk.qcow2` to `<approved-inbox>/<artifact_id>/` (a private `0700` directory).
Never copy or execute foreign domain XML. Stop the target service/exclusively lock
its journal and explicitly attest the independently inspected source fence:

```sh
/usr/local/sbin/aster-node --config /etc/aster-node/node.json \
  --approve-storage-import 0123456789abcdef0123456789abcdef \
  --reviewed-source-fence 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

The root CLI validates the source proof and actual flat disk, signs a protected
**target-bound** `approval.json`, fsyncs it, and does **not** define/start a VM.
Empty/malformed/partial approval flags are rejected before configuration or I/O;
approval, doctor and reconciliation modes are mutually exclusive. The token is a
binding, not a substitute for independent source-fence verification.

### Opt-in pinned-mTLS controller relay (no arbitrary network endpoint)

The same fixed approved controller TLS certificate is required for every route:

- Source `GET /v1/storage-artifacts/<id>/manifest|disk`: only available migration
  exports with matching persistent source fence and fresh owned off/no-autostart
  state. Streams exact `Content-Length`, `X-Content-SHA256` for raw file bytes and
  `X-Manifest-SHA256` for canonical manifest identity.
- Target `PUT /v1/storage-inbox/<id>/manifest|disk`: manifest first; requires exact
  Content-Length, `X-Content-SHA256` and a 32-hex `X-Transfer-ID` permanently bound
  to the artifact. No chunked/unknown-size uploads, URLs, user paths or overwrite
  of other bytes. Source pins/target identity/image/file budgets are checked.
  Private O_EXCL partial files are hashed/fsynced, disks independently checked,
  and final names committed atomically without clobbering existing files.
- Target `GET /v1/storage-inbox/<id>/manifest|disk` with the same transfer header:
  returns a typed file receipt, not disk bytes. Only a genuinely absent file
  record is 404; a receiving/partial/uncertain file remains a 200 uncertain receipt.
  Wrong transfer binding is 409, never absence. Same ID/digest cannot silently
  replace partial or different content. A lost response is followed only by GET
  verification; a complete committed exact file can be recognized, while partial
  data requires explicit operator inspection, not automatic upload retries.
- Target `POST /v1/storage-inbox/<id>/approve`: disabled by default. Only root's
  `storage.allow_controller_inbox_approval=true`, migration enablement and approved
  source pins permit this mode. Typed body binds transfer/artifact/source op/
  instance/owner/target/manifest/fence. Target rechecks both full files and source
  proof, persists an approval-in-progress marker before signing, and issues a
  distinct controller-attested target approval. **No VM import/start occurs.**
- Target `GET /v1/storage-inbox/<id>/approval`: read-only proof/receipt query.
  Missing and never-requested approval is 404; an approval-in-progress marker or
  invalid/incomplete approval is uncertain, never disguised as absence. GET
  cannot sign or create an approval. Success reports file=approval/status=approved
  and the verified disk SHA/length bindings.

The fixed controller's relay must use its approved source/target endpoints and
certificates, no redirects/proxy/arbitrary URLs, and the dedicated bounded stream
client rather than a 10-second metadata RPC timeout. Transfers have bounded
20-minute stream deadlines and size budgets. Explicit controller approval is a
root trust-policy opt-in, not a web user's `source_fenced` assertion. Default mode
continues requiring the independently reviewed root CLI handoff.

### Fresh instance observation

`GET /v1/instances/<32hex-id>` is pinned-mTLS read-only and returns protocol
`aster.node.instance/1`, node/instance/owner/hostname, fresh libvirt state,
verified configured IPv4/MAC, observed UTC time, source_fenced and target_pending.
It holds admission against new writers, checks complete owned XML and fresh
libvirt state, and refuses busy/reserved/uncertain/unresolved instances rather
than presenting cached state as current. No paths, seeds, private keys or fence
tokens are returned. Observation never resolves a pending operation or changes
billing/financial status.

**Storage/relay/migration are implemented and fake/filesystem/TLS regression
verified, not real KVM acceptance.** Required future tests include actual flat
image validity, VM/application recovery after restore, disk ownership/AppArmor,
NoCloud and target IP/network behavior, source host reboot/autostart/fencing,
mid-copy disk-full/fsync/crash cases, large real mTLS transfer interruption,
certificate rotation, cold migration activation/dual-start checks and schema-2
backup/upgrade/recovery. Do not claim a copied file or green unit test proves a
recoverable production VM.

### Read-only instance metrics

`GET /v1/instances/<32hex-id>/metrics` uses the same pinned controller mTLS
identity. It serializes with node workers, verifies the owned domain XML and
fresh libvirt state, and invokes only fixed `virsh domstats` arguments for that
ledger-owned domain. Busy, reserved, uncertain, pending or unowned instances are
not sampled. It does not write journals, reconcile tasks, create a VM, retry a
mutation or change billing. Query parameters and non-GET methods are rejected.

The separate `aster.node.metrics/1` response includes identity, UTC observation
time, vCPU count and eight nullable decimal uint64 string counters: cumulative
CPU nanoseconds, QEMU RSS/current balloon/guest-reported unused KiB, system-disk
read/write bytes and domain-perspective network receive/transmit bytes. Only
owned `vda` and the single managed interface are counted; the seed CD-ROM and
host-wide totals are excluded. Unsupported fields are `null`, never synthetic
zeroes. RSS/balloon/unused values are not interchangeable and do not prove guest
memory utilization. Counters may reset at restart and are not billable transfer.

Parsing is bounded and refuses duplicate, malformed, overflow, cross-domain or
unexpected device data. Output never includes host disk paths or tap names.
Current tests cover deterministic runners and real pinned mTLS, not actual KVM
counter accuracy, guest-agent freshness or historical monitoring/alerts.


## OVS profile: integrated lifecycle, not an alternate CLI

New `aster.node/2` requests carry a strict immutable network binding: owner,
instance, node, lease/pool/VPC, private CIDR/IP, deterministic MAC/interface UUID,
VLAN metadata, positive ingress/egress Mbps, profile ID and canonical fabric
config SHA-256. Legacy `aster.node/1` bytes and behavior are unchanged. The
controller reserves IPAM and stores the binding in the same transaction as the
instance and task; the node never selects a lease from a guessed current pool.
The financial request/digest, money, payment and sold product snapshots are not
rewritten. Profile IDs are local root approvals, not paths supplied by clients.

Review `deploy/node-ovs.example.json`, `deploy/fabric-private.example.json`,
`deploy/node-ovs.conf.example` and `deploy/controller-ovs.example.json` together.
Examples intentionally fail validation until every placeholder/approval is set.
The OVS-only example disables the unmetered legacy fallback. Before enabling:

1. Prepare and externally review an **empty dedicated** `aster-` OVS bridge,
   fail-mode secure, OpenFlow14, no controller/uplink/foreign port or flow, with
   required root OVS labels from [fabric README](internal/fabric/README.md).
   Do not move the SSH/public/finance NIC. No installer creates a bridge.
2. Protect the fabric config root:root 0600; its independent state directory is
   root:root 0700, outside node/storage/artifact/inbox roots. The optional systemd
   drop-in grants only that exact state directory write access. Keep node TLS,
   approved image SHA and Ed25519 keys under the existing ownership checks.
3. Read `aster-network fingerprint --config /etc/aster-node/fabric/private-v1.json`
   and pin the returned canonical config SHA in the matching controller profile.
   Raw file whitespace is not the fingerprint. Do not repurpose an existing sold
   preset: create a new versioned `ovs-vpc-...-v1` ID and matching owner/pool.
4. Run doctor read-only, then complete isolated host acceptance before sales.
   Empty bridge readiness does not prove VM network connectivity. Existing
   uncertain fabric state cannot be cleared by doctor or a historical receipt.

Creation defines a persistent **link-down** OVS NIC with fixed TAP/domain/interface
IDs and `on_reboot=destroy`. Under one fabric lock, the gate installs whole-bridge
drop, bootstraps `virsh start --paused`, verifies paused/link-down state, resolves
current TAP/ofport identities, applies and reads back exact isolation/meters,
then enables the live link and resumes. The lock stays through final verification
and durable completion. Ubuntu22 libvirt8 `domif-getlink/setlink` default to live
active-domain state; they have **no `--live` option**. Persistent link remains down.
An already-running start only checks the current gate; it never repairs/restarts.
A shut-off start repeats the new gate sequence, never reuses an old start permit.

Shutdown/force-off/drop-before-delete isolates first and confirms TAP disappearance
before rebuilding remaining known-running peers. This can briefly interrupt all
VMs on the approved bridge. Failures retain uncertainty/IP/disk reservations; a
failed activation additionally attempts bounded, ownership-checked link-down and
suspend, never destructive stop or repeated start. Failure of that safety attempt
is not isolation proof. Old power-only reconcile is refused for OVS. Direct
reboot and old storage/restore/migration contracts are refused: use explicit
shutdown then start, and do not use legacy restore as a network-gate bypass.

The original node/2 binding uses node journal schema 3. New explicit recovery
completion upgrades it to schema 4; the fabric archive and overlay mode pin use
fabric schema 3. Older binaries must reject unsupported schemas. The former
64-mutation lifetime cap is removed: 32-record active pages rotate into immutable
SHA-linked archives retaining all exact replay/conflict and unknown-state evidence.
Opening verifies the complete chain, so storage/I/O costs still grow with history.
Never delete journals or archives to unlock a failed bridge.

An independently root-approved `aster.overlay/1` contract now connects fixed-peer
VXLAN, full global-VPC epochs, constrained router-appliance forwarding and explicit
all-node recovery to VM creation/start/stop. New VM seed/XML use approved MTU and
routes; old immutable bindings/seeds are not rewritten. Separately approved
namespace SNAT/DNAT and public IPv4 egress now have real controller/UI intent,
three-phase execution and independent per-node root approvals; see
[public NAT egress](docs/PUBLIC_NAT_EGRESS.md). DHCP, floating IP allocation,
dynamic routing and real-host acceptance are not implied. The original
single-host contract stays unchanged when overlay is not configured. See
[network implementation and boundaries](docs/OVERLAY_DESIGN.md),
[deployment/recovery runbook](deploy/OVERLAY_OPERATIONS.md), and
[current validation](docs/NETWORK_RECOVERY_VALIDATION.md). Keep this development
slice off real customer nodes until the deferred KVM/OVS acceptance is complete.

## 托管直绑公网 IPv4（node/3，journal5）

新合同使用精确控制器租约，不再由被控 first-free 挑地址；迁移使用独立
`aster.node.storage/2`，保持 IP/MAC 与 source fence，显式退役后才允许回迁复用节点。
部署需要新精确 nwfilter、独立 routed public bridge、完整 Network SHA 和
`require_public_lease:true`。CLI 仅生成 XML：

```sh
aster-node --print-public-network-filter aster-public-ipv4 > /root/aster-public-ipv4.xml
```

须先停止相关 VM、人工审核/定义 filter，再 pin 实际 dumpxml SHA，不在运行中自动
替换规则或改宿主管理网。HOST_IPS 由节点完整探测并严格读回，变更不静默放开。
旧无租约公网 create/start/reboot 被禁，关机/清理仍保留；原 VM 仅支持停机同 IP/MAC
接管，不通过改 seed 冒充热换 IP。完整配置、恢复与升级备份边界见
[VM 公网管理](docs/VM_PUBLIC_IP_MANAGEMENT.md)。实际 KVM/上联和物理重启验收仍后置。

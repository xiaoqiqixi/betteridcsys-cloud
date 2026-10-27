# Root-approved namespace NAT

## What is implemented

`Snapshot.nat_policies` is optional and omitted from legacy canonical snapshots.
Each policy binds one VPC/gateway/node and one complete root NAT profile SHA-256.
It enables IPv4 SNAT and explicit TCP/UDP single-port DNAT to **enabled, frozen
members of that VPC**, including members on other overlay participants. NAT does
not alter the financial contract, original node/2 binding or an old snapshot.

Egress has two independent modes: **approved-prefix SNAT** and explicitly
approved **public IPv4 Internet SNAT**. Existing policies without
`internet_egress_enabled` keep their original canonical bytes and prefix-only
behavior. Internet egress does not insert `0.0.0.0/0` into the old route approval.
The root gateway's explicit destination prefixes still cannot overlap VPCs,
management, underlay, loopback, multicast or metadata ranges. A selected route
can narrow a root prefix or be removed. DNAT source prefixes must be contained
both in the root NAT source approval and selected gateway prefixes; enabling
Internet egress never grants unrestricted inbound DNAT. No IPv6 NAT, hairpin
NAT or ICMP DNAT is claimed. The node never configures public interface
addresses or physical uplinks automatically; controller IP-pool allocation is a
separate management ledger, not authority to change host network ownership.

The administrator uses the controller network UI to select approved gateways,
prefixes and NAT profiles, submit an epoch, inspect node phases and explicitly
recover an uncertain epoch. Root provisioning remains a separate host operation:
HTTP administrators cannot name a host interface, namespace path, arbitrary
command or unapproved public IP.

## Selected public IPs and controller allocation

`NATPolicy.public_ipv4` is an optional canonical public-unicast IPv4 selection.
Omission retains the profile's original `public_ipv4` default and **all original
snapshot/task bytes and hashes**. An explicit selection changes immutable new
intent; every approved-prefix SNAT, Internet SNAT and DNAT rule binds that exact
address. One local snapshot cannot bind the same effective address to two
policies, including a default/explicit collision, even if their root grants share
reserve addresses. VPC, node, gateway, profile ID and full profile SHA approvals
remain mandatory; another tenant's profile cannot be borrowed.

Root can additionally approve `NATProfile.public_ipv4s`, at most 64 entries.
The canonical grant is sorted/deduplicated, omits an empty list, rejects the
primary address and every NAT uplink address, and accepts only canonical public
IPv4 addresses outside protected management/underlay/VPC ranges. The unchanged
primary field retains compatibility with historical explicit-prefix profiles.
Changing this root list changes the NAT and overlay pins and requires the same
explicit previous-pin, exact-head recovery and ownership migration as other
root capability changes. Ordinary controller prepare cannot adopt it.

Before prepare, program, release and readiness checks, the node independently
proves namespace identity, veth ownership, MTU, addresses, routes and policy
rules. The outside IPv4 inventory must be a duplicate-free subset of the root
grant; **both primary and selected addresses must actually be configured**.
An approved reserve may stay unconfigured but cannot then be selected. The only
nonlocal routes are the exact VPC route, connected prefixes matching configured
outside addresses, and one default via the exact on-link approved uplink. Only
the three kernel policy-routing defaults are accepted. There is no command to
silently add/remove an address, alter a physical interface, change host routes,
or accept a missing/unreachable source as a successful allocation. Providers
must separately route those operator-owned addresses to the dedicated uplink.

All locally approved pool addresses, including unconfigured reserves, and all
explicit selected addresses in the snapshot join the Internet exclusion lists in
nftables and OVS. Existing separately root-approved
explicit prefixes/DNAT retain their narrower semantics and priority. A public-IP
switch or policy removal uses the full isolate/program/readback/release barriers
and flushes conntrack only in the dedicated namespace, revoking old mappings.
Old operation, snapshot and receipt files are not rewritten or recycled.

The existing mandatory Ubuntu22/24 Internet native gate now provisions a second
address inside isolated veth namespaces and checks exact TCP/UDP source identity,
selected TCP/UDP DNAT, address switching, old held-TCP revocation, old DNAT denial,
final unbinding, strict readback and an approved-but-unconfigured source reject.
It still does not contact the public Internet, use KVM/physical OVS, or establish
provider routing. Actual host/physical-public acceptance remains a separate gate.

## Public Internet egress

The private root NAT profile opts in with `allow_internet_egress: true`, which
requires `allow_snat: true` and a canonical public-unicast `public_ipv4` (not
RFC1918, shared/CGNAT, loopback, link-local, documentation, benchmarking,
multicast or other conservatively reserved ranges). Old profiles keep their
hashes because a false flag is omitted. The uplink is still prepared and pinned
by root; this approval does not allocate an address or prove that the provider
has routed it.

Every overlay participant also requires an exact root `guest_networks` entry
with `allow_internet_egress: true`, `vpc_id` equal to the selected overlay VPC,
and matching owner/CIDR/gateway. Local members additionally need their precise
local-VPC mapping approved. A remote participant cannot acquire a public
gateway merely from a controller request or another node's NAT approval.
Root guest-network seed approval can carry `dns_ipv4`; see the guest-network
contract. Existing installed guests are not silently rewritten by a network
epoch. Empty explicit `allowed_prefixes: []` remains empty: by itself it grants
no Internet access.

After this root provisioning/migration, the management UI can enable or disable
`internet_egress_enabled` on a selected SNAT policy, inspect its approval and
submit/recover the same three-phase epoch as other network changes. Internet
egress requires SNAT; disabling SNAT disables that policy's Internet permission.
The actual public source must belong to that exact root-approved profile; a
controller allocation or UI field alone cannot grant an address.

The new public path accepts member-initiated TCP, UDP and ICMP echo to public
IPv4 destinations outside all explicit gateway prefixes. It denies the shared
reserved-address floor **plus** root protected CIDRs, local/peer underlay IPs,
all snapshot VPC ranges and local NAT public/uplink interface addresses. Public
management addresses are protected too. The same exclusions apply to incoming
Internet source addresses. Explicit old root-approved routes and exact DNAT
rules remain separate and take precedence; public permission does not broaden
their approval or destination/port/source semantics.

Namespace `internet_out`, `internet_in` and `internet_snat` ordinary chains
share per-direction deny lists rather than duplicating them for every member.
Initiating packets must be new/established tracked flows, not invalid/untracked
packets that could escape without a translation. Responses require an exact enabled member destination and established
source-NAT conntrack state. Related ICMP accepts only destination-unreachable
(including PMTU), time-exceeded and parameter-problem errors; unrelated errors,
echo requests from outside and unsolicited TCP/UDP ingress remain denied. No
arbitrary `established,related accept` rule is added. Kernel ICMP error behavior
from private intermediate routers remains denied by the isolation floor.

OVS adds only gateway-identity-specific priority-190 public fallback flows and
priority-195 exclusions. Existing approved routes retain priority 200. The
gateway's exact MAC, local port or remote tunnel source/destination/VNI and
metadata restrictions remain in force; no unknown-MAC learning, flooding,
peer-to-peer transit or policing bypass is introduced. The namespace firewall
is authoritative for transport/conntrack checks, while OVS retains identity and
cross-VPC/underlay isolation.

## Root prerequisites and private profile

Install `iproute2`, `nftables`, `conntrack`, `util-linux`, and OVS 2.17+ on Ubuntu
22.04 or newer. The node does not start a host nftables service or modify its
rules. Prepare one dedicated namespace per approved NAT VPC with exactly:

- `lo`, one inside veth and one outside veth; both up at `guest_mtu`.
- The inside address is the approved gateway IPv4/VPC prefix and its MAC equals
  the gateway MAC. Its host peer is `TAPName(gateway_instance_id)` **but is a
  veth, never represented as a libvirt TAP or VM**.
- The outside address is the sole IPv4 `public_ipv4`; its veth peer is the
  explicitly approved `outside_peer`. An operator connects that peer to an
  isolated external uplink. The service never attaches a physical NIC, changes
  a host default route or enables host forwarding.
- The namespace route table contains the VPC connected route, the public
  connected route and exactly one default via `uplink_gateway_ipv4`, plus the
  kernel local/broadcast routes. Only the standard local/main/default policy
  routing rules are allowed.
- Four link aliases identify the exact node/profile/side:
  `aster-nat:<node_id>:<profile_id>:inside`, `:inside-peer`, `:outside`,
  `:outside-peer`. Both ifindex/iflink directions and veth type are checked.
- The inside OVS Interface has exactly these external IDs:
  `aster-node-id`, `aster-owner`, `aster-gateway-vpc`, `aster-nat-profile`,
  `aster-interface-id`, `aster-gateway-mac`. Its Port must have one Interface,
  no VLAN/trunk/bond and the approved MTU. Old appliance gateways retain their
  separate libvirt/TAP validation.

Add `nat_profiles` to the root-owned overlay approval. Example shape (replace
IDs, namespace identity and address approval with actual operator-owned values):

```json
{
  "id": "nat-a",
  "namespace": "aster-nat-a",
  "namespace_device": 4,
  "namespace_inode": 4026533000,
  "dedicated_ack": true,
  "vpc_id": "22222222222222222222222222222222",
  "vpc_cidr": "10.11.0.0/24",
  "gateway_instance_id": "88888888888888888888888888888888",
  "inside_interface": "inside",
  "outside_interface": "outside",
  "outside_peer": "nat-uplink",
  "public_ipv4": "198.51.100.2",
  "uplink_gateway_ipv4": "198.51.100.1",
  "allow_snat": true,
  "allowed_source_cidrs": ["198.51.100.0/24"],
  "allowed_ports": [{"protocol": "tcp", "start": 10000, "end": 20000}]
}
```

The complete root overlay SHA includes these private approvals. Publish only the
safe policy projection/profile SHA to the controller's `nat_profiles` directory;
namespace names, inode/device numbers and host interface paths are not UI data.
A rebuilt namespace has a different inode and needs a fresh explicit approval.
The implementation opens `/run/netns/NAME` with `O_NOFOLLOW`, checks root
ownership, device/inode and the Linux NSFS type, rejects the process and PID 1
network namespaces, and passes that descriptor to `nsenter` using `ExtraFiles`.
Renaming the namespace after the open cannot redirect the command to the host.

## Commit and recovery

- **prepare:** persist the uncertain phase first, verify root namespace/routes/
  veth/OVS identities, establish durable ownership, set and read back
  namespace-only `net.ipv4.ip_forward=0`; OVS/VM fencing is also retained.
- **program:** validate generated JSON using `nft -j -c -f`, atomically replace
  only owned `inet aster_nat`, flush only that namespace's conntrack, and compare
  every chain/rule/expression against live JSON. Only metainfo, kernel handles
  and immaterial cross-chain output order are normalized. Every input/output/
  forward base chain defaults to drop, including IPv6. No host ruleset flush.
- **release:** verify the complete expected rules, exact root identity and
  forwarding-off state; only after the controller all-participant program
  barrier enable namespace forwarding and release the existing OVS VM gate.
- **failure:** independently disable namespace forwarding; retain unknown
  intent/receipt and require explicit recovery. Exact old operation replay only
  returns its old receipt; it never reprograms NAT.
- **removal:** all root NAT namespaces are processed even if a policy or gateway
  is removed from the new snapshot. They receive a default-drop table, and their
  cached translations are removed. Root gateway ports remain in owned inventory
  but receive no selected gateway flow. They are not silently deleted/adopted.
- **readiness:** CheckOverlay, OverlayCheck and VM lifecycle gates read actual
  namespace identity, routes, nft rules and forwarding state, not cached success.
  A removed/inactive NAT policy keeps namespace forwarding at zero after release.

A NAT/network epoch intentionally **interrupts existing translated connections**.
This is required to revoke first-packet conntrack NAT mappings reliably. Ordinary
VM start/stop does not reset NAT conntrack unless a failure requires isolation.
The full generated ruleset is bounded to 512 KiB; oversized intent is rejected
before any phase mutation rather than truncated.

## Upgrade an existing root profile

Existing full configuration pins are not silently weakened to exclude new NAT
fields. To migrate a deployed cluster, add the previous full SHA as optional
`previous_profile_sha256` in the new root OverlayConfig; the **new** full SHA also
includes this field. The controller root directory separately approves its old
`previous_profiles` and current pins. An explicit recovery epoch must bind the
exact observed old node head and select the current root pins.

Only recovery **prepare** may transition the journal pin. The new unknown intent,
an immutable `overlay-profile-migration-<operation>.json` evidence record, then
the new journal pin are durably written before any host mutation. The evidence
binds node, old/new SHA, operation/request SHA and previous head. Unknown writes
never become success, and old tasks/epoch snapshots are not rewritten. Normal
plan, auto-create or VM lifecycle cannot migrate a pin. Keep the previous field
in the approved file after migration: removing it changes the full config SHA.

### Updating or rebuilding an existing NAT profile

The node keeps the full private approval in `nat-owner-<profile>.json`, with the
exact profile SHA. A root approval change needs both the full overlay migration
above and `nat_profiles[].previous_profile_sha256` equal to that old NAT SHA.
Only recovery prepare may migrate this owner. With the same namespace identity,
the executor first disables forwarding and flushes that old namespace's
conntrack. Migration evidence binds full old/new profiles and exact recovery
operation/request; the new owner is persisted only after this evidence.

For a rebuilt inode the namespace name, VPC/CIDR, gateway and interface names
must remain the same, its newly pinned veth/route identity must pass, and its nft
ruleset must be empty. Root additionally sets
`retired_previous_namespace_ack: true` **after independently confirming that the
old namespace is no longer connected**. This flag is not a connectivity probe:
**an unreachable old namespace is not proof that it is isolated.** HTTP/UI users
cannot set this private root-only assertion. It never overrides host-namespace,
symlink, new-veth, route or foreign-table checks.

Persistent `nat_profile_ids` journal tombstones prevent deleting an owner file
or simply removing a root NAT profile to forget a previously controlled
namespace. To disable NAT use the UI policy removal; retain the root profile in
the owned inventory. Automatic permanent host-profile retirement is not offered.
Old binaries reject the added journal field instead of silently downgrading it.

## Evidence and limitations

`TestNativeNATPacketFlowAndRevocation`, enabled with `ASTER_NATIVE_NAT=1`, is a
mandatory Ubuntu 22/24 CI gate. It provisions only temporary namespaces/veths,
uses actual nftables/conntrack, checks SNAT observed source and DNAT destination,
proves program remains isolated before release, refuses unapproved ports,
keeps an actual TCP connection open during revocation, and asserts the host nft
rules are unchanged. It does **not** test OVS forwarding or KVM: those remain the
separate overlay parser/packet-model and deferred real-host acceptance tracks.

`TestNativeNATInternetEgressAndRevocation` is an additional mandatory Ubuntu
22/24 gate under the same variable. Three isolated namespaces use public-syntax
addresses on temporary veth/loopback only, with **no external packet path**.
The test proves TCP/UDP egress and responses to a destination absent from every
explicit prefix, observed translated source, real ICMP echo replies,
prepare/program isolation, denial of unsolicited ingress and private/metadata/
public-underlay/protected destinations, and interruption of an already-open
TCP connection when Internet permission is disabled. That held client forbids
redial, so a reconnection cannot substitute for the physical-connection check.
Host nft rules must remain byte-for-byte unchanged. This gate does not claim
live provider routing, physical uplink, real OVS forwarding, KVM or native PMTU
error injection; the constrained related-ICMP policy has compiler packet-model
coverage.

Local fake tests cover three-phase ordering, exact replay, uncertain command
failures, stale namespace/peer/route, foreign tables, root pins, source/port/target
confusion, removal/default-drop, read-only drift and configuration canonicality.
Public tests additionally cover every reserved class, public management and
underlay exclusions, full 128-member rule bounds, removed conntrack/exclusion/
ordinary-chain readback drift, exact local/remote gateway packet identities,
policing and disabled-member behavior. Native OVS parser fixtures now include
both local and remote public NAT fallback/exclusion plans.
Migration tests inject write/sync/rename/directory-sync failures at each durable
boundary. No real KVM, physical uplink/public reachability or HA failover claim
follows from these isolated tests.

## Primary references actually consulted

- [nftables NAT semantics](https://wiki.nftables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_(NAT)) — first-packet conntrack bindings and SNAT/DNAT.
- [Atomic rule replacement](https://wiki.nftables.org/wiki-nftables/index.php/Atomic_rule_replacement) — whole-file atomic updates, not incremental shell rules.
- [libnftables JSON schema](https://manpages.debian.org/bookworm/libnftables1/libnftables-json.5.en.html) — inet NAT family, match/bitmask operators and object structure.
- [ip-netns manual](https://man7.org/linux/man-pages/man8/ip-netns.8.html) — named namespaces and descriptor lifetime.
- [Conntrack state and status](https://wiki.nftables.org/wiki-nftables/index.php/Matching_connection_tracking_stateful_metainformation) and [Linux conntrack UAPI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter/nf_conntrack_common.h) — established/related and source-NAT status guards.
- [IANA IPv4 special-purpose registry](https://www.iana.org/assignments/iana-ipv4-special-registry) — conservative public address exclusions; no claim of provider routing from address syntax.

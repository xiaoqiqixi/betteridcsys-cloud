# Network console browser gate

`network-browser` in `.github/workflows/cloud.yml` is a non-skipping
Ubuntu 24.04 acceptance job. It builds the real Vue bundle and starts the real
console HTTP/session/RBAC/CSRF handlers, SQL store and asynchronous overlay
runner against `mysql-native.sh`'s independent MySQL 8.4 Unix-socket fixture.
There is **no live KVM node**: the existing deterministic node RPC test double
records receipts and loses exactly one `program` acknowledgement. Actual Linux
NAT packet flow is checked separately in the Ubuntu 22.04/24.04 `native-nat`
matrix; browser acceptance does not establish physical cross-node reachability.
The public addresses `8.8.4.2`, `8.8.4.3`, `8.8.4.4` and `9.9.9.2` in this fixture are
**synthetic controller approval metadata**: they are not assigned, contacted,
claimed as owned, or configured as runner routes. This is not a private root
NAT profile or provider-ownership proof; the real native namespace gate checks
the node data plane separately.

## Reproduce in a disposable Ubuntu 24.04 runner

Use the workflow's pinned Go 1.27.3, Node 24.19.0 and **Playwright 1.64.0**.
Build `aster-cloud/frontend` with `npm ci --ignore-scripts && npm run build`.
Provision the existing native runner prerequisites; install Firefox through the
pinned Playwright CLI and `libnss3-tools`. Keep browser packages outside product
dependencies in a private scratch directory. Export:

- `RUNNER_TEMP`: a writable, private runner scratch directory;
- `PLAYWRIGHT_MODULE_DIR`: the pinned scratch `node_modules` directory;
- `PLAYWRIGHT_BROWSERS_PATH`: the scratch browser download directory.

Then run from the repository root:

```sh
bash vps-billing/deploy/ci/mysql-native.sh -- \
  bash aster-cloud/deploy/ci/network-browser.sh
```

Do not point this runner at a production database. It deliberately rejects a
missing native fixture, root execution or an existing output directory. It
discards inherited `ASTER_CLOUD_TEST_DSN` values before starting the helper. The `.gotxt` helper is introduced by an explicit Go
`-overlay`; it is absent from ordinary tests and all production binaries.

## TLS and cleanup

All keys and the one-day, localhost-constrained CA are generated inside private
CI scratch. The server listens only on `127.0.0.1:5447`. The real Firefox first
must reject the untrusted CA. `certutil` then trusts that CA **only in the new
private NSS profile**, and Firefox must connect with `ignoreHTTPSErrors: false`.
No system CA store, macOS keychain, global browser policy or certificate warning
is modified/bypassed. The signing key is deleted immediately after signing.

On success and failure the runner signals its owned fixture to stop and waits
for the test result. Passing additionally requires database assertions that
plan, VPC creation, lost-ACK reconciliation and recovery actually persisted,
and that original financial/node request bytes, network snapshot bytes and
initial node receipts stayed unchanged. UI success alone is not sufficient.
The fixture additionally requires exactly **thirteen epochs, two VPCs and seventy-eight
unique overlay node task POSTs**, plus three direct node/3 POSTs; its original first thirty POSTs must remain the
unchanged five-epoch, no-explicit-public-address prefix. Its first forty-two tasks retain the original seven NAT/network epochs with no floating policy. Epoch 1 is the original prefix-only snapshot. Through
visible UI controls, epoch 2 enables public IPv4 Internet while retaining its
explicit route and DNAT mapping, epoch 3 recovers that selection after the lost
ACK, epoch 4 disables SNAT/Internet and removes routes/mappings, and epoch 5
re-enables Internet with **empty explicit route and DNAT lists**. The fourth
snapshot must stay disabled and unchanged after the fifth is complete. A
passing report never substitutes a receipt for a different Internet-mode hash.

After the original five-epoch flow, the visible public-IP UI must:

1. Create one `8.8.4.0/24` pool containing only `8.8.4.3`, then append `8.8.4.4`
   through **补充地址**. The original creation operation must still contain only
   its original address; extension is one separate immutable operation.
2. Allocate `8.8.4.3` to the exact fixture VPC/customer/node/profile. The fixture
   deliberately loses this first allocation's response **after the unchanged
   real Console handler commits**. It buffers that one response, flushes its genuine 201 headers with the exact
   original body length, then raises `http.ErrAbortHandler` to truncate that body.
   Closing before response headers can provoke an implicit transport replay;
   a failed header flush immediately fails the test and the final fixture requires
   an explicit successful-flush proof. The regression separately verifies both
   HTTP/1.1 and HTTP/2 TLS expose the committed headers then an incomplete JSON
   body with exactly one server POST. Firefox may suppress Playwright's `response`
   event when the HTTP/2 stream resets; browser evidence instead requires exactly
   one original `requestfailed` event and one attempt. If a response event is
   emitted, it must be 201, never a replayed 200. A network failure alone proves
   no business success: only the exact original-operation GET below confirms the
   immutable allocation result. It changes no UI request/body,
   invents no success and performs no extra POST. The browser must keep the
   result unknown, then click **核对原操作** and clear it only after exactly one
   GET of that original operation matches its exact submitted intent. The browser
   clicks the real reconciliation button only once its busy/disabled state clears
   after the POST settles; a pre-send pending indicator is not a commit boundary.
   It never races a direct evidence GET against a still-processing allocation. Both
   browser attempts and server allocation POST counts prohibit silent replay.
3. Select the allocated address through **公网地址绑定** and complete epoch 6,
   including all six exact node phase receipts. The bound lease must display a
   disabled reclamation button and the read-only API must confirm `bound`.
4. Disable/re-enable the pool from the UI. Admission stops, while the bound
   lease, epoch 6 snapshot and receipts stay unchanged; no live connection is
   claimed by this simulated node fixture.
5. Remove the NAT policy in epoch 7. Its pending overview must hide new-plan
   controls and expose the exact original recovery link; read-only pool/lease
   navigation remains available. A merely pending removal must still block
   reclamation. Only completion of every prepare/program/release receipt makes
   the typed-IP-confirmed **回收公网 IP** action available.
6. Reallocate the same address into a distinct reserved lease. The released
   original lease and all original five network snapshots/receipts remain
   intact. At this stage the NAT workflow retains one pool, two immutable inventory
   addresses, two lease-history rows, one exclusive active reservation and
   exactly seven public-IP operations (create, extend, two pool-state changes,
   two allocations and one reclamation). Old allocation-operation results stay
   `reserved`, not rewritten to mirror their later mutable lease state.

## VM direct addresses and independent floating IPs

The same mandatory job then continues through visible controls, not a separate
optional test or API-only demonstration:

1. Allocate `8.8.4.4` as an independent floating IP. Choose the exact
   owner/VPC/profile/VM, review its independently fetched ingress policy, then
   type the VM ID. The binding POST freezes `expected_ingress_revision: 0` and
   the resource generation. Epoch 8 includes an explicit non-null empty policy:
   new public inbound connections are denied, while legitimate replies to
   connections initiated by the VM remain permitted. There is no all-port
   exposure checkbox and no rule is inferred from a UI confirmation.
2. Open the original VM's independent **公网入站规则** panel and add explicit
   TCP, UDP-range and ICMP-echo source rules through custom UI controls. Epoch 9
   applies its first policy revision only after all six exact phase receipts.
   Move the same address to the other node's VM in epoch 10: the target's own
   revision-zero empty policy is frozen, not the original VM's three rules.
3. Configure the new target's restricted SSH source in epoch 11, then remove
   its rule in epoch 12. Its original policy operation and earlier epoch
   snapshots/receipts must remain immutable after revocation. Unbind in epoch 13,
   prove every node's prepare/program/release receipt, then reclaim and reallocate
   the same address into a distinct resource. Every original seven NAT/network
   snapshot/receipt remains unchanged. A pending removal never frees inventory.
4. A separate fixture-approved normal network and `9.9.9.0/24` pool supply
   `9.9.9.2`. Allocate it via the new UI, select its exact resource in the real
   CreateInstanceDialog, and explicitly dispatch the real persisted creation task.
   The browser freezes resource ID plus `public_ip_expected_generation: 0`; the task is node/3 with exact IP, MAC, owner, node, profile and generation.
5. View the current binding in the instance public-address panel, explicitly
   create/dispatch shutdown, then plan/dispatch exact public detachment and reclaim.
   This is never presented as live primary-IP replacement. The fixture compares
   the three actual substitute Send responses to the exact frozen MySQL requests
   and successful controller operation states; it does not invent results later.

The final database requires three VM resource-history rows, nine immutable VM
resource operations (**allocate 3, bind 2, unbind 2, release 2**), two NAT lease
history rows and their original seven UI operations. The fixture-seeded direct
pool adds one separate inventory operation: eight total legacy pool/NAT operations,
two pools, three inventory addresses and exactly two exclusive active claims.
Every active row must resolve to one reserved NAT lease or VM resource. The
released direct address must have no claim. Creation and shutdown are controller
operations, not counted among those nine resource operations. Three separate
`public_ingress.update` operations and three immutable policy-version rows are
required, with exact actor/target/request/result identities. Foreign-actor lookup
cannot resolve an operation. VM0 keeps its three rules after the IP moves; VM1
keeps its empty revision two after detachment. The live policy read distinguishes
saved desired revisions, confirmed effective revisions, unsupported nodes and
legacy unrestricted bindings. Rules currently restrict VPC floating-IP public
ingress only, not private traffic, normal direct public interfaces or a complete
security group. Feature capability is refreshed independently for every participant.

The separate typed UI/API tests cover generation conflicts and durable full-intent
unknown reconciliation, including recovery-only detachment with the exact original
epoch SHA. Recovery does not restore a public binding. Its public-resource POST
only plans a new epoch; only GET original-operation proof can resolve a lost ACK.
No physical VM or provider allocation is claimed by this deterministic node fixture.

All writes use visible Vue controls. The script's `fetch` evidence is GET-only;
no component-state mutation, response-body replacement, TLS bypass, write retry
loop or direct test SQL mutation substitutes for this workflow. The separate
SQL/RBAC suite tests forbidden ownership and pool-disabled server mutations.
The fixture database, credentials, cookies, NSS profile, remaining TLS key,
private logs and package scratch are removed by the owned cleanup routines.

## Evidence

Only `*.png`, `report.json`, `tls.json` and `fixture.json` from
`aster-cloud/artifacts/network-browser` are uploaded (seven-day retention).
Screenshots are taken only on signed-in business pages. Reports contain bounded
check results and synthetic operation paths, not headers, tokens, passwords,
DSNs, raw response bodies, DOM dumps or HAR traces. An incomplete/failed run
cannot produce a passing `fixture.json`. Raw browser/fixture diagnostics remain
private and are removed instead of being published.

The browser covers desktop/mobile, Chinese/English and light/dark presentation,
keyboard focus, Escape, Back/Forward, custom selects, route/NAT editing, VPC
creation, explicit continuation and read-only receipt reconciliation. Each
continuation uses at most one POST followed by bounded GET observation; no write
retry loop hides uncertainty.

### Responsive command rail (legacy sidebar artifact identifiers)

`sidebar-browser.mjs` now validates the **actual 52px command rail**, not the
retired 216–232px sidebar. Its exported function, `report.sidebar_checks`,
`report.sidebar_screenshots` and twelve `sidebar-*.png` filenames remain legacy
compatibility identifiers for the artifact gate. New geometry
records carry `shell_contract: "command-rail-v1"`; old sidebar results are not
new-rail acceptance evidence. No business workflow, POST count, thirteen-epoch
history proof or original business screenshot is replaced.

The new shell phase requires **53 records across the two modes** (37 Chinese /
light and 16 English / dark), including two new semantic-anchor checks. This is
the required new matrix, not a claim that the new bundle has already passed it.
The outer gate requires these new 53/37/16 minimums and both semantic-anchor
proofs, plus actual 44px keyboard targets for navigation, appearance and logout.

- At **320, 390, 768, 1024, 1025 and 1440 CSS pixels**, scroll the real persisted
  epoch-five business document to top/middle/bottom. Verify genuine long content,
  one sticky **52px** rail, full-width workspace, document footer and no body
  horizontal overflow. At `<=1024px` the desktop links are hidden and the actual
  menu trigger is visible; above the boundary six semantic route anchors own a
  horizontal scrollport separate from the brand/account utilities. There is no
  old sidebar or duplicate topbar.
- At **1440x360 and 1025x360**, wheel the real navigation horizontally. When
  its real labels overflow, the navigation must reach its end; when all six fit,
  the evidence explicitly records that scrolling was unnecessary rather than
  inserting fake content. In either case business scroll and brand/utilities
  remain fixed. Starting at the actual brand anchor, Tab through all six links,
  appearance and logout without activating logout. Each target must be focused,
  fully inside its clip/viewport, at least **44x44px**, and pointer-hittable.
  The legacy seven-target array retains six links plus logout; appearance has
  its own additional keyboard geometry receipt. No keyboard step moves the
  business document.
- **720x450 and 512x384 CSS viewports** are reflow equivalents of 200% zoom at
  1440x900 and 1024x768, not actual browser zoom or physical-phone evidence.
  The real six-link drawer must overflow at these short heights; wheel input
  scrolls its body independently while header/footer remain usable and the
  background document remains locked.
- Open navigation at the bottom of the long page; check focus wrap, background
  `inert`, scroll lock, Escape/backdrop/Back and successful visible-link routing.
  **1024→1025** consumes the overlay entry and focuses main; **1025→1024** moves
  focused desktop navigation to the compact menu even when CSS blurs first.
  The skip link must focus main without changing the hash URL. Permission
  filtering and native modified-link behavior have separate Vue regressions;
  no view component invents grants or bypasses the existing deep-link gate.
- Repeat boundary geometry, short-screen keyboard/scroll and transitions in
  English/dark. Compare business POST and attempted-write counts before/after
  both complete phases: navigation/layout tests cannot create resources.

The horizontal scrollport uses `tabindex="-1"`; its actual anchors provide Tab
stops and focus-reveal behavior. No DOM/CSS injection, response replacement,
clock mocking or hidden control substitutes for the measured UI. A failure
exports bounded element identities and geometry, never raw DOM or credentials.

The twelve fixed legacy **viewport** screenshot names remain disjoint from all
fifty-two original business PNGs, so the bundle still contains **64 PNGs**:

```
sidebar-320-top.png                 sidebar-320-drawer.png
sidebar-390-bottom.png              sidebar-390-drawer.png
sidebar-768-drawer.png              sidebar-1024-drawer.png
sidebar-1025-middle.png             sidebar-1440-bottom.png
sidebar-1440-short-nav-bottom.png   sidebar-1025-short-nav-bottom.png
sidebar-zoom-720-drawer.png         sidebar-zoom-512-drawer.png
```

The exported `sidebarLayout(page)` is a read-only measurement helper with its
legacy name; current measurements describe the rail. Merely calling it cannot
produce passing acceptance. Keep before failures separate from the final run.

The original fourteen screenshots remain, including the two
`*-public-egress-editor.png` images showing the Internet-only editor. Eighteen
additional desktop/mobile images show pool creation, extension, inventory,
allocation, bound NAT selection, bound leases, reclamation, lease history and
English/dark lease presentation. Twelve further real images show floating binding and bound/history resources, direct creation and the instance public panel: **44 original PNGs**. Eight additional actual desktop/mobile images cover the custom public-ingress editor, applied allow rules, empty revoked policy and English/dark policy presentation: **52 business PNGs**, retained alongside the twelve shell PNGs above (**64 total**). New dialogs and list pages are measured at
1440, 390 and 320 CSS pixels for actual horizontal overflow. Final
Chinese/light and English/dark overview screenshots are taken after epoch 5 and
must show its persisted public mode and synthetic egress IPv4. Plan and recovery
of the original NAT flow still require its real public-access consent checkbox plus typed confirmation; floating-IP binding instead requires the separately loaded target policy revision and typed VM identity;
the test never bypasses either by manipulating component state or issuing a
write through `fetch`.

The notification regression gate also checks that consecutive information notices
do not accumulate, that a modal excludes background notices from paint/hit/focus,
and that changing locale removes the previous-language notice. Final screenshots
wait for the real five-second information notice expiry, with the pointer moved
away; they never hide DOM, click dismiss, mock clocks or edit application state.
The first measured package provisioning took 21m48s, so the job permits 40 minutes;
the expanded fixture has an 18-minute lifetime and a 21-minute Go test deadline; individual page-operation deadlines remain bounded.

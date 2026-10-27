# Independent Cloud packages and first-RC publisher proof

Local packaging produces **unpublished candidates**, not proof of publication or
native installation, real KVM, networking, upgrade or recovery acceptance. The
financial Core `v0.5.9` assets and installer are not Cloud packages.

Two separate policies are implemented:

- Development: `0.x.y-dev` / `0.x.y-dev.n`, `release_kind=development`; installation
  requires explicit `--allow-development`, a real local bundle and its trusted
  external whole-archive SHA256. A checksum is integrity, not publisher identity.
- Publisher-authenticated first RC only: `0.1.0-rc.1`, tag
  **`cloud-v0.1.0-rc.1`**, `release_kind=release`, `channel=prerelease`. It requires
  the exact signed manifest/attestation chain and a private `--release-receipt`
  that is cryptographically reverified offline. A development opt-in cannot
  authorize this envelope. No stable/latest/other-tag fallback is supported.

**A supported tag/pipeline is not a published Release.** The official role commands
must come from the actual
[cloud-v0.1.0-rc.1 Release body](https://github.com/xiaoqiqixi/betteridcsys/releases/tag/cloud-v0.1.0-rc.1)
after its complete assets/proof exist. If absent, stop; this document provides no
invented `/main`, placeholder curl, or finance-release substitute.

## Build from one reviewed commit

From a clean monorepo, with Python 3.9+, Git, Go (toolchain `go1.27.3`) and
Node `24.19.0` / npm available on `PATH`:

```sh
python3 /absolute/path/to/betteridcsys/aster-cloud/deploy/scripts/package-cloud.py \
  --source-root /absolute/path/to/betteridcsys \
  --source-commit FULL_40_LOWERCASE_HEX_COMMIT \
  --version 0.1.0-dev \
  --output /absolute/path/outside-the-repository/cloud-candidate
```

The full commit must exist locally. Tracked edits, staged edits and nonignored
untracked files are refused; there is no dirty-source bypass. Ignored build caches
are never copied. The builder safely extracts **Git objects at that exact SHA**,
not the current worktree or whatever a branch name resolves to later. The SHA can
be older than a clean `HEAD`; the manifest always names the requested source.

The production path cross-compiles three real `CGO_ENABLED=0` Linux amd64 Go
executables, runs `npm ci --ignore-scripts --no-audit --no-fund --include=dev` and the actual
frontend `npm run build`. It neither accepts prebuilt binary/UI directories nor
offers a fake-build CLI option. It may download the pinned Go toolchain and locked
Go/npm dependencies, so builds require approved network access or populated
caches. Ambient Go flags/experiments and `VITE_*` variables are excluded from the
build configuration; the amd64 instruction baseline is pinned to `GOAMD64=v1`.
It does not install host packages, services, databases or VM software.

The public `controllerapi` contract currently resolves through the adjacent
financial Go module and its `internal/controllers` wrappers. Those reviewed source
dependencies come from the **same monorepo SHA** during compilation. No financial
Release archive, executable, installer, configuration, database or secret is
copied. The resulting static cloud binaries do not require the financial directory
at runtime. This is not yet a separately published public-contract module.

## Output and installer contract

Development packaging emits exactly two archives and an external checksum file:

```text
aster-cloud-controller-0.1.0-dev-linux-amd64.tar.gz
aster-cloud-node-0.1.0-dev-linux-amd64.tar.gz
SHA256SUMS
```

Each tar contains only regular files, with **no enclosing directory**, symlinks,
hardlinks, devices, FIFOs, absolute paths or `..`. No explicit directory members
are emitted. File names are canonical POSIX paths. Archive owner/group are zero,
names empty, modes normalized, timestamp fixed to the source commit; gzip headers
omit temporary paths. Running the same build twice with the same dependencies
should produce identical output; a release gate must actually compare the bytes
rather than assume this property.

Common prefixes: `manifest.json`, `bin/`, `templates/`, `licenses/`, `docs/`.
The controller also contains **compiled** `ui/index.html` and `ui/assets/...`.
The node package has no UI or npm dependency notices.

- Controller binary: `bin/aster-controller`.
- Node binaries: `bin/aster-node`, `bin/aster-network`.
- Templates retain their reviewed source names, such as
  `templates/controller-aster.service`, `templates/node-aster-node.service` and
  `templates/node-config.example.json`. They are review material, not permission
  for an installer to execute archive-provided scripts or activate example policy.
- Licenses include the project license, Go standard library and external module
  notices; the controller includes frontend dependency notices.
- No credentials, databases, VM images, journals, source checkout or `node_modules`
  implementation files are packaged.

Required manifest schema:

```json
{
  "schema": 1,
  "component": "aster-cloud-controller",
  "version": "0.1.0-dev",
  "source_commit": "0123456789abcdef0123456789abcdef01234567",
  "platform": "linux-amd64",
  "release_kind": "development",
  "files": [
    {"path": "bin/aster-controller", "sha256": "64_lowercase_hex", "size": 123, "mode": "0755"}
  ]
}
```

Node `component` is `aster-cloud-node`. `files` is sorted by path and lists
**every non-manifest member exactly once**. `manifest.json` cannot self-hash and
is excluded from that list. Mode is an exact four-digit octal **string**: `0755`
only for binaries and `0644` for other content. Additional metadata records
`role`, source-declared `protocols`, supported `data_schemas` and pinned `build`
tool versions. Schema/protocol metadata describes compatibility, not deployment
approval or a guarantee that all features were acceptance-tested.

Development `SHA256SUMS` uses the standard `64hex␠␠archive-name` format and hashes both complete
archives, including their manifests. It is a checksum, **not an authenticated
signature or provenance attestation**. An installer must receive a checksum from
an operator-approved source; downloading an archive and its checksum from the
same compromised location is not an independent trust anchor. Packaging never
creates a tag, Release, signature, remote upload or production-readiness claim.

Existing candidate names are never overwritten. Build/validation errors publish
no archives; the checksum file is published last as the complete-set marker.
Incomplete output after interruption must be reviewed, not silently overwritten.

## Sole prerelease envelope and distribution chain

Using `--version 0.1.0-rc.1` on a clean exact source commit selects the sole RC
candidate mode. It adds `channel=prerelease` and
`release_tag=cloud-v0.1.0-rc.1` to both role manifests; ordinary file inventory,
ELF, mode, canonical-path and external-SHA requirements do not change. The
additional installer capsule contains only regular `manifest.json`, `install.py`,
`provision.py`, `release_verify.py` files. All code hashes/sizes/modes are bound by
its manifest; there is no arbitrary adjacent module/script allowance.

The completed publisher asset contract is:

```text
aster-cloud-controller-0.1.0-rc.1-linux-amd64.tar.gz
aster-cloud-node-0.1.0-rc.1-linux-amd64.tar.gz
aster-cloud-installer-0.1.0-rc.1.tar.gz
aster-cloud-bootstrap-0.1.0-rc.1.py
release-trusted-root.json
provenance.json
SHA256SUMS
release-manifest.json
attestations.jsonl
```

The local packager does **not** create `attestations.jsonl`, publish these assets,
or authenticate its own output. Those are separate reviewed publisher-workflow
operations. `release-manifest.json` binds the fixed repository and numeric
repository/owner IDs, exact source SHA/ref, approved workflow, sole RC tag/channel
and sorted complete asset names/sizes/SHA256. Its acceptance fields remain
`production_ready=false`, `real_kvm_accepted=false`; signed software is not host
or VM acceptance. Checksums and provenance are covered by the publisher chain,
not promoted to standalone trust roots.

The Release-body bootstrap must use a **full immutable commit**, never `/main`.
That initial reviewed HTTPS command is an operator trust root, not a script
which proves itself using a same-origin checksum. Anonymous verification of all
subsequent executable payloads uses the fixed official Linux amd64 `gh` binary
hash and fixed official Sigstore trusted-root bytes. The verifier pins repository,
GitHub OIDC issuer, workflow certificate identity, source/signer SHA, public
repository owner/ID, GitHub-hosted runner, trigger and verified transparency
timestamps. Do not add an authentication token or disable TLS to work around a
failed public download.

The private receipt records exact repository/tag/source/component/asset
name/hash/size and paths/hashes for local manifest, capsule, attestation, verifier
and roots. `release_id` is only an observed HTTPS API consistency value, **not a
signed code authorization**. Root-private regular files, empty private anonymous
HOME/config and exact capsule neighbors are required. A JSON `verified:true`
assertion cannot replace verification. Before a release plan/apply, the installer
performs three local offline publisher rechecks (manifest, capsule, role package)
using `--bundle` and `--custom-trusted-root`; it neither downloads nor writes a
verifier cache. The installer then independently checks every tar/manifest member.

Bootstrap `--download-only` is a distinct operation: it may download private
assets/proofs and invoke the authenticated installer's real read-only plan. It
must not apply APT/DB changes or start services. Its successful proof, once
obtained from a real published RC, still would not prove fresh-host or KVM
readiness. This page records no such public-download result.

## Native installer relationship

Both roles use the same [interactive native installer](../deploy/install/README.md).
Controller optional signed packages/new dedicated MySQL and node optional
`--prepare-libvirt` remain explicit approvals, never packaging side effects.
Fresh libvirt preparation retains Ubuntu AppArmor/QEMU users, permanently masks
vendor service/socket activation and starts only owned UNIX daemons whose real
mount namespace sees a read-only empty networks directory. Vendor default XML may
exist on fresh disk, but it may not be activated; existing active hosts are only
inspected read-only. No bridge/uplink/firewall rewrite, controller private-key
import, dummy image or KVM bypass is permitted.

The current Ubuntu 22.04/24.04 signed-image **TCG gate requires a fresh exact-source CI run**. Ubuntu 26.04 is deferred and unsupported by the installer/harness; historical failures are not reclassified as success. It is designed
to test actual APT/systemd/libvirt namespace behavior and an honest missing-KVM
doctor refusal; it cannot pass hardware KVM acceptance. Preserve this distinction
even if reproducible packaging and all offline tests pass.

## Offline tests and remaining gates

```sh
python3 -B /absolute/path/to/betteridcsys/aster-cloud/deploy/scripts/test_cloud_package.py
```

Tests inject a Python build callback into private temporary repositories; tiny
ELF-shaped **test fixtures are not executable production binaries**. Tests cover
manifest/installer compatibility, exact SHA snapshots, dirty-source refusal,
deterministic archive serialization, output conflicts, static ELF checks,
missing UI, links/special files and canonical paths. There is no test callback
option in the packaging CLI.

These tests do not replace a real pinned Go/npm build, two-build reproducibility
comparison, dependency/security scans, strict native TLS/MySQL/systemd installation
and rollback acceptance, or later dedicated KVM host acceptance. In particular,
the existing 1 GB financial server must not be used as a new KVM installation
target merely because a node archive can be built.

Current installer-side offline safety results are **108 installer-security + 14
installer-unit + 19 independent publisher-policy methods**, with synthetic
inputs/process models, not actual Sigstore proof or host apply. Publisher and
native CI results must be checked for the exact eventual release source; this
document does not appoint an uncommitted workspace SHA as an acceptance endpoint.

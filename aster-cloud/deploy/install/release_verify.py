#!/usr/bin/env python3
"""Reviewed first-RC bootstrap and offline publisher verifier. No import-time IO.

The initial fixed-commit HTTPS script is an explicit operator trust root, not a
self-verifying download. All later executable payloads require Sigstore proof.
No host installation, APT, service or network mutation occurs in this module.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

REPOSITORY = "xiaoqiqixi/betteridcsys"
REPOSITORY_ID = 1418618420
OWNER_ID = 123864154
VERSION = "0.1.0-rc.1"
TAG = "cloud-v" + VERSION
SOURCE_REF = "refs/heads/main"
WORKFLOW = ".github/workflows/cloud-release-build.yml"
WORKFLOW_IDENTITY = "https://github.com/" + REPOSITORY + "/" + WORKFLOW + "@" + SOURCE_REF
ISSUER = "https://token.actions.githubusercontent.com"
PREDICATE = "https://slsa.dev/provenance/v1"
GH_VERSION = "2.103.2"
GH_TAR_NAME = "gh_2.103.2_linux_amd64.tar.gz"
GH_TAR_SIZE = 15031001
GH_TAR_SHA256 = "62ccf747115ddc61237efffdde66a3c8f70ba249433dc64f70801089b59c59c8"
GH_BINARY_SIZE = 41070752
GH_BINARY_SHA256 = "cbfdc94f3a5c0713c0d6df3e0a1d88a59a76b0c52332aad7d21d112f9da2cc0e"
TRUSTED_ROOT_SIZE = 34634
TRUSTED_ROOT_SHA256 = "65ca537f6ed8a47fd0e560c421baa1f6c1efb8b25fc200d8c5c02c0e92eb2b9c"
CAPSULE_NAME = "aster-cloud-installer-" + VERSION + ".tar.gz"
BOOTSTRAP_NAME = "aster-cloud-bootstrap-" + VERSION + ".py"
CAPSULE_FILES = ("install.py", "provision.py", "release_verify.py")
PAYLOAD_NAMES = tuple(sorted((
    "aster-cloud-controller-" + VERSION + "-linux-amd64.tar.gz",
    "aster-cloud-node-" + VERSION + "-linux-amd64.tar.gz",
    CAPSULE_NAME, BOOTSTRAP_NAME, "release-trusted-root.json", "provenance.json",
)))
SIGNED_NAMES = tuple(sorted((*PAYLOAD_NAMES, "SHA256SUMS", "release-manifest.json")))
RELEASE_NAMES = tuple(sorted((*SIGNED_NAMES, "attestations.jsonl")))
CACHE_ROOT = Path("/var/cache/aster-cloud-release")
MAX_PACKAGE_BYTES = 256 * 1024 * 1024
MAX_SMALL_BYTES = 4 * 1024 * 1024
HEX = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")


class ReleaseError(Exception):
    pass


def fail(message):
    raise ReleaseError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                fail("Duplicate release JSON key")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs)
    except (ValueError, UnicodeError):
        fail("Malformed release JSON")


def protected_path(value, *, directory=False):
    path = Path(value)
    if not path.is_absolute() or str(path) != str(value) or ".." in path.parts or any(c in str(path) for c in "\r\n\x00"):
        fail("Canonical absolute release path required")
    for current in [*reversed(path.parents), path]:
        info = current.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            fail("Release path ownership, mode or symlink refused")
        if current != path and not stat.S_ISDIR(info.st_mode):
            fail("Release ancestor is not a directory")
        if current == path:
            if info.st_mode & 0o077:
                fail("Private root-only release material required")
            if directory:
                if not stat.S_ISDIR(info.st_mode):
                    fail("Release directory required")
            elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                fail("Single-link regular release file required")
    return path


def read_private(value, limit):
    path = protected_path(value)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if info.st_uid != 0 or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o077 or not 0 < info.st_size <= limit:
            fail("Opened release inode refused")
        raw = stream.read(limit + 1)
        if len(raw) != info.st_size or len(raw) > limit:
            fail("Changed or oversized release input")
    return raw


def run_fixed(argv, env):
    """Only the authenticated, code-pinned verifier is executed; never a shell."""
    try:
        result = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45, check=False)
    except (OSError, subprocess.TimeoutExpired):
        fail("Offline publisher verifier unavailable or timed out")
    if result.returncode or len(result.stdout) > MAX_SMALL_BYTES:
        fail("Publisher signature verification failed; diagnostics withheld")
    return result.stdout


def verification_environment(home, config):
    # gh 2.103.2 otherwise creates ~/.local/state/gh/device-id even for a
    # successful local-bundle verification. Explicitly disable telemetry and
    # update probes rather than permitting writes in an offline installer plan.
    return {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": str(home),
            "GH_CONFIG_DIR": str(config), "GH_HOST": "github.com", "GIT_CONFIG_NOSYSTEM": "1",
            "XDG_CACHE_HOME": str(home / "cache"), "TMPDIR": str(home),
            "GH_TELEMETRY": "disabled", "DO_NOT_TRACK": "1", "GH_NO_UPDATE_NOTIFIER": "1",
            "GH_NO_EXTENSION_UPDATE_NOTIFIER": "1"}


def verify_attestation(path, expected_sha, source_commit, gh, root, bundle, home, config):
    if not COMMIT.fullmatch(source_commit) or not HEX.fullmatch(expected_sha):
        fail("Exact source and artifact digests required")
    env = verification_environment(home, config)
    argv = [str(gh), "attestation", "verify", str(path), "--bundle", str(bundle),
            "--repo", REPOSITORY, "--signer-workflow", REPOSITORY + "/" + WORKFLOW,
            "--source-ref", SOURCE_REF, "--source-digest", source_commit,
            "--signer-digest", source_commit, "--cert-oidc-issuer", ISSUER,
            "--deny-self-hosted-runners", "--predicate-type", PREDICATE,
            "--custom-trusted-root", str(root), "--format", "json"]
    verified = strict_json(run_fixed(argv, env))
    if not isinstance(verified, list) or not 0 < len(verified) <= 30:
        fail("Missing verified publisher statement")
    found = False
    for item in verified:
        result = item.get("verificationResult", {}) if isinstance(item, dict) else {}
        if not isinstance(result, dict) or not isinstance(result.get("signature"), dict):
            fail("Malformed verified publisher result")
        cert = result["signature"].get("certificate", {})
        expected = {
            "issuer": ISSUER, "subjectAlternativeName": WORKFLOW_IDENTITY,
            "sourceRepositoryURI": "https://github.com/" + REPOSITORY,
            "sourceRepositoryIdentifier": str(REPOSITORY_ID),
            "sourceRepositoryOwnerIdentifier": str(OWNER_ID),
            "sourceRepositoryOwnerURI": "https://github.com/xiaoqiqixi",
            "sourceRepositoryDigest": source_commit, "sourceRepositoryRef": SOURCE_REF,
            "sourceRepositoryVisibilityAtSigning": "public", "runnerEnvironment": "github-hosted",
            "buildSignerURI": WORKFLOW_IDENTITY, "buildConfigURI": WORKFLOW_IDENTITY,
            "buildSignerDigest": source_commit, "buildConfigDigest": source_commit,
            "buildTrigger": "workflow_dispatch",
        }
        if not isinstance(cert, dict) or any(cert.get(key) != value for key, value in expected.items()):
            fail("Verified certificate is not the authorized Cloud publisher")
        if not isinstance(result.get("verifiedTimestamps"), list) or not result["verifiedTimestamps"]:
            fail("Publisher proof has no verified transparency timestamp")
        statement = result.get("statement", {})
        if not isinstance(statement, dict) or statement.get("predicateType") != PREDICATE or not isinstance(statement.get("subject"), list):
            fail("Unexpected verified publisher predicate")
        found |= any(isinstance(subject, dict) and subject.get("name") == Path(path).name and
                     subject.get("digest") == {"sha256": expected_sha} for subject in statement["subject"])
    if not found:
        fail("Verified statement does not bind the exact asset name and bytes")


def release_manifest(raw):
    value = strict_json(raw)
    keys = {"schema", "repository", "repository_id", "owner_id", "version", "tag", "source_commit",
            "source_ref", "channel", "workflow", "assets", "acceptance"}
    if not isinstance(value, dict) or set(value) != keys or type(value.get("schema")) is not int or value["schema"] != 1:
        fail("Unexpected release manifest schema")
    if (value["repository"] != REPOSITORY or value["repository_id"] != REPOSITORY_ID or
            value["owner_id"] != OWNER_ID or value["version"] != VERSION or value["tag"] != TAG or
            value["source_ref"] != SOURCE_REF or value["channel"] != "prerelease" or value["workflow"] != WORKFLOW or
            not isinstance(value["source_commit"], str) or not COMMIT.fullmatch(value["source_commit"]) or
            value["acceptance"] != {"production_ready": False, "real_kvm_accepted": False}):
        fail("Release manifest identity or prerelease policy mismatch")
    assets = value["assets"]
    if not isinstance(assets, list) or len(assets) != len(PAYLOAD_NAMES) + 1:
        fail("Unexpected signed asset inventory")
    indexed = {}
    for item in assets:
        if (not isinstance(item, dict) or set(item) != {"name", "sha256", "size"} or
                item.get("name") not in (*PAYLOAD_NAMES, "SHA256SUMS") or item["name"] in indexed or
                not isinstance(item.get("sha256"), str) or not HEX.fullmatch(item["sha256"]) or
                type(item.get("size")) is not int or not 0 < item["size"] <= MAX_PACKAGE_BYTES):
            fail("Malformed signed asset entry")
        indexed[item["name"]] = item
    if list(indexed) != sorted((*PAYLOAD_NAMES, "SHA256SUMS")):
        fail("Signed asset inventory must be exact and sorted")
    return value, indexed


def capsule_files(raw, source_commit):
    """No extraction helpers/extensions: bounded bytes, regular exact members."""
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as compressed:
            content = compressed.read(MAX_SMALL_BYTES + 1)
        if len(content) > MAX_SMALL_BYTES:
            fail("Installer capsule exceeds unpacked limit")
        stream, files = io.BytesIO(content), {}
        while True:
            header = stream.read(512)
            if len(header) != 512:
                fail("Truncated installer capsule")
            if header == b"\0" * 512:
                tail = stream.read()
                if len(tail) < 512 or any(tail):
                    fail("Malformed installer capsule terminator")
                break
            member = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
            if (member.type != tarfile.REGTYPE or member.name not in ("manifest.json", *CAPSULE_FILES) or
                    member.name in files or member.mode != 0o644 or member.linkname or member.uid != 0 or member.gid != 0 or
                    not 0 < member.size <= MAX_SMALL_BYTES):
                fail("Unsafe or unknown installer capsule member")
            data = stream.read(member.size)
            padding = stream.read((-member.size) % 512)
            if len(data) != member.size or padding != b"\0" * ((-member.size) % 512):
                fail("Truncated installer capsule member")
            files[member.name] = data
        if set(files) != {"manifest.json", *CAPSULE_FILES}:
            fail("Incomplete installer capsule")
        manifest = strict_json(files.pop("manifest.json"))
        if (not isinstance(manifest, dict) or type(manifest.get("schema")) is not int or manifest.get("schema") != 1 or
                manifest.get("component") != "aster-cloud-installer" or manifest.get("version") != VERSION or
                manifest.get("release_kind") != "release" or manifest.get("channel") != "prerelease" or
                manifest.get("release_tag") != TAG or manifest.get("source_commit") != source_commit or
                not isinstance(manifest.get("files"), list) or len(manifest["files"]) != 3):
            fail("Wrong installer capsule manifest")
        expected = [{"path": name, "sha256": digest(files[name]), "size": len(files[name]), "mode": "0644"}
                    for name in sorted(CAPSULE_FILES)]
        if manifest["files"] != expected:
            fail("Installer capsule file hash, size or mode mismatch")
        return files
    except (OSError, EOFError, tarfile.TarError, UnicodeError, ValueError):
        fail("Unreadable installer capsule")


def verify_release_receipt(bundle_abs, sha256, component, manifest, receipt_abs, *, offline=True):
    """Reverify local cryptographic proof, never JSON 'verified' assertions.

    No downloads, keychain, user config or TUF refresh. Bootstrap must first
    create the private HOME/config and obtain the code-pinned official roots.
    release_id is observed GitHub HTTPS metadata, NOT a signed authorization.
    """
    if offline is not True:
        fail("Only offline release verification is supported")
    receipt = strict_json(read_private(receipt_abs, MAX_SMALL_BYTES))
    keys = {"schema", "repository", "repository_id", "tag", "version", "channel", "release_id", "source_commit",
            "component", "asset_name", "asset_sha256", "asset_size", "files", "verification_home", "verification_config"}
    if not isinstance(receipt, dict) or set(receipt) != keys or type(receipt.get("schema")) is not int or receipt["schema"] != 1:
        fail("Unexpected publisher receipt schema")
    role = component.removeprefix("aster-cloud-")
    if role not in ("controller", "node"):
        fail("Unknown Cloud release component")
    asset_name = "aster-cloud-" + role + "-" + VERSION + "-linux-amd64.tar.gz"
    if (receipt["repository"] != REPOSITORY or receipt["repository_id"] != REPOSITORY_ID or
            receipt["tag"] != TAG or receipt["version"] != VERSION or receipt["channel"] != "prerelease" or
            type(receipt["release_id"]) is not int or receipt["release_id"] <= 0 or receipt["component"] != component or
            receipt["asset_name"] != asset_name or receipt["asset_sha256"] != sha256 or
            Path(bundle_abs).name != asset_name or not isinstance(sha256, str) or not HEX.fullmatch(sha256)):
        fail("Release receipt identity mismatch")
    files = receipt["files"]
    if not isinstance(files, dict) or set(files) != {"manifest", "capsule", "attestation", "trusted_root", "gh"}:
        fail("Incomplete release proof files")
    raw, paths = {}, {}
    for key, item in files.items():
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "size"}:
            fail("Malformed release proof file")
        paths[key] = protected_path(item["path"])
        raw[key] = read_private(item["path"], GH_BINARY_SIZE if key == "gh" else MAX_SMALL_BYTES)
        if type(item["size"]) is not int or len(raw[key]) != item["size"] or digest(raw[key]) != item["sha256"]:
            fail("Release proof file hash or size mismatch")
    if (digest(raw["gh"]) != GH_BINARY_SHA256 or len(raw["gh"]) != GH_BINARY_SIZE or
            digest(raw["trusted_root"]) != TRUSTED_ROOT_SHA256 or len(raw["trusted_root"]) != TRUSTED_ROOT_SIZE or
            paths["manifest"].name != "release-manifest.json" or paths["capsule"].name != CAPSULE_NAME or
            paths["attestation"].name != "attestations.jsonl"):
        fail("Publisher verifier, trusted roots or proof filenames are not code-pinned")
    home = protected_path(receipt["verification_home"], directory=True)
    config = protected_path(receipt["verification_config"], directory=True)
    if any(home.iterdir()) or any(config.iterdir()):
        fail("Offline verifier requires empty private anonymous HOME/config")
    published, assets = release_manifest(raw["manifest"])
    source = published["source_commit"]
    if receipt["source_commit"] != source:
        fail("Receipt source does not match signed release manifest")
    if any(manifest.get(key) != value for key, value in {
        "schema": 1, "component": component, "version": VERSION, "release_kind": "release", "channel": "prerelease",
        "release_tag": TAG, "source_commit": source, "platform": "linux-amd64",
    }.items()):
        fail("Bundle manifest does not match the official prerelease identity")
    package = read_private(bundle_abs, MAX_PACKAGE_BYTES)
    if (len(package) != receipt["asset_size"] or digest(package) != sha256 or
            assets[asset_name] != {"name": asset_name, "sha256": sha256, "size": len(package)} or
            assets[CAPSULE_NAME] != {"name": CAPSULE_NAME, "sha256": digest(raw["capsule"]), "size": len(raw["capsule"])}):
        fail("Package or capsule bytes do not match signed release inventory")
    for key in ("manifest", "capsule"):
        verify_attestation(paths[key], digest(raw[key]), source, paths["gh"], paths["trusted_root"], paths["attestation"], home, config)
    verify_attestation(Path(bundle_abs), sha256, source, paths["gh"], paths["trusted_root"], paths["attestation"], home, config)
    code = capsule_files(raw["capsule"], source)
    bootstrap = assets[BOOTSTRAP_NAME]
    if bootstrap["sha256"] != digest(code["release_verify.py"]) or bootstrap["size"] != len(code["release_verify.py"]):
        fail("Bootstrap and installer verifier code differ")
    installer_dir = Path(receipt_abs).parent / "installer"
    protected_path(str(installer_dir), directory=True)
    if {p.name for p in installer_dir.iterdir()} != set(CAPSULE_FILES):
        fail("Installer directory has unknown adjacent imports or partial state")
    for name in CAPSULE_FILES:
        if read_private(str(installer_dir / name), MAX_SMALL_BYTES) != code[name]:
            fail("Installer adjacent code differs from its authenticated capsule")
    return {key: receipt[key] for key in ("repository", "release_id", "tag", "version", "source_commit", "component", "asset_name", "asset_sha256")}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


def allowed_url(url, *, redirected=False):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or parsed.username or parsed.password or parsed.port not in (None, 443) or
            parsed.fragment or any(c.isspace() or ord(c) < 32 for c in url)):
        fail("Only canonical official HTTPS release URLs are allowed")
    prefix = "/repos/" + REPOSITORY
    if parsed.hostname == "api.github.com" and not parsed.query:
        if (parsed.path in (prefix, prefix + "/releases/tags/" + TAG, prefix + "/git/ref/tags/" + TAG) or
                re.fullmatch(re.escape(prefix) + r"/releases/[1-9][0-9]*", parsed.path) or
                re.fullmatch(re.escape(prefix) + r"/git/tags/[0-9a-f]{40}", parsed.path)):
            return "api"
    if parsed.hostname == "github.com" and not parsed.query:
        if parsed.path == "/cli/cli/releases/download/v" + GH_VERSION + "/" + GH_TAR_NAME:
            return "asset"
        if any(parsed.path == "/" + REPOSITORY + "/releases/download/" + TAG + "/" + name for name in RELEASE_NAMES):
            return "asset"
    if redirected and parsed.hostname == "release-assets.githubusercontent.com" and parsed.path.startswith("/github-production-release-asset/"):
        return "asset"
    fail("Release URL repository, tag, asset or redirect host refused")


def fetch(url, limit, *, opener=None):
    """Anonymous, bounded GET with explicit redirect policy and no env proxy/auth."""
    kind = allowed_url(url)
    if opener is None:
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=context))
    deadline = time.monotonic() + 120
    for redirects in range(4):
        if time.monotonic() >= deadline:
            fail("Official release download deadline exceeded")
        request = urllib.request.Request(url, headers={"Accept": "application/json" if kind == "api" else "application/octet-stream",
                                                       "Accept-Encoding": "identity", "User-Agent": "aster-cloud-reviewed-bootstrap/" + VERSION})
        try:
            response = opener.open(request, timeout=min(15, max(1, deadline - time.monotonic())))
        except urllib.error.HTTPError as error:
            if error.code not in (301, 302, 303, 307, 308) or kind != "asset" or redirects == 3:
                fail("Official release HTTP request refused")
            target = urllib.parse.urljoin(url, error.headers.get("Location", ""))
            if target == url or allowed_url(target, redirected=True) != "asset":
                fail("Official release redirect refused")
            url = target
            continue
        except (OSError, ValueError, urllib.error.URLError):
            fail("Official release download failed; diagnostics withheld")
        try:
            with response:
                if response.status != 200 or response.geturl() != url or response.headers.get("Content-Encoding", "identity") != "identity":
                    fail("Unexpected release response or content encoding")
                length = response.headers.get("Content-Length")
                if length is not None and (not length.isdigit() or not 0 < int(length) <= limit):
                    fail("Release response exceeds the allowed size")
                chunks, total = [], 0
                while True:
                    if time.monotonic() >= deadline:
                        fail("Official release download deadline exceeded")
                    chunk = response.read(min(65536, limit + 1 - total))
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > limit:
                        fail("Release response exceeds the allowed size")
                    chunks.append(chunk)
                if total == 0 or length is not None and total != int(length):
                    fail("Empty or truncated release response")
                return b"".join(chunks)
        except (OSError, ValueError):
            fail("Official release transfer failed; diagnostics withheld")
    fail("Too many release redirects")


def public_release_metadata():
    prefix = "https://api.github.com/repos/" + REPOSITORY
    repository = strict_json(fetch(prefix, MAX_SMALL_BYTES))
    if (not isinstance(repository, dict) or repository.get("id") != REPOSITORY_ID or repository.get("full_name") != REPOSITORY or
            repository.get("private") is not False or repository.get("default_branch") != "main" or
            repository.get("owner", {}).get("id") != OWNER_ID):
        fail("Official public repository identity mismatch")
    release = strict_json(fetch(prefix + "/releases/tags/" + TAG, MAX_SMALL_BYTES))
    if (not isinstance(release, dict) or type(release.get("id")) is not int or release["id"] <= 0 or
            release.get("tag_name") != TAG or release.get("draft") is not False or release.get("prerelease") is not True):
        fail("The authorized Cloud prerelease is not publicly available")
    assets = {}
    if not isinstance(release.get("assets"), list):
        fail("Missing release assets")
    for asset in release["assets"]:
        if (not isinstance(asset, dict) or asset.get("name") not in RELEASE_NAMES or asset["name"] in assets or
                type(asset.get("id")) is not int or asset["id"] <= 0 or asset.get("state") != "uploaded" or
                type(asset.get("size")) is not int or not 0 < asset["size"] <= MAX_PACKAGE_BYTES or
                not isinstance(asset.get("digest"), str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", asset["digest"]) or
                asset.get("browser_download_url") != "https://github.com/" + REPOSITORY + "/releases/download/" + TAG + "/" + asset["name"]):
            fail("Unexpected, duplicate or incomplete official release asset")
        assets[asset["name"]] = {key: asset[key] for key in ("id", "name", "size", "digest", "browser_download_url")}
    if set(assets) != set(RELEASE_NAMES) or len({asset["id"] for asset in assets.values()}) != len(assets):
        fail("Official release asset allowlist is incomplete")
    ref = strict_json(fetch(prefix + "/git/ref/tags/" + TAG, MAX_SMALL_BYTES))
    obj = ref.get("object", {}) if isinstance(ref, dict) else {}
    for _ in range(4):
        if not isinstance(obj, dict) or not isinstance(obj.get("sha"), str) or not COMMIT.fullmatch(obj["sha"]):
            fail("Malformed official tag reference")
        if obj.get("type") == "commit":
            return {"release_id": release["id"], "source_commit": obj["sha"], "assets": assets}
        if obj.get("type") != "tag":
            fail("Official tag does not resolve to a commit")
        obj = strict_json(fetch(prefix + "/git/tags/" + obj["sha"], MAX_SMALL_BYTES)).get("object", {})
    fail("Excessive annotated tag depth")


def write_new(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def pinned_gh(raw):
    if len(raw) != GH_TAR_SIZE or digest(raw) != GH_TAR_SHA256:
        fail("Official GitHub CLI archive does not match the reviewed pin")
    try:
        # The entire compressed archive is already pinned immutable bytes; only
        # this single regular member is ever read, never extract()/extractall().
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
            matches = [member for member in archive if member.name == "gh_" + GH_VERSION + "_linux_amd64/bin/gh"]
            if len(matches) != 1 or not matches[0].isfile() or matches[0].size != GH_BINARY_SIZE:
                fail("Unexpected pinned GitHub CLI member")
            output = archive.extractfile(matches[0]).read(GH_BINARY_SIZE + 1)
        if len(output) != GH_BINARY_SIZE or digest(output) != GH_BINARY_SHA256:
            fail("Pinned GitHub CLI binary differs from the reviewed archive")
        return output
    except (OSError, tarfile.TarError, EOFError):
        fail("Malformed pinned GitHub CLI archive")


def bundle_manifest(raw):
    # This is only the bounded first metadata member, not a replacement for the
    # installer's complete tar/file/ELF verifier before any installation writes.
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as archive:
            header = archive.read(512)
            member = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
            if member.name != "manifest.json" or member.type != tarfile.REGTYPE or not 0 < member.size <= MAX_SMALL_BYTES:
                fail("Expected first regular bundle manifest")
            value = strict_json(archive.read(member.size))
            if not isinstance(value, dict):
                fail("Bundle manifest must be an object")
            return value
    except (OSError, EOFError, tarfile.TarError, UnicodeError, ValueError):
        fail("Malformed bundle manifest")


def handoff(final, role, package_sha, *, apply=False, start=False, resume=False, download_only=False, evidence=None):
    asset_name = "aster-cloud-" + role + "-" + VERSION + "-linux-amd64.tar.gz"
    manifest = bundle_manifest(read_private(str(final / asset_name), MAX_PACKAGE_BYTES))
    identity = verify_release_receipt(str(final / asset_name), package_sha, "aster-cloud-" + role, manifest, str(final / "release-receipt.json"))
    command = ["/usr/bin/python3", "-I", str(final / "installer/install.py"), role, "--wizard",
               "--bundle", str(final / asset_name), "--sha256", package_sha,
               "--release-receipt", str(final / "release-receipt.json")]
    if apply:
        command.append("--apply")
    if start:
        command.append("--start")
    if resume:
        command.append("--resume")
    if download_only:
        # A real production installer plan is executed only after every code
        # byte above is authenticated. It never receives wizard/apply/start.
        command = ["/usr/bin/python3", "-I", str(final / "installer/install.py"), role, "--plan",
                   "--bundle", str(final / asset_name), "--sha256", package_sha,
                   "--release-receipt", str(final / "release-receipt.json")]
        try:
            result = subprocess.run(command, env={"PATH": "/usr/bin:/bin", "HOME": "/root", "LANG": "C.UTF-8"},
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180, check=False)
        except (OSError, subprocess.TimeoutExpired):
            fail("Authenticated production plan unavailable or timed out")
        if result.returncode or len(result.stdout) > MAX_SMALL_BYTES:
            fail("Authenticated production plan refused; diagnostics withheld")
        plan = strict_json(result.stdout)
        if (not isinstance(plan, dict) or plan.get("mode") != "plan" or plan.get("release_kind") != "release" or
                plan.get("source_commit") != identity["source_commit"] or plan.get("component") != role or
                plan.get("software") != "not-installed-by-plan" or plan.get("service") != "not-started-by-plan"):
            fail("Authenticated production plan evidence mismatch")
        proof = {"schema": 1, "passed": True, "role": role, "tag": TAG, "source_commit": identity["source_commit"],
                 "release_id": identity["release_id"], "artifact_sha256": package_sha, "anonymous_download": True,
                 "publisher_signature_reverified": True, "production_installer_plan": True,
                 "host_apply": False, "service_started": False, "real_kvm_acceptance": False}
        if evidence is not None:
            target = Path(evidence)
            if not target.is_absolute() or str(target) != str(evidence) or ".." in target.parts:
                fail("Canonical absolute redacted-evidence file required")
            for parent in target.parents:
                if parent.is_symlink() or not parent.is_dir():
                    fail("Evidence directory aliases refused")
            write_new(target, (json.dumps(proof, sort_keys=True, indent=2) + "\n").encode())
        print(json.dumps(proof, sort_keys=True))
        return proof
    tty = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
    os.dup2(tty, 0)
    os.close(tty)
    os.execve(command[0], command, {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LANG": "C.UTF-8"})


def bootstrap(role, *, apply=False, start=False, resume=False, download_only=False, evidence=None):
    if role not in ("controller", "node") or os.geteuid() != 0 or sys.platform != "linux" or os.uname().machine not in ("x86_64", "amd64"):
        fail("Official bootstrap requires root on Linux amd64 and a fixed Cloud role")
    # The code pipe is not a terminal. Never accept credentials through it or
    # silently downgrade the wizard to EOF/noninteractive defaults.
    if not download_only:
        try:
            tty = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
        except OSError:
            fail("Interactive installation requires a real controlling terminal")
        os.close(tty)
    metadata = public_release_metadata()
    if not CACHE_ROOT.exists():
        for ancestor in CACHE_ROOT.parents:
            info = ancestor.lstat()
            if info.st_uid != 0 or not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
                fail("Unsafe official download cache ancestor")
        CACHE_ROOT.mkdir(mode=0o700)
    protected_path(str(CACHE_ROOT), directory=True)
    final = CACHE_ROOT / (TAG + "-" + role + "-" + metadata["source_commit"])
    if final.exists() or final.is_symlink():
        if not resume:
            fail("Existing official download cache is never overwritten or silently adopted; explicitly review and resume")
        protected_path(str(final), directory=True)
        receipt = strict_json(read_private(str(final / "release-receipt.json"), MAX_SMALL_BYTES))
        asset_name = "aster-cloud-" + role + "-" + VERSION + "-linux-amd64.tar.gz"
        if (receipt.get("release_id") != metadata["release_id"] or receipt.get("source_commit") != metadata["source_commit"] or
                "sha256:" + str(receipt.get("asset_sha256")) != metadata["assets"][asset_name]["digest"]):
            fail("Resume no longer matches the original observed official release")
        handoff(final, role, receipt["asset_sha256"], apply=apply, start=start, resume=True, download_only=download_only, evidence=evidence)
        return
    with tempfile.TemporaryDirectory(prefix=".download-", dir=CACHE_ROOT) as temporary:
        stage = Path(temporary)
        for name in ("home", "config", "installer"):
            (stage / name).mkdir(mode=0o700)
        gh_archive = fetch("https://github.com/cli/cli/releases/download/v" + GH_VERSION + "/" + GH_TAR_NAME, GH_TAR_SIZE)
        write_new(stage / "gh", pinned_gh(gh_archive), 0o700)
        asset_name = "aster-cloud-" + role + "-" + VERSION + "-linux-amd64.tar.gz"
        needed = ("release-trusted-root.json", "attestations.jsonl", "release-manifest.json", CAPSULE_NAME, asset_name)
        for name in needed:
            entry = metadata["assets"][name]
            limit = MAX_PACKAGE_BYTES if name == asset_name else MAX_SMALL_BYTES
            if entry["size"] > limit:
                fail("Official asset exceeds its fixed role limit")
            raw = fetch(entry["browser_download_url"], limit)
            if len(raw) != entry["size"] or "sha256:" + digest(raw) != entry["digest"]:
                fail("Official asset changed or was truncated during download")
            write_new(stage / name, raw)
        if digest(read_private(str(stage / "release-trusted-root.json"), MAX_SMALL_BYTES)) != TRUSTED_ROOT_SHA256:
            fail("Official trusted-root snapshot has changed; reviewed bootstrap update required")
        published, assets = release_manifest(read_private(str(stage / "release-manifest.json"), MAX_SMALL_BYTES))
        if published["source_commit"] != metadata["source_commit"]:
            fail("Signed source and observed official tag disagree")
        for name, entry in assets.items():
            observed = metadata["assets"][name]
            if entry["size"] != observed["size"] or "sha256:" + entry["sha256"] != observed["digest"]:
                fail("Signed inventory and observed release asset metadata disagree")
        for name in ("release-manifest.json", CAPSULE_NAME, asset_name):
            path = stage / name
            raw = read_private(str(path), MAX_PACKAGE_BYTES if name == asset_name else MAX_SMALL_BYTES)
            verify_attestation(path, digest(raw), metadata["source_commit"], stage / "gh", stage / "release-trusted-root.json", stage / "attestations.jsonl", stage / "home", stage / "config")
        code = capsule_files(read_private(str(stage / CAPSULE_NAME), MAX_SMALL_BYTES), metadata["source_commit"])
        for name, raw in code.items():
            write_new(stage / "installer" / name, raw)
        # Recheck the same observed release ID, tag and every asset after all
        # transfers. No mutable latest link or mixed-release download is used.
        if public_release_metadata() != metadata:
            fail("Official release changed during download; original cache preserved")
        def receipt_for(base):
            file_names = {"manifest": "release-manifest.json", "capsule": CAPSULE_NAME, "attestation": "attestations.jsonl", "trusted_root": "release-trusted-root.json", "gh": "gh"}
            files = {}
            for key, name in file_names.items():
                raw = read_private(str(stage / name), GH_BINARY_SIZE if key == "gh" else MAX_SMALL_BYTES)
                files[key] = {"path": str(base / name), "sha256": digest(raw), "size": len(raw)}
            entry = assets[asset_name]
            return {"schema": 1, "repository": REPOSITORY, "repository_id": REPOSITORY_ID, "tag": TAG, "version": VERSION,
                    "channel": "prerelease", "release_id": metadata["release_id"], "source_commit": metadata["source_commit"],
                    "component": "aster-cloud-" + role, "asset_name": asset_name, "asset_sha256": entry["sha256"], "asset_size": entry["size"],
                    "files": files, "verification_home": str(base / "home"), "verification_config": str(base / "config")}
        receipt = receipt_for(stage)
        receipt_path = stage / "release-receipt.json"
        write_new(receipt_path, (json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode())
        package_manifest = bundle_manifest(read_private(str(stage / asset_name), MAX_PACKAGE_BYTES))
        verify_release_receipt(str(stage / asset_name), assets[asset_name]["sha256"], "aster-cloud-" + role, package_manifest, str(receipt_path))
        replacement = stage / "receipt.final"
        write_new(replacement, (json.dumps(receipt_for(final), sort_keys=True, indent=2) + "\n").encode())
        os.replace(replacement, receipt_path)
        if final.exists() or final.is_symlink():
            fail("Official destination appeared during download; refusing to replace it")
        os.rename(stage, final)
        directory = os.open(CACHE_ROOT, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    return handoff(final, role, assets[asset_name]["sha256"], apply=apply, start=start, resume=resume, download_only=download_only, evidence=evidence)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=("controller", "node"))
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--start", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--download-only", action="store_true", help="anonymous verified download plus real read-only installer plan; no host apply")
    parser.add_argument("--evidence", type=Path, help="new absolute file for redacted download-only proof")
    args = parser.parse_args(argv)
    try:
        if args.download_only and (args.apply or args.start) or args.evidence and not args.download_only:
            fail("Download-only evidence must never request host apply or start")
        bootstrap(args.role, apply=args.apply, start=args.start, resume=args.resume, download_only=args.download_only, evidence=args.evidence)
    except (ReleaseError, OSError, ValueError, KeyError, TypeError):
        print("Cloud prerelease bootstrap refused; no unverified installer executed. Check the reviewed release instructions.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

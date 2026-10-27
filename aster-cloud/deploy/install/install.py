#!/usr/bin/env python3
"""Fail-closed native Aster Cloud installer (stdlib core).

This program never downloads a release, edits physical networking, or deletes
application data. Native dependencies, new dedicated MySQL and isolated libvirt
preparation require explicit approval. A SHA256 alone is NOT publisher identity:
local development needs opt-in; the sole prerelease envelope needs offline
cryptographic publisher reverification. No stable channel is inferred.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import datetime
import fcntl
import getpass
import gzip
import hashlib
import http.client
import io
import importlib.util
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import secrets
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import time
from urllib.parse import urlsplit

MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_FILES = 10000
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
COMPONENTS = {"controller": "aster-cloud-controller", "node": "aster-cloud-node"}
INSTALL_ROOT = Path("/opt/aster-cloud")
STATE_ROOT = Path("/var/lib/aster-cloud-installer")
SYSTEMD_ROOT = Path("/etc/systemd/system")
CONFIG_PATHS = {"controller": Path("/etc/aster-controller/config.json"),
                "node": Path("/etc/aster-node/node.json")}
SYSTEMCTL = "/usr/bin/systemctl"
SAFE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "HOME": "/root"}
PROVISION_MODULE = None
RELEASE_MODULE = None


class InstallerError(Exception):
    """Only fixed, secret-free diagnostics are exposed to the operator."""


@dataclass
class VerifiedBundle:
    manifest: dict
    files: dict[str, bytes]


def fail(message):
    raise InstallerError(message)


def provisioning_module():
    global PROVISION_MODULE
    if PROVISION_MODULE is None:
        spec = importlib.util.spec_from_file_location("aster_native_provision", Path(__file__).with_name("provision.py"))
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        previous = sys.dont_write_bytecode
        try:
            # Even a non-root plan with opt-in flags must not create __pycache__.
            sys.dont_write_bytecode = True
            spec.loader.exec_module(module)
        finally:
            sys.dont_write_bytecode = previous
        PROVISION_MODULE = module
    return PROVISION_MODULE


def native_options(args):
    options = {"install_dependencies": bool(getattr(args, "install_dependencies", False)),
               "provision_mysql": bool(getattr(args, "provision_mysql", False)),
               "prepare_libvirt": bool(getattr(args, "prepare_libvirt", False))}
    if options["prepare_libvirt"] and args.component != "node":
        fail("Libvirt daemon preparation is node-only")
    if options["provision_mysql"]:
        if args.component != "controller":
            fail("Dedicated MySQL provisioning is controller-only")
        module = provisioning_module()
        try:
            module.validate_names(args.database_name, args.runtime_db_user, args.migration_db_user)
        except module.ProvisionError as error:
            fail(str(error))
        options.update(database=args.database_name, runtime_user=args.runtime_db_user, migration_user=args.migration_db_user)
    return options


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                fail("Duplicate JSON key rejected")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: fail("Non-finite JSON value rejected"))
    except (ValueError, UnicodeError, RecursionError):
        fail("Invalid JSON document")


def safe_member(name):
    if (not isinstance(name, str) or not name or len(name) > 240 or
            any(ord(c) < 32 or ord(c) == 127 for c in name) or "\\" in name or
            not re.fullmatch(r"[A-Za-z0-9_./@+:-]+", name) or
            name.startswith("/") or str(PurePosixPath(name)) != name or
            any(part in ("", ".", "..") for part in name.split("/"))):
        fail("Noncanonical or unsafe bundle path")
    if name != "manifest.json" and name.split("/")[0] not in {
            "bin", "ui", "templates", "licenses", "docs"}:
        fail("Unknown bundle top-level path")
    return name


def verify_bundle(path, expected_sha256, component):
    """Read and completely validate a local archive before any installation write."""
    if component in COMPONENTS:
        component = COMPONENTS[component]
    if component not in COMPONENTS.values() or not SHA_RE.fullmatch(expected_sha256 or ""):
        fail("Exact component and lowercase external SHA256 required")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                    before.st_size < 1 or before.st_size > MAX_ARCHIVE_BYTES):
                fail("Bundle must be a bounded regular file without hardlinks")
            # Hash and parse exactly one bounded immutable byte snapshot. An fd
            # alone prevents path replacement but NOT same-inode writes followed
            # by restoring mtime. No seek/re-read of attacker-changeable bytes.
            snapshot = stream.read(MAX_ARCHIVE_BYTES + 1)
            if len(snapshot) != before.st_size or len(snapshot) > MAX_ARCHIVE_BYTES:
                fail("Bundle size changed during snapshot")
            if hashlib.sha256(snapshot).hexdigest() != expected_sha256:
                fail("External bundle SHA256 mismatch")
            tar_stream = io.BytesIO(snapshot)
            files, metadata, total = {}, {}, 0
            # Parse each bounded raw header ourselves. tarfile's iterator eagerly
            # reads PAX/GNU metadata BEFORE yielding, which would bypass our size
            # limits. TarInfo.frombuf parses just one 512-byte header and cannot
            # read extension payloads. Only ordinary USTAR regular files pass.
            compressed = tar_stream.read(2) == b"\x1f\x8b"
            tar_stream.seek(0)
            archive = gzip.GzipFile(fileobj=tar_stream) if compressed else tar_stream
            try:
                while True:
                    header = archive.read(512)
                    if header == b"\0" * 512:
                        if archive.read(512) != b"\0" * 512:
                            fail("Two zero end-of-archive blocks required")
                        trailing = archive.read(10241)
                        if len(trailing) > 10240 or trailing.strip(b"\0"):
                            fail("Unexpected or oversized trailing tar data")
                        break
                    if len(header) != 512:
                        fail("Truncated tar header")
                    member = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
                    name = safe_member(member.name)
                    limit = MAX_MANIFEST_BYTES if name == "manifest.json" else MAX_FILE_BYTES
                    if (not member.isreg() or member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE)
                            or member.sparse is not None or member.linkname or member.pax_headers
                            or member.mode not in (0o644, 0o755) or member.size < 0 or
                            member.size > limit or name in files or len(files) >= MAX_FILES):
                        fail("Unsafe, duplicate, oversized or special tar member")
                    total += member.size
                    if total > MAX_TOTAL_BYTES:
                        fail("Unpacked bundle exceeds total limit")
                    raw = archive.read(member.size)
                    if len(raw) != member.size:
                        fail("Truncated bundle member")
                    padding = (-member.size) % 512
                    if archive.read(padding) != b"\0" * padding:
                        fail("Malformed nonzero tar padding")
                    files[name] = raw
                    metadata[name] = member.mode
            finally:
                if compressed:
                    archive.close()
            after = os.fstat(stream.fileno())
            if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
                fail("Bundle changed during verification")
    except (OSError, tarfile.TarError, EOFError, UnicodeError, ValueError):
        fail("Local bundle unreadable or malformed")
    if "manifest.json" not in files:
        fail("Bundle manifest.json missing")
    manifest = strict_json(files.pop("manifest.json"))
    if (not isinstance(manifest, dict) or type(manifest.get("schema")) is not int or
            manifest["schema"] != 1 or manifest.get("component") != component or
            manifest.get("platform") != "linux-amd64" or
            not isinstance(manifest.get("version"), str) or
            not isinstance(manifest.get("source_commit"), str) or
            not re.fullmatch(r"[0-9a-f]{40}", manifest["source_commit"]) or
            not isinstance(manifest.get("files"), list) or
            len(manifest["files"]) != len(files)):
        fail("Wrong component, platform, version or manifest schema")
    development = manifest.get("release_kind") == "development" and re.fullmatch(r"0\.[0-9]+\.[0-9]+-dev(?:\.[0-9]+)?", manifest["version"])
    release = (manifest.get("release_kind") == "release" and manifest["version"] == "0.1.0-rc.1" and
               manifest.get("channel") == "prerelease" and manifest.get("release_tag") == "cloud-v0.1.0-rc.1")
    if not development and not release:
        fail("Only explicit development versions or the authenticated 0.1.0-rc.1 prerelease envelope are supported")
    listed = set()
    for entry in manifest["files"]:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "size", "mode"}:
            fail("Malformed manifest file entry")
        name = safe_member(entry["path"])
        if (name == "manifest.json" or name in listed or name not in files or
                type(entry["size"]) is not int or entry["size"] != len(files[name]) or
                entry["mode"] not in ("0644", "0755") or
                int(entry["mode"], 8) != metadata[name] or
                not isinstance(entry["sha256"], str) or not SHA_RE.fullmatch(entry["sha256"]) or
                hashlib.sha256(files[name]).hexdigest() != entry["sha256"]):
            fail("Manifest file digest, size, mode or membership mismatch")
        if (name.startswith("bin/") and entry["mode"] != "0755") or (
                not name.startswith("bin/") and entry["mode"] != "0644"):
            fail("Unexpected executable or non-executable file mode")
        listed.add(name)
    required = ({"bin/aster-controller", "ui/index.html"} if component.endswith("controller")
                else {"bin/aster-node", "bin/aster-network"})
    if listed != set(files) or not required <= listed:
        fail("Bundle required files missing or unlisted files present")
    for name in listed:
        parent = PurePosixPath(name).parent
        while str(parent) != ".":
            if str(parent) in listed:
                fail("Bundle file collides with an implied parent directory")
            parent = parent.parent
    for name in required:
        if name.startswith("bin/"):
            raw = files[name]
            if len(raw) < 20 or raw[:6] != b"\x7fELF\x02\x01" or raw[18:20] != b"\x3e\x00":
                fail("Bundle executable is not Linux amd64 ELF")
    return VerifiedBundle(manifest, files)


def canonical(path):
    p = Path(path)
    if (not p.is_absolute() or str(p) != str(path) or
            any(ord(c) < 32 or ord(c) == 127 for c in str(path)) or
            ".." in p.parts):
        fail("Canonical absolute path required")
    return p


def protected_path(path, *, private=False, directory=False, allow_missing=False):
    """Require a root-owned, nonwritable ancestry, without symlink/hardlink aliases."""
    p = canonical(path)
    for current in [*reversed(p.parents), p]:
        try:
            info = current.lstat()
        except FileNotFoundError:
            if allow_missing:
                continue
            fail("Protected path missing")
        last = current == p
        if (info.st_uid != 0 or stat.S_ISLNK(info.st_mode) or
                info.st_mode & 0o022 or
                (not last and not stat.S_ISDIR(info.st_mode))):
            fail("Unsafe protected path ownership, permissions or symlink")
        if last:
            if directory:
                if not stat.S_ISDIR(info.st_mode):
                    fail("Protected directory required")
            elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                fail("Protected regular file without hardlinks required")
            if private and info.st_mode & 0o077:
                fail("Private root-only permissions required")
    return p


def protected_read(path, maximum=65536, private=True):
    p = protected_path(path, private=private)
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as f:
            st = os.fstat(f.fileno())
            if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != 0 or
                    st.st_mode & (0o077 if private else 0o022) or st.st_size > maximum):
                fail("Protected opened inode rejected")
            raw = f.read(maximum + 1)
            if len(raw) > maximum or not raw:
                fail("Protected input empty or oversized")
            return raw
    except OSError:
        fail("Protected input cannot be read")


def ensure_dir(path, mode=0o700):
    p = protected_path(str(path), directory=True, allow_missing=True)
    if p.exists():
        protected_path(str(p), directory=True)
    else:
        if not p.parent.exists():
            ensure_dir(p.parent, 0o755)
        p.mkdir(mode=mode)
        p.chmod(mode)
    return p


def write_new(path, raw, mode=0o600):
    """Exclusive write; matching existing content is reusable, never overwritten."""
    path = Path(path)
    protected_path(str(path), private=mode == 0o600, allow_missing=True)
    if path.exists():
        if protected_read(str(path), max(len(raw), 1), mode == 0o600) != raw or stat.S_IMODE(path.stat().st_mode) != mode:
            fail("Existing managed file differs; refusing overwrite")
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as f:
        os.fchmod(f.fileno(), mode)
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())


def atomic_state(path, state):
    # Only this installer's own receipt is replaced, never app config or secrets.
    protected_path(str(path), private=True, allow_missing=True)
    temporary = path.with_name("state.new")
    raw = (json.dumps(state, indent=2, sort_keys=True) + "\n").encode()
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temporary, path)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def recover_pending_state(state_path, args):
    """Explicitly resume an interrupted atomic receipt write, never app data."""
    pending = state_path.with_name("state.new")
    if not pending.exists():
        return
    if not args.resume:
        fail("Interrupted receipt update exists; review it then explicitly --resume")
    new_state = strict_json(protected_read(str(pending)))
    if (not isinstance(new_state, dict) or new_state.get("schema") != 1 or
            new_state.get("bundle_sha256") != args.sha256 or new_state.get("component") != args.component):
        fail("Interrupted receipt is incomplete or belongs to another bundle; manual review required")
    if state_path.exists():
        old_state = strict_json(protected_read(str(state_path)))
        if (not isinstance(old_state, dict) or old_state.get("component") != args.component or
                old_state.get("bundle_sha256") != args.sha256):
            fail("Interrupted receipt conflicts with durable receipt")
    protected_path(str(state_path), private=True, allow_missing=True)
    os.replace(pending, state_path)
    parent = os.open(state_path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def target_info():
    fields = {}
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                fields[key] = value.strip('"')
    except OSError:
        pass
    return {"system": platform.system(), "architecture": platform.machine(),
            "distribution": fields.get("ID", "unknown"), "version": fields.get("VERSION_ID", "unknown")}


def supported_target(info):
    return (info["system"] == "Linux" and info["architecture"] in ("x86_64", "amd64") and
            info["distribution"] == "ubuntu" and info["version"] in ("22.04", "24.04"))


def check_target():
    info = target_info()
    if os.geteuid() != 0:
        fail("Apply requires root; plan works without root")
    if not supported_target(info):
        fail("Apply targets native Ubuntu 22.04 or 24.04 amd64 only; Ubuntu 26.04 and unknown releases are unsupported")
    protected_path(SYSTEMCTL)
    if not Path("/run/systemd/system").is_dir():
        fail("Native booted systemd host required")


def node_preflight():
    missing = []
    for name in ("/usr/bin/virsh", "/usr/bin/qemu-img", "/usr/bin/qemu-system-x86_64", "/usr/bin/cloud-localds"):
        try:
            p = protected_path(name)
            if not p.stat().st_mode & 0o111:
                missing.append("host-binary-not-executable")
        except (InstallerError, OSError):
            missing.append("missing-host-binary:" + name)
    try:
        info = Path("/dev/kvm").stat()
        if not stat.S_ISCHR(info.st_mode) or not os.access("/dev/kvm", os.R_OK | os.W_OK):
            missing.append("kvm-unavailable")
    except OSError:
        missing.append("kvm-unavailable")
    try:
        memory = Path("/proc/meminfo").read_text()
        total = int(re.search(r"^MemTotal:\s+(\d+)\s+kB$", memory, re.M)[1])
        if total < 2 * 1024 * 1024:
            missing.append("dedicated-kvm-host-needs-at-least-2GiB-not-finance-test-server")
    except (OSError, TypeError, ValueError):
        missing.append("host-memory-unconfirmed")
    return missing


def source_bundle(args):
    receipt = getattr(args, "release_receipt", None)
    if receipt and args.allow_development:
        fail("Publisher-authenticated release and explicit local development are mutually exclusive")
    if not args.bundle or not args.sha256 or not (args.allow_development or receipt):
        fail("Provide a publisher-verified release receipt or explicit local development bundle, canonical path and SHA256")
    canonical(args.bundle)
    bundle = verify_bundle(args.bundle, args.sha256, COMPONENTS[args.component])
    if receipt:
        if bundle.manifest.get("release_kind") != "release":
            fail("Release receipt cannot authorize a development bundle")
        canonical(receipt)
        global RELEASE_MODULE
        if RELEASE_MODULE is None:
            spec = importlib.util.spec_from_file_location("aster_release_verify", Path(__file__).with_name("release_verify.py"))
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            previous = sys.dont_write_bytecode
            try:
                sys.dont_write_bytecode = True
                spec.loader.exec_module(module)
            finally:
                sys.dont_write_bytecode = previous
            RELEASE_MODULE = module
        try:
            RELEASE_MODULE.verify_release_receipt(args.bundle, args.sha256, COMPONENTS[args.component], bundle.manifest, receipt, offline=True)
        except RELEASE_MODULE.ReleaseError:
            fail("Publisher release signature or exact bundle identity rejected; no installation performed")
    elif bundle.manifest.get("release_kind") != "development":
        fail("--allow-development never authorizes a formal/prerelease bundle; verified publisher receipt required")
    return bundle


def make_plan(args):
    options = native_options(args)
    bundle = source_bundle(args)
    target = target_info()
    codename = None
    if options["prepare_libvirt"]:
        if not supported_target(target):
            fail("Libvirt preparation plan requires a verified Ubuntu 22.04 or 24.04 amd64 target; Ubuntu 26.04 and unknown releases are unsupported")
        codename = provisioning_module().CODENAMES[target["version"]]
    return {"mode": "plan", "component": args.component, "release_kind": bundle.manifest["release_kind"],
            "version": bundle.manifest["version"], "source_commit": bundle.manifest["source_commit"],
            "bundle_sha256": args.sha256, "target": target,
            "target_support": "supported-target-not-accepted" if supported_target(target) else "unsupported-no-apply",
            "supported_ubuntu": ["22.04", "24.04"],
            "software": "not-installed-by-plan", "configuration": "approval-required",
            "service": "not-started-by-plan", "approval_supplied": bool(args.approval),
            "start_requested": args.start,
            "guided_configuration_requested": bool(getattr(args, "wizard_inputs", None)),
            "native_options": options,
            "dependency_plan": provisioning_module().dependency_plan(args.component, options["provision_mysql"], options["prepare_libvirt"], codename=codename) if options["install_dependencies"] or options["prepare_libvirt"] else None,
            "steps": ["verify external SHA256 and every tar/manifest member", "root/Ubuntu/systemd/path preflight",
                      "exclusive lock and private persistent receipt", "atomic immutable version staging",
                      "import reviewed config without overwriting existing secrets", "fixed inactive native systemd unit",
                      ("only with complete approval and --start: runtime schema check; separate migration identity if needed; admin bootstrap; strict TLS health"
                       if args.component == "controller" else
                       "only with complete approval and --start: real image checks, doctor, active unit and local listener; admission pending controller")],
            "will_not": ["download unpublished releases", "perform any APT/database action during plan", "edit firewall or physical networking",
                         "start libvirt default network", "create VM or dummy image", "modify financial application", "delete application data"]}


def parse_origin(value):
    if not isinstance(value, str) or not re.fullmatch(r"https://[A-Za-z0-9.\[\]:-]+", value):
        fail("Fixed HTTPS origin required without path, credentials, query or fragment")
    try:
        u = urlsplit(value)
        if not u.hostname or u.username or u.password or u.path or u.query or u.fragment or u.port == 0:
            fail("Fixed HTTPS origin invalid")
        # Force hostname/port parse now, before unit rendering.
        return u.hostname, u.port or 443
    except ValueError:
        fail("Fixed HTTPS origin invalid")


def validate_certificate(cert, key, hostname):
    protected_read(cert, 1024 * 1024, False)
    protected_read(key, 1024 * 1024, True)
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)  # checks real public/private pair
        decoded = ssl._ssl._test_decode_cert(cert)
        now = time.time()
        if (ssl.cert_time_to_seconds(decoded["notBefore"]) > now or
                ssl.cert_time_to_seconds(decoded["notAfter"]) < now + 86400):
            fail("TLS certificate not valid now and for the next 24 hours")
        sans = decoded.get("subjectAltName", ())
        try:
            ip = ipaddress.ip_address(hostname)
        except ValueError:
            ip = None
        matched = False
        for kind, name in sans:
            if ip is not None and kind == "IP Address":
                matched |= ipaddress.ip_address(name) == ip
            elif ip is None and kind == "DNS":
                host, pattern = hostname.lower().rstrip("."), name.lower().rstrip(".")
                matched |= host == pattern or (pattern.startswith("*.") and "*" not in pattern[2:] and
                                                host.count(".") == pattern.count(".") and host.endswith(pattern[1:]))
        if not matched:
            fail("TLS certificate SAN does not cover approved HTTPS hostname")
    except (OSError, ssl.SSLError, KeyError, ValueError, AttributeError):
        fail("TLS certificate pair, SAN or validity rejected")


def validate_dsn_pair(runtime_path, migration_path=None):
    """Strictly separate runtime DML identity from an optional migration identity."""
    def identity(path):
        if not isinstance(path, str):
            fail("Protected DSN file path required, never inline credentials")
        raw = protected_read(path, 4096).decode("utf-8").strip()
        database = raw.rsplit("/", 1)[-1].split("?", 1)[0]
        user = raw.split("@", 1)[0].split(":", 1)[0]
        if (not re.fullmatch(r"aster_(?:controller|cloud)(?:_[A-Za-z0-9_]+)?", database) or
                not re.fullmatch(r"[A-Za-z0-9_]{1,64}", user) or user.lower() == "root" or
                not re.search(r"@(?:unix\(/[^\r\n]*\)|tcp\((?:127\.0\.0\.1|\[::1\]):[0-9]+\))/", raw)):
            fail("Dedicated local nonfinancial MySQL DB and non-root account required")
        return database, user
    runtime = identity(runtime_path)
    if migration_path:
        migration = identity(migration_path)
        if runtime[0] != migration[0] or runtime[1] == migration[1]:
            fail("Migration requires same dedicated DB but a separate non-root identity; runtime DDL reuse refused")
    return runtime[0]


def load_approval(args):
    raw = protected_read(args.approval)
    approval = strict_json(raw)
    allowed = ({"schema", "component", "config_file", "console_origin", "tls_ca_file", "existing_administrator",
                "dedicated_database", "database_name", "migration_dsn_file", "bootstrap_admin_email", "bootstrap_admin_name"}
               if args.component == "controller" else
               {"schema", "component", "config_file", "dedicated_kvm_host", "health_origin"})
    if (not isinstance(approval, dict) or set(approval) - allowed or type(approval.get("schema")) is not int or approval.get("schema") != 1 or
            approval.get("component") != COMPONENTS[args.component] or
            not isinstance(approval.get("config_file"), str)):
        fail("Root approval schema/component rejected")
    config_raw = protected_read(approval["config_file"])
    cfg = strict_json(config_raw)
    if not isinstance(cfg, dict):
        fail("Root approved configuration must be an object")
    if args.component == "controller":
        host, _ = parse_origin(approval.get("console_origin"))
        for field in ("tls_cert_file", "tls_key_file", "dsn_file", "billing_token_file", "admin_read_token_file", "admin_write_token_file"):
            if not isinstance(cfg.get(field), str):
                fail("Controller root approval is incomplete")
            protected_read(cfg[field], private=field != "tls_cert_file")
            if cfg[field].startswith(("/root/", "/home/", "/run/user/")):
                fail("Runtime controller material must be outside systemd ProtectHome")
        if approval.get("dedicated_database") is not True:
            fail("Explicit dedicated nonfinancial controller database approval required")
        database = validate_dsn_pair(cfg["dsn_file"], approval.get("migration_dsn_file"))
        if approval.get("database_name") != database:
            fail("Dedicated Aster Cloud database and non-root account required; finance DSN prohibited")
        validate_certificate(cfg["tls_cert_file"], cfg["tls_key_file"], host)
        protected_read(approval.get("tls_ca_file", ""), 1024 * 1024, False)
        tokens = [protected_read(cfg[k], 4096).strip() for k in ("billing_token_file", "admin_read_token_file", "admin_write_token_file")]
        if len(set(tokens)) != 3 or any(len(t) < 32 or any(c in t for c in b" \r\n\t") for t in tokens):
            fail("Three unique protected controller tokens required")
        if "bootstrap_admin_email" in approval and (not isinstance(approval["bootstrap_admin_email"], str) or
                not re.fullmatch(r"[^\s@]{1,128}@[^\s@]{1,128}", approval["bootstrap_admin_email"])):
            fail("Bootstrap administrator identity invalid")
        if not approval.get("bootstrap_admin_email") and approval.get("existing_administrator") is not True:
            fail("First administrator bootstrap or explicit existing administrator approval required")
    else:
        if (approval.get("dedicated_kvm_host") is not True or cfg.get("maintenance") is not True or
                cfg.get("allow_delete") is not False or
                not isinstance(cfg.get("network"), dict) or cfg["network"].get("enabled") is not False or
                cfg.get("ovs_profiles") or cfg.get("allow_isolated_no_nic") is not False or
                cfg.get("storage", {}).get("enabled") is not False):
            fail("First node install requires dedicated host, maintenance on, delete/network/storage mutations off")
        images = cfg.get("images")
        if not isinstance(images, dict) or not images:
            fail("Real approved node image required; no dummy images")
        for image in images.values():
            if (not isinstance(image, dict) or not SHA_RE.fullmatch(image.get("sha256", ""))):
                fail("Node image approval incomplete")
            p = protected_path(image.get("path", ""))
            if not str(p).startswith("/var/lib/aster-images/"):
                fail("Native first-install unit requires images under /var/lib/aster-images")
            digest = hashlib.sha256()
            with p.open("rb") as f:
                while chunk := f.read(1024 * 1024):
                    digest.update(chunk)
            if digest.hexdigest() != image["sha256"]:
                fail("Approved node image SHA256 mismatch")
        for field in ("cpu_allocation_limit", "memory_allocation_limit_mib", "disk_allocation_limit_gib"):
            if type(cfg.get(field)) is not int or cfg[field] < 1:
                fail("Explicit approved node allocation budgets required")
        for field in ("state_directory", "storage_directory"):
            protected_path(cfg.get(field, ""), directory=True)
        if cfg.get("state_directory") != "/var/lib/aster-node" or cfg.get("storage_directory") != "/var/lib/aster-instances":
            fail("Native first-install unit requires fixed /var/lib/aster-node and /var/lib/aster-instances directories")
        for field, expected in (("directory", "/var/lib/aster-artifacts"), ("inbox_directory", "/var/lib/aster-inbox")):
            if cfg.get("storage", {}).get(field, expected) != expected:
                fail("Native first-install unit requires fixed artifact/inbox paths")
        for field in ("certificate", "private_key", "controller_ca"):
            if not isinstance(cfg.get(field), str) or not cfg[field].startswith("/etc/aster-node/"):
                fail("Node runtime TLS material must be protected files under /etc/aster-node")
        host, _ = parse_origin(approval.get("health_origin"))
        validate_certificate(cfg.get("certificate", ""), cfg.get("private_key", ""), host)
        for field in ("controller_ca",):
            protected_read(cfg.get(field, ""), 1024 * 1024, False)
        if not SHA_RE.fullmatch(cfg.get("expected_controller_certificate_sha256", "")):
            fail("Real approved public controller certificate SHA256 required")
        try:
            ssl.create_default_context(cafile=cfg["controller_ca"])
        except (OSError, ssl.SSLError):
            fail("Controller public trust CA rejected")
    return approval, cfg, config_raw, hashlib.sha256(raw + b"\0" + config_raw).hexdigest()


def run_fixed(argv, *, stdin=None, timeout=60):
    # No shell, no arbitrary command hook, no inherited loader/Python environment.
    try:
        result = subprocess.run(argv, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=timeout, env=SAFE_ENV, check=False)
    except (OSError, subprocess.TimeoutExpired):
        fail("Fixed installer check failed or timed out; command output withheld")
    if result.returncode:
        fail("Fixed installer check rejected; command output withheld to protect secrets")
    return result.stdout


def unit_bytes(component, version_dir, approval=None):
    config = CONFIG_PATHS[component]
    if component == "controller":
        # No material from a bundle template or arbitrary user command reaches ExecStart.
        origin = approval["console_origin"] if approval else None
        extra = f" -console-origin {origin} -ui-dir {version_dir}/ui" if origin else ""
        executable = f"{version_dir}/bin/aster-controller serve -config {config}{extra}"
        extra_sandbox = "PrivateDevices=true\nCapabilityBoundingSet=\nAmbientCapabilities=\nMemoryMax=256M\nTasksMax=64\n"
    else:
        executable = f"{version_dir}/bin/aster-node --config {config}"
        extra_sandbox = ("ReadWritePaths=/var/lib/aster-node /var/lib/aster-instances /var/lib/aster-artifacts /var/lib/aster-inbox\n"
                         "ReadOnlyPaths=/etc/aster-node /var/lib/aster-images\n")
    return ("[Unit]\nDescription=Aster Cloud " + component + " (root-reviewed native install)\n"
            "After=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nUser=root\nGroup=root\n"
            "ExecStart=" + executable + "\nRestart=on-failure\nRestartSec=5\nUMask=0077\n"
            "NoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=true\n"
            "ProtectKernelTunables=true\nProtectKernelModules=true\nProtectKernelLogs=true\nProtectControlGroups=true\n"
            "LockPersonality=true\nRestrictSUIDSGID=true\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n"
            "RestrictRealtime=true\nSystemCallArchitectures=native\nLimitNOFILE=1024\n"
            "TimeoutStopSec=45\nStandardOutput=journal\nStandardError=journal\n"
            "LogRateLimitIntervalSec=30s\nLogRateLimitBurst=1000\n" + extra_sandbox +
            "\n[Install]\nWantedBy=multi-user.target\n").encode()


def strict_health(component, approval, cfg):
    if component != "controller":
        fail("Node mTLS admission must be checked from controller; never import its private identity onto a node")
    origin = approval["console_origin"]
    host, port = parse_origin(origin)
    try:
        context = ssl.create_default_context(cafile=approval["tls_ca_file"])
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        headers = {}
        if component == "controller":
            headers["Authorization"] = "Bearer " + protected_read(cfg["admin_read_token_file"], 4096).decode().strip()
        connection = http.client.HTTPSConnection(host, port, context=context, timeout=10)
        try:
            connection.request("GET", "/v1/health" if component == "controller" else "/healthz", headers=headers)
            response = connection.getresponse()
            body = strict_json(response.read(65537))
            if response.status != 200 or not isinstance(body, dict):
                fail("Strict HTTPS service health rejected")
            if component == "controller" and (body.get("status") != "ready" or body.get("controller_id") != cfg.get("controller_id")):
                fail("Controller health identity or database readiness rejected")
        finally:
            connection.close()
    except (OSError, ssl.SSLError, http.client.HTTPException, ValueError):
        fail("Strict HTTPS health failed; certificate verification was not bypassed")


def node_listener_check(cfg):
    """Local TCP listener observation only. NOT an mTLS/HTTP admission probe."""
    try:
        address, port = cfg["listen"].rsplit(":", 1)
        ip = ipaddress.ip_address(address.strip("[]"))
        host = ("::1" if ip.version == 6 else "127.0.0.1") if ip.is_unspecified else str(ip)
        with socket.create_connection((host, int(port)), timeout=5):
            pass
    except (OSError, ValueError, KeyError):
        fail("Node local TCP listener not observed; controller mTLS admission remains unconfirmed")


def verify_node_images(cfg):
    """Read-only format/integrity checks; never create, repair or convert images."""
    for image in cfg["images"].values():
        info = strict_json(run_fixed(["/usr/bin/qemu-img", "info", "--output=json", "-f", "qcow2", image["path"]]))
        specific = info.get("format-specific", {}) if isinstance(info, dict) else None
        data = specific.get("data", {}) if isinstance(specific, dict) else None
        if (not isinstance(info, dict) or not isinstance(specific, dict) or not isinstance(data, dict) or info.get("format") != "qcow2" or
                type(info.get("virtual-size")) is not int or info["virtual-size"] < 1 or
                info.get("backing-filename") or info.get("full-backing-filename") or info.get("encrypted") or
                "data-file" in info or data.get("data-file")):
            fail("Approved image must be a real flat qcow2 without backing/external-data/encryption")
        # No -r repair flag: this validates the approved immutable input only.
        run_fixed(["/usr/bin/qemu-img", "check", "-f", "qcow2", image["path"]], timeout=300)


def install_version(args, bundle):
    root = ensure_dir(INSTALL_ROOT / args.component, 0o755)
    versions = ensure_dir(root / "versions", 0o755)
    name = bundle.manifest["version"] + "-" + args.sha256[:16]
    destination = versions / name
    protected_path(str(destination), directory=True, allow_missing=True)
    stage = destination if destination.exists() else ensure_dir(versions / (".staging-" + name), 0o700)
    all_files = dict(bundle.files)
    all_files["manifest.json"] = (json.dumps(bundle.manifest, indent=2, sort_keys=True) + "\n").encode()
    modes = {entry["path"]: int(entry["mode"], 8) for entry in bundle.manifest["files"]}
    for relative, raw in all_files.items():
        target = stage / relative
        ensure_dir(target.parent, 0o755)
        write_new(target, raw, modes.get(relative, 0o644))
    actual = set()
    for base, directories, files in os.walk(stage, followlinks=False):
        protected_path(str(Path(base)), directory=True)
        for directory in directories:
            protected_path(str(Path(base) / directory), directory=True)
        for file in files:
            p = Path(base) / file
            protected_path(str(p))
            actual.add(str(p.relative_to(stage)))
    if actual != set(all_files):
        fail("Version staging has unexpected files; manual review required")
    if stage != destination:
        os.chmod(stage, 0o755)
        os.rename(stage, destination)
        parent = os.open(versions, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    return destination


def validate_guided_inputs(component, inputs):
    """Validate real, root-reviewed inputs before guided apply writes anything."""
    host, _ = parse_origin(inputs.get("origin"))
    validate_certificate(inputs.get("certificate", ""), inputs.get("private_key", ""), host)
    if component == "controller":
        protected_read(inputs.get("tls_ca_file", ""), 1024 * 1024, False)
    listen = inputs.get("listen", "")
    try:
        address, port = listen.rsplit(":", 1)
        ip = ipaddress.ip_address(address.strip("[]"))
        if not 1 <= int(port) <= 65535:
            fail("Listen port invalid")
    except (ValueError, AttributeError):
        fail("Literal IP:port listen address required")
    if not ip.is_loopback and inputs.get("public_listen_approved") is not True:
        fail("Explicit public-listen approval required; installer never opens a firewall")
    if component == "controller":
        if inputs.get("provision_database"):
            module = provisioning_module()
            try:
                module.validate_names(**inputs["provision_database"])
            except (module.ProvisionError, TypeError):
                fail("Safe dedicated MySQL provisioning names required")
        else:
            validate_dsn_pair(inputs.get("dsn_file", ""), inputs.get("migration_dsn_file"))
        email = inputs.get("administrator_email", "")
        if not re.fullmatch(r"[^\s@]{1,128}@[^\s@]{1,128}", email):
            fail("First administrator email required")
    else:
        if inputs.get("dedicated_kvm_host") is not True:
            fail("Dedicated KVM host acknowledgement required; never use the 1GB financial test host")
        for key in ("node_id", "datacenter_id", "node_group_id", "image_id"):
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", inputs.get(key, "")):
                fail("Safe node/datacenter/group/image identity required")
        if {"client_certificate", "client_key"} & set(inputs):
            fail("Controller private identity must never be imported onto a KVM node")
        protected_read(inputs.get("controller_ca", ""), 1024 * 1024, False)
        for key in ("controller_pin", "image_sha256"):
            if not SHA_RE.fullmatch(inputs.get(key, "")):
                fail("Exact real controller/image SHA256 approval required")
        image_path = protected_path(inputs.get("image_path", ""))
        if not str(image_path).startswith("/var/lib/aster-images/"):
            fail("Approved image must already be under /var/lib/aster-images; installer never downloads images")
        with image_path.open("rb") as image:
            if image.read(4) != b"QFI\xfb":
                fail("A real approved qcow2 image is required")
        for key, lower, upper in (("cpu", 1, 4096), ("memory_mib", 128, 2**40), ("disk_gib", 1, 2**40)):
            if type(inputs.get(key)) is not int or not lower <= inputs[key] <= upper:
                fail("Explicit node allocation budgets required")
    return inputs


def generate_approved_configuration(args, version_dir, state_dir):
    """Guided existing-dependencies mode; no edits to existing config or secrets.

    Controller's own init creates random tokens in a new private seed directory.
    Its generated default config is not overwritten: the final approved config
    is a separate exclusive file, using those tokens and real imported material.
    Partial seed directories are retained and never mistaken for usable config.
    """
    inputs = dict(validate_guided_inputs(args.component, args.wizard_inputs))
    if inputs.get("provision_database"):
        resolved = getattr(args, "generated_dsn_files", None)
        if not resolved:
            fail("Dedicated MySQL provisioning has not completed; no runtime credentials fabricated")
        inputs.update(dsn_file=resolved["dsn_file"], migration_dsn_file=resolved["migration_dsn_file"])
    config_dir = ensure_dir(CONFIG_PATHS[args.component].parent)
    config_source = state_dir / "generated-config.json"
    approval_path = state_dir / "generated-approval.json"
    if approval_path.exists():
        return str(approval_path)
    cert, key, ca = (config_dir / "server.crt", config_dir / "server.key", config_dir / "health-ca.crt")
    material = [(inputs["certificate"], cert, False), (inputs["private_key"], key, True)]
    if args.component == "controller":
        material.append((inputs["tls_ca_file"], ca, False))
    for source, target, private in material:
        write_new(target, protected_read(source, 1024 * 1024, private), 0o600 if private else 0o644)
    if args.component == "controller":
        dsn = config_dir / "mysql-dsn"
        dsn_raw = protected_read(inputs["dsn_file"], 4096)
        write_new(dsn, dsn_raw)
        if config_source.exists():
            cfg = strict_json(protected_read(str(config_source)))
        else:
            # A fresh seed avoids overwriting partial init secrets after a crash.
            seed = config_dir / ("install-seed-" + secrets.token_hex(8))
            run_fixed([str(version_dir / "bin/aster-controller"), "init", "-config", str(seed / "config.json")])
            cfg = strict_json(protected_read(str(seed / "config.json")))
            cfg.update(listen=inputs["listen"], tls_cert_file=str(cert), tls_key_file=str(key), dsn_file=str(dsn))
        approval = {"schema": 1, "component": COMPONENTS[args.component], "config_file": str(config_source),
                    "console_origin": inputs["origin"], "tls_ca_file": str(ca), "dedicated_database": True,
                    "database_name": dsn_raw.decode().strip().rsplit("/", 1)[-1].split("?", 1)[0],
                    "bootstrap_admin_email": inputs["administrator_email"], "bootstrap_admin_name": "Administrator"}
        if inputs.get("migration_dsn_file"):
            # Keep this separate protected input in operator custody (preferably
            # /root, hidden by the runtime unit's ProtectHome). Never copy it to
            # the long-lived serve config's DSN or expose it in a unit argument.
            approval["migration_dsn_file"] = inputs["migration_dsn_file"]
    else:
        controller_ca = config_dir / "controller-ca.crt"
        # Controller private identities are not requested, referenced or copied.
        for source, target, private in ((inputs["controller_ca"], controller_ca, False),):
            write_new(target, protected_read(source, 1024 * 1024, private), 0o600 if private else 0o644)
        ensure_dir(Path("/var/lib/aster-node"))
        ensure_dir(Path("/var/lib/aster-instances"), 0o755)
        ensure_dir(Path("/var/lib/aster-artifacts"))
        ensure_dir(Path("/var/lib/aster-inbox"))
        cfg = {"node_id": inputs["node_id"], "datacenter_id": inputs["datacenter_id"], "node_group_id": inputs["node_group_id"],
               "listen": inputs["listen"], "allow_public_listen": inputs.get("public_listen_approved", False),
               "certificate": str(cert), "private_key": str(key), "controller_ca": str(controller_ca),
               "expected_controller_certificate_sha256": inputs["controller_pin"],
               "state_directory": "/var/lib/aster-node", "storage_id": "local", "storage_directory": "/var/lib/aster-instances",
               "images": {inputs["image_id"]: {"path": inputs["image_path"], "sha256": inputs["image_sha256"]}},
               "allow_isolated_no_nic": False, "allow_unmetered_default": True, "allow_delete": False, "maintenance": True,
               "cpu_allocation_limit": inputs["cpu"], "memory_allocation_limit_mib": inputs["memory_mib"],
               "disk_allocation_limit_gib": inputs["disk_gib"], "network": {"enabled": False},
               "storage": {"enabled": False, "directory": "/var/lib/aster-artifacts", "inbox_directory": "/var/lib/aster-inbox",
                           "allow_migration": False, "allow_controller_inbox_approval": False}}
        approval = {"schema": 1, "component": COMPONENTS[args.component], "config_file": str(config_source),
                    "dedicated_kvm_host": True, "health_origin": inputs["origin"]}
    write_new(config_source, (json.dumps(cfg, indent=2, sort_keys=True) + "\n").encode())
    write_new(approval_path, (json.dumps(approval, indent=2, sort_keys=True) + "\n").encode())
    return str(approval_path)


def execute(args):
    if not args.apply or args.dry_run or args.plan:
        return make_plan(args)
    bundle = source_bundle(args)  # all archive checks precede writes, including lock
    check_target()
    protected_path(args.bundle)
    options = native_options(args)
    guided = getattr(args, "wizard_inputs", None)
    if options["provision_mysql"] and not guided:
        fail("Dedicated MySQL provisioning requires guided new controller configuration, never an existing imported config")
    if guided and options["provision_mysql"]:
        expected = {"database": options["database"], "runtime_user": options["runtime_user"], "migration_user": options["migration_user"]}
        if guided.get("provision_database") != expected:
            fail("Guided dedicated MySQL request differs from explicit approved names")
    if guided:
        validate_guided_inputs(args.component, guided)
        generated_approval = STATE_ROOT / args.component / "generated-approval.json"
        if generated_approval.exists():
            args.approval = str(generated_approval)
    approval = cfg = config_raw = approval_digest = None
    if args.approval:
        approval, cfg, config_raw, approval_digest = load_approval(args)
    if args.start and not approval and not guided:
        fail("--start requires complete explicit root approval; software-only install can omit it")
    # Refuse conflicting app config before changing the host at all.
    destination_config = CONFIG_PATHS[args.component]
    protected_path(str(destination_config), private=True, allow_missing=True)
    if guided and not approval and destination_config.exists():
        fail("Existing config requires explicit import approval; guided first install never overwrites it")
    if config_raw is not None and destination_config.exists():
        if protected_read(str(destination_config)) != config_raw:
            fail("Existing app configuration differs; never overwritten")
    unit_path = SYSTEMD_ROOT / ("aster-controller.service" if args.component == "controller" else "aster-node.service")
    protected_path(str(unit_path), allow_missing=True)
    # Versioned ExecStart is fixed; upgrades and existing custom units require manual review.
    version_dir = INSTALL_ROOT / args.component / "versions" / (bundle.manifest["version"] + "-" + args.sha256[:16])
    anticipated_approval = approval or ({"console_origin": guided["origin"]} if guided and args.component == "controller" else None)
    desired_unit = unit_bytes(args.component, version_dir, anticipated_approval)
    if unit_path.exists() and protected_read(str(unit_path), private=False) != desired_unit:
        fail("Existing systemd unit differs; explicit manual service review required")
    state_dir = ensure_dir(STATE_ROOT / args.component)
    lock = state_dir / "install.lock"
    protected_path(str(lock), private=True, allow_missing=True)
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        opened = os.fstat(fd)
        if opened.st_uid != 0 or opened.st_nlink != 1 or not stat.S_ISREG(opened.st_mode) or opened.st_mode & 0o077:
            fail("Unsafe installation lock")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            fail("Another installation is active")
        state_path = state_dir / "state.json"
        recover_pending_state(state_path, args)
        if state_path.exists():
            if not args.resume:
                fail("Installation receipt already exists; review it and explicitly pass --resume")
            state = strict_json(protected_read(str(state_path)))
            if (not isinstance(state, dict) or state.get("schema") != 1 or not isinstance(state.get("steps"), list) or
                    state.get("bundle_sha256") != args.sha256 or state.get("component") != args.component):
                fail("Resume must use the original exact component and bundle")
            if state.get("approval_sha256") and state["approval_sha256"] != approval_digest:
                fail("Resume root approval/config changed; manual review required")
        else:
            if args.resume:
                fail("No installation receipt to resume")
            state = {"schema": 1, "component": args.component, "bundle_sha256": args.sha256,
                     "source_commit": bundle.manifest["source_commit"], "version": bundle.manifest["version"], "steps": [],
                     "native_options": options}
        if approval_digest:
            state["approval_sha256"] = approval_digest
        # Legacy schema-1 receipts predate native provisioning and therefore
        # approve NO package/database side effects. Resume may not silently add
        # such approval merely because the older receipt omitted this field.
        prior_options = dict(state.get("native_options", {"install_dependencies": False, "provision_mysql": False}))
        prior_options.setdefault("prepare_libvirt", False)
        if prior_options != options:
            fail("Native dependency/database resume options changed; manual review required")
        state["native_options"] = options
        if guided:
            request_digest = hashlib.sha256(json.dumps(guided, sort_keys=True).encode()).hexdigest()
            if state.get("wizard_request_sha256") and state["wizard_request_sha256"] != request_digest:
                fail("Guided resume inputs differ; original approval must be reviewed explicitly")
            state["wizard_request_sha256"] = request_digest
        state["status"] = "installing"
        # A crashed atomic write leaves only our own private pending receipt. Do
        # not delete it automatically; require recovery review instead.
        atomic_state(state_path, state)
        def step(name, fn):
            state["current_step"] = name
            atomic_state(state_path, state)
            result = fn()
            if name not in state["steps"]:
                state["steps"].append(name)
            atomic_state(state_path, state)
            return result
        try:
            if options["install_dependencies"] or options["provision_mysql"] or options["prepare_libvirt"]:
                module = provisioning_module()
                try:
                    if options["prepare_libvirt"]:
                        # A daemon software-preparation receipt never skips the
                        # real KVM/image/doctor gates below. Existing daemons are
                        # inspected only; fresh setup owns its activation policy.
                        state["libvirt_preparation"] = step("native-libvirt-preparation", lambda: module.prepare_libvirt(state_dir, resume=args.resume))
                    elif options["install_dependencies"]:
                        step("native-dependencies", lambda: module.install_dependencies(args.component, state_dir,
                             with_mysql=options["provision_mysql"], resume=args.resume))
                    if options["provision_mysql"]:
                        if options["install_dependencies"]:
                            # Only a new dedicated server with the module's exact
                            # socket-only drop-in is started. Never restart/adapt
                            # an existing database service or edit its globals.
                            step("dedicated-mysql-local-start", lambda: module.start_owned_mysql(state_dir))
                        args.generated_dsn_files = step("dedicated-mysql-provision", lambda: module.provision_mysql(state_dir,
                             options["database"], options["runtime_user"], options["migration_user"], resume=args.resume))
                except module.ProvisionError as error:
                    fail(str(error))
            installed = step("software-installed", lambda: install_version(args, bundle))
            if guided and not approval:
                args.approval = step("guided-material", lambda: generate_approved_configuration(args, installed, state_dir))
                approval, cfg, config_raw, approval_digest = load_approval(args)
                state["approval_sha256"] = approval_digest
                atomic_state(state_path, state)
            if approval:
                def configure():
                    ensure_dir(destination_config.parent)
                    write_new(destination_config, config_raw)
                    if args.component == "node":
                        for path in ("/var/lib/aster-artifacts", "/var/lib/aster-inbox"):
                            ensure_dir(Path(path))
                step("configuration-approved", configure)
            # Without approval install an inert review template, NOT a live unit:
            # adding console flags later must not require replacing a live unit.
            if approval:
                step("inactive-systemd-unit", lambda: write_new(unit_path, desired_unit, 0o644))
            if not args.start:
                state["status"] = "configuration-approved" if approval else "software-installed"
                state["configuration"] = "approved" if approval else "waiting-approval"
                state["service"] = "not-started"
            else:
                binary = str(installed / "bin" / ("aster-controller" if args.component == "controller" else "aster-node"))
                if args.component == "node":
                    if node_preflight():
                        fail("Node host prerequisites incomplete; software preparation is not KVM readiness; no node service started")
                    step("node-images-readonly-check", lambda: verify_node_images(cfg))
                    def doctor():
                        report = strict_json(run_fixed([binary, "--config", str(destination_config), "--doctor"]))
                        if not isinstance(report, dict) or report.get("ready") is not True:
                            fail("Node doctor did not confirm host readiness")
                    step("node-doctor", doctor)
                else:
                    try:
                        step("database-schema-current", lambda: run_fixed([binary, "check", "-config", str(destination_config)]))
                    except InstallerError:
                        if not approval.get("migration_dsn_file"):
                            fail("Runtime schema check failed; a distinct approved migration DSN is required for migration")
                        migration_config = dict(cfg)
                        migration_config["dsn_file"] = approval["migration_dsn_file"]
                        migration_path = state_dir / "migration-config.json"
                        step("migration-config", lambda: write_new(migration_path,
                             (json.dumps(migration_config, indent=2, sort_keys=True) + "\n").encode()))
                        step("database-migrate", lambda: run_fixed([binary, "migrate", "-config", str(migration_path)]))
                    step("database-check", lambda: run_fixed([binary, "check", "-config", str(destination_config)]))
                    if approval.get("bootstrap_admin_email") and "bootstrap-admin" not in state["steps"]:
                        if not sys.stdin.isatty():
                            fail("Bootstrap password requires an interactive terminal, never argv/environment/logs")
                        password = getpass.getpass("Administrator password (not logged): ")
                        if password != getpass.getpass("Repeat password: "):
                            fail("Bootstrap passwords differ")
                        raw_password = (password + "\n").encode()
                        step("bootstrap-admin", lambda: run_fixed([binary, "bootstrap-admin", "-config", str(destination_config),
                             "-console-origin", approval["console_origin"], "-email", approval["bootstrap_admin_email"],
                             "-name", approval.get("bootstrap_admin_name", "Administrator"), "-password-stdin"], stdin=raw_password))
                        del password, raw_password
                step("systemd-reload", lambda: run_fixed([SYSTEMCTL, "daemon-reload"]))
                step("service-start", lambda: run_fixed([SYSTEMCTL, "start", unit_path.name]))
                step("service-active", lambda: run_fixed([SYSTEMCTL, "is-active", "--quiet", unit_path.name]))
                # Only enable boot after an authenticated, strictly verified probe.
                def wait_health():
                    for attempt in range(10):
                        try:
                            strict_health(args.component, approval, cfg)
                            return
                        except InstallerError:
                            if attempt == 9:
                                raise
                            time.sleep(1)
                if args.component == "controller":
                    step("strict-tls-health", wait_health)
                else:
                    step("local-listener-only", lambda: node_listener_check(cfg))
                step("service-enable", lambda: run_fixed([SYSTEMCTL, "enable", unit_path.name]))
                if args.component == "controller":
                    state["status"], state["configuration"], state["service"] = "service-ready", "approved", "ready"
                else:
                    state["status"], state["configuration"], state["service"] = "node_started_pending_controller", "approved", "active-unadmitted"
                    state["controller_admission"] = "pending-real-controller-mTLS-heartbeat"
            state["current_step"] = None
            atomic_state(state_path, state)
        except Exception:
            state["status"] = "failed"
            start_uncertain = "service-start" in state["steps"] or state.get("current_step") == "service-start"
            state["service"] = "unconfirmed" if start_uncertain else "not-started"
            if start_uncertain:
                # This exact dedicated unit was installed by this operation. Do
                # not leave a newly started, unverified API running after failure.
                try:
                    run_fixed([SYSTEMCTL, "stop", unit_path.name])
                    state["failure_cleanup"] = "own-service-stopped"
                except InstallerError:
                    state["failure_cleanup"] = "own-service-stop-unconfirmed"
            atomic_state(state_path, state)
            raise
        return {"component": args.component, "status": state["status"], "configuration": state["configuration"],
                "service": state["service"], "receipt": str(state_path), "private_material": "not printed",
                "console_url": approval["console_origin"] + "/" if args.component == "controller" and state["status"] == "service-ready" else None,
                "administrator": {"email": approval.get("bootstrap_admin_email"), "password": "set privately; never displayed"}
                    if args.component == "controller" and state["status"] == "service-ready" else None,
                "next_step": "real pinned mTLS heartbeat FROM controller; maintenance remains on" if state["status"] == "node_started_pending_controller" else None,
                "libvirt_preparation": state.get("libvirt_preparation"),
                "warning": ("Development bundle; " if bundle.manifest["release_kind"] == "development" else "Authenticated prerelease; ") + "installation is not financial integration or VM provisioning acceptance"}
    finally:
        os.close(fd)


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("component", choices=COMPONENTS)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--plan", action="store_true", help="read-only plan (default)")
    action.add_argument("--dry-run", action="store_true", help="alias of read-only plan")
    action.add_argument("--apply", action="store_true", help="root-only native install")
    parser.add_argument("--allow-development", action="store_true", help="explicitly trust local development code")
    parser.add_argument("--release-receipt", help="publisher-verified prerelease receipt; offline cryptographic reverification is mandatory")
    parser.add_argument("--bundle", help="local canonical absolute development tar.gz path")
    parser.add_argument("--sha256", help="independently obtained lowercase external archive SHA256")
    parser.add_argument("--approval", help="root-owned 0600 approval JSON file; never inline secrets")
    parser.add_argument("--start", action="store_true", help="after complete approval, check then start and verify service")
    parser.add_argument("--resume", action="store_true", help="explicitly continue original bundle/approval after reviewing receipt")
    parser.add_argument("--wizard", action="store_true", help="interactive local bundle and approval wizard")
    parser.add_argument("--install-dependencies", action="store_true", help="explicitly approve fixed signed Ubuntu packages on a fresh dedicated host (never a plan side effect)")
    parser.add_argument("--prepare-libvirt", action="store_true", help="node-only: explicitly prepare a fresh local-only libvirt daemon with persistent vendor activation masks and no default network; existing active daemon is read-only")
    parser.add_argument("--provision-mysql", action="store_true", help="explicitly create a NEW dedicated controller DB and separate local DML/DDL identities")
    parser.add_argument("--database-name", default="aster_cloud", help="new dedicated DB name; never an existing finance DB")
    parser.add_argument("--runtime-db-user", default="aster_cloud_api", help="new local DML-only identity")
    parser.add_argument("--migration-db-user", default="aster_cloud_migrate", help="new separate local migration identity")
    return parser


def wizard(args):
    if not sys.stdin.isatty():
        fail("Wizard needs a terminal; invoke install.py with explicit flags for automation")
    print("Aster Cloud native installer: no unverified download, firewall/physical-network/VM changes.")
    print("Existing-dependencies is the default. Signed Ubuntu packages and NEW dedicated MySQL are explicit opt-ins.")
    print("Real TLS/approved node images remain required. Libvirt software preparation is NOT KVM or controller admission readiness.")
    if args.component == "node":
        print("Use a dedicated KVM host, never the 1GB financial test server. Maintenance stays on.")
    if not args.allow_development and not getattr(args, "release_receipt", None):
        if input("Trust an independently reviewed LOCAL DEVELOPMENT bundle? Type development: ") != "development":
            fail("Development execution not approved")
        args.allow_development = True
    if not args.bundle:
        args.bundle = input("Absolute bundle path: ").strip()
    if not args.sha256:
        args.sha256 = input("Trusted external archive SHA256: ").strip()
    if not args.install_dependencies:
        print("Optional APT: fixed Ubuntu signed packages; fresh dedicated host only, owned temporary policy blocks autostart.")
        args.install_dependencies = input("Approve this package transaction? Type apt (blank = existing dependencies): ").strip() == "apt"
    if args.component == "node" and not args.prepare_libvirt:
        print("Optional libvirt: fresh dedicated >=2GiB host only, official AppArmor/users retained, all vendor activation masked.")
        print("Only owned UNIX daemons see an empty read-only networks directory. Existing active libvirt is preserved read-only.")
        args.prepare_libvirt = input("Approve local libvirt software preparation? Type libvirt (blank = existing daemon): ").strip() == "libvirt"
    if not args.approval:
        choice = input("Existing root 0600 approval JSON path (blank = guided setup; software = binaries only): ").strip()
        if choice and choice != "software":
            args.approval = choice
        elif not choice:
            def ask(label, default=None):
                value = input(label + (f" [{default}]" if default is not None else "") + ": ").strip()
                return value if value else default
            def integer(label):
                try:
                    return int(ask(label))
                except (ValueError, TypeError):
                    fail("Integer allocation budget required")
            origin = ask("Fixed HTTPS console origin" if args.component == "controller" else "Fixed node HTTPS health origin")
            args.wizard_inputs = {
                "origin": origin, "certificate": ask("Existing root-owned real server certificate PEM path"),
                "private_key": ask("Existing root0600 server private key PEM path")}
            if args.component == "controller":
                args.wizard_inputs["tls_ca_file"] = ask("Existing root-owned server TLS trust CA PEM path (no insecure/self-signed shortcut)")
            args.wizard_inputs["listen"] = ask("Service listen literal IP:port (do not copy HTTP Origin)", "127.0.0.1:9443")
            listen_ip = args.wizard_inputs["listen"].rsplit(":", 1)[0].strip("[]")
            try:
                public = not ipaddress.ip_address(listen_ip).is_loopback
            except ValueError:
                fail("Literal IP listen address required")
            args.wizard_inputs["public_listen_approved"] = False
            if public:
                args.wizard_inputs["public_listen_approved"] = ask(
                    "Expose this specific TLS listener? Firewall is NOT modified. Type expose") == "expose"
            if args.component == "controller":
                print("Use a precreated dedicated aster_controller[_...] or aster_cloud[_...] DB/account.")
                print("The runtime account must have API DML ONLY in this database. DDL requires a SEPARATE non-root migration account.")
                print("No financial DB/account reuse, MySQL package/global-config changes, or inline DSN.")
                dsn_choice = "new" if args.provision_mysql else ask("Existing root0600 runtime DSN file path, or new for approved dedicated DB provisioning")
                if dsn_choice == "new":
                    print("Only local root socket auth; no existing DB/users adopted. New DML and DDL identities remain separate.")
                    if not args.provision_mysql and ask("Approve NEW dedicated DB/accounts creation? Type provision") != "provision":
                        fail("Dedicated database provisioning not approved")
                    args.provision_mysql = True
                    args.database_name = ask("New dedicated database name", args.database_name)
                    args.runtime_db_user = ask("New runtime DML-only account", args.runtime_db_user)
                    args.migration_db_user = ask("New separate migration account", args.migration_db_user)
                    args.wizard_inputs["provision_database"] = {"database": args.database_name, "runtime_user": args.runtime_db_user,
                                                                 "migration_user": args.migration_db_user}
                else:
                    args.wizard_inputs.update(dsn_file=dsn_choice,
                        migration_dsn_file=ask("Separate root0600 migration DSN file path (blank only if schema already current)"))
                args.wizard_inputs["administrator_email"] = ask("First administrator email (password is prompted privately at bootstrap)")
            else:
                if ask("Confirm dedicated KVM host, never 1GB finance test server. Type dedicated-kvm") != "dedicated-kvm":
                    fail("Dedicated host approval not provided")
                print("Initial policy: maintenance=true; network/delete/storage migration=false. No bridge/uplink edits.")
                print("Never put controller client private keys on this node. Admission is later checked FROM controller.")
                args.wizard_inputs.update(
                    dedicated_kvm_host=True,
                    node_id=ask("Node ID"), datacenter_id=ask("Datacenter ID"), node_group_id=ask("Node group ID"),
                    controller_ca=ask("Controller client trust CA PEM path"),
                    controller_pin=ask("Independently reviewed controller client leaf DER SHA256"),
                    image_id=ask("Approved image ID", "ubuntu22"),
                    image_path=ask("Real preinstalled flat qcow2 path under /var/lib/aster-images"),
                    image_sha256=ask("Independently approved complete qcow2 SHA256 (not a placeholder)"),
                    cpu=integer("Approved CPU allocation ceiling"),
                    memory_mib=integer("Approved memory allocation ceiling MiB"),
                    disk_gib=integer("Approved disk allocation ceiling GiB"))
    preview = make_plan(args)
    print("Read-only bundle preflight: " + preview["component"] + " " + preview["version"] + " / " + preview["release_kind"])
    print("Target: " + json.dumps(preview["target"], sort_keys=True))
    if args.install_dependencies or args.prepare_libvirt:
        print("Explicit package plan: " + ", ".join(preview["dependency_plan"]["packages"]) + "; owned temporary service-start policy required.")
    if args.provision_mysql:
        print("Explicit NEW dedicated DB/accounts. MySQL will be started UNIX-SOCKET-ONLY even if Cloud API start is declined.")
    if not (args.apply or args.plan or args.dry_run):
        args.apply = input("Install now? Type install (anything else = read-only plan): ") == "install"
    if args.apply and (args.approval or getattr(args, "wizard_inputs", None)) and not args.start:
        args.start = input("After checks, start approved service? Type start (blank = no): ") == "start"
    return args


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.wizard:
            wizard(args)
        print(json.dumps(execute(args), indent=2, sort_keys=True))
        return 0
    except InstallerError as error:
        print("ERROR: " + str(error), file=sys.stderr)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError):
        print("ERROR: Installation input or protected host operation failed; details withheld to protect secrets", file=sys.stderr)
    except KeyboardInterrupt:
        print("ERROR: Interrupted; review private receipt before explicit --resume", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())

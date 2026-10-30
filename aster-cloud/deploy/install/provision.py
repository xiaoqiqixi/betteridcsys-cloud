#!/usr/bin/env python3
"""Explicit opt-in native dependency and dedicated-MySQL provisioning.

This module is NOT invoked by plan/dry-run. All subprocess output is captured;
no scripts, third-party repositories, arbitrary package names or SQL are inputs.
Native integration of these paths remains an acceptance-test requirement.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import re
import secrets
import stat
import subprocess
import time
import xml.etree.ElementTree as ET

APT_GET = "/usr/bin/apt-get"
MYSQL = "/usr/bin/mysql"
SYSTEMCTL = "/usr/bin/systemctl"
POLICY_PATH = Path("/usr/sbin/policy-rc.d")
APT_KEYRING = Path("/usr/share/keyrings/ubuntu-archive-keyring.gpg")
APT_WORK_ROOT = Path("/var/cache/aster-cloud-installer")
MYSQL_CONFIG = Path("/etc/mysql")
MYSQL_DATA = Path("/var/lib/mysql")
MYSQL_SOCKET = "/run/mysqld/mysqld.sock"
MYSQL_DROPIN = Path("/etc/systemd/system/mysql.service.d/aster-cloud-local-only.conf")
CODENAMES = {"22.04": "jammy", "24.04": "noble"}
PACKAGES = {"controller": ("ca-certificates", "openssl"),
            "node": ("ca-certificates", "qemu-utils", "qemu-system-x86", "libvirt-clients", "cloud-image-utils")}
SYSTEM_SCHEMAS = {"mysql", "sys", "information_schema", "performance_schema"}
RUNTIME_PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "DELETE")
# 002_console_identity creates an FK; MySQL also requires REFERENCES on its
# parent table. This remains a dedicated-DB grant, never runtime/global access.
MIGRATION_PRIVILEGES = RUNTIME_PRIVILEGES + ("CREATE", "ALTER", "INDEX", "REFERENCES")
SAFE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "HOME": "/root"}
MAX_OUTPUT = 1024 * 1024
MYSQL_LOCAL_DROPIN = b"[Service]\nExecStart=\nExecStart=/usr/sbin/mysqld --skip-networking --mysqlx=0\n"
VIRSH = "/usr/bin/virsh"
LIBVIRTD = "/usr/sbin/libvirtd"
LIBVIRT_CONFIG = Path("/etc/libvirt")
LIBVIRT_STATE = Path("/var/lib/libvirt")
LIBVIRT_SOCKET = Path("/run/libvirt/libvirt-sock")
LIBVIRT_EMPTY = Path("/var/lib/aster-cloud-installer/libvirt-empty-networks")
LIBVIRT_OWN_CONFIG = LIBVIRT_CONFIG / "aster-cloud-libvirtd.conf"
UNIT_ROOT = Path("/etc/systemd/system")
RUNTIME_UNIT_ROOT = Path("/run/systemd/system")
LIBVIRT_OWN_UNITS = ("aster-cloud-virtlogd.service", "aster-cloud-virtlockd.service", "aster-cloud-libvirtd.service")
# Both monolithic and modular activation paths stay persistently masked. A
# socket can start a daemon even when its service was never explicitly enabled.
LIBVIRT_VENDOR_UNITS = tuple(sorted({"libvirt-guests.service", "virt-guest-shutdown.target"} | {
    daemon + suffix for daemon in ("libvirtd", "virtlogd", "virtlockd", "virtproxyd", "virtqemud",
        "virtnetworkd", "virtnodedevd", "virtnwfilterd", "virtsecretd", "virtstoraged", "virtinterfaced")
    for suffix in (".service", ".socket", "-ro.socket", "-admin.socket", "-tcp.socket", "-tls.socket")}))
LIBVIRT_DAEMON_CONFIG = (b'listen_tls = 0\nlisten_tcp = 0\nlisten_addr = "127.0.0.1"\n'
    b'unix_sock_group = "root"\nunix_sock_ro_perms = "0700"\nunix_sock_rw_perms = "0700"\n'
    b'auth_unix_ro = "none"\nauth_unix_rw = "none"\n')


class ProvisionError(Exception):
    def __init__(self, message, *, code=None):
        super().__init__(message)
        self.code = code


def fail(message, *, code=None):
    raise ProvisionError(message, code=code)


def _json(raw):
    def pairs(items):
        output = {}
        for key, value in items:
            if key in output:
                fail("Duplicate provisioning JSON field")
            output[key] = value
        return output
    try:
        value = json.loads(raw, object_pairs_hook=pairs)
        if not isinstance(value, dict):
            fail("Provisioning receipt must be an object")
        return value
    except (ValueError, UnicodeError):
        fail("Malformed provisioning receipt; manual review required")


def protected_path(path, *, directory=False, private=False, missing=False):
    p = Path(path)
    if not p.is_absolute() or str(p) != str(path) or any(c in str(p) for c in "\r\n\x00") or ".." in p.parts:
        fail("Canonical protected provisioning path required")
    for current in [*reversed(p.parents), p]:
        try:
            info = current.lstat()
        except FileNotFoundError:
            if missing:
                continue
            fail("Protected provisioning input missing")
        final = current == p
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            fail("Unsafe provisioning path ownership, mode or symlink")
        if not final and not stat.S_ISDIR(info.st_mode):
            fail("Provisioning ancestor must be a directory")
        if final and (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1) is False:
            fail("Unexpected provisioning file type or hardlink")
        if final and private and info.st_mode & 0o077:
            fail("Private root-only provisioning material required")
    return p


def read_private(path):
    p = protected_path(path, private=True)
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if info.st_uid != 0 or info.st_nlink != 1 or not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > MAX_OUTPUT:
            fail("Opened private provisioning inode rejected")
        raw = stream.read(MAX_OUTPUT + 1)
        if not raw or len(raw) > MAX_OUTPUT:
            fail("Private provisioning input empty or oversized")
        return raw


def ensure_dir(path, mode=0o700):
    p = protected_path(str(path), directory=True, missing=True)
    if not p.exists():
        if not p.parent.exists():
            ensure_dir(p.parent, 0o755)
        p.mkdir(mode=mode)
        p.chmod(mode)
    return p


def write_new(path, raw, mode=0o600):
    p = protected_path(str(path), private=mode == 0o600, missing=True)
    if p.exists():
        # Public APT configuration is nonsensitive but still root protected.
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o022 or stat.S_IMODE(info.st_mode) != mode:
                fail("Existing provisioning file has unsafe ownership or mode")
            if stream.read(len(raw) + 1) != raw:
                fail("Existing provisioning material differs; never overwritten")
        return
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def save_receipt(path, receipt):
    protected_path(str(path), private=True, missing=True)
    temporary = path.with_suffix(".pending")
    if temporary.exists():
        fail("Interrupted provisioning receipt write; manual review required")
    write_new(temporary, (json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def apt_failure_code(stdout, stderr):
    """Map captured APT diagnostics to fixed public categories, never raw text.

    Categories describe the observed failure only. They neither grant a retry
    nor loosen transport, package-selection, signature or no-upgrade policy.
    """
    raw = (stdout[:MAX_OUTPUT] + b"\n" + stderr[:MAX_OUTPUT]).lower()
    patterns = (
        ("APT_DNS_FAILURE", (b"temporary failure resolving", b"could not resolve", b"name or service not known")),
        ("APT_TLS_FAILURE", (b"certificate verification failed", b"could not handshake", b"certificate is not trusted", b"tls connection")),
        ("APT_SIGNATURE_FAILURE", (b"no_pubkey", b"signatures couldn't be verified", b"invalid signature", b"is not signed", b"signature verification failed")),
        ("APT_METADATA_FAILURE", (b"does not have a release file", b"some index files failed", b"failed to fetch", b"hash sum mismatch", b"release file expired", b"release file is not valid yet")),
        ("APT_PACKAGE_UNAVAILABLE", (b"unable to locate package", b"has no installation candidate")),
        ("APT_DEPENDENCY_CONFLICT", (b"unmet dependencies", b"held broken packages", b"pkgproblemresolver", b"packages were downgraded")),
        ("APT_LOCKED", (b"could not get lock", b"unable to acquire", b"is another process using it")),
    )
    for code, needles in patterns:
        if any(needle in raw for needle in needles):
            return code
    return "APT_COMMAND_REJECTED"


def run_fixed(argv, *, stdin=None, env=None, timeout=120):
    is_apt = bool(argv) and argv[0] == APT_GET
    try:
        result = subprocess.run(argv, input=stdin, env=env or SAFE_ENV, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise ProvisionError("Fixed native provisioning command timed out; output withheld",
                             code="APT_COMMAND_TIMEOUT" if is_apt else None) from None
    except OSError:
        raise ProvisionError("Fixed native provisioning command unavailable; output withheld",
                             code="APT_COMMAND_UNAVAILABLE" if is_apt else None) from None
    if len(result.stdout) > MAX_OUTPUT or len(result.stderr) > MAX_OUTPUT:
        raise ProvisionError("Fixed native provisioning command output exceeded limit; output withheld",
                             code="APT_OUTPUT_OVERSIZED" if is_apt else None)
    if result.returncode:
        code = apt_failure_code(result.stdout, result.stderr) if is_apt else None
        raise ProvisionError("Fixed native provisioning command rejected; output withheld to protect secrets",
                             code=code)
    return result.stdout


def root_target():
    if os.geteuid() != 0 or platform.system() != "Linux" or platform.machine() not in ("amd64", "x86_64"):
        fail("Native provisioning requires root on Ubuntu amd64")
    fields = {}
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                fields[key] = value.strip('"')
    except OSError:
        fail("Ubuntu release cannot be verified")
    if fields.get("ID") != "ubuntu" or fields.get("VERSION_ID") not in CODENAMES:
        fail("Native provisioning targets Ubuntu 22.04 or 24.04 only; Ubuntu 26.04 and unknown releases are unsupported")
    return CODENAMES[fields["VERSION_ID"]]


def dependency_plan(component, with_mysql=False, with_libvirt=False, *, codename=None):
    if (component not in PACKAGES or with_mysql and component != "controller" or
            with_libvirt and component != "node"):
        fail("Invalid fixed dependency role")
    if with_libvirt and codename not in CODENAMES.values():
        fail("Libvirt dependency plan requires a verified Ubuntu target")
    if codename is not None and codename not in CODENAMES.values():
        fail("Dependency plan requires Ubuntu 22.04 or 24.04; unsupported codename")
    packages = list(PACKAGES[component]) + (["mysql-server", "mysql-client"] if with_mysql else []) + (["libvirt-daemon-system"] if with_libvirt else [])
    # Both supported releases bundle virtlockd in libvirt-daemon. Unknown or
    # deferred releases cannot silently gain a different package transaction.
    return {"packages": packages, "source": "Ubuntu signed archive/security HTTPS only", "node_daemon_included": with_libvirt,
            "service_autostart": "blocked during explicit fresh-host package transaction",
            "mysql_transport": "unix-socket-only" if with_mysql else "unchanged",
            "limitations": ["No APT upgrade/removal, third-party repository, firewall or host bridge edits",
                            "Libvirt preparation is not KVM, image, VM or controller admission acceptance"]}


def _fresh_mysql_host():
    for p in (MYSQL_CONFIG, MYSQL_DATA, MYSQL_DROPIN.parent,
              Path("/etc/systemd/system/mysql.service"), Path("/etc/systemd/system/mysqld.service"),
              Path("/usr/sbin/mysqld"), Path(MYSQL_SOCKET)):
        if p.exists() or p.is_symlink():
            fail("MySQL package provisioning is fresh-host only; existing service/config/data is never modified")


def fresh_dependency_host(component):
    """Conservative evidence gate, not a claim to detect every possible workload."""
    paths = (Path("/var/lib/mysql"), Path("/var/lib/mariadb"), Path("/var/lib/postgresql"),
             Path("/var/lib/libvirt"), Path("/etc/libvirt"), Path("/opt/vps-billing"), Path("/opt/aster-billing"))
    if any(p.exists() or p.is_symlink() for p in paths):
        fail("Dependency installation is fresh dedicated-host only; existing database/virt/finance workloads refused")
    if component == "node":
        try:
            raw = Path("/proc/meminfo").read_text()
            memory = re.search(r"^MemTotal:\s+(\d+)\s+kB$", raw, re.M)
            if not memory or int(memory[1]) < 2 * 1024 * 1024 or not stat.S_ISCHR(Path("/dev/kvm").stat().st_mode):
                fail("Node dependency install requires a dedicated real KVM host with at least 2GiB; never the finance test server")
        except OSError:
            fail("Real KVM host evidence is absent; no node packages installed")


def fresh_libvirt_host():
    """Software preparation can run without KVM; the real node doctor cannot.

    This is a separate approved operation, not a skip-KVM switch on node start.
    Its result always says kvm=not-asserted. Existing virt hosts go through the
    read-only validation branch of prepare_libvirt instead of this function.
    """
    fresh_dependency_host("controller")
    paths = (Path("/var/lib/mariadb"), Path("/etc/mysql"), Path("/usr/sbin/mysqld"),
             Path("/usr/sbin/dnsmasq"), Path("/etc/dnsmasq.d-available/libvirt-daemon"),
             LIBVIRT_SOCKET, Path(LIBVIRTD), LIBVIRT_EMPTY)
    if any(p.exists() or p.is_symlink() for p in paths):
        fail("Libvirt preparation requires a fresh dedicated host; foreign services/configuration refused")
    for unit in LIBVIRT_VENDOR_UNITS + LIBVIRT_OWN_UNITS:
        for root in (UNIT_ROOT, RUNTIME_UNIT_ROOT):
            p = root / unit
            if p.exists() or p.is_symlink() or (root / (unit + ".d")).exists() or (root / (unit + ".d")).is_symlink():
                fail("Foreign libvirt unit, override or mask exists; never overwritten")
    try:
        memory = re.search(r"^MemTotal:\s+(\d+)\s+kB$", Path("/proc/meminfo").read_text(), re.M)
        if not memory or int(memory[1]) < 2 * 1024 * 1024:
            fail("Libvirt preparation requires a dedicated host with at least 2GiB; never the finance test server")
    except OSError:
        fail("Dedicated host memory evidence is unavailable")


def _policy_bytes(nonce):
    return ("#!/bin/sh\n# aster-cloud-installer owned transient policy " + nonce + "\nexit 101\n").encode()


def _remove_owned_policy(receipt):
    if not POLICY_PATH.exists() and not POLICY_PATH.is_symlink():
        return
    protected_path(str(POLICY_PATH))
    expected = _policy_bytes(receipt["policy_nonce"])
    fd = os.open(POLICY_PATH, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        raw = stream.read(len(expected) + 1)
    if (raw != expected or info.st_ino != receipt.get("policy_inode") or info.st_dev != receipt.get("policy_device")):
        fail("Transient policy changed; refusing to remove any non-owned system policy")
    POLICY_PATH.unlink()  # Only our exact O_EXCL-created policy; never app/network data.


def _apt_configuration(work, codename):
    # APT_CONFIG is read BEFORE system apt.conf.d/main. These first two settings
    # prevent inherited root hooks/source/preferences from entering this run.
    for name in ("empty-parts", "source-parts", "trusted-parts", "preferences-parts", "lists", "archives"):
        ensure_dir(work / name, 0o755)
    for name in ("empty-parts", "source-parts", "trusted-parts", "preferences-parts"):
        if any((work / name).iterdir()):
            fail("Private APT configuration isolation directory is not empty; foreign hooks/sources refused")
    write_new(work / "empty.conf", b"// intentionally empty\n", 0o644)
    write_new(work / "preferences", b"# no package pinning\n", 0o644)
    sources = (f"deb [arch=amd64 signed-by={APT_KEYRING}] https://archive.ubuntu.com/ubuntu {codename} main universe\n"
               f"deb [arch=amd64 signed-by={APT_KEYRING}] https://archive.ubuntu.com/ubuntu {codename}-updates main universe\n"
               f"deb [arch=amd64 signed-by={APT_KEYRING}] https://security.ubuntu.com/ubuntu {codename}-security main universe\n")
    write_new(work / "sources.list", sources.encode(), 0o644)
    config = (f'Dir::Etc::parts "{work}/empty-parts";\nDir::Etc::main "{work}/empty.conf";\n'
              f'Dir::Etc::sourcelist "{work}/sources.list";\nDir::Etc::sourceparts "{work}/source-parts";\n'
              f'Dir::Etc::preferences "{work}/preferences";\nDir::Etc::preferencesparts "{work}/preferences-parts";\n'
              f'Dir::Etc::trusted "{APT_KEYRING}";\nDir::Etc::trustedparts "{work}/trusted-parts";\n'
              f'Dir::State::lists "{work}/lists";\nDir::Cache::archives "{work}/archives";\n'
              'APT::Update::Error-Mode "any";\n'
              'APT::Get::AllowUnauthenticated "false";\nAcquire::AllowInsecureRepositories "false";\n'
              'Acquire::AllowDowngradeToInsecureRepositories "false";\nAcquire::https::Verify-Peer "true";\n'
              'Acquire::https::Verify-Host "true";\nAcquire::Check-Valid-Until "true";\nAcquire::Check-Date "true";\n'
              'DPkg::Options { "--force-confold"; };\n')
    write_new(work / "apt.conf", config.encode(), 0o644)
    return str(work / "apt.conf")


def install_dependencies(component, state_dir, *, with_mysql=False, with_libvirt=False, resume=False):
    codename = root_target()
    plan = dependency_plan(component, with_mysql, with_libvirt, codename=codename)
    # Full daemon packages may never be installed without the outer operation's
    # persistent activation masks and approved receipt already being in place.
    if with_libvirt:
        outer = _json(read_private(str(Path(state_dir) / "libvirt.json")))
        if (outer.get("mode") != "fresh-owned" or outer.get("codename") != codename or
                outer.get("plan_sha256") != libvirt_plan_digest(codename)):
            fail("Libvirt packages require the owned preparation transaction")
        verify_libvirt_masks(outer)
    for executable in (APT_GET, SYSTEMCTL):
        protected_path(executable)
    protected_path(str(APT_KEYRING))
    state_dir = ensure_dir(Path(state_dir))
    path = state_dir / "dependencies.json"
    if path.exists():
        if not resume:
            fail("Dependency receipt exists; explicitly resume the original package plan")
        receipt = _json(read_private(str(path)))
        if (receipt.get("component") != component or receipt.get("with_mysql") != with_mysql or
                receipt.get("with_libvirt", False) != with_libvirt or receipt.get("codename") != codename):
            fail("Dependency resume plan changed")
    else:
        if POLICY_PATH.exists() or POLICY_PATH.is_symlink():
            fail("Existing policy-rc.d is never replaced, even temporarily")
        if not with_libvirt:
            fresh_dependency_host(component)
        if with_mysql:
            _fresh_mysql_host()
        receipt = {"schema": 1, "component": component, "with_mysql": with_mysql, "with_libvirt": with_libvirt,
                   "codename": codename, "policy_nonce": secrets.token_hex(32), "steps": []}
        save_receipt(path, receipt)
    if receipt.get("status") == "dependencies-installed":
        return {"status": "dependencies-installed", "receipt": str(path), "node_daemon_included": with_libvirt}
    work = ensure_dir(APT_WORK_ROOT / component, 0o755)
    config = _apt_configuration(work, codename)
    env = dict(SAFE_ENV, APT_CONFIG=config, DEBIAN_FRONTEND="noninteractive", NEEDRESTART_MODE="l")
    if "policy-created" not in receipt["steps"]:
        if POLICY_PATH.exists() or POLICY_PATH.is_symlink():
            fail("Another service policy appeared; refusing to replace it")
        write_new(POLICY_PATH, _policy_bytes(receipt["policy_nonce"]), 0o755)
        info = POLICY_PATH.lstat()
        receipt.update(policy_inode=info.st_ino, policy_device=info.st_dev)
        receipt["steps"].append("policy-created")
        save_receipt(path, receipt)
    else:
        # A failed transaction retains its blocking policy until explicit resume.
        protected_path(str(POLICY_PATH))
        info = POLICY_PATH.lstat()
        if (POLICY_PATH.read_bytes() != _policy_bytes(receipt["policy_nonce"]) or stat.S_IMODE(info.st_mode) != 0o755 or
                info.st_ino != receipt.get("policy_inode") or info.st_dev != receipt.get("policy_device")):
            fail("Owned package-start policy missing or changed; manual review required")
    try:
        run_fixed([APT_GET, "update"], env=env, timeout=600)
        arguments = ["--no-install-recommends", "--no-upgrade", "--no-remove", "install", *plan["packages"]]
        simulation = run_fixed([APT_GET, "--simulate", *arguments], env=env).decode("utf-8")
        for line in simulation.splitlines():
            if (line.startswith("Remv ") or re.match(r"^Inst \S+ \[", line) or
                    re.match(r"^Inst (?:firewalld|ufw|openvswitch\S*)\b", line) or
                    not with_libvirt and re.match(r"^Inst libvirt-daemon\S*\b", line)):
                fail("APT plan would upgrade/remove existing software or install unapproved network daemons", code="APT_PLAN_UNSAFE")
        receipt["status"] = "package-transaction-pending"
        save_receipt(path, receipt)
        run_fixed([APT_GET, "--assume-yes", *arguments], env=env, timeout=1200)
        if "packages-installed" not in receipt["steps"]:
            receipt["steps"].append("packages-installed")
        if with_mysql:
            # Only a fresh dedicated service gets this owned local-only drop-in.
            # No global MySQL configuration, root password or existing unit edited.
            ensure_dir(MYSQL_DROPIN.parent, 0o755)
            write_new(MYSQL_DROPIN, MYSQL_LOCAL_DROPIN, 0o644)
        _remove_owned_policy(receipt)
        receipt["status"] = "dependencies-installed"
        save_receipt(path, receipt)
        return {"status": "dependencies-installed", "receipt": str(path), "node_daemon_included": with_libvirt}
    except Exception:
        receipt["status"] = "failed-package-transaction-review-required"
        save_receipt(path, receipt)
        raise


def libvirt_unit_bytes(name):
    if name not in LIBVIRT_OWN_UNITS:
        fail("Unknown owned libvirt unit")
    daemon = name.removeprefix("aster-cloud-").removesuffix(".service")
    dependencies = "Requires=aster-cloud-virtlogd.service aster-cloud-virtlockd.service\nAfter=aster-cloud-virtlogd.service aster-cloud-virtlockd.service\n" if daemon == "libvirtd" else ""
    command = "/usr/sbin/" + daemon + (" --config " + str(LIBVIRT_OWN_CONFIG) if daemon == "libvirtd" else "")
    namespace = f"BindReadOnlyPaths={LIBVIRT_EMPTY}:/etc/libvirt/qemu/networks\n" if daemon == "libvirtd" else ""
    # Do not blindly impose app-daemon seccomp/capability restrictions on the
    # privileged virtualization driver or disable the vendor AppArmor driver.
    return (f"[Unit]\nDescription=Aster Cloud owned {daemon} (local UNIX only)\n{dependencies}"
        f"[Service]\nType=exec\nExecStart={command}\nRestart=on-failure\nRestartSec=2\n"
        "KillMode=process\nRuntimeDirectory=libvirt\nRuntimeDirectoryMode=0755\nRuntimeDirectoryPreserve=yes\n"
        f"{namespace}PrivateTmp=yes\nProtectHome=yes\nLimitNOFILE=1048576\nTasksMax=32768\n"
        "[Install]\nWantedBy=multi-user.target\n").encode()


def libvirt_plan_digest(codename):
    plan = {"schema": 1, "packages": dependency_plan("node", with_libvirt=True, codename=codename)["packages"],
            "masks": list(LIBVIRT_VENDOR_UNITS), "empty": str(LIBVIRT_EMPTY),
            "config": hashlib.sha256(LIBVIRT_DAEMON_CONFIG).hexdigest(),
            "units": {name: hashlib.sha256(libvirt_unit_bytes(name)).hexdigest() for name in LIBVIRT_OWN_UNITS}}
    return hashlib.sha256(json.dumps(plan, sort_keys=True).encode()).hexdigest()


def verify_libvirt_masks(receipt):
    masks = receipt.get("masks")
    if not isinstance(masks, dict) or set(masks) != set(LIBVIRT_VENDOR_UNITS):
        fail("Incomplete libvirt activation protection; manual review required")
    for name, owned in masks.items():
        _verify_libvirt_mask(name, owned)


def _verify_libvirt_mask(name, owned):
    if name not in LIBVIRT_VENDOR_UNITS:
        fail("Unknown activation mask in receipt")
    # Deliberately created /dev/null symlinks are the sole exception to the
    # ordinary no-symlink installation rule; their exact inode is receipted.
    p = UNIT_ROOT / name
    info = p.lstat()
    if (not isinstance(owned, dict) or not stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or
            os.readlink(p) != "/dev/null" or info.st_ino != owned.get("inode") or info.st_dev != owned.get("device")):
        fail("Owned persistent libvirt activation mask changed; never adopted or replaced")
    for root in (UNIT_ROOT, RUNTIME_UNIT_ROOT):
        dropin = root / (name + ".d")
        if dropin.exists() or dropin.is_symlink() or root != UNIT_ROOT and ((root / name).exists() or (root / name).is_symlink()):
            fail("Foreign libvirt activation override appeared")


def _approved_system_tool(path):
    p = Path(path)
    if not p.exists():
        return False
    # Ubuntu alternatives use root-owned symlinks for iptables-save. Their
    # resolved inode and every canonical ancestor must still be root protected.
    protected_path(str(p.parent), directory=True)
    info = p.lstat()
    if info.st_uid != 0 or not (stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)):
        fail("Untrusted system networking inspection tool")
    protected_path(str(p.resolve(strict=True)))
    return True


def network_snapshot():
    """Read-only evidence; no network configuration command is ever issued."""
    links = {}
    for p in Path("/sys/class/net").iterdir():
        links[p.name] = {field: (p / field).read_text().strip() for field in ("ifindex", "address", "mtu")}
    rules = {}
    for name, argv in (("nft", ["/usr/sbin/nft", "--stateless", "list", "ruleset"]),
                       ("iptables", ["/usr/sbin/iptables-save"]), ("ip6tables", ["/usr/sbin/ip6tables-save"])):
        if _approved_system_tool(argv[0]):
            raw = run_fixed(argv).decode("utf-8")
            rules[name] = normalize_firewall_evidence(name, raw)
        else:
            rules[name] = None
    return {"links": links, "rules": rules}


def normalize_firewall_evidence(name, raw):
    lines = [line for line in raw.splitlines() if not line.startswith("#")]
    if name in ("iptables", "ip6tables"):
        # Policy-chain counters are traffic state, not firewall configuration.
        # Preserve every chain name, policy, rule, match, target and COMMIT.
        lines = [re.sub(r"^(:\S+\s+\S+\s+)\[[0-9]+:[0-9]+\]$", r"\1[0:0]", line) for line in lines]
    return "\n".join(lines).strip()


def verify_network_unchanged(before, after):
    if not isinstance(before, dict) or before.get("links") != after["links"]:
        fail("Host interface evidence changed; owned libvirt services stopped for review")
    for name, old in before.get("rules", {}).items():
        new = after["rules"].get(name)
        # An absent inspection binary on a clean host may be newly installed by
        # the signed dependency transaction, but a new nonempty ruleset may not.
        if old != new and not (old is None and new in (None, "")):
            fail("Firewall evidence changed or is unavailable; no acceptance claimed")


def _virsh_readonly(*command):
    return run_fixed([VIRSH, "--connect", "qemu:///system", "--readonly", *command])


def verify_libvirt_daemon(*, owned=False):
    protected_path(VIRSH)
    protected_path(str(LIBVIRT_SOCKET.parent), directory=True)
    info = LIBVIRT_SOCKET.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or owned and info.st_mode & 0o077:
        fail("Root-protected libvirt UNIX socket required")
    domains = _virsh_readonly("list", "--all", "--name").strip()
    networks = _virsh_readonly("net-list", "--all", "--name").strip()
    try:
        capabilities = ET.fromstring(_virsh_readonly("capabilities"))
        if capabilities.tag != "capabilities" or capabilities.find("host") is None or capabilities.find("guest") is None:
            fail("Libvirt did not report actual system QEMU capabilities")
    except ET.ParseError:
        fail("Libvirt system capabilities are malformed")
    if owned and (domains or networks):
        fail("Fresh owned libvirt must expose no domains or networks; nothing is deleted or changed")
    return {"daemon": "owned-unix-only" if owned else "preserved-existing", "kvm": "not-asserted"}


def verify_libvirt_namespace():
    # Re-read the effective unit, not just our source template: foreign drop-ins
    # and transient overrides can otherwise silently remove mount isolation.
    name = "aster-cloud-libvirtd.service"
    properties = run_fixed([SYSTEMCTL, "show", name, "--property=FragmentPath,DropInPaths,MainPID", "--no-pager"]).decode()
    values = dict(line.split("=", 1) for line in properties.splitlines() if "=" in line)
    if values.get("FragmentPath") != str(UNIT_ROOT / name) or values.get("DropInPaths") != "" or not re.fullmatch(r"[1-9][0-9]*", values.get("MainPID", "")):
        fail("Effective owned libvirt unit or process differs; refusing readiness")
    pid = values["MainPID"]
    if Path(f"/proc/{pid}/exe").resolve() != Path(LIBVIRTD).resolve():
        fail("Owned libvirt process identity differs")
    source = LIBVIRT_EMPTY.stat()
    target = Path(f"/proc/{pid}/root/etc/libvirt/qemu/networks").stat()
    if (source.st_dev, source.st_ino) != (target.st_dev, target.st_ino):
        fail("Libvirt network directory is not isolated in its real mount namespace")
    lines = Path(f"/proc/{pid}/mountinfo").read_text().splitlines()
    if not any(len(fields := line.split()) > 6 and fields[4] == "/etc/libvirt/qemu/networks" and "ro" in fields[5].split(",") for line in lines):
        fail("Libvirt network mount is not read-only")


def verify_libvirt_effective_units():
    for name in LIBVIRT_OWN_UNITS:
        output = run_fixed([SYSTEMCTL, "show", name, "--property=FragmentPath,DropInPaths", "--no-pager"]).decode()
        fields = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
        if fields.get("FragmentPath") != str(UNIT_ROOT / name) or fields.get("DropInPaths") != "":
            fail("Foreign effective libvirt unit override; no owned service started")


def _verify_empty_networks():
    protected_path(str(LIBVIRT_EMPTY), directory=True)
    protected_path(str(LIBVIRT_EMPTY / "autostart"), directory=True)
    if set(p.name for p in LIBVIRT_EMPTY.iterdir()) != {"autostart"} or any((LIBVIRT_EMPTY / "autostart").iterdir()):
        fail("Owned empty network namespace was modified; never overwritten")


def prepare_libvirt(state_dir, *, resume=False):
    """Explicit fresh-daemon preparation, never a claim of KVM/VM readiness.

    Existing active daemons are only inspected. Fresh official packages retain
    their AppArmor/QEMU user policy and vendor default XML on disk; every vendor
    service/socket is persistently masked, and only our UNIX-only daemon runs
    with a read-only empty network directory in its actual mount namespace.
    """
    codename = root_target()
    protected_path(SYSTEMCTL)
    state_dir = ensure_dir(Path(state_dir))
    path = state_dir / "libvirt.json"
    digest = libvirt_plan_digest(codename)
    if path.exists():
        if not resume:
            fail("Libvirt receipt exists; explicitly resume the exact preparation plan")
        receipt = _json(read_private(str(path)))
        if receipt.get("schema") != 1 or receipt.get("codename") != codename or receipt.get("plan_sha256") != digest:
            fail("Libvirt resume plan or Ubuntu target changed")
    else:
        # A socket may activate a stopped vendor daemon. Do not even connect to
        # it unless an existing service is already active; never start/adapt it.
        if LIBVIRT_CONFIG.exists() or LIBVIRT_STATE.exists() or LIBVIRT_SOCKET.exists() or Path(LIBVIRTD).exists():
            run_fixed([SYSTEMCTL, "is-active", "--quiet", "libvirtd.service"])
            result = verify_libvirt_daemon()
            receipt = {"schema": 1, "codename": codename, "plan_sha256": digest, "mode": "preserved-existing",
                       "status": "libvirt-prepared", "steps": ["existing-daemon-readonly-verified"]}
            save_receipt(path, receipt)
            return dict(result, status="libvirt-prepared", receipt=str(path))
        fresh_libvirt_host()
        if POLICY_PATH.exists() or POLICY_PATH.is_symlink():
            fail("Existing service-start policy is never replaced")
        receipt = {"schema": 1, "codename": codename, "plan_sha256": digest, "mode": "fresh-owned",
                   "status": "preparing", "masks": {}, "steps": [], "network_before": network_snapshot()}
        save_receipt(path, receipt)
    if receipt.get("mode") == "preserved-existing":
        run_fixed([SYSTEMCTL, "is-active", "--quiet", "libvirtd.service"])
        return dict(verify_libvirt_daemon(), status="libvirt-prepared", receipt=str(path))
    if receipt.get("mode") != "fresh-owned":
        fail("Unknown libvirt receipt ownership")
    if not isinstance(receipt.get("masks"), dict) or not set(receipt["masks"]) <= set(LIBVIRT_VENDOR_UNITS):
        fail("Malformed libvirt activation receipt")
    # A foreign mask/unit on resume must fail BEFORE any systemctl operation,
    # including cleanup. Never execute a stranger's ExecStop via our unit name.
    for name, ownership in receipt["masks"].items():
        _verify_libvirt_mask(name, ownership)
    for name in LIBVIRT_OWN_UNITS:
        p = UNIT_ROOT / name
        if p.exists() or p.is_symlink():
            protected_path(str(p))
            if p.read_bytes() != libvirt_unit_bytes(name):
                fail("Owned daemon unit changed; manual review required")
        for root in (UNIT_ROOT, RUNTIME_UNIT_ROOT):
            if (root / (name + ".d")).exists() or (root / (name + ".d")).is_symlink() or root != UNIT_ROOT and ((root / name).exists() or (root / name).is_symlink()):
                fail("Foreign owned-daemon override appeared")
    started = False
    try:
        ensure_dir(UNIT_ROOT, 0o755)
        for name in LIBVIRT_VENDOR_UNITS:
            if name in receipt["masks"]:
                continue
            p = UNIT_ROOT / name
            if p.exists() or p.is_symlink():
                fail("Foreign or unacknowledged activation mask exists; manual review required")
            os.symlink("/dev/null", p)
            directory_fd = os.open(UNIT_ROOT, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            info = p.lstat()
            receipt["masks"][name] = {"inode": info.st_ino, "device": info.st_dev}
            save_receipt(path, receipt)
        verify_libvirt_masks(receipt)
        run_fixed([SYSTEMCTL, "daemon-reload"])
        install_dependencies("node", state_dir, with_libvirt=True, resume=resume)
        if "packages-installed" not in receipt["steps"]:
            receipt["steps"].append("packages-installed")
            save_receipt(path, receipt)
        ensure_dir(LIBVIRT_EMPTY, 0o755)
        ensure_dir(LIBVIRT_EMPTY / "autostart", 0o755)
        _verify_empty_networks()
        write_new(LIBVIRT_OWN_CONFIG, LIBVIRT_DAEMON_CONFIG, 0o600)
        for name in LIBVIRT_OWN_UNITS:
            for root in (UNIT_ROOT, RUNTIME_UNIT_ROOT):
                if (root / (name + ".d")).exists() or (root / (name + ".d")).is_symlink():
                    fail("Foreign owned-daemon override exists")
            write_new(UNIT_ROOT / name, libvirt_unit_bytes(name), 0o644)
        verify_libvirt_masks(receipt)
        verify_network_unchanged(receipt["network_before"], network_snapshot())
        run_fixed([SYSTEMCTL, "daemon-reload"])
        verify_libvirt_effective_units()
        if receipt.get("status") != "libvirt-prepared":
            receipt["status"] = "own-service-start-attempted"
            save_receipt(path, receipt)
            started = True  # Persisted intent covers a lost systemctl ACK.
            run_fixed([SYSTEMCTL, "start", *LIBVIRT_OWN_UNITS])
        for name in LIBVIRT_OWN_UNITS:
            run_fixed([SYSTEMCTL, "is-active", "--quiet", name])
        verify_libvirt_namespace()
        for attempt in range(15):
            try:
                result = verify_libvirt_daemon(owned=True)
                break
            except (OSError, ProvisionError):
                if attempt == 14:
                    raise
                time.sleep(1)
        verify_network_unchanged(receipt["network_before"], network_snapshot())
        receipt["status"] = "own-service-enable-attempted"
        save_receipt(path, receipt)
        run_fixed([SYSTEMCTL, "enable", *LIBVIRT_OWN_UNITS])
        receipt["status"] = "libvirt-prepared"
        receipt["kvm"] = "not-asserted"
        save_receipt(path, receipt)
        return dict(result, status="libvirt-prepared", receipt=str(path))
    except Exception:
        # Never unmask vendor units or delete state, networks, VMs or journals.
        # On resume a previously attempted start remains uncertain until checked.
        if started or receipt.get("status") in ("own-service-start-attempted", "own-service-enable-attempted", "libvirt-prepared"):
            try:
                run_fixed([SYSTEMCTL, "disable", *LIBVIRT_OWN_UNITS])
                receipt["boot_cleanup"] = "owned-boot-activation-disabled"
            except ProvisionError:
                receipt["boot_cleanup"] = "owned-boot-disable-unconfirmed"
            try:
                run_fixed([SYSTEMCTL, "stop", *reversed(LIBVIRT_OWN_UNITS)])
                receipt["cleanup"] = "owned-daemons-stopped"
            except ProvisionError:
                receipt["cleanup"] = "owned-daemon-stop-unconfirmed"
        receipt["status"] = "failed-review-required"
        save_receipt(path, receipt)
        raise


def start_owned_mysql(state_dir):
    """Start only the exact fresh service prepared by this package operation."""
    state_dir = Path(state_dir)
    receipt_path = state_dir / "dependencies.json"
    receipt = _json(read_private(str(receipt_path)))
    if (receipt.get("status") != "dependencies-installed" or receipt.get("component") != "controller" or
            receipt.get("with_mysql") is not True):
        fail("Only this operation's newly installed dedicated MySQL may be started")
    protected_path(str(MYSQL_DROPIN))
    if MYSQL_DROPIN.read_bytes() != MYSQL_LOCAL_DROPIN:
        fail("Owned socket-only MySQL unit policy changed; refusing start")
    run_fixed([SYSTEMCTL, "daemon-reload"])
    try:
        run_fixed([SYSTEMCTL, "start", "mysql.service"])
        run_fixed([SYSTEMCTL, "is-active", "--quiet", "mysql.service"])
        for attempt in range(10):
            try:
                info = _query(state_dir,
                    "SELECT JSON_OBJECT('tcp_disabled',@@skip_networking,'mysqlx_enabled',"
                    "(SELECT COUNT(*) FROM information_schema.PLUGINS WHERE PLUGIN_NAME='mysqlx' AND PLUGIN_STATUS='ACTIVE'));\n")
                if info.get("tcp_disabled") not in (1, True) or info.get("mysqlx_enabled") != 0:
                    fail("Dedicated MySQL must have both classic and X TCP listeners disabled")
                receipt["mysql_transport"] = "unix-socket-only-verified"
                save_receipt(receipt_path, receipt)
                return {"status": "dedicated-mysql-local-ready", "transport": "unix-socket-only"}
            except ProvisionError:
                if attempt == 9:
                    raise
                time.sleep(1)
    except Exception:
        try:
            run_fixed([SYSTEMCTL, "stop", "mysql.service"])
        except ProvisionError:
            pass
        raise


def validate_names(database, runtime_user, migration_user):
    if (not isinstance(database, str) or not re.fullmatch(r"aster_(?:cloud|controller)(?:_[a-z0-9]{1,32})?", database) or
            any(not isinstance(user, str) or not re.fullmatch(r"aster_[a-z0-9_]{1,25}", user)
                for user in (runtime_user, migration_user)) or runtime_user == migration_user):
        fail("Dedicated safe Aster DB plus distinct non-root Aster account names required")
    return database, runtime_user, migration_user


def mysql_sql(state_dir, sql):
    """Local root socket bootstrap only, no implicit option/login files or history."""
    protected_path(MYSQL)
    home = ensure_dir(Path(state_dir) / "mysql-client-home")
    login = home / ".disabled-login-path"
    if login.exists() or login.is_symlink():
        fail("Unexpected MySQL login-path file refused")
    env = dict(SAFE_ENV, HOME=str(home), MYSQL_TEST_LOGIN_FILE=str(login), MYSQL_HISTFILE="/dev/null")
    return run_fixed([MYSQL, "--no-defaults", "--protocol=SOCKET", "--socket=" + MYSQL_SOCKET, "--user=root",
                      "--batch", "--raw", "--skip-column-names", "--skip-reconnect", "--connect-timeout=5", "--binary-mode"],
                     stdin=sql.encode("utf-8"), env=env)


def _query(state_dir, sql):
    try:
        return _json(mysql_sql(state_dir, sql).decode("utf-8"))
    except (UnicodeError, ValueError):
        fail("Unexpected local MySQL provisioning response")


def verify_grants(state_dir, user, database, privileges):
    """Refuse implicit roles/global/DDL extras rather than revoking existing grants."""
    account = "`" + user + "`@`localhost`"
    target = "`" + database.replace("_", "\\_") + "`.*"
    lines = mysql_sql(state_dir, "SHOW GRANTS FOR '" + user + "'@'localhost';\n").decode("utf-8").splitlines()
    seen = False
    for line in lines:
        if line == "GRANT USAGE ON *.* TO " + account:
            continue
        match = re.fullmatch(r"GRANT ([A-Z, ]+) ON " + re.escape(target) + r" TO " + re.escape(account), line)
        if not match or set(match[1].split(", ")) != set(privileges):
            fail("Provisioned account has unexpected global/schema/role/grant-option privileges; never altered to hide mismatch")
        seen = True
    if not seen:
        fail("Expected exact dedicated account privileges were not confirmed")


def provision_mysql(state_dir, database, runtime_user, migration_user, *, resume=False):
    root_target()
    validate_names(database, runtime_user, migration_user)
    return _provision_mysql(state_dir, database, runtime_user, migration_user, resume=resume)


def _provision_mysql(state_dir, database, runtime_user, migration_user, *, resume=False,
                     charset="utf8mb4", collation="utf8mb4_unicode_ci"):
    # Only callers above this boundary validate/derive identifiers. No CLI or
    # HTTP input can select raw SQL, a target path, root credentials or grants.
    state_dir = ensure_dir(Path(state_dir))
    receipt_path = state_dir / "mysql-provision.json"
    request = {"database": database, "runtime_user": runtime_user, "migration_user": migration_user}
    receipt = _json(read_private(str(receipt_path))) if receipt_path.exists() else None
    if receipt and (not resume or any(receipt.get(k) != v for k, v in request.items())):
        fail("Dedicated MySQL receipt exists; explicitly resume the original names")
    # No password is requested/generated/written before these collision checks.
    info = _query(state_dir,
        "SELECT JSON_OBJECT('current_user',CURRENT_USER(),'version',VERSION(),'server_uuid',@@server_uuid,"
        "'partial_revokes',@@partial_revokes,'mandatory_roles',@@mandatory_roles,'db_exists',(SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='" + database + "'),"
        "'foreign_databases',(SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME NOT IN ('mysql','sys','information_schema','performance_schema','" + database + "')),"
        "'runtime_exists',(SELECT COUNT(*) FROM mysql.user WHERE User='" + runtime_user + "'),"
        "'migration_exists',(SELECT COUNT(*) FROM mysql.user WHERE User='" + migration_user + "'));\n")
    if (info.get("current_user") != "root@localhost" or not isinstance(info.get("version"), str) or
            not re.match(r"8\.(?:0\.(?:2[1-9]|[3-9][0-9])|4\.[0-9]+)", info["version"]) or
            info.get("partial_revokes") not in (0, False) or info.get("foreign_databases") != 0 or
            info.get("mandatory_roles", "") or
            not isinstance(info.get("server_uuid"), str) or not re.fullmatch(r"[a-fA-F0-9-]{36}", info["server_uuid"])):
        fail("Dedicated MySQL 8.0.21+/8.4 local-root server with no foreign DBs and standard grant semantics required")
    if receipt is None:
        if any(info.get(key) != 0 for key in ("db_exists", "runtime_exists", "migration_exists")):
            fail("Database or account already exists; refusing any adoption/overwrite")
        receipt = {"schema": 1, **request, "server_uuid": info["server_uuid"], "nonce": secrets.token_hex(32), "steps": []}
        save_receipt(receipt_path, receipt)
    elif receipt.get("server_uuid") != info["server_uuid"]:
        fail("MySQL server identity changed; resume refused")
    nonce = receipt["nonce"]
    if not re.fullmatch(r"[0-9a-f]{64}", nonce):
        fail("Invalid MySQL ownership receipt")
    def persist(step):
        if step not in receipt["steps"]:
            receipt["steps"].append(step)
        save_receipt(receipt_path, receipt)
    try:
        if info["db_exists"]:
            owner = _query(state_dir, "SELECT JSON_OBJECT('nonce',nonce,'server_uuid',server_uuid) FROM `" + database + "`.aster_installer_ownership WHERE id=1;\n")
            if owner != {"nonce": nonce, "server_uuid": receipt["server_uuid"]}:
                fail("Existing DB lacks this operation's exact ownership marker; never adopted")
        else:
            if "database-created" in receipt["steps"]:
                fail("Previously owned DB disappeared; never recreated automatically")
            mysql_sql(state_dir, "CREATE DATABASE `" + database + "` CHARACTER SET " + charset + " COLLATE " + collation + ";\n"
                "CREATE TABLE `" + database + "`.aster_installer_ownership (id INT PRIMARY KEY,nonce CHAR(64) NOT NULL,server_uuid CHAR(36) NOT NULL) ENGINE=InnoDB;\n"
                "INSERT INTO `" + database + "`.aster_installer_ownership VALUES (1,'" + nonce + "','" + receipt["server_uuid"] + "');\n")
        persist("database-created")
        result = {"database_name": database}
        for role, user, exists, privileges in (
                ("runtime", runtime_user, info["runtime_exists"], RUNTIME_PRIVILEGES),
                ("migration", migration_user, info["migration_exists"], MIGRATION_PRIVILEGES)):
            dsn_path = state_dir / (role + "-mysql-dsn")
            if exists:
                owner = _query(state_dir, "SELECT JSON_OBJECT('nonce',ATTRIBUTE->>'$.aster_cloud_installer','host',HOST) FROM information_schema.USER_ATTRIBUTES WHERE USER='" + user + "';\n")
                if owner != {"nonce": nonce, "host": "localhost"} or not dsn_path.exists():
                    fail("Existing account is foreign or CREATE acknowledgement/credential was lost; no reset/overwrite")
                read_private(str(dsn_path))
            else:
                if role + "-created" in receipt["steps"] or dsn_path.exists():
                    fail("Account/credential state is ambiguous; never recreate or reset it automatically")
                # Server-generated passwords never occur in submitted SQL (nor
                # argv/env/client history). Capture the one-time response privately.
                raw = mysql_sql(state_dir, "CREATE USER '" + user + "'@'localhost' IDENTIFIED WITH caching_sha2_password BY RANDOM PASSWORD ATTRIBUTE '{\"aster_cloud_installer\":\"" + nonce + "\"}';\n")
                values = raw.decode("utf-8").rstrip("\n").split("\t")
                if (len(values) not in (3, 4) or len(values) == 4 and values[3] != "1" or
                        values[:2] != [user, "localhost"] or not 16 <= len(values[2]) <= 1024 or
                        any(c in values[2] for c in "\r\n\t\x00")):
                    fail("Random password acknowledgement ambiguous; retain DB/account for manual recovery")
                write_new(dsn_path, (user + ":" + values[2] + "@unix(" + MYSQL_SOCKET + ")/" + database + "\n").encode())
                del raw, values
            persist(role + "-created")
            # Escape database underscores: MySQL otherwise treats them as grant
            # wildcards even inside backticks. partial_revokes=1 is refused above.
            grant_database = database.replace("_", "\\_")
            mysql_sql(state_dir, "GRANT " + ", ".join(privileges) + " ON `" + grant_database + "`.* TO '" + user + "'@'localhost';\n")
            verify_grants(state_dir, user, database, privileges)
            persist(role + "-granted")
            result["dsn_file" if role == "runtime" else "migration_dsn_file"] = str(dsn_path)
        receipt["status"] = "dedicated-database-provisioned"
        save_receipt(receipt_path, receipt)
        return result
    except Exception:
        receipt["status"] = "failed-preserved-no-drop-no-reset"
        save_receipt(receipt_path, receipt)
        raise


def restore_database_names(operation):
    if not isinstance(operation, str) or not re.fullmatch(r"[a-f0-9]{32}", operation):
        fail("Exact lowercase restoration operation required")
    return "aster_cloud_restore_" + operation, "aster_r_" + operation[:23], "aster_m_" + operation[:23]


def _restore_server_baseline(state_dir, database, runtime_user, migration_user, *, verification_user=None):
    accounts = [runtime_user, migration_user]
    if verification_user is not None:
        operation = state_dir.parent.name
        if (restore_database_names(operation) != (database, runtime_user, migration_user) or
                verification_user != 'aster_v_' + operation[:23]):
            fail("Verification account binding changed", code="TARGET_VERIFICATION_IDENTITY_REJECTED")
        accounts.append(verification_user)
    account_names = "','".join(accounts)
    # Root's auth_socket mapping must not authorize another OS principal. The
    # vendor account is inspected separately, not accepted merely by its name.
    info = _query(state_dir,
        "SELECT JSON_OBJECT('root',CURRENT_USER(),'uuid',@@server_uuid,'tcp_disabled',@@skip_networking,"
        "'partial_revokes',@@partial_revokes,'mandatory_roles',@@mandatory_roles,"
        "'mysqlx',(SELECT COUNT(*) FROM information_schema.PLUGINS WHERE PLUGIN_NAME='mysqlx' AND PLUGIN_STATUS='ACTIVE'),"
        "'roles',(SELECT COUNT(*) FROM mysql.role_edges),'default_roles',(SELECT COUNT(*) FROM mysql.default_roles),"
        "'foreign_schemas',(SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME NOT IN ('mysql','sys','information_schema','performance_schema','" + database + "')),"
        "'database_exists',(SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='" + database + "'),"
        "'application_accounts',(SELECT COUNT(*) FROM mysql.user WHERE BINARY User IN ('" + account_names + "')),"
        "'vendor_count',(SELECT COUNT(*) FROM mysql.user WHERE BINARY User='debian-sys-maint'),"
        "'accounts',(SELECT COUNT(*) FROM mysql.user WHERE BINARY User<>'debian-sys-maint' AND NOT (BINARY Host='localhost' AND ("
        "(BINARY User='root' AND BINARY plugin='auth_socket' AND BINARY authentication_string IN ('','root')) OR "
        "(BINARY User IN ('mysql.infoschema','mysql.session','mysql.sys') AND account_locked='Y') OR "
        "(BINARY User IN ('" + account_names + "') AND BINARY plugin='caching_sha2_password')))));\n")
    expected = {'root': 'root@localhost', 'tcp_disabled': 1, 'mysqlx': 0, 'roles': 0, 'default_roles': 0,
                'accounts': 0, 'foreign_schemas': 0, 'partial_revokes': 0, 'mandatory_roles': ''}
    if (set(info) != set(expected) | {'uuid', 'database_exists', 'application_accounts', 'vendor_count'} or
            any(info[k] != v for k, v in expected.items()) or
            not isinstance(info['uuid'], str) or not re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', info['uuid']) or
            type(info['vendor_count']) is not int or info['vendor_count'] not in (0, 1)):
        fail("Dedicated restore server inventory changed", code="TARGET_RESTORE_SERVER_INVENTORY_REJECTED")
    if not info['vendor_count']:
        return info, {'mode': 'absent', 'auth_sha256': '', 'grants_sha256': ''}
    # auth_socket also accepts an OS user with the SAME name as the MySQL user,
    # even with AS 'root'. Never permit that second principal to exist.
    try:
        pwd.getpwnam('debian-sys-maint')
    except KeyError:
        pass
    else:
        fail("Maintenance OS identity is not root-only", code="TARGET_RESTORE_MAINTENANCE_IDENTITY_REJECTED")
    profile = _query(state_dir,
        "SELECT JSON_OBJECT('local',BINARY Host='localhost','unlocked',account_locked='N',"
        "'attributes_clear',COALESCE(JSON_LENGTH(User_attributes),0)=0,"
        "'mode',CASE WHEN BINARY plugin='auth_socket' AND BINARY authentication_string='root' THEN 'root-socket' "
        "WHEN BINARY plugin IN ('mysql_native_password','caching_sha2_password') AND OCTET_LENGTH(authentication_string)>=32 THEN 'password' ELSE 'unapproved' END,"
        "'auth_sha256',SHA2(CONCAT(plugin,CHAR(0),authentication_string),256)) "
        "FROM mysql.user WHERE BINARY User='debian-sys-maint';\n")
    if (set(profile) != {'local', 'unlocked', 'attributes_clear', 'mode', 'auth_sha256'} or
            any(profile[k] != 1 for k in ('local', 'unlocked', 'attributes_clear')) or
            profile['mode'] not in ('password', 'root-socket') or not isinstance(profile['auth_sha256'], str) or
            not re.fullmatch(r'[a-f0-9]{64}', profile['auth_sha256'])):
        fail("Maintenance identity is outside the fixed policy", code="TARGET_RESTORE_MAINTENANCE_IDENTITY_REJECTED")
    grants = mysql_sql(state_dir, "SHOW GRANTS FOR 'debian-sys-maint'@'localhost';\n")
    if not grants or len(grants) > 65536:
        fail("Maintenance privileges cannot be verified", code="TARGET_RESTORE_MAINTENANCE_IDENTITY_REJECTED")
    return info, {'mode': profile['mode'], 'auth_sha256': profile['auth_sha256'],
                  'grants_sha256': hashlib.sha256(grants).hexdigest()}


def _restore_maintenance(state_dir, operation, database, runtime_user, migration_user, *, prepare=False, verification_user=None):
    """Harden only this operation's fresh MySQL; never reset an existing host.

    Immutable intent precedes the single fixed ALTER. On lost acknowledgement,
    the exact intended root-socket state can be verified, not blindly rewritten.
    A completed receipt makes any later credential/grant drift a refusal.
    """
    codename = root_target()
    if verification_user is not None and prepare:
        fail("Verification cannot alter maintenance identity", code="TARGET_VERIFICATION_IDENTITY_REJECTED")
    dependency_raw = read_private(str(state_dir / 'dependencies.json'))
    dependency = _json(dependency_raw)
    if (dependency.get('schema') != 1 or dependency.get('status') != 'dependencies-installed' or
            dependency.get('component') != 'controller' or dependency.get('with_mysql') is not True or
            dependency.get('codename') != codename or dependency.get('mysql_transport') != 'unix-socket-only-verified' or
            'packages-installed' not in dependency.get('steps', [])):
        fail("Maintenance policy requires the owned fresh package transaction", code="TARGET_RESTORE_MAINTENANCE_PROVENANCE_REJECTED")
    info, profile = _restore_server_baseline(state_dir, database, runtime_user, migration_user, verification_user=verification_user)
    fixed = {'schema': 1, 'operation_id': operation, 'server_uuid': info['uuid'],
             'dependencies_sha256': hashlib.sha256(dependency_raw).hexdigest()}
    intent_path, verified_path = (state_dir / ('maintenance-auth-' + name + '.json') for name in ('intent', 'verified'))
    def publish(path, value):
        raw = (json.dumps(value, sort_keys=True) + '\n').encode()
        write_new(path, raw)
        fd = os.open(state_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        return raw
    if intent_path.exists() or intent_path.is_symlink():
        intent_raw = read_private(str(intent_path))
        intent = _json(intent_raw)
        if (set(intent) != set(fixed) | {'before'} or type(intent['schema']) is not int or any(intent[k] != v for k, v in fixed.items()) or
                not isinstance(intent['before'], dict) or set(intent['before']) != {'mode', 'auth_sha256', 'grants_sha256'}):
            fail("Maintenance intent binding changed", code="TARGET_RESTORE_MAINTENANCE_PROVENANCE_REJECTED")
    else:
        if (not prepare or verified_path.exists() or verified_path.is_symlink() or
                info['database_exists'] != 0 or info['application_accounts'] != 0):
            fail("Unrecorded maintenance identity cannot be adopted", code="TARGET_RESTORE_MAINTENANCE_PROVENANCE_REJECTED")
        intent = {**fixed, 'before': profile}
        intent_raw = publish(intent_path, intent)
    before = intent['before']
    if (before['mode'] not in ('absent', 'password', 'root-socket') or
            any(not isinstance(before[k], str) or not re.fullmatch(r'[a-f0-9]{64}' if before['mode'] != 'absent' else r'', before[k])
                for k in ('auth_sha256', 'grants_sha256'))):
        fail("Maintenance intent malformed", code="TARGET_RESTORE_MAINTENANCE_PROVENANCE_REJECTED")
    wanted = {'mode': 'absent', 'auth_sha256': '', 'grants_sha256': ''} if before['mode'] == 'absent' else {
        'mode': 'root-socket', 'auth_sha256': hashlib.sha256(b'auth_socket\x00root').hexdigest(),
        'grants_sha256': before['grants_sha256']}
    if before['mode'] == 'root-socket' and before != wanted:
        fail("Maintenance intent mapping is invalid", code="TARGET_RESTORE_MAINTENANCE_PROVENANCE_REJECTED")
    verified = {'schema': 1, 'intent_sha256': hashlib.sha256(intent_raw).hexdigest(), 'profile': wanted}
    if verified_path.exists() or verified_path.is_symlink():
        if read_private(str(verified_path)) != (json.dumps(verified, sort_keys=True) + '\n').encode() or profile != wanted:
            fail("Verified maintenance authentication changed; never reset", code="TARGET_RESTORE_MAINTENANCE_DRIFT_REJECTED")
        return
    if not prepare:
        fail("Maintenance authentication is not verified", code="TARGET_RESTORE_MAINTENANCE_PROVENANCE_REJECTED")
    if profile != wanted:
        if before['mode'] != 'password' or profile != before:
            fail("Maintenance outcome is ambiguous; never reset", code="TARGET_RESTORE_MAINTENANCE_OUTCOME_UNCONFIRMED")
        # No password, grant, account name, path or SQL comes from caller input.
        mysql_sql(state_dir, "ALTER USER 'debian-sys-maint'@'localhost' IDENTIFIED WITH auth_socket AS 'root';\n")
        after_info, profile = _restore_server_baseline(state_dir, database, runtime_user, migration_user, verification_user=verification_user)
        if after_info != info or profile != wanted:
            fail("Maintenance conversion outcome unconfirmed", code="TARGET_RESTORE_MAINTENANCE_OUTCOME_UNCONFIRMED")
    publish(verified_path, verified)


def _restore_server_inventory(state_dir, database, runtime_user, migration_user):
    # Read-only every time: the fixed vendor exception needs immutable fresh-
    # install provenance, exact root-socket identity, unchanged grants and NSS.
    operation = state_dir.parent.name
    if restore_database_names(operation) != (database, runtime_user, migration_user):
        fail("Restore operation binding changed", code="TARGET_RESTORE_SERVER_INVENTORY_REJECTED")
    _restore_maintenance(state_dir, operation, database, runtime_user, migration_user)


def provision_restore_mysql(operation, charset, collation, *, resume=False):
    """Restore-only fixed destination; ordinary provision_mysql names unchanged.

    The coordinator has already authenticated every archive row and persisted
    its complete source/target-bound data plan under the target admission seal.
    Existing/ambiguous data or accounts are retained, never reset or dropped.
    """
    root_target()
    database, runtime_user, migration_user = restore_database_names(operation)
    if any(not isinstance(x, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", x) for x in (charset, collation)):
        fail("Authenticated source database encoding identifiers required")
    state_dir = Path('/var/lib/aster-controller-restore') / operation / 'database'
    protected_path(str(state_dir), directory=True, private=True)
    binding = {'schema': 1, 'operation_id': operation, 'database': database, 'runtime_user': runtime_user,
               'migration_user': migration_user, 'charset': charset, 'collation': collation}
    binding_path = state_dir / 'restore-provision.json'
    if binding_path.exists() or binding_path.is_symlink():
        if not resume or _json(read_private(str(binding_path))) != binding:
            fail("Restore provisioning binding changed; original operation retained")
    else:
        if (state_dir / 'mysql-provision.json').exists() or (state_dir / 'mysql-provision.pending').exists():
            fail("Unbound provisioning history cannot be adopted")
        write_new(binding_path, (json.dumps(binding, sort_keys=True) + "\n").encode())
        fd = os.open(state_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    _restore_maintenance(state_dir, operation, database, runtime_user, migration_user, prepare=True)
    _restore_server_inventory(state_dir, database, runtime_user, migration_user)
    # Validate actual encoding support without interpreting arbitrary SQL.
    encoding = _query(state_dir, "SELECT JSON_OBJECT('matches',COUNT(*)) FROM information_schema.COLLATIONS WHERE COLLATION_NAME='" +
                      collation + "' AND CHARACTER_SET_NAME='" + charset + "';\n")
    if encoding != {'matches': 1}:
        fail("Authenticated source encoding is unavailable on this server")
    result = _provision_mysql(state_dir, database, runtime_user, migration_user, resume=resume,
                              charset=charset, collation=collation)
    verify_restore_mysql(operation, charset, collation)
    return result


def verify_restore_mysql(operation, charset, collation, *, restored=False):
    """Original two-account inventory. No caller can opt extra identities in."""
    return _verify_restore_mysql(operation, charset, collation, restored=restored)


def _verify_restore_mysql(operation, charset, collation, *, restored=False, verification_user=None):
    """The extra identity is used only after its immutable verification binding."""
    database, runtime_user, migration_user = restore_database_names(operation)
    state_dir = Path('/var/lib/aster-controller-restore') / operation / 'database'
    protected_path(str(state_dir), directory=True, private=True)
    if verification_user is None:
        _restore_server_inventory(state_dir, database, runtime_user, migration_user)
    else:
        _restore_maintenance(state_dir, operation, database, runtime_user, migration_user, verification_user=verification_user)
    verify_grants(state_dir, runtime_user, database, RUNTIME_PRIVILEGES)
    verify_grants(state_dir, migration_user, database, MIGRATION_PRIVILEGES)
    info = _query(state_dir,
        "SELECT JSON_OBJECT('charset',DEFAULT_CHARACTER_SET_NAME,'collation',DEFAULT_COLLATION_NAME,"
        "'tables',(SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='" + database + "'),"
        "'marker',(SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='" + database + "' AND TABLE_NAME='aster_installer_ownership' AND ENGINE='InnoDB' AND TABLE_TYPE='BASE TABLE'),"
        "'routines',(SELECT COUNT(*) FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA='" + database + "'),"
        "'events',(SELECT COUNT(*) FROM information_schema.EVENTS WHERE EVENT_SCHEMA='" + database + "'),"
        "'triggers',(SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA='" + database + "')) "
        "FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='" + database + "';\n")
    if type(restored) is not bool or info != {'charset': charset, 'collation': collation, 'tables': 35 if restored else 1, 'marker': 1, 'routines': 0, 'events': 0, 'triggers': 0}:
        fail("Restore target object inventory or source encoding changed")
    owner = _json(read_private(str(state_dir / 'mysql-provision.json')))
    if not isinstance(owner.get('nonce'), str) or not re.fullmatch(r'[a-f0-9]{64}', owner['nonce']):
        fail("Malformed target ownership receipt")
    actual = _query(state_dir, "SELECT JSON_OBJECT('rows',COUNT(*),'owned',COALESCE(SUM(id=1 AND nonce='" + owner['nonce'] +
                    "' AND server_uuid=@@server_uuid),0)) FROM `" + database + "`.aster_installer_ownership;\n")
    if actual != {'rows': 1, 'owned': 1}:
        fail("Target ownership marker changed; never adopted or repaired")
    return {'database_provisioned': True, 'database_restored': False, 'target_restore_approved': False, 'migration_ready': False}


def verification_sql_policy(operation):
    database, _, _ = restore_database_names(operation)
    user = 'aster_v_' + operation[:23]
    account, table = '`' + user + '`@`localhost`', '`' + database + '`.'
    return {'database': database, 'user': user, 'grants': [
        'GRANT SELECT ON `' + database.replace('_', '\\_') + '`.* TO ' + account,
        'GRANT INSERT, DELETE ON ' + table + '`controller_console_sessions` TO ' + account,
        'GRANT INSERT, UPDATE, DELETE ON ' + table + '`controller_console_login_limits` TO ' + account,
        'GRANT INSERT (`actor`, `action`, `target`, `created_at`) ON ' + table + '`controller_identity_audit` TO ' + account]}


def _verification_write_new(path, value):
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    write_new(path, raw)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return raw


def _verification_grants(state_dir, policy):
    """Root reads all grants; no broad privileges are revoked to hide drift."""
    user, database = policy['user'], policy['database']
    raw = mysql_sql(state_dir, "SHOW GRANTS FOR '" + user + "'@'localhost';\n")
    if len(raw) > 65536:
        fail('Verification grant output exceeds bound', code='TARGET_VERIFICATION_GRANTS_REJECTED')
    def normalize(line):
        suffix = ' TO `' + user + '`@`localhost`'
        if not line.startswith('GRANT ') or not line.endswith(suffix):
            fail('Unexpected verification privilege source', code='TARGET_VERIFICATION_GRANTS_REJECTED')
        parts = line[6:-len(suffix)].split(' ON ')
        if len(parts) != 2:
            fail('Malformed verification grants', code='TARGET_VERIFICATION_GRANTS_REJECTED')
        privileges, obj = parts
        if privileges.startswith('INSERT (') and privileges.endswith(')'):
            privileges = 'INSERT (' + ', '.join(sorted(privileges[8:-1].split(', '))) + ')'
        else:
            privileges = ', '.join(sorted(privileges.split(', ')))
        return obj, privileges
    wanted = dict(normalize(line) for line in policy['grants'])
    wanted['*.*'] = 'USAGE'
    actual = {}
    try:
        lines = raw.decode('utf-8').splitlines()
    except UnicodeError:
        fail('Verification grants not decoded', code='TARGET_VERIFICATION_GRANTS_REJECTED')
    for line in lines:
        obj, privileges = normalize(line)
        if obj in actual:
            fail('Duplicate verification grant object', code='TARGET_VERIFICATION_GRANTS_REJECTED')
        actual[obj] = privileges
    if actual != wanted:
        fail('Verification privileges differ from exact policy', code='TARGET_VERIFICATION_GRANTS_REJECTED')
    return hashlib.sha256(json.dumps(actual, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _verification_binding(operation, plan_sha256, charset, collation):
    root_target()
    policy = verification_sql_policy(operation)
    if not isinstance(plan_sha256, str) or not re.fullmatch('[a-f0-9]{64}', plan_sha256):
        fail('Exact verification plan digest required', code='TARGET_VERIFICATION_BINDING_REJECTED')
    if any(not isinstance(v, str) or not re.fullmatch('[a-z][a-z0-9_]{0,63}', v) for v in (charset, collation)):
        fail('Unsafe verification encoding', code='TARGET_VERIFICATION_BINDING_REJECTED')
    state = Path('/var/lib/aster-controller-restore') / operation / 'database'
    protected_path(str(state), directory=True, private=True)
    owner_raw = read_private(str(state / 'mysql-provision.json'))
    owner = _json(owner_raw)
    if (owner.get('database') != policy['database'] or not isinstance(owner.get('server_uuid'), str) or
            not re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', owner['server_uuid'])):
        fail('Verification owner binding invalid', code='TARGET_VERIFICATION_BINDING_REJECTED')
    fixed = {'schema': 1, 'operation_id': operation, 'plan_sha256': plan_sha256,
             'database': policy['database'], 'user': policy['user'], 'server_uuid': owner['server_uuid'],
             'owner_sha256': hashlib.sha256(owner_raw).hexdigest(), 'charset': charset, 'collation': collation}
    return state, policy, fixed


def _verification_intent(state, fixed):
    raw = read_private(str(state / 'verification-started.json'))
    intent = _json(raw)
    if (set(intent) != set(fixed) | {'nonce'} or type(intent['schema']) is not int or
            any(intent[k] != v for k, v in fixed.items()) or not isinstance(intent['nonce'], str) or
            not re.fullmatch('[a-f0-9]{64}', intent['nonce'])):
        fail('Verification intent differs from original operation', code='TARGET_VERIFICATION_BINDING_REJECTED')
    return intent, hashlib.sha256(raw).hexdigest()


def verification_account_candidate(operation, plan_sha256, charset, collation):
    state,_,_ = _verification_binding(operation,plan_sha256,charset,collation)
    _verification_not_revoking(state)
    return _verification_account_candidate(operation,plan_sha256,charset,collation,locked='N')


def _verification_account_candidate(operation, plan_sha256, charset, collation, *, locked):
    """Read-only exact three-account inventory, only after owned intent binding.

    A successful root candidate is not yet proof its credential logs in; the
    fixed Go coordinator must authenticate that private DSN before completion.
    """
    if locked not in ('N','Y'):
        fail('Invalid verification lock policy',code='TARGET_VERIFICATION_IDENTITY_REJECTED')
    state, policy, fixed = _verification_binding(operation, plan_sha256, charset, collation)
    intent, intent_sha = _verification_intent(state, fixed)
    _verify_restore_mysql(operation, charset, collation, restored=True, verification_user=policy['user'])
    actual = _query(state,
        "SELECT JSON_OBJECT('host',Host,'plugin',plugin,'locked',account_locked,'expired',password_expired,"
        "'attributes',User_attributes,'auth_sha256',SHA2(authentication_string,256),'uuid',@@server_uuid) "
        "FROM mysql.user WHERE BINARY User='" + policy['user'] + "';\n")
    if (set(actual) != {'host','plugin','locked','expired','attributes','auth_sha256','uuid'} or
            actual['host'] != 'localhost' or actual['plugin'] != 'caching_sha2_password' or
            actual['locked'] != locked or actual['expired'] != 'N' or
            actual['attributes'] != {'metadata': {'aster_cloud_verification': intent['nonce']}} or
            actual['uuid'] != fixed['server_uuid'] or not isinstance(actual['auth_sha256'], str) or
            not re.fullmatch('[a-f0-9]{64}', actual['auth_sha256'])):
        fail('Verification account identity changed', code='TARGET_VERIFICATION_IDENTITY_REJECTED')
    raw = read_private(str(state / 'verification-mysql-dsn'))
    # The Go credential check independently parses and authenticates it. Root
    # binds exact bytes, never logs the DSN or treats a path as successful login.
    prefix = (policy['user'] + ':').encode()
    suffix = ('@unix(' + MYSQL_SOCKET + ')/' + policy['database'] + '\n').encode()
    if not raw.startswith(prefix) or not raw.endswith(suffix) or not 16 <= len(raw)-len(prefix)-len(suffix) <= 1024:
        fail('Verification private credential binding changed', code='TARGET_VERIFICATION_CREDENTIAL_REJECTED')
    return {'schema': 1, 'operation_id': operation, 'plan_sha256': plan_sha256,
            'intent_sha256': intent_sha, 'auth_sha256': actual['auth_sha256'],
            'grants_sha256': _verification_grants(state, policy), 'credential_sha256': hashlib.sha256(raw).hexdigest()}


def prepare_verification_mysql(operation, plan_sha256, charset, collation):
    """Caller holds installation+target locks and has verified approved plan.

    Only the first clean invocation performs CREATE/GRANT. Existing or partial
    state is checked read-only; no reset, adoption, re-CREATE or grant repair.
    """
    state, policy, fixed = _verification_binding(operation, plan_sha256, charset, collation)
    _verification_not_revoking(state)
    intent_path = state / 'verification-started.json'
    if intent_path.exists() or intent_path.is_symlink():
        return verification_account_candidate(operation, plan_sha256, charset, collation)
    if any((state / name).exists() or (state / name).is_symlink() for name in ('verification-mysql-dsn','verification-account.json')):
        fail('Unbound verification state cannot be adopted', code='TARGET_VERIFICATION_BINDING_REJECTED')
    # The original strict two-account check refuses any pre-existing same-name
    # account (including a remote host variant) before intent/password creation.
    verify_restore_mysql(operation, charset, collation, restored=True)
    nonce = secrets.token_hex(32)
    _verification_write_new(intent_path, {**fixed, 'nonce': nonce})
    user = policy['user']
    raw = mysql_sql(state, "CREATE USER '" + user + "'@'localhost' IDENTIFIED WITH caching_sha2_password BY RANDOM PASSWORD ATTRIBUTE '{\"aster_cloud_verification\":\"" + nonce + "\"}';\n")
    try:
        values = raw.decode('utf-8').rstrip('\n').split('\t')
    except UnicodeError:
        fail('Verification CREATE outcome unconfirmed', code='TARGET_VERIFICATION_CREATE_UNCONFIRMED')
    if (len(values) not in (3,4) or len(values) == 4 and values[3] != '1' or
            values[:2] != [user,'localhost'] or not 16 <= len(values[2]) <= 1024 or
            any(c in values[2] for c in '\r\n\t\x00')):
        fail('Verification CREATE outcome unconfirmed', code='TARGET_VERIFICATION_CREATE_UNCONFIRMED')
    write_new(state / 'verification-mysql-dsn', (user + ':' + values[2] + '@unix(' + MYSQL_SOCKET + ')/' + policy['database'] + '\n').encode())
    del raw, values
    for statement in policy['grants']:
        mysql_sql(state, statement + ';\n')
    return verification_account_candidate(operation, plan_sha256, charset, collation)


def complete_verification_mysql(operation, plan_sha256, charset, collation, *, readonly=False):
    """Called after Go authenticated the credential and applicable full data phase."""
    value = verification_account_candidate(operation, plan_sha256, charset, collation)
    path = Path('/var/lib/aster-controller-restore') / operation / 'database/verification-account.json'
    if path.exists() or path.is_symlink():
        expected = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
        if read_private(str(path)) != expected:
            fail('Verification account receipt drifted', code='TARGET_VERIFICATION_BINDING_REJECTED')
    elif readonly:
        fail('Verification account has no completion proof', code='TARGET_VERIFICATION_ACCOUNT_UNCONFIRMED')
    else:
        _verification_write_new(path, value)
    return value

def _verification_not_revoking(state):
    if any((state/name).exists() or (state/name).is_symlink() for name in
           ('verification-revoke-started.json','verification-revoked.json')):
        fail('Verification revocation already started', code='TARGET_VERIFICATION_REVOCATION_STARTED')


def _verification_saved_completion(state, operation, plan_sha256):
    raw = read_private(str(state/'verification-account.json'))
    value = _json(raw)
    digests = {'plan_sha256','intent_sha256','auth_sha256','grants_sha256','credential_sha256'}
    if (set(value) != {'schema','operation_id'} | digests or type(value['schema']) is not int or value['schema'] != 1 or
            value['operation_id'] != operation or value['plan_sha256'] != plan_sha256 or
            any(not isinstance(value[k],str) or not re.fullmatch('[a-f0-9]{64}',value[k]) for k in digests) or
            raw != (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()):
        fail('Original account completion changed',code='TARGET_VERIFICATION_BINDING_REJECTED')
    return value,hashlib.sha256(raw).hexdigest()


def verification_revocation_plan(operation, plan_sha256, charset, collation):
    state,policy,_ = _verification_binding(operation,plan_sha256,charset,collation)
    account,account_sha = _verification_saved_completion(state,operation,plan_sha256)
    value = {'schema':1,'protocol':'aster.controller-verification-revocation/1','operation_id':operation,
             'verification_plan_sha256':plan_sha256,'account_receipt_sha256':account_sha,
             'database':policy['database'],'user':policy['user']}
    raw = (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
    started,completed = state/'verification-revoke-started.json',state/'verification-revoked.json'
    locked = 'N'
    if started.exists() or started.is_symlink():
        if read_private(str(started)) != raw:
            fail('Revocation intent changed',code='TARGET_VERIFICATION_REVOCATION_BINDING_REJECTED')
        actual = _query(state,"SELECT JSON_OBJECT('locked',account_locked) FROM mysql.user WHERE BINARY User='"+policy['user']+"' AND BINARY Host='localhost';\n")
        if set(actual) != {'locked'} or actual['locked'] not in ('N','Y'):
            fail('Revocation lock state unknown',code='TARGET_VERIFICATION_REVOCATION_UNCONFIRMED')
        locked = actual['locked']
        if (completed.exists() or completed.is_symlink()) and locked != 'Y':
            fail('Completed revocation was changed',code='TARGET_VERIFICATION_REVOCATION_BINDING_REJECTED')
    elif completed.exists() or completed.is_symlink():
        fail('Revocation has no original intent',code='TARGET_VERIFICATION_REVOCATION_BINDING_REJECTED')
    if _verification_account_candidate(operation,plan_sha256,charset,collation,locked=locked) != account:
        fail('Revocation account differs from completion',code='TARGET_VERIFICATION_BINDING_REJECTED')
    return {'plan':value,'plan_sha256':hashlib.sha256(raw).hexdigest(),'account_locked':locked=='Y'}


def verification_connection_inventory_sql(user):
    if not isinstance(user,str) or not re.fullmatch('aster_v_[a-f0-9]{23}',user):
        fail('Unexpected SQL identity',code='TARGET_VERIFICATION_IDENTITY_REJECTED')
    # MySQL 8.0's documented GTID compressor is FOREGROUND with a process ID
    # but is not a client. Exclude only its complete fixed internal shape;
    # unknown/partially matching rows still block drain. COALESCE is essential:
    # a NULL command/name must not disappear through SQL three-valued logic.
    # https://dev.mysql.com/doc/refman/8.0/en/replication-gtids-concepts.html
    internal_gtid = ("COALESCE((BINARY NAME='thread/sql/compress_gtid_table' AND "
                     "PROCESSLIST_USER IS NULL AND PROCESSLIST_HOST IS NULL AND PROCESSLIST_DB IS NULL AND "
                     "BINARY PROCESSLIST_COMMAND='Daemon' AND CONNECTION_TYPE IS NULL),FALSE)")
    # A root username alone does not prove PROCESS visibility. This actual
    # performance_schema table exposes all rows to any SELECT-capable reader;
    # require enabled collection, zero lost instances and a positive observer.
    return (
        "SELECT JSON_OBJECT('enabled',@@performance_schema,"
        "'observer',(SELECT COUNT(*) FROM performance_schema.threads WHERE PROCESSLIST_ID=CONNECTION_ID() AND BINARY PROCESSLIST_USER='root'),"
        "'lost',(SELECT CAST(VARIABLE_VALUE AS UNSIGNED) FROM performance_schema.global_status WHERE VARIABLE_NAME='Performance_schema_thread_instances_lost'),"
        "'active',(SELECT COUNT(*) FROM performance_schema.threads WHERE TYPE='FOREGROUND' AND BINARY PROCESSLIST_USER='"+user+"'),"
        "'internal_gtid',(SELECT COUNT(*) FROM performance_schema.threads WHERE TYPE='FOREGROUND' AND PROCESSLIST_ID IS NOT NULL AND "+internal_gtid+"),"
        "'pending',(SELECT COUNT(*) FROM performance_schema.threads WHERE TYPE='FOREGROUND' AND PROCESSLIST_ID IS NOT NULL AND "
        "(PROCESSLIST_USER IS NULL OR BINARY PROCESSLIST_USER='unauthenticated user') AND NOT "+internal_gtid+"));\n")


def verification_connection_inventory(state, user):
    info = _query(state, verification_connection_inventory_sql(user))
    if (set(info) != {'enabled','observer','lost','active','pending','internal_gtid'} or info['enabled'] != 1 or
            info['observer'] != 1 or info['lost'] != 0 or
            any(type(info[k]) is not int or info[k]<0 for k in ('observer','lost','active','pending','internal_gtid')) or
            info['internal_gtid'] > 1):
        fail('Complete SQL connection visibility unavailable',code='TARGET_VERIFICATION_CONNECTION_INVENTORY_UNCONFIRMED')
    return info


def revoke_verification_mysql(operation, plan_sha256, charset, collation, *, readonly=False):
    """Only an exact completed identity can be locked. Never KILL/DROP/UNLOCK.

    ACCOUNT LOCK prevents new authentication but does not terminate existing
    sessions. A live or unobservable session leaves revocation incomplete.
    Explicit same-operation reentry can confirm an applied lock/lost receipt;
    completed lock drift is refused instead of silently repaired.
    """
    state,policy,_ = _verification_binding(operation,plan_sha256,charset,collation)
    report = verification_revocation_plan(operation,plan_sha256,charset,collation)
    started,completed = state/'verification-revoke-started.json',state/'verification-revoked.json'
    exists = started.exists() or started.is_symlink()
    if not exists:
        if readonly:
            fail('Revocation not started',code='TARGET_VERIFICATION_REVOCATION_NOT_STARTED')
        verification_connection_inventory(state,policy['user'])  # visibility before any effect
        _verification_write_new(started,report['plan'])
    if not report['account_locked']:
        if readonly:
            fail('Revocation not confirmed',code='TARGET_VERIFICATION_REVOCATION_UNCONFIRMED')
        mysql_sql(state,"ALTER USER '"+policy['user']+"'@'localhost' ACCOUNT LOCK;\n")
    after = verification_revocation_plan(operation,plan_sha256,charset,collation)
    if after['plan_sha256'] != report['plan_sha256'] or after['account_locked'] is not True:
        fail('Revocation lock not confirmed',code='TARGET_VERIFICATION_REVOCATION_UNCONFIRMED')
    connections = verification_connection_inventory(state,policy['user'])
    if connections['active'] or connections['pending']:
        fail('Existing or authenticating sessions remain',code='TARGET_VERIFICATION_SESSIONS_ACTIVE')
    value = {'schema':1,'operation_id':operation,'revocation_intent_sha256':report['plan_sha256'],
             'account_receipt_sha256':report['plan']['account_receipt_sha256'],
             'account_locked':True,'active_connections':0,'pending_authentication':0}
    raw = (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
    if completed.exists() or completed.is_symlink():
        if read_private(str(completed)) != raw:
            fail('Revocation completion changed',code='TARGET_VERIFICATION_REVOCATION_BINDING_REJECTED')
    elif readonly:
        fail('Revocation has no completion receipt',code='TARGET_VERIFICATION_REVOCATION_UNCONFIRMED')
    else:
        _verification_write_new(completed,value)
    return value

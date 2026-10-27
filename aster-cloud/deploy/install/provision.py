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


def fail(message):
    raise ProvisionError(message)


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
                fail("APT plan would upgrade/remove existing software or install unapproved network daemons")
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
            mysql_sql(state_dir, "CREATE DATABASE `" + database + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\n"
                "CREATE TABLE `" + database + "`.aster_installer_ownership (id INT PRIMARY KEY,nonce CHAR(64) NOT NULL,server_uuid CHAR(36) NOT NULL);\n"
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

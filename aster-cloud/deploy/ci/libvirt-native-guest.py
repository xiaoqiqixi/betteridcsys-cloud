#!/usr/bin/env python3
"""Runs only inside the owned NoCloud TCG VM, never on its host runner."""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ROOT = Path("/root/aster-native")
DOCTOR_PROTOCOL = "aster.node/1"
PHASE = "preflight"
FAILED_COMMANDS = []
PROGRESS_NONCE = None
APT_PLAN_DIAGNOSTICS = None
APT_CODES = set("APT_DNS_FAILURE APT_TLS_FAILURE APT_SIGNATURE_FAILURE APT_METADATA_FAILURE APT_PACKAGE_UNAVAILABLE APT_DEPENDENCY_CONFLICT APT_LOCKED APT_COMMAND_REJECTED APT_COMMAND_UNAVAILABLE APT_COMMAND_TIMEOUT APT_OUTPUT_OVERSIZED".split())
APT_PLAN_CATEGORIES = {"remove", "installed-package-version-change", "unapproved-network-daemon"}
# Fixed public inventory: unknown package tokens are counted, never exported.
APT_PLAN_PACKAGES = set("""
ca-certificates openssl libc6 libc-bin libgcc-s1 libstdc++6 libssl3 libssl3t64
systemd systemd-sysv systemd-resolved libsystemd0 libsystemd-shared libudev1 udev libnss-systemd libpam-systemd
libpam0g libpam-modules libpam-modules-bin libpam-runtime libcap2 libcap2-bin libcap-ng0
libglib2.0-0 libglib2.0-0t64 libglib2.0-bin libglib2.0-data libgcrypt20 libgpg-error0
libgnutls30 libgnutls30t64 libgnutls-dane0t64 libp11-kit0 libtasn1-6 libhogweed6 libhogweed6t64 libnettle8 libnettle8t64
libxml2 libxml2-16 libxslt1.1 libselinux1 libapparmor1 libseccomp2 libaudit1 libaudit-common libacl1 libattr1
zlib1g libzstd1 liblzma5 liblz4-1 libbz2-1.0 libpcre2-8-0 libffi8 libuuid1 libblkid1 libmount1
python3 python3-minimal python3-apt python3.10 python3.10-minimal libpython3.10-minimal libpython3.10-stdlib
python3.12 python3.12-minimal libpython3.12-minimal libpython3.12-stdlib
python3.14 python3.14-minimal libpython3.14-minimal libpython3.14-stdlib
libvirt0 libvirt-clients libvirt-daemon libvirt-daemon-system libvirt-daemon-system-systemd
libvirt-daemon-common libvirt-daemon-log libvirt-daemon-lock libvirt-daemon-driver-qemu libvirt-daemon-config-network
qemu-system-x86 qemu-system-common qemu-system-data qemu-utils qemu-block-extra qemu-system-gui seabios ovmf
libaio1 libaio1t64 liburing2 libnuma1 libfdt1 libslirp0 libpixman-1-0 libepoxy0 libdrm2 libdrm-common
libcurl4 libcurl4t64 libssh-4 libssh2-1 libssh2-1t64 libyajl2 libtirpc3 libtirpc3t64 libnl-3-200 libnl-route-3-200
libnftnl11 libnftables1 libmnl0 libxtables12 iptables nftables dnsmasq-base iproute2
firewalld ufw openvswitch-common openvswitch-switch openvswitch-switch-dpdk
""".split())
PROVISION_CODES = {
    "APT plan would upgrade/remove": "APT_PLAN_UNSAFE",
    "Fixed native provisioning command unavailable": "NATIVE_COMMAND_UNAVAILABLE",
    "Fixed native provisioning command rejected": "NATIVE_COMMAND_REJECTED",
    "Host interface evidence changed": "INTERFACE_PROOF_CHANGED",
    "Firewall evidence changed": "FIREWALL_PROOF_CHANGED",
    "Libvirt network directory is not isolated": "LIBVIRT_MOUNT_INODE_MISMATCH",
    "Libvirt network mount is not read-only": "LIBVIRT_MOUNT_NOT_READONLY",
    "Owned libvirt process identity differs": "LIBVIRT_PROCESS_IDENTITY_MISMATCH",
    "Foreign effective libvirt unit override": "LIBVIRT_FOREIGN_EFFECTIVE_UNIT",
    "Root-protected libvirt UNIX socket required": "LIBVIRT_UNIX_SOCKET_REJECTED",
    "Fresh owned libvirt must expose no domains or networks": "LIBVIRT_UNEXPECTED_RESOURCES",
    "Libvirt did not report actual system QEMU capabilities": "LIBVIRT_CAPABILITIES_REJECTED",
}
UNITS = tuple("aster-cloud-" + name + ".service" for name in ("libvirtd", "virtlogd", "virtlockd"))
VENDOR = tuple(sorted({"libvirt-guests.service", "virt-guest-shutdown.target"} | {
    daemon + suffix for daemon in ("libvirtd", "virtlogd", "virtlockd", "virtproxyd", "virtqemud",
        "virtnetworkd", "virtnodedevd", "virtnwfilterd", "virtsecretd", "virtstoraged", "virtinterfaced")
    for suffix in (".service", ".socket", "-ro.socket", "-admin.socket", "-tcp.socket", "-tls.socket")}))
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root/aster-native", "LANG": "C.UTF-8"}


class Refused(Exception):
    pass


def require(condition, code):
    if not condition:
        raise Refused(code)


def run(argv, *, timeout=60, check=True):
    p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV, timeout=timeout, check=False)
    require(len(p.stdout) <= 1024 * 1024 and len(p.stderr) <= 1024 * 1024, "GUEST_COMMAND_OUTPUT_BOUND")
    if check:
        require(p.returncode == 0, "GUEST_FIXED_COMMAND_FAILED")
    return p


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def progress(stage):
    """Fixed diagnostic checkpoints only; never a success/acceptance signal."""
    if PROGRESS_NONCE is None:
        return
    allowed = {"preflight", "prepare", "inspect", "resume", "image-and-config", "doctor"}
    commands = {"apt-update", "apt-simulate", "apt-install", "network-rules-readonly", "other-fixed-command"}
    commands |= {"systemd-" + name for name in ("start", "stop", "enable", "disable", "daemon-reload", "show", "is-active")}
    commands |= {"virsh-" + name for name in ("net-list", "list", "capabilities")}
    allowed |= {name + ":" + outcome for name in commands for outcome in ("start", "done", "failed")}
    if stage not in allowed or not re.fullmatch(r"[0-9a-f]{32}", PROGRESS_NONCE):
        return
    try:
        with open("/dev/ttyS0", "w") as console:
            console.write("ASTER_LIBVIRT_NATIVE_PROGRESS_" + PROGRESS_NONCE + " " + stage + "\n")
            console.flush()
    except OSError:
        pass  # Diagnostic delivery must not alter a real command's outcome.


def command_code(argv):
    """Classify fixed native commands without persisting any argument data."""
    if not isinstance(argv, list) or not argv:
        return "other-fixed-command"
    if argv[0] == "/usr/bin/apt-get":
        if "--simulate" in argv: return "apt-simulate"
        if "--assume-yes" in argv: return "apt-install"
        if argv[1:] == ["update"]: return "apt-update"
    if argv[0] == "/usr/bin/systemctl":
        for value in ("start", "stop", "enable", "disable", "daemon-reload", "show", "is-active"):
            if value in argv: return "systemd-" + value
    if argv[0] == "/usr/bin/virsh":
        for value in ("net-list", "list", "capabilities"):
            if value in argv: return "virsh-" + value
    if argv[0] in ("/usr/sbin/nft", "/usr/sbin/iptables-save", "/usr/sbin/ip6tables-save"):
        return "network-rules-readonly"
    return "other-fixed-command"


def classify_apt_plan(raw):
    """Inspect only real bounded simulation bytes; never return raw tokens/versions."""
    if not isinstance(raw, bytes) or len(raw) > 1024 * 1024:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    categories, packages, unknown = set(), set(), set()
    for line in text.splitlines():
        reasons = set()
        if line.startswith("Remv "):
            reasons.add("remove")
        if re.match(r"^Inst \S+ \[", line):
            reasons.add("installed-package-version-change")
        if re.match(r"^Inst (?:firewalld|ufw|openvswitch\S*)\b", line):
            reasons.add("unapproved-network-daemon")
        if not reasons:
            continue
        categories.update(reasons)
        token = line.split(maxsplit=2)[1] if len(line.split(maxsplit=2)) > 1 else ""
        name = token.split(":", 1)[0]
        if re.fullmatch(r"[a-z0-9][a-z0-9+.-]{0,63}(?::(?:amd64|all))?", token) and name in APT_PLAN_PACKAGES:
            packages.add(name)
        else:
            unknown.add(token)
    return {"categories": sorted(categories), "packages": sorted(packages)[:12],
            "unknown_package_count": min(len(unknown), 255), "truncated": len(packages) > 12 or len(unknown) > 255}


def observe_real_commands(module):
    """Observability only: exact real calls/results/exceptions are preserved."""
    real = module.run_fixed
    def observed(argv, **kwargs):
        global APT_PLAN_DIAGNOSTICS
        code = command_code(argv)
        progress(code + ":start")
        try:
            result = real(argv, **kwargs)
            if code == "apt-simulate":
                try:
                    APT_PLAN_DIAGNOSTICS = classify_apt_plan(result)
                except Exception:
                    APT_PLAN_DIAGNOSTICS = None  # Diagnostics cannot change production execution.
            progress(code + ":done")
            return result
        except Exception:
            progress(code + ":failed")
            if code not in FAILED_COMMANDS and len(FAILED_COMMANDS) < 4:
                FAILED_COMMANDS.append(code)
            raise
    module.run_fixed = observed


def safe_diagnostics():
    output = {"failed_commands": list(FAILED_COMMANDS)}
    if APT_PLAN_DIAGNOSTICS is not None:
        output["apt_plan_rejections"] = APT_PLAN_DIAGNOSTICS
    statuses = {"preparing", "package-transaction-pending", "dependencies-installed", "failed-package-transaction-review-required",
                "own-service-start-attempted", "own-service-enable-attempted", "libvirt-prepared", "failed-review-required"}
    steps = {"policy-created", "packages-installed", "existing-daemon-readonly-verified"}
    for name, prefix in (("dependencies.json", "dependencies"), ("libvirt.json", "libvirt")):
        path = Path("/var/lib/aster-cloud-installer/native-ci") / name
        try:
            info = path.lstat()
            if not (stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and not info.st_mode & 0o077 and info.st_size <= 131072):
                continue
            receipt = json.loads(path.read_bytes())
            output[prefix + "_status"] = receipt.get("status") if receipt.get("status") in statuses else "unrecognized"
            output[prefix + "_steps"] = [v for v in receipt.get("steps", []) if isinstance(v, str) and v in steps][:4]
        except Exception:
            continue
    return output


def private(path, contents, mode=0o600):
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as stream:
        os.fchmod(stream.fileno(), mode); stream.write(contents)


def doctor_evidence(code, report):
    require(code != 0 and isinstance(report, dict) and report.get("ready") is False, "DOCTOR_DID_NOT_DENY_KVM")
    require(report.get("protocol") == DOCTOR_PROTOCOL and report.get("node_id") == "native-tcg-node", "DOCTOR_CONFIG_NOT_ACCEPTED")
    entries = report.get("checks", [])
    require(isinstance(entries, list) and all(set(v) == {"name", "passed"} and type(v["passed"]) is bool for v in entries), "DOCTOR_CHECK_SCHEMA_REJECTED")
    checks = {v["name"]: v["passed"] for v in entries}
    require(len(checks) == len(entries), "DOCTOR_DUPLICATE_CHECK_REJECTED")
    expected = {"ubuntu_at_least_22", "x86_64_host", "hardware_virtualization_flags", "dev_kvm_read_write",
                "binary:/usr/bin/virsh", "binary:/usr/bin/qemu-img", "binary:/usr/bin/qemu-system-x86_64",
                "storage_directory", "libvirt_system_readonly_query"}
    require(set(checks) == expected, "DOCTOR_CHECK_INVENTORY_REJECTED")
    require(checks["dev_kvm_read_write"] is False, "DOCTOR_MISSING_EXPLICIT_KVM_DENIAL")
    allowed_failure = {"dev_kvm_read_write", "hardware_virtualization_flags"}
    require(all(passed for name, passed in checks.items() if name not in allowed_failure), "DOCTOR_OTHER_PREREQUISITE_FAILED")
    return checks


def image_and_config(metadata):
    source = Path("/dev/vdb")
    require(stat.S_ISBLK(source.stat().st_mode), "APPROVED_IMAGE_BLOCK_DEVICE_REQUIRED")
    require(run(["/usr/sbin/blockdev", "--getro", str(source)]).stdout.strip() == b"1", "APPROVED_IMAGE_MUST_BE_READONLY")
    directories = ("/etc/aster-node", "/var/lib/aster-images", "/var/lib/aster-node", "/var/lib/aster-instances")
    for name in directories:
        p = Path(name); require(not p.exists(), "NODE_FIXTURE_PATH_ALREADY_EXISTS"); p.mkdir(mode=0o700, parents=True)
    image = Path("/var/lib/aster-images/ubuntu-signed-base.qcow2")
    remaining = metadata["image_bytes"]
    require(type(remaining) is int and 0 < remaining <= 2 * 1024 ** 3, "APPROVED_IMAGE_SIZE_REJECTED")
    with source.open("rb", buffering=0) as inp, image.open("xb") as out:
        while remaining:
            block = inp.read(min(1024 * 1024, remaining)); require(block, "APPROVED_IMAGE_TRUNCATED")
            out.write(block); remaining -= len(block)
    image.chmod(0o600)
    require(sha(image) == metadata["image_sha256"], "APPROVED_IMAGE_HASH_MISMATCH")
    info = json.loads(run(["/usr/bin/qemu-img", "info", "--output=json", str(image)]).stdout)
    require(info.get("format") == "qcow2" and not info.get("backing-filename") and not info.get("encrypted"), "APPROVED_IMAGE_FORMAT_REJECTED")
    # Real, isolated fixture PKI: no production node/controller identities enter
    # the VM, and neither keys nor passwords are included in public results.
    ca, cakey = ROOT / "ca.pem", ROOT / "ca.key"
    run(["/usr/bin/openssl", "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "2", "-subj", "/CN=Aster disposable native CI CA", "-keyout", str(cakey), "-out", str(ca)])
    for role, purpose in (("node", "serverAuth"), ("controller", "clientAuth")):
        key, csr, cert, ext = (ROOT / (role + suffix) for suffix in (".key", ".csr", ".pem", ".ext"))
        private(ext, ("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=" + purpose + "\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n").encode())
        run(["/usr/bin/openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256", "-subj", "/CN=localhost", "-keyout", str(key), "-out", str(csr)])
        run(["/usr/bin/openssl", "x509", "-req", "-sha256", "-days", "2", "-in", str(csr), "-CA", str(ca), "-CAkey", str(cakey), "-CAcreateserial", "-extfile", str(ext), "-out", str(cert)])
        key.chmod(0o600); cert.chmod(0o600)
        run(["/usr/bin/openssl", "verify", "-CAfile", str(ca), str(cert)])
    pin = hashlib.sha256(run(["/usr/bin/openssl", "x509", "-in", str(ROOT / "controller.pem"), "-outform", "DER"]).stdout).hexdigest()
    config = {"node_id": "native-tcg-node", "datacenter_id": "native-ci", "node_group_id": "native-ci", "listen": "127.0.0.1:9444",
              "certificate": str(ROOT / "node.pem"), "private_key": str(ROOT / "node.key"), "controller_ca": str(ca),
              "expected_controller_certificate_sha256": pin, "state_directory": "/var/lib/aster-node", "storage_directory": "/var/lib/aster-instances",
              "storage_id": "local", "images": {"signed-ubuntu": {"path": str(image), "sha256": metadata["image_sha256"]}},
              "cpu_allocation_limit": 1, "memory_allocation_limit_mib": 512, "disk_allocation_limit_gib": 4,
              "allow_isolated_no_nic": False, "allow_unmetered_default": True, "allow_delete": False, "maintenance": True,
              "network": {"enabled": False}, "storage": {"enabled": False}}
    path = Path("/etc/aster-node/node.json"); private(path, json.dumps(config).encode())
    return path


def inspect_libvirt():
    for unit in UNITS:
        require(run(["/usr/bin/systemctl", "is-active", unit]).stdout.strip() == b"active", "OWNED_UNIT_NOT_ACTIVE")
    for unit in VENDOR:
        require(run(["/usr/bin/systemctl", "is-enabled", unit], check=False).stdout.strip() == b"masked", "VENDOR_UNIT_NOT_PERSISTENTLY_MASKED")
        mask = Path("/etc/systemd/system") / unit
        require(mask.is_symlink() and os.readlink(mask) == "/dev/null", "VENDOR_MASK_NOT_PERSISTENT")
    require(run(["/usr/bin/virsh", "--connect", "qemu:///system", "list", "--all", "--name"]).stdout.strip() == b"", "UNEXPECTED_DOMAIN")
    require(run(["/usr/bin/virsh", "--connect", "qemu:///system", "net-list", "--all", "--name"]).stdout.strip() == b"", "DEFAULT_NETWORK_VISIBLE")
    caps = run(["/usr/bin/virsh", "--connect", "qemu:///system", "capabilities"]).stdout
    require(b"<capabilities>" in caps and b"<arch>x86_64</arch>" in caps, "REAL_LIBVIRT_CAPABILITIES_REQUIRED")
    require(not any(p.name.startswith("virbr") for p in Path("/sys/class/net").iterdir()), "LIBVIRT_BRIDGE_CREATED")
    pid = run(["/usr/bin/systemctl", "show", "--property=MainPID", "--value", UNITS[0]]).stdout.decode().strip()
    require(re.fullmatch(r"[1-9][0-9]*", pid) is not None, "OWNED_DAEMON_PID_REQUIRED")
    empty = Path("/var/lib/aster-cloud-installer/libvirt-empty-networks")
    mounted = Path("/proc") / pid / "root/etc/libvirt/qemu/networks"
    require((mounted.stat().st_dev, mounted.stat().st_ino) == (empty.stat().st_dev, empty.stat().st_ino), "EMPTY_NETWORK_MOUNT_NOT_EFFECTIVE")
    require(not list(mounted.rglob("*.xml")), "MOUNTED_DEFAULT_NETWORK_XML_VISIBLE")
    entries = (Path("/proc") / pid / "mountinfo").read_text().splitlines()
    require(any(" /etc/libvirt/qemu/networks " in line and "ro" in line.split()[5].split(",") for line in entries), "EMPTY_NETWORK_MOUNT_NOT_READONLY")
    socket_inodes = set()
    for fd in (Path("/proc") / pid / "fd").iterdir():
        try:
            match = re.fullmatch(r"socket:\[([0-9]+)\]", os.readlink(fd))
        except FileNotFoundError:
            continue
        if match:
            socket_inodes.add(match[1])
    for version in ("tcp", "tcp6"):
        for line in (Path("/proc") / pid / "net" / version).read_text().splitlines()[1:]:
            fields = line.split()
            require(not (len(fields) > 9 and fields[3] == "0A" and fields[9] in socket_inodes), "OWNED_LIBVIRT_TCP_LISTENER_FOUND")
    return {"owned_units_active": True, "vendor_masks_persistent": True, "empty_network_mount_verified": True,
            "unix_libvirt_query_passed": True, "default_network_absent": True, "virbr_absent": True,
            "libvirt_no_tcp_listener": True}


def execute(metadata):
    global PHASE
    PHASE = "preflight"
    progress(PHASE)
    require(os.geteuid() == 0 and (Path("/proc/1/comm").read_text().strip() == "systemd"), "REAL_GUEST_SYSTEMD_ROOT_REQUIRED")
    require(Path("/sys/class/dmi/id/product_name").read_text().strip() in ("Standard PC (i440FX + PIIX, 1996)", "Standard PC (Q35 + ICH9, 2009)"), "OWNED_QEMU_GUEST_REQUIRED")
    release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
    require(release.get("ID", "").strip('"') == "ubuntu" and release.get("VERSION_ID", "").strip('"') == metadata["ubuntu"], "GUEST_UBUNTU_MISMATCH")
    require(not Path("/dev/kvm").exists(), "TCG_GUEST_UNEXPECTED_KVM")
    require(sha(ROOT / "aster-node") == metadata["node_binary_sha256"], "REAL_NODE_BINARY_HASH_MISMATCH")
    for path in ("/var/lib/mysql", "/var/lib/mariadb", "/var/lib/postgresql", "/etc/libvirt", "/var/lib/libvirt"):
        require(not Path(path).exists(), "OFFICIAL_GUEST_NOT_FRESH_NO_PURGE_ALLOWED")
    spec = importlib.util.spec_from_file_location("native_libvirt_provision", ROOT / "provision.py")
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module; spec.loader.exec_module(module)
    observe_real_commands(module)
    state = Path("/var/lib/aster-cloud-installer/native-ci"); state.mkdir(mode=0o700, parents=True)
    PHASE = "prepare"
    progress(PHASE)
    result = module.prepare_libvirt(state)
    require(result.get("status") == "libvirt-prepared" and result.get("daemon") == "owned-unix-only" and result.get("kvm") == "not-asserted", "REAL_PREPARE_RECEIPT_REJECTED")
    receipt = Path(result["receipt"]); info = receipt.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and not info.st_mode & 0o077, "PRIVATE_PREPARE_RECEIPT_REQUIRED")
    require(run(["/usr/bin/dpkg-query", "-W", "-f=${db:Status-Status}", "libvirt-daemon-system"]).stdout == b"installed", "REAL_APT_PACKAGE_NOT_INSTALLED")
    PHASE = "inspect"
    progress(PHASE)
    proof = inspect_libvirt()
    vendor_xml = Path("/etc/libvirt/qemu/networks/default.xml")
    require(vendor_xml.is_file() and not vendor_xml.is_symlink(), "VENDOR_DEFAULT_XML_NOT_RETAINED")
    vendor_before_resume = sha(vendor_xml)
    # Revalidation uses the original production resume API, not substituted
    # system calls, fake receipts, a bypass flag or fabricated /dev/kvm.
    PHASE = "resume"
    progress(PHASE)
    again = module.prepare_libvirt(state, resume=True)
    require(again.get("status") == "libvirt-prepared", "PREPARE_RESUME_FAILED")
    require(inspect_libvirt() == proof, "PREPARE_RESUME_CHANGED_PROOF")
    require(sha(vendor_xml) == vendor_before_resume, "VENDOR_DEFAULT_XML_CHANGED_ON_RESUME")
    PHASE = "image-and-config"
    progress(PHASE)
    config = image_and_config(metadata)
    PHASE = "doctor"
    progress(PHASE)
    doctor = run([str(ROOT / "aster-node"), "--config", str(config), "--doctor"], check=False)
    try:
        report = json.loads(doctor.stdout)
    except (ValueError, UnicodeError):
        raise Refused("DOCTOR_CONFIG_NOT_ACCEPTED")
    checks = doctor_evidence(doctor.returncode, report)
    return {"schema": 1, "passed": True, "real_apt": True, "real_systemd": True, "libvirt_prepared": True,
            "kvm_ready": False, "explicit_kvm_denial": True, "non_kvm_doctor_checks_passed": True,
            "source_sha": metadata["source_sha"], "ubuntu": metadata["ubuntu"], "image_sha256": metadata["image_sha256"],
            "real_approved_image_validated": True, "vendor_default_xml_retained_unchanged_on_resume": True,
            "doctor_protocol": report["protocol"], "doctor_checks": checks, **proof}


def provision_error_code(error):
    if error.__class__.__name__ != "ProvisionError":
        return "NATIVE_GUEST_REFUSED_DETAILS_WITHHELD"
    apt_code = getattr(error, "code", None)
    if isinstance(apt_code, str) and apt_code in APT_CODES:
        return apt_code
    return next((value for prefix, value in PROVISION_CODES.items() if str(error).startswith(prefix)), "PROVISION_PREPARE_REFUSED")


def main():
    global PROGRESS_NONCE
    metadata = json.loads((ROOT / "metadata.json").read_text())
    PROGRESS_NONCE = metadata.get("nonce")
    try:
        report = execute(metadata)
    except Refused as error:
        report = {"schema": 1, "passed": False, "code": str(error), "ubuntu": metadata["ubuntu"],
                  "source_sha": metadata["source_sha"], "image_sha256": metadata["image_sha256"], "kvm_ready": False, "phase": PHASE,
                  "diagnostics": safe_diagnostics()}
    except Exception as error:
        code = provision_error_code(error)
        report = {"schema": 1, "passed": False, "code": code, "ubuntu": metadata["ubuntu"],
                  "source_sha": metadata["source_sha"], "image_sha256": metadata["image_sha256"], "kvm_ready": False, "phase": PHASE,
                  "diagnostics": safe_diagnostics()}
    line = "ASTER_LIBVIRT_NATIVE_RESULT_" + metadata["nonce"] + " " + base64.b64encode(json.dumps(report, sort_keys=True).encode()).decode() + "\n"
    # Direct serial writes avoid cloud-init's varying stdout prefix/truncation.
    with open("/dev/ttyS0", "w") as console:
        console.write(line); console.flush()
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())

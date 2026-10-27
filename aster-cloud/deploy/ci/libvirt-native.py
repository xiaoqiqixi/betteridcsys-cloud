#!/usr/bin/env python3
"""Owned TCG-only Ubuntu VM acceptance. Never installs software on the host.

Only three fixed-schema JSON files are public outputs. Serial logs, seed data,
build files and disposable disks stay in private scratch and are removed.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import selectors
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
KEY_FINGERPRINT = "D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81"
KEY_SHA256 = "690a3d2de5af22d572c204677f2e3e785870fc53d5512abd2a90bf58b55142e2"
IMAGES = {
    "22.04": ("jammy", "20261020", "2099e63da0b822ef8e05e3d596c1b402eaaae658fc08ab919cb8495bfcdc488b"),
    "24.04": ("noble", "20261017", "04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94"),
}
APT_DESTINATIONS = ("archive.ubuntu.com", "security.ubuntu.com")
HOSTS_BOOT_COMMAND = r"printf '%s\n' '' '10.0.2.100 archive.ubuntu.com' '10.0.2.101 security.ubuntu.com' >> /etc/hosts"
TOOLS = ("/usr/bin/qemu-system-x86_64", "/usr/bin/qemu-img", "/usr/bin/cloud-localds", "/usr/bin/gpg", "/usr/bin/gpgv")
MAX_SERIAL = 16 * 1024 * 1024
MAX_IMAGE = 2 * 1024 * 1024 * 1024
SAFE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}
OUTPUT_CREATED = None
VM_PROGRESS = []
HOST_PROOF = {}
HOST_PRE_VM_PROOF = {}
GUEST_RESULT_SEEN = False
RELAY_PROOF = {}
SANDBOX_PROOF = {}
RELAY_EVENTS = {"spawned", "dns-ok", "dns-failed", "dns-nonpublic", "connect-ok", "connect-failed", "guest-first-bytes", "server-first-bytes", "guest-eof", "server-eof", "timeout", "io-failed"}
BOOT_STAGES = {"bootcmd", "boot-mask:start", "boot-mask:done", "boot-hosts:start", "boot-hosts:done", "runcmd-enter"}
GUEST_PHASES = {"preflight", "prepare", "inspect", "resume", "image-and-config", "doctor"}
DIAGNOSTIC_COMMANDS = {"apt-update", "apt-simulate", "apt-install", "network-rules-readonly", "other-fixed-command"} | {
    "systemd-" + name for name in ("start", "stop", "enable", "disable", "daemon-reload", "show", "is-active")} | {
    "virsh-" + name for name in ("net-list", "list", "capabilities")}
DIAGNOSTIC_STATUSES = {"preparing", "package-transaction-pending", "dependencies-installed", "failed-package-transaction-review-required",
                       "own-service-start-attempted", "own-service-enable-attempted", "libvirt-prepared", "failed-review-required", "unrecognized"}
DIAGNOSTIC_STEPS = {"policy-created", "packages-installed", "existing-daemon-readonly-verified"}
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
GUEST_ERROR_CODES = set("""
APPROVED_IMAGE_BLOCK_DEVICE_REQUIRED APPROVED_IMAGE_FORMAT_REJECTED APPROVED_IMAGE_HASH_MISMATCH APPROVED_IMAGE_MUST_BE_READONLY
APPROVED_IMAGE_SIZE_REJECTED APPROVED_IMAGE_TRUNCATED DEFAULT_NETWORK_VISIBLE DOCTOR_CHECK_INVENTORY_REJECTED DOCTOR_CHECK_SCHEMA_REJECTED
DOCTOR_CONFIG_NOT_ACCEPTED DOCTOR_DID_NOT_DENY_KVM DOCTOR_DUPLICATE_CHECK_REJECTED DOCTOR_MISSING_EXPLICIT_KVM_DENIAL
DOCTOR_OTHER_PREREQUISITE_FAILED EMPTY_NETWORK_MOUNT_NOT_EFFECTIVE EMPTY_NETWORK_MOUNT_NOT_READONLY GUEST_COMMAND_OUTPUT_BOUND
GUEST_FIXED_COMMAND_FAILED GUEST_UBUNTU_MISMATCH LIBVIRT_BRIDGE_CREATED MOUNTED_DEFAULT_NETWORK_XML_VISIBLE NODE_FIXTURE_PATH_ALREADY_EXISTS
OFFICIAL_GUEST_NOT_FRESH_NO_PURGE_ALLOWED OWNED_DAEMON_PID_REQUIRED OWNED_LIBVIRT_TCP_LISTENER_FOUND OWNED_QEMU_GUEST_REQUIRED
OWNED_UNIT_NOT_ACTIVE PREPARE_RESUME_CHANGED_PROOF PREPARE_RESUME_FAILED PRIVATE_PREPARE_RECEIPT_REQUIRED REAL_APT_PACKAGE_NOT_INSTALLED
REAL_GUEST_SYSTEMD_ROOT_REQUIRED REAL_LIBVIRT_CAPABILITIES_REQUIRED REAL_NODE_BINARY_HASH_MISMATCH REAL_PREPARE_RECEIPT_REJECTED
TCG_GUEST_UNEXPECTED_KVM UNEXPECTED_DOMAIN VENDOR_DEFAULT_XML_CHANGED_ON_RESUME VENDOR_DEFAULT_XML_NOT_RETAINED
VENDOR_MASK_NOT_PERSISTENT VENDOR_UNIT_NOT_PERSISTENTLY_MASKED APT_PLAN_UNSAFE NATIVE_COMMAND_UNAVAILABLE NATIVE_COMMAND_REJECTED
INTERFACE_PROOF_CHANGED FIREWALL_PROOF_CHANGED LIBVIRT_MOUNT_INODE_MISMATCH LIBVIRT_MOUNT_NOT_READONLY LIBVIRT_PROCESS_IDENTITY_MISMATCH
LIBVIRT_FOREIGN_EFFECTIVE_UNIT LIBVIRT_UNIX_SOCKET_REJECTED LIBVIRT_UNEXPECTED_RESOURCES LIBVIRT_CAPABILITIES_REJECTED
PROVISION_PREPARE_REFUSED NATIVE_GUEST_REFUSED_DETAILS_WITHHELD APT_DNS_FAILURE APT_TLS_FAILURE APT_SIGNATURE_FAILURE APT_METADATA_FAILURE APT_PACKAGE_UNAVAILABLE APT_DEPENDENCY_CONFLICT APT_LOCKED APT_COMMAND_REJECTED APT_COMMAND_UNAVAILABLE APT_COMMAND_TIMEOUT APT_OUTPUT_OVERSIZED
""".split())


class Refused(Exception):
    """Only bounded fixed diagnostic codes may leave the private VM harness."""


def require(condition, code):
    if not condition:
        raise Refused(code)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def regular(path, maximum):
    p = Path(path)
    info = p.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= maximum, "INPUT_FILE_REJECTED")
    require(not info.st_mode & 0o022, "INPUT_FILE_WRITABLE")
    return p


def run(argv, *, timeout=120, env=None, cwd=None):
    process = subprocess.Popen(argv, cwd=cwd, env=env or SAFE_ENV, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        require(len(stdout) <= MAX_SERIAL and len(stderr) <= MAX_SERIAL, "COMMAND_OUTPUT_OVERSIZED")
        require(process.returncode == 0, "FIXED_COMMAND_FAILED")
        return stdout
    finally:
        stop_owned(process)


def stop_owned(process):
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=10)


class HTTPSOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        u = urlsplit(newurl)
        require(u.scheme == "https" and u.hostname == "cloud-images.ubuntu.com" and not u.username and not u.password, "IMAGE_REDIRECT_REJECTED")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url, path, maximum):
    u = urlsplit(url)
    require(u.scheme == "https" and u.hostname == "cloud-images.ubuntu.com" and not u.username and not u.password, "IMAGE_URL_REJECTED")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), HTTPSOnly())
    total = 0
    deadline = time.monotonic() + 300
    with opener.open(url, timeout=30) as response, Path(path).open("xb") as stream:
        while True:
            block = response.read(1024 * 1024)
            if not block:
                break
            total += len(block)
            require(total <= maximum and time.monotonic() < deadline, "IMAGE_DOWNLOAD_BOUND_EXCEEDED")
            stream.write(block)
    Path(path).chmod(0o600)


def verify_signature(status):
    lines = status.decode("ascii", errors="strict").splitlines()
    require(not any(any(code in line for code in ("BADSIG", "ERRSIG", "EXPKEYSIG", "REVKEYSIG")) for line in lines), "IMAGE_SIGNATURE_REJECTED")
    valid = [line.split() for line in lines if line.startswith("[GNUPG:] VALIDSIG ")]
    require(len(valid) == 1 and KEY_FINGERPRINT in (valid[0][2], valid[0][-1]), "IMAGE_SIGNER_REJECTED")


def obtain_image(ubuntu, work):
    suite, date, expected = IMAGES[ubuntu]
    name = f"ubuntu-{ubuntu}-server-cloudimg-amd64.img"
    base = f"https://cloud-images.ubuntu.com/releases/{suite}/release-{date}"
    sums, signature = work / "SHA256SUMS", work / "SHA256SUMS.gpg"
    download(base + "/SHA256SUMS", sums, 65536)
    download(base + "/SHA256SUMS.gpg", signature, 65536)
    key = regular(HERE / "libvirt-native-image-key.asc", 16384)
    require(digest(key) == KEY_SHA256, "PINNED_IMAGE_KEY_CHANGED")
    gpg_home = work / "gpg"
    gpg_home.mkdir(mode=0o700)
    common = ["--batch", "--no-options", "--homedir", str(gpg_home)]
    listed = run(["/usr/bin/gpg", *common, "--with-colons", "--show-keys", str(key)])
    primary = []
    waiting = False
    for line in listed.decode().splitlines():
        fields = line.split(":")
        if fields[0] == "pub":
            waiting = True
        elif fields[0] == "fpr" and waiting:
            primary.append(fields[9]); waiting = False
    require(primary == [KEY_FINGERPRINT], "PINNED_IMAGE_KEY_IDENTITY_REJECTED")
    keyring = work / "ubuntu-cloud.gpg"
    run(["/usr/bin/gpg", *common, "--dearmor", "--output", str(keyring), str(key)])
    status = run(["/usr/bin/gpgv", "--homedir", str(gpg_home), "--keyring", str(keyring), "--status-fd", "1", str(signature), str(sums)])
    verify_signature(status)
    entries = re.findall(r"^([0-9a-f]{64}) [ *]" + re.escape(name) + r"$", sums.read_text(), re.M)
    require(entries == [expected], "PINNED_IMAGE_MANIFEST_MISMATCH")
    image = work / name
    download(base + "/" + name, image, MAX_IMAGE)
    require(digest(image) == expected and image.stat().st_size % 512 == 0, "IMAGE_BYTES_REJECTED")
    info = json.loads(run(["/usr/bin/qemu-img", "info", "--output=json", str(image)]))
    require(info.get("format") == "qcow2" and not info.get("backing-filename") and not info.get("encrypted"), "IMAGE_BACKING_OR_FORMAT_REJECTED")
    image.chmod(0o400)
    return image, {"ubuntu": ubuntu, "url": base + "/" + name, "image_sha256": expected,
                   "image_bytes": image.stat().st_size, "signed_manifest_sha256": digest(sums),
                   "signature_sha256": digest(signature), "signer_fingerprint": KEY_FINGERPRINT,
                   "key_sha256": KEY_SHA256, "signature_verified": True}


def normalized(value, *, kind="ip", parent=None):
    """Remove only observed runtime counters/lifetimes, never rule parameters."""
    if isinstance(value, list):
        return [normalized(x, kind=kind, parent=parent) for x in value]
    if isinstance(value, dict):
        omitted = {"valid_life_time", "preferred_life_time", "expires", "lastuse"} if kind == "ip" else ({"packets", "bytes"} if parent == "counter" else set())
        return {k: normalized(v, kind=kind, parent=k) for k, v in value.items() if k not in omitted}
    return value


def changed_paths(before, after, path="", limit=32):
    # Kernel/nft schema names only. Interface names, addresses, chains, marks,
    # rule strings and any unknown dictionary key are never exported.
    known = set("addresses routes firewall nftables metainfo version release_name json_schema_version ifindex ifname flags mtu qdisc operstate group txqlen link_type address broadcast addr_info family local prefixlen scope label metric protocol table dev dst gateway type src prefsrc priority uid pref name handle chain rule set map expr counter packets bytes mangle payload field match op left right lookup elem val accept drop queue reject masquerade snat dnat ct key fwd saddr daddr dport sport mark verdict limit rate per burst policy hook prio cache link_index link_netnsid master".split())
    output = []
    def visit(left, right, here):
        if len(output) >= limit or left == right:
            return
        if isinstance(left, dict) and isinstance(right, dict):
            for key in sorted(set(left) | set(right)):
                child = here + "." + (key if key in known else "unknown-field")
                if key not in left or key not in right:
                    output.append(child)
                else:
                    visit(left[key], right[key], child)
                if len(output) >= limit: break
        elif isinstance(left, list) and isinstance(right, list):
            if len(left) != len(right): output.append(here + ".length")
            for index, (a, b) in enumerate(zip(left, right)):
                visit(a, b, here + "[" + str(index) + "]")
                if len(output) >= limit: break
        else:
            output.append(here or "root")
    visit(before, after, path)
    return list(dict.fromkeys(output))[:limit]


def address_inventory_delta(before, after):
    """Classify interface changes without exporting names, MACs or addresses.

    This is diagnostic only: raw normalized equality remains the admission
    condition. Docker/veth/libvirt interfaces are never excluded from it.
    """
    result = {"available": False,
              "before_count": len(before) if isinstance(before, list) else None,
              "after_count": len(after) if isinstance(after, list) else None}
    categories = {"lo": "loopback", "eth0": "primary_ethernet", "eth1": "secondary_ethernet",
                  "docker0": "docker_bridge", "virbr0": "libvirt_bridge"}
    link_types = {"loopback", "ether", "none", "ppp", "tunnel", "sit", "ip6tnl", "tunnel6", "gre", "wireguard"}
    link_kinds = {"bridge", "veth", "tun", "dummy", "vlan", "vxlan", "bond", "openvswitch", "macvlan", "ipvlan", "wireguard", "vrf", "geneve"}

    def inventory(items):
        if not isinstance(items, list) or len(items) > 4096:
            return None
        values = {}
        names = {item["ifindex"]: item.get("ifname") for item in items
                 if isinstance(item, dict) and type(item.get("ifindex")) is int}
        for item in items:
            if not isinstance(item, dict) or type(item.get("ifindex")) is not int or not 0 < item["ifindex"] < 2 ** 31 or item["ifindex"] in values:
                return None
            families = {"inet": 0, "inet6": 0, "other": 0}
            addresses = item.get("addr_info", [])
            if not isinstance(addresses, list):
                return None
            for address in addresses:
                family = address.get("family") if isinstance(address, dict) else None
                families[family if family in ("inet", "inet6") else "other"] += 1
            name, link_type = item.get("ifname"), item.get("link_type")
            link_info = item.get("linkinfo")
            link_kind = link_info.get("info_kind") if isinstance(link_info, dict) else None
            master = item.get("master")
            if type(master) is int:
                master = names.get(master)
            values[item["ifindex"]] = {"ifindex": item["ifindex"],
                "name_category": categories.get(name, "other") if isinstance(name, str) else "other",
                "link_type": link_type if isinstance(link_type, str) and link_type in link_types else "other",
                "link_kind": link_kind if isinstance(link_kind, str) and link_kind in link_kinds else "other",
                "address_families": families, "master_present": "master" in item,
                "master_category": (categories.get(master, "other") if isinstance(master, str) else "other") if "master" in item else "none"}
        return values

    left, right = inventory(before), inventory(after)
    if left is None or right is None:
        return result
    added, removed = sorted(set(right) - set(left)), sorted(set(left) - set(right))
    result.update(available=True, added_count=len(added), removed_count=len(removed),
                  added=[right[index] for index in added[:32]], removed=[left[index] for index in removed[:32]],
                  details_truncated=len(added) > 32 or len(removed) > 32)
    return result


def network_proof(before, after):
    """Only category/hash evidence; no host address or firewall value leaves CI."""
    sections = ("addresses", "routes", "firewall")
    require(set(before) == set(after) == set(sections), "HOST_NETWORK_PROOF_SCHEMA_REJECTED")
    hashed = lambda value: hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"unchanged": before == after,
            "changed_sections": [name for name in sections if before[name] != after[name]],
            "difference_paths": changed_paths(before, after),
            "address_inventory_delta": address_inventory_delta(before["addresses"], after["addresses"]),
            "before_sha256": {name: hashed(before[name]) for name in sections},
            "after_sha256": {name: hashed(after[name]) for name in sections}}


def host_network():
    ip = next((p for p in ("/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip") if Path(p).is_file()), None)
    require(ip is not None, "HOST_READONLY_IP_TOOL_REQUIRED")
    result = {"addresses": normalized(json.loads(run([ip, "-j", "address", "show"]))),
              "routes": normalized(json.loads(run([ip, "-j", "route", "show", "table", "all"]))) }
    nft = next((p for p in ("/usr/sbin/nft", "/sbin/nft") if Path(p).is_file()), None)
    if nft:
        result["firewall"] = normalized(json.loads(run(["/usr/bin/sudo", "-n", nft, "-j", "list", "ruleset"])), kind="nft")
    else:
        saves = ["/usr/sbin/iptables-save", "/usr/sbin/ip6tables-save"]
        require(all(Path(p).is_file() for p in saves), "HOST_READONLY_FIREWALL_TOOLS_REQUIRED")
        result["firewall"] = ["\n".join(re.sub(r"\[[0-9]+:[0-9]+\]", "[COUNTERS]", line)
                                            for line in run(["/usr/bin/sudo", "-n", p]).decode().splitlines()
                                            if not line.startswith("#")) for p in saves]
    return result


def verify_host_network_checkpoint(before, *, phase):
    global HOST_PROOF, HOST_PRE_VM_PROOF
    require(phase in {"before_vm", "after_vm"}, "HOST_NETWORK_CHECKPOINT_REJECTED")
    proof = network_proof(before, host_network())
    if phase == "before_vm":
        HOST_PRE_VM_PROOF = proof
    else:
        HOST_PROOF = proof
    if not proof["unchanged"]:
        try:
            ip = next(p for p in ("/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip") if Path(p).is_file())
            # Separate diagnostic snapshot: detailed link timers must not enter
            # or rebase the original complete address/route/firewall admission.
            details = json.loads(run([ip, "-j", "-d", "link", "show"]))
            delta = address_inventory_delta(before["addresses"], details)
            for item in delta.get("added", []) + delta.get("removed", []):
                item.pop("address_families")  # `link show` does not read addresses.
            proof["link_inventory_delta"] = delta
        except Exception:
            proof["link_inventory_delta"] = {"available": False}
    require(proof["unchanged"], "HOST_NETWORK_CHANGED_BEFORE_VM" if phase == "before_vm" else "HOST_NETWORK_OR_FIREWALL_CHANGED")
    return proof


def process_identity(pid):
    directory = Path("/proc") / str(pid)
    fields = {}
    for line in (directory / "status").read_text().splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            if key in {"Uid", "Gid", "CapInh", "CapPrm", "CapEff", "CapAmb", "NoNewPrivs", "Seccomp", "Seccomp_filters"}:
                fields[key] = value.split()
    stat_line = (directory / "stat").read_text()
    end = stat_line.rfind(")")
    require(end > 0, "OWNED_PROCESS_STAT_REJECTED")
    return {"start_time": int(stat_line[end + 2:].split()[19]), "status": fields}


def unprivileged_status(fields, *, sandbox=False, minimum_filters=0):
    try:
        require(len(fields["Uid"]) == len(fields["Gid"]) == 4 and
                {int(v) for v in fields["Uid"]} == {os.getuid()} and os.getuid() != 0 and
                {int(v) for v in fields["Gid"]} == {os.getgid()} and os.getgid() != 0,
                "QEMU_UNPRIVILEGED_IDENTITIES_REQUIRED")
        require(all(len(fields[key]) == 1 and int(fields[key][0], 16) == 0 for key in ("CapInh", "CapPrm", "CapEff", "CapAmb")), "QEMU_CAPABILITIES_MUST_BE_EMPTY")
        if sandbox:
            require(fields["NoNewPrivs"] == ["1"] and fields["Seccomp"] == ["2"] and
                    len(fields["Seccomp_filters"]) == 1 and int(fields["Seccomp_filters"][0]) >= minimum_filters,
                    "QEMU_OUTER_AND_INNER_FILTERS_REQUIRED")
    except (KeyError, ValueError, TypeError):
        raise Refused("QEMU_STATUS_SCHEMA_REJECTED") from None


def record_relay_identity(host, nonce):
    directory = Path(__file__).resolve().parent
    require(stat.S_IMODE(directory.stat().st_mode) == 0o700 and directory.stat().st_uid == os.getuid(), "RELAY_PRIVATE_WORK_REQUIRED")
    identity = process_identity(os.getpid())
    unprivileged_status(identity["status"], sandbox=True, minimum_filters=2)
    record = {"pid": os.getpid(), "start_time": identity["start_time"], "host": host, "nonce": nonce}
    path = directory / ("relay-owner-" + str(record["pid"]) + "-" + str(record["start_time"]) + ".json")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(json.dumps(record, sort_keys=True).encode()); stream.flush(); os.fsync(stream.fileno())


def cleanup_relays(work, metadata):
    """setsid children leave QEMU's group: pin PID identity then signal pidfd."""
    require(hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"), "PIDFD_RELAY_CLEANUP_REQUIRED")
    records = list(work.glob("relay-owner-*.json"))
    require(len(records) <= 4096, "RELAY_OWNERSHIP_RECORD_BOUND")
    matched, terminated = 0, 0
    for path in records:
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid() and
                stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 512, "RELAY_OWNER_RECORD_REJECTED")
        record = json.loads(path.read_bytes())
        require(isinstance(record, dict) and set(record) == {"pid", "start_time", "host", "nonce"} and
                type(record["pid"]) is int and record["pid"] > 1 and type(record["start_time"]) is int and record["start_time"] > 0 and
                record["host"] in APT_DESTINATIONS and record["nonce"] == metadata["nonce"] and
                path.name == "relay-owner-" + str(record["pid"]) + "-" + str(record["start_time"]) + ".json", "RELAY_OWNER_BINDING_REJECTED")
        try:
            identity = process_identity(record["pid"])
        except FileNotFoundError:
            continue
        require(identity["start_time"] == record["start_time"], "RELAY_PID_REUSED_NO_SIGNAL")
        expected = b"\0".join(v.encode() for v in ("/usr/bin/python3", "-I", str(work / "relay.py"), record["host"], metadata["nonce"])) + b"\0"
        try:
            command = (Path("/proc") / str(record["pid"]) / "cmdline").read_bytes()
        except (FileNotFoundError, ProcessLookupError):
            continue  # Exact recorded process exited before it could be signalled.
        if not command:
            continue  # An exited zombie cannot retain an outbound connection.
        require(command == expected, "RELAY_COMMAND_CHANGED_NO_SIGNAL")
        unprivileged_status(identity["status"], sandbox=True, minimum_filters=2)
        try:
            descriptor = os.pidfd_open(record["pid"], 0)
        except ProcessLookupError:
            continue
        try:
            require(process_identity(record["pid"])["start_time"] == record["start_time"], "RELAY_PID_CHANGED_NO_SIGNAL")
            matched += 1
            with selectors.DefaultSelector() as waiter:
                waiter.register(descriptor, selectors.EVENT_READ)
                if not waiter.select(0):
                    signal.pidfd_send_signal(descriptor, signal.SIGTERM, None, 0)
                    if not waiter.select(3):
                        signal.pidfd_send_signal(descriptor, signal.SIGKILL, None, 0)
                        require(bool(waiter.select(3)), "OWNED_RELAY_DID_NOT_EXIT")
                    terminated += 1
        except (ProcessLookupError, FileNotFoundError):
            pass
        finally:
            os.close(descriptor)
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit(): continue
        try:
            if entry.stat().st_uid != os.getuid(): continue
            command = (entry / "cmdline").read_bytes()
            for host in APT_DESTINATIONS:
                expected = b"\0".join(v.encode() for v in ("/usr/bin/python3", "-I", str(work / "relay.py"), host, metadata["nonce"])) + b"\0"
                require(command != expected, "OWNED_RELAY_REMAINS_NO_CLEANUP_CLAIM")
        except (FileNotFoundError, ProcessLookupError):
            continue
    return {"owned_records": len(records), "live_identities_matched": matched, "terminated_owned": terminated, "cleanup_complete": True}


def prepare_sandbox(work):
    global SANDBOX_PROOF
    unprivileged_status(process_identity(os.getpid())["status"])
    release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
    require(release.get("ID", "").strip('"') == "ubuntu" and release.get("VERSION_ID", "").strip('"') == "24.04", "REVIEWED_EMULATOR_HOST_REQUIRED")
    version = run(["/usr/bin/dpkg-query", "-W", "-f=${Version}", "libslirp0"]).decode().strip()
    require(re.fullmatch(r"(?:[0-9]+:)?4\.7\.[0-9]+[A-Za-z0-9.+:~_-]*", version) is not None, "REVIEWED_LIBSLIRP_47_REQUIRED")
    source = regular(HERE / "libvirt-native-sandbox.c", 65536)
    executable = work / "qemu-sandbox"
    run(["/usr/bin/cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-D_FORTIFY_SOURCE=2", "-fstack-protector-strong", str(source), "-o", str(executable)])
    executable.chmod(0o700)
    proof = json.loads(run([str(executable), "--self-test"], cwd=work))
    required = {"schema", "passed", "setsid_allowed", "denied_syscalls", "x32_denied", "i386_denied", "no_new_privs", "seccomp", "capabilities_zero"}
    denied = {"setuid", "setgid", "setpgid", "setreuid", "setregid", "setresuid", "setresgid", "setfsuid", "setfsgid", "setgroups", "capset"}
    require(isinstance(proof, dict) and set(proof) == required and proof["schema"] == 1 and
            all(proof[k] is True for k in ("passed", "setsid_allowed", "x32_denied", "i386_denied", "capabilities_zero")) and
            proof["no_new_privs"] == 1 and proof["seccomp"] == 2 and isinstance(proof["denied_syscalls"], list) and
            len(proof["denied_syscalls"]) == len(denied) and set(proof["denied_syscalls"]) == denied,
            "REAL_SANDBOX_SELF_TEST_REJECTED")
    SANDBOX_PROOF = {**proof, "emulator_host": "24.04", "libslirp_version": version, "qemu_process_verified": False}
    return executable


def verify_running_sandbox(process):
    baseline = int(process_identity(os.getpid())["status"].get("Seccomp_filters", ["0"])[0])
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        require(process.poll() is None, "QEMU_LAUNCHER_EXITED_BEFORE_PROOF")
        try:
            if (Path("/proc") / str(process.pid) / "exe").resolve() == Path("/usr/bin/qemu-system-x86_64").resolve():
                status = process_identity(process.pid)["status"]
                unprivileged_status(status, sandbox=True, minimum_filters=baseline + 2)
                return {"qemu_process_verified": True, "minimum_filter_count": baseline + 2}
        except (FileNotFoundError, Refused):
            pass
        time.sleep(0.05)
    raise Refused("QEMU_REAL_SANDBOX_NOT_OBSERVED")


def relay_event(host, nonce, event):
    """Private append-only static diagnostics; never addresses or exception text."""
    if host not in APT_DESTINATIONS or event not in RELAY_EVENTS or not re.fullmatch(r"[0-9a-f]{32}", nonce or ""):
        return
    directory = Path(__file__).resolve().parent
    try:
        info = directory.stat()
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            return
        path = directory / "relay-events.jsonl"
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if (info.st_uid != os.getuid() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                    stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 256 * 1024):
                return
            os.write(fd, (json.dumps({"host": host, "nonce": nonce, "event": event}, sort_keys=True) + "\n").encode())
        finally:
            os.close(fd)
    except OSError:
        pass  # Diagnostic failure must not change the byte relay's semantics.


def relay_evidence(work, metadata):
    counts = {host: {} for host in APT_DESTINATIONS}
    path = work / "relay-events.jsonl"
    if not path.exists():
        return {"spawned_seen": False, "counts": counts}
    try:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or
                stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 512 * 1024):
            return {"diagnostic_rejected": True}
        for raw in path.read_bytes().splitlines():
            if len(raw) > 256: continue
            item = json.loads(raw)
            if (not isinstance(item, dict) or set(item) != {"host", "nonce", "event"} or item.get("nonce") != metadata["nonce"] or
                    item.get("host") not in APT_DESTINATIONS or item.get("event") not in RELAY_EVENTS):
                continue
            events = counts[item["host"]]
            events[item["event"]] = events.get(item["event"], 0) + 1
        return {"spawned_seen": any(v.get("spawned", 0) for v in counts.values()), "counts": counts}
    except (OSError, ValueError, TypeError):
        return {"diagnostic_rejected": True}


def relay_stream(target, input_stream, output_stream, observe=lambda _event: None):
    """Preserve TCP half-close: drain responses after guest write-side EOF."""
    with selectors.DefaultSelector() as selector:
        selector.register(input_stream, selectors.EVENT_READ, "input")
        selector.register(target, selectors.EVENT_READ, "remote")
        deadline, total, seen = time.monotonic() + 300, 0, set()
        while time.monotonic() < deadline:
            for key, _ in selector.select(1):
                try:
                    data = os.read(key.fileobj.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not data:
                    if key.data == "input":
                        observe("guest-eof")
                        selector.unregister(key.fileobj)
                        target.shutdown(socket.SHUT_WR)
                        # A peer that never closes cannot orphan this child.
                        # Do not discard a legitimate response after FIN.
                        deadline = min(deadline, time.monotonic() + 60)
                        continue
                    observe("server-eof")
                    return
                if key.data not in seen:
                    observe("guest-first-bytes" if key.data == "input" else "server-first-bytes")
                    seen.add(key.data)
                total += len(data)
                require(total <= 512 * 1024 * 1024, "RELAY_BYTE_BOUND_EXCEEDED")
                if key.data == "input":
                    target.settimeout(20); target.sendall(data); target.setblocking(False)
                else:
                    output_stream.write(data); output_stream.flush()
        observe("timeout")
        raise Refused("RELAY_DEADLINE_EXCEEDED")


def relay(host, nonce=None):
    """A fixed-target TLS-transparent byte relay, never an HTTP CONNECT proxy."""
    require(host in APT_DESTINATIONS, "RELAY_TARGET_REJECTED")
    require(re.fullmatch(r"[0-9a-f]{32}", nonce or "") is not None, "RELAY_NONCE_REJECTED")
    record_relay_identity(host, nonce)
    observe = lambda event: relay_event(host, nonce, event)
    observe("spawned")
    try:
        addresses = socket.getaddrinfo(host, 443, family=socket.AF_INET, type=socket.SOCK_STREAM)
    except OSError:
        observe("dns-failed")
        raise Refused("RELAY_DNS_FAILED") from None
    if not addresses or not all(ipaddress.ip_address(a[4][0]).is_global for a in addresses):
        observe("dns-nonpublic")
        raise Refused("RELAY_NONPUBLIC_ADDRESS_REJECTED")
    observe("dns-ok")
    family, socktype, proto, _, address = addresses[0]
    with socket.socket(family, socktype, proto) as target:
        try:
            target.settimeout(20); target.connect(address); target.setblocking(False)
        except OSError:
            observe("connect-failed")
            raise Refused("RELAY_CONNECT_FAILED") from None
        observe("connect-ok")
        try:
            relay_stream(target, sys.stdin.buffer, sys.stdout.buffer, observe)
        except (OSError, Refused):
            observe("io-failed")
            raise


def qemu_arguments(work, image, overlay, seed, *, nonce):
    require(re.fullmatch(r"[0-9a-f]{32}", nonce) is not None, "RELAY_NONCE_REJECTED")
    args = ["/usr/bin/qemu-system-x86_64", "-machine", "pc,accel=tcg", "-cpu", "max,vmx=off,svm=off", "-smp", "2", "-m", "3072",
            "-nodefaults", "-display", "none", "-monitor", "none", "-serial", "stdio", "-no-reboot",
            "-sandbox", "on,obsolete=deny,elevateprivileges=allow,spawn=allow,resourcecontrol=deny",
            "-drive", f"file={overlay},if=none,id=root,format=qcow2", "-device", "virtio-blk-pci,drive=root,bootindex=0",
            "-drive", f"file={image},if=none,id=approved,format=raw,readonly=on", "-device", "virtio-blk-pci,drive=approved",
            "-drive", f"file={seed},if=none,id=seed,format=raw,readonly=on", "-device", "virtio-blk-pci,drive=seed",
            "-netdev", "user,id=apt,restrict=on,ipv6=off" + "".join(
                f",guestfwd=tcp:10.0.2.{100+n}:443-cmd:/usr/bin/python3 -I {work}/relay.py {host} {nonce}"
                for n, host in enumerate(APT_DESTINATIONS)), "-device", "virtio-net-pci,netdev=apt"]
    return args


def seed_commands(nonce):
    """Only add static checkpoints around the unchanged guest-only commands."""
    require(re.fullmatch(r"[0-9a-f]{32}", nonce or "") is not None, "SEED_PROGRESS_NONCE_REJECTED")
    def checkpoint(stage):
        require(stage in BOOT_STAGES, "SEED_PROGRESS_STAGE_REJECTED")
        return ["sh", "-c", "printf '%s\\n' 'ASTER_LIBVIRT_NATIVE_PROGRESS_" + nonce + " " + stage + "' > /dev/ttyS0"]
    return {"bootcmd": [checkpoint("bootcmd"), checkpoint("boot-mask:start"),
                        ["sh", "-c", "systemctl mask --now apt-daily.service apt-daily-upgrade.service apt-daily.timer apt-daily-upgrade.timer ssh.service ssh.socket || true"],
                        checkpoint("boot-mask:done"), checkpoint("boot-hosts:start"),
                        ["sh", "-c", HOSTS_BOOT_COMMAND], checkpoint("boot-hosts:done")],
            "runcmd": [checkpoint("runcmd-enter"), ["sh", "-c", "/usr/bin/python3 -I /root/aster-native/guest.py; /sbin/poweroff -f"]]}


def make_seed(work, root, source_sha, image_provenance):
    go = shutil.which("go")
    require(go is not None, "GO_TOOLCHAIN_REQUIRED")
    env = dict(SAFE_ENV, PATH=os.environ.get("PATH", SAFE_ENV["PATH"]), HOME=str(work), GOTOOLCHAIN="local", CGO_ENABLED="0", GOOS="linux", GOARCH="amd64")
    require(run([go, "version"], env=env).decode().startswith("go version go1.27.3 "), "PINNED_GO_TOOLCHAIN_REQUIRED")
    binary = work / "aster-node"
    run([go, "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-ldflags=-s -w", "-o", str(binary), "./cmd/aster-node"], cwd=root / "aster-cloud", env=env, timeout=300)
    nonce = os.urandom(16).hex()
    metadata = {"schema": 1, "nonce": nonce, "source_sha": source_sha, **image_provenance,
                "node_binary_sha256": digest(binary)}
    content = {"provision.py": (root / "aster-cloud/deploy/install/provision.py").read_bytes(),
               "guest.py": (HERE / "libvirt-native-guest.py").read_bytes(), "aster-node": binary.read_bytes(),
               "metadata.json": json.dumps(metadata).encode()}
    files = [{"path": "/root/aster-native/" + name, "owner": "root:root", "permissions": "0700" if name == "aster-node" else "0600",
              "encoding": "gz+b64", "content": base64.b64encode(gzip.compress(raw, mtime=0)).decode()} for name, raw in content.items()]
    config = {"users": [], "disable_root": True, "ssh_pwauth": False, "manage_etc_hosts": False, "write_files": files,
              "package_update": False, "package_upgrade": False,
              **seed_commands(nonce)}
    (work / "user-data").write_text("#cloud-config\n" + json.dumps(config))
    (work / "meta-data").write_text(json.dumps({"instance-id": "aster-native-" + nonce, "local-hostname": "aster-native"}))
    seed = work / "seed.img"
    run(["/usr/bin/cloud-localds", str(seed), str(work / "user-data"), str(work / "meta-data")])
    shutil.copyfile(HERE / "libvirt-native.py", work / "relay.py")
    return seed, metadata


def run_vm(arguments, work, metadata):
    global GUEST_RESULT_SEEN, RELAY_PROOF, SANDBOX_PROOF
    progress_pattern = ("ASTER_LIBVIRT_NATIVE_PROGRESS_" + metadata["nonce"] + " ").encode()
    progress_allowed = GUEST_PHASES | {name + ":" + outcome for name in DIAGNOSTIC_COMMANDS for outcome in ("start", "done", "failed")} | BOOT_STAGES
    started = time.monotonic()
    pattern = ("ASTER_LIBVIRT_NATIVE_RESULT_" + metadata["nonce"] + " ").encode()
    result, buffer, total = None, b"", 0
    process = subprocess.Popen([str(work / "qemu-sandbox"), *arguments], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               cwd=work, env=dict(SAFE_ENV, HOME=str(work)), start_new_session=True)
    selector = selectors.DefaultSelector(); selector.register(process.stdout, selectors.EVENT_READ)
    try:
        SANDBOX_PROOF.update(verify_running_sandbox(process))
        deadline = time.monotonic() + 1200
        with (work / "private-serial.log").open("xb") as log:
            (work / "private-serial.log").chmod(0o600)
            while time.monotonic() < deadline:
                for key, _ in selector.select(1):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj); continue
                    total += len(chunk); require(total <= MAX_SERIAL, "PRIVATE_SERIAL_BOUND_EXCEEDED")
                    log.write(chunk); buffer += chunk
                    while b"\n" in buffer:
                        line, buffer = buffer.split(b"\n", 1)
                        if progress_pattern in line:
                            label = line.split(progress_pattern, 1)[1].strip().decode("ascii", errors="ignore")
                            if label in progress_allowed:
                                VM_PROGRESS.append({"stage": label, "elapsed_seconds": int(time.monotonic() - started)})
                                del VM_PROGRESS[:-32]
                        if pattern in line:
                            require(result is None, "DUPLICATE_GUEST_RESULT")
                            encoded = line.split(pattern, 1)[1].strip()
                            require(len(encoded) <= 65536, "GUEST_RESULT_OVERSIZED")
                            result = json.loads(base64.b64decode(encoded, validate=True))
                            GUEST_RESULT_SEEN = True
                            public = public_result(result, metadata)
                            if OUTPUT_CREATED is not None:
                                (OUTPUT_CREATED / "guest-report.json").write_text(json.dumps(public, indent=2) + "\n")
                if process.poll() is not None and not selector.get_map():
                    break
            require(process.poll() is not None, "GUEST_VM_DEADLINE_EXCEEDED")
            require(process.returncode == 0 and isinstance(result, dict), "GUEST_RESULT_UNAVAILABLE")
            return result
    finally:
        selector.close()
        stop_owned(process)
        RELAY_PROOF = relay_evidence(work, metadata)
        RELAY_PROOF["lifecycle"] = cleanup_relays(work, metadata)


def validate_result(result, metadata):
    allowed = {"schema", "passed", "real_apt", "real_systemd", "libvirt_prepared", "kvm_ready", "explicit_kvm_denial",
               "non_kvm_doctor_checks_passed", "source_sha", "ubuntu", "image_sha256", "real_approved_image_validated",
               "doctor_checks", "owned_units_active", "vendor_masks_persistent", "empty_network_mount_verified",
               "unix_libvirt_query_passed", "default_network_absent", "virbr_absent", "libvirt_no_tcp_listener", "vendor_default_xml_retained_unchanged_on_resume", "doctor_protocol"}
    require(isinstance(result, dict) and set(result) <= allowed, "GUEST_RESULT_SCHEMA_REJECTED")
    require(result.get("schema") == 1 and result.get("source_sha") == metadata["source_sha"] and result.get("ubuntu") == metadata["ubuntu"], "GUEST_RESULT_BINDING_MISMATCH")
    require(result.get("image_sha256") == metadata["image_sha256"], "GUEST_IMAGE_BINDING_MISMATCH")
    require(all(result.get(k) is True for k in ("passed", "real_apt", "real_systemd", "libvirt_prepared", "explicit_kvm_denial", "non_kvm_doctor_checks_passed",
                                               "real_approved_image_validated", "owned_units_active", "vendor_masks_persistent", "empty_network_mount_verified",
                                               "unix_libvirt_query_passed", "default_network_absent", "virbr_absent", "libvirt_no_tcp_listener", "vendor_default_xml_retained_unchanged_on_resume")), "GUEST_ACCEPTANCE_FAILED")
    require(result.get("kvm_ready") is False, "GUEST_MUST_NOT_CLAIM_KVM_READY")
    require(result.get("doctor_protocol") == "aster.node/1", "GUEST_DOCTOR_PROTOCOL_REJECTED")
    checks = result.get("doctor_checks", {})
    expected = {"ubuntu_at_least_22", "x86_64_host", "hardware_virtualization_flags", "dev_kvm_read_write",
                "binary:/usr/bin/virsh", "binary:/usr/bin/qemu-img", "binary:/usr/bin/qemu-system-x86_64",
                "storage_directory", "libvirt_system_readonly_query"}
    require(isinstance(checks, dict) and set(checks) == expected and all(type(v) is bool for v in checks.values()), "GUEST_DOCTOR_INVENTORY_REJECTED")
    require(checks["dev_kvm_read_write"] is False and all(v for k, v in checks.items() if k not in ("dev_kvm_read_write", "hardware_virtualization_flags")), "GUEST_DOCTOR_NOT_EXPLICIT_KVM_ONLY_DENIAL")


def public_result(result, metadata):
    """Validate success before export; failure exports only fixed enums."""
    if isinstance(result, dict) and result.get("passed") is True:
        validate_result(result, metadata)
        return result
    require(isinstance(result, dict) and result.get("schema") == 1 and result.get("passed") is False and
            all(result.get(k) == metadata[k] for k in ("source_sha", "ubuntu", "image_sha256")) and
            result.get("kvm_ready") is False, "GUEST_FAILURE_BINDING_REJECTED")
    code, phase = result.get("code"), result.get("phase")
    output = {"schema": 1, "passed": False, "kvm_ready": False,
              **{k: metadata[k] for k in ("source_sha", "ubuntu", "image_sha256")},
              "code": code if isinstance(code, str) and code in GUEST_ERROR_CODES else "GUEST_REPORTED_FAILURE",
              "phase": phase if isinstance(phase, str) and phase in GUEST_PHASES else "unrecognized"}
    diagnostics = result.get("diagnostics")
    if isinstance(diagnostics, dict):
        safe = {}
        plan = diagnostics.get("apt_plan_rejections")
        if (isinstance(plan, dict) and set(plan) == {"categories", "packages", "unknown_package_count", "truncated"} and
                isinstance(plan["categories"], list) and len(plan["categories"]) <= 3 and
                all(isinstance(v, str) and v in APT_PLAN_CATEGORIES for v in plan["categories"]) and
                isinstance(plan["packages"], list) and len(plan["packages"]) <= 12 and
                all(isinstance(v, str) and v in APT_PLAN_PACKAGES for v in plan["packages"]) and
                type(plan["unknown_package_count"]) is int and 0 <= plan["unknown_package_count"] <= 255 and
                type(plan["truncated"]) is bool):
            safe["apt_plan_rejections"] = {"categories": sorted(set(plan["categories"])), "packages": sorted(set(plan["packages"])),
                                           "unknown_package_count": plan["unknown_package_count"], "truncated": plan["truncated"]}
        commands = diagnostics.get("failed_commands")
        if isinstance(commands, list):
            safe["failed_commands"] = [v for v in commands if isinstance(v, str) and v in DIAGNOSTIC_COMMANDS][:4]
        for prefix in ("dependencies", "libvirt"):
            status, steps = diagnostics.get(prefix + "_status"), diagnostics.get(prefix + "_steps")
            if isinstance(status, str) and status in DIAGNOSTIC_STATUSES:
                safe[prefix + "_status"] = status
            if isinstance(steps, list):
                safe[prefix + "_steps"] = [v for v in steps if isinstance(v, str) and v in DIAGNOSTIC_STEPS][:4]
        output["diagnostics"] = safe
    return output


def execute(args):
    global OUTPUT_CREATED, HOST_PROOF
    require(platform.system() == "Linux" and platform.machine() in ("x86_64", "amd64") and os.geteuid() != 0, "LINUX_AMD64_NONROOT_RUNNER_REQUIRED")
    require(re.fullmatch(r"[0-9a-f]{40}", args.source_sha or ""), "FULL_SOURCE_SHA_REQUIRED")
    root, output = Path(args.source_root), Path(args.output)
    require(root.is_absolute() and root.resolve() == root and output.is_absolute() and output.resolve() == output and not output.exists(), "NEW_CANONICAL_OUTPUT_REQUIRED")
    require(run(["/usr/bin/git", "-C", str(root), "rev-parse", "HEAD"]).decode().strip() == args.source_sha, "SOURCE_SHA_MISMATCH")
    run(["/usr/bin/git", "-C", str(root), "diff", "--quiet", "HEAD", "--", "aster-cloud"])
    require(all(Path(p).is_file() for p in TOOLS), "FIXED_HOST_TOOLS_REQUIRED")
    output.mkdir(mode=0o700)
    OUTPUT_CREATED = output
    before = host_network()
    result = None
    try:
        with tempfile.TemporaryDirectory(prefix="aster-libvirt-native.", dir=output.parent) as temporary:
            work = Path(temporary); work.chmod(0o700)
            require(re.fullmatch(r"/[A-Za-z0-9_./-]+", str(work)) is not None, "SCRATCH_COMMAND_PATH_REJECTED")
            prepare_sandbox(work)
            image, provenance = obtain_image(args.ubuntu, work)
            (output / "image-provenance.json").write_text(json.dumps({"source_sha": args.source_sha, **provenance}, indent=2) + "\n")
            seed, metadata = make_seed(work, root, args.source_sha, provenance)
            overlay = work / "root.qcow2"
            run(["/usr/bin/qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(image), str(overlay), "16G"])
            verify_host_network_checkpoint(before, phase="before_vm")
            result = run_vm(qemu_arguments(work, image, overlay, seed, nonce=metadata["nonce"]), work, metadata)
            # Never export arbitrary nested data from a failed VM report.
            # Successful reports also pass the complete schema before export.
            (output / "guest-report.json").write_text(json.dumps(public_result(result, metadata), indent=2) + "\n")
            require(result.get("passed") is True, "GUEST_ACCEPTANCE_FAILED")
            validate_result(result, metadata)
    finally:
        already_failed = sys.exc_info()[0] is not None
        try:
            verify_host_network_checkpoint(before, phase="after_vm")
        except Exception:
            # Never turn a failure into success, or replace the earlier cause.
            # Final proof is still recorded if available; absent proof is not green.
            if not already_failed:
                raise
    require(SANDBOX_PROOF.get("passed") is True and SANDBOX_PROOF.get("qemu_process_verified") is True and
            RELAY_PROOF.get("spawned_seen") is True and RELAY_PROOF.get("lifecycle", {}).get("cleanup_complete") is True,
            "NATIVE_PROCESS_ISOLATION_OR_RELAY_CLEANUP_UNVERIFIED")
    summary = {k: result[k] for k in ("passed", "real_apt", "real_systemd", "libvirt_prepared", "kvm_ready", "image_sha256", "ubuntu", "source_sha")}
    summary.update(schema=1, host_network_unchanged=True, tcg_only=True,
                   host_network_proof=HOST_PROOF, host_network_pre_vm_proof=HOST_PRE_VM_PROOF,
                   host_process_isolation_verified=True, sandbox_selftests_passed=True, relay_cleanup_verified=True,
                   sandbox_proof=SANDBOX_PROOF, relay_proof=RELAY_PROOF,
                   doctor_protocol=result["doctor_protocol"], explicit_kvm_denial=result["explicit_kvm_denial"],
                   non_kvm_doctor_checks_passed=result["non_kvm_doctor_checks_passed"],
                   scope="Software preparation and explicit no-KVM doctor denial only; not a real KVM guest or production deployment acceptance.")
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def main(argv=None):
    global OUTPUT_CREATED, VM_PROGRESS, HOST_PROOF, HOST_PRE_VM_PROOF, GUEST_RESULT_SEEN, RELAY_PROOF, SANDBOX_PROOF
    OUTPUT_CREATED, VM_PROGRESS, HOST_PROOF, HOST_PRE_VM_PROOF, GUEST_RESULT_SEEN, RELAY_PROOF, SANDBOX_PROOF = None, [], {}, {}, False, {}, {}
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ubuntu", choices=sorted(IMAGES), required=True)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    def interrupted(_number, _frame):
        raise Refused("NATIVE_FIXTURE_INTERRUPTED")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        print(json.dumps(execute(args), sort_keys=True)); return 0
    except Refused as error:
        if OUTPUT_CREATED is not None:
            (OUTPUT_CREATED / "summary.json").write_text(json.dumps({"schema": 1, "passed": False, "code": str(error), "source_sha": args.source_sha, "ubuntu": args.ubuntu, "image_sha256": IMAGES[args.ubuntu][2], "kvm_ready": False,
                "progress": VM_PROGRESS, "guest_result_seen": GUEST_RESULT_SEEN, "host_network_proof": HOST_PROOF,
                "host_network_pre_vm_proof": HOST_PRE_VM_PROOF, "relay_proof": RELAY_PROOF, "sandbox_proof": SANDBOX_PROOF}) + "\n")
        print("FAIL: " + str(error), file=sys.stderr); return 1
    except Exception:
        if OUTPUT_CREATED is not None:
            (OUTPUT_CREATED / "summary.json").write_text(json.dumps({"schema": 1, "passed": False, "code": "NATIVE_FIXTURE_REFUSED_DETAILS_WITHHELD", "source_sha": args.source_sha, "ubuntu": args.ubuntu, "image_sha256": IMAGES[args.ubuntu][2], "kvm_ready": False,
                "progress": VM_PROGRESS, "guest_result_seen": GUEST_RESULT_SEEN, "host_network_proof": HOST_PROOF,
                "host_network_pre_vm_proof": HOST_PRE_VM_PROOF, "relay_proof": RELAY_PROOF, "sandbox_proof": SANDBOX_PROOF}) + "\n")
        print("FAIL: NATIVE_FIXTURE_REFUSED_DETAILS_WITHHELD", file=sys.stderr); return 1


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] in APT_DESTINATIONS:
        try:
            def relay_deadline(_number, _frame):
                relay_event(sys.argv[1], sys.argv[2], "timeout")
                raise Refused("RELAY_OVERALL_DEADLINE")
            signal.signal(signal.SIGALRM, relay_deadline)
            signal.alarm(300)
            relay(sys.argv[1], sys.argv[2])
        except Exception:
            sys.exit(1)
    else:
        sys.exit(main())

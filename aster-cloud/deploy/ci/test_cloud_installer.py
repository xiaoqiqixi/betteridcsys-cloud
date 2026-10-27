#!/usr/bin/env python3
"""Independent, host-safe installer contract tests; never install a service.

All payloads and credentials are synthetic. Privileged host commands are denied
in tests; any platform/ownership substitutions exist only in this test process.
"""

import contextlib
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import tempfile
import types
import unittest
from unittest import mock


INSTALLER_PATH = Path(__file__).resolve().parents[1] / "install" / "install.py"
_SPEC = importlib.util.spec_from_file_location("aster_cloud_installer_test_target", INSTALLER_PATH)
installer = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = installer
_SPEC.loader.exec_module(installer)


def sha256(value):
    return hashlib.sha256(value).hexdigest()


ELF_HEADER = b"\x7fELF\x02\x01" + b"\x00" * 12 + b"\x3e\x00" + b"\x00" * 44
FRESH_DEPENDENCY_PATHS = (
    "/var/lib/mysql", "/var/lib/mariadb", "/var/lib/postgresql",
    "/var/lib/libvirt", "/etc/libvirt", "/opt/vps-billing", "/opt/aster-billing",
)
FRESH_MYSQL_PATHS = (
    "/etc/mysql", "/var/lib/mysql", "/etc/systemd/system/mysql.service.d",
    "/etc/systemd/system/mysql.service", "/etc/systemd/system/mysqld.service",
    "/usr/sbin/mysqld", "/run/mysqld/mysqld.sock",
)


class SyntheticMySQL:
    """A bounded SQL boundary model, not an actual MySQL acceptance fixture."""
    def __init__(self, provision):
        self.provision = provision
        self.info = {"current_user": "root@localhost", "version": "8.0.44", "server_uuid": "11111111-2222-3333-4444-555555555555", "partial_revokes": 0, "db_exists": 0, "foreign_databases": 0, "runtime_exists": 0, "migration_exists": 0}
        self.nonce = None
        self.accounts = {}
        self.grants = {}
        self.sql = []
        self.lose_account_ack = False

    def __call__(self, state_dir, sql):
        self.sql.append(sql)
        if "CURRENT_USER()" in sql:
            return json.dumps(self.info).encode()
        if sql.startswith("CREATE DATABASE"):
            self.info["db_exists"] = 1
            self.nonce = re.search(r"VALUES \(1,'([a-f0-9]{64})'", sql)[1]
            return b""
        if "FROM `" in sql and ".aster_installer_ownership" in sql:
            return json.dumps({"nonce": self.nonce, "server_uuid": self.info["server_uuid"]}).encode()
        if sql.startswith("CREATE USER"):
            user = re.search(r"CREATE USER '([^']+)'@'localhost'", sql)[1]
            self.accounts[user] = {"nonce": self.nonce, "host": "localhost"}
            self.info["runtime_exists" if user.endswith("_api") else "migration_exists"] = 1
            if self.lose_account_ack:
                self.lose_account_ack = False
                raise self.provision.ProvisionError("synthetic CREATE acknowledgement lost")
            return (user + "\tlocalhost\tDO_NOT_PRINT_SYNTHETIC_" + user + "_PASSWORD\n").encode()
        if "FROM information_schema.USER_ATTRIBUTES" in sql:
            user = re.search(r"WHERE USER='([^']+)'", sql)[1]
            return json.dumps(self.accounts.get(user, {})).encode()
        if sql.startswith("GRANT "):
            user = re.search(r" TO '([^']+)'@'localhost'", sql)[1]
            self.grants[user] = sql.strip().rstrip(";").replace("'" + user + "'@'localhost'", "`" + user + "`@`localhost`")
            return b""
        if sql.startswith("SHOW GRANTS"):
            user = re.search(r"FOR '([^']+)'@'localhost'", sql)[1]
            return ("GRANT USAGE ON *.* TO `" + user + "`@`localhost`\n" + self.grants[user] + "\n").encode()
        raise AssertionError("unmodeled SQL boundary: " + sql.split(" ", 1)[0])


class InstallerContract(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="aster-installer-contract-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        # Fail closed: an accidental apt/systemctl/host subprocess is a test error.
        self.commands = mock.patch.object(
            installer.subprocess, "run", side_effect=AssertionError("host subprocess forbidden in this test")
        )
        self.commands.start()
        self.addCleanup(self.commands.stop)
        self.network = mock.patch("socket.create_connection", side_effect=AssertionError("network forbidden in this test"))
        self.network.start()
        self.addCleanup(self.network.stop)

    def payload(self, component="controller"):
        if component == "controller":
            return {"bin/aster-controller": (ELF_HEADER + b"synthetic-controller\n", 0o755), "ui/index.html": (b"<p>synthetic UI</p>\n", 0o644)}
        return {"bin/aster-node": (ELF_HEADER + b"synthetic-node\n", 0o755), "bin/aster-network": (ELF_HEADER + b"synthetic-network\n", 0o755)}

    def manifest(self, payload, component="controller"):
        return {
            "schema": 1,
            "component": "aster-cloud-" + component,
            "version": "0.1.0-dev",
            "source_commit": "1" * 40,
            "platform": "linux-amd64",
            "release_kind": "development",
            "files": [
                {"path": path, "sha256": sha256(data), "size": len(data), "mode": format(mode, "04o")}
                for path, (data, mode) in sorted(payload.items())
            ],
        }

    def archive(self, payload=None, manifest=None, component="controller", extra=(), omit=()):
        payload = self.payload(component) if payload is None else payload
        manifest = self.manifest(payload, component) if manifest is None else manifest
        path = self.root / ("bundle-%s.tar.gz" % len(list(self.root.glob("bundle-*"))))
        with tarfile.open(path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
            manifest_data = json.dumps(manifest, sort_keys=True).encode() if not isinstance(manifest, bytes) else manifest
            info = tarfile.TarInfo("manifest.json")
            info.mode = 0o644
            info.size = len(manifest_data)
            archive.addfile(info, io.BytesIO(manifest_data))
            for name, (data, mode) in payload.items():
                if name in omit:
                    continue
                info = tarfile.TarInfo(name)
                info.mode = mode
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            for info, data in extra:
                archive.addfile(info, io.BytesIO(data) if data is not None else None)
        return path, sha256(path.read_bytes())

    def verify(self, path, digest, component="controller"):
        return installer.verify_bundle(path, digest, component)

    def rejected(self, path, digest, component="controller"):
        with self.assertRaises(installer.InstallerError):
            self.verify(path, digest, component)

    def args(self, component="controller", extra=()):
        path, digest = self.archive(component=component)
        return installer.build_parser().parse_args([
            component, "--allow-development", "--bundle", str(path), "--sha256", digest, *extra
        ])

    def tree(self):
        return {
            str(path.relative_to(self.root)): (stat.S_IMODE(path.lstat().st_mode), path.read_bytes())
            for path in self.root.rglob("*") if path.is_file() and not path.is_symlink()
        }

    @contextlib.contextmanager
    def isolated_host(self):
        """Model root-owned temp paths without chown or a production bypass.

        Preserve descendant file modes/types/link counts: permission and alias
        rejection still use the production checks. Only ownership and writable
        *external temp ancestry* are substituted in this unit process.
        """
        original_lstat, original_stat, original_path_open = Path.lstat, Path.stat, Path.open
        original_fstat, original_os_open = os.fstat, os.open
        self.virtual_files = {}
        virtual_directories = {
            Path("/var"), Path("/var/lib"), Path("/var/lib/aster-node"), Path("/var/lib/aster-instances"),
            Path("/var/lib/aster-artifacts"), Path("/var/lib/aster-inbox"), Path("/var/lib/aster-images"),
            Path("/etc"), Path("/etc/aster-node"),
        }
        systemd = self.root / "units"
        systemd.mkdir(exist_ok=True, mode=0o755)
        configs = {role: self.root / "config" / role / "config.json" for role in ("controller", "node")}
        for config in configs.values():
            config.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

        def owned(info, ancestor=False):
            fields = {key: getattr(info, key) for key in dir(info) if key.startswith("st_")}
            fields["st_uid"] = 0
            if ancestor:
                fields["st_mode"] &= ~0o022
            return types.SimpleNamespace(**fields)

        def root_lstat(path, *args, **kwargs):
            # Model the node unit's fixed sandbox directories, read-only. No
            # corresponding host directory is created or used for writes.
            if path in virtual_directories:
                return owned(original_lstat(self.root), ancestor=True)
            if path in self.virtual_files:
                return owned(original_lstat(self.virtual_files[path]))
            info = original_lstat(path, *args, **kwargs)
            if path == self.root or path in self.root.parents:
                return owned(info, ancestor=True)
            if self.root in path.parents:
                return owned(info)
            return info

        def virtual_stat(path, *args, **kwargs):
            if path in virtual_directories:
                return owned(original_stat(self.root), ancestor=True)
            if path in self.virtual_files:
                return owned(original_stat(self.virtual_files[path], *args, **kwargs))
            return original_stat(path, *args, **kwargs)

        def virtual_open(path, *args, **kwargs):
            return original_path_open(self.virtual_files.get(path, path), *args, **kwargs)

        def virtual_os_open(path, flags, *args, **kwargs):
            target = Path(path)
            if target in self.virtual_files:
                if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT):
                    raise AssertionError("virtual host credentials must be read-only")
                return original_os_open(self.virtual_files[target], flags, *args, **kwargs)
            if str(target).startswith(("/var/lib/aster-", "/etc/aster-node/")) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT):
                raise AssertionError("real host filesystem writes forbidden")
            return original_os_open(path, flags, *args, **kwargs)

        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(Path, "lstat", root_lstat))
            stack.enter_context(mock.patch.object(Path, "stat", virtual_stat))
            stack.enter_context(mock.patch.object(Path, "open", virtual_open))
            stack.enter_context(mock.patch.object(installer.os, "open", virtual_os_open))
            stack.enter_context(mock.patch.object(installer.os, "fstat", side_effect=lambda fd: owned(original_fstat(fd))))
            stack.enter_context(mock.patch.object(installer, "INSTALL_ROOT", self.root / "installed"))
            stack.enter_context(mock.patch.object(installer, "STATE_ROOT", self.root / "receipts"))
            stack.enter_context(mock.patch.object(installer, "SYSTEMD_ROOT", systemd))
            stack.enter_context(mock.patch.object(installer, "CONFIG_PATHS", configs))
            stack.enter_context(mock.patch.object(installer, "check_target", return_value=None))
            yield configs

    def private_file(self, relative, content, mode=0o600):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(content)
        path.chmod(mode)
        return path

    def approval_input(self, component="controller"):
        """Only a synthetic config graph; certificate acceptance is separately tested."""
        cert = self.private_file("inputs/server.crt", b"synthetic server certificate", 0o644)
        key = self.private_file("inputs/server.key", b"DO_NOT_PRINT_TEST_PRIVATE_KEY")
        ca = self.private_file("inputs/ca.crt", b"synthetic CA", 0o644)
        cfg = {"controller_id": "synthetic-controller", "listen": "127.0.0.1:9443"}
        approval = {"schema": 1, "component": "aster-cloud-" + component}
        if component == "controller":
            cfg.update({"tls_cert_file": str(cert), "tls_key_file": str(key)})
            for field, content in {
                "dsn_file": b"synthetic:DO_NOT_PRINT_TEST_DSN@unix(/run/aster-test.sock)/aster_controller_test?parseTime=true",
                "billing_token_file": b"DO_NOT_PRINT_TEST_BILLING_TOKEN_" + b"a" * 32,
                "admin_read_token_file": b"DO_NOT_PRINT_TEST_READ_TOKEN_" + b"b" * 32,
                "admin_write_token_file": b"DO_NOT_PRINT_TEST_WRITE_TOKEN_" + b"c" * 32,
            }.items():
                cfg[field] = str(self.private_file("inputs/" + field, content))
            approval.update({"console_origin": "https://console.example.invalid", "dedicated_database": True, "database_name": "aster_controller_test", "existing_administrator": True, "tls_ca_file": str(ca)})
        else:
            image = self.private_file("inputs/image.qcow2", b"synthetic-not-a-real-qcow2", 0o644)
            state, storage = self.root / "node-state", self.root / "node-storage"
            state.mkdir(mode=0o700, exist_ok=True)
            storage.mkdir(mode=0o700, exist_ok=True)
            node_paths = {"certificate": "/etc/aster-node/server.crt", "private_key": "/etc/aster-node/server.key", "controller_ca": "/etc/aster-node/controller-ca.crt"}
            self.virtual_files.update({Path(node_paths["certificate"]): cert, Path(node_paths["private_key"]): key, Path(node_paths["controller_ca"]): ca, Path("/var/lib/aster-images/synthetic.qcow2"): image})
            cfg = {
                "node_id": "synthetic-node", "maintenance": True, "allow_delete": False,
                "allow_isolated_no_nic": False, "network": {"enabled": False}, "storage": {"enabled": False},
                "images": {"synthetic": {"path": "/var/lib/aster-images/synthetic.qcow2", "sha256": sha256(image.read_bytes())}},
                "cpu_allocation_limit": 2, "memory_allocation_limit_mib": 1024, "disk_allocation_limit_gib": 10,
                "state_directory": "/var/lib/aster-node", "storage_directory": "/var/lib/aster-instances",
                **node_paths,
                "expected_controller_certificate_sha256": sha256(b"synthetic DER"),
            }
            approval.update({"dedicated_kvm_host": True, "health_origin": "https://node.example.invalid:9443"})
        config = self.private_file("inputs/config.json", json.dumps(cfg).encode())
        approval["config_file"] = str(config)
        path = self.private_file("inputs/approval.json", json.dumps(approval).encode())
        return path, approval, cfg, config

    @contextlib.contextmanager
    def synthetic_certificate_acceptance(self):
        # Never presented as cryptographic validation: real invalid-PEM and
        # protected-file checks have independent rejection tests below.
        with mock.patch.object(installer, "validate_certificate", return_value=None), mock.patch.object(installer.ssl, "create_default_context"):
            yield

    def guided_controller_inputs(self):
        _, _, cfg, _ = self.approval_input()
        return {
            "origin": "https://console.example.invalid",
            "certificate": cfg["tls_cert_file"], "private_key": cfg["tls_key_file"],
            "tls_ca_file": str(self.root / "inputs" / "ca.crt"),
            "listen": "127.0.0.1:9443", "public_listen_approved": False,
            "dsn_file": cfg["dsn_file"], "migration_dsn_file": None, "administrator_email": "admin@example.invalid",
        }

    @contextlib.contextmanager
    def dependency_host_evidence(self, *, existing=(), symlinks=(),
                                 memory="MemTotal: 2097152 kB\n", kvm_mode=stat.S_IFCHR | 0o600):
        """Virtualize only read boundaries; execute the real fresh-host guards.

        Unknown filesystem probes fail rather than falling back to this Mac or
        a pre-populated CI runner. No provisioning fixture/precondition stub is
        used by the independent guard tests.
        """
        known = set(FRESH_DEPENDENCY_PATHS + FRESH_MYSQL_PATHS)
        existing, symlinks = set(existing), set(symlinks)
        self.assertLessEqual(existing | symlinks, known)
        def exists(path):
            self.assertIn(str(path), known)
            return str(path) in existing
        def is_symlink(path):
            self.assertIn(str(path), known)
            return str(path) in symlinks
        def read_text(path, *args, **kwargs):
            self.assertEqual(str(path), "/proc/meminfo")
            if isinstance(memory, OSError):
                raise memory
            return memory
        def path_stat(path, *args, **kwargs):
            self.assertEqual(str(path), "/dev/kvm")
            if kvm_mode is None:
                raise FileNotFoundError("synthetic missing KVM device")
            return types.SimpleNamespace(st_mode=kvm_mode)
        with contextlib.ExitStack() as stack:
            probes = {}
            for name, callback in (("exists", exists), ("is_symlink", is_symlink),
                                   ("read_text", read_text), ("stat", path_stat)):
                probes[name] = stack.enter_context(mock.patch.object(Path, name, autospec=True, side_effect=callback))
            yield types.SimpleNamespace(**probes)

    @contextlib.contextmanager
    def provision_host(self):
        """Only fixture-owned provisioning paths; never real APT or MySQL."""
        provision = installer.provisioning_module()
        with self.isolated_host(), contextlib.ExitStack() as stack:
            for name in ("APT_GET", "MYSQL", "SYSTEMCTL"):
                executable = self.private_file("native-bin/" + name.lower(), b"synthetic-not-executed", 0o755)
                stack.enter_context(mock.patch.object(provision, name, str(executable)))
            keyring = self.private_file("native-host/ubuntu-keyring.gpg", b"synthetic-not-a-real-keyring", 0o644)
            constants = {
                "POLICY_PATH": self.root / "native-host/policy-rc.d",
                "APT_KEYRING": keyring,
                "APT_WORK_ROOT": self.root / "apt-work",
                "MYSQL_CONFIG": self.root / "native-host/etc-mysql",
                "MYSQL_DATA": self.root / "native-host/mysql-data",
                "MYSQL_DROPIN": self.root / "native-host/mysql.service.d/aster-cloud-local-only.conf",
                "MYSQL_SOCKET": str(self.root / "native-host/mysql.sock"),
            }
            for name, value in constants.items():
                stack.enter_context(mock.patch.object(provision, name, value))
            stack.enter_context(mock.patch.object(provision, "root_target", return_value="noble"))
            # Package/source/policy tests exercise later boundaries, not the
            # runner's databases/virt/KVM. Real fresh-host guards are covered
            # directly below with every filesystem read virtualized instead.
            stack.enter_context(mock.patch.object(provision, "fresh_dependency_host", return_value=None))
            original_exists, original_is_symlink = Path.exists, Path.is_symlink
            fixed_mysql_paths = set(FRESH_MYSQL_PATHS) - {"/etc/mysql", "/var/lib/mysql"}
            def fixture_exists(path):
                return False if str(path) in fixed_mysql_paths else original_exists(path)
            def fixture_is_symlink(path):
                return False if str(path) in fixed_mysql_paths else original_is_symlink(path)
            stack.enter_context(mock.patch.object(Path, "exists", fixture_exists))
            stack.enter_context(mock.patch.object(Path, "is_symlink", fixture_is_symlink))
            yield provision, self.root / "native-state"

    @contextlib.contextmanager
    def libvirt_host(self):
        """Later-boundary model only; real guard/readiness get separate tests."""
        with self.provision_host() as (p, state), contextlib.ExitStack() as stack:
            for name, value in {
                "UNIT_ROOT": self.root / "virt-units", "RUNTIME_UNIT_ROOT": self.root / "runtime-virt-units",
                "LIBVIRT_CONFIG": self.root / "etc-libvirt", "LIBVIRT_STATE": self.root / "libvirt-state",
                "LIBVIRT_SOCKET": self.root / "libvirt-run/libvirt-sock", "LIBVIRT_EMPTY": self.root / "empty-networks",
                "LIBVIRT_OWN_CONFIG": self.root / "etc-libvirt/aster-cloud-libvirtd.conf",
                "LIBVIRTD": str(self.root / "libvirt-bin/libvirtd"),
            }.items():
                stack.enter_context(mock.patch.object(p, name, value))
            p.UNIT_ROOT.mkdir(mode=0o755)
            p.RUNTIME_UNIT_ROOT.mkdir(mode=0o755)
            stack.enter_context(mock.patch.object(p, "fresh_libvirt_host"))
            snapshot = {"links": {"lo": {"ifindex": "1", "address": "00", "mtu": "65536"}}, "rules": {"nft": "", "iptables": "", "ip6tables": ""}}
            stack.enter_context(mock.patch.object(p, "network_snapshot", return_value=snapshot))
            namespace = stack.enter_context(mock.patch.object(p, "verify_libvirt_namespace"))
            ready = stack.enter_context(mock.patch.object(p, "verify_libvirt_daemon", return_value={"daemon": "owned-unix-only", "kvm": "not-asserted"}))
            commands = []
            def fixed(argv, **kwargs):
                commands.append((argv, kwargs))
                if argv[0] == p.APT_GET and "--assume-yes" in argv:
                    p.LIBVIRT_CONFIG.mkdir(mode=0o755, exist_ok=True)
                    # Model only vendor-created bytes, never a real network.
                    (p.LIBVIRT_CONFIG / "vendor-default.xml").write_bytes(b"vendor default kept unchanged")
                if argv[:2] == [p.SYSTEMCTL, "show"]:
                    return ("FragmentPath=" + str(p.UNIT_ROOT / argv[2]) + "\nDropInPaths=\n").encode()
                return b""
            run = stack.enter_context(mock.patch.object(p, "run_fixed", side_effect=fixed))
            yield types.SimpleNamespace(p=p, state=state, run=run, commands=commands, namespace=namespace, ready=ready)

    def test_libvirt_plan_is_explicit_node_only_and_has_no_host_actions(self):
        args = self.args("node", ("--plan", "--prepare-libvirt"))
        p = installer.provisioning_module()
        before = self.tree()
        target = {"system": "Linux", "architecture": "x86_64", "distribution": "ubuntu", "version": "24.04"}
        with mock.patch.object(p, "prepare_libvirt") as prepare, mock.patch.object(installer, "target_info", return_value=target):
            result = installer.execute(args)
        prepare.assert_not_called()
        self.assertTrue(result["native_options"]["prepare_libvirt"])
        self.assertIn("libvirt-daemon-system", result["dependency_plan"]["packages"])
        self.assertEqual(before, self.tree())
        with self.assertRaises(installer.InstallerError):
            installer.execute(self.args("controller", ("--prepare-libvirt",)))
        with self.assertRaises(p.ProvisionError):
            p.dependency_plan("controller", with_libvirt=True)

    def test_libvirt_fresh_software_guard_is_real_and_does_not_require_or_fake_kvm(self):
        p = installer.provisioning_module()
        extra = ("/var/lib/mariadb", "/etc/mysql", "/usr/sbin/mysqld", "/usr/sbin/dnsmasq", "/etc/dnsmasq.d-available/libvirt-daemon", str(p.LIBVIRT_SOCKET), p.LIBVIRTD, str(p.LIBVIRT_EMPTY))
        unit_paths = tuple(str(root / (name + suffix)) for name in p.LIBVIRT_VENDOR_UNITS + p.LIBVIRT_OWN_UNITS for root in (p.UNIT_ROOT, p.RUNTIME_UNIT_ROOT) for suffix in ("", ".d"))
        known = set(FRESH_DEPENDENCY_PATHS + extra + unit_paths)
        for collision, kind in [(None, "exists"), *((name, kind) for name in sorted(known) for kind in ("exists", "symlink"))]:
            def exists(path):
                self.assertIn(str(path), known)
                return kind == "exists" and str(path) == collision
            def symlink(path):
                self.assertIn(str(path), known)
                return kind == "symlink" and str(path) == collision
            def memory(path, *args, **kwargs):
                self.assertEqual(str(path), "/proc/meminfo")
                return "MemTotal: 2097152 kB\n"
            with self.subTest(collision=collision, kind=kind), mock.patch.object(Path, "exists", exists), mock.patch.object(Path, "is_symlink", symlink), mock.patch.object(Path, "read_text", memory), mock.patch.object(Path, "stat", side_effect=AssertionError("software preparation must never require or fake a KVM device")), mock.patch.object(p, "run_fixed") as run:
                if collision is None:
                    p.fresh_libvirt_host()
                else:
                    with self.assertRaises(p.ProvisionError):
                        p.fresh_libvirt_host()
                run.assert_not_called()
        for memory in ("MemTotal: 1048576 kB\n", "unknown"):
            with mock.patch.object(Path, "exists", return_value=False), mock.patch.object(Path, "is_symlink", return_value=False), mock.patch.object(Path, "read_text", return_value=memory), self.assertRaises(p.ProvisionError):
                p.fresh_libvirt_host()

    def test_libvirt_package_path_cannot_be_used_without_outer_ownership_receipt(self):
        with self.provision_host() as (p, state), mock.patch.object(p, "run_fixed") as run:
            with self.assertRaises(p.ProvisionError):
                p.install_dependencies("node", state, with_libvirt=True)
            run.assert_not_called()

    def test_libvirt_foreign_policy_refuses_before_any_mask_or_apt(self):
        with self.libvirt_host() as h:
            h.p.POLICY_PATH.write_bytes(b"foreign policy never overwrite")
            with self.assertRaises(h.p.ProvisionError):
                h.p.prepare_libvirt(h.state)
            self.assertEqual(h.p.POLICY_PATH.read_bytes(), b"foreign policy never overwrite")
            self.assertEqual(list(h.p.UNIT_ROOT.iterdir()), [])
            h.run.assert_not_called()

    def test_libvirt_legacy_receipt_cannot_add_preparation_on_resume(self):
        args = self.args("node", ("--apply",))
        p = installer.provisioning_module()
        with self.isolated_host():
            installer.execute(args)
            receipt_path = installer.STATE_ROOT / "node/state.json"
            receipt = json.loads(receipt_path.read_text())
            receipt["native_options"].pop("prepare_libvirt")
            receipt_path.write_text(json.dumps(receipt))
            original = receipt_path.read_bytes()
            args.resume, args.prepare_libvirt = True, True
            with mock.patch.object(p, "prepare_libvirt") as prepare, self.assertRaises(installer.InstallerError):
                installer.execute(args)
            prepare.assert_not_called()
            self.assertEqual(receipt_path.read_bytes(), original)

    def test_libvirt_fresh_prepare_masks_every_vendor_activation_before_apt(self):
        with self.libvirt_host() as h:
            result = h.p.prepare_libvirt(h.state)
            self.assertEqual(result["status"], "libvirt-prepared")
            self.assertEqual(result["kvm"], "not-asserted")
            receipt = json.loads((h.state / "libvirt.json").read_text())
            self.assertEqual(set(receipt["masks"]), set(h.p.LIBVIRT_VENDOR_UNITS))
            for name in h.p.LIBVIRT_VENDOR_UNITS:
                self.assertEqual(os.readlink(h.p.UNIT_ROOT / name), "/dev/null")
            h.p.verify_libvirt_masks(receipt)
            self.assertFalse(h.p.POLICY_PATH.exists())
            self.assertEqual((h.p.LIBVIRT_CONFIG / "vendor-default.xml").read_bytes(), b"vendor default kept unchanged")
            for argv, _ in h.commands:
                self.assertNotIn("unmask", argv)
                if argv[0] == h.p.SYSTEMCTL and "start" in argv:
                    self.assertEqual(argv[2:], list(h.p.LIBVIRT_OWN_UNITS))
            h.namespace.assert_called_once_with()
            h.ready.assert_called_once_with(owned=True)
            for name in h.p.LIBVIRT_OWN_UNITS:
                raw = (h.p.UNIT_ROOT / name).read_bytes()
                self.assertNotIn(b"security_driver", raw)
                self.assertNotIn(b"--listen", raw)
            self.assertIn(b"BindReadOnlyPaths=", h.p.libvirt_unit_bytes("aster-cloud-libvirtd.service"))
            self.assertEqual(list((h.p.LIBVIRT_EMPTY / "autostart").iterdir()), [])

    def test_libvirt_failed_or_lost_start_ack_preserves_masks_and_stops_only_owned_services(self):
        with self.libvirt_host() as h:
            original = h.run.side_effect
            def fail_start(argv, **kwargs):
                if argv[:2] == [h.p.SYSTEMCTL, "start"]:
                    h.commands.append((argv, kwargs))
                    raise h.p.ProvisionError("synthetic acknowledgement lost")
                return original(argv, **kwargs)
            h.run.side_effect = fail_start
            with self.assertRaises(h.p.ProvisionError):
                h.p.prepare_libvirt(h.state)
            receipt = json.loads((h.state / "libvirt.json").read_text())
            self.assertEqual(receipt["status"], "failed-review-required")
            self.assertEqual(receipt["cleanup"], "owned-daemons-stopped")
            self.assertIn(([h.p.SYSTEMCTL, "stop", *reversed(h.p.LIBVIRT_OWN_UNITS)], {}), h.commands)
            h.p.verify_libvirt_masks(receipt)
            self.assertFalse(any(argv[:2] == [h.p.SYSTEMCTL, "enable"] for argv, _ in h.commands))
            h.run.side_effect = original
            self.assertEqual(h.p.prepare_libvirt(h.state, resume=True)["status"], "libvirt-prepared")

    def test_libvirt_target_packages_match_preview_and_keep_no_recommends(self):
        p = installer.provisioning_module()
        for version, codename in p.CODENAMES.items():
            with self.subTest(version=version), tempfile.TemporaryDirectory(dir=self.root) as temporary, mock.patch.object(self, "root", Path(temporary)):
                args = self.args("node", ("--plan", "--prepare-libvirt"))
                target = {"system": "Linux", "architecture": "x86_64", "distribution": "ubuntu", "version": version}
                with mock.patch.object(installer, "target_info", return_value=target), mock.patch.object(installer.os, "geteuid", return_value=501):
                    preview = installer.execute(args)["dependency_plan"]["packages"]
                with self.libvirt_host() as h, mock.patch.object(h.p, "root_target", return_value=codename):
                    h.p.prepare_libvirt(h.state)
                    expected = list(h.p.PACKAGES["node"]) + ["libvirt-daemon-system"]
                    self.assertEqual(preview, expected)
                    package_commands = [argv for argv, _ in h.commands if argv[0] == h.p.APT_GET and "install" in argv]
                    self.assertEqual(len(package_commands), 2)
                    for argv in package_commands:
                        self.assertEqual(argv[argv.index("install") + 1:], expected)
                        for option in ("--no-install-recommends", "--no-upgrade", "--no-remove"):
                            self.assertIn(option, argv)
                    receipt = json.loads((h.state / "libvirt.json").read_text())
                    self.assertEqual(receipt["codename"], codename)
                    self.assertEqual(receipt["plan_sha256"], h.p.libvirt_plan_digest(codename))

    def test_libvirt_plan_rejects_unknown_target_without_blocking_plain_offline_plan(self):
        args = self.args("node", ("--plan", "--prepare-libvirt"))
        base = {"system": "Linux", "architecture": "x86_64", "distribution": "ubuntu", "version": "24.04"}
        p = installer.provisioning_module()
        for change in ({"system": "Darwin"}, {"architecture": "aarch64"}, {"distribution": "debian"}, {"version": "unknown"}, {"version": "26.04"}):
            with self.subTest(change=change), mock.patch.object(installer, "target_info", return_value={**base, **change}), mock.patch.object(p, "run_fixed") as run:
                with self.assertRaisesRegex(installer.InstallerError, "verified Ubuntu"):
                    installer.execute(args)
                args.prepare_libvirt = False
                try:
                    plan = installer.execute(args)
                    self.assertEqual(plan["mode"], "plan")
                    self.assertEqual(plan["target_support"], "unsupported-no-apply")
                    self.assertEqual(plan["supported_ubuntu"], ["22.04", "24.04"])
                finally:
                    args.prepare_libvirt = True
                run.assert_not_called()

    def test_libvirt_resume_refuses_deferred_release_receipt_before_host_commands(self):
        with self.libvirt_host() as h:
            h.p.prepare_libvirt(h.state)
            path = h.state / "libvirt.json"
            original = json.loads(path.read_text())
            # A historic 26 receipt cannot authorize a supported 22/24 host,
            # even if someone substitutes the currently approved package hash.
            for change in ({"codename": "resolute"}, {"codename": "resolute", "plan_sha256": "0" * 64}):
                with self.subTest(change=change):
                    path.write_text(json.dumps({**original, **change}))
                    before = self.tree()
                    h.run.reset_mock()
                    with self.assertRaisesRegex(h.p.ProvisionError, "resume plan"):
                        h.p.prepare_libvirt(h.state, resume=True)
                    with self.assertRaisesRegex(h.p.ProvisionError, "owned preparation transaction"):
                        h.p.install_dependencies("node", h.state, with_libvirt=True, resume=True)
                    h.run.assert_not_called()
                    self.assertEqual(before, self.tree())

    def test_libvirt_resume_refuses_changed_plan_and_foreign_same_content_mask(self):
        with self.libvirt_host() as h:
            h.p.prepare_libvirt(h.state)
            path = h.state / "libvirt.json"
            original = path.read_bytes()
            receipt = json.loads(original)
            receipt["plan_sha256"] = "0" * 64
            path.write_text(json.dumps(receipt))
            h.run.reset_mock()
            with self.assertRaisesRegex(h.p.ProvisionError, "resume plan"):
                h.p.prepare_libvirt(h.state, resume=True)
            h.run.assert_not_called()
            path.write_bytes(original)
            name = h.p.LIBVIRT_VENDOR_UNITS[0]
            replaced = h.p.UNIT_ROOT / name
            aside = h.p.UNIT_ROOT / "old-mask"
            replaced.rename(aside)
            replaced.symlink_to("/dev/null")
            with self.assertRaisesRegex(h.p.ProvisionError, "mask changed"):
                h.p.prepare_libvirt(h.state, resume=True)
            h.run.assert_not_called()
            self.assertTrue(aside.is_symlink())

    def test_libvirt_existing_host_is_readonly_and_never_reconfigured_or_started(self):
        with self.libvirt_host() as h:
            h.p.LIBVIRT_CONFIG.mkdir(mode=0o755)
            original = h.p.LIBVIRT_CONFIG / "qemu.conf"
            original.write_bytes(b"foreign reviewed qemu policy")
            h.ready.return_value = {"daemon": "preserved-existing", "kvm": "not-asserted"}
            result = h.p.prepare_libvirt(h.state)
            self.assertEqual(result["daemon"], "preserved-existing")
            self.assertEqual(original.read_bytes(), b"foreign reviewed qemu policy")
            self.assertEqual(h.commands, [([h.p.SYSTEMCTL, "is-active", "--quiet", "libvirtd.service"], {})])
            self.assertEqual(list(h.p.UNIT_ROOT.iterdir()), [])
            self.assertFalse(h.p.POLICY_PATH.exists())
            h.ready.assert_called_once_with()

    def test_libvirt_existing_inactive_host_is_not_socket_activated_or_adopted(self):
        with self.libvirt_host() as h:
            h.p.LIBVIRT_CONFIG.mkdir(mode=0o755)
            h.run.side_effect = h.p.ProvisionError("not active")
            with self.assertRaises(h.p.ProvisionError):
                h.p.prepare_libvirt(h.state)
            h.ready.assert_not_called()
            self.assertFalse((h.state / "libvirt.json").exists())

    def test_libvirt_real_readiness_commands_are_fixed_readonly_and_no_kvm_claim(self):
        p = installer.provisioning_module()
        caps = b"<capabilities><host/><guest><arch name='x86_64'/></guest></capabilities>"
        with mock.patch.object(p, "protected_path"), mock.patch.object(Path, "lstat", return_value=types.SimpleNamespace(st_uid=0, st_mode=stat.S_IFSOCK | 0o700)), mock.patch.object(p, "run_fixed", side_effect=[b"", b"", caps]) as run:
            self.assertEqual(p.verify_libvirt_daemon(owned=True)["kvm"], "not-asserted")
        self.assertEqual([call.args[0] for call in run.call_args_list], [[p.VIRSH, "--connect", "qemu:///system", "--readonly", *tail] for tail in (("list", "--all", "--name"), ("net-list", "--all", "--name"), ("capabilities",))])
        for values in ([b"existing-domain", b"", caps], [b"", b"default", caps], [b"", b"", b"<not-capabilities/>"]):
            with self.subTest(values=values), mock.patch.object(p, "protected_path"), mock.patch.object(Path, "lstat", return_value=types.SimpleNamespace(st_uid=0, st_mode=stat.S_IFSOCK | 0o700)), mock.patch.object(p, "run_fixed", side_effect=values), self.assertRaises(p.ProvisionError):
                p.verify_libvirt_daemon(owned=True)

    def test_libvirt_network_or_firewall_change_is_not_accepted(self):
        p = installer.provisioning_module()
        before = {"links": {"eth0": {}}, "rules": {"nft": "", "iptables": None}}
        p.verify_network_unchanged(before, {"links": before["links"], "rules": {"nft": "", "iptables": ""}})
        for after in ({"links": {"virbr0": {}}, "rules": before["rules"]}, {"links": before["links"], "rules": {"nft": "table ip libvirt {}", "iptables": None}}):
            with self.subTest(after=after), self.assertRaises(p.ProvisionError):
                p.verify_network_unchanged(before, after)

    def test_libvirt_software_prepared_never_skips_node_kvm_preflight(self):
        args = self.args("node", ("--apply", "--start", "--prepare-libvirt"))
        p = installer.provisioning_module()
        with self.isolated_host(), self.synthetic_certificate_acceptance():
            args.approval, _, _, _ = self.approval_input("node")
            with mock.patch.object(p, "prepare_libvirt", return_value={"status": "libvirt-prepared", "kvm": "not-asserted"}) as prepare, mock.patch.object(installer, "node_preflight", return_value=["kvm-unavailable"]), mock.patch.object(installer, "run_fixed") as run:
                with self.assertRaisesRegex(installer.InstallerError, "not KVM readiness"):
                    installer.execute(args)
            prepare.assert_called_once()
            run.assert_not_called()
            receipt = json.loads((installer.STATE_ROOT / "node/state.json").read_text())
            self.assertEqual(receipt["libvirt_preparation"]["kvm"], "not-asserted")
            self.assertEqual(receipt["service"], "not-started")

    def test_release_envelope_requires_offline_publisher_verification_not_development_opt_in(self):
        payload = self.payload()
        manifest = self.manifest(payload)
        manifest.update(release_kind="release", version="0.1.0-rc.1", channel="prerelease", release_tag="cloud-v0.1.0-rc.1")
        path, digest = self.archive(payload, manifest)
        args = installer.build_parser().parse_args(["controller", "--bundle", str(path), "--sha256", digest, "--allow-development"])
        with self.assertRaises(installer.InstallerError):
            installer.execute(args)
        args.allow_development = False
        args.release_receipt = str(self.private_file("release-receipt.json", b'{"verified":true}'))
        module = types.SimpleNamespace(ReleaseError=type("ReleaseError", (Exception,), {}), verify_release_receipt=mock.Mock(return_value={"channel": "prerelease"}))
        with mock.patch.object(installer, "RELEASE_MODULE", module):
            result = installer.execute(args)
        self.assertEqual(result["release_kind"], "release")
        module.verify_release_receipt.assert_called_once_with(str(path), digest, "aster-cloud-controller", manifest, args.release_receipt, offline=True)
        module.verify_release_receipt.side_effect = module.ReleaseError("forged receipt")
        with mock.patch.object(installer, "RELEASE_MODULE", module), self.assertRaises(installer.InstallerError):
            installer.execute(args)

    def test_release_mode_cannot_authorize_development_or_stable_versions(self):
        args = self.args()
        args.allow_development = False
        args.release_receipt = str(self.root / "receipt.json")
        module = mock.Mock()
        with mock.patch.object(installer, "RELEASE_MODULE", module), self.assertRaises(installer.InstallerError):
            installer.execute(args)
        module.verify_release_receipt.assert_not_called()
        payload = self.payload()
        for version, channel in (("0.1.0", "stable"), ("0.2.0-rc.1", "prerelease"), ("0.1.0-rc.1", "stable")):
            manifest = self.manifest(payload)
            manifest.update(release_kind="release", version=version, channel=channel)
            self.rejected(*self.archive(payload, manifest))

    def test_valid_controller_bundle_is_verified_without_writes(self):
        path, digest = self.archive()
        before = self.tree()
        result = self.verify(path, digest)
        self.assertEqual(result.manifest["component"], "aster-cloud-controller")
        self.assertEqual(result.files["bin/aster-controller"], ELF_HEADER + b"synthetic-controller\n")
        self.assertEqual(before, self.tree())

    def test_valid_node_bundle_is_verified(self):
        path, digest = self.archive(component="node")
        result = self.verify(path, digest, "node")
        self.assertEqual(set(result.files), {"bin/aster-node", "bin/aster-network"})

    def test_external_sha256_is_mandatory_and_exact(self):
        path, digest = self.archive()
        for bad in ("", "x" * 64, "0" * 64, digest.upper(), digest[:-1]):
            with self.subTest(digest=bad):
                self.rejected(path, bad)

    def test_hash_then_source_replacement_or_same_inode_write_cannot_change_verified_bytes(self):
        # Change the source immediately AFTER the external SHA completes. For
        # in-place writes preserve both size and mtime: an inode+mtime check
        # alone must not allow hash(A), parse/install(B).
        original_sha = hashlib.sha256
        for mutation in ("replace-path", "same-inode-same-mtime"):
            with self.subTest(mutation=mutation):
                path, _ = self.archive()
                payload = self.payload()
                payload["ui/index.html"] = (b"<p>malicious UI</p>\n", 0o644)
                alternate, _ = self.archive(payload)
                approved = gzip.compress(gzip.decompress(path.read_bytes()), compresslevel=0, mtime=0)
                changed = gzip.compress(gzip.decompress(alternate.read_bytes()), compresslevel=0, mtime=0)
                self.assertEqual(len(approved), len(changed))
                path.write_bytes(approved)
                alternate.write_bytes(changed)
                prior = path.stat()
                expected = original_sha(approved).hexdigest()
                mutated = []

                class MutationAfterDigest:
                    def __init__(self, value=b"", **kwargs):
                        self.real = original_sha(value, **kwargs)

                    def update(self, value):
                        return self.real.update(value)

                    def hexdigest(self):
                        result = self.real.hexdigest()
                        if result == expected and not mutated:
                            mutated.append(True)
                            if mutation == "replace-path":
                                os.replace(alternate, path)
                            else:
                                path.write_bytes(changed)
                                os.utime(path, ns=(prior.st_atime_ns, prior.st_mtime_ns))
                        return result

                with mock.patch.object(installer.hashlib, "sha256", MutationAfterDigest):
                    try:
                        verified = self.verify(path, expected)
                    except installer.InstallerError:
                        verified = None
                self.assertTrue(mutated, "the test must actually mutate after the full archive digest")
                if verified is not None:
                    self.assertEqual(verified.files["ui/index.html"], b"<p>synthetic UI</p>\n")

    def test_manifest_hash_size_and_mode_are_independently_enforced(self):
        payload = self.payload()
        for field, value in (("sha256", "0" * 64), ("size", 999), ("mode", "0644")):
            with self.subTest(field=field):
                manifest = self.manifest(payload)
                manifest["files"][0][field] = value
                self.rejected(*self.archive(payload, manifest))

    def test_real_packager_ustar_envelope_and_extra_metadata_match_verifier(self):
        path = Path(__file__).resolve().parents[1] / "scripts" / "package-cloud.py"
        spec = importlib.util.spec_from_file_location("aster_cloud_package_envelope_test", path)
        package = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(package)
        for role in ("controller", "node"):
            with self.subTest(role=role):
                payload = self.payload(role)
                manifest = self.manifest(payload, role)
                manifest.update({"role": role, "protocols": ["aster.controller/1", "aster.node/1"], "data_schemas": {"synthetic": 1}, "build": {"go_toolchain": "go1.27.3"}})
                target = self.root / ("packager-" + role + ".tar.gz")
                package.write_archive(target, {name: (raw, format(mode, "04o")) for name, (raw, mode) in payload.items()}, manifest, 0)
                self.assertEqual(self.verify(target, sha256(target.read_bytes()), role).manifest, manifest)

    def test_wrong_component_and_platform_are_rejected(self):
        path, digest = self.archive()
        self.rejected(path, digest, "node")
        payload = self.payload()
        for field, value in (("schema", 2), ("component", "vps-billing"), ("platform", "linux-arm64"), ("release_kind", "official"), ("source_commit", "not-a-commit")):
            with self.subTest(field=field):
                manifest = self.manifest(payload)
                manifest[field] = value
                self.rejected(*self.archive(payload, manifest))

    def test_manifest_cannot_omit_or_duplicate_inventory(self):
        payload = self.payload()
        manifest = self.manifest(payload)
        manifest["files"] = manifest["files"][1:]
        self.rejected(*self.archive(payload, manifest))
        manifest = self.manifest(payload)
        manifest["files"].append(dict(manifest["files"][0]))
        self.rejected(*self.archive(payload, manifest))
        self.rejected(*self.archive(omit=("ui/index.html",)))

    def test_bundle_parent_file_collision_is_rejected_before_install(self):
        payload = self.payload()
        payload["ui/assets"] = (b"not a directory", 0o644)
        payload["ui/assets/app.js"] = (b"synthetic", 0o644)
        path, digest = self.archive(payload)
        self.rejected(path, digest)

    def test_malformed_manifest_and_duplicate_json_keys_are_rejected(self):
        for value in (b"not JSON", b"[]", b'{"schema":1,"schema":1}', b'{"schema":true}'):
            with self.subTest(value=value):
                self.rejected(*self.archive(manifest=value))

    def test_unsafe_member_names_are_rejected(self):
        for name in ("../escape", "/tmp/escape", "bin/../../escape", "./bin/aster-controller", "bin//aster-controller", "bin\\escape", "C:/escape"):
            with self.subTest(name=name):
                info = tarfile.TarInfo(name)
                info.mode, info.size = 0o644, 1
                self.rejected(*self.archive(extra=((info, b"x"),)))
        self.assertFalse((self.root.parent / "escape").exists())

    def test_links_and_special_files_are_rejected(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE, tarfile.DIRTYPE):
            with self.subTest(kind=kind):
                info = tarfile.TarInfo("unexpected")
                info.type, info.mode, info.linkname = kind, 0o644, "../../escape"
                self.rejected(*self.archive(extra=((info, None),)))

    def test_duplicate_tar_members_including_manifest_are_rejected(self):
        for name in ("manifest.json", "bin/aster-controller"):
            with self.subTest(name=name):
                info = tarfile.TarInfo(name)
                info.mode, info.size = 0o644, 1
                self.rejected(*self.archive(extra=((info, b"x"),)))

    def test_pax_path_traversal_is_rejected(self):
        info = tarfile.TarInfo("apparently-safe")
        info.mode, info.size = 0o644, 1
        info.pax_headers = {"path": "../escape"}
        self.rejected(*self.archive(extra=((info, b"x"),)))

    def test_extension_headers_are_rejected_before_reading_declared_metadata(self):
        # The stdlib tar iterator eagerly reads PAX/GNU payloads before yielding
        # a member. These raw headers prove refusal before such an allocation.
        original_gzip = gzip.GzipFile
        for kind in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK, tarfile.GNUTYPE_SPARSE):
            with self.subTest(kind=kind):
                info = tarfile.TarInfo("docs/metadata")
                info.type, info.mode, info.size = kind, 0o644, 16384
                path = self.root / ("metadata-%s.tar.gz" % kind.hex())
                path.write_bytes(gzip.compress(info.tobuf(format=tarfile.USTAR_FORMAT) + b"\0" * 1024))
                reads = []

                class BoundedMetadataReader:
                    def __init__(self, *args, **kwargs):
                        self.stream = original_gzip(*args, **kwargs)

                    def read(self, size=-1):
                        reads.append(size)
                        if not 0 <= size <= 10241:
                            raise AssertionError("extension payload must not be eagerly read")
                        return self.stream.read(size)

                    def close(self):
                        self.stream.close()

                with mock.patch.object(installer.gzip, "GzipFile", BoundedMetadataReader), mock.patch.object(installer, "MAX_FILE_BYTES", 16):
                    self.rejected(path, sha256(path.read_bytes()))
                self.assertEqual(reads, [512])

    def test_trailing_nonzero_data_is_not_an_unchecked_second_archive(self):
        path, _ = self.archive()
        raw = gzip.decompress(path.read_bytes()) + b"unexpected trailing payload"
        path.write_bytes(gzip.compress(raw))
        self.rejected(path, sha256(path.read_bytes()))

    def test_privileged_or_world_writable_payload_modes_are_rejected(self):
        for mode in (0o4755, 0o2755, 0o777, 0o666):
            with self.subTest(mode=mode):
                payload = self.payload()
                payload["bin/aster-controller"] = (ELF_HEADER + b"synthetic-controller\n", mode)
                self.rejected(*self.archive(payload))

    def test_archive_file_total_manifest_and_count_limits_are_enforced(self):
        # Lower limits in this unit process; exercise actual paths without a
        # 512 MiB allocation, sparse files, production overrides or unsafe CLI.
        path, digest = self.archive()
        for constant, limit in (("MAX_ARCHIVE_BYTES", 1), ("MAX_TOTAL_BYTES", 1), ("MAX_FILE_BYTES", 1), ("MAX_FILES", 1), ("MAX_MANIFEST_BYTES", 1)):
            with self.subTest(constant=constant), mock.patch.object(installer, constant, limit):
                self.rejected(path, digest)

    def test_symlink_bundle_input_is_rejected(self):
        path, digest = self.archive()
        link = self.root / "symlink.tar.gz"
        link.symlink_to(path)
        self.rejected(link, digest)

    def test_hardlinked_bundle_input_is_rejected(self):
        path, digest = self.archive()
        os.link(path, self.root / "hardlink.tar.gz")
        self.rejected(path, digest)

    def test_non_elf_or_wrong_architecture_executable_is_rejected(self):
        for data in (b"#!/bin/sh\nexit 0\n", b"\x7fELF\x01\x01" + b"\0" * 32, ELF_HEADER[:18] + b"\xb7\0" + ELF_HEADER[20:]):
            with self.subTest(data=data):
                payload = self.payload()
                payload["bin/aster-controller"] = (data, 0o755)
                self.rejected(*self.archive(payload))

    def test_default_plan_is_nonroot_and_zero_side_effect(self):
        args = self.args()
        before = self.tree()
        with mock.patch.object(installer.os, "geteuid", return_value=501):
            result = installer.make_plan(args)
        self.assertIsInstance(result, dict)
        self.assertEqual(before, self.tree())

    def test_plan_and_dry_run_do_not_execute_or_print_secret_content(self):
        for flags in (("--plan",), ("--dry-run",)):
            with self.subTest(flags=flags):
                args = self.args(extra=flags)
                before = self.tree()
                output = io.StringIO()
                with mock.patch.object(installer.os, "geteuid", return_value=501), contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                    result = installer.execute(args)
                rendered = output.getvalue() + json.dumps(result)
                self.assertNotIn("synthetic-controller", rendered)
                self.assertEqual(before, self.tree())

    def test_candidate_bundle_never_becomes_an_official_release(self):
        args = self.args()
        args.allow_development = False
        with self.assertRaises(installer.InstallerError):
            installer.make_plan(args)

    def test_missing_official_release_fails_without_download_or_install(self):
        args = installer.build_parser().parse_args(["controller"])
        before = self.tree()
        with self.assertRaises(installer.InstallerError):
            installer.execute(args)
        self.assertEqual(before, self.tree())

    def test_cli_has_no_test_only_ownership_or_host_command_bypass(self):
        for flag in ("--unsafe", "--root-prefix", "--skip-tls-verify", "--runner-command", "--test-owner"):
            with self.subTest(flag=flag), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                installer.build_parser().parse_args(["node", flag])

    def test_apply_cannot_run_as_nonroot(self):
        args = self.args(extra=("--apply",))
        before = self.tree()
        with mock.patch.object(installer.os, "geteuid", return_value=501), self.assertRaises(installer.InstallerError):
            installer.execute(args)
        self.assertEqual(before, self.tree())

    def test_root_private_input_rejects_readable_aliases_and_shared_writes(self):
        with self.isolated_host():
            secret = self.private_file("private/secret", b"DO_NOT_PRINT_TEST_SECRET")
            self.assertEqual(installer.protected_read(str(secret)), b"DO_NOT_PRINT_TEST_SECRET")
            for mode in (0o640, 0o644, 0o620):
                with self.subTest(mode=mode):
                    secret.chmod(mode)
                    with self.assertRaises(installer.InstallerError):
                        installer.protected_read(str(secret))
            secret.chmod(0o600)
            symlink = self.root / "private" / "alias"
            symlink.symlink_to(secret)
            with self.assertRaises(installer.InstallerError):
                installer.protected_read(str(symlink))
            os.link(secret, self.root / "private" / "hardlink")
            with self.assertRaises(installer.InstallerError):
                installer.protected_read(str(secret))

    def test_invalid_certificate_is_rejected_without_echoing_key(self):
        with self.isolated_host():
            cert = self.private_file("inputs/bad.crt", b"not a certificate", 0o644)
            key = self.private_file("inputs/bad.key", b"DO_NOT_PRINT_TEST_PRIVATE_KEY")
            with self.assertRaises(installer.InstallerError) as rejected:
                installer.validate_certificate(str(cert), str(key), "console.example.invalid")
            self.assertNotIn("DO_NOT_PRINT", str(rejected.exception))

    def test_controller_approval_requires_root_private_config_and_dedicated_database(self):
        with self.isolated_host(), self.synthetic_certificate_acceptance():
            approval, document, cfg, config = self.approval_input()
            args = self.args(extra=("--approval", str(approval)))
            loaded, loaded_config, raw, digest = installer.load_approval(args)
            self.assertEqual(loaded["component"], "aster-cloud-controller")
            self.assertEqual(raw, config.read_bytes())
            self.assertEqual(loaded_config["controller_id"], "synthetic-controller")
            self.assertEqual(len(digest), 64)
            for field, value in (("dedicated_database", False), ("database_name", "vps_billing"), ("console_origin", "http://console.example.invalid")):
                with self.subTest(field=field):
                    changed = dict(document, **{field: value})
                    approval.write_text(json.dumps(changed))
                    with self.assertRaises(installer.InstallerError):
                        installer.load_approval(args)
            approval.write_text(json.dumps(document))
            config.chmod(0o644)
            with self.assertRaises(installer.InstallerError):
                installer.load_approval(args)

    def test_migration_credentials_require_same_dedicated_database_and_different_identity(self):
        with self.isolated_host():
            runtime = self.private_file("inputs/runtime-dsn", b"aster_runtime:DO_NOT_PRINT_RUNTIME@unix(/run/synthetic.sock)/aster_controller_test")
            migration = self.private_file("inputs/migration-dsn", b"aster_migrator:DO_NOT_PRINT_DDL@unix(/run/synthetic.sock)/aster_controller_test")
            self.assertEqual(installer.validate_dsn_pair(str(runtime), str(migration)), "aster_controller_test")
            for bad in (
                b"aster_runtime:different@unix(/run/synthetic.sock)/aster_controller_test",
                b"aster_migrator:secret@unix(/run/synthetic.sock)/aster_cloud_other",
                b"root:secret@unix(/run/synthetic.sock)/aster_controller_test",
                b"aster_migrator:secret@tcp(192.0.2.9:3306)/aster_controller_test",
                b"aster_migrator:secret@unix(/run/synthetic.sock)/vps_billing",
            ):
                with self.subTest(dsn=bad.split(b"@", 1)[-1]):
                    migration.write_bytes(bad)
                    with self.assertRaises(installer.InstallerError) as rejected:
                        installer.validate_dsn_pair(str(runtime), str(migration))
                    self.assertNotIn("DO_NOT_PRINT", str(rejected.exception))

    def test_current_controller_schema_never_runs_migration_with_runtime_credentials(self):
        with self.isolated_host(), self.synthetic_certificate_acceptance():
            approval, _, _, _ = self.approval_input()
            args = self.args(extra=("--apply", "--approval", str(approval), "--start"))
            with mock.patch.object(installer, "run_fixed", return_value=b"") as run, mock.patch.object(installer, "strict_health"):
                result = installer.execute(args)
            self.assertEqual(result["service"], "ready")
            calls = [call.args[0] for call in run.call_args_list]
            self.assertTrue(any("check" in argv for argv in calls))
            self.assertFalse(any("migrate" in argv for argv in calls), "a current schema needs no DDL identity")

    def test_fresh_controller_schema_without_migration_identity_never_starts(self):
        with self.isolated_host(), self.synthetic_certificate_acceptance():
            approval, _, _, _ = self.approval_input()
            args = self.args(extra=("--apply", "--approval", str(approval), "--start"))

            def missing_schema(argv, **kwargs):
                if "check" in argv:
                    raise installer.InstallerError("synthetic schema unavailable")
                return b""

            with mock.patch.object(installer, "run_fixed", side_effect=missing_schema) as run, mock.patch.object(installer, "strict_health") as health:
                with self.assertRaises(installer.InstallerError):
                    installer.execute(args)
            calls = [call.args[0] for call in run.call_args_list]
            self.assertFalse(any("migrate" in argv for argv in calls))
            self.assertFalse(any("start" in argv for argv in calls))
            health.assert_not_called()

    def test_fresh_controller_migration_uses_separate_private_config_never_runtime_unit(self):
        with self.isolated_host(), self.synthetic_certificate_acceptance():
            approval, document, _, _ = self.approval_input()
            ddl = self.private_file("inputs/ddl-dsn", b"aster_migrator:DO_NOT_PRINT_DDL@unix(/run/aster-test.sock)/aster_controller_test?parseTime=true")
            document["migration_dsn_file"] = str(ddl)
            approval.write_text(json.dumps(document))
            args = self.args(extra=("--apply", "--approval", str(approval), "--start"))
            checks, migrations = [], []

            def commands(argv, **kwargs):
                if "check" in argv:
                    checks.append(argv)
                    if len(checks) == 1:
                        raise installer.InstallerError("synthetic schema unavailable")
                if "migrate" in argv:
                    config = Path(argv[argv.index("-config") + 1])
                    self.assertNotEqual(config, installer.CONFIG_PATHS["controller"])
                    self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o600)
                    self.assertEqual(json.loads(config.read_text())["dsn_file"], str(ddl))
                    migrations.append(config)
                return b""

            with mock.patch.object(installer, "run_fixed", side_effect=commands), mock.patch.object(installer, "strict_health"):
                result = installer.execute(args)
            self.assertEqual(result["service"], "ready")
            self.assertEqual(len(migrations), 1)
            self.assertEqual(len(checks), 2)
            runtime = json.loads(installer.CONFIG_PATHS["controller"].read_text())
            self.assertNotEqual(runtime["dsn_file"], str(ddl))
            unit = (installer.SYSTEMD_ROOT / "aster-controller.service").read_text()
            self.assertNotIn(str(ddl), unit)
            self.assertNotIn(str(migrations[0]), unit)
            self.assertNotIn("DO_NOT_PRINT", json.dumps(result))

    def test_software_only_install_never_starts_or_rewrites_unknown_secrets(self):
        with self.isolated_host() as configs:
            args = self.args(extra=("--apply",))
            original = b"DO_NOT_PRINT_EXISTING_PRIVATE_CONFIG"
            configs["controller"].write_bytes(original)
            configs["controller"].chmod(0o600)
            with mock.patch.object(installer, "run_fixed") as run, mock.patch.object(installer, "strict_health") as health:
                result = installer.execute(args)
            self.assertEqual(result["status"], "software-installed")
            self.assertEqual(result["service"], "not-started")
            self.assertEqual(configs["controller"].read_bytes(), original)
            self.assertFalse((installer.SYSTEMD_ROOT / "aster-controller.service").exists())
            self.assertNotIn("DO_NOT_PRINT", json.dumps(result))
            run.assert_not_called()
            health.assert_not_called()

    def test_restrictive_caller_umask_does_not_change_verified_payload_modes(self):
        with self.isolated_host():
            args = self.args(extra=("--apply",))
            previous = os.umask(0o077)
            try:
                installer.execute(args)
            finally:
                os.umask(previous)
            version = installer.INSTALL_ROOT / "controller" / "versions" / ("0.1.0-dev-" + args.sha256[:16])
            self.assertEqual(stat.S_IMODE((version / "bin/aster-controller").stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE((version / "ui/index.html").stat().st_mode), 0o644)
            self.assertEqual(stat.S_IMODE((installer.STATE_ROOT / "controller/state.json").stat().st_mode), 0o600)

    def test_existing_different_config_fails_before_any_install_write(self):
        with self.isolated_host() as configs, self.synthetic_certificate_acceptance():
            approval, _, _, _ = self.approval_input()
            args = self.args(extra=("--apply", "--approval", str(approval)))
            configs["controller"].write_bytes(b"DO_NOT_PRINT_EXISTING_PRIVATE_CONFIG")
            configs["controller"].chmod(0o600)
            before = self.tree()
            with self.assertRaises(installer.InstallerError) as rejected:
                installer.execute(args)
            self.assertNotIn("DO_NOT_PRINT", str(rejected.exception))
            self.assertEqual(before, self.tree())

    def test_existing_unit_is_not_silently_replaced(self):
        with self.isolated_host():
            args = self.args(extra=("--apply",))
            unit = self.private_file("units/aster-controller.service", b"# existing operator policy\n", 0o644)
            before = self.tree()
            with self.assertRaises(installer.InstallerError):
                installer.execute(args)
            self.assertEqual(unit.read_bytes(), b"# existing operator policy\n")
            self.assertEqual(before, self.tree())

    def test_broken_config_or_unit_symlink_cannot_be_mistaken_for_a_fresh_install(self):
        for target in ("config", "unit"):
            with self.subTest(target=target), self.isolated_host() as configs:
                args = self.args(extra=("--apply",))
                path = configs["controller"] if target == "config" else installer.SYSTEMD_ROOT / "aster-controller.service"
                path.symlink_to(self.root / ("missing-" + target))
                before = self.tree()
                with self.assertRaises(installer.InstallerError):
                    installer.execute(args)
                self.assertTrue(path.is_symlink())
                self.assertEqual(before, self.tree())
                path.unlink()

    def test_repeat_and_mismatched_resume_preserve_original_receipt(self):
        with self.isolated_host():
            args = self.args(extra=("--apply",))
            installer.execute(args)
            before = self.tree()
            with self.assertRaises(installer.InstallerError):
                installer.execute(args)
            self.assertEqual(before, self.tree())
            other = self.args(extra=("--apply", "--resume"))
            # Different immutable source intent, not merely a differently named archive.
            payload = self.payload()
            payload["ui/index.html"] = (b"different synthetic UI", 0o644)
            path, digest = self.archive(payload)
            other.bundle, other.sha256 = str(path), digest
            before = self.tree()
            with self.assertRaises(installer.InstallerError):
                installer.execute(other)
            self.assertEqual(before, self.tree())

    def test_node_with_missing_prerequisites_does_not_run_doctor_or_start(self):
        with self.isolated_host(), self.synthetic_certificate_acceptance():
            approval, _, _, _ = self.approval_input("node")
            args = self.args("node", ("--apply", "--approval", str(approval), "--start"))
            with mock.patch.object(installer, "node_preflight", return_value=["kvm-unavailable"]), mock.patch.object(installer, "run_fixed") as run, mock.patch.object(installer, "strict_health") as health:
                with self.assertRaises(installer.InstallerError):
                    installer.execute(args)
            run.assert_not_called()
            health.assert_not_called()
            receipt = json.loads((installer.STATE_ROOT / "node" / "state.json").read_text())
            self.assertEqual(receipt["status"], "failed")
            self.assertEqual(receipt["service"], "not-started")

    def test_node_doctor_not_ready_prevents_systemd_and_health(self):
        with self.isolated_host(), self.synthetic_certificate_acceptance():
            approval, _, _, _ = self.approval_input("node")
            args = self.args("node", ("--apply", "--approval", str(approval), "--start"))
            def readonly_checks(argv, **kwargs):
                if argv[:2] == ["/usr/bin/qemu-img", "info"]:
                    return b'{"format":"qcow2","virtual-size":1073741824}'
                return b'{"ready":false}' if "--doctor" in argv else b""

            with mock.patch.object(installer, "node_preflight", return_value=[]), mock.patch.object(installer, "run_fixed", side_effect=readonly_checks) as run, mock.patch.object(installer, "strict_health") as health:
                with self.assertRaises(installer.InstallerError):
                    installer.execute(args)
            self.assertEqual(run.call_count, 3)
            self.assertIn("--doctor", run.call_args.args[0])
            health.assert_not_called()

    def test_failed_controller_tls_health_never_enables_service_and_receipt_stays_failed(self):
        with self.isolated_host(), self.synthetic_certificate_acceptance():
            approval, _, _, _ = self.approval_input("controller")
            args = self.args("controller", ("--apply", "--approval", str(approval), "--start"))
            with mock.patch.object(installer, "run_fixed", return_value=b"") as run, mock.patch.object(installer, "strict_health", side_effect=installer.InstallerError("synthetic TLS rejection")), mock.patch.object(installer.time, "sleep", return_value=None):
                with self.assertRaises(installer.InstallerError):
                    installer.execute(args)
            calls = [call.args[0] for call in run.call_args_list]
            self.assertTrue(any("start" in argv for argv in calls))
            self.assertFalse(any("enable" in argv for argv in calls))
            receipt = json.loads((installer.STATE_ROOT / "controller" / "state.json").read_text())
            self.assertEqual(receipt["status"], "failed")
            self.assertIn(receipt["service"], ("unconfirmed", "stopped-after-failed-check"))

    def test_node_approval_rejects_controller_client_credentials_even_if_explicit(self):
        with self.isolated_host(), self.synthetic_certificate_acceptance():
            approval, document, _, _ = self.approval_input("node")
            args = self.args("node", ("--approval", str(approval)))
            loaded, _, _, _ = installer.load_approval(args)
            self.assertEqual(loaded["component"], "aster-cloud-node")
            for field in ("client_certificate", "client_key", "tls_ca_file"):
                with self.subTest(field=field):
                    approval.write_text(json.dumps(dict(document, **{field: "/root/forbidden-controller-identity"})))
                    with self.assertRaisesRegex(installer.InstallerError, "schema/component"):
                        installer.load_approval(args)

    def test_node_import_cannot_escape_fixed_systemd_runtime_paths(self):
        with self.isolated_host(), self.synthetic_certificate_acceptance():
            approval, _, cfg, config = self.approval_input("node")
            args = self.args("node", ("--approval", str(approval)))
            installer.load_approval(args)
            variants = [
                {"state_directory": str(self.root / "node-state")},
                {"storage_directory": str(self.root / "node-storage")},
                {"certificate": str(self.root / "inputs/server.crt")},
                {"private_key": str(self.root / "inputs/server.key")},
                {"controller_ca": str(self.root / "inputs/ca.crt")},
                {"storage": {"enabled": False, "directory": "/var/lib/not-approved"}},
                {"storage": {"enabled": False, "inbox_directory": "/var/lib/not-approved"}},
                {"images": {"synthetic": {"path": str(self.root / "inputs/image.qcow2"), "sha256": sha256((self.root / "inputs/image.qcow2").read_bytes())}}},
            ]
            for changed in variants:
                with self.subTest(changed=list(changed)):
                    config.write_text(json.dumps(dict(cfg, **changed)))
                    with self.assertRaises(installer.InstallerError):
                        installer.load_approval(args)

    def test_node_start_stays_pending_controller_without_importing_or_using_client_identity(self):
        with self.isolated_host(), self.synthetic_certificate_acceptance():
            approval, _, _, _ = self.approval_input("node")
            args = self.args("node", ("--apply", "--approval", str(approval), "--start"))
            def readonly_checks(argv, **kwargs):
                if argv[:2] == ["/usr/bin/qemu-img", "info"]:
                    return b'{"format":"qcow2","virtual-size":1073741824}'
                return b'{"ready":true}' if "--doctor" in argv else b""

            with mock.patch.object(installer, "node_preflight", return_value=[]), mock.patch.object(installer, "node_listener_check") as listener, mock.patch.object(installer, "run_fixed", side_effect=readonly_checks), mock.patch.object(installer, "strict_health") as health:
                result = installer.execute(args)
            self.assertEqual(result["status"], "node_started_pending_controller")
            self.assertEqual(result["service"], "active-unadmitted")
            listener.assert_called_once()
            health.assert_not_called()
            final = json.loads(installer.CONFIG_PATHS["node"].read_text())
            self.assertNotIn("client_certificate", final)
            self.assertNotIn("client_key", final)
            self.assertTrue(final["maintenance"])
            self.assertFalse(final["network"]["enabled"])
            self.assertFalse(final["allow_delete"])

    def test_node_image_checks_are_fixed_read_only_and_reject_backing_external_encrypted_or_dummy(self):
        cfg = {"images": {"synthetic": {"path": "/var/lib/aster-images/synthetic.qcow2", "sha256": "1" * 64}}}
        valid = {"format": "qcow2", "virtual-size": 1073741824}
        with mock.patch.object(installer, "run_fixed", side_effect=[json.dumps(valid).encode(), b""]) as run:
            installer.verify_node_images(cfg)
        self.assertEqual(run.call_args_list[0].args[0], ["/usr/bin/qemu-img", "info", "--output=json", "-f", "qcow2", "/var/lib/aster-images/synthetic.qcow2"])
        self.assertEqual(run.call_args_list[1].args[0], ["/usr/bin/qemu-img", "check", "-f", "qcow2", "/var/lib/aster-images/synthetic.qcow2"])
        self.assertFalse(any("-r" in call.args[0] for call in run.call_args_list))
        for change in (
            {"format": "raw"}, {"virtual-size": 0}, {"virtual-size": True},
            {"backing-filename": "base.qcow2"}, {"full-backing-filename": "/private/base"},
            {"encrypted": True}, {"data-file": "outside.raw"},
            {"format-specific": {"data": {"data-file": "outside.raw"}}},
            {"format-specific": None}, {"format-specific": {"data": None}},
        ):
            with self.subTest(change=change), mock.patch.object(installer, "run_fixed", return_value=json.dumps(dict(valid, **change)).encode()) as run:
                with self.assertRaises(installer.InstallerError):
                    installer.verify_node_images(cfg)
                self.assertEqual(run.call_count, 1, "unsafe images must not even reach qemu-img check")

    def test_fixed_command_errors_do_not_echo_secrets_or_inherit_environment(self):
        result = types.SimpleNamespace(returncode=1, stdout=b"DO_NOT_PRINT_TEST_DSN", stderr=b"DO_NOT_PRINT_TEST_TOKEN")
        output = io.StringIO()
        with mock.patch.object(installer.subprocess, "run", return_value=result) as run, contextlib.redirect_stdout(output), contextlib.redirect_stderr(output), self.assertRaises(installer.InstallerError) as rejected:
            installer.run_fixed(["/synthetic/fixed-command"])
        self.assertNotIn("DO_NOT_PRINT", output.getvalue() + str(rejected.exception))
        self.assertEqual(run.call_args.kwargs["env"], {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "HOME": "/root"})
        self.assertNotIn("shell", run.call_args.kwargs)

    def test_guided_controller_validation_is_read_only_and_requires_public_bind_approval(self):
        with self.isolated_host(), self.synthetic_certificate_acceptance():
            inputs = self.guided_controller_inputs()
            before = self.tree()
            self.assertEqual(installer.validate_guided_inputs("controller", inputs), inputs)
            self.assertEqual(before, self.tree())
            inputs["listen"] = "0.0.0.0:9443"
            with self.assertRaises(installer.InstallerError):
                installer.validate_guided_inputs("controller", inputs)
            inputs["public_listen_approved"] = True
            self.assertEqual(installer.validate_guided_inputs("controller", inputs), inputs)

    def test_guided_plan_never_generates_config_or_tokens(self):
        with self.isolated_host(), self.synthetic_certificate_acceptance():
            args = self.args(extra=("--plan",))
            args.wizard_inputs = self.guided_controller_inputs()
            before = self.tree()
            with mock.patch.object(installer, "generate_approved_configuration") as generate:
                result = installer.execute(args)
            self.assertEqual(result["mode"], "plan")
            self.assertEqual(before, self.tree())
            generate.assert_not_called()

    def test_guided_partial_seed_failure_preserves_secrets_and_changed_resume_is_rejected(self):
        with self.isolated_host(), self.synthetic_certificate_acceptance():
            args = self.args(extra=("--apply",))
            args.wizard_inputs = self.guided_controller_inputs()
            partial = []

            def fail_after_private_token(argv, **kwargs):
                self.assertEqual(argv[1], "init")
                config = Path(argv[argv.index("-config") + 1])
                config.parent.mkdir(mode=0o700)
                token = config.parent / "billing.token"
                token.write_bytes(b"DO_NOT_PRINT_PARTIAL_TOKEN")
                token.chmod(0o600)
                partial.append(token)
                raise installer.InstallerError("synthetic interrupted initialization")

            with mock.patch.object(installer, "run_fixed", side_effect=fail_after_private_token):
                with self.assertRaises(installer.InstallerError):
                    installer.execute(args)
            self.assertEqual(len(partial), 1)
            self.assertEqual(partial[0].read_bytes(), b"DO_NOT_PRINT_PARTIAL_TOKEN")
            self.assertFalse(installer.CONFIG_PATHS["controller"].exists())
            self.assertFalse((installer.STATE_ROOT / "controller" / "generated-approval.json").exists())
            args.resume = True
            args.wizard_inputs = dict(args.wizard_inputs, administrator_email="other@example.invalid")
            before = self.tree()
            with self.assertRaisesRegex(installer.InstallerError, "Guided resume inputs differ"):
                installer.execute(args)
            self.assertEqual(before, self.tree())
            self.assertEqual(partial[0].read_bytes(), b"DO_NOT_PRINT_PARTIAL_TOKEN")

    def test_guided_controller_generates_separate_config_with_init_tokens_without_start(self):
        with self.isolated_host(), self.synthetic_certificate_acceptance():
            args = self.args(extra=("--apply",))
            args.wizard_inputs = self.guided_controller_inputs()
            initialized = []

            def synthetic_init(argv, **kwargs):
                self.assertEqual(argv[1], "init")
                seed = Path(argv[argv.index("-config") + 1])
                seed.parent.mkdir(mode=0o700)
                cfg = {"schema": 1, "controller_id": "synthetic-controller", "nodes": [], "presets": []}
                for field, marker in (("billing_token_file", b"B"), ("admin_read_token_file", b"R"), ("admin_write_token_file", b"W")):
                    token = seed.parent / (field + ".token")
                    token.write_bytes(marker * 64)
                    token.chmod(0o600)
                    cfg[field] = str(token)
                seed.write_text(json.dumps(cfg))
                seed.chmod(0o600)
                initialized.append((seed, seed.read_bytes()))
                return b""

            with mock.patch.object(installer, "run_fixed", side_effect=synthetic_init) as run, mock.patch.object(installer, "strict_health") as health:
                result = installer.execute(args)
            self.assertEqual(result["status"], "configuration-approved")
            self.assertEqual(result["service"], "not-started")
            self.assertEqual(run.call_count, 1)
            health.assert_not_called()
            self.assertEqual(len(initialized), 1)
            seed, original_seed = initialized[0]
            self.assertEqual(seed.read_bytes(), original_seed)
            final = json.loads(installer.CONFIG_PATHS["controller"].read_text())
            tokens = [Path(final[field]).read_bytes() for field in ("billing_token_file", "admin_read_token_file", "admin_write_token_file")]
            self.assertEqual(tokens, [b"B" * 64, b"R" * 64, b"W" * 64])
            self.assertEqual(Path(final["dsn_file"]).read_bytes(), Path(args.wizard_inputs["dsn_file"]).read_bytes())
            self.assertNotEqual(seed, installer.CONFIG_PATHS["controller"])
            args.resume = True
            before = self.tree()
            with mock.patch.object(installer, "run_fixed") as run:
                resumed = installer.execute(args)
            run.assert_not_called()
            self.assertEqual(resumed["service"], "not-started")
            self.assertEqual(before, self.tree())

    def test_actual_controller_wizard_collects_inputs_without_writes_or_secret_echo(self):
        args = self.args(extra=("--wizard", "--plan"))
        inputs = self.guided_controller_inputs()
        responses = ["", "", inputs["origin"], inputs["certificate"], inputs["private_key"], inputs["tls_ca_file"], inputs["listen"], inputs["dsn_file"], "", inputs["administrator_email"]]
        before, output = self.tree(), io.StringIO()
        with mock.patch.object(installer.sys.stdin, "isatty", return_value=True), mock.patch("builtins.input", side_effect=responses), contextlib.redirect_stdout(output):
            result = installer.wizard(args)
        self.assertEqual(result.wizard_inputs, inputs)
        self.assertFalse(result.apply)
        self.assertEqual(before, self.tree())
        self.assertNotIn("DO_NOT_PRINT", output.getvalue())

    def test_wizard_without_terminal_fails_without_collecting_secrets(self):
        args = self.args(extra=("--wizard",))
        before = self.tree()
        with mock.patch.object(installer.sys.stdin, "isatty", return_value=False), mock.patch("builtins.input") as ask, self.assertRaises(installer.InstallerError):
            installer.wizard(args)
        ask.assert_not_called()
        self.assertEqual(before, self.tree())

    def test_node_wizard_never_requests_controller_client_certificate_or_key(self):
        args = self.args("node", ("--wizard", "--plan"))
        responses = [
            "", "", "", "https://node.example.invalid:9443", "/etc/aster-input/server.crt", "/etc/aster-input/server.key", "127.0.0.1:9443", "dedicated-kvm",
            "node-a", "dc-a", "group-a", "/etc/aster-input/controller-ca.crt", "1" * 64,
            "ubuntu22", "/var/lib/aster-images/ubuntu22.qcow2", "2" * 64, "2", "1024", "10",
        ]
        before, output = self.tree(), io.StringIO()
        with mock.patch.object(installer.sys.stdin, "isatty", return_value=True), mock.patch("builtins.input", side_effect=responses) as ask, contextlib.redirect_stdout(output):
            result = installer.wizard(args)
        self.assertEqual(before, self.tree())
        self.assertNotIn("client_certificate", result.wizard_inputs)
        self.assertNotIn("client_key", result.wizard_inputs)
        self.assertNotIn("tls_ca_file", result.wizard_inputs)
        prompts = "\n".join(call.args[0].lower() for call in ask.call_args_list)
        self.assertNotIn("client private key", prompts)
        self.assertNotIn("client certificate pem", prompts)
        self.assertEqual(result.wizard_inputs["controller_ca"], "/etc/aster-input/controller-ca.crt")

    def test_native_opt_in_plan_is_nonroot_no_commands_no_secret_generation(self):
        args = self.args(extra=("--plan", "--install-dependencies", "--provision-mysql"))
        provision = installer.provisioning_module()
        before = self.tree()
        with mock.patch.object(installer.os, "geteuid", return_value=501), mock.patch.object(provision, "install_dependencies") as packages, mock.patch.object(provision, "provision_mysql") as database, mock.patch.object(provision.secrets, "token_hex", side_effect=AssertionError("plan must not generate credentials")), mock.patch.object(installer.getpass, "getpass", side_effect=AssertionError("plan must not collect credentials")):
            result = installer.execute(args)
        packages.assert_not_called()
        database.assert_not_called()
        self.assertEqual(result["mode"], "plan")
        self.assertEqual(before, self.tree())

    def test_node_rejects_mysql_provisioning_and_arbitrary_packages_have_no_cli(self):
        args = self.args("node", ("--plan", "--provision-mysql"))
        with self.assertRaises(installer.InstallerError):
            installer.execute(args)
        for option in ("--apt-package", "--mysql-password", "--root-password", "--mysql-host", "--add-repository"):
            with self.subTest(option=option), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                installer.build_parser().parse_args(["controller", option, "DO_NOT_PRINT"])

    def test_dependency_plan_is_fixed_read_only_and_does_not_claim_node_daemon_installation(self):
        provision = installer.provisioning_module()
        before = self.tree()
        self.assertEqual(provision.dependency_plan("controller")["packages"], ["ca-certificates", "openssl"])
        node = provision.dependency_plan("node")
        self.assertFalse(node["node_daemon_included"])
        self.assertFalse(any("libvirt-daemon" in name or "openvswitch" in name for name in node["packages"]))
        with self.assertRaises(provision.ProvisionError):
            provision.dependency_plan("node", with_mysql=True)
        with self.assertRaises(provision.ProvisionError):
            provision.dependency_plan("arbitrary; command")
        self.assertEqual(before, self.tree())

    def test_fresh_dependency_host_refuses_every_existing_workload_or_broken_symlink(self):
        provision = installer.provisioning_module()
        before = self.tree()
        for component in ("controller", "node"):
            for path in FRESH_DEPENDENCY_PATHS:
                for kind in ("existing", "symlinks"):
                    with self.subTest(component=component, path=path, kind=kind):
                        with self.dependency_host_evidence(**{kind: (path,)}) as probes, mock.patch.object(provision, "run_fixed") as run:
                            with self.assertRaisesRegex(provision.ProvisionError, "fresh dedicated-host only"):
                                provision.fresh_dependency_host(component)
                            probes.read_text.assert_not_called()
                            probes.stat.assert_not_called()
                            run.assert_not_called()
        self.assertEqual(before, self.tree())

    def test_fresh_dependency_node_refuses_insufficient_or_unverifiable_memory(self):
        provision = installer.provisioning_module()
        for memory in ("MemTotal: 0 kB\n", "MemTotal: 2097151 kB\n", "MemFree: 4194304 kB\n",
                       "MemTotal: malformed kB\n", OSError("synthetic unreadable meminfo")):
            with self.subTest(memory=str(memory)), self.dependency_host_evidence(memory=memory) as probes:
                with self.assertRaises(provision.ProvisionError):
                    provision.fresh_dependency_host("node")
                probes.read_text.assert_called_once()
                probes.stat.assert_not_called()

    def test_fresh_dependency_node_refuses_missing_or_non_character_kvm(self):
        provision = installer.provisioning_module()
        for mode in (None, stat.S_IFREG | 0o600, stat.S_IFDIR | 0o700, stat.S_IFBLK | 0o600):
            with self.subTest(mode=mode), self.dependency_host_evidence(kvm_mode=mode) as probes:
                with self.assertRaises(provision.ProvisionError):
                    provision.fresh_dependency_host("node")
                probes.read_text.assert_called_once()
                probes.stat.assert_called_once()

    def test_fresh_dependency_host_accepts_only_clean_valid_role_evidence_without_writes(self):
        provision = installer.provisioning_module()
        before = self.tree()
        # Controller does not require node-only memory or KVM evidence.
        with self.dependency_host_evidence(memory=OSError("must not read node evidence"), kvm_mode=None) as probes:
            self.assertIsNone(provision.fresh_dependency_host("controller"))
            self.assertEqual([str(call.args[0]) for call in probes.exists.call_args_list], list(FRESH_DEPENDENCY_PATHS))
            self.assertEqual([str(call.args[0]) for call in probes.is_symlink.call_args_list], list(FRESH_DEPENDENCY_PATHS))
            probes.read_text.assert_not_called()
            probes.stat.assert_not_called()
        # Exact 2GiB boundary plus a character KVM device is valid for node.
        with self.dependency_host_evidence() as probes:
            self.assertIsNone(provision.fresh_dependency_host("node"))
            self.assertEqual(probes.exists.call_count, len(FRESH_DEPENDENCY_PATHS))
            self.assertEqual(probes.is_symlink.call_count, len(FRESH_DEPENDENCY_PATHS))
            probes.read_text.assert_called_once()
            probes.stat.assert_called_once()
        self.assertEqual(before, self.tree())

    def test_fresh_mysql_host_refuses_all_existing_service_paths_or_broken_symlinks(self):
        provision = installer.provisioning_module()
        for path in FRESH_MYSQL_PATHS:
            for kind in ("existing", "symlinks"):
                with self.subTest(path=path, kind=kind), self.dependency_host_evidence(**{kind: (path,)}) as probes:
                    with self.assertRaisesRegex(provision.ProvisionError, "fresh-host only"):
                        provision._fresh_mysql_host()
                    probes.read_text.assert_not_called()
                    probes.stat.assert_not_called()
        with self.dependency_host_evidence() as probes:
            self.assertIsNone(provision._fresh_mysql_host())
            self.assertEqual(probes.exists.call_count, len(FRESH_MYSQL_PATHS))
            self.assertEqual(probes.is_symlink.call_count, len(FRESH_MYSQL_PATHS))

    def test_existing_service_policy_is_never_overwritten_even_temporarily(self):
        with self.provision_host() as (provision, state):
            provision.POLICY_PATH.write_bytes(b"#!/bin/sh\n# existing operator policy\nexit 0\n")
            provision.POLICY_PATH.chmod(0o755)
            before = self.tree()
            with mock.patch.object(provision, "run_fixed") as run, self.assertRaises(provision.ProvisionError):
                provision.install_dependencies("controller", state)
            self.assertEqual(provision.POLICY_PATH.read_bytes(), b"#!/bin/sh\n# existing operator policy\nexit 0\n")
            run.assert_not_called()
            # Creating only an empty private state directory is harmless; no
            # receipt/config/policy bytes may be changed before this refusal.
            self.assertEqual(before, self.tree())

    def test_dependency_commands_use_private_signed_ubuntu_sources_and_block_autostart(self):
        with self.provision_host() as (provision, state):
            calls = []

            def apt(argv, **kwargs):
                calls.append((argv, kwargs))
                self.assertEqual(argv[0], provision.APT_GET)
                self.assertTrue(provision.POLICY_PATH.read_bytes().endswith(b"exit 101\n"))
                self.assertEqual(stat.S_IMODE(provision.POLICY_PATH.stat().st_mode), 0o755)
                return b"Inst openssl (3.0 synthetic [amd64])\n" if "--simulate" in argv else b""

            with mock.patch.object(provision, "run_fixed", side_effect=apt):
                result = provision.install_dependencies("controller", state)
            self.assertEqual(result["status"], "dependencies-installed")
            self.assertFalse(provision.POLICY_PATH.exists())
            self.assertEqual(len(calls), 3)
            self.assertEqual(calls[0][0], [provision.APT_GET, "update"])
            install = calls[-1][0]
            self.assertIn("--no-upgrade", install)
            self.assertIn("--no-remove", install)
            self.assertIn("--no-install-recommends", install)
            self.assertFalse(any(word in " ".join(install) for word in ("firewall", "ufw", "libvirt-daemon", "openvswitch")))
            self.assertFalse(any(word in install for word in ("upgrade", "dist-upgrade", "full-upgrade")))
            config = Path(calls[0][1]["env"]["APT_CONFIG"])
            settings = config.read_text()
            self.assertIn('Acquire::https::Verify-Peer "true"', settings)
            self.assertIn('Acquire::https::Verify-Host "true"', settings)
            self.assertIn('APT::Get::AllowUnauthenticated "false"', settings)
            self.assertIn('APT::Update::Error-Mode "any"', settings)
            self.assertIn('Dir::Etc::parts "', settings)
            self.assertIn('empty-parts', settings)
            sources = config.with_name("sources.list").read_text()
            self.assertIn("https://archive.ubuntu.com/ubuntu noble", sources)
            self.assertIn("https://security.ubuntu.com/ubuntu noble-security", sources)
            self.assertIn("signed-by=" + str(provision.APT_KEYRING), sources)
            self.assertNotIn("trusted=yes", sources)

    def test_dependency_fixture_is_independent_of_runner_workloads(self):
        # Reproduce an occupied Linux runner even on Darwin. This is a fixture
        # contract, not permission to install packages on that occupied host.
        original_exists = Path.exists
        occupied = set(FRESH_DEPENDENCY_PATHS + FRESH_MYSQL_PATHS)
        def runner_exists(path):
            return str(path) in occupied or original_exists(path)
        with mock.patch.object(Path, "exists", runner_exists), self.provision_host() as (provision, state):
            with mock.patch.object(provision, "run_fixed", return_value=b"") as run:
                result = provision.install_dependencies("controller", state, with_mysql=True)
            self.assertEqual(result["status"], "dependencies-installed")
            commands = [call.args[0] for call in run.call_args_list]
            self.assertEqual(len(commands), 3)
            self.assertEqual(commands[0], [provision.APT_GET, "update"])
            self.assertEqual(sum("--simulate" in argv for argv in commands), 1)
            self.assertEqual(sum("--assume-yes" in argv for argv in commands), 1)
            self.assertEqual(provision.MYSQL_DROPIN.read_bytes(), provision.MYSQL_LOCAL_DROPIN)

    def test_dependency_simulation_refuses_upgrade_remove_or_network_daemon(self):
        for simulation in (b"Remv existing-service [1.0]\n", b"Inst openssl [1.0] (2.0 Ubuntu [amd64])\n", b"Inst libvirt-daemon-system (1.0 Ubuntu [amd64])\n", b"Inst ufw (1.0 Ubuntu [amd64])\n"):
            with self.subTest(simulation=simulation), self.provision_host() as (provision, state):
                # A distinct owned state per subcase; each failed policy is
                # explicitly removed by the test, never by a production bypass.
                if state.exists():
                    state = self.root / ("native-state-" + sha256(simulation)[:8])
                def apt(argv, **kwargs):
                    return simulation if "--simulate" in argv else b""
                with mock.patch.object(provision, "run_fixed", side_effect=apt) as run, self.assertRaisesRegex(provision.ProvisionError, "APT plan would upgrade/remove"):
                    provision.install_dependencies("node", state)
                self.assertEqual(sum("--simulate" in call.args[0] for call in run.call_args_list), 1)
                self.assertEqual(sum(call.args[0] == [provision.APT_GET, "update"] for call in run.call_args_list), 1)
                self.assertFalse(any("--assume-yes" in call.args[0] for call in run.call_args_list))
                if provision.POLICY_PATH.exists():
                    provision.POLICY_PATH.unlink()

    def test_failed_package_transaction_retains_only_owned_policy_until_explicit_same_plan_resume(self):
        with self.provision_host() as (provision, state):
            def fail_install(argv, **kwargs):
                if "--assume-yes" in argv:
                    raise provision.ProvisionError("synthetic package transaction interrupted")
                return b""
            with mock.patch.object(provision, "run_fixed", side_effect=fail_install) as run, self.assertRaisesRegex(provision.ProvisionError, "synthetic package transaction interrupted"):
                provision.install_dependencies("controller", state)
            self.assertEqual(run.call_count, 3)
            self.assertEqual(sum("--simulate" in call.args[0] for call in run.call_args_list), 1)
            self.assertEqual(sum("--assume-yes" in call.args[0] for call in run.call_args_list), 1)
            owned_policy = provision.POLICY_PATH.read_bytes()
            self.assertTrue(owned_policy.endswith(b"exit 101\n"))
            with mock.patch.object(provision, "run_fixed") as run, self.assertRaises(provision.ProvisionError):
                provision.install_dependencies("controller", state)
            run.assert_not_called()
            self.assertEqual(provision.POLICY_PATH.read_bytes(), owned_policy)
            with mock.patch.object(provision, "run_fixed") as run, self.assertRaises(provision.ProvisionError):
                provision.install_dependencies("node", state, resume=True)
            run.assert_not_called()
            with mock.patch.object(provision, "run_fixed", return_value=b""):
                result = provision.install_dependencies("controller", state, resume=True)
            self.assertEqual(result["status"], "dependencies-installed")
            self.assertFalse(provision.POLICY_PATH.exists())

    def test_policy_replaced_during_apt_is_never_removed_even_with_matching_bytes(self):
        with self.provision_host() as (provision, state):
            replacement_inode = []
            def replace_policy(argv, **kwargs):
                if "--assume-yes" in argv:
                    replacement = provision.POLICY_PATH.with_name("foreign-policy")
                    replacement.write_bytes(provision.POLICY_PATH.read_bytes())
                    replacement.chmod(0o755)
                    replacement_inode.append(replacement.stat().st_ino)
                    os.replace(replacement, provision.POLICY_PATH)
                return b""
            with mock.patch.object(provision, "run_fixed", side_effect=replace_policy), self.assertRaises(provision.ProvisionError):
                provision.install_dependencies("controller", state)
            self.assertTrue(provision.POLICY_PATH.exists())
            self.assertEqual(provision.POLICY_PATH.stat().st_ino, replacement_inode[0])

    def test_resume_refuses_same_content_foreign_policy_before_any_apt_action(self):
        with self.provision_host() as (provision, state):
            with mock.patch.object(provision, "run_fixed", side_effect=provision.ProvisionError("synthetic interruption")) as interrupted, self.assertRaisesRegex(provision.ProvisionError, "synthetic interruption"):
                provision.install_dependencies("controller", state)
            interrupted.assert_called_once()
            self.assertEqual(interrupted.call_args.args[0], [provision.APT_GET, "update"])
            replacement = provision.POLICY_PATH.with_name("replacement")
            replacement.write_bytes(provision.POLICY_PATH.read_bytes())
            replacement.chmod(0o755)
            os.replace(replacement, provision.POLICY_PATH)
            with mock.patch.object(provision, "run_fixed", return_value=b"") as run, self.assertRaises(provision.ProvisionError):
                provision.install_dependencies("controller", state, resume=True)
            run.assert_not_called()

    def test_dependency_private_config_refuses_foreign_hooks_sources_or_trust(self):
        for directory in ("empty-parts", "source-parts", "trusted-parts", "preferences-parts"):
            with self.subTest(directory=directory), self.provision_host() as (provision, state):
                foreign = self.private_file("apt-work/controller/" + directory + "/foreign-entry", b"unapproved configuration", 0o644)
                with mock.patch.object(provision, "run_fixed") as run, self.assertRaisesRegex(provision.ProvisionError, "Private APT configuration isolation directory is not empty"):
                    provision.install_dependencies("controller", state)
                run.assert_not_called()
                self.assertEqual(foreign.read_bytes(), b"unapproved configuration")
                foreign.unlink()
                # No package policy is created before private APT config passes.
                self.assertFalse(provision.POLICY_PATH.exists())
                if (state / "dependencies.json").exists():
                    (state / "dependencies.json").unlink()

    def test_fresh_mysql_package_path_refuses_existing_config_data_or_dropin(self):
        for target in ("MYSQL_CONFIG", "MYSQL_DATA", "MYSQL_DROPIN"):
            with self.subTest(target=target), self.provision_host() as (provision, state):
                path = getattr(provision, target)
                path.parent.mkdir(parents=True, exist_ok=True)
                if target == "MYSQL_DROPIN":
                    path.write_bytes(b"existing operator MySQL policy")
                else:
                    path.mkdir(exist_ok=True)
                with mock.patch.object(provision, "run_fixed") as run, self.assertRaisesRegex(provision.ProvisionError, "MySQL package provisioning is fresh-host only"):
                    provision.install_dependencies("controller", state, with_mysql=True)
                run.assert_not_called()
                self.assertFalse(provision.POLICY_PATH.exists())
                if path.is_dir():
                    path.rmdir()
                else:
                    path.unlink()
                    path.parent.rmdir()

    def test_mysql_cli_uses_socket_private_login_home_and_stdin_never_secret_argv(self):
        with self.provision_host() as (provision, state):
            sql = "SELECT 'DO_NOT_PRINT_SYNTHETIC_SQL';\n"
            with mock.patch.object(provision, "run_fixed", return_value=b"synthetic") as run:
                self.assertEqual(provision.mysql_sql(state, sql), b"synthetic")
            argv, kwargs = run.call_args.args[0], run.call_args.kwargs
            self.assertEqual(argv[0], provision.MYSQL)
            self.assertIn("--no-defaults", argv)
            self.assertIn("--protocol=SOCKET", argv)
            self.assertIn("--skip-reconnect", argv)
            self.assertNotIn("--no-login-paths", argv, "8.2-only option is not compatible with Ubuntu's MySQL 8.0 client")
            self.assertEqual(kwargs["stdin"], sql.encode())
            self.assertNotIn("DO_NOT_PRINT", " ".join(argv))
            self.assertFalse(any(arg.startswith(("--password", "-p")) and not arg.startswith("--protocol") for arg in argv))
            env = kwargs["env"]
            self.assertEqual(env["MYSQL_HISTFILE"], "/dev/null")
            self.assertNotEqual(env["HOME"], "/root")
            self.assertTrue(str(Path(env["HOME"])).startswith(str(state)))
            self.assertFalse(Path(env["MYSQL_TEST_LOGIN_FILE"]).exists())
            self.assertEqual(stat.S_IMODE(Path(env["HOME"]).stat().st_mode), 0o700)
            self.assertNotIn("MYSQL_PWD", env)

    def test_mysql_identifier_validation_refuses_root_shared_finance_and_sql_injection(self):
        provision = installer.provisioning_module()
        for names in (("vps_billing", "aster_api", "aster_migrate"), ("aster_cloud", "root", "aster_migrate"), ("aster_cloud", "aster_same", "aster_same"), ("aster_cloud` ; DROP DATABASE mysql;", "aster_api", "aster_migrate"), ("aster_cloud", "aster_api'@'%'", "aster_migrate")):
            with self.subTest(names=names), self.assertRaises(provision.ProvisionError):
                provision.validate_names(*names)

    def test_mysql_foreign_database_or_any_target_account_refuses_before_secret_generation(self):
        for key in ("db_exists", "runtime_exists", "migration_exists", "foreign_databases"):
            with self.subTest(key=key), self.provision_host() as (provision, state):
                server = SyntheticMySQL(provision)
                server.info[key] = 1
                with mock.patch.object(provision, "mysql_sql", side_effect=server), mock.patch.object(provision.secrets, "token_hex", side_effect=AssertionError("collision must precede secret/nonce generation")), self.assertRaises(provision.ProvisionError):
                    provision.provision_mysql(state, "aster_cloud", "aster_cloud_api", "aster_cloud_migrate")
                self.assertEqual(len(server.sql), 1)
                self.assertFalse((state / "runtime-mysql-dsn").exists())
                self.assertFalse((state / "migration-mysql-dsn").exists())

    def test_mysql_nonstandard_server_or_implicit_privileges_are_rejected_before_creates(self):
        for changed in ({"version": "5.7.44"}, {"version": "8.0.20"}, {"version": "10.11-MariaDB"}, {"current_user": "root@remote"}, {"partial_revokes": 1}, {"mandatory_roles": "global_admin"}):
            with self.subTest(changed=changed), self.provision_host() as (provision, state):
                server = SyntheticMySQL(provision)
                server.info.update(changed)
                with mock.patch.object(provision, "mysql_sql", side_effect=server), mock.patch.object(provision.secrets, "token_hex", side_effect=AssertionError("server refusal must precede secret creation")), self.assertRaises(provision.ProvisionError):
                    provision.provision_mysql(state, "aster_cloud", "aster_cloud_api", "aster_cloud_migrate")
                self.assertEqual(len(server.sql), 1)

    def test_runtime_grant_verifier_refuses_global_ddl_roles_wildcards_and_grant_option(self):
        provision = installer.provisioning_module()
        account = "`aster_cloud_api`@`localhost`"
        exact = "GRANT SELECT, INSERT, UPDATE, DELETE ON `aster\\_cloud`.* TO " + account
        with mock.patch.object(provision, "mysql_sql", return_value=("GRANT USAGE ON *.* TO " + account + "\n" + exact).encode()):
            provision.verify_grants(self.root, "aster_cloud_api", "aster_cloud", ("SELECT", "INSERT", "UPDATE", "DELETE"))
        for value in (
            "GRANT ALL PRIVILEGES ON *.* TO " + account,
            "GRANT SELECT, INSERT, UPDATE, DELETE, CREATE ON `aster\\_cloud`.* TO " + account,
            "GRANT `some_role`@`localhost` TO " + account,
            "GRANT SELECT, INSERT, UPDATE, DELETE ON `aster_cloud`.* TO " + account,
            exact + " WITH GRANT OPTION",
            exact + "\nGRANT SELECT ON `other`.* TO " + account,
        ):
            with self.subTest(value=value), mock.patch.object(provision, "mysql_sql", return_value=value.encode()), self.assertRaises(provision.ProvisionError):
                provision.verify_grants(self.root, "aster_cloud_api", "aster_cloud", ("SELECT", "INSERT", "UPDATE", "DELETE"))

    def test_mysql_new_accounts_have_scoped_dml_vs_ddl_and_server_random_passwords_only(self):
        with self.provision_host() as (provision, state):
            server, output = SyntheticMySQL(provision), io.StringIO()
            with mock.patch.object(provision, "mysql_sql", side_effect=server), contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                result = provision.provision_mysql(state, "aster_cloud", "aster_cloud_api", "aster_cloud_migrate")
            runtime = Path(result["dsn_file"])
            migration = Path(result["migration_dsn_file"])
            self.assertEqual(stat.S_IMODE(runtime.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(migration.stat().st_mode), 0o600)
            self.assertTrue(runtime.read_text().startswith("aster_cloud_api:"))
            self.assertTrue(migration.read_text().startswith("aster_cloud_migrate:"))
            self.assertNotEqual(runtime.read_bytes(), migration.read_bytes())
            sql = "\n".join(server.sql)
            self.assertNotIn("DO_NOT_PRINT", sql + output.getvalue() + json.dumps(result))
            self.assertEqual(sql.count("BY RANDOM PASSWORD"), 2)
            self.assertNotRegex(sql, r"(?i)\b(?:DROP|ALTER USER|REPLACE|IF NOT EXISTS|GRANT OPTION)\b")
            grants = [value for value in server.sql if value.startswith("GRANT ")]
            self.assertEqual(grants[0], "GRANT SELECT, INSERT, UPDATE, DELETE ON `aster\\_cloud`.* TO 'aster_cloud_api'@'localhost';\n")
            self.assertIn("CREATE, ALTER, INDEX, REFERENCES ON `aster\\_cloud`.*", grants[1])
            self.assertNotIn("*.*", sql)
            self.assertNotIn("'%'", sql)

    def test_real_identity_migration_fk_requires_references_only_for_the_scoped_migrator(self):
        sql = (INSTALLER_PATH.parents[2] / "migrations/002_console_identity.sql").read_text()
        self.assertRegex(sql, r"FOREIGN KEY\s*\([^)]*\)\s+REFERENCES\s+controller_console_users")
        with self.provision_host() as (provision, state):
            self.assertEqual(provision.RUNTIME_PRIVILEGES, ("SELECT", "INSERT", "UPDATE", "DELETE"))
            self.assertIn("REFERENCES", provision.MIGRATION_PRIVILEGES)
            server = SyntheticMySQL(provision)
            with mock.patch.object(provision, "mysql_sql", side_effect=server):
                provision.provision_mysql(state, "aster_cloud", "aster_cloud_api", "aster_cloud_migrate")
            runtime, migrator = [value for value in server.sql if value.startswith("GRANT ")]
            self.assertNotIn("REFERENCES", runtime)
            self.assertIn("REFERENCES ON `aster\\_cloud`.*", migrator)
            self.assertNotRegex(runtime + migrator, r"\*\.\*|\bDROP\b|GRANT OPTION")

    def test_mysql_lost_create_ack_never_resets_password_or_recreates_unknown_account(self):
        with self.provision_host() as (provision, state):
            server = SyntheticMySQL(provision)
            server.lose_account_ack = True
            with mock.patch.object(provision, "mysql_sql", side_effect=server):
                with self.assertRaises(provision.ProvisionError):
                    provision.provision_mysql(state, "aster_cloud", "aster_cloud_api", "aster_cloud_migrate")
                original_creates = sum(value.startswith("CREATE USER") for value in server.sql)
                with self.assertRaises(provision.ProvisionError):
                    provision.provision_mysql(state, "aster_cloud", "aster_cloud_api", "aster_cloud_migrate", resume=True)
            self.assertEqual(sum(value.startswith("CREATE USER") for value in server.sql), original_creates)
            self.assertFalse((state / "runtime-mysql-dsn").exists())
            self.assertTrue(server.info["db_exists"])
            self.assertTrue(server.info["runtime_exists"])
            self.assertFalse(any("ALTER USER" in value or "DROP " in value for value in server.sql))

    def test_mysql_resume_rejects_changed_names_server_or_ownership_marker(self):
        with self.provision_host() as (provision, state):
            server = SyntheticMySQL(provision)
            with mock.patch.object(provision, "mysql_sql", side_effect=server):
                provision.provision_mysql(state, "aster_cloud", "aster_cloud_api", "aster_cloud_migrate")
                before = self.tree()
                with self.assertRaises(provision.ProvisionError):
                    provision.provision_mysql(state, "aster_controller", "aster_cloud_api", "aster_cloud_migrate", resume=True)
                self.assertEqual(before, self.tree())
                server.info["server_uuid"] = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
                with self.assertRaises(provision.ProvisionError):
                    provision.provision_mysql(state, "aster_cloud", "aster_cloud_api", "aster_cloud_migrate", resume=True)
                self.assertEqual(before, self.tree())
                server.info["server_uuid"] = "11111111-2222-3333-4444-555555555555"
                server.nonce = "0" * 64
                writes = len([sql for sql in server.sql if sql.startswith(("GRANT", "CREATE"))])
                with self.assertRaises(provision.ProvisionError):
                    provision.provision_mysql(state, "aster_cloud", "aster_cloud_api", "aster_cloud_migrate", resume=True)
                self.assertEqual(len([sql for sql in server.sql if sql.startswith(("GRANT", "CREATE"))]), writes)

    def test_new_mysql_start_requires_owned_fresh_receipt_and_proves_tcp_disabled(self):
        with self.provision_host() as (provision, state):
            state.mkdir(mode=0o700)
            receipt = {"schema": 1, "component": "controller", "with_mysql": True, "status": "dependencies-installed"}
            provision.write_new(state / "dependencies.json", json.dumps(receipt).encode())
            provision.MYSQL_DROPIN.parent.mkdir(mode=0o755)
            provision.write_new(provision.MYSQL_DROPIN, provision.MYSQL_LOCAL_DROPIN, 0o644)
            with mock.patch.object(provision, "run_fixed", return_value=b"") as run, mock.patch.object(provision, "_query", return_value={"tcp_disabled": 1, "mysqlx_enabled": 0}):
                result = provision.start_owned_mysql(state)
            self.assertEqual(result["transport"], "unix-socket-only")
            self.assertTrue(any(call.args[0] == [provision.SYSTEMCTL, "start", "mysql.service"] for call in run.call_args_list))
            self.assertIn(b"--skip-networking --mysqlx=0", provision.MYSQL_DROPIN.read_bytes())
            self.assertFalse(any("enable" in call.args[0] for call in run.call_args_list))

    def test_new_mysql_tcp_or_x_listener_failure_stops_only_owned_fresh_mysql(self):
        with self.provision_host() as (provision, state):
            state.mkdir(mode=0o700)
            provision.write_new(state / "dependencies.json", json.dumps({"component": "controller", "with_mysql": True, "status": "dependencies-installed"}).encode())
            provision.MYSQL_DROPIN.parent.mkdir(mode=0o755)
            provision.write_new(provision.MYSQL_DROPIN, provision.MYSQL_LOCAL_DROPIN, 0o644)
            with mock.patch.object(provision, "run_fixed", return_value=b"") as run, mock.patch.object(provision, "_query", return_value={"tcp_disabled": 0, "mysqlx_enabled": 1}), mock.patch.object(provision.time, "sleep", return_value=None), self.assertRaises(provision.ProvisionError):
                provision.start_owned_mysql(state)
            self.assertTrue(any(call.args[0] == [provision.SYSTEMCTL, "stop", "mysql.service"] for call in run.call_args_list))

    def test_mysql_start_refuses_unowned_receipt_or_changed_dropin_before_commands(self):
        with self.provision_host() as (provision, state):
            state.mkdir(mode=0o700)
            provision.write_new(state / "dependencies.json", json.dumps({"component": "controller", "with_mysql": False, "status": "dependencies-installed"}).encode())
            with mock.patch.object(provision, "run_fixed") as run, self.assertRaises(provision.ProvisionError):
                provision.start_owned_mysql(state)
            run.assert_not_called()
            (state / "dependencies.json").write_text(json.dumps({"component": "controller", "with_mysql": True, "status": "dependencies-installed"}))
            provision.MYSQL_DROPIN.parent.mkdir(mode=0o755)
            provision.write_new(provision.MYSQL_DROPIN, b"[Service]\nExecStart=/usr/sbin/mysqld --bind-address=0.0.0.0\n", 0o644)
            with mock.patch.object(provision, "run_fixed") as run, self.assertRaises(provision.ProvisionError):
                provision.start_owned_mysql(state)
            run.assert_not_called()

    def test_lost_mysql_start_ack_still_attempts_stop_and_never_claims_local_ready(self):
        with self.provision_host() as (provision, state):
            state.mkdir(mode=0o700)
            provision.write_new(state / "dependencies.json", json.dumps({"component": "controller", "with_mysql": True, "status": "dependencies-installed"}).encode())
            provision.MYSQL_DROPIN.parent.mkdir(mode=0o755)
            provision.write_new(provision.MYSQL_DROPIN, provision.MYSQL_LOCAL_DROPIN, 0o644)
            def uncertain_start(argv, **kwargs):
                if argv == [provision.SYSTEMCTL, "start", "mysql.service"]:
                    raise provision.ProvisionError("synthetic start acknowledgement lost")
                return b""
            with mock.patch.object(provision, "run_fixed", side_effect=uncertain_start) as run, mock.patch.object(provision, "_query") as query, self.assertRaises(provision.ProvisionError):
                provision.start_owned_mysql(state)
            self.assertTrue(any(call.args[0] == [provision.SYSTEMCTL, "stop", "mysql.service"] for call in run.call_args_list))
            query.assert_not_called()
            self.assertNotIn("unix-socket-only-verified", (state / "dependencies.json").read_text())

    def test_lost_controller_start_ack_never_becomes_not_started_or_enabled(self):
        with self.isolated_host(), self.synthetic_certificate_acceptance():
            approval, _, _, _ = self.approval_input()
            args = self.args(extra=("--apply", "--approval", str(approval), "--start"))
            def uncertain_start(argv, **kwargs):
                if argv == [installer.SYSTEMCTL, "start", "aster-controller.service"]:
                    raise installer.InstallerError("synthetic start acknowledgement lost")
                return b""
            with mock.patch.object(installer, "run_fixed", side_effect=uncertain_start) as run, mock.patch.object(installer, "strict_health") as health, self.assertRaises(installer.InstallerError):
                installer.execute(args)
            calls = [call.args[0] for call in run.call_args_list]
            self.assertIn([installer.SYSTEMCTL, "stop", "aster-controller.service"], calls)
            self.assertFalse(any("enable" in argv for argv in calls))
            health.assert_not_called()
            receipt = json.loads((installer.STATE_ROOT / "controller/state.json").read_text())
            self.assertNotEqual(receipt["service"], "not-started", "lost acknowledgement does not prove a service never started")

    def test_provision_command_failures_withhold_arbitrary_stdout_stderr_and_credentials(self):
        provision = installer.provisioning_module()
        result = types.SimpleNamespace(returncode=1, stdout=b"DO_NOT_PRINT_SQL_PASSWORD", stderr=b"DO_NOT_PRINT_TOKEN")
        output = io.StringIO()
        with mock.patch.object(provision.subprocess, "run", return_value=result) as run, contextlib.redirect_stdout(output), contextlib.redirect_stderr(output), self.assertRaises(provision.ProvisionError) as rejected:
            provision.run_fixed(["/synthetic/fixed-command"])
        self.assertNotIn("DO_NOT_PRINT", output.getvalue() + str(rejected.exception))
        self.assertNotIn("shell", run.call_args.kwargs)
        self.assertNotIn("MYSQL_PWD", run.call_args.kwargs["env"])

    def test_resume_cannot_silently_add_package_or_database_side_effects(self):
        with self.isolated_host():
            args = self.args(extra=("--apply",))
            installer.execute(args)
            before = self.tree()
            args.resume, args.install_dependencies = True, True
            provision = installer.provisioning_module()
            with mock.patch.object(provision, "install_dependencies") as packages, mock.patch.object(provision, "provision_mysql") as database, self.assertRaisesRegex(installer.InstallerError, "resume options changed"):
                installer.execute(args)
            packages.assert_not_called()
            database.assert_not_called()
            self.assertEqual(before, self.tree())

    def test_legacy_receipt_without_native_options_cannot_opt_in_during_resume(self):
        with self.isolated_host():
            args = self.args(extra=("--apply",))
            installer.execute(args)
            receipt_path = installer.STATE_ROOT / "controller/state.json"
            receipt = json.loads(receipt_path.read_text())
            receipt.pop("native_options")
            receipt_path.write_text(json.dumps(receipt))
            before = self.tree()
            args.resume, args.install_dependencies = True, True
            provision = installer.provisioning_module()
            with mock.patch.object(provision, "install_dependencies") as packages, self.assertRaises(installer.InstallerError):
                installer.execute(args)
            packages.assert_not_called()
            self.assertEqual(before, self.tree())

    def test_database_provisioning_never_adopts_an_imported_existing_controller_config(self):
        with self.isolated_host(), self.synthetic_certificate_acceptance():
            approval, _, _, _ = self.approval_input()
            args = self.args(extra=("--apply", "--provision-mysql", "--approval", str(approval)))
            before = self.tree()
            provision = installer.provisioning_module()
            with mock.patch.object(provision, "install_dependencies") as packages, mock.patch.object(provision, "provision_mysql") as database, self.assertRaises(installer.InstallerError):
                installer.execute(args)
            packages.assert_not_called()
            database.assert_not_called()
            self.assertEqual(before, self.tree())

    def native_grants_module(self):
        path = Path(__file__).with_name("test_cloud_mysql_grants.py")
        spec = importlib.util.spec_from_file_location("cloud_native_grants_guard_unit", path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        previous = sys.dont_write_bytecode
        try:
            sys.dont_write_bytecode = True
            spec.loader.exec_module(module)
        finally:
            sys.dont_write_bytecode = previous
        return module

    def test_native_grants_entry_rejects_root_missing_fixture_and_external_paths_without_commands(self):
        native = self.native_grants_module()
        before = self.tree()
        with mock.patch.object(native.os, "geteuid", return_value=0), self.assertRaises(native.ContractError):
            native.validate_fixture({})
        with mock.patch.object(native.os, "geteuid", return_value=501), mock.patch.object(native.platform, "system", return_value="Linux"), mock.patch.object(native.platform, "machine", return_value="x86_64"):
            with self.assertRaisesRegex(native.ContractError, "FIXTURE_ENV_REQUIRED"):
                native.validate_fixture({})
            fixture = self.root / "aster-mysql.12345678"
            env = {"RUNNER_TEMP": str(self.root), "ASTER_NATIVE_MYSQL_FIXTURE_ROOT": str(fixture), "ASTER_NATIVE_MYSQL_ROOT": str(fixture / "distribution/usr"), "ASTER_NATIVE_MYSQL_SOCKET": "/run/mysqld/mysqld.sock", "ASTER_NATIVE_MYSQL_ADMIN_CNF": str(fixture / "admin.cnf")}
            with self.assertRaisesRegex(native.ContractError, "PATHS_MUST_MATCH"):
                native.validate_fixture(env)
        self.assertEqual(before, self.tree())

    def test_native_grants_private_client_files_keep_passwords_out_of_arguments_and_environment(self):
        native = self.native_grants_module()
        password = 'DO_NOT_PRINT_#quoted"\\native_password'
        config = native.account_config(self.root, "aster_cg_r123456abcdef", password)
        self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o600)
        fixture = native.Fixture(self.root, self.root / "distribution/usr", self.root / "mysql.sock", config, self.root / "distribution/usr/bin/mysql")
        client = native.Client(fixture, self.root, config, principal="aster_cg_r123456abcdef")
        result = types.SimpleNamespace(returncode=0, stdout=b"1\n", stderr=b"")
        with mock.patch.object(native.subprocess, "run", return_value=result) as run:
            self.assertEqual(client.run("SELECT 1;\n"), b"1\n")
        argv, kwargs = run.call_args.args[0], run.call_args.kwargs
        self.assertNotIn("DO_NOT_PRINT", " ".join(argv) + json.dumps(kwargs["env"]))
        self.assertEqual(argv[:3], [str(fixture.client), "--defaults-file=" + str(config), "--no-login-paths"])
        self.assertEqual(kwargs["input"], b"SELECT 1;\n")
        self.assertIn("--protocol=SOCKET", argv)
        self.assertIn("--socket=" + str(fixture.socket), argv)
        self.assertIn("--no-login-paths", argv)
        self.assertFalse(any(arg.startswith("--password") for arg in argv))
        self.assertNotIn("MYSQL_PWD", kwargs["env"])

    def test_native_grants_negative_checks_do_not_mistake_auth_or_syntax_failures_for_permission_proof(self):
        native = self.native_grants_module()
        fixture = native.Fixture(self.root, self.root, self.root / "mysql.sock", self.root / "client.cnf", self.root / "mysql")
        client = native.Client(fixture, self.root, fixture.admin_cnf, principal="aster_cg_r123456abcdef")
        for response in (
            types.SimpleNamespace(returncode=1, stdout=b"", stderr=b"ERROR 1045 (28000): private authentication failure"),
            types.SimpleNamespace(returncode=1, stdout=b"aster_cg_r123456abcdef@localhost\n", stderr=b"ERROR 1064 (42000): syntax error"),
        ):
            with self.subTest(error=response.stderr[:10]), mock.patch.object(native.subprocess, "run", return_value=response), self.assertRaises(native.ContractError):
                client.run("CREATE TABLE forbidden(id INT);", denied=True)
        denied = types.SimpleNamespace(returncode=1, stdout=b"aster_cg_r123456abcdef@localhost\n", stderr=b"ERROR 1142 (42000): CREATE command denied")
        with mock.patch.object(native.subprocess, "run", return_value=denied):
            client.run("CREATE TABLE forbidden(id INT);", denied=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)

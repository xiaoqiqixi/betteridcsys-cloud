#!/usr/bin/env python3
"""Local installer unit tests. No package/service/network/VM host actions."""
import argparse
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import ssl
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("aster_install_unit", Path(__file__).with_name("install.py"))
i = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = i
SPEC.loader.exec_module(i)
p = i.provisioning_module()


class InstallerUnits(unittest.TestCase):
    def test_apply_target_rejects_26_unknown_and_other_platforms_before_host_access(self):
        base = {"system": "Linux", "architecture": "x86_64", "distribution": "ubuntu", "version": "24.04"}
        for change in ({"version": "26.04"}, {"version": "unknown"}, {"version": "24.10"},
                       {"version": "20.04"}, {"distribution": "debian"},
                       {"architecture": "aarch64"}, {"system": "Darwin"}):
            with self.subTest(change=change), mock.patch.object(i, "target_info", return_value={**base, **change}), \
                    mock.patch.object(i.os, "geteuid", return_value=0), mock.patch.object(i, "protected_path") as path:
                with self.assertRaisesRegex(i.InstallerError, "Ubuntu 22.04 or 24.04"):
                    i.check_target()
                path.assert_not_called()
        for version in ("22.04", "24.04"):
            with self.subTest(version=version), mock.patch.object(i, "target_info", return_value={**base, "version": version}), \
                    mock.patch.object(i.os, "geteuid", return_value=0), mock.patch.object(i, "protected_path"), \
                    mock.patch.object(Path, "is_dir", return_value=True):
                i.check_target()

    def test_dependency_target_allows_only_22_24_and_rejects_before_commands(self):
        for version, expected in (("22.04", "jammy"), ("24.04", "noble"),
                                  ("26.04", None), ("unknown", None), ("24.10", None)):
            with self.subTest(version=version), mock.patch.object(p.os, "geteuid", return_value=0), \
                    mock.patch.object(p.platform, "system", return_value="Linux"), \
                    mock.patch.object(p.platform, "machine", return_value="x86_64"), \
                    mock.patch.object(Path, "read_text", return_value='ID=ubuntu\nVERSION_ID="' + version + '"\n'), \
                    mock.patch.object(p, "run_fixed") as run:
                if expected:
                    self.assertEqual(p.root_target(), expected)
                else:
                    with self.assertRaisesRegex(p.ProvisionError, "Ubuntu 22.04 or 24.04"):
                        p.root_target()
                run.assert_not_called()

    def test_libvirt_package_plan_is_fixed_for_each_verified_ubuntu_target(self):
        base = list(p.PACKAGES["node"]) + ["libvirt-daemon-system"]
        for codename in ("jammy", "noble"):
            with self.subTest(codename=codename):
                expected = base
                plan = p.dependency_plan("node", with_libvirt=True, codename=codename)
                self.assertEqual(plan["packages"], expected)
                self.assertTrue(plan["node_daemon_included"])
                self.assertEqual(p.dependency_plan("node", codename=codename)["packages"], list(p.PACKAGES["node"]))
                self.assertEqual(p.dependency_plan("controller", codename=codename)["packages"], list(p.PACKAGES["controller"]))
        for codename in (None, "", "bionic", "resolute", "unknown", "resolute; arbitrary"):
            with self.subTest(codename=codename), self.assertRaises(p.ProvisionError):
                p.dependency_plan("node", with_libvirt=True, codename=codename)

    def test_libvirt_plan_digest_preserves_22_24_and_rejects_deferred_releases(self):
        self.assertEqual(p.libvirt_plan_digest("jammy"), p.libvirt_plan_digest("noble"))
        with self.assertRaises(p.ProvisionError):
            p.libvirt_plan_digest("resolute")
        for component in ("node", "controller"):
            for codename in ("resolute", "unknown", ""):
                with self.subTest(component=component, codename=codename), self.assertRaises(p.ProvisionError):
                    p.dependency_plan(component, codename=codename)

    def test_apt_failures_report_only_fixed_categories_without_replaying_commands(self):
        cases = (
            (b"Temporary failure resolving 'secret.invalid'", "APT_DNS_FAILURE"),
            (b"Certificate verification failed: bearer SECRET", "APT_TLS_FAILURE"),
            (b"NO_PUBKEY SECRET", "APT_SIGNATURE_FAILURE"),
            (b"The repository 'https://secret.invalid' does not have a Release file", "APT_METADATA_FAILURE"),
            (b"Unable to locate package SECRET", "APT_PACKAGE_UNAVAILABLE"),
            (b"Unable to correct problems, you have held broken packages SECRET", "APT_DEPENDENCY_CONFLICT"),
            (b"Could not get lock SECRET", "APT_LOCKED"),
            (b"unknown SECRET", "APT_COMMAND_REJECTED"),
        )
        for diagnostic, code in cases:
            with self.subTest(code=code):
                result = argparse.Namespace(returncode=100, stdout=b"SECRET output", stderr=diagnostic)
                output = io.StringIO()
                with mock.patch.object(p.subprocess, "run", return_value=result) as run, contextlib.redirect_stdout(output), contextlib.redirect_stderr(output), self.assertRaises(p.ProvisionError) as error:
                    p.run_fixed([p.APT_GET, "--simulate", "--no-upgrade", "--no-remove", "install", "libvirt-daemon-system"])
                self.assertEqual(getattr(error.exception, "code", None), code)
                self.assertNotIn("SECRET", str(error.exception) + output.getvalue())
                self.assertNotIn("secret.invalid", str(error.exception) + output.getvalue())
                self.assertEqual(run.call_count, 1)

    def test_libvirt_firewall_snapshot_ignores_only_traffic_counters_and_clock_comments(self):
        first = "# Generated at first time\n*filter\n:INPUT ACCEPT [123:456]\n-A INPUT -s 192.0.2.1 -j DROP\nCOMMIT\n"
        second = first.replace("first time", "second time").replace("123:456", "9999:88888")
        normalized = p.normalize_firewall_evidence("iptables", first)
        self.assertEqual(normalized, p.normalize_firewall_evidence("iptables", second))
        self.assertIn("-s 192.0.2.1 -j DROP", normalized)
        self.assertIn(":INPUT ACCEPT [0:0]", normalized)
        for changed in (first.replace("ACCEPT", "DROP"), first.replace("192.0.2.1", "192.0.2.2"), first.replace("-j DROP", "-j ACCEPT")):
            self.assertNotEqual(normalized, p.normalize_firewall_evidence("iptables", changed))

    def test_libvirt_effective_units_reject_every_foreign_override_before_start(self):
        def effective(argv, **kwargs):
            return ("FragmentPath=" + str(p.UNIT_ROOT / argv[2]) + "\nDropInPaths=\n").encode()
        with mock.patch.object(p, "run_fixed", side_effect=effective) as run:
            p.verify_libvirt_effective_units()
        self.assertEqual(len(run.call_args_list), 3)
        self.assertTrue(all(call.args[0][1] == "show" for call in run.call_args_list))
        for raw in (b"FragmentPath=/foreign/unit\nDropInPaths=\n", b"FragmentPath=/etc/systemd/system/aster-cloud-virtlogd.service\nDropInPaths=/usr/lib/systemd/system/foreign.conf\n"):
            with self.subTest(raw=raw), mock.patch.object(p, "run_fixed", return_value=raw), self.assertRaises(p.ProvisionError):
                p.verify_libvirt_effective_units()

    def test_libvirt_namespace_checks_real_process_inode_and_readonly_mount(self):
        properties = ("FragmentPath=" + str(p.UNIT_ROOT / "aster-cloud-libvirtd.service") + "\nDropInPaths=\nMainPID=812\n").encode()
        def resolve(path, **kwargs):
            return Path(p.LIBVIRTD) if str(path) == "/proc/812/exe" else path
        for inode, mount, accepted in ((5, "ro,relatime", True), (6, "ro,relatime", False), (5, "rw,relatime", False)):
            def info(path, **kwargs):
                return argparse.Namespace(st_dev=7, st_ino=5 if path == p.LIBVIRT_EMPTY else inode)
            with self.subTest(inode=inode, mount=mount), mock.patch.object(p, "run_fixed", return_value=properties), mock.patch.object(Path, "resolve", resolve), mock.patch.object(Path, "stat", info), mock.patch.object(Path, "read_text", return_value="100 1 7:0 /empty /etc/libvirt/qemu/networks " + mount + " - ext4 /dev/vda1 rw\n"):
                if accepted:
                    p.verify_libvirt_namespace()
                else:
                    with self.assertRaises(p.ProvisionError):
                        p.verify_libvirt_namespace()

    def test_libvirt_root_only_unix_configuration_never_disables_apparmor(self):
        self.assertIn(b"listen_tls = 0", p.LIBVIRT_DAEMON_CONFIG)
        self.assertIn(b"listen_tcp = 0", p.LIBVIRT_DAEMON_CONFIG)
        self.assertIn(b'unix_sock_rw_perms = "0700"', p.LIBVIRT_DAEMON_CONFIG)
        self.assertNotIn(b"security_driver", p.LIBVIRT_DAEMON_CONFIG)
        self.assertNotIn(b'user = "root"', p.LIBVIRT_DAEMON_CONFIG)
        for daemon in ("libvirtd", "virtlogd", "virtlockd", "virtnetworkd", "virtqemud", "virtproxyd"):
            self.assertIn(daemon + ".service", p.LIBVIRT_VENDOR_UNITS)
            self.assertIn(daemon + ".socket", p.LIBVIRT_VENDOR_UNITS)
            self.assertIn(daemon + "-tls.socket", p.LIBVIRT_VENDOR_UNITS)

    def test_actual_migration_sql_privileges_include_foreign_key_references(self):
        # Read the real embedded SQL, not a synthetic CREATE fixture. New DDL
        # classes require an explicit grant-policy review instead of silently
        # assuming CREATE alone covers indexes and foreign-key parent access.
        migrations = Path(__file__).resolve().parents[2] / "migrations"
        identity = (migrations / "002_console_identity.sql").read_text()
        self.assertRegex(identity, r"FOREIGN\s+KEY\s*\(user_id\)\s+REFERENCES\s+controller_console_users\s*\(id\)")
        required = set()
        for path in sorted(migrations.glob("[0-9]*.sql")):
            raw = path.read_text()
            if re.search(r"\bCREATE\s+TABLE\b", raw, re.I):
                required.add("CREATE")
            if re.search(r"\bCREATE\s+(?:UNIQUE\s+)?INDEX\b", raw, re.I):
                required.add("INDEX")
            if re.search(r"\bALTER\s+TABLE\b", raw, re.I):
                required.add("ALTER")
            if re.search(r"\bFOREIGN\s+KEY\b[\s\S]*?\bREFERENCES\b", raw, re.I):
                required.add("REFERENCES")
        self.assertIn("REFERENCES", required)
        self.assertLessEqual(required, set(p.MIGRATION_PRIVILEGES))
        self.assertEqual(set(p.RUNTIME_PRIVILEGES), {"SELECT", "INSERT", "UPDATE", "DELETE"})
        self.assertFalse(set(p.RUNTIME_PRIVILEGES) & {"CREATE", "ALTER", "INDEX", "REFERENCES", "DROP", "GRANT OPTION"})

    def certificate(self, sans, before=None, after=None):
        now = time.time()
        return {"subjectAltName": sans,
                "notBefore": time.strftime("%b %d %H:%M:%S %Y GMT", time.gmtime(before or now - 86400)),
                "notAfter": time.strftime("%b %d %H:%M:%S %Y GMT", time.gmtime(after or now + 86400 * 4))}

    @contextlib.contextmanager
    def cert_mocks(self, decoded, pair_error=None):
        with mock.patch.object(i, "protected_read", return_value=b"synthetic public/private PEM"), \
                mock.patch.object(i.ssl, "SSLContext") as ctx, \
                mock.patch.object(i.ssl._ssl, "_test_decode_cert", return_value=decoded):
            if pair_error:
                ctx.return_value.load_cert_chain.side_effect = pair_error
            yield ctx

    def test_certificate_requires_valid_pair_and_exact_san(self):
        with self.cert_mocks(self.certificate((("DNS", "cloud.example.test"),))) as ctx:
            i.validate_certificate("/real.crt", "/private.key", "cloud.example.test")
            ctx.return_value.load_cert_chain.assert_called_once_with("/real.crt", "/private.key")
            with self.assertRaises(i.InstallerError):
                i.validate_certificate("/real.crt", "/private.key", "wrong.example.test")
        with self.cert_mocks(self.certificate((("DNS", "cloud.example.test"),)), ssl.SSLError("MISMATCH")):
            with self.assertRaises(i.InstallerError):
                i.validate_certificate("/real.crt", "/private.key", "cloud.example.test")

    def test_certificate_rejects_expired_not_yet_valid_and_nearly_expired(self):
        now = time.time()
        for before, after in ((now - 86400, now - 1), (now + 10, now + 86400 * 3), (now - 1, now + 3600)):
            with self.subTest(before=before, after=after), self.cert_mocks(self.certificate((("DNS", "cloud.test"),), before, after)):
                with self.assertRaises(i.InstallerError):
                    i.validate_certificate("/crt", "/key", "cloud.test")

    def test_certificate_wildcard_is_one_leftmost_label_and_ip_requires_ip_san(self):
        with self.cert_mocks(self.certificate((("DNS", "*.example.test"), ("IP Address", "192.0.2.8")))):
            i.validate_certificate("/crt", "/key", "cloud.example.test")
            i.validate_certificate("/crt", "/key", "192.0.2.8")
            for host in ("example.test", "a.b.example.test", "other.test", "192.0.2.9"):
                with self.subTest(host=host), self.assertRaises(i.InstallerError):
                    i.validate_certificate("/crt", "/key", host)
        with self.cert_mocks(self.certificate((("DNS", "192.0.2.8"),))):
            with self.assertRaises(i.InstallerError):
                i.validate_certificate("/crt", "/key", "192.0.2.8")

    def test_origin_rejects_systemd_and_url_injection(self):
        for origin in ("https://ok.test\nExecStart=/bin/evil", "https://ok.test/%n", "https://user:password@ok.test", "http://ok.test", "https://ok.test?q=secret", "https://ok.test#secret", "https://ok.test:0"):
            with self.subTest(origin=origin), self.assertRaises(i.InstallerError):
                i.parse_origin(origin)
        self.assertEqual(i.parse_origin("https://cloud.example.test:9443"), ("cloud.example.test", 9443))

    def test_node_has_no_tls_bypass_or_controller_private_identity_probe(self):
        with mock.patch.object(i.ssl, "create_default_context") as context:
            with self.assertRaises(i.InstallerError):
                i.strict_health("node", {}, {})
            context.assert_not_called()
        with mock.patch.object(i.socket, "create_connection") as connect:
            i.node_listener_check({"listen": "0.0.0.0:9443"})
            connect.assert_called_once_with(("127.0.0.1", 9443), timeout=5)

    def test_write_new_respects_exact_mode_despite_umask_and_preserves_existing(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(i, "protected_path", side_effect=lambda p, **_: Path(p)):
            p = Path(directory) / "config.json"
            previous = os.umask(0o077)
            try:
                i.write_new(p, b"original", 0o644)
            finally:
                os.umask(previous)
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o644)
            with mock.patch.object(i, "protected_read", side_effect=lambda p, *args: Path(p).read_bytes()):
                i.write_new(p, b"original", 0o644)
                with self.assertRaises(i.InstallerError):
                    i.write_new(p, b"replacement", 0o644)
            self.assertEqual(p.read_bytes(), b"original")

    def test_pending_atomic_state_needs_explicit_resume_and_matching_bundle(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(i, "protected_path", side_effect=lambda p, **_: Path(p)), \
                mock.patch.object(i, "protected_read", side_effect=lambda p, *args: Path(p).read_bytes()):
            state = Path(directory) / "state.json"
            pending = state.with_name("state.new")
            content = {"schema": 1, "component": "controller", "bundle_sha256": "a" * 64, "steps": ["software-installed"]}
            pending.write_text(json.dumps(content))
            args = argparse.Namespace(component="controller", sha256="a" * 64, resume=False)
            with self.assertRaises(i.InstallerError):
                i.recover_pending_state(state, args)
            self.assertTrue(pending.exists())
            args.resume, args.sha256 = True, "b" * 64
            with self.assertRaises(i.InstallerError):
                i.recover_pending_state(state, args)
            self.assertTrue(pending.exists())
            args.sha256 = "a" * 64
            i.recover_pending_state(state, args)
            self.assertEqual(json.loads(state.read_text()), content)
            self.assertFalse(pending.exists())

    def test_invalid_pending_receipt_is_not_deleted_or_promoted(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(i, "protected_read", side_effect=lambda p, *args: Path(p).read_bytes()):
            state = Path(directory) / "state.json"
            pending = state.with_name("state.new")
            pending.write_bytes(b'{"schema":')
            with self.assertRaises(i.InstallerError):
                i.recover_pending_state(state, argparse.Namespace(component="node", sha256="a" * 64, resume=True))
            self.assertEqual(pending.read_bytes(), b'{"schema":')
            self.assertFalse(state.exists())

    def test_main_withholds_oserror_paths_and_secrets(self):
        output = io.StringIO()
        with mock.patch.object(i, "execute", side_effect=OSError("mysql-secret-token /root/private.key")), contextlib.redirect_stderr(output):
            self.assertEqual(i.main(["controller"]), 1)
        self.assertNotIn("mysql-secret-token", output.getvalue())
        self.assertNotIn("/root/private.key", output.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)

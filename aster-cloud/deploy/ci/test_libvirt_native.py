#!/usr/bin/env python3
"""Offline harness contracts, not cryptographic/native/KVM acceptance."""
import argparse
import ast
import copy
import contextlib
import hashlib
import importlib.util
import json
import io
import socket
import threading
import os
from pathlib import Path
import re
import subprocess
import tempfile
import types
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


h = load("libvirt_native_contract", "libvirt-native.py")
g = load("libvirt_native_guest_contract", "libvirt-native-guest.py")


class NativeFixtureContract(unittest.TestCase):
    def checks(self):
        names = ("ubuntu_at_least_22", "x86_64_host", "hardware_virtualization_flags", "dev_kvm_read_write",
                 "binary:/usr/bin/virsh", "binary:/usr/bin/qemu-img", "binary:/usr/bin/qemu-system-x86_64",
                 "storage_directory", "libvirt_system_readonly_query")
        return {name: name not in ("hardware_virtualization_flags", "dev_kvm_read_write") for name in names}

    def report(self):
        return {"protocol": "aster.node/1", "node_id": "native-tcg-node", "ready": False,
                "checks": [{"name": k, "passed": v} for k, v in self.checks().items()]}

    def result(self):
        value = {k: True for k in ("passed", "real_apt", "real_systemd", "libvirt_prepared", "explicit_kvm_denial",
                                  "non_kvm_doctor_checks_passed", "real_approved_image_validated", "owned_units_active",
                                  "vendor_masks_persistent", "empty_network_mount_verified", "unix_libvirt_query_passed",
                                  "default_network_absent", "virbr_absent", "libvirt_no_tcp_listener", "vendor_default_xml_retained_unchanged_on_resume")}
        value.update(schema=1, kvm_ready=False, source_sha="a" * 40, ubuntu="22.04", image_sha256=h.IMAGES["22.04"][2], doctor_checks=self.checks(), doctor_protocol=g.DOCTOR_PROTOCOL)
        return value

    def metadata(self):
        return {"source_sha": "a" * 40, "ubuntu": "22.04", "image_sha256": h.IMAGES["22.04"][2]}

    def test_python_310_syntax(self):
        for name in ("libvirt-native.py", "libvirt-native-guest.py", "test_libvirt_native.py"):
            ast.parse((HERE / name).read_text(), feature_version=(3, 10))

    def test_only_fixed_signed_dated_official_images(self):
        self.assertEqual(set(h.IMAGES), {"22.04", "24.04"})
        for ubuntu, (suite, date, sha) in h.IMAGES.items():
            self.assertRegex(date, r"^[0-9]{8}$")
            self.assertRegex(sha, r"^[0-9a-f]{64}$")
            self.assertNotIn(suite, ("current", "latest", "release"))
            self.assertNotEqual(sha, "0" * 64)
        self.assertEqual(h.IMAGES["22.04"][0], "jammy")
        self.assertEqual(h.IMAGES["24.04"][0], "noble")

    def test_deferred_and_unknown_releases_stop_before_any_fixture_execution(self):
        for version in ("26.04", "24.10", "unknown"):
            with self.subTest(version=version), mock.patch.object(h, "execute") as execute, \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                h.main(["--ubuntu", version, "--source-root", "/unused", "--source-sha", "a" * 40, "--output", "/unused"])
            self.assertEqual(error.exception.code, 2)
            execute.assert_not_called()

    def test_supported_release_inventory_matches_installer_workflow_and_sandbox(self):
        repo = HERE.parents[2]
        provision = load("libvirt_native_supported_provision", "../install/provision.py")
        self.assertEqual(provision.CODENAMES, {"22.04": "jammy", "24.04": "noble"})
        workflow = (repo / ".github/workflows/cloud.yml").read_text()
        self.assertEqual(re.findall(r"ubuntu: '([^']+)'", workflow), ["22.04", "24.04"])
        sandbox = (HERE / "libvirt-native-sandbox.c").read_text()
        self.assertEqual(re.findall(r'"ubuntu-([0-9.]+)-server-cloudimg-amd64.img"', sandbox), ["22.04", "24.04"])

    def test_public_key_is_independently_code_pinned(self):
        raw = (HERE / "libvirt-native-image-key.asc").read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), h.KEY_SHA256)
        self.assertEqual(h.KEY_FINGERPRINT, "D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81")
        self.assertIn(b"BEGIN PGP PUBLIC KEY BLOCK", raw)
        self.assertNotIn(b"PRIVATE KEY", raw)

    def test_doctor_protocol_matches_real_production_constant_not_task_protocol(self):
        contract = (HERE.parents[1] / "internal/nodeproto/contract.go").read_text()
        actual = re.search(r'const Protocol = "([^"]+)"', contract).group(1)
        self.assertEqual(g.DOCTOR_PROTOCOL, actual)

    def test_boot_checkpoints_preserve_existing_commands_and_fixed_sequence(self):
        nonce = "a" * 32
        commands = h.seed_commands(nonce)
        boot = commands["bootcmd"]
        self.assertEqual(len(boot), 7)
        self.assertEqual(boot[2], ["sh", "-c", "systemctl mask --now apt-daily.service apt-daily-upgrade.service apt-daily.timer apt-daily-upgrade.timer ssh.service ssh.socket || true"])
        self.assertEqual(boot[5], ["sh", "-c", h.HOSTS_BOOT_COMMAND])
        for index, stage in ((0, "bootcmd"), (1, "boot-mask:start"), (3, "boot-mask:done"), (4, "boot-hosts:start"), (6, "boot-hosts:done")):
            self.assertIn(stage, h.BOOT_STAGES)
            self.assertEqual(boot[index], ["sh", "-c", "printf '%s\\n' 'ASTER_LIBVIRT_NATIVE_PROGRESS_" + nonce + " " + stage + "' > /dev/ttyS0"])
        self.assertIn("runcmd-enter", commands["runcmd"][0][2])
        self.assertEqual(commands["runcmd"][1], ["sh", "-c", "/usr/bin/python3 -I /root/aster-native/guest.py; /sbin/poweroff -f"])
        with self.assertRaises(h.Refused): h.seed_commands("bad;command")

    def test_hosts_boot_command_produces_real_newlines_without_host_write(self):
        suffix = " >> /etc/hosts"
        self.assertTrue(h.HOSTS_BOOT_COMMAND.endswith(suffix))
        # Execute only the fixed printf, with the redirection removed. This
        # checks actual shell escaping without touching any host configuration.
        p = subprocess.run(["/bin/sh", "-c", h.HOSTS_BOOT_COMMAND[:-len(suffix)]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        self.assertEqual(p.stdout, b"\n10.0.2.100 archive.ubuntu.com\n10.0.2.101 security.ubuntu.com\n")

    def test_signature_status_requires_exact_expected_key(self):
        # Simulated GnuPG status is a parser test, not a signature proof.
        h.verify_signature(("[GNUPG:] VALIDSIG " + h.KEY_FINGERPRINT + " 2026 1 0 4 0 1 10 00\n").encode())
        for status in (b"", b"[GNUPG:] GOODSIG 123 Example\n", b"[GNUPG:] VALIDSIG " + b"a" * 40 + b" rest\n",
                       ("[GNUPG:] BADSIG 123\n[GNUPG:] VALIDSIG " + h.KEY_FINGERPRINT + " rest\n").encode()):
            with self.subTest(status=status), self.assertRaises(h.Refused):
                h.verify_signature(status)

    def test_https_redirect_never_downgrades_or_changes_origin(self):
        for url in ("http://cloud-images.ubuntu.com/image", "https://evil.invalid/image", "https://user@cloud-images.ubuntu.com/image"):
            with self.subTest(url=url), self.assertRaises(h.Refused):
                h.HTTPSOnly().redirect_request(None, None, 302, "", {}, url)

    def test_network_downloader_has_no_inherited_proxy(self):
        source = (HERE / "libvirt-native.py").read_text()
        self.assertIn("ProxyHandler({})", source)
        self.assertNotIn("CERT_NONE", source)
        self.assertNotIn("check_hostname = False", source)

    def test_payload_qemu_network_is_fixed_restricted_user_mode(self):
        args = h.qemu_arguments(Path("/tmp/owned"), Path("/tmp/base.img"), Path("/tmp/root.qcow2"), Path("/tmp/seed.img"), nonce="a" * 32)
        text = " ".join(args)
        self.assertIn("pc,accel=tcg", args)
        self.assertIn("max,vmx=off,svm=off", args)
        self.assertIn("3072", args)
        self.assertIn("restrict=on,ipv6=off", text)
        self.assertIn("guestfwd=tcp:10.0.2.100:443-cmd:/usr/bin/python3 -I /tmp/owned/relay.py archive.ubuntu.com", text)
        self.assertIn("guestfwd=tcp:10.0.2.101:443-cmd:/usr/bin/python3 -I /tmp/owned/relay.py security.ubuntu.com", text)
        for forbidden in ("hostfwd=", "tap,", "bridge,", "virtfs", "9p", "-enable-kvm", "accel=kvm", "-netdev socket", "tftp=", "smb="):
            self.assertNotIn(forbidden, text)
        self.assertIn("format=raw,readonly=on", text)
        self.assertIn("-no-reboot", args)

    def test_relay_is_not_an_arbitrary_connect_proxy(self):
        for host in ("localhost", "127.0.0.1", "169.254.169.254", "github.com", "archive.ubuntu.com:443"):
            with self.subTest(host=host), self.assertRaises(h.Refused), mock.patch.object(h.socket, "getaddrinfo") as lookup:
                h.relay(host)
            lookup.assert_not_called()
        with mock.patch.object(h, "record_relay_identity"), mock.patch.object(h.socket, "getaddrinfo", return_value=[(2, 1, 6, "", ("127.0.0.1", 443))]), self.assertRaises(h.Refused):
            h.relay("archive.ubuntu.com", "a" * 32)

    def test_real_relay_drains_server_response_after_guest_pipe_eof(self):
        target, server = socket.socketpair()
        read_fd, write_fd = os.pipe()
        os.write(write_fd, b"request")
        os.close(write_fd)
        response, received, events = io.BytesIO(), [], []
        def remote():
            server.settimeout(1)
            try:
                chunks = []
                while True:
                    block = server.recv(1024)
                    if not block: break
                    chunks.append(block)
                received.append(b"".join(chunks))
                server.sendall(b"response-after-half-close")
                server.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            finally:
                server.close()
        worker = threading.Thread(target=remote)
        worker.start()
        try:
            with os.fdopen(read_fd, "rb", buffering=0) as request:
                target.setblocking(False)
                h.relay_stream(target, request, response, events.append)
        finally:
            target.close()
            worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(received, [b"request"])
        self.assertEqual(response.getvalue(), b"response-after-half-close")
        self.assertLess(events.index("guest-eof"), events.index("server-first-bytes"))
        self.assertIn("server-eof", events)

    def test_relay_private_events_are_nonce_bound_and_redacted_to_static_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory); work.chmod(0o700)
            with mock.patch.object(h, "__file__", str(work / "relay.py")):
                h.relay_event("archive.ubuntu.com", "a" * 32, "spawned")
                h.relay_event("archive.ubuntu.com", "a" * 32, "connect-ok")
                h.relay_event("security.ubuntu.com", "b" * 32, "spawned")
                h.relay_event("SECRET_HOST", "a" * 32, "spawned")
                h.relay_event("archive.ubuntu.com", "a" * 32, "SECRET_ERROR")
            proof = h.relay_evidence(work, {"nonce": "a" * 32})
            self.assertTrue(proof["spawned_seen"])
            self.assertEqual(proof["counts"], {"archive.ubuntu.com": {"spawned": 1, "connect-ok": 1}, "security.ubuntu.com": {}})
            self.assertNotIn("SECRET", json.dumps(proof)); self.assertNotIn("a" * 32, json.dumps(proof))
            self.assertEqual((work / "relay-events.jsonl").stat().st_mode & 0o777, 0o600)
            (work / "relay-events.jsonl").chmod(0o644)
            self.assertEqual(h.relay_evidence(work, {"nonce": "a" * 32}), {"diagnostic_rejected": True})

    def test_relay_never_exposes_credentials_or_allows_nonpublic_dns(self):
        events = []
        with mock.patch.object(h, "record_relay_identity"), mock.patch.object(h, "relay_event", side_effect=lambda host, nonce, event: events.append(event)), mock.patch.object(h.socket, "getaddrinfo", return_value=[(2, 1, 6, "", ("198.18.0.10", 443))]), self.assertRaises(h.Refused):
            h.relay("archive.ubuntu.com", "a" * 32)
        self.assertEqual(events, ["spawned", "dns-nonpublic"])
        with mock.patch.object(h.socket, "getaddrinfo") as lookup, self.assertRaises(h.Refused):
            h.relay("archive.ubuntu.com", "SECRET_INVALID_NONCE")
        lookup.assert_not_called()

    def test_no_secret_environment_is_forwarded(self):
        self.assertEqual(set(h.SAFE_ENV), {"PATH", "LANG"})
        source = (HERE / "libvirt-native.py").read_text()
        self.assertIn("start_new_session=True", source)
        self.assertIn("os.killpg(process.pid", source)
        self.assertNotIn("process_group=", source)
        self.assertNotIn("shutil.copytree", source)
        self.assertNotIn("os.environ.copy()", source)

    def test_doctor_must_reach_json_and_explicit_dev_kvm_check(self):
        self.assertEqual(g.doctor_evidence(1, self.report()), self.checks())
        for report in ({}, {"ready": False}, {"protocol": "aster.node/1", "node_id": "native-tcg-node", "ready": False, "checks": []}):
            with self.subTest(report=report), self.assertRaises(g.Refused):
                g.doctor_evidence(1, report)
        with self.assertRaises(g.Refused):
            g.doctor_evidence(0, self.report())

    def test_every_other_real_doctor_check_must_pass(self):
        for name in self.checks():
            if name in ("dev_kvm_read_write", "hardware_virtualization_flags"):
                continue
            report = self.report()
            next(c for c in report["checks"] if c["name"] == name)["passed"] = False
            with self.subTest(name=name), self.assertRaises(g.Refused):
                g.doctor_evidence(1, report)

    def test_doctor_cannot_claim_missing_image_or_rejected_configuration_is_kvm_denial(self):
        report = self.report(); report["node_id"] = "wrong-node"
        with self.assertRaises(g.Refused): g.doctor_evidence(1, report)
        report = self.report(); report["checks"].append(copy.deepcopy(report["checks"][0]))
        with self.assertRaises(g.Refused): g.doctor_evidence(1, report)
        report = self.report(); next(c for c in report["checks"] if c["name"] == "dev_kvm_read_write")["passed"] = True
        with self.assertRaises(g.Refused): g.doctor_evidence(1, report)

    def test_result_bindings_and_all_proofs_are_required(self):
        h.validate_result(self.result(), self.metadata())
        for key, value in (("source_sha", "b" * 40), ("image_sha256", "b" * 64), ("ubuntu", "24.04"), ("kvm_ready", True),
                           ("real_apt", False), ("real_systemd", False), ("default_network_absent", False), ("libvirt_prepared", False)):
            result = self.result(); result[key] = value
            with self.subTest(key=key), self.assertRaises(h.Refused): h.validate_result(result, self.metadata())
        result = self.result(); result["secret"] = "must never export"
        with self.assertRaises(h.Refused): h.validate_result(result, self.metadata())

    def test_host_rechecks_explicit_doctor_evidence(self):
        result = self.result(); result["doctor_checks"]["dev_kvm_read_write"] = True
        with self.assertRaises(h.Refused): h.validate_result(result, self.metadata())
        result = self.result(); result["doctor_checks"]["libvirt_system_readonly_query"] = False
        with self.assertRaises(h.Refused): h.validate_result(result, self.metadata())

    def test_guest_uses_real_approved_image_and_no_fake_kvm(self):
        source = (HERE / "libvirt-native-guest.py").read_text()
        self.assertIn('"/dev/vdb"', source)
        self.assertIn('sha(image) == metadata["image_sha256"]', source)
        self.assertIn('info.get("format") == "qcow2"', source)
        self.assertIn("module.prepare_libvirt(state)", source)
        self.assertIn("module.prepare_libvirt(state, resume=True)", source)
        self.assertNotIn("mknod", source)
        self.assertNotIn("mock.patch", source)
        self.assertNotIn("security_driver", source)

    def test_only_public_json_outputs_not_serial_or_seed(self):
        source = (HERE / "libvirt-native.py").read_text()
        self.assertIn('work / "private-serial.log"', source)
        for name in ("summary.json", "guest-report.json", "image-provenance.json"):
            self.assertIn('output / "' + name + '"', source)
        self.assertNotIn('output / "private-serial.log"', source)
        self.assertNotIn('output / "user-data"', source)

    def test_no_native_or_host_write_on_unsupported_platform(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "out"
            args = argparse.Namespace(ubuntu="22.04", source_root=directory, source_sha="a" * 40, output=str(out))
            with mock.patch.object(h.platform, "system", return_value="Darwin"), mock.patch.object(h, "run") as command, self.assertRaises(h.Refused):
                h.execute(args)
            command.assert_not_called(); self.assertFalse(out.exists())

    def test_input_links_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "file"; p.write_bytes(b"test"); p.chmod(0o600)
            h.regular(p, 16)
            linked = p.with_name("link"); linked.symlink_to(p)
            with self.assertRaises(h.Refused): h.regular(linked, 16)
            linked.unlink(); os.link(p, linked)
            with self.assertRaises(h.Refused): h.regular(p, 16)

    def test_apt_plan_diagnostics_use_real_rejection_branches_without_versions(self):
        plan = (b"Inst new-safe-package (1.0 Ubuntu)\n"
                b"Inst libssl3t64:amd64 [PRIVATE_OLD] (PRIVATE_NEW Ubuntu)\n"
                b"Remv libc6 [PRIVATE_VERSION]\n"
                b"Inst openvswitch-switch (PRIVATE_NEW Ubuntu)\n")
        result = g.classify_apt_plan(plan)
        self.assertEqual(result, {"categories": ["installed-package-version-change", "remove", "unapproved-network-daemon"],
                                 "packages": ["libc6", "libssl3t64", "openvswitch-switch"],
                                 "unknown_package_count": 0, "truncated": False})
        self.assertNotIn("PRIVATE", json.dumps(result))
        self.assertEqual(g.APT_PLAN_PACKAGES, h.APT_PLAN_PACKAGES)
        self.assertEqual(g.APT_PLAN_CATEGORIES, h.APT_PLAN_CATEGORIES)

    def test_apt_plan_diagnostics_bounds_unknown_names_and_invalid_bytes(self):
        result = g.classify_apt_plan(b"Inst token-secret [PRIVATE] (https://credential:secret@host/path)\nRemv /private/path [SECRET]\n")
        self.assertEqual(result["packages"], [])
        self.assertEqual(result["unknown_package_count"], 2)
        self.assertNotIn("secret", json.dumps(result)); self.assertNotIn("private", json.dumps(result))
        names = sorted(g.APT_PLAN_PACKAGES)
        result = g.classify_apt_plan("".join("Remv " + name + " [private]\n" for name in names).encode())
        self.assertEqual(len(result["packages"]), 12); self.assertTrue(result["truncated"])
        result = g.classify_apt_plan("".join("Remv unknown-package-" + str(i) + "\n" for i in range(300)).encode())
        self.assertEqual(result["unknown_package_count"], 255); self.assertTrue(result["truncated"])
        for value in (None, "secret", b"\xff", b"x" * (1024 * 1024 + 1)):
            self.assertIsNone(g.classify_apt_plan(value))

    def test_apt_plan_observer_preserves_return_identity_and_diagnostic_errors(self):
        result = b"Inst libc6 [PRIVATE_OLD] (PRIVATE_NEW)\n"
        module = types.SimpleNamespace(run_fixed=mock.Mock(return_value=result))
        g.observe_real_commands(module)
        argv = ["/usr/bin/apt-get", "--simulate", "install", "libvirt-daemon-system"]
        with mock.patch.object(g, "APT_PLAN_DIAGNOSTICS", None):
            self.assertIs(module.run_fixed(argv, timeout=7), result)
            self.assertEqual(g.APT_PLAN_DIAGNOSTICS["packages"], ["libc6"])
            with mock.patch.object(g, "classify_apt_plan", side_effect=RuntimeError("PRIVATE")):
                self.assertIs(module.run_fixed(argv, timeout=7), result)
            self.assertIsNone(g.APT_PLAN_DIAGNOSTICS)

    def test_host_apt_plan_diagnostics_rejects_injected_schema_values_and_bounds(self):
        safe = g.classify_apt_plan(b"Inst libc6 [PRIVATE_OLD] (PRIVATE_NEW)\n")
        report = dict(self.metadata(), schema=1, passed=False, kvm_ready=False, code="APT_PLAN_UNSAFE", phase="prepare",
                      diagnostics={"apt_plan_rejections": safe})
        self.assertEqual(h.public_result(report, self.metadata())["diagnostics"]["apt_plan_rejections"], safe)
        for key, value in (("packages", ["PRIVATE"]), ("packages", ["libc6"] * 13), ("categories", ["PRIVATE"]),
                           ("unknown_package_count", True), ("unknown_package_count", -1), ("unknown_package_count", 256),
                           ("truncated", "PRIVATE"), ("raw", "PRIVATE")):
            changed = copy.deepcopy(report); changed["diagnostics"]["apt_plan_rejections"][key] = value
            output = h.public_result(changed, self.metadata())
            self.assertNotIn("apt_plan_rejections", output["diagnostics"])
            self.assertNotIn("PRIVATE", json.dumps(output))

    def test_real_command_observer_never_changes_calls_results_or_exceptions(self):
        calls, result = [], object()
        failure = RuntimeError("private stderr must not escape")
        def real(argv, **kwargs):
            calls.append((argv, kwargs))
            if argv[0] == "/usr/bin/apt-get": raise failure
            return result
        module = types.SimpleNamespace(run_fixed=real)
        g.observe_real_commands(module)
        with mock.patch.object(g, "FAILED_COMMANDS", []):
            argv, kwargs = ["/usr/bin/virsh", "capabilities"], {"timeout": 19, "env": {"PRIVATE": "not exported"}}
            self.assertIs(module.run_fixed(argv, **kwargs), result)
            self.assertEqual(calls[-1], (argv, kwargs))
            with self.assertRaises(RuntimeError) as raised:
                module.run_fixed(["/usr/bin/apt-get", "--simulate", "install", "private-value"])
            self.assertIs(raised.exception, failure)
            self.assertEqual(g.FAILED_COMMANDS, ["apt-simulate"])

    def test_failed_public_report_exports_only_fixed_enums_not_nested_values(self):
        report = dict(self.metadata(), schema=1, passed=False, kvm_ready=False, code="APT_PLAN_UNSAFE", phase="prepare",
                      doctor_checks={"secret": "must not export"}, arbitrary="must not export",
                      diagnostics={"failed_commands": ["apt-simulate", "SECRET_ARGV", {"argv": "secret"}],
                                   "dependencies_status": "failed-package-transaction-review-required",
                                   "libvirt_status": "SECRET_NONCE", "dependencies_steps": ["policy-created", "SECRET_PASSWORD"],
                                   "argv": ["secret"]})
        public = h.public_result(report, self.metadata())
        self.assertEqual(public["code"], "APT_PLAN_UNSAFE")
        self.assertEqual(public["diagnostics"], {"failed_commands": ["apt-simulate"],
                         "dependencies_status": "failed-package-transaction-review-required", "dependencies_steps": ["policy-created"]})
        self.assertNotIn("SECRET", json.dumps(public)); self.assertNotIn("secret", json.dumps(public))
        report.update(code="ARBITRARY_SECRET", phase="ARBITRARY_SECRET")
        public = h.public_result(report, self.metadata())
        self.assertEqual(public["code"], "GUEST_REPORTED_FAILURE"); self.assertEqual(public["phase"], "unrecognized")
        report["source_sha"] = "b" * 40
        with self.assertRaises(h.Refused): h.public_result(report, self.metadata())

    def test_public_success_is_fully_validated_before_export(self):
        self.assertEqual(h.public_result(self.result(), self.metadata()), self.result())
        for extra in ("code", "phase", "diagnostics"):
            result = self.result(); result[extra] = "secret"
            with self.subTest(extra=extra), self.assertRaises(h.Refused): h.public_result(result, self.metadata())

    def test_firewall_normalization_preserves_policy_values_and_only_removes_counters(self):
        rule = {"nftables": [{"rule": {"expr": [{"counter": {"packets": 3, "bytes": 20}},
                 {"limit": {"rate": 100, "bytes": 1024}}, {"match": {"right": "secret-address"}}]}}]}
        changed = copy.deepcopy(rule)
        changed["nftables"][0]["rule"]["expr"][0]["counter"] = {"packets": 50, "bytes": 90}
        self.assertEqual(h.normalized(rule, kind="nft"), h.normalized(changed, kind="nft"))
        changed["nftables"][0]["rule"]["expr"][1]["limit"]["bytes"] = 4096
        self.assertNotEqual(h.normalized(rule, kind="nft"), h.normalized(changed, kind="nft"))
        self.assertEqual(h.normalized({"local": "192.0.2.1", "valid_life_time": 20}),
                         h.normalized({"local": "192.0.2.1", "valid_life_time": 19}))
        self.assertNotEqual(h.normalized({"local": "192.0.2.1"}), h.normalized({"local": "192.0.2.2"}))

    def test_host_network_diagnostics_do_not_export_values_or_unknown_keys(self):
        before = {"addresses": [{"local": "SECRET_IP"}], "routes": [{"SECRET_NAME": "SECRET_VALUE"}], "firewall": {"policy": "drop"}}
        after = copy.deepcopy(before)
        after["addresses"][0]["local"] = "ANOTHER_IP"
        after["routes"][0]["SECRET_NAME"] = "ANOTHER_VALUE"
        proof = h.network_proof(before, after)
        self.assertFalse(proof["unchanged"])
        self.assertEqual(proof["changed_sections"], ["addresses", "routes"])
        self.assertEqual(proof["difference_paths"], [".addresses[0].local", ".routes[0].unknown-field"])
        self.assertNotIn("SECRET", json.dumps(proof)); self.assertNotIn("ANOTHER", json.dumps(proof))
        self.assertEqual(proof["before_sha256"]["firewall"], proof["after_sha256"]["firewall"])
        self.assertNotEqual(proof["before_sha256"]["addresses"], proof["after_sha256"]["addresses"])
        self.assertTrue(h.network_proof(before, before)["unchanged"])

    def test_interface_delta_is_structural_and_never_exports_addresses_or_names(self):
        before = {"addresses": [{"ifindex": 1, "ifname": "lo", "link_type": "loopback", "addr_info": []}], "routes": [], "firewall": {}}
        after = copy.deepcopy(before)
        after["addresses"].append({"ifindex": 8, "ifname": "PRIVATE_INTERFACE", "link_type": "ether",
            "address": "PRIVATE_MAC", "master": "PRIVATE_MASTER", "addr_info": [
                {"family": "inet", "local": "PRIVATE_IP"}, {"family": "inet6", "local": "PRIVATE_IPV6"}],
            "flags": ["UP", "PRIVATE_FLAG"], "operstate": "UP"})
        proof = h.network_proof(before, after)
        self.assertFalse(proof["unchanged"])
        delta = proof["address_inventory_delta"]
        self.assertTrue(delta["available"])
        self.assertEqual((delta["before_count"], delta["after_count"]), (1, 2))
        self.assertEqual(delta["added_count"], 1)
        self.assertEqual(delta["removed_count"], 0)
        self.assertEqual(delta["added"], [{"ifindex": 8, "name_category": "other", "link_type": "ether",
            "link_kind": "other", "address_families": {"inet": 1, "inet6": 1, "other": 0},
            "master_present": True, "master_category": "other"}])
        self.assertNotIn("PRIVATE", json.dumps(proof))
        # A known Docker/libvirt interface is only classified, never ignored.
        for name, category in (("docker0", "docker_bridge"), ("virbr0", "libvirt_bridge")):
            after["addresses"][-1]["ifname"] = name
            value = h.network_proof(before, after)
            self.assertFalse(value["unchanged"])
            self.assertEqual(value["address_inventory_delta"]["added"][0]["name_category"], category)

    def test_interface_delta_handles_invalid_inventory_without_exporting_it_or_passing_changes(self):
        for item in ({"ifname": "PRIVATE_NAME"}, {"ifindex": True}, {"ifindex": "PRIVATE_INDEX"}, None):
            before = {"addresses": [], "routes": [], "firewall": {}}
            after = {**before, "addresses": [item]}
            proof = h.network_proof(before, after)
            self.assertFalse(proof["unchanged"])
            self.assertFalse(proof["address_inventory_delta"]["available"])
            self.assertNotIn("PRIVATE", json.dumps(proof))

    def test_diagnostic_detail_budget_never_truncates_actual_equality_or_hashes(self):
        empty = {"addresses": [], "routes": [], "firewall": {}}
        full = {**empty, "addresses": [{"ifindex": index + 1, "addr_info": []} for index in range(65)]}
        proof = h.network_proof(empty, full)
        self.assertFalse(proof["unchanged"])
        self.assertEqual(proof["address_inventory_delta"]["added_count"], 65)
        self.assertEqual(len(proof["address_inventory_delta"]["added"]), 32)
        self.assertTrue(proof["address_inventory_delta"]["details_truncated"])
        changed = copy.deepcopy(full)
        changed["addresses"][64]["addr_info"] = [{"family": "inet", "local": "PRIVATE_IP"}]
        proof = h.network_proof(full, changed)
        self.assertFalse(proof["unchanged"])
        self.assertNotEqual(proof["before_sha256"]["addresses"], proof["after_sha256"]["addresses"])
        self.assertNotIn("PRIVATE", json.dumps(proof))

    def test_pre_vm_checkpoint_fails_before_the_guest_without_rebasing_or_ignoring_changes(self):
        before = {"addresses": [], "routes": [], "firewall": {}}
        after = {**before, "addresses": [{"ifindex": 8, "ifname": "docker0", "addr_info": []}]}
        with mock.patch.object(h, "HOST_PRE_VM_PROOF", {}), mock.patch.object(h, "host_network", return_value=after):
            with self.assertRaisesRegex(h.Refused, "HOST_NETWORK_CHANGED_BEFORE_VM"):
                h.verify_host_network_checkpoint(before, phase="before_vm")
            self.assertFalse(h.HOST_PRE_VM_PROOF["unchanged"])
        with mock.patch.object(h, "HOST_PROOF", {}), mock.patch.object(h, "host_network", return_value=before):
            self.assertTrue(h.verify_host_network_checkpoint(before, phase="after_vm")["unchanged"])
        import inspect
        source = inspect.getsource(h.execute)
        self.assertLess(source.index('verify_host_network_checkpoint(before, phase="before_vm")'), source.index('result = run_vm('))
        self.assertEqual(source.count('before = host_network()'), 1)

    def test_execute_preserves_the_first_failure_but_always_records_final_network_proof(self):
        before = {"addresses": [], "routes": [], "firewall": {}}
        after = {**before, "addresses": [{"ifindex": 4, "ifname": "PRIVATE_LINK", "master": "docker0"}]}
        unavailable = h.Refused("HOST_READONLY_IP_TOOL_REQUIRED")
        cases = ((after, None, after, "HOST_NETWORK_CHANGED_BEFORE_VM", 0),
                 (after, None, before, "HOST_NETWORK_CHANGED_BEFORE_VM", 0),
                 (before, h.Refused("GUEST_ACCEPTANCE_FAILED"), after, "GUEST_ACCEPTANCE_FAILED", 1),
                 (before, h.Refused("GUEST_ACCEPTANCE_FAILED"), unavailable, "GUEST_ACCEPTANCE_FAILED", 1),
                 (before, None, after, "HOST_NETWORK_OR_FIREWALL_CHANGED", 1),
                 (before, None, unavailable, "HOST_READONLY_IP_TOOL_REQUIRED", 1))
        for pre_vm, guest_error, final_state, expected, guest_calls in cases:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
                root = Path(directory).resolve()
                args = argparse.Namespace(ubuntu="22.04", source_root=str(root), source_sha="a" * 40, output=str(root / "out"))
                metadata = {**self.metadata(), "nonce": "b" * 32}
                stack.enter_context(mock.patch.object(h.platform, "system", return_value="Linux"))
                stack.enter_context(mock.patch.object(h.platform, "machine", return_value="x86_64"))
                stack.enter_context(mock.patch.object(h.os, "geteuid", return_value=1000))
                stack.enter_context(mock.patch.multiple(h, TOOLS=(), HOST_PROOF={}, HOST_PRE_VM_PROOF={}, OUTPUT_CREATED=None))
                stack.enter_context(mock.patch.object(h, "run", return_value=b"a" * 40))
                stack.enter_context(mock.patch.object(h, "prepare_sandbox"))
                stack.enter_context(mock.patch.object(h, "obtain_image", return_value=(root / "image", {})))
                stack.enter_context(mock.patch.object(h, "make_seed", return_value=(root / "seed", metadata)))
                snapshots = stack.enter_context(mock.patch.object(h, "host_network", side_effect=[before, pre_vm, final_state]))
                vm = stack.enter_context(mock.patch.object(h, "run_vm", return_value=self.result(), side_effect=guest_error))
                with self.assertRaisesRegex(h.Refused, "^" + expected + "$"):
                    h.execute(args)
                self.assertEqual(vm.call_count, guest_calls)
                self.assertEqual(snapshots.call_count, 3)
                self.assertEqual(h.HOST_PROOF.get("unchanged"), final_state == before if isinstance(final_state, dict) else None)
                self.assertEqual(h.HOST_PRE_VM_PROOF["unchanged"], pre_vm == before)
                self.assertFalse((root / "out" / "summary.json").exists())

    def test_detailed_links_classify_veth_and_master_without_exporting_private_values(self):
        import inspect
        self.assertIn('[ip, "-j", "address", "show"]', inspect.getsource(h.host_network))
        self.assertNotIn('"-d"', inspect.getsource(h.host_network))
        self.assertIn('[ip, "-j", "-d", "link", "show"]', inspect.getsource(h.verify_host_network_checkpoint))
        before = {"addresses": [{"ifindex": 3, "ifname": "docker0", "addr_info": []}], "routes": [], "firewall": {}}
        after = copy.deepcopy(before)
        link = {"ifindex": 4, "ifname": "PRIVATE_LINK", "master": 3,
                "link_type": "ether", "linkinfo": {"info_kind": "veth", "info_data": {"PRIVATE_KEY": "PRIVATE_VALUE"}}}
        after["addresses"].append(link)
        proof = h.network_proof(before, after)
        self.assertFalse(proof["unchanged"])
        added = proof["address_inventory_delta"]["added"][0]
        self.assertEqual(added["link_kind"], "veth")
        self.assertEqual(added["master_category"], "docker_bridge")
        self.assertNotIn("PRIVATE", json.dumps(proof))
        for master in ("docker0", 3):
            link["master"] = master
            self.assertEqual(h.address_inventory_delta(before["addresses"], after["addresses"])["added"][0]["master_category"], "docker_bridge")
        for value in ("PRIVATE_KIND", [], None, {"info_kind": "PRIVATE_KIND"}):
            link["linkinfo"] = value
            proof = h.network_proof(before, after)
            self.assertFalse(proof["unchanged"])
            self.assertEqual(proof["address_inventory_delta"]["added"][0]["link_kind"], "other")
            self.assertNotIn("PRIVATE", json.dumps(proof))

    def test_optional_link_diagnostics_never_authorize_a_changed_or_unavailable_network(self):
        before = {"addresses": [], "routes": [], "firewall": {}}
        after = {**before, "addresses": [{"ifindex": 4, "ifname": "PRIVATE_LINK"}]}
        links = [{"ifindex": 3, "ifname": "docker0"}, {"ifindex": 4, "ifname": "PRIVATE_LINK", "master": "docker0",
                  "linkinfo": {"info_kind": "veth", "info_data": {"PRIVATE_KEY": "PRIVATE_VALUE"}}}]
        for output in (json.dumps(links).encode(), b"PRIVATE_INVALID_JSON", OSError("PRIVATE_DIAGNOSTIC_FAILURE")):
            with self.subTest(output_type=type(output).__name__), mock.patch.object(h, "HOST_PRE_VM_PROOF", {}), \
                    mock.patch.object(h, "host_network", return_value=after), mock.patch.object(h.Path, "is_file", return_value=True), \
                    mock.patch.object(h, "run", return_value=output, side_effect=output if isinstance(output, Exception) else None) as command:
                with self.assertRaisesRegex(h.Refused, "^HOST_NETWORK_CHANGED_BEFORE_VM$"):
                    h.verify_host_network_checkpoint(before, phase="before_vm")
                proof = h.HOST_PRE_VM_PROOF
                self.assertFalse(proof["unchanged"])
                self.assertEqual(proof["after_sha256"], h.network_proof(before, after)["after_sha256"])
                self.assertNotIn("PRIVATE", json.dumps(proof))
                command.assert_called_once_with(["/usr/sbin/ip", "-j", "-d", "link", "show"])
                self.assertNotIn("address_families", json.dumps(proof["link_inventory_delta"]))
        with mock.patch.object(h, "HOST_PROOF", {}), mock.patch.object(h, "host_network", return_value=before), mock.patch.object(h, "run") as command:
            self.assertTrue(h.verify_host_network_checkpoint(before, phase="after_vm")["unchanged"])
            command.assert_not_called()

    def test_progress_requires_owned_nonce_and_fixed_stage_without_exporting_inputs(self):
        with mock.patch.object(g, "PROGRESS_NONCE", None), mock.patch("builtins.open") as opened:
            g.progress("prepare")
            opened.assert_not_called()
        with mock.patch.object(g, "PROGRESS_NONCE", "a" * 32), mock.patch("builtins.open", mock.mock_open()) as opened:
            g.progress("prepare")
            opened.assert_called_once_with("/dev/ttyS0", "w")
            opened().write.assert_called_once_with("ASTER_LIBVIRT_NATIVE_PROGRESS_" + "a" * 32 + " prepare\n")
            opened.reset_mock(); g.progress("SECRET_PATH_OR_ARGV")
            opened.assert_not_called()

    def test_guest_apt_error_codes_are_fixed_and_host_allowlisted(self):
        self.assertTrue(g.APT_CODES <= h.GUEST_ERROR_CODES)
        self.assertIn("APT_TLS_FAILURE", g.APT_CODES)
        self.assertIn("APT_PACKAGE_UNAVAILABLE", g.APT_CODES)
        source = (HERE / "libvirt-native-guest.py").read_text()
        self.assertIn('getattr(error, "code", None)', source)
        self.assertNotIn('str(error.stderr)', source)

    def test_guest_error_classification_never_loses_unrelated_exception_or_exports_text(self):
        unrelated = RuntimeError("PRIVATE_STDERR")
        self.assertEqual(g.provision_error_code(unrelated), "NATIVE_GUEST_REFUSED_DETAILS_WITHHELD")
        error = type("ProvisionError", (Exception,), {})("PRIVATE_STDERR")
        error.code = "APT_TLS_FAILURE"
        self.assertEqual(g.provision_error_code(error), "APT_TLS_FAILURE")
        error.code = "PRIVATE_PROVIDER_TEXT"
        self.assertEqual(g.provision_error_code(error), "PROVISION_PREPARE_REFUSED")
        self.assertNotIn("PRIVATE", g.provision_error_code(error))
        error = type("ProvisionError", (Exception,), {})("Fixed native provisioning command rejected; private")
        self.assertEqual(g.provision_error_code(error), "NATIVE_COMMAND_REJECTED")

    def test_runtime_failure_keeps_report_and_does_not_require_success_schema(self):
        source = (HERE / "libvirt-native.py").read_text()
        self.assertIn('require(result.get("passed") is True, "GUEST_ACCEPTANCE_FAILED")', source)
        self.assertIn('public = public_result(result, metadata)', source)
        self.assertIn('"progress": VM_PROGRESS, "guest_result_seen": GUEST_RESULT_SEEN', source)
        self.assertIn('deadline = time.monotonic() + 1200', source)

    def test_real_proc_sandbox_contract_requires_identity_caps_and_two_filters(self):
        fields = {"Uid": [str(os.getuid())] * 4, "Gid": [str(os.getgid())] * 4,
                  "CapInh": ["0"], "CapPrm": ["0"], "CapEff": ["0"], "CapAmb": ["0"],
                  "CapBnd": ["ffffffff"], "NoNewPrivs": ["1"], "Seccomp": ["2"], "Seccomp_filters": ["2"]}
        h.unprivileged_status(fields, sandbox=True, minimum_filters=2)
        for name, value in (("Uid", ["0"] * 4), ("Gid", ["0"] * 4), ("CapEff", ["1"]), ("CapAmb", ["1"]),
                            ("NoNewPrivs", ["0"]), ("Seccomp", ["0"]), ("Seccomp_filters", ["1"])):
            invalid = copy.deepcopy(fields); invalid[name] = value
            with self.subTest(name=name), self.assertRaises(h.Refused): h.unprivileged_status(invalid, sandbox=True, minimum_filters=2)

    def test_emulator_uses_outer_credential_filter_not_unprotected_allow(self):
        source = (HERE / "libvirt-native.py").read_text()
        self.assertIn('subprocess.Popen([str(work / "qemu-sandbox"), *arguments]', source)
        self.assertNotIn('subprocess.Popen(arguments,', source)
        self.assertIn('minimum_filters=baseline + 2', source)
        self.assertIn('prepare_sandbox(work)', source)
        self.assertIn('signal.pidfd_send_signal', source)
        self.assertIn('"OWNED_RELAY_REMAINS_NO_CLEANUP_CLAIM"', source)
        self.assertIn('signal.alarm(300)', source)
        helper = (HERE / "libvirt-native-sandbox.c").read_text()
        self.assertIn('SECCOMP_RET_KILL_PROCESS', helper)
        self.assertIn('AUDIT_ARCH_X86_64', helper)
        self.assertIn('PR_SET_NO_NEW_PRIVS', helper)
        self.assertIn('SIGSYS', helper)

    def test_relay_cleanup_accepts_exact_process_exit_race_without_signalling(self):
        with tempfile.TemporaryDirectory() as raw:
            work = Path(raw)
            record = {"pid": 12345, "start_time": 9, "host": "archive.ubuntu.com", "nonce": "a" * 32}
            path = work / "relay-owner-12345-9.json"
            path.write_text(json.dumps(record)); path.chmod(0o600)
            original = Path.read_bytes
            def read(path):
                if path == Path("/proc/12345/cmdline"):
                    raise FileNotFoundError()
                return original(path)
            with mock.patch.object(h.os, "pidfd_open", create=True) as pidfd, \
                    mock.patch.object(h.signal, "pidfd_send_signal", create=True) as send, \
                    mock.patch.object(h, "process_identity", return_value={"start_time": 9}), \
                    mock.patch.object(Path, "read_bytes", read), \
                    mock.patch.object(Path, "iterdir", return_value=iter(())):
                proof = h.cleanup_relays(work, {"nonce": "a" * 32})
            self.assertTrue(proof["cleanup_complete"])
            self.assertEqual(proof["owned_records"], 1)
            pidfd.assert_not_called(); send.assert_not_called()

    def test_guest_error_catalog_and_command_categories_stay_in_sync(self):
        tree = ast.parse((HERE / "libvirt-native-guest.py").read_text())
        codes = set(g.PROVISION_CODES.values())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"require", "Refused"}:
                value = node.args[-1] if node.args else None
                if isinstance(value, ast.Constant) and isinstance(value.value, str): codes.add(value.value)
        self.assertTrue(codes <= h.GUEST_ERROR_CODES, codes - h.GUEST_ERROR_CODES)
        for argv in (["/usr/bin/apt-get", "update"], ["/usr/bin/apt-get", "--simulate"], ["/usr/bin/apt-get", "--assume-yes"],
                     ["/usr/bin/systemctl", "start"], ["/usr/bin/virsh", "net-list"], ["/usr/sbin/nft"], []):
            self.assertIn(g.command_code(argv), h.DIAGNOSTIC_COMMANDS)


if __name__ == "__main__":
    unittest.main(verbosity=2)

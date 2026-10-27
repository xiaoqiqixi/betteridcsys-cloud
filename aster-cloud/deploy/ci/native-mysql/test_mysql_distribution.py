"""Offline platform/pin validation; never downloads, extracts or runs MySQL."""
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("mysql_distribution_policy", HERE / "mysql-distribution.py")
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)


class DistributionPolicyTests(unittest.TestCase):
    def manifest(self, version):
        return json.loads((HERE / POLICY.PLATFORMS[version][1]).read_text())

    def test_independent_reviewed_pins_match_both_exact_platforms(self):
        for version, mysql in (("22.04", "8.4.13"), ("24.04", "8.4.11")):
            with self.subTest(version=version):
                lines = POLICY.validate_manifest(self.manifest(version), version)
                self.assertEqual(lines[0], mysql)
                self.assertEqual(len(lines), 13)
                self.assertEqual(len(set(lines[1::3])), 4)
                self.assertTrue(all(name.endswith(f"_{mysql}-1ubuntu{version}_amd64.deb") for name in lines[1::3]))

    def test_only_two_ubuntu_lts_identities_are_supported(self):
        for version in ("22.04", "24.04"):
            self.assertEqual(POLICY.ubuntu_version(f'NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="{version}"\n'), version)
        for text in ('ID=debian\nVERSION_ID="22.04"', 'ID=mint\nID_LIKE=ubuntu\nVERSION_ID=22.04',
                     'ID=ubuntu\nVERSION_ID=26.04', 'ID=ubuntu\nVERSION_ID=22.10',
                     'ID=ubuntu\nVERSION_ID=24.04\nVERSION_ID=22.04', 'ID=ubuntu\nVERSION_ID="22.04;cmd"', ''):
            with self.subTest(text=text), self.assertRaises(ValueError):
                POLICY.ubuntu_version(text)

    def test_cross_platform_pins_are_never_substituted(self):
        for host, other in (("22.04", "24.04"), ("24.04", "22.04")):
            with self.subTest(host=host), self.assertRaises(ValueError):
                POLICY.validate_manifest(self.manifest(other), host)

    def test_manifest_header_types_origin_and_exact_architecture_are_enforced(self):
        for version in POLICY.PLATFORMS:
            for field, value in (("schema", True), ("schema", 1), ("status", "verified"),
                                 ("version", "8.0.44"), ("version", 8.4), ("architecture", "arm64"),
                                 ("package_version", "8.4.13-1ubuntu26.04"), ("distribution", "ubuntu-26.04"),
                                 ("metadata_url", "https://mirror.example.invalid/Packages"),
                                 ("metadata_url", "http://repo.mysql.com/apt/ubuntu/dists/jammy/mysql-8.4-lts/binary-amd64/Packages")):
                with self.subTest(version=version, field=field, value=value):
                    manifest = self.manifest(version)
                    manifest[field] = value
                    with self.assertRaises(ValueError):
                        POLICY.validate_manifest(manifest, version)

    def test_all_four_unique_package_names_are_required(self):
        manifest = self.manifest("22.04")
        packages = manifest["packages"]
        for bad in (None, {}, packages[:-1], packages + [packages[0]],
                    [packages[0]] * 4, [packages[0], packages[1], packages[2], {}],
                    [packages[0], packages[1], packages[2], {"name": ["nested"]}]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                POLICY.validate_manifest({**manifest, "packages": bad}, "22.04")

    def test_package_hash_and_size_are_exact_and_bounded(self):
        for field, values in (("sha256", [None, "", "0" * 64, "A" * 64, "a" * 63, "a" * 65]),
                              ("size", [None, True, 0, -1, "1", 1.5, 1024 ** 3 + 1])):
            for value in values:
                with self.subTest(field=field, value=value):
                    manifest = self.manifest("22.04")
                    manifest["packages"][-1][field] = value
                    with self.assertRaises(ValueError):
                        POLICY.validate_manifest(manifest, "22.04")

    def test_duplicate_json_fields_cannot_shadow_reviewed_pins(self):
        for raw in ('{"schema":2,"schema":2}', '{"packages":[{"sha256":"a","sha256":"b"}]}'):
            with self.assertRaisesRegex(ValueError, "duplicate manifest"):
                json.loads(raw, object_pairs_hook=POLICY.strict_pairs)

    def test_security_backport_capability_is_required_not_a_python_major_version(self):
        def extractall(self, path=".", *, filter=None):
            pass
        backport = SimpleNamespace(data_filter=lambda member, path: member,
                                   TarFile=SimpleNamespace(extractall=extractall))
        with patch.object(POLICY, "tarfile", backport):
            POLICY.require_data_filter()
        for missing in (SimpleNamespace(TarFile=backport.TarFile),
                        SimpleNamespace(data_filter=None, TarFile=backport.TarFile),
                        SimpleNamespace(data_filter=backport.data_filter,
                                        TarFile=SimpleNamespace(extractall=lambda self, path=".": None))):
            with patch.object(POLICY, "tarfile", missing), self.assertRaisesRegex(ValueError, "before any download"):
                POLICY.require_data_filter()

    def test_cli_rejects_distribution_overrides_before_any_action(self):
        result = subprocess.run([sys.executable, '-I', str(HERE / 'mysql-distribution.py'), '--manifest', '/tmp/foreign.json'],
                                capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('takes no arguments', result.stderr)


    def test_download_verify_extract_order_and_filter_remain_mandatory(self):
        source = (HERE / 'mysql-native.sh').read_text()
        self.assertLess(source.index('mysql-distribution.py'), source.index('curl --fail'))
        self.assertLess(source.index('SHA-256 mismatch'), source.index('archive.extractall('))
        self.assertIn('archive.extractall(destination, members=members, filter="data")', source)
        self.assertNotIn('fully_trusted', source)




if __name__ == '__main__':
    unittest.main()

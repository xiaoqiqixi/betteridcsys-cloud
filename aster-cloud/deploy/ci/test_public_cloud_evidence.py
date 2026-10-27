#!/usr/bin/env python3
"""Offline proof-boundary negatives; real root bootstrap runs in its own gate."""
import copy
import importlib.util
import json
import stat
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("cloud_public_proof_contract", Path(__file__).with_name("public_cloud_evidence.py"))
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)


def proof(role="controller"):
    return {"schema": 1, "passed": True, "role": role, "tag": "cloud-v0.1.0-rc.1",
            "source_commit": "8092c3cc0517c69562e8a5cdd94bc5e389e1bc8e", "release_id": 425041579,
            "artifact_sha256": {"controller": "1feebda62813f91b4aa9eca97d52f62e991593c5ff7bfe45d4a38c699856292a",
                                "node": "cf92656ba8daf210815dfe8fa8d04d36ef46a9cd27c5f488c52780f511ff5544"}[role],
            "anonymous_download": True, "publisher_signature_reverified": True, "production_installer_plan": True,
            "host_apply": False, "service_started": False, "real_kvm_acceptance": False}


class PublishedCloudEvidence(unittest.TestCase):
    def verify(self, value=None, role="controller", runner="ubuntu-22.04", facts=None, source="c" * 40):
        if facts is None:
            facts = {"system": "Linux", "architecture": "x86_64", "distribution": "ubuntu", "version": runner.removeprefix("ubuntu-")}
        raw = json.dumps(proof(role) if value is None else value).encode()
        return P.validate(raw, role, runner, facts, source)

    def test_both_roles_on_both_platforms_keep_release_and_control_sources_separate(self):
        for role in ("controller", "node"):
            for runner in ("ubuntu-22.04", "ubuntu-24.04"):
                with self.subTest(role=role, runner=runner):
                    result = self.verify(role=role, runner=runner)
                    self.assertTrue(result["passed"])
                    self.assertEqual(result["control_source"], "c" * 40)
                    self.assertEqual(result["proof"], proof(role))
                    self.assertEqual(result["runner_os"], runner)

    def test_identity_and_exact_schema_cannot_be_substituted(self):
        for field, value in (("schema", True), ("schema", 2), ("passed", False), ("tag", "v0.5.10"),
                             ("source_commit", "d" * 40), ("release_id", 1), ("role", "node"),
                             ("artifact_sha256", "0" * 64), ("unknown", "ignored")):
            with self.subTest(field=field):
                changed = proof(); changed[field] = value
                with self.assertRaises(P.EvidenceError):
                    self.verify(changed)
        for field in proof():
            changed = proof(); del changed[field]
            with self.subTest(missing=field), self.assertRaises(P.EvidenceError):
                self.verify(changed)

    def test_booleans_are_exact_and_no_host_action_can_pass(self):
        for field in ("anonymous_download", "publisher_signature_reverified", "production_installer_plan",
                      "host_apply", "service_started", "real_kvm_acceptance"):
            for value in (None, "false", 0, 1, not proof()[field]):
                changed = proof(); changed[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(P.EvidenceError):
                    self.verify(changed)

    def test_actual_host_must_match_supported_runner(self):
        facts = {"system": "Linux", "architecture": "x86_64", "distribution": "ubuntu", "version": "22.04"}
        for key, value in (("system", "Darwin"), ("architecture", "arm64"), ("distribution", "debian"),
                           ("version", "24.04"), ("version", "26.04")):
            changed = copy.deepcopy(facts); changed[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(P.EvidenceError):
                self.verify(facts=changed)
        for runner in ("ubuntu-26.04", "linux", ""):
            with self.subTest(runner=runner), self.assertRaises(P.EvidenceError):
                self.verify(runner=runner, facts=facts)

    def test_bad_bytes_duplicate_fields_unknown_role_or_control_source_refused(self):
        facts = {"system": "Linux", "architecture": "x86_64", "distribution": "ubuntu", "version": "22.04"}
        for raw in (b"", b"[]", b"null", b"{", b"\xff", b"x" * 16385,
                    json.dumps(proof()).encode().replace(b'"passed": true', b'"passed": true, "passed": true')):
            with self.subTest(raw_length=len(raw)), self.assertRaises(P.EvidenceError):
                P.validate(raw, "controller", "ubuntu-22.04", facts, "c" * 40)
        for role, source in (("other", "c" * 40), ("controller", "main"), ("controller", "C" * 40)):
            with self.subTest(role=role, source=source), self.assertRaises(P.EvidenceError):
                P.validate(json.dumps(proof()).encode(), role, "ubuntu-22.04", facts, source)

    def test_root_reader_allows_read_atime_but_rejects_mutated_content(self):
        # fstat is an OS boundary. This is a root-file metadata model, not a
        # claim of root execution on this developer machine; CI runs it real.
        raw = json.dumps(proof()).encode()
        fields = {"st_mode": stat.S_IFREG | 0o644, "st_uid": 0, "st_nlink": 1, "st_size": len(raw),
                  "st_dev": 1, "st_ino": 2, "st_mtime_ns": 3, "st_ctime_ns": 4, "st_atime_ns": 5}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "proof.json"
            path.write_bytes(raw)
            accessed = dict(fields, st_atime_ns=6)
            with mock.patch.object(P.os, "fstat", side_effect=[types.SimpleNamespace(**fields), types.SimpleNamespace(**accessed)]):
                self.assertEqual(P.read_root_proof(path), raw)
            for field in ("st_mtime_ns", "st_ctime_ns", "st_uid", "st_mode", "st_nlink", "st_size"):
                changed = dict(fields); changed[field] += 1
                with self.subTest(field=field), mock.patch.object(P.os, "fstat", side_effect=[types.SimpleNamespace(**fields), types.SimpleNamespace(**changed)]), self.assertRaises(P.EvidenceError):
                    P.read_root_proof(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)

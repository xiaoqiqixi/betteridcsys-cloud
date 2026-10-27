#!/usr/bin/env python3
"""Independent publisher-verifier parser/boundary models, NOT crypto acceptance.

Every asset/certificate/process result is synthetic, private temp files only.
Mocked gh stdout proves our policy parser is exercised, never a valid signature.
"""
import contextlib
import copy
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import types
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("independent_cloud_publisher_policy", Path(__file__).resolve().parents[1] / "install/release_verify.py")
v = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = v
SPEC.loader.exec_module(v)
SOURCE = "a" * 40


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class PublisherVerifierContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cloud-publisher-policy-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        self.guard = mock.patch.object(v.subprocess, "run", side_effect=AssertionError("no real gh/host command in policy unit tests"))
        self.guard.start()
        self.addCleanup(self.guard.stop)
        network = mock.patch.object(v.urllib.request, "urlopen", side_effect=AssertionError("no network in verifier policy unit tests"))
        network.start()
        self.addCleanup(network.stop)

    def file(self, name, raw, mode=0o600):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(raw)
        path.chmod(mode)
        return path

    @contextlib.contextmanager
    def root_owned_model(self):
        original_lstat, original_fstat = Path.lstat, os.fstat
        def owned(info, ancestor=False):
            fields = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
            fields["st_uid"] = 0
            if ancestor:
                fields["st_mode"] &= ~0o022
            return types.SimpleNamespace(**fields)
        def lstat(path):
            info = original_lstat(path)
            if path in self.root.parents:
                return owned(info, ancestor=True)
            if path == self.root or self.root in path.parents:
                return owned(info)
            raise AssertionError("unexpected real host filesystem probe: " + str(path))
        with mock.patch.object(Path, "lstat", lstat), mock.patch.object(v.os, "fstat", side_effect=lambda fd: owned(original_fstat(fd))):
            yield

    def certificate(self):
        return {"issuer": v.ISSUER, "subjectAlternativeName": v.WORKFLOW_IDENTITY,
            "sourceRepositoryURI": "https://github.com/" + v.REPOSITORY,
            "sourceRepositoryIdentifier": str(v.REPOSITORY_ID), "sourceRepositoryOwnerIdentifier": str(v.OWNER_ID),
            "sourceRepositoryOwnerURI": "https://github.com/xiaoqiqixi", "sourceRepositoryDigest": SOURCE,
            "sourceRepositoryRef": v.SOURCE_REF, "sourceRepositoryVisibilityAtSigning": "public",
            "runnerEnvironment": "github-hosted", "buildSignerURI": v.WORKFLOW_IDENTITY,
            "buildConfigURI": v.WORKFLOW_IDENTITY, "buildSignerDigest": SOURCE, "buildConfigDigest": SOURCE,
            "buildTrigger": "workflow_dispatch"}

    def proof(self, name="asset.tar.gz", digest=None):
        return [{"verificationResult": {"signature": {"certificate": self.certificate()},
            "verifiedTimestamps": [{"type": "tlog", "uri": "https://rekor.sigstore.dev", "timestamp": "2026-10-25T00:00:00Z"}],
            "statement": {"predicateType": v.PREDICATE, "subject": [{"name": name, "digest": {"sha256": digest or "b" * 64}}]}}}]

    def attest(self, proof):
        with mock.patch.object(v, "run_fixed", return_value=json.dumps(proof).encode()) as run:
            v.verify_attestation(Path("/private/tmp/asset.tar.gz"), "b" * 64, SOURCE,
                Path("/private/tmp/gh"), Path("/private/tmp/root.json"), Path("/private/tmp/bundle.json"),
                Path("/private/tmp/home"), Path("/private/tmp/config"))
        return run

    def capsule(self, changes=None, extra=(), manifest_change=None):
        files = {name: ("synthetic " + name + "\n").encode() for name in v.CAPSULE_FILES}
        manifest = {"schema": 1, "component": "aster-cloud-installer", "version": v.VERSION,
            "release_kind": "release", "channel": "prerelease", "release_tag": v.TAG, "source_commit": SOURCE,
            "files": [{"path": name, "sha256": sha(raw), "size": len(raw), "mode": "0644"} for name, raw in sorted(files.items())]}
        if manifest_change:
            manifest_change(manifest)
        members = [("manifest.json", json.dumps(manifest).encode()), *sorted(files.items())]
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as tar:
            for name, raw in members:
                info = tarfile.TarInfo(name)
                info.uid, info.gid, info.mode, info.size = 0, 0, 0o644, len(raw)
                if changes:
                    changes(info)
                tar.addfile(info, io.BytesIO(raw) if info.isreg() else None)
            for info, raw in extra:
                tar.addfile(info, io.BytesIO(raw) if info.isreg() else None)
        return gzip.compress(stream.getvalue(), mtime=0), files

    def published(self, payloads=None):
        payloads = payloads or {name: ("synthetic " + name).encode() for name in (*v.PAYLOAD_NAMES, "SHA256SUMS")}
        return {"schema": 1, "repository": v.REPOSITORY, "repository_id": v.REPOSITORY_ID, "owner_id": v.OWNER_ID,
            "version": v.VERSION, "tag": v.TAG, "source_commit": SOURCE, "source_ref": v.SOURCE_REF,
            "channel": "prerelease", "workflow": v.WORKFLOW,
            "assets": [{"name": name, "sha256": sha(payloads[name]), "size": len(payloads[name])} for name in sorted(payloads)],
            "acceptance": {"production_ready": False, "real_kvm_accepted": False}}

    @contextlib.contextmanager
    def receipt_model(self):
        parent = self.root
        self.root = Path(tempfile.mkdtemp(prefix="receipt-", dir=parent))
        capsule, code = self.capsule()
        name = "aster-cloud-controller-" + v.VERSION + "-linux-amd64.tar.gz"
        payloads = {asset: ("synthetic " + asset).encode() for asset in (*v.PAYLOAD_NAMES, "SHA256SUMS")}
        payloads[v.CAPSULE_NAME] = capsule
        payloads[v.BOOTSTRAP_NAME] = code["release_verify.py"]
        published = self.published(payloads)
        paths = {"manifest": self.file("release-manifest.json", json.dumps(published).encode()),
            "capsule": self.file(v.CAPSULE_NAME, capsule), "attestation": self.file("attestations.jsonl", b"synthetic non-cryptographic proof"),
            "trusted_root": self.file("trusted-root.json", b"synthetic nontrusted root"), "gh": self.file("gh", b"synthetic never-executed gh", 0o700)}
        package = self.file(name, payloads[name])
        for member, raw in code.items():
            self.file("installer/" + member, raw)
        home, config = self.root / "anonymous-home", self.root / "anonymous-config"
        home.mkdir(mode=0o700)
        config.mkdir(mode=0o700)
        receipt = {"schema": 1, "repository": v.REPOSITORY, "repository_id": v.REPOSITORY_ID,
            "tag": v.TAG, "version": v.VERSION, "channel": "prerelease", "release_id": 12345, "source_commit": SOURCE,
            "component": "aster-cloud-controller", "asset_name": name, "asset_sha256": sha(payloads[name]), "asset_size": len(payloads[name]),
            "files": {key: {"path": str(path), "sha256": sha(path.read_bytes()), "size": path.stat().st_size} for key, path in paths.items()},
            "verification_home": str(home), "verification_config": str(config)}
        receipt_path = self.file("release-receipt.json", json.dumps(receipt).encode())
        manifest = {"schema": 1, "component": "aster-cloud-controller", "version": v.VERSION, "release_kind": "release",
            "channel": "prerelease", "release_tag": v.TAG, "source_commit": SOURCE, "platform": "linux-amd64"}
        def run(argv, env):
            asset = Path(argv[3])
            return json.dumps(self.proof(asset.name, sha(asset.read_bytes()))).encode()
        with self.root_owned_model(), contextlib.ExitStack() as stack:
            for key, value in {"GH_BINARY_SIZE": paths["gh"].stat().st_size, "GH_BINARY_SHA256": sha(paths["gh"].read_bytes()),
                    "TRUSTED_ROOT_SIZE": paths["trusted_root"].stat().st_size, "TRUSTED_ROOT_SHA256": sha(paths["trusted_root"].read_bytes())}.items():
                stack.enter_context(mock.patch.object(v, key, value))
            command = stack.enter_context(mock.patch.object(v, "run_fixed", side_effect=run))
            try:
                yield types.SimpleNamespace(receipt=receipt, path=receipt_path, package=package, digest=receipt["asset_sha256"], manifest=manifest,
                    files=paths, home=home, config=config, run=command)
            finally:
                self.root = parent

    def verify(self, model):
        return v.verify_release_receipt(str(model.package), model.digest, "aster-cloud-controller", model.manifest, str(model.path))

    def test_authorized_certificate_and_exact_subject_drive_real_policy_parser(self):
        run = self.attest(self.proof())
        argv, env = run.call_args.args
        for flag in ("--signer-workflow", "--source-ref", "--source-digest", "--signer-digest", "--deny-self-hosted-runners", "--custom-trusted-root"):
            self.assertIn(flag, argv)
        self.assertNotIn("--cert-identity", argv)
        self.assertNotIn("--signer-repo", argv)
        self.assertEqual(env["GH_HOST"], "github.com")
        self.assertEqual(env.get("GH_TELEMETRY"), "disabled")
        self.assertEqual(env.get("DO_NOT_TRACK"), "1")
        self.assertEqual(env.get("GH_NO_UPDATE_NOTIFIER"), "1")
        self.assertEqual(env.get("GH_NO_EXTENSION_UPDATE_NOTIFIER"), "1")
        self.assertFalse(set(env) & {"GH_TOKEN", "GITHUB_TOKEN", "MYSQL_PWD", "LD_PRELOAD", "HTTP_PROXY", "HTTPS_PROXY"})

    def test_wrong_certificate_identity_source_owner_runner_or_trigger_is_rejected(self):
        for field in self.certificate():
            proof = self.proof()
            proof[0]["verificationResult"]["signature"]["certificate"][field] = "unauthorized"
            with self.subTest(field=field), self.assertRaises(v.ReleaseError):
                self.attest(proof)

    def test_missing_timestamp_predicate_or_exact_asset_subject_is_rejected(self):
        for changed in ("timestamp", "predicate", "name", "digest", "extra-digest"):
            proof = self.proof()
            result = proof[0]["verificationResult"]
            if changed == "timestamp":
                result["verifiedTimestamps"] = []
            elif changed == "predicate":
                result["statement"]["predicateType"] = "https://untrusted.invalid/predicate"
            elif changed == "name":
                result["statement"]["subject"][0]["name"] = "another.tar.gz"
            elif changed == "digest":
                result["statement"]["subject"][0]["digest"]["sha256"] = "0" * 64
            else:
                result["statement"]["subject"][0]["digest"]["sha512"] = "0" * 128
            with self.subTest(changed=changed), self.assertRaises(v.ReleaseError):
                self.attest(proof)

    def test_attestation_receipt_verified_true_is_not_a_publisher_statement(self):
        for proof in ({"verified": True}, [], [{"verified": True}], [True], self.proof() * 31):
            with self.subTest(kind=str(type(proof))), self.assertRaises(v.ReleaseError):
                self.attest(proof)

    def test_malformed_nested_attestation_fails_with_fixed_release_error(self):
        for location, bad in (("signature", []), ("statement", []), ("verificationResult", []), ("verifiedTimestamps", "forged timestamp"), ("verifiedTimestamps", {"verified": True})):
            proof = self.proof()
            if location == "verificationResult":
                proof[0][location] = bad
            else:
                proof[0]["verificationResult"][location] = bad
            with self.subTest(location=location, bad=bad), self.assertRaises(v.ReleaseError):
                self.attest(proof)

    def test_signed_release_manifest_requires_exact_repo_tag_source_inventory_and_rc_policy(self):
        value, indexed = v.release_manifest(json.dumps(self.published()).encode())
        self.assertEqual(set(indexed), set((*v.PAYLOAD_NAMES, "SHA256SUMS")))
        for key, changed in (("schema", True), ("repository", "wrong/repo"), ("repository_id", 1), ("owner_id", 1),
                ("version", "0.1.0"), ("tag", "v0.1.0"), ("source_commit", "a" * 39), ("source_ref", "refs/heads/other"),
                ("channel", "stable"), ("workflow", "evil.yml"), ("acceptance", {"production_ready": True, "real_kvm_accepted": True})):
            changed_value = copy.deepcopy(value)
            changed_value[key] = changed
            with self.subTest(key=key), self.assertRaises(v.ReleaseError):
                v.release_manifest(json.dumps(changed_value).encode())

    def test_signed_manifest_rejects_unknown_duplicate_unsorted_and_malformed_assets(self):
        for change in ("unknown", "duplicate", "unsorted", "size", "hash", "extra-key"):
            value = self.published()
            if change == "unknown":
                value["assets"][0]["name"] = "evil.sh"
            elif change == "duplicate":
                value["assets"][-1] = dict(value["assets"][0])
            elif change == "unsorted":
                value["assets"].reverse()
            elif change == "size":
                value["assets"][0]["size"] = True
            elif change == "hash":
                value["assets"][0]["sha256"] = "F" * 64
            else:
                value["assets"][0]["verified"] = True
            with self.subTest(change=change), self.assertRaises(v.ReleaseError):
                v.release_manifest(json.dumps(value).encode())

    def test_capsule_exact_regular_files_and_metadata_are_verified_without_extraction(self):
        capsule, files = self.capsule()
        before = list(self.root.iterdir())
        self.assertEqual(v.capsule_files(capsule, SOURCE), files)
        self.assertEqual(list(self.root.iterdir()), before)
        for field, value in (("schema", True), ("source_commit", "b" * 40), ("release_kind", "development"), ("channel", "stable")):
            raw, _ = self.capsule(manifest_change=lambda data: data.update({field: value}))
            with self.subTest(field=field), self.assertRaises(v.ReleaseError):
                v.capsule_files(raw, SOURCE)

    def test_capsule_rejects_links_extensions_duplicates_privileged_modes_and_foreign_members(self):
        for typecode in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.XHDTYPE, tarfile.GNUTYPE_LONGNAME):
            def changed(info):
                if info.name == "install.py":
                    info.type, info.linkname = typecode, "../foreign"
            raw, _ = self.capsule(changes=changed)
            with self.subTest(typecode=typecode), self.assertRaises(v.ReleaseError):
                v.capsule_files(raw, SOURCE)
        for name in ("install.py", "../escape.py", "/tmp/escape.py", "unknown.py"):
            member = tarfile.TarInfo(name)
            member.uid, member.gid, member.mode, member.size = 0, 0, 0o644, 1
            raw, _ = self.capsule(extra=((member, b"x"),))
            with self.subTest(name=name), self.assertRaises(v.ReleaseError):
                v.capsule_files(raw, SOURCE)
        for field, value in (("mode", 0o755), ("mode", 0o4644), ("uid", 1000), ("gid", 1000)):
            def changed(info):
                if info.name == "install.py":
                    setattr(info, field, value)
            raw, _ = self.capsule(changes=changed)
            with self.subTest(field=field, value=value), self.assertRaises(v.ReleaseError):
                v.capsule_files(raw, SOURCE)

    def test_capsule_inventory_hash_size_and_mode_are_independently_bound(self):
        for key, value in (("sha256", "0" * 64), ("size", 1), ("mode", "0755")):
            def changed(manifest):
                manifest["files"][0][key] = value
            raw, _ = self.capsule(manifest_change=changed)
            with self.subTest(key=key), self.assertRaises(v.ReleaseError):
                v.capsule_files(raw, SOURCE)

    def test_capsule_unpacked_limit_and_truncated_or_nonzero_tail_are_rejected(self):
        raw, _ = self.capsule()
        uncompressed = gzip.decompress(raw)
        with mock.patch.object(v, "MAX_SMALL_BYTES", 512), self.assertRaises(v.ReleaseError):
            v.capsule_files(raw, SOURCE)
        for broken in (raw[:10], gzip.compress(uncompressed[:511], mtime=0), gzip.compress(uncompressed + b"not-zero", mtime=0)):
            with self.subTest(size=len(broken)), self.assertRaises(v.ReleaseError):
                v.capsule_files(broken, SOURCE)

    def test_publisher_json_duplicates_are_never_accepted(self):
        raw = json.dumps(self.published()).encode()
        with self.assertRaises(v.ReleaseError):
            v.release_manifest(raw.replace(b'"schema": 1', b'"schema": 1, "schema": 1', 1))
        for raw in (b"not-json", b'{"verified":true,"verified":true}'):
            with self.subTest(raw=raw), self.assertRaises(v.ReleaseError):
                v.strict_json(raw)

    def test_private_path_boundary_rejects_public_symlinks_hardlinks_and_foreign_owner(self):
        private = self.file("private", b"not a secret")
        public = self.file("public", b"not a secret", 0o644)
        link = self.root / "symlink"
        link.symlink_to(private)
        hard = self.root / "hard"
        os.link(private, hard)
        with self.root_owned_model():
            for path in (private, public, link, hard):
                with self.subTest(path=path.name), self.assertRaises(v.ReleaseError):
                    v.read_private(str(path), 100)
        foreign = self.file("foreign", b"not a secret")
        with mock.patch.object(Path, "lstat", return_value=types.SimpleNamespace(st_uid=1000, st_mode=stat.S_IFREG | 0o600, st_nlink=1)), self.assertRaises(v.ReleaseError):
            v.protected_path(str(foreign))

    def test_success_receipt_reverifies_all_three_signatures_offline_without_writes(self):
        with self.receipt_model() as model:
            before = {str(path): path.read_bytes() for path in self.root.rglob("*") if path.is_file()}
            result = self.verify(model)
            self.assertEqual(result["source_commit"], SOURCE)
            self.assertEqual(model.run.call_count, 3)
            self.assertEqual([Path(call.args[0][3]).name for call in model.run.call_args_list], ["release-manifest.json", v.CAPSULE_NAME, model.package.name])
            for call in model.run.call_args_list:
                argv, env = call.args
                self.assertIn("--custom-trusted-root", argv)
                self.assertNotIn("--cert-identity", argv)
                self.assertNotIn("--signer-repo", argv)
                self.assertEqual(env["HOME"], str(model.home))
                self.assertEqual(env["GH_CONFIG_DIR"], str(model.config))
            self.assertEqual(before, {str(path): path.read_bytes() for path in self.root.rglob("*") if path.is_file()})
            self.assertEqual(list(model.home.iterdir()), [])
            self.assertEqual(list(model.config.iterdir()), [])

    def test_receipt_verified_true_or_wrong_identity_never_authorizes_any_code(self):
        with self.receipt_model() as model:
            for field, changed in (("verified", True), ("source_commit", "b" * 40), ("repository", "wrong/repo"), ("repository_id", 1),
                    ("tag", "v0.1.0"), ("version", "0.1.0"), ("channel", "stable"), ("component", "aster-cloud-node"),
                    ("release_id", True), ("asset_name", "wrong.tar.gz"), ("asset_sha256", "0" * 64), ("asset_size", 1)):
                receipt = copy.deepcopy(model.receipt)
                receipt[field] = changed
                model.path.write_text(json.dumps(receipt))
                with self.subTest(field=field), self.assertRaises(v.ReleaseError):
                    self.verify(model)
            model.run.assert_not_called()

    def test_receipt_rejects_unpinned_gh_or_roots_even_when_local_json_hashes_are_updated(self):
        for key, constant in (("gh", "GH_BINARY_SHA256"), ("trusted_root", "TRUSTED_ROOT_SHA256")):
            with self.subTest(key=key), self.receipt_model() as model, mock.patch.object(v, constant, "0" * 64), self.assertRaises(v.ReleaseError):
                self.verify(model)
            model.run.assert_not_called()

    def test_receipt_private_proof_symlinks_hardlinks_and_nonempty_config_refuse_before_gh(self):
        for kind in ("symlink", "hardlink", "public", "home-config"):
            with self.subTest(kind=kind), self.receipt_model() as model:
                target = model.files["attestation"]
                if kind == "symlink":
                    aside = self.file("attestation-aside", target.read_bytes())
                    target.unlink()
                    target.symlink_to(aside)
                elif kind == "hardlink":
                    os.link(target, self.root / "alias")
                elif kind == "public":
                    target.chmod(0o644)
                else:
                    model.home.joinpath(".gitconfig").write_text("foreign configuration")
                with self.assertRaises(v.ReleaseError):
                    self.verify(model)
                model.run.assert_not_called()

    def test_observed_release_id_is_not_signature_authority_or_an_authentication_bypass(self):
        with self.receipt_model() as model:
            receipt = copy.deepcopy(model.receipt)
            receipt["release_id"] += 1
            model.path.write_text(json.dumps(receipt))
            result = self.verify(model)
            self.assertEqual(result["release_id"], receipt["release_id"])
            self.assertEqual(model.run.call_count, 3, "an observed API release ID must never skip signature verification")

    def test_receipt_unknown_adjacent_code_or_changed_installer_is_not_executed(self):
        for change in ("unknown-neighbor", "changed-installer", "nonempty-home", "nonempty-config"):
            with self.subTest(change=change), self.receipt_model() as model:
                if change == "unknown-neighbor":
                    self.file("installer/json.py", b"never import me")
                elif change == "changed-installer":
                    self.file("installer/install.py", b"changed never execute")
                else:
                    (model.home if change == "nonempty-home" else model.config).joinpath("foreign-config").write_text("never read")
                with self.assertRaises(v.ReleaseError):
                    self.verify(model)


if __name__ == "__main__":
    unittest.main(verbosity=2)

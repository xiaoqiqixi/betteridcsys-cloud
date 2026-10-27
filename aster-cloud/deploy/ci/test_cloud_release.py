#!/usr/bin/env python3
"""Offline release/bootstrap policy contracts; optional real anonymous CLI proof.

Default tests never contact GitHub or install a host. --native-verifier is a
separate, fail-closed Linux contract using an official public CLI example; it
does NOT claim that a Cloud release was published/downloaded or KVM accepted.
"""
import argparse
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock
import urllib.error
import zipfile

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("cloud_release_policy_contract", HERE / "cloud_release.py")
C = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = C
SPEC.loader.exec_module(C)
V = C.V
SOURCE = "a" * 40
OFFICIAL_SOURCE = "4f2cfe92e3499f8581bf39db77e0a1431fa7b55c"
OFFICIAL_BUNDLE_SHA = "56a973357566cb0ac6e2297731f238951d0f5f5291e3733fc89e754ae38934be"
NATIVE_PHASE = "preflight"


def native_cli_failure(result):
    """Classify only this no-token public-fixture invocation; never echo stderr."""
    message = result.stderr[:V.MAX_SMALL_BYTES].lower()
    if result.returncode == -4:
        return "CLI_CPU_INSTRUCTION_UNAVAILABLE"
    if b"glibc_" in message and b"not found" in message:
        return "CLI_LIBC_UNAVAILABLE"
    if b"unknown flag" in message or b"unknown command" in message:
        return "CLI_USAGE_MISMATCH"
    if b"gh auth login" in message:
        return "CLI_UNEXPECTED_AUTH_REQUIREMENT"
    if b"verification failed" in message or b"failed to verify" in message or b"no matching attestations" in message:
        return "CLI_SIGNATURE_VERIFICATION_FAILED"
    return "CLI_NONZERO_EXIT_DETAILS_WITHHELD"


def native_verifier(evidence):
    """Real pinned Linux CLI, anonymous local bundle, fresh empty HOME/config."""
    global NATIVE_PHASE
    NATIVE_PHASE = "preflight"
    if sys.platform != "linux" or os.uname().machine not in ("x86_64", "amd64"):
        raise C.PolicyError("Native anonymous contract requires Linux amd64; never skip-success")
    bundle = HERE / "fixtures/gh-2.103.2-linux-amd64.attestation.json"
    roots = HERE.parent / "install/release-trusted-root.json"
    if V.digest(bundle.read_bytes()) != OFFICIAL_BUNDLE_SHA or V.digest(roots.read_bytes()) != V.TRUSTED_ROOT_SHA256:
        raise C.PolicyError("Official example/trust-root bytes differ from reviewed pins")
    with tempfile.TemporaryDirectory(prefix="cloud-anonymous-signature-") as temporary:
        base = Path(temporary)
        home, config = base / "home", base / "config"
        home.mkdir(mode=0o700)
        config.mkdir(mode=0o700)
        NATIVE_PHASE = "official-cli-download"
        archive = V.fetch("https://github.com/cli/cli/releases/download/v" + V.GH_VERSION + "/" + V.GH_TAR_NAME, V.GH_TAR_SIZE)
        V.write_new(base / V.GH_TAR_NAME, archive)
        NATIVE_PHASE = "pinned-cli-extraction"
        V.write_new(base / "gh", V.pinned_gh(archive), 0o700)
        argv = [str(base / "gh"), "attestation", "verify", str(base / V.GH_TAR_NAME), "--bundle", str(bundle),
                "--repo", "cli/cli", "--signer-workflow", "cli/cli/.github/workflows/deployment.yml",
                "--source-ref", "refs/heads/trunk", "--source-digest", OFFICIAL_SOURCE, "--signer-digest", OFFICIAL_SOURCE,
                "--cert-oidc-issuer", V.ISSUER, "--deny-self-hosted-runners", "--custom-trusted-root", str(roots), "--format", "json"]
        env = V.verification_environment(home, config)
        # No inherited GH_TOKEN/GITHUB_TOKEN, user HOME/config or keychain.
        NATIVE_PHASE = "offline-signature-command"
        result = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45, check=False)
        if len(result.stdout) > V.MAX_SMALL_BYTES or len(result.stderr) > V.MAX_SMALL_BYTES:
            raise C.PolicyError("CLI verification output exceeds the fixed bound")
        if result.returncode:
            raise C.PolicyError(native_cli_failure(result))
        NATIVE_PHASE = "verified-result-json"
        rows = V.strict_json(result.stdout)
        if not isinstance(rows, list) or len(rows) != 1:
            raise C.PolicyError("Unexpected official example verification result")
        verified = rows[0]["verificationResult"]
        certificate = verified["signature"]["certificate"]
        NATIVE_PHASE = "verified-certificate-identity"
        required = {"sourceRepositoryIdentifier": "212613049", "sourceRepositoryOwnerIdentifier": "59704711",
                    "issuer": V.ISSUER, "sourceRepositoryDigest": OFFICIAL_SOURCE, "sourceRepositoryRef": "refs/heads/trunk",
                    "buildSignerDigest": OFFICIAL_SOURCE, "runnerEnvironment": "github-hosted",
                    "subjectAlternativeName": "https://github.com/cli/cli/.github/workflows/deployment.yml@refs/heads/trunk"}
        if any(certificate.get(key) != value for key, value in required.items()):
            raise C.PolicyError("Anonymous verified certificate identity mismatch")
        NATIVE_PHASE = "verified-subject-and-time"
        if (not verified.get("verifiedTimestamps") or
                not any(item.get("name") == V.GH_TAR_NAME and item.get("digest") == {"sha256": V.GH_TAR_SHA256} for item in verified["statement"]["subject"])):
            raise C.PolicyError("Anonymous verified artifact digest or timestamp mismatch")
        NATIVE_PHASE = "empty-home-and-config"
        if any(home.iterdir()) or any(config.iterdir()):
            raise C.PolicyError("Offline verifier wrote unexpected private HOME or config state")
    proof = {"schema": 1, "passed": True, "gh_version": V.GH_VERSION, "gh_archive_sha256": V.GH_TAR_SHA256,
             "gh_binary_sha256": V.GH_BINARY_SHA256, "trusted_root_sha256": V.TRUSTED_ROOT_SHA256,
             "example_bundle_sha256": OFFICIAL_BUNDLE_SHA, "anonymous": True, "token_environment": False,
             "fresh_empty_home_config_unchanged": True, "local_bundle_custom_roots": True,
             "signer_workflow_source_digest_policy_verified": True, "host_apply": False, "cloud_release_acceptance": False}
    NATIVE_PHASE = "redacted-proof-output"
    if evidence is not None:
        if not evidence.is_absolute() or ".." in evidence.parts:
            raise C.PolicyError("Absolute new redacted JSON evidence file required")
        V.write_new(evidence, C.json_bytes(proof))
    print(json.dumps(proof, sort_keys=True))
    return proof


class Gates:
    def __init__(self):
        self.jobs = {"cloud.yml": copy.deepcopy(C.CLOUD_JOBS), "ci.yml": copy.deepcopy(C.FINANCE_JOBS)}
        self.job_conclusion = "success"
        self.run_conclusion = "success"
        self.source = SOURCE
        self.calls = []

    def request(self, method, suffix, value=None):
        self.calls.append((method, suffix, value))
        assert method == "GET", "unit policy must not mutate a real API"
        if suffix == "":
            return {"id": V.REPOSITORY_ID, "full_name": V.REPOSITORY, "private": False, "default_branch": "main", "owner": {"id": V.OWNER_ID}}
        if suffix.startswith("/git/ref/"):
            return {"object": {"type": "commit", "sha": self.source}}
        if suffix == "/releases/tags/" + V.TAG:
            raise C.APIError(404)
        for index, workflow in enumerate(("cloud.yml", "ci.yml"), 1):
            if suffix == "/actions/workflows/" + workflow:
                return {"id": index, "path": ".github/workflows/" + workflow, "state": "active"}
            if suffix.startswith("/actions/workflows/" + workflow + "/runs?"):
                return {"total_count": 1, "workflow_runs": [{"id": index * 100, "run_attempt": 1, "workflow_id": index,
                    "head_sha": SOURCE, "head_branch": "main", "event": "push", "status": "completed", "conclusion": self.run_conclusion}]}
            if suffix == "/actions/runs/" + str(index * 100) + "/attempts/1/jobs?per_page=100":
                return {"total_count": len(self.jobs[workflow]), "jobs": [{"name": name, "status": "completed", "conclusion": self.job_conclusion} for name in self.jobs[workflow]]}
        raise AssertionError("Unmodeled fixed API boundary")


def environment(workflow=C.BUILD_PATH):
    return {"GITHUB_REPOSITORY": V.REPOSITORY, "GITHUB_REPOSITORY_ID": str(V.REPOSITORY_ID),
            "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": V.SOURCE_REF,
            "GITHUB_WORKFLOW_REF": V.REPOSITORY + "/" + workflow + "@" + V.SOURCE_REF,
            "GITHUB_SHA": SOURCE, "GITHUB_WORKFLOW_SHA": SOURCE, "GITHUB_RUN_ID": "10", "GITHUB_RUN_ATTEMPT": "1"}


class CloudReleaseContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cloud-release-contract-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def test_all_sixteen_exact_sha_jobs_require_both_supported_native_guests_and_financial_browser(self):
        api = Gates()
        result = C.prepare_build(api, environment(), {"inputs": {"tag": V.TAG}})
        self.assertEqual(sum(len(proof["jobs"]) for proof in result["prechecks"]), 16)
        for version in ("22.04", "24.04"):
            self.assertIn("Native libvirt preparation (ubuntu-" + version + ")", result["prechecks"][0]["jobs"])
        self.assertNotIn("Native libvirt preparation (ubuntu-26.04)", result["prechecks"][0]["jobs"])
        self.assertIn("Real MySQL financial browser acceptance", result["prechecks"][1]["jobs"])
        self.assertIn("Native financial acceptance (ubuntu-22.04)", result["prechecks"][1]["jobs"])
        self.assertTrue(all(method == "GET" for method, _, _ in api.calls))

    def test_exact_sha_push_gates_are_scheduled_for_every_main_change(self):
        for workflow in ("cloud.yml", "ci.yml"):
            with self.subTest(workflow=workflow):
                text = (C.ROOT / ".github/workflows" / workflow).read_text()
                trigger = text.split("\npermissions:", 1)[0]
                self.assertIn("\n  push:\n    branches: ['main']\n", trigger)
                self.assertNotRegex(trigger, r"(?m)^\s+(?:paths|paths-ignore|branches-ignore):")
                self.assertNotIn("workflow_dispatch", text[text.index("jobs:"):])

    def test_each_supported_native_gate_is_required_at_exact_source(self):
        for version in ("22.04", "24.04"):
            with self.subTest(version=version):
                api = Gates()
                api.jobs["cloud.yml"].remove("Native libvirt preparation (ubuntu-" + version + ")")
                with self.assertRaises(C.PolicyError):
                    C.green_checks(api, SOURCE)

    def test_real_financial_browser_gate_is_required_and_not_substitutable(self):
        browser = "Real MySQL financial browser acceptance"
        self.assertIn(browser, C.FINANCE_JOBS)
        for replacement in (None, "checks", "Demo financial browser acceptance"):
            with self.subTest(replacement=replacement):
                api = Gates()
                api.jobs["ci.yml"].remove(browser)
                if replacement:
                    api.jobs["ci.yml"].add(replacement)
                with self.assertRaises(C.PolicyError):
                    C.green_checks(api, SOURCE)

    def test_only_financial_browser_non_success_refuses_release(self):
        browser = "Real MySQL financial browser acceptance"
        self.assertIn(browser, C.FINANCE_JOBS)
        for status, conclusion in (("completed", "skipped"), ("completed", "failure"),
                                   ("completed", "cancelled"), ("in_progress", None)):
            with self.subTest(status=status, conclusion=conclusion):
                api = Gates()
                original = api.request

                def request(method, suffix, value=None):
                    result = original(method, suffix, value)
                    if suffix == "/actions/runs/200/attempts/1/jobs?per_page=100":
                        for job in result["jobs"]:
                            if job["name"] == browser:
                                job["status"] = status
                                job["conclusion"] = conclusion
                    return result

                api.request = request
                with self.assertRaises(C.PolicyError):
                    C.green_checks(api, SOURCE)

    def test_skipped_or_failed_required_job_or_latest_run_refused(self):
        for field in ("job_conclusion", "run_conclusion"):
            for conclusion in ("skipped", "failure", "cancelled", None):
                api = Gates()
                setattr(api, field, conclusion)
                with self.subTest(field=field, conclusion=conclusion), self.assertRaises(C.PolicyError):
                    C.green_checks(api, SOURCE)

    def test_main_tag_and_workflow_digest_must_be_identical(self):
        for key in ("GITHUB_SHA", "GITHUB_WORKFLOW_SHA", "GITHUB_REF", "GITHUB_WORKFLOW_REF", "GITHUB_REPOSITORY_ID", "GITHUB_EVENT_NAME"):
            env = environment()
            env[key] = "b" * 40 if "SHA" in key else "untrusted"
            with self.subTest(field=key), self.assertRaises(C.PolicyError):
                C.prepare_build(Gates(), env, {"inputs": {"tag": V.TAG}})
        api = Gates()
        api.source = "b" * 40
        with self.assertRaises(C.PolicyError):
            C.prepare_build(api, environment(), {"inputs": {"tag": V.TAG}})

    def test_financial_stable_or_other_cloud_tags_are_not_release_inputs(self):
        for tag in ("v0.5.9", "smtp-v0.5.9", "cloud-v0.1.0", "cloud-v0.1.0-rc.2", V.TAG + "\n"):
            with self.subTest(tag=tag), self.assertRaises(C.PolicyError):
                C.prepare_build(Gates(), environment(), {"inputs": {"tag": tag}})

    def test_existing_cloud_release_or_draft_is_never_adopted(self):
        api = mock.Mock()
        api.request.return_value = {"id": 5, "draft": True}
        with self.assertRaises(C.PolicyError):
            C.no_release(api)

    def test_non404_release_absence_error_is_not_treated_as_fresh(self):
        for status in (401, 403, 429, 500):
            api = mock.Mock()
            api.request.side_effect = C.APIError(status)
            with self.subTest(status=status), self.assertRaises(C.PolicyError):
                C.no_release(api)

    def test_publisher_lists_and_refuses_existing_drafts_even_when_tag_get_is_404(self):
        api = mock.Mock()
        def request(method, suffix, value=None):
            self.assertEqual(method, "GET")
            if suffix == "/releases/tags/" + V.TAG:
                raise C.APIError(404)
            self.assertEqual(suffix, "/releases?per_page=100&page=1")
            return [{"id": 41, "tag_name": V.TAG, "draft": True}]
        api.request.side_effect = request
        with self.assertRaisesRegex(C.PolicyError, "Existing Cloud draft"):
            C.no_release(api, include_drafts=True)
        self.assertEqual(api.request.call_count, 2)

    def test_publisher_draft_absence_is_paginated_and_fails_closed_at_bound(self):
        api = mock.Mock()
        full = [{"tag_name": "v0.5.9", "id": index} for index in range(100)]
        api.request.side_effect = [C.APIError(404), full, []]
        C.no_release(api, include_drafts=True)
        self.assertEqual(api.request.call_args.args[1], "/releases?per_page=100&page=2")
        api.request.side_effect = [C.APIError(404), *([full] * 5)]
        with self.assertRaisesRegex(C.PolicyError, "bounded inventory"):
            C.no_release(api, include_drafts=True)

    def test_main_or_required_check_change_during_upload_retains_draft_without_publish(self):
        # Orchestration-only model: crypto/source/ZIP boundaries have their own
        # independent tests. This proves the final check is AFTER all uploads.
        for boundary in ("main", "checks"):
            api = mock.Mock()
            files = {name: b"synthetic data" for name in V.RELEASE_NAMES}
            def request(method, suffix, value=None):
                if suffix == "/actions/workflows/cloud-release-build.yml":
                    return {"id": 1, "path": C.BUILD_PATH, "state": "active"}
                if suffix == "/actions/runs/10":
                    return {"workflow_id": 1, "path": C.BUILD_PATH, "event": "workflow_dispatch", "head_branch": "main", "head_sha": SOURCE,
                            "run_attempt": 1, "status": "completed", "conclusion": "success", "repository": {"id": V.REPOSITORY_ID, "full_name": V.REPOSITORY},
                            "head_repository": {"id": V.REPOSITORY_ID, "full_name": V.REPOSITORY}}
                if method == "POST":
                    self.assertEqual(suffix, "/releases")
                    return {"id": 42, "tag_name": V.TAG, "draft": True, "prerelease": True}
                if suffix == "/releases/42" and method == "GET":
                    return {"draft": True, "tag_name": V.TAG, "assets": [{"name": name, "state": "uploaded", "size": len(raw), "digest": "sha256:" + V.digest(raw)} for name, raw in files.items()]}
                raise AssertionError("Publication must not reach PATCH after the final gate changed")
            api.request.side_effect = request
            event = {"inputs": {"tag": V.TAG, "build_run_id": "10", "build_attempt": "1"}}
            main_results = [SOURCE, SOURCE, C.PolicyError("final main changed")] if boundary == "main" else [SOURCE] * 3
            check_results = [[], [], C.PolicyError("final CI changed")] if boundary == "checks" else [[], [], []]
            with self.subTest(boundary=boundary), mock.patch.object(C, "main_identity", side_effect=main_results), mock.patch.object(C, "green_checks", side_effect=check_results), mock.patch.object(C, "no_release"), mock.patch.object(C, "artifact", return_value={}), mock.patch.object(C, "zip_files", return_value=files), mock.patch.object(C, "write_directory"), mock.patch.object(C, "verify_signed") as verified, mock.patch.object(C, "resolve", return_value=SOURCE), self.assertRaises(C.PolicyError):
                C.publish(api, environment(C.PUBLISH_PATH), event, self.root / "candidate")
            verified.assert_called_once()
            self.assertEqual(api.upload.call_count, len(V.RELEASE_NAMES))
            self.assertTrue(any(call.args[0] == "POST" for call in api.request.call_args_list))
            self.assertFalse(any(call.args[0] == "PATCH" for call in api.request.call_args_list))

    def test_api_never_mutates_finance_existing_release_or_latest_setting(self):
        api = C.GitHub("synthetic-not-real-token")
        with mock.patch.object(api, "open") as opened:
            for method, suffix, value in (("PATCH", "/releases/5", {"draft": False, "prerelease": True, "make_latest": "false"}),
                    ("POST", "/releases", {"tag_name": "v0.5.9"}), ("DELETE", "/releases/5", None),
                    ("PATCH", "/releases/5", {"make_latest": "true"})):
                with self.subTest(method=method, suffix=suffix), self.assertRaises(C.PolicyError):
                    api.request(method, suffix, value)
            opened.assert_not_called()

    def test_new_draft_upload_and_publication_are_owned_channel_only(self):
        api = C.GitHub("synthetic-not-real-token")
        draft = {"tag_name": V.TAG, "target_commitish": SOURCE, "name": "test", "body": "test", "draft": True, "prerelease": True, "make_latest": "false"}
        with mock.patch.object(api, "open", return_value=(201, {}, b'{"id":42}')) as opened:
            api.request("POST", "/releases", draft)
            self.assertEqual(opened.call_count, 1)
        with mock.patch.object(api, "open", return_value=(200, {}, b'{"id":42}')) as opened:
            api.request("PATCH", "/releases/42", {"draft": False, "prerelease": True, "make_latest": "false"})
            self.assertNotIn('"make_latest": "true"', opened.call_args.args[2].decode())
        with self.assertRaises(C.PolicyError):
            api.upload(41, "SHA256SUMS", b"data")
        with self.assertRaises(C.PolicyError):
            api.upload(42, "vps-billing.tar.gz", b"data")

    def test_public_body_has_exact_full_commit_and_no_unverified_capsule_execution(self):
        body = C.release_body(SOURCE, "b" * 64)
        self.assertEqual(body.count("raw.githubusercontent.com/" + V.REPOSITORY + "/" + SOURCE), 2)
        self.assertIn("初始脚本是操作者审核并信任的固定源码入口", body)
        self.assertIn("不能在执行前自证可信", body)
        self.assertIn("匿名 Sigstore 验签通过后才执行", body)
        self.assertIn("Ubuntu 22.04 / 24.04 amd64", body)
        self.assertIn("Ubuntu 26.04 暂不支持", body)
        self.assertIn("Python 3.10+", body)
        self.assertIn("默认不安装", body)
        self.assertIn("真实 KVM、物理网络和生产部署尚未验收", body)
        self.assertIn("财务既有标签、Release、资产和 latest 均不改变", body)
        self.assertIn("## 主控", body)
        self.assertIn("## 专用 KVM 被控", body)
        self.assertNotIn("/main/", body)
        self.assertNotIn("--apply", body)
        self.assertIn("- controller'", body)
        self.assertIn("- node'", body)

    def zip(self, entries):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            for name, mode in entries:
                item = zipfile.ZipInfo(name)
                item.external_attr = mode << 16
                archive.writestr(item, b"synthetic data")
        return output.getvalue()

    def test_candidate_zip_requires_flat_exact_regular_inventory(self):
        entries = [(name, stat.S_IFREG | 0o644) for name in V.SIGNED_NAMES]
        self.assertEqual(set(C.zip_files(self.zip(entries), signed=False)), set(V.SIGNED_NAMES))
        for extra in (("../escape", stat.S_IFREG | 0o644), (V.SIGNED_NAMES[0], stat.S_IFREG | 0o644), ("other", stat.S_IFLNK | 0o777)):
            with self.subTest(extra=extra), self.assertRaises(C.PolicyError):
                C.zip_files(self.zip(entries + [extra]), signed=False)
        linked = entries.copy()
        linked[0] = (linked[0][0], stat.S_IFLNK | 0o777)
        with self.assertRaises(C.PolicyError):
            C.zip_files(self.zip(linked), signed=False)

    def test_candidate_zip_unpacked_total_and_malformed_zip_refused(self):
        with self.assertRaises(C.PolicyError):
            C.zip_files(b"not zip", signed=False)
        with mock.patch.object(C, "MAX_ZIP", 1), self.assertRaises(C.PolicyError):
            C.zip_files(self.zip([(name, stat.S_IFREG | 0o644) for name in V.SIGNED_NAMES]), signed=False)

    def test_staging_never_overwrites_existing_data_or_symlinks(self):
        directory = self.root / "existing"
        directory.mkdir()
        (directory / "operator-file").write_bytes(b"preserve")
        with self.assertRaises(C.PolicyError):
            C.write_directory(directory, {"SHA256SUMS": b"new"})
        self.assertEqual((directory / "operator-file").read_bytes(), b"preserve")

    def test_native_cli_failure_diagnostics_are_fixed_codes_never_raw_stderr(self):
        cases = ((-4, b"synthetic-private-marker", "CLI_CPU_INSTRUCTION_UNAVAILABLE"),
                 (1, b"GLIBC_2.99 not found synthetic-private-marker", "CLI_LIBC_UNAVAILABLE"),
                 (1, b"unknown flag synthetic-private-marker", "CLI_USAGE_MISMATCH"),
                 (4, b"please run gh auth login synthetic-private-marker", "CLI_UNEXPECTED_AUTH_REQUIREMENT"),
                 (1, b"verification failed synthetic-private-marker", "CLI_SIGNATURE_VERIFICATION_FAILED"),
                 (1, b"unrecognized synthetic-private-marker", "CLI_NONZERO_EXIT_DETAILS_WITHHELD"))
        for code, stderr, expected in cases:
            with self.subTest(expected=expected):
                message = native_cli_failure(types.SimpleNamespace(returncode=code, stderr=stderr))
                self.assertEqual(message, expected)
                self.assertNotIn("synthetic-private-marker", message)

    def test_code_pinned_root_snapshot_matches_committed_official_material(self):
        raw = (HERE.parent / "install/release-trusted-root.json").read_bytes()
        self.assertEqual(len(raw), V.TRUSTED_ROOT_SIZE)
        self.assertEqual(V.digest(raw), V.TRUSTED_ROOT_SHA256)

    def test_url_policy_refuses_arbitrary_urls_repos_tags_assets_and_credentials(self):
        for url in ("http://github.com/" + V.REPOSITORY, "https://evil.invalid/file", "https://github.com@evil.invalid/file",
                    "https://github.com/other/repo/releases/download/" + V.TAG + "/SHA256SUMS",
                    "https://github.com/" + V.REPOSITORY + "/releases/latest/download/SHA256SUMS",
                    "https://github.com/" + V.REPOSITORY + "/releases/download/" + V.TAG + "/evil.py",
                    "https://api.github.com/repos/" + V.REPOSITORY + "/releases/tags/v0.5.9",
                    "https://github.com:444/cli/cli/releases/download/v" + V.GH_VERSION + "/" + V.GH_TAR_NAME):
            with self.subTest(url=url), self.assertRaises(V.ReleaseError):
                V.allowed_url(url)

    def test_asset_redirect_only_accepts_the_official_release_cdn(self):
        url = "https://github.com/" + V.REPOSITORY + "/releases/download/" + V.TAG + "/SHA256SUMS"
        opener = mock.Mock()
        opener.open.side_effect = urllib.error.HTTPError(url, 302, "synthetic", {"Location": "https://evil.invalid/payload"}, None)
        with self.assertRaises(V.ReleaseError):
            V.fetch(url, 32, opener=opener)
        self.assertEqual(opener.open.call_count, 1)

    def test_pinned_gh_archive_is_hashed_before_any_tar_parsing(self):
        with mock.patch.object(V.tarfile, "open") as archive, self.assertRaises(V.ReleaseError):
            V.pinned_gh(b"untrusted code")
        archive.assert_not_called()

    def test_bootstrap_nonroot_or_missing_terminal_never_downloads(self):
        with mock.patch.object(V.os, "geteuid", return_value=501), mock.patch.object(V, "fetch") as fetch, self.assertRaises(V.ReleaseError):
            V.bootstrap("controller")
        fetch.assert_not_called()
        with mock.patch.object(V.os, "geteuid", return_value=0), mock.patch.object(V.sys, "platform", "linux"), mock.patch.object(V.os, "uname", return_value=types.SimpleNamespace(machine="x86_64")), mock.patch.object(V.os, "open", side_effect=OSError("no tty")), mock.patch.object(V, "public_release_metadata") as metadata, self.assertRaises(V.ReleaseError):
            V.bootstrap("node")
        metadata.assert_not_called()

    @contextlib.contextmanager
    def handoff_model(self, *, plan=None):
        identity = {"source_commit": SOURCE, "release_id": 42}
        with mock.patch.object(V, "read_private", return_value=b"synthetic"), mock.patch.object(V, "bundle_manifest", return_value={}), mock.patch.object(V, "verify_release_receipt", return_value=identity), mock.patch.object(V.os, "open", return_value=9), mock.patch.object(V.os, "dup2") as dup, mock.patch.object(V.os, "close"), mock.patch.object(V.os, "execve") as execute, mock.patch.object(V.subprocess, "run", return_value=types.SimpleNamespace(returncode=0, stdout=json.dumps(plan).encode() if plan else b"", stderr=b"")) as run:
            yield execute, dup, run

    def test_interactive_handoff_preserves_original_wizard_final_install_approval(self):
        for apply in (False, True):
            with self.subTest(apply=apply), self.handoff_model() as (execute, dup, run):
                V.handoff(self.root, "controller", "b" * 64, apply=apply)
                argv = execute.call_args.args[1]
                self.assertIn("--wizard", argv)
                self.assertNotIn("--plan", argv)
                self.assertEqual("--apply" in argv, apply)
                dup.assert_called_once_with(9, 0)
                run.assert_not_called()

    def test_download_only_runs_actual_plan_argv_without_wizard_apply_start_or_tty(self):
        plan = {"mode": "plan", "release_kind": "release", "source_commit": SOURCE, "component": "node", "software": "not-installed-by-plan", "service": "not-started-by-plan"}
        with self.handoff_model(plan=plan) as (execute, dup, run):
            proof = V.handoff(self.root, "node", "b" * 64, download_only=True)
            argv = run.call_args.args[0]
            self.assertIn("--plan", argv)
            self.assertFalse(any(flag in argv for flag in ("--wizard", "--apply", "--start")))
            self.assertFalse(proof["host_apply"])
            self.assertEqual(run.call_count, 1)
            execute.assert_not_called()
            dup.assert_not_called()

    def test_download_only_mixed_with_apply_or_start_is_rejected_before_bootstrap(self):
        for flag in ("--apply", "--start"):
            with self.subTest(flag=flag), mock.patch.object(V, "bootstrap") as bootstrap, contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(V.main(["controller", "--download-only", flag]), 1)
            bootstrap.assert_not_called()

    def test_all_workflow_actions_are_immutable_and_privileges_are_separated(self):
        for name in ("cloud-release-build.yml", "cloud-release-publish.yml"):
            text = (C.ROOT / ".github/workflows" / name).read_text()
            references = re.findall(r"uses:\s+([^\s#]+)", text)
            self.assertTrue(references)
            self.assertTrue(all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", reference) for reference in references))
            self.assertNotIn("pull_request_target", text)
            self.assertNotIn("secrets.", text)
        build = (C.ROOT / C.BUILD_PATH).read_text()
        unprivileged = build.split("  build:", 1)[1].split("  attest:", 1)[0]
        self.assertNotIn("id-token: write", unprivileged)
        self.assertNotIn("contents: write", unprivileged)
        self.assertIn("actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6", build)


if __name__ == "__main__":
    if "--native-verifier" in sys.argv:
        parser = argparse.ArgumentParser()
        parser.add_argument("--native-verifier", action="store_true", required=True)
        parser.add_argument("--evidence", type=Path)
        args = parser.parse_args()
        try:
            native_verifier(args.evidence)
        except (C.PolicyError, V.ReleaseError) as error:
            # These two types contain only our own fixed policy messages, never
            # provider stderr, credential data, arbitrary argv or source text.
            print("Native anonymous verifier refused [" + NATIVE_PHASE + "]: " + str(error), file=sys.stderr)
            sys.exit(1)
        except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
            code = "COMMAND_TIMEOUT" if isinstance(error, subprocess.TimeoutExpired) else "OS_OPERATION_REFUSED" if isinstance(error, OSError) else "STRUCTURED_RESULT_INVALID"
            print("Native anonymous verifier refused [" + NATIVE_PHASE + "]: " + code, file=sys.stderr)
            sys.exit(1)
    else:
        unittest.main(verbosity=2)

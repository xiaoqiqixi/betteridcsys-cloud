#!/usr/bin/env python3
"""Validate the published RC's real root plan proof, never install or publish."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("cloud_public_evidence_policy", Path(__file__).with_name("cloud_release.py"))
C = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = C
SPEC.loader.exec_module(C)

# This is an immutable published release contract, not the current main SHA.
RELEASE_SOURCE = "8092c3cc0517c69562e8a5cdd94bc5e389e1bc8e"
RELEASE_ID = 425041579
PACKAGE_DIGESTS = {
    "controller": "1feebda62813f91b4aa9eca97d52f62e991593c5ff7bfe45d4a38c699856292a",
    "node": "cf92656ba8daf210815dfe8fa8d04d36ef46a9cd27c5f488c52780f511ff5544",
}
TARGETS = {"ubuntu-22.04": "22.04", "ubuntu-24.04": "24.04"}


class EvidenceError(Exception):
    pass


def validate(raw, role, runner_os, facts, control_source):
    if (not isinstance(raw, bytes) or not 0 < len(raw) <= 16384 or
            not isinstance(role, str) or role not in PACKAGE_DIGESTS or
            not isinstance(runner_os, str) or runner_os not in TARGETS or
            not isinstance(control_source, str) or not C.V.COMMIT.fullmatch(control_source)):
        raise EvidenceError("Invalid published-proof identity or input")
    if (not isinstance(facts, dict) or set(facts) != {"system", "architecture", "distribution", "version"} or
            any(type(value) is not str for value in facts.values()) or not C.I.supported_target(facts) or
            facts["version"] != TARGETS[runner_os]):
        raise EvidenceError("Actual host does not match the supported runner")
    try:
        proof = C.V.strict_json(raw)
    except C.V.ReleaseError:
        raise EvidenceError("Malformed published proof") from None
    expected = {"schema": 1, "passed": True, "role": role, "tag": "cloud-v0.1.0-rc.1",
                "source_commit": RELEASE_SOURCE, "release_id": RELEASE_ID, "artifact_sha256": PACKAGE_DIGESTS[role],
                "anonymous_download": True, "publisher_signature_reverified": True, "production_installer_plan": True,
                "host_apply": False, "service_started": False, "real_kvm_acceptance": False}
    if (not isinstance(proof, dict) or set(proof) != set(expected) or
            any(type(proof[key]) is not type(value) or proof[key] != value for key, value in expected.items())):
        raise EvidenceError("Published source, signature, role, exact proof or no-apply boundary mismatch")
    return {"schema": 1, "passed": True, "control_source": control_source,
            "runner_os": runner_os, "target": dict(facts), "proof": proof}


def read_root_proof(path):
    if not path.is_absolute() or str(path) != os.path.normpath(str(path)):
        raise EvidenceError("Canonical absolute root evidence required")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1 or
                    before.st_mode & 0o022 or not 0 < before.st_size <= 16384):
                raise EvidenceError("Root-owned bounded non-writable proof required")
            raw = stream.read(16385)
            after = os.fstat(stream.fileno())
            # Reading may update atime. Identity, content and authorization
            # metadata must stay fixed; our own access time is not a mutation.
            stable = ("st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
            if len(raw) != before.st_size or any(getattr(before, key) != getattr(after, key) for key in stable):
                raise EvidenceError("Proof changed during read")
            return raw
    except OSError:
        raise EvidenceError("Published root evidence unavailable") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--role", required=True, choices=tuple(PACKAGE_DIGESTS))
    parser.add_argument("--runner-os", required=True, choices=tuple(TARGETS))
    args = parser.parse_args(argv)
    try:
        if (os.environ.get("GITHUB_REPOSITORY") != C.V.REPOSITORY or
                os.environ.get("GITHUB_REF") != "refs/heads/main"):
            raise EvidenceError("Only reviewed main CI may report this acceptance")
        report = validate(read_root_proof(args.evidence), args.role, args.runner_os,
                          C.I.target_info(), os.environ.get("GITHUB_SHA", ""))
        print(json.dumps(report, sort_keys=True))
    except EvidenceError as error:
        print("Published Cloud verification refused: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

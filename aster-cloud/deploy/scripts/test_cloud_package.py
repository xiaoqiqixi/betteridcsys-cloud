#!/usr/bin/env python3
"""Offline packager tests. Synthetic ELF bytes exist only inside these tests."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location("cloud_package", Path(__file__).with_name("package-cloud.py"))
PACKAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGE)


def test_elf(program_type=1):
    """Small structure fixture, not a runnable or production binary."""
    raw = bytearray(120)
    raw[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", raw, 16, 2, 62, 1)
    struct.pack_into("<Q", raw, 32, 64)
    struct.pack_into("<HHH", raw, 52, 64, 56, 1)
    struct.pack_into("<I", raw, 64, program_type)
    return bytes(raw)


class CloudPackageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cloud-package-test-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.repo = self.base / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("config", "user.name", "Package Test")
        self.git("config", "user.email", "package-test@example.invalid")
        self.write("LICENSE", "Synthetic project license for unit testing only.\n")
        mapping = dict(PACKAGE.COMMON_FILES)
        for role in PACKAGE.ROLE_FILES.values():
            mapping.update(role)
        for relative in mapping.values():
            self.write("aster-cloud/" + relative, "committed fixture: " + relative + "\n")
        for n in range(1, 11):
            self.write("aster-cloud/migrations/%03d_test.sql" % n, "SELECT %d;\n" % n)
        self.write("aster-cloud/internal/hypervisor/ledger.go", "l.state.Schema != 1 && l.state.Schema != 5\n")
        self.write("aster-cloud/internal/fabric/files.go", "l.state.Schema != 1 && l.state.Schema != 3\n")
        self.write("aster-cloud/internal/nodeproto/contract.go", 'const Protocol = "aster.node/1"\n')
        self.write("contracts/billing/internal/controllers/contract.go", 'const Protocol = "aster.controller/1"\n')
        for name in ("install.py", "provision.py", "release_verify.py"):
            self.write("aster-cloud/deploy/install/" + name, "# committed synthetic " + name + "\n")
        roots = Path(__file__).parents[1] / "install/release-trusted-root.json"
        target = self.repo / "aster-cloud/deploy/install/release-trusted-root.json"
        target.write_bytes(roots.read_bytes())
        self.commit = self.commit_all()
        self.output = self.base / "out"
        self.calls = 0

    def git(self, *arguments):
        return subprocess.run(["git", "-C", str(self.repo), *arguments], check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode().strip()

    def write(self, relative, text):
        target = self.repo / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
        return target

    def commit_all(self):
        self.git("add", ".")
        self.git("commit", "-qm", "fixture")
        return self.git("rev-parse", "HEAD")

    def fake_builder(self, source, built, epoch):
        self.calls += 1
        self.assertGreater(epoch, 0)
        self.assertEqual((source / "LICENSE").read_text(), "Synthetic project license for unit testing only.\n")
        for binary in ("aster-controller", "aster-node", "aster-network"):
            path = built / "bin" / binary
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(test_elf())
        for relative in ("licenses/go/test-LICENSE", "licenses/npm/test/LICENSE"):
            path = built / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("Synthetic dependency license.\n")
        for relative, text in (("index.html", '<!doctype html><script src="/assets/app.js"></script>'),
                               ("assets/app.js", 'console.log("test fixture");')):
            path = source / "aster-cloud/frontend/dist" / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)

    def package(self, output=None, builder=None, version="0.1.0-dev", commit=None):
        return PACKAGE.package_cloud(self.repo, commit or self.commit, output or self.output,
                                     version, build_runner=builder or self.fake_builder)

    def read_archive(self, path):
        with tarfile.open(path, "r:gz") as archive:
            members = archive.getmembers()
            content = {m.name: archive.extractfile(m).read() for m in members}
        return members, content

    def test_exact_role_manifests_and_external_sums(self):
        controller, node, sums = self.package()
        self.assertEqual(self.calls, 1)
        for role, path in (("controller", controller), ("node", node)):
            members, content = self.read_archive(path)
            manifest = json.loads(content.pop("manifest.json"))
            self.assertEqual(manifest["schema"], 1)
            self.assertEqual(manifest["component"], "aster-cloud-" + role)
            self.assertEqual(manifest["version"], "0.1.0-dev")
            self.assertEqual(manifest["source_commit"], self.commit)
            self.assertEqual(manifest["platform"], "linux-amd64")
            self.assertEqual(manifest["release_kind"], "development")
            self.assertEqual(set(content), {f["path"] for f in manifest["files"]})
            self.assertEqual([f["path"] for f in manifest["files"]], sorted(content))
            for entry in manifest["files"]:
                self.assertEqual(entry["sha256"], hashlib.sha256(content[entry["path"]]).hexdigest())
                self.assertEqual(entry["size"], len(content[entry["path"]]))
                self.assertEqual(entry["mode"], "0755" if entry["path"].startswith("bin/") else "0644")
            for member in members:
                self.assertTrue(member.isfile())
                self.assertFalse(member.islnk() or member.issym())
                self.assertEqual((member.uid, member.gid, member.uname, member.gname), (0, 0, "", ""))
                self.assertEqual(member.mode, 0o755 if member.name.startswith("bin/") else 0o644)
            self.assertIn("licenses/PROJECT-LICENSE", content)
            self.assertIn("docs/DEVELOPMENT.txt", content)
            self.assertFalse(any("vps-billing" in name or "node_modules" in name for name in content))
            if role == "controller":
                self.assertEqual(manifest["data_schemas"], {"controller_mysql": 10})
                self.assertIn("bin/aster-controller", content)
                self.assertIn("ui/index.html", content)
                self.assertNotIn("bin/aster-node", content)
            else:
                self.assertEqual(manifest["data_schemas"], {"node_journal": 5, "fabric_journal": 3})
                self.assertIn("bin/aster-node", content)
                self.assertIn("bin/aster-network", content)
                self.assertFalse(any(name.startswith("ui/") or name.startswith("licenses/npm/") for name in content))
        self.assertEqual(sums.read_text(), "".join(hashlib.sha256(p.read_bytes()).hexdigest() + "  " + p.name + "\n" for p in (controller, node)))

    def test_deterministic_across_build_directories(self):
        first = self.package(self.base / "first")
        second = self.package(self.base / "second")
        self.assertEqual([p.read_bytes() for p in first], [p.read_bytes() for p in second])

    def test_new_users_index_schema_is_bound_to_requested_commit(self):
        original = self.commit
        self.write("aster-cloud/migrations/011_console_users_pagination.sql",
                   "CREATE INDEX controller_console_users_created_id ON controller_console_users (created_at,id);\n")
        latest = self.commit_all()
        for commit, schema, output in ((latest, 11, self.output), (original, 10, self.base / "older")):
            controller, node, _ = self.package(commit=commit, output=output)
            _, controller_files = self.read_archive(controller)
            _, node_files = self.read_archive(node)
            manifest = json.loads(controller_files["manifest.json"])
            self.assertEqual(manifest["source_commit"], commit)
            self.assertEqual(manifest["data_schemas"], {"controller_mysql": schema})
            self.assertEqual(json.loads(node_files["manifest.json"])["data_schemas"],
                             {"node_journal": 5, "fabric_journal": 3})

    def test_snapshot_is_requested_commit_not_worktree_head(self):
        self.write("aster-cloud/README.md", "new committed README\n")
        self.commit_all()
        controller, _, _ = self.package()
        _, content = self.read_archive(controller)
        self.assertEqual(content["docs/README.md"], b"committed fixture: README.md\n")

    def test_git_replace_cannot_spoof_requested_sha(self):
        original = self.commit
        self.write("aster-cloud/README.md", "replacement commit contents\n")
        replacement = self.commit_all()
        self.git("replace", original, replacement)
        controller, _, _ = self.package(commit=original)
        _, content = self.read_archive(controller)
        self.assertEqual(content["docs/README.md"], b"committed fixture: README.md\n")

    def test_tracked_dirty_source_refused_before_build(self):
        self.write("aster-cloud/README.md", "uncommitted\n")
        with self.assertRaisesRegex(PACKAGE.PackageError, "not clean"):
            self.package()
        self.assertEqual(self.calls, 0)
        self.assertFalse(self.output.exists())

    def test_untracked_source_refused_before_build(self):
        self.write("untracked.py", "uncommitted\n")
        with self.assertRaisesRegex(PACKAGE.PackageError, "not clean"):
            self.package()

    def test_staged_source_refused(self):
        self.write("aster-cloud/README.md", "staged\n")
        self.git("add", ".")
        with self.assertRaisesRegex(PACKAGE.PackageError, "not clean"):
            self.package()

    def test_stable_or_unsafe_versions_refused(self):
        for version in ("0.1.0", "v0.1.0-dev", "../0.1.0-dev", "0.1.0-dev/evil", "0.1.0-dev\n", "0.1.0-rc.2", "1.2.3-dev", "0.1.0-dev.custom"):
            with self.subTest(version=version), self.assertRaises(PACKAGE.PackageError):
                self.package(version=version)

    def test_only_first_official_prerelease_has_release_identity_without_stable_claim(self):
        paths = self.package(version="0.1.0-rc.1")
        for role, path in zip(("controller", "node"), paths[:2]):
            _, content = self.read_archive(path)
            manifest = json.loads(content["manifest.json"])
            self.assertEqual(manifest["release_kind"], "release")
            self.assertEqual(manifest["channel"], "prerelease")
            self.assertEqual(manifest["release_tag"], "cloud-v0.1.0-rc.1")
            self.assertEqual(manifest["version"], "0.1.0-rc.1")
            self.assertEqual(manifest["source_commit"], self.commit)
            self.assertEqual(manifest["component"], "aster-cloud-" + role)
            self.assertIn(b"Not production-ready", content["docs/DEVELOPMENT.txt"])
        names = {p.name for p in paths}
        self.assertIn("aster-cloud-installer-0.1.0-rc.1.tar.gz", names)
        self.assertIn("aster-cloud-bootstrap-0.1.0-rc.1.py", names)
        self.assertIn("release-trusted-root.json", names)
        self.assertIn("release-manifest.json", names)
        self.assertIn("provenance.json", names)
        self.assertEqual(len(paths), 8)
        manifest = json.loads((self.output / "release-manifest.json").read_bytes())
        self.assertNotIn("release_id", manifest)
        self.assertEqual(manifest["tag"], "cloud-v0.1.0-rc.1")
        self.assertEqual(manifest["repository_id"], 1418618420)
        for entry in manifest["assets"]:
            raw = (self.output / entry["name"]).read_bytes()
            self.assertEqual(entry["size"], len(raw))
            self.assertEqual(entry["sha256"], hashlib.sha256(raw).hexdigest())

    def test_official_prerelease_is_reproducible_across_private_build_directories(self):
        first = self.package(self.base / "first-rc", version="0.1.0-rc.1")
        second = self.package(self.base / "second-rc", version="0.1.0-rc.1")
        self.assertEqual([p.read_bytes() for p in first], [p.read_bytes() for p in second])

    def test_short_uppercase_or_missing_commit_refused(self):
        for commit in (self.commit[:7], self.commit.upper(), "f" * 40):
            with self.subTest(commit=commit), self.assertRaises(PACKAGE.PackageError):
                self.package(commit=commit)

    def test_nested_source_root_refused(self):
        with self.assertRaisesRegex(PACKAGE.PackageError, "monorepo git root"):
            PACKAGE.package_cloud(self.repo / "aster-cloud", self.commit, self.output,
                                  build_runner=self.fake_builder)

    def test_output_no_overwrite(self):
        paths = self.package()
        before = [p.read_bytes() for p in paths]
        with self.assertRaisesRegex(PACKAGE.PackageError, "overwrite"):
            self.package()
        self.assertEqual(before, [p.read_bytes() for p in paths])

    def test_output_symlink_refused(self):
        elsewhere = self.base / "elsewhere"
        elsewhere.mkdir()
        self.output.symlink_to(elsewhere, target_is_directory=True)
        with self.assertRaisesRegex(PACKAGE.PackageError, "symlink"):
            self.package()

    def test_build_failure_publishes_nothing(self):
        def failed(*_):
            raise PACKAGE.PackageError("test build failure")
        with self.assertRaisesRegex(PACKAGE.PackageError, "test build failure"):
            self.package(builder=failed)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_committed_symlink_source_refused(self):
        (self.repo / "link").symlink_to("LICENSE")
        self.commit = self.commit_all()
        with self.assertRaisesRegex(PACKAGE.PackageError, "links"):
            self.package()
        self.assertEqual(self.calls, 0)

    def test_bad_or_dynamic_binary_refused(self):
        for raw in (b"#!/bin/sh\nexit 0\n", test_elf(2), test_elf(3)):
            def builder(source, built, epoch):
                self.fake_builder(source, built, epoch)
                (built / "bin/aster-node").write_bytes(raw)
            with self.subTest(raw=raw[:8]), self.assertRaises(PACKAGE.PackageError):
                self.package(builder=builder)
            self.assertEqual(list(self.output.iterdir()), [])

    def test_ui_symlink_file_directory_and_hardlink_refused(self):
        for kind in ("file", "directory", "hardlink"):
            def builder(source, built, epoch):
                self.fake_builder(source, built, epoch)
                ui = source / "aster-cloud/frontend/dist"
                if kind == "file":
                    (ui / "unsafe.txt").symlink_to(ui / "index.html")
                elif kind == "directory":
                    (ui / "unsafe").symlink_to(ui / "assets", target_is_directory=True)
                else:
                    os.link(ui / "index.html", ui / "unsafe.txt")
            with self.subTest(kind=kind), self.assertRaises(PACKAGE.PackageError):
                self.package(builder=builder)

    def test_missing_ui_refused(self):
        def builder(source, built, epoch):
            self.fake_builder(source, built, epoch)
            (source / "aster-cloud/frontend/dist/index.html").unlink()
        with self.assertRaisesRegex(PACKAGE.PackageError, "UI"):
            self.package(builder=builder)

    def test_special_file_refused_without_opening(self):
        fifo = self.base / "pipe"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(PACKAGE.PackageError, "nonregular"):
            PACKAGE.read_regular(fifo)

    def test_unsafe_or_duplicate_paths_refused(self):
        for path in ("../file", "/file", "bin/../file", "bin//file", "./bin/file", "bin\\file", "bin/a\n", "", "bin/"):
            with self.subTest(path=path), self.assertRaises(PACKAGE.PackageError):
                PACKAGE.canonical_path(path)
        files = {}
        PACKAGE.add_file(files, "docs/test.txt", b"test")
        with self.assertRaisesRegex(PACKAGE.PackageError, "duplicate"):
            PACKAGE.add_file(files, "docs/test.txt", b"different")
        with self.assertRaisesRegex(PACKAGE.PackageError, "prefix"):
            PACKAGE.add_file(files, "secrets/token", b"secret")

    def test_noncontiguous_schema_refused_before_build(self):
        (self.repo / "aster-cloud/migrations/005_test.sql").unlink()
        self.commit = self.commit_all()
        with self.assertRaisesRegex(PACKAGE.PackageError, "noncontiguous"):
            self.package()
        self.assertEqual(self.calls, 0)

    def test_protocol_metadata_required(self):
        self.write("aster-cloud/internal/nodeproto/contract.go", "// missing protocol\n")
        self.commit = self.commit_all()
        with self.assertRaisesRegex(PACKAGE.PackageError, "protocol"):
            self.package()

    def test_bounded_elf_program_headers(self):
        for offset, count in ((0, 1), (10000, 1), (64, 0), (64, 65535)):
            raw = bytearray(test_elf())
            struct.pack_into("<Q", raw, 32, offset)
            struct.pack_into("<H", raw, 56, count)
            with self.subTest(offset=offset, count=count), self.assertRaises(PACKAGE.PackageError):
                PACKAGE.validate_static_amd64(raw)

    def test_production_builder_pins_flags_and_licenses_only_linked_modules(self):
        toolchain = self.base / "test-toolchain"
        dependency = self.base / "test-linked-dependency"
        for directory in (toolchain, dependency):
            directory.mkdir()
            (directory / "LICENSE").write_text("Synthetic license.\n")
        built = self.base / "built"
        built.mkdir()
        commands = []

        def fake_run(command, cwd, env):
            commands.append(command)
            self.assertNotIn("VITE_TEST_SECRET", env)
            self.assertEqual(env["GOFLAGS"], "")
            self.assertEqual(env["GOEXPERIMENT"], "")
            self.assertEqual(env["GOAMD64"], "v1")
            if command == ["go", "version"]:
                return ("go version " + PACKAGE.GO_TOOLCHAIN + " test/fixture\n").encode()
            if command == ["node", "--version"]:
                return (PACKAGE.NODE_VERSION + "\n").encode()
            if command[:2] == ["go", "build"]:
                Path(command[command.index("-o") + 1]).write_bytes(test_elf())
                return b""
            if command[:2] == ["npm", "ci"]:
                self.assertIn("--ignore-scripts", command)
                self.assertIn("--include=dev", command)
                path = cwd / "node_modules/test/LICENSE"
                path.parent.mkdir(parents=True)
                path.write_text("Synthetic npm license.\n")
                return b""
            if command == ["npm", "run", "build"]:
                self.assertEqual(env["NODE_ENV"], "production")
                path = cwd / "dist/index.html"
                path.parent.mkdir()
                path.write_text("Synthetic UI.\n")
                return b""
            if command == ["go", "env", "GOROOT"]:
                return (str(toolchain) + "\n").encode()
            if command[:2] == ["go", "list"]:
                self.assertIn("-deps", command)
                self.assertNotIn("-m", command)
                values = [{"Standard": True}, {"Module": {"Path": "aster/cloud", "Main": True}},
                          {"Module": {"Path": "aster/billing", "Replace": {"Dir": "unused"}}},
                          {"Module": {"Path": "example.invalid/linked", "Version": "v1.0.0", "Dir": str(dependency)}}]
                return "\n".join(json.dumps(value) for value in values).encode()
            self.fail("unexpected build command: " + repr(command))

        with mock.patch.dict(os.environ, {"VITE_TEST_SECRET": "must not embed", "GOFLAGS": "bad", "GOEXPERIMENT": "bad"}), \
                mock.patch.object(PACKAGE, "run", side_effect=fake_run):
            PACKAGE.build_artifacts(self.repo, built, 1)
        self.assertEqual(len([c for c in commands if c[:2] == ["go", "build"]]), 3)
        self.assertTrue((built / "licenses/go/example.invalid/linked@v1.0.0/LICENSE").is_file())


if __name__ == "__main__":
    unittest.main()

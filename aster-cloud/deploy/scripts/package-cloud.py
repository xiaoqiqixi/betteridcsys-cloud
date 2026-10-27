#!/usr/bin/env python3
"""Build deterministic cloud development or first-RC bundles. Never installs/publishes them."""

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile


GO_TOOLCHAIN = "go1.27.3"
NODE_VERSION = "v24.19.0"
VERSION_RE = re.compile(r"0\.[0-9]+\.[0-9]+-dev(?:\.[0-9]+)?\Z")
RC_VERSION = "0.1.0-rc.1"
REPOSITORY = "xiaoqiqixi/betteridcsys"
REPOSITORY_ID = 1418618420
OWNER_ID = 123864154
RC_ROOT_SHA256 = "65ca537f6ed8a47fd0e560c421baa1f6c1efb8b25fc200d8c5c02c0e92eb2b9c"
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
MAX_FILE_BYTES = 128 * 1024 * 1024
ROLE_FILES = {
    "controller": {
        "templates/controller-aster.service": "deploy/controller-aster.service",
        "templates/controller-heartbeat@.service": "deploy/controller-heartbeat@.service",
        "templates/controller-heartbeat@.timer": "deploy/controller-heartbeat@.timer",
        "templates/host-management/controller-migration.py": "deploy/install/controller-migration.py",
        "templates/host-management/install.py": "deploy/install/install.py",
        "templates/host-management/provision.py": "deploy/install/provision.py",
        "docs/CONTROLLER_MIGRATION.md": "docs/CONTROLLER_MIGRATION.md",
        "templates/controller-ovs.example.json": "deploy/controller-ovs.example.json",
        "docs/CONTROLLER_OPERATIONS.md": "deploy/controller-OPERATIONS.md",
        "docs/CONSOLE_API.md": "docs/CONSOLE_API.md",
    },
    "node": {
        "templates/node-aster-node.service": "deploy/node-aster-node.service",
        "templates/node-config.example.json": "deploy/node-config.example.json",
        "templates/node-static-ipv4-filter.example.xml": "deploy/node-static-ipv4-filter.example.xml",
        "templates/fabric-private.example.json": "deploy/fabric-private.example.json",
        "templates/node-ovs.conf.example": "deploy/node-ovs.conf.example",
        "templates/node-ovs.example.json": "deploy/node-ovs.example.json",
        "templates/overlay-private.example.json": "deploy/overlay-private.example.json",
        "docs/NODE_README.md": "NODE_README.md",
        "docs/FABRIC.md": "internal/fabric/README.md",
        "docs/FABRIC_RECOVERY.md": "internal/fabric/RECOVERY.md",
        "docs/FABRIC_NAT.md": "internal/fabric/NAT.md",
    },
}
COMMON_FILES = {
    "docs/THIRD_PARTY_GO_NOTICES.md": "docs/THIRD_PARTY_GO_NOTICES.md",
    "docs/README.md": "README.md",
    "docs/ARCHITECTURE.md": "docs/ARCHITECTURE.md",
    "docs/LOGGING.md": "docs/LOGGING.md",
    "docs/OVERLAY_OPERATIONS.md": "deploy/OVERLAY_OPERATIONS.md",
    "templates/journald-aster-cloud.conf.example": "deploy/journald-aster-cloud.conf.example",
}


class PackageError(Exception):
    pass


def canonical_path(name):
    """Reject tar aliases rather than normalizing potentially hostile names."""
    if not isinstance(name, str) or not name or "\\" in name:
        raise PackageError("invalid archive path")
    if any(ord(c) < 32 or ord(c) == 127 for c in name):
        raise PackageError("control character in archive path")
    path = PurePosixPath(name)
    if path.is_absolute() or path.as_posix() != name or any(
        part in ("", ".", "..") for part in name.split("/")
    ):
        raise PackageError("noncanonical archive path")
    return path


def read_regular(path):
    """Pack only bounded single-link regular files, never symlinks or devices."""
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > MAX_FILE_BYTES:
        raise PackageError("nonregular, linked, or oversized input: " + str(path))
    # Every ancestor within the source/build tree is checked during extraction
    # or walking. O_NOFOLLOW also closes the final-component symlink race.
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as source:
        actual = os.fstat(source.fileno())
        if (actual.st_dev, actual.st_ino) != (st.st_dev, st.st_ino):
            raise PackageError("input changed while opening")
        raw = source.read(MAX_FILE_BYTES + 1)
        if len(raw) != st.st_size or len(raw) > MAX_FILE_BYTES:
            raise PackageError("input changed or exceeds size limit")
    return raw


def git(root, *args):
    try:
        return subprocess.run(
            ["git", "--no-replace-objects", "-C", str(root), *args], check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ).stdout
    except subprocess.CalledProcessError as error:
        raise PackageError("git source verification failed") from error


def verify_source(root, commit):
    if not COMMIT_RE.fullmatch(commit):
        raise PackageError("--source-commit must be exactly 40 lowercase hex characters")
    top = Path(os.fsdecode(git(root, "rev-parse", "--show-toplevel")).strip()).resolve()
    if top != root.resolve():
        raise PackageError("--source-root must be the monorepo git root")
    if git(root, "rev-parse", "--verify", commit + "^{commit}").decode().strip() != commit:
        raise PackageError("requested source is not the exact commit")
    # Ignored caches/artifacts are not sources. All tracked edits and untracked
    # nonignored files are refused; there is deliberately no --allow-dirty flag.
    if git(root, "status", "--porcelain=v1", "--untracked-files=all", "-z"):
        raise PackageError("source tree is not clean; commit or remove uncommitted files first")
    epoch = int(git(root, "show", "-s", "--format=%ct", commit).decode().strip())
    if epoch < 0 or epoch > 0xFFFFFFFF:
        raise PackageError("source timestamp cannot be represented by gzip")
    return epoch


def snapshot_source(root, commit, destination):
    """Use Git objects, not the worktree, including the public contract source."""
    raw = git(root, "archive", "--format=tar", commit)
    seen = set()
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        for member in archive:
            name = member.name.rstrip("/") if member.isdir() else member.name
            relative = canonical_path(name)
            if name in seen or not (member.isdir() or member.isfile()):
                raise PackageError("source archive contains duplicates, links, or special files")
            seen.add(name)
            target = destination.joinpath(*relative.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if member.size > MAX_FILE_BYTES:
                raise PackageError("source file too large")
            target.parent.mkdir(parents=True, exist_ok=True)
            data = archive.extractfile(member)
            if data is None:
                raise PackageError("source archive member is unreadable")
            with target.open("xb") as output:
                output.write(data.read(MAX_FILE_BYTES + 1))
            target.chmod(0o755 if member.mode & 0o111 else 0o644)


def run(command, cwd, env):
    try:
        return subprocess.run(
            command, cwd=str(cwd), env=env, check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        # Avoid forwarding arbitrary build output, URLs, environment or secrets.
        raise PackageError("build command failed: " + " ".join(command[:3])) from error


def json_stream(raw):
    text = raw.decode("utf-8")
    decoder = json.JSONDecoder()
    while text.strip():
        text = text.lstrip()
        value, end = decoder.raw_decode(text)
        yield value
        text = text[end:]


def license_files(directory):
    return sorted(
        p for p in directory.iterdir()
        if re.match(r"^(LICENSE|LICENCE|COPYING|NOTICE|COPYRIGHT)(?:[._-].*)?$", p.name, re.I)
        and not p.is_dir()
    )


def copy_license(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(read_regular(source))
    destination.chmod(0o644)


def build_artifacts(source, built, epoch):
    """The only production builder: compile real source, no fixture binary path."""
    cloud = source / "aster-cloud"
    # Ambient Go flags/experiments or VITE_* values must not silently change a
    # reviewed binary/UI or embed a caller's environment into a candidate.
    inherited = {key: value for key, value in os.environ.items() if not key.startswith("VITE_")}
    env = dict(inherited, GOTOOLCHAIN=GO_TOOLCHAIN, GOWORK="off", CGO_ENABLED="0",
               GOOS="linux", GOARCH="amd64", GOAMD64="v1", GOENV="off", GOFLAGS="", GOEXPERIMENT="",
               SOURCE_DATE_EPOCH=str(epoch), TZ="UTC", NODE_ENV="development", CI="true",
               LC_ALL="C", npm_config_audit="false", npm_config_fund="false",
               GOCACHE=os.environ.get("GOCACHE", str(built / ".go-cache")))
    if not run(["go", "version"], cloud, env).decode().startswith("go version " + GO_TOOLCHAIN + " "):
        raise PackageError("unexpected Go toolchain")
    if run(["node", "--version"], cloud, env).decode().strip() != NODE_VERSION:
        raise PackageError("Node " + NODE_VERSION + " is required for the reviewed UI build")
    (built / "bin").mkdir(parents=True)
    for binary in ("aster-controller", "aster-node", "aster-network"):
        run(["go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false",
             "-ldflags=-buildid=", "-o", str(built / "bin" / binary), "./cmd/" + binary], cloud, env)
    frontend = cloud / "frontend"
    run(["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund", "--include=dev"], frontend, env)
    run(["npm", "run", "build"], frontend, dict(env, NODE_ENV="production"))

    goroot = Path(os.fsdecode(run(["go", "env", "GOROOT"], cloud, env)).strip())
    copy_license(goroot / "LICENSE", built / "licenses" / "go" / "stdlib-LICENSE")
    # -m all includes unrelated dependencies of the adjacent financial module.
    # Inspect only the actual package closure linked into our three binaries.
    packages = json_stream(run(["go", "list", "-mod=readonly", "-deps", "-json",
                                "./cmd/aster-controller", "./cmd/aster-node", "./cmd/aster-network"], cloud, env))
    modules = {}
    for package in packages:
        module = package.get("Module")
        if module:
            modules[module["Path"]] = module
    for module in modules.values():
        if module.get("Main") or module.get("Replace"):
            # The reviewed local billing public-contract source is covered by
            # the monorepo PROJECT-LICENSE, not by any billing release asset.
            continue
        directory = Path(module.get("Dir", ""))
        candidates = license_files(directory) if module.get("Dir") else []
        if not candidates:
            raise PackageError("dependency license not found: " + module["Path"])
        prefix = built / "licenses" / "go" / (module["Path"] + "@" + module["Version"])
        for candidate in candidates:
            copy_license(candidate, prefix / candidate.name)
    # Keep dependency notices, never node_modules code or executable scripts.
    npm_count = 0
    for directory, subdirs, _ in os.walk(str(frontend / "node_modules"), followlinks=False):
        subdirs[:] = sorted(d for d in subdirs if not (Path(directory) / d).is_symlink())
        base = Path(directory)
        for candidate in license_files(base):
            relative = candidate.relative_to(frontend / "node_modules")
            copy_license(candidate, built / "licenses" / "npm" / relative)
            npm_count += 1
    if not npm_count:
        raise PackageError("frontend dependency licenses are missing")


def validate_static_amd64(raw):
    if len(raw) < 64 or raw[:7] != b"\x7fELF\x02\x01\x01":
        raise PackageError("binary is not little-endian ELF64")
    if struct.unpack_from("<HHI", raw, 16) != (2, 62, 1):
        raise PackageError("binary is not a Linux amd64 static executable")
    offset = struct.unpack_from("<Q", raw, 32)[0]
    entry_size, count = struct.unpack_from("<HH", raw, 54)
    if not count or entry_size != 56 or offset < 64 or offset + entry_size * count > len(raw):
        raise PackageError("invalid ELF program headers")
    if any(struct.unpack_from("<I", raw, offset + entry_size * n)[0] in (2, 3) for n in range(count)):
        raise PackageError("dynamic/interpreted binary refused")


def add_file(files, name, raw, mode="0644"):
    path = canonical_path(name)
    if path.parts[0] not in ("bin", "ui", "templates", "licenses", "docs"):
        raise PackageError("unexpected package file prefix")
    if name in files or len(raw) > MAX_FILE_BYTES or mode not in ("0644", "0755"):
        raise PackageError("duplicate/oversized file or invalid mode")
    files[name] = (raw, mode)


def add_tree(files, directory, prefix):
    if directory.is_symlink() or not directory.is_dir():
        raise PackageError("required directory missing or linked: " + str(directory))
    for base, directories, names in os.walk(str(directory), followlinks=False):
        for name in directories:
            if (Path(base) / name).is_symlink():
                raise PackageError("symlink directory in build output")
        for name in names:
            path = Path(base) / name
            relative = path.relative_to(directory).as_posix()
            add_file(files, prefix + "/" + relative, read_regular(path))


def source_metadata(source):
    cloud = source / "aster-cloud"
    migrations = sorted(int(p.name.split("_", 1)[0]) for p in (cloud / "migrations").glob("[0-9]*_*.sql"))
    if not migrations or migrations != list(range(1, max(migrations) + 1)):
        raise PackageError("noncontiguous or missing controller migrations")
    schemas = {}
    for key, relative in (("node_journal", "internal/hypervisor/ledger.go"),
                          ("fabric_journal", "internal/fabric/files.go")):
        raw = (cloud / relative).read_text()
        versions = re.findall(r"l\.state\.Schema\s*!=\s*([0-9]+)", raw)
        if not versions:
            raise PackageError("cannot identify supported " + key)
        schemas[key] = max(map(int, versions))
    protocols = set()
    for base in (cloud / "internal", source / "contracts/billing/internal/controllers"):
        for path in base.rglob("*.go"):
            if path.name.endswith("_test.go"):
                continue
            protocols.update(re.findall(r'^\s*(?:const\s+)?\w*Protocol\s*=\s*"(aster\.[^"]+)"', path.read_text(), re.M))
    if "aster.controller/1" not in protocols or "aster.node/1" not in protocols:
        raise PackageError("required protocol declarations not found")
    return migrations[-1], schemas, sorted(protocols)


def role_files(source, built, role, *, prerelease=False):
    files = {}
    cloud = source / "aster-cloud"
    for name, relative in dict(COMMON_FILES, **ROLE_FILES[role]).items():
        add_file(files, name, read_regular(cloud / relative))
    add_file(files, "licenses/PROJECT-LICENSE", read_regular(source / "LICENSE"))
    for binary in (("aster-controller",) if role == "controller" else ("aster-node", "aster-network")):
        raw = read_regular(built / "bin" / binary)
        validate_static_amd64(raw)
        add_file(files, "bin/" + binary, raw, "0755")
    add_tree(files, built / "licenses/go", "licenses/go")
    if role == "controller":
        ui = cloud / "frontend/dist"
        if not (ui / "index.html").is_file():
            raise PackageError("real compiled UI index.html is missing")
        add_tree(files, ui, "ui")
        add_tree(files, built / "licenses/npm", "licenses/npm")
    warning = (
        ("UNPUBLISHED OFFICIAL PRERELEASE CANDIDATE\nNot production-ready.\n" if prerelease else "DEVELOPMENT CANDIDATE ONLY\n") +
        "Packaging is not publication, installer acceptance, KVM/guest/network acceptance, or production readiness.\n"
        "No billing release assets, credentials, databases, VM images or journals are included.\n"
        "Templates require root review. Never install example approvals as active policy.\n"
        "Install/upgrade must retain uncertain operations and consistent database/journal backups.\n"
    ).encode()
    add_file(files, "docs/DEVELOPMENT.txt", warning)
    return files


def write_archive(path, files, manifest, epoch):
    raw_manifest = (json.dumps(manifest, sort_keys=True, ensure_ascii=True, indent=2) + "\n").encode()
    members = [("manifest.json", raw_manifest, "0644")]
    members.extend((name, *files[name]) for name in sorted(files))
    with path.open("xb") as output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=epoch, compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
                for name, raw, mode in members:
                    item = tarfile.TarInfo(name)
                    item.size, item.mode, item.mtime = len(raw), int(mode, 8), epoch
                    item.uid = item.gid = 0
                    item.uname = item.gname = ""
                    item.type = tarfile.REGTYPE
                    archive.addfile(item, io.BytesIO(raw))


def rc_files(source, scratch, source_commit, epoch):
    """Package every adjacent Python import before any remote execution."""
    directory = source / "aster-cloud/deploy/install"
    files = {name: (read_regular(directory / name), "0644")
             for name in ("install.py", "provision.py", "release_verify.py")}
    manifest = {"schema": 1, "component": "aster-cloud-installer", "version": RC_VERSION,
                "release_kind": "release", "channel": "prerelease", "release_tag": "cloud-v" + RC_VERSION,
                "source_commit": source_commit,
                "files": [{"path": name, "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw), "mode": mode}
                          for name, (raw, mode) in sorted(files.items())]}
    capsule = "aster-cloud-installer-" + RC_VERSION + ".tar.gz"
    write_archive(scratch / capsule, files, manifest, epoch)
    bootstrap = "aster-cloud-bootstrap-" + RC_VERSION + ".py"
    (scratch / bootstrap).write_bytes(files["release_verify.py"][0])
    roots = read_regular(directory / "release-trusted-root.json")
    if hashlib.sha256(roots).hexdigest() != RC_ROOT_SHA256:
        raise PackageError("official trusted-root snapshot differs from the reviewed pin")
    (scratch / "release-trusted-root.json").write_bytes(roots)
    provenance = {"schema": 1, "repository": REPOSITORY, "repository_id": REPOSITORY_ID,
                  "tag": "cloud-v" + RC_VERSION, "version": RC_VERSION, "source_commit": source_commit,
                  "source_date_epoch": epoch, "toolchains": {"go": GO_TOOLCHAIN, "node": NODE_VERSION},
                  "scope": "independent-cloud-only", "production_ready": False, "real_kvm_accepted": False}
    (scratch / "provenance.json").write_text(json.dumps(provenance, sort_keys=True, indent=2) + "\n")
    return [capsule, bootstrap, "release-trusted-root.json", "provenance.json"]


def package_cloud(source_root, source_commit, output, version="0.1.0-dev", *, build_runner=build_artifacts):
    """The builder injection is Python-test-only; the CLI has no fixture option."""
    prerelease = version == RC_VERSION
    if not prerelease and not VERSION_RE.fullmatch(version):
        raise PackageError("only development versions or the first 0.1.0-rc.1 prerelease are supported")
    root, output = Path(source_root).resolve(), Path(output).absolute()
    epoch = verify_source(root, source_commit)
    if output.is_symlink():
        raise PackageError("output may not be a symlink")
    output.mkdir(parents=True, exist_ok=True)
    role_names = ["aster-cloud-" + role + "-" + version + "-linux-amd64.tar.gz" for role in ROLE_FILES]
    extra_names = (["aster-cloud-installer-" + version + ".tar.gz", "aster-cloud-bootstrap-" + version + ".py",
                    "release-trusted-root.json", "provenance.json", "release-manifest.json"] if prerelease else [])
    names = role_names + extra_names + ["SHA256SUMS"]
    if any((output / name).exists() or (output / name).is_symlink() for name in names):
        raise PackageError("refusing to overwrite package output")
    with tempfile.TemporaryDirectory(prefix=".cloud-package-", dir=str(output)) as temporary:
        scratch = Path(temporary)
        source, built = scratch / "source", scratch / "built"
        source.mkdir()
        built.mkdir()
        snapshot_source(root, source_commit, source)
        db_schema, journal_schemas, protocols = source_metadata(source)
        build_runner(source, built, epoch)
        for role, name in zip(ROLE_FILES, role_names):
            files = role_files(source, built, role, prerelease=prerelease)
            manifest = {
                "schema": 1, "component": "aster-cloud-" + role, "role": role,
                "version": version, "source_commit": source_commit, "platform": "linux-amd64",
                "release_kind": "release" if prerelease else "development", "protocols": protocols,
                "data_schemas": {"controller_mysql": db_schema} if role == "controller" else journal_schemas,
                "build": {"go_toolchain": GO_TOOLCHAIN, **({"node": NODE_VERSION.lstrip("v")} if role == "controller" else {})},
                "files": [{"path": name, "sha256": hashlib.sha256(raw).hexdigest(),
                           "size": len(raw), "mode": mode} for name, (raw, mode) in sorted(files.items())],
            }
            if prerelease:
                manifest.update(channel="prerelease", release_tag="cloud-v" + version)
            write_archive(scratch / name, files, manifest, epoch)
        payloads = role_names + (rc_files(source, scratch, source_commit, epoch) if prerelease else [])
        sums = "".join(hashlib.sha256(read_regular(scratch / name)).hexdigest() + "  " + name + "\n" for name in sorted(payloads))
        (scratch / "SHA256SUMS").write_text(sums)
        if prerelease:
            manifest = {"schema": 1, "repository": REPOSITORY, "repository_id": REPOSITORY_ID, "owner_id": OWNER_ID,
                        "version": version, "tag": "cloud-v" + version, "source_commit": source_commit,
                        "source_ref": "refs/heads/main", "channel": "prerelease", "workflow": ".github/workflows/cloud-release-build.yml",
                        "acceptance": {"production_ready": False, "real_kvm_accepted": False},
                        "assets": [{"name": name, "sha256": hashlib.sha256(read_regular(scratch / name)).hexdigest(),
                                    "size": (scratch / name).stat().st_size} for name in sorted(payloads + ["SHA256SUMS"])]}
            (scratch / "release-manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
        # Build/validation failures publish no tarballs. Never replace an older
        # candidate. All artifacts originate from this owned private scratch.
        for name in names:
            os.link(str(scratch / name), str(output / name))
            (output / name).chmod(0o644)
    return [output / name for name in names]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--version", default="0.1.0-dev")
    args = parser.parse_args(argv)
    try:
        paths = package_cloud(args.source_root, args.source_commit, args.output, args.version)
    except (PackageError, OSError, ValueError, tarfile.TarError) as error:
        print("cloud package refused: " + str(error), file=sys.stderr)
        return 1
    print("UNPUBLISHED PRERELEASE CANDIDATES; packaging establishes no publisher identity or native acceptance."
          if args.version == RC_VERSION else "DEVELOPMENT CANDIDATES ONLY; no installation or KVM acceptance performed.")
    for path in paths:
        print(path.resolve())
    return 0


if __name__ == "__main__":
    sys.exit(main())

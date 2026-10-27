#!/usr/bin/env python3
"""Trusted-main policy for the independent, first Cloud prerelease only.

Candidates are bounded data: never import/execute their Python or binaries in a
privileged attester/publisher. No financial tag, asset, latest setting or release
is changed, and no uncertain mutation is retried or adopted.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

sys.dont_write_bytecode = True
CLOUD = Path(__file__).resolve().parents[2]
ROOT = CLOUD.parent
BUILD_PATH = ".github/workflows/cloud-release-build.yml"
PUBLISH_PATH = ".github/workflows/cloud-release-publish.yml"
MAX_JSON = 4 * 1024 * 1024
MAX_ZIP = 128 * 1024 * 1024


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


V = load("cloud_release_trusted_verifier", CLOUD / "deploy/install/release_verify.py")
I = load("cloud_release_trusted_installer", CLOUD / "deploy/install/install.py")
P = load("cloud_release_trusted_packager", CLOUD / "deploy/scripts/package-cloud.py")
CLOUD_JOBS = {
    *("Linux unit and build (" + os_name + ")" for os_name in ("ubuntu-22.04", "ubuntu-24.04")),
    *("Native libvirt preparation (ubuntu-" + version + ")" for version in ("22.04", "24.04")),
    *("Native OVS parser and encoder (" + os_name + ")" for os_name in ("ubuntu-22.04", "ubuntu-24.04")),
    *("Native NAT packet flow and revocation (" + os_name + ")" for os_name in ("ubuntu-22.04", "ubuntu-24.04")),
    "Vue management console checks", "Independent controller MySQL acceptance",
    "Real MySQL network management browser acceptance",
}
FINANCE_JOBS = {
    "checks", "go-vulnerability", "official-release-metadata",
    "Native financial acceptance (ubuntu-22.04)",
    "Real MySQL financial browser acceptance",
}


class PolicyError(Exception):
    pass


class APIError(PolicyError):
    def __init__(self, status):
        self.status = status
        super().__init__("Official API request refused (status " + str(status) + ")")


def require(condition, message):
    if not condition:
        raise PolicyError(message)


def positive(value):
    require(type(value) is int and value > 0, "Positive exact integer required")
    return value


def api_path(suffix=""):
    return "/repos/" + V.REPOSITORY + suffix


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


class GitHub:
    def __init__(self, token):
        require(isinstance(token, str) and token and not any(c.isspace() for c in token), "CI-scoped API token required")
        self.token, self.created = token, set()
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), V.NoRedirect(), urllib.request.HTTPSHandler(context=context))

    def open(self, method, url, raw=None, *, anonymous=False, limit=MAX_JSON):
        parsed = urllib.parse.urlsplit(url)
        require(parsed.scheme == "https" and not parsed.username and not parsed.password and not parsed.fragment and
                parsed.port in (None, 443), "Unsafe official API URL")
        host = parsed.hostname or ""
        if anonymous:
            require(host.endswith(".blob.core.windows.net") or host.endswith(".actions.githubusercontent.com"), "Unrecognized artifact storage redirect")
            require(method == "GET", "Anonymous artifact access is GET-only")
        else:
            require(host in {"api.github.com", "uploads.github.com"}, "Credential-bearing redirect refused")
        headers = {"User-Agent": "aster-cloud-first-rc-policy", "Accept": "application/vnd.github+json",
                   "Accept-Encoding": "identity", "X-GitHub-Api-Version": "2022-11-28"}
        if not anonymous:
            headers["Authorization"] = "Bearer " + self.token
        if raw is not None:
            headers["Content-Type"] = "application/octet-stream" if host == "uploads.github.com" else "application/json"
        try:
            request = urllib.request.Request(url, headers=headers, data=raw, method=method)
            with self.opener.open(request, timeout=30) as response:
                require(response.geturl() == url and response.headers.get("Content-Encoding", "identity") == "identity", "Unexpected API response redirect/encoding")
                chunks, size, deadline = [], 0, time.monotonic() + 120
                while True:
                    require(time.monotonic() < deadline, "Bounded API transfer timed out")
                    chunk = response.read(min(65536, limit + 1 - size))
                    if not chunk:
                        break
                    size += len(chunk)
                    require(size <= limit, "Official API response exceeds bound")
                    chunks.append(chunk)
                return response.status, response.headers, b"".join(chunks)
        except urllib.error.HTTPError as error:
            if error.code in (301, 302, 303, 307, 308):
                return error.code, error.headers, b""
            raise APIError(error.code) from None
        except (OSError, urllib.error.URLError):
            raise PolicyError("Official API outcome uncertain; no mutation retried") from None

    def request(self, method, suffix, value=None):
        require((suffix == "" or suffix.startswith("/")) and not suffix.startswith("//") and "#" not in suffix and not any(c.isspace() for c in suffix), "Unsafe API route")
        require(method in {"GET", "POST", "PATCH"}, "Unsupported API operation")
        if method == "POST":
            require(suffix == "/releases" and isinstance(value, dict) and set(value) == {"tag_name", "target_commitish", "name", "body", "draft", "prerelease", "make_latest"} and
                    isinstance(value.get("target_commitish"), str) and V.COMMIT.fullmatch(value["target_commitish"]) and value.get("tag_name") == V.TAG and
                    value.get("draft") is True and value.get("prerelease") is True and value.get("make_latest") == "false", "Only a new Cloud prerelease draft may be created")
        if method == "PATCH":
            match = re.fullmatch(r"/releases/([1-9][0-9]*)", suffix)
            require(match is not None and int(match[1]) in self.created and
                    value == {"draft": False, "prerelease": True, "make_latest": "false"}, "Only this process's new Cloud draft may be published")
        status, _, raw = self.open(method, "https://api.github.com" + api_path(suffix), json_bytes(value) if value is not None else None)
        require(status == (201 if method == "POST" else 200), "Official API status mismatch")
        result = V.strict_json(raw)
        if method == "POST":
            self.created.add(positive(result.get("id")))
        return result

    def download(self, artifact):
        status, headers, raw = self.open("GET", "https://api.github.com" + api_path("/actions/artifacts/" + str(positive(artifact["id"])) + "/zip"), limit=MAX_ZIP)
        if status == 302:
            status, _, raw = self.open("GET", headers.get("Location", ""), anonymous=True, limit=MAX_ZIP)
        require(status == 200 and artifact.get("digest") == "sha256:" + V.digest(raw), "Artifact ZIP identity mismatch")
        return raw

    def upload(self, release_id, name, raw):
        require(release_id in self.created and name in V.RELEASE_NAMES and 0 < len(raw) <= MAX_ZIP, "Only owned Cloud draft allowlisted assets may be uploaded")
        url = "https://uploads.github.com" + api_path("/releases/" + str(positive(release_id)) + "/assets?name=" + urllib.parse.quote(name, safe=""))
        status, _, body = self.open("POST", url, raw)
        require(status == 201, "Cloud asset upload status mismatch")
        result = V.strict_json(body)
        require(result.get("name") == name and result.get("size") == len(raw) and result.get("digest") == "sha256:" + V.digest(raw), "Uploaded Cloud asset bytes mismatch")


def repository(api):
    result = api.request("GET", "")
    require(result.get("id") == V.REPOSITORY_ID and result.get("full_name") == V.REPOSITORY and result.get("private") is False and
            result.get("default_branch") == "main" and result.get("owner", {}).get("id") == V.OWNER_ID, "Fixed public repository identity mismatch")


def resolve(api, ref):
    result = api.request("GET", "/git/ref/" + ref)
    obj = result.get("object", {})
    for _ in range(4):
        require(isinstance(obj.get("sha"), str) and V.COMMIT.fullmatch(obj["sha"]), "Invalid Git reference")
        if obj.get("type") == "commit":
            return obj["sha"]
        require(obj.get("type") == "tag", "Reference is not a commit/tag")
        obj = api.request("GET", "/git/tags/" + obj["sha"]).get("object", {})
    raise PolicyError("Excessive annotated tag depth")


def green_checks(api, source):
    proofs = []
    for workflow, expected in (("cloud.yml", CLOUD_JOBS), ("ci.yml", FINANCE_JOBS)):
        identity = api.request("GET", "/actions/workflows/" + workflow)
        require(identity.get("path") == ".github/workflows/" + workflow and identity.get("state") == "active", "Required workflow identity mismatch")
        runs = api.request("GET", "/actions/workflows/" + workflow + "/runs?branch=main&event=push&head_sha=" + source + "&per_page=100")
        require(isinstance(runs.get("workflow_runs"), list) and runs.get("total_count", 101) <= 100, "Required workflow run list incomplete")
        matches = [run for run in runs["workflow_runs"] if run.get("head_sha") == source and run.get("head_branch") == "main" and run.get("event") == "push" and run.get("workflow_id") == identity.get("id")]
        require(matches, "No required exact-main-SHA workflow run")
        run = max(matches, key=lambda row: positive(row.get("id")))
        require(run.get("status") == "completed" and run.get("conclusion") == "success", "Latest required exact-SHA run is not successful")
        jobs = api.request("GET", "/actions/runs/" + str(positive(run["id"])) + "/attempts/" + str(positive(run.get("run_attempt"))) + "/jobs?per_page=100")
        rows = jobs.get("jobs", [])
        require(jobs.get("total_count") == len(expected) and len(rows) == len(expected) and {job.get("name") for job in rows} == expected and
                all(job.get("status") == "completed" and job.get("conclusion") == "success" for job in rows), "All required real CI jobs must pass at the exact source; no skip/substitution")
        proofs.append({"workflow": workflow, "run_id": run["id"], "attempt": run["run_attempt"], "jobs": sorted(expected)})
    return proofs


def main_identity(api, env, event, workflow):
    require(env.get("GITHUB_REPOSITORY") == V.REPOSITORY and env.get("GITHUB_REPOSITORY_ID") == str(V.REPOSITORY_ID) and
            env.get("GITHUB_EVENT_NAME") == "workflow_dispatch" and env.get("GITHUB_REF") == V.SOURCE_REF and
            env.get("GITHUB_WORKFLOW_REF") == V.REPOSITORY + "/" + workflow + "@" + V.SOURCE_REF,
            "Cloud release controller must be the exact trusted-main manual workflow")
    source = env.get("GITHUB_SHA", "")
    require(V.COMMIT.fullmatch(source) and env.get("GITHUB_WORKFLOW_SHA") == source and event.get("inputs", {}).get("tag") == V.TAG,
            "Only the reviewed first Cloud RC and exact workflow SHA are authorized")
    repository(api)
    require(resolve(api, "heads/main") == source and resolve(api, "tags/" + V.TAG) == source,
            "First RC tag, current main, source SHA and signer SHA must be identical")
    return source


def no_release(api, *, include_drafts=False):
    try:
        api.request("GET", "/releases/tags/" + V.TAG)
    except APIError as error:
        require(error.status == 404, "Cannot establish release absence")
    else:
        raise PolicyError("Existing Cloud published release is never overwritten or adopted")
    if include_drafts:
        # Get-by-tag does not establish draft absence. The contents-write
        # publisher lists bounded pages under its own token, never adopts an
        # old draft after an uncertain POST/upload acknowledgement.
        for page in range(1, 6):
            rows = api.request("GET", "/releases?per_page=100&page=" + str(page))
            require(isinstance(rows, list) and len(rows) <= 100 and all(isinstance(row, dict) and isinstance(row.get("tag_name"), str) for row in rows),
                    "Cannot establish complete release/draft inventory")
            require(not any(row["tag_name"] == V.TAG for row in rows), "Existing Cloud draft/release is never overwritten or adopted")
            if len(rows) < 100:
                return
        raise PolicyError("Release/draft absence exceeds bounded inventory; manual review required")


def prepare_build(api, env, event):
    source = main_identity(api, env, event, BUILD_PATH)
    no_release(api)
    return {"schema": 1, "source_commit": source, "tag": V.TAG, "version": V.VERSION,
            "run_id": positive(int(env.get("GITHUB_RUN_ID", "0"))), "attempt": positive(int(env.get("GITHUB_RUN_ATTEMPT", "0"))),
            "prechecks": green_checks(api, source)}


def artifact(api, run_id, attempt, source, kind):
    name = "cloud-" + kind + "-" + str(run_id) + "-" + str(attempt)
    listing = api.request("GET", "/actions/runs/" + str(run_id) + "/artifacts?per_page=100")
    require(listing.get("total_count", 101) <= 100 and isinstance(listing.get("artifacts"), list), "Artifact listing incomplete")
    matches = [item for item in listing["artifacts"] if item.get("name") == name]
    require(len(matches) == 1, "Exact run/attempt candidate artifact missing or ambiguous")
    item = matches[0]
    run = item.get("workflow_run", {})
    require(item.get("expired") is False and 0 < item.get("size_in_bytes", 0) <= MAX_ZIP and
            isinstance(item.get("digest"), str) and re.fullmatch(r"sha256:[0-9a-f]{64}", item["digest"]) and
            run.get("id") == run_id and run.get("repository_id") == V.REPOSITORY_ID and run.get("head_repository_id") == V.REPOSITORY_ID and
            run.get("head_sha") == source and run.get("head_branch") == "main", "Candidate artifact run identity mismatch")
    return item


def zip_files(raw, *, signed):
    expected = set(V.RELEASE_NAMES if signed else V.SIGNED_NAMES)
    result, total = {}, 0
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            for member in archive.infolist():
                mode = member.external_attr >> 16
                require(member.filename in expected and member.filename not in result and not member.is_dir() and not member.flag_bits & 1 and
                        stat.S_IFMT(mode) in (0, stat.S_IFREG) and member.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED), "Unsafe candidate ZIP member")
                total += member.file_size
                require(0 < member.file_size <= MAX_ZIP and total <= MAX_ZIP, "Candidate ZIP exceeds bounds")
                content = archive.read(member)
                require(len(content) == member.file_size, "Truncated candidate ZIP member")
                result[member.filename] = content
    except (zipfile.BadZipFile, OSError, ValueError):
        raise PolicyError("Malformed candidate ZIP") from None
    require(set(result) == expected, "Incomplete or unknown candidate asset inventory")
    return result


def source_bytes(source, relative):
    require(V.COMMIT.fullmatch(source) and relative in {"aster-cloud/deploy/install/" + name for name in (*V.CAPSULE_FILES, "release-trusted-root.json")}, "Unexpected candidate source comparison")
    try:
        return subprocess.run(["git", "--no-replace-objects", "-C", str(ROOT), "show", source + ":" + relative],
                              check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30).stdout
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        raise PolicyError("Exact trusted source blob unavailable") from None


def validate_candidate(files, source):
    require(set(files) in (set(V.SIGNED_NAMES), set(V.RELEASE_NAMES)), "Candidate file allowlist mismatch")
    manifest, assets = V.release_manifest(files["release-manifest.json"])
    require(manifest["source_commit"] == source, "Candidate exact source SHA mismatch")
    for name, entry in assets.items():
        require(entry["size"] == len(files[name]) and entry["sha256"] == V.digest(files[name]), "Candidate signed file hash/size mismatch")
    sums = "".join(V.digest(files[name]) + "  " + name + "\n" for name in V.PAYLOAD_NAMES).encode()
    require(files["SHA256SUMS"] == sums, "Exact payload checksum inventory mismatch")
    require(V.digest(files["release-trusted-root.json"]) == V.TRUSTED_ROOT_SHA256 and len(files["release-trusted-root.json"]) == V.TRUSTED_ROOT_SIZE,
            "Official trust-root snapshot differs from reviewed code pin")
    code = V.capsule_files(files[V.CAPSULE_NAME], source)
    for name, raw in code.items():
        require(raw == source_bytes(source, "aster-cloud/deploy/install/" + name), "Installer capsule differs from exact trusted Git source")
    require(files[V.BOOTSTRAP_NAME] == code["release_verify.py"], "Bootstrap and adjacent verifier differ")
    provenance = V.strict_json(files["provenance.json"])
    require(provenance == {"schema": 1, "repository": V.REPOSITORY, "repository_id": V.REPOSITORY_ID, "tag": V.TAG,
                          "version": V.VERSION, "source_commit": source, "source_date_epoch": provenance.get("source_date_epoch"),
                          "toolchains": {"go": P.GO_TOOLCHAIN, "node": P.NODE_VERSION}, "scope": "independent-cloud-only",
                          "production_ready": False, "real_kvm_accepted": False} and type(provenance.get("source_date_epoch")) is int and
            provenance["source_date_epoch"] >= 0, "Unexpected candidate provenance")
    with tempfile.TemporaryDirectory(prefix="cloud-package-data-") as temporary:
        for role in ("controller", "node"):
            name = "aster-cloud-" + role + "-" + V.VERSION + "-linux-amd64.tar.gz"
            path = Path(temporary) / name
            V.write_new(path, files[name])
            bundle = I.verify_bundle(path, V.digest(files[name]), "aster-cloud-" + role)
            require(bundle.manifest.get("source_commit") == source and bundle.manifest.get("version") == V.VERSION and bundle.manifest.get("release_kind") == "release",
                    "Role package identity mismatch")
            for relative, raw in bundle.files.items():
                if relative.startswith("bin/"):
                    P.validate_static_amd64(raw)
    return manifest


def write_directory(directory, files):
    require(not directory.exists() and not directory.is_symlink(), "Candidate staging destination already exists")
    directory.mkdir(mode=0o700)
    for name, raw in files.items():
        V.write_new(directory / name, raw)


def read_directory(directory, *, signed):
    require(directory.is_dir() and not directory.is_symlink(), "Candidate data directory required")
    expected = set(V.RELEASE_NAMES if signed else V.SIGNED_NAMES)
    require({path.name for path in directory.iterdir()} == expected, "Unexpected candidate data files")
    files = {}
    for name in sorted(expected):
        path = directory / name
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= MAX_ZIP, "Unsafe candidate data inode")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            raw = stream.read(MAX_ZIP + 1)
        require(len(raw) == info.st_size, "Changed candidate data file")
        files[name] = raw
    require(sum(map(len, files.values())) <= MAX_ZIP, "Candidate data exceeds total bound")
    return files


def verify_signed(directory, files, source):
    validate_candidate(files, source)
    with tempfile.TemporaryDirectory(prefix="cloud-offline-verifier-") as temporary:
        base = Path(temporary)
        for name in ("home", "config"):
            (base / name).mkdir(mode=0o700)
        gh = base / "gh"
        V.write_new(gh, V.pinned_gh(V.fetch("https://github.com/cli/cli/releases/download/v" + V.GH_VERSION + "/" + V.GH_TAR_NAME, V.GH_TAR_SIZE)), 0o700)
        for name in V.SIGNED_NAMES:
            V.verify_attestation(directory / name, V.digest(files[name]), source, gh, directory / "release-trusted-root.json",
                                 directory / "attestations.jsonl", base / "home", base / "config")
        require(not any((base / "home").iterdir()) and not any((base / "config").iterdir()), "Anonymous offline verifier unexpectedly wrote state")


def release_body(source, bootstrap_sha):
    require(V.COMMIT.fullmatch(source) and V.HEX.fullmatch(bootstrap_sha), "Invalid public installation permalink identity")
    url = "https://raw.githubusercontent.com/" + V.REPOSITORY + "/" + source + "/aster-cloud/deploy/install/release_verify.py"
    commands = []
    for role in ("controller", "node"):
        commands.append("```sh\nbash -o pipefail -c 'curl --fail --silent --show-error --proto \"=https\" --tlsv1.2 --connect-timeout 10 --max-time 60 --max-filesize 1048576 " + url + " | sudo /usr/bin/python3 -I - " + role + "'\n```")
    return ("# Aster Cloud " + V.VERSION + " · 官方预发布\n\n"
            "这是 RC 候选版，不是 stable 稳定版；真实 KVM、物理网络和生产部署尚未验收。\n\n"
            "适用：Ubuntu 22.04 / 24.04 amd64，Python 3.10+、curl、sudo 与已启动的 systemd。Ubuntu 26.04 暂不支持。"
            "主控和被控分别在各自机器执行以下一条命令。交互向导默认不安装；核对真实 TLS、身份和配置后，"
            "需明确输入 install 才应用，Cloud 服务启动还需 start 批准。主控可选新专用 MySQL，被控可选 libvirt 自动准备；"
            "这些准备步骤可安装并启动相应依赖服务。\n\n"
            "初始脚本是操作者审核并信任的固定源码入口，依赖 HTTPS 和下方精确提交，不能在执行前自证可信。"
            "脚本固定验证器与信任根；后续下载的安装器代码只有匿名 Sigstore 验签通过后才执行，无需 GitHub 登录。\n\n"
            "## 主控\n" + commands[0] + "\n\n## 专用 KVM 被控\n" + commands[1] + "\n\n"
            "被控仅用于专用计算宿主，不要安装到现有 1GB 财务测试机；主控 client 私钥不得复制到被控。"
            "软件准备完成不等于 KVM 就绪或已加入主控。\n\n"
            "源码提交：`" + source + "`。初始脚本 SHA256（供人工核对）：`" + bootstrap_sha + "`。\n\n"
            "财务既有标签、Release、资产和 latest 均不改变，不修改宿主防火墙或物理上联。"
            "失败不会自动重试；先核对保留的私有状态，再明确使用 resume。\n")


def publish(api, env, event, directory):
    source = main_identity(api, env, event, PUBLISH_PATH)
    run_id = positive(int(event.get("inputs", {}).get("build_run_id", "0")))
    attempt = positive(int(event.get("inputs", {}).get("build_attempt", "0")))
    identity = api.request("GET", "/actions/workflows/cloud-release-build.yml")
    run = api.request("GET", "/actions/runs/" + str(run_id))
    require(identity.get("path") == BUILD_PATH and identity.get("state") == "active" and run.get("workflow_id") == identity.get("id") and
            run.get("path") == BUILD_PATH and run.get("event") == "workflow_dispatch" and run.get("head_branch") == "main" and
            run.get("head_sha") == source and run.get("run_attempt") == attempt and run.get("status") == "completed" and run.get("conclusion") == "success" and
            all(run.get(key, {}).get("id") == V.REPOSITORY_ID and run[key].get("full_name") == V.REPOSITORY for key in ("repository", "head_repository")),
            "Upstream Cloud signer run identity/success mismatch")
    green_checks(api, source)
    no_release(api, include_drafts=True)
    files = zip_files(api.download(artifact(api, run_id, attempt, source, "signed")), signed=True)
    write_directory(directory, files)
    verify_signed(directory, files, source)
    # Final tag/main/CI/release absence rechecks happen after all potentially
    # long transfers and verification, before the first contents mutation.
    main_identity(api, env, event, PUBLISH_PATH)
    green_checks(api, source)
    no_release(api, include_drafts=True)
    draft = api.request("POST", "/releases", {"tag_name": V.TAG, "target_commitish": source, "name": "Aster Cloud " + V.VERSION,
                         "body": release_body(source, V.digest(files[V.BOOTSTRAP_NAME])), "draft": True, "prerelease": True, "make_latest": "false"})
    release_id = positive(draft.get("id"))
    require(draft.get("tag_name") == V.TAG and draft.get("draft") is True and draft.get("prerelease") is True, "New Cloud draft response mismatch")
    for name in V.RELEASE_NAMES:
        api.upload(release_id, name, files[name])
    current = api.request("GET", "/releases/" + str(release_id))
    rows = current.get("assets", [])
    require(current.get("draft") is True and current.get("tag_name") == V.TAG and len(rows) == len(files) and
            {item.get("name") for item in rows} == set(files) and all(item.get("state") == "uploaded" and item.get("size") == len(files[item["name"]]) and
            item.get("digest") == "sha256:" + V.digest(files[item["name"]]) for item in rows), "Staged Cloud release inventory mismatch")
    require(resolve(api, "tags/" + V.TAG) == source, "Cloud tag changed before publication")
    main_identity(api, env, event, PUBLISH_PATH)
    green_checks(api, source)
    result = api.request("PATCH", "/releases/" + str(release_id), {"draft": False, "prerelease": True, "make_latest": "false"})
    require(result.get("id") == release_id and result.get("tag_name") == V.TAG and result.get("draft") is False and result.get("prerelease") is True, "Cloud publication response mismatch; review manually")
    return {"schema": 1, "published": True, "release_id": release_id, "tag": V.TAG, "source_commit": source,
            "make_latest": False, "prerelease": True, "production_ready": False, "real_kvm_accepted": False}


def outputs(value):
    destination = os.environ.get("GITHUB_OUTPUT")
    if destination:
        with open(destination, "a", encoding="utf-8") as stream:
            for name, item in value.items():
                require(re.fullmatch(r"[a-z_]+", name) and isinstance(item, (str, int)) and not any(c in str(item) for c in "\r\n"), "Unsafe workflow output")
                stream.write(name + "=" + str(item) + "\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("prepare-build", "prepare-attest", "seal-attest", "publish"))
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--bundle", type=Path)
    args = parser.parse_args(argv)
    try:
        api = GitHub(os.environ.get("GH_TOKEN"))
        event = V.strict_json(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes())
        if args.operation == "publish":
            result = publish(api, os.environ, event, args.directory)
            outputs({"release_id": result["release_id"], "source_sha": result["source_commit"]})
            print(json.dumps(result, sort_keys=True))
        else:
            policy = prepare_build(api, os.environ, event)
            if args.operation == "prepare-attest":
                files = zip_files(api.download(artifact(api, policy["run_id"], policy["attempt"], policy["source_commit"], "unsigned")), signed=False)
                validate_candidate(files, policy["source_commit"])
                write_directory(args.directory, files)
            elif args.operation == "seal-attest":
                require(args.bundle is not None and args.bundle.is_file() and not args.bundle.is_symlink(), "Official attestation bundle required")
                raw = args.bundle.read_bytes()
                require(0 < len(raw) <= MAX_JSON, "Attestation bundle size refused")
                V.write_new(args.directory / "attestations.jsonl", raw)
                files = read_directory(args.directory, signed=True)
                verify_signed(args.directory, files, policy["source_commit"])
            if args.policy:
                V.write_new(args.policy, json_bytes(policy))
            outputs({"source_sha": policy["source_commit"], "version": V.VERSION})
            print("PASS: trusted-main Cloud prerelease policy; " + str(len(CLOUD_JOBS) + len(FINANCE_JOBS)) + " exact-SHA prechecks, no host apply")
    except (PolicyError, V.ReleaseError, I.InstallerError, P.PackageError) as error:
        # These exception messages are fixed strings from our trusted policy,
        # never HTTP response bodies, subprocess diagnostics or token values.
        print("Cloud release policy refused: " + str(error), file=sys.stderr)
        return 1
    except (OSError, ValueError, TypeError, KeyError):
        print("Cloud release policy refused; no uncertain mutation retried and no candidate code executed.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

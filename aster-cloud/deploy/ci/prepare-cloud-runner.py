#!/usr/bin/env python3
"""Prepare libraries and private scratch on this repo's disposable CI only.

Not an installer: no database service, Nginx, libvirt or finance implementation.
The separate mysql-native.sh owns its server process and cleanup. This helper
never accepts a URL, package, command or deletion path as a CLI argument.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile

REPOSITORY = 'xiaoqiqixi/betteridcsys-cloud'
REPOSITORY_ID = '1435344151'
PLATFORMS = {'22.04': ['libaio1', 'libssl3', 'libtirpc3'],
             '24.04': ['libaio1t64', 'libssl3t64', 'libtirpc3t64']}
APT_SECURITY = ['-o', 'Acquire::Retries=0', '-o', 'APT::Get::AllowUnauthenticated=false',
                '-o', 'Acquire::AllowInsecureRepositories=false',
                '-o', 'Acquire::AllowDowngradeToInsecureRepositories=false']


def require(condition, code):
    if not condition:
        raise ValueError(code)


def owned_path(value, *, directory):
    require(isinstance(value, str) and value and not any(ord(c) < 32 for c in value), 'invalid_path')
    path = Path(value)
    require(path.is_absolute() and str(path) == value and path.resolve(strict=True) == path, 'noncanonical_path')
    info = path.lstat()
    require(info.st_uid == os.geteuid() and not info.st_mode & 0o022 and
            (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1),
            'path_ownership_or_mode')
    return path


def context():
    env = os.environ
    require(env.get('GITHUB_ACTIONS') == 'true' and env.get('RUNNER_ENVIRONMENT') == 'github-hosted', 'hosted_runner_required')
    require(env.get('GITHUB_REPOSITORY') == REPOSITORY and env.get('GITHUB_REPOSITORY_ID') == REPOSITORY_ID, 'repository_mismatch')
    require(env.get('GITHUB_REF') == 'refs/heads/main' and env.get('GITHUB_EVENT_NAME') in ('push', 'workflow_dispatch'), 'main_event_required')
    require(re.fullmatch(r'[0-9a-f]{40}', env.get('GITHUB_SHA', '')) is not None, 'source_sha_required')
    require(all(re.fullmatch(r'[1-9][0-9]{0,19}', env.get(key, '')) for key in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT')), 'run_identity_required')
    require(os.geteuid() != 0 and platform.system() == 'Linux' and platform.machine() == 'x86_64', 'unprivileged_linux_amd64_required')
    fields = {}
    for line in Path('/etc/os-release').read_text(encoding='utf-8').splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            require(key not in fields, 'duplicate_os_field')
            fields[key] = value.strip('"')
    require(fields.get('ID') == 'ubuntu' and fields.get('VERSION_ID') in PLATFORMS, 'ubuntu22_or_24_required')
    parent = owned_path(env.get('RUNNER_TEMP'), directory=True)
    identity = dict(repository=REPOSITORY, repository_id=REPOSITORY_ID, source_sha=env['GITHUB_SHA'],
                    run_id=env['GITHUB_RUN_ID'], run_attempt=env['GITHUB_RUN_ATTEMPT'])
    return parent, fields['VERSION_ID'], identity


def prepare(parent, version, identity):
    require(not os.environ.get('ASTER_NATIVE_FIXTURE_ROOT'), 'existing_fixture_refused')
    output = owned_path(os.environ.get('GITHUB_ENV'), directory=False)
    require(parent in output.parents, 'environment_file_outside_runner')
    libraries = PLATFORMS[version] + ['libmecab2', 'libnuma1', 'libtinfo6', 'libgssapi-krb5-2',
                                    'libkrb5-3', 'libsasl2-2', 'libudev1', 'libpcre2-8-0', 'openssl', 'fonts-noto-cjk']
    # Fixed executable paths and signed distribution repositories only. These
    # package operations are confined to a disposable hosted runner, not users.
    subprocess.run(['/usr/bin/sudo', '--', '/usr/bin/apt-get', *APT_SECURITY, 'update'], check=True, timeout=600)
    subprocess.run(['/usr/bin/sudo', '--', '/usr/bin/env', 'DEBIAN_FRONTEND=noninteractive',
                    '/usr/bin/apt-get', *APT_SECURITY, 'install', '--yes', '--no-install-recommends', *libraries],
                   check=True, timeout=900)
    case = Path(tempfile.mkdtemp(prefix='aster-cloud-ci.', dir=parent))
    marker = case / '.cloud-ci-owner.json'
    with marker.open('x', encoding='utf-8') as stream:
        json.dump(identity, stream, sort_keys=True)
    marker.chmod(0o600)
    fd = os.open(output, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1 and not info.st_mode & 0o022,
                'environment_file_changed')
        stream.write('ASTER_NATIVE_FIXTURE_ROOT=' + str(case) + '\n')
    return dict(action='prepare', ubuntu=version, private_fixture_created=True, native_acceptance_passed=False)


def cleanup(parent, identity):
    value = os.environ.get('ASTER_NATIVE_FIXTURE_ROOT')
    if not value:
        return dict(action='cleanup', removed=False)
    case = owned_path(value, directory=True)
    require(case.parent == parent and re.fullmatch(r'aster-cloud-ci\.[a-z0-9_]{8}', case.name), 'foreign_fixture_refused')
    require(case.stat().st_mode & 0o777 == 0o700, 'private_fixture_required')
    marker = owned_path(str(case / '.cloud-ci-owner.json'), directory=False)
    fd = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1 and
                not info.st_mode & 0o077 and 0 < info.st_size <= 4096, 'owner_marker_invalid')
        raw = stream.read(4097)
    require(len(raw) <= 4096 and json.loads(raw) == identity, 'owner_marker_mismatch')
    require(shutil.rmtree.avoids_symlink_attacks, 'safe_tree_removal_required')
    shutil.rmtree(case)
    return dict(action='cleanup', removed=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'cleanup'))
    args = parser.parse_args()
    try:
        parent, version, identity = context()
        result = prepare(parent, version, identity) if args.action == 'prepare' else cleanup(parent, identity)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        # Never echo path/env contents or subprocess diagnostics from callers.
        code = str(error) if isinstance(error, ValueError) else type(error).__name__
        print('Cloud runner refused: ' + code, file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

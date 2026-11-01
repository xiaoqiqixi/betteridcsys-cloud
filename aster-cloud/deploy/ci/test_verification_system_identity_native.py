#!/usr/bin/env python3
"""Actual useradd/NSS contract on disposable Ubuntu 22/24 CI runners only.

Calls the same fixed creation and inspection used by the installed manager.
Does not approve a migration, start HTTP, touch MySQL, or alter an existing user.
Only this invocation's nonce-owned idle identity may be removed; no force/rm.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import sys

sys.dont_write_bytecode = True


class ProbeFailure(Exception):
    pass


def require(ok):
    if not ok:
        raise ProbeFailure()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    args = parser.parse_args()
    require(sys.platform == 'linux' and os.getuid() == os.geteuid() == 0 and
            re.fullmatch(r'[0-9a-f]{40}', args.source))
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    require(release.get('ID', '').strip('"') == 'ubuntu' and
            release.get('VERSION_ID', '').strip('"') in ('22.04', '24.04'))
    entry = Path(__file__).resolve().parents[1]/'install/controller-migration.py'
    spec = importlib.util.spec_from_file_location('actual_system_identity', entry)
    manager = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(manager)
    manager.local_system_identity_sources(Path('/etc/nsswitch.conf').read_text())
    require(not Path('/nonexistent').exists() and not Path('/nonexistent').is_symlink())
    operation, nonce = secrets.token_hex(16), secrets.token_hex(32)
    name = 'asterv-'+operation[:24]
    databases = ('passwd', 'group', 'shadow', 'gshadow')

    def snapshot():
        # These private records are compared only in memory, never logged.
        return {key:manager.system_account_lookup(key, name, missing=True) for key in databases}

    def refused(action, code):
        before = snapshot()
        try:
            action()
        except manager.Refused as error:
            require(str(error) == code)
        else:
            raise ProbeFailure()
        require(snapshot() == before)

    identity = None
    created = False
    try:
        require(all(value is None for value in snapshot().values()))
        manager.create_system_identity(operation, nonce)
        created = True
        identity, records = manager.inspect_system_identity(operation, nonce)
        fields = records['shadow'].removesuffix('\n').split(':')
        require(len(fields) == 9 and fields[0:2] == [name, '!'] and fields[7] == '')
        owned = snapshot()
        require(owned['passwd'].removesuffix('\n').split(':')[5:] == ['/nonexistent', '/usr/sbin/nologin'])
        require(manager.inspect_system_identity(operation, nonce)[0] == identity)
        refused(lambda:manager.create_system_identity(operation, secrets.token_hex(32)),
                'TARGET_VERIFICATION_SYSTEM_FOREIGN_IDENTITY')
        refused(lambda:manager.inspect_system_identity(operation, secrets.token_hex(32)),
                'TARGET_VERIFICATION_SYSTEM_IDENTITY_REJECTED')
        # This fixture alone changes its own noninteractive shell. Inspection
        # must reject drift, not silently repair or unlock the identity.
        manager.run(['/usr/sbin/usermod', '--shell', '/bin/false', name])
        changed = {**owned, 'passwd':owned['passwd'].replace(':/usr/sbin/nologin\n', ':/bin/false\n')}
        try:
            require(snapshot() == changed)
            refused(lambda:manager.inspect_system_identity(operation, nonce),
                    'TARGET_VERIFICATION_SYSTEM_IDENTITY_REJECTED')
        finally:
            # Never restore a record that another actor changed underneath us.
            require(snapshot() == changed)
            manager.system_identity_idle(identity['uid'], identity['gid'])
            manager.run(['/usr/sbin/usermod', '--shell', '/usr/sbin/nologin', name])
        require(snapshot() == owned and manager.inspect_system_identity(operation, nonce)[0] == identity)
    finally:
        if created:
            current, _ = manager.inspect_system_identity(operation, nonce)
            require(identity is not None and current == identity)
            group = manager.system_account_lookup('group', name)
            gshadow = manager.system_account_lookup('gshadow', name)
            manager.run(['/usr/sbin/userdel', name])
            remaining = snapshot()
            require(remaining['passwd'] is None and remaining['shadow'] is None)
            if remaining['group'] is not None:
                require(remaining['group'] == group and remaining['gshadow'] == gshadow)
                # Re-enumerate to refuse any new numeric owner or member before
                # deleting a fixture group retained by a host USERGROUPS_ENAB.
                users = manager.system_account_lookup('passwd').splitlines()
                groups = manager.system_account_lookup('group').splitlines()
                require(all(row.split(':')[3] != str(identity['gid']) for row in users))
                require([row+'\n' for row in groups if row.split(':')[2] == str(identity['gid'])] == [group])
                manager.system_identity_idle(identity['uid'], identity['gid'])
                manager.run(['/usr/sbin/groupdel', name])
            require(all(value is None for value in snapshot().values()))
    print(json.dumps(dict(schema=1, source_sha=args.source, passed=True,
        real_linux_accounts=True, locked_password=True, nonlogin_shell=True,
        no_account_expiry=True, isolated_uid_gid=True, foreign_identity_refused=True,
        drift_not_repaired=True, cleanup_verified=True, http_started=False,
        mysql_verified=False, installed_target_approval=False, migration_ready=False), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Never emit NSS/shadow records, subprocess output or a raw traceback.
        print('SYSTEM_IDENTITY_NATIVE_UNCONFIRMED', file=sys.stderr)
        raise SystemExit(1)

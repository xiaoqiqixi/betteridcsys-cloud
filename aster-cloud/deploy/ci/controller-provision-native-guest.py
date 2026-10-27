#!/usr/bin/env python3
"""Fixed target-provisioning scenario in an owned signed Ubuntu TCG guest.

Source metadata and typed table headers are synthetic: this is NOT database
restore, real source export, boot recovery, controller activation or takeover.
The installer, root APT/systemd/MySQL and target coordinator are actual code.
"""
import base64
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
import tarfile

sys.dont_write_bytecode = True
ROOT = Path('/root/aster-native')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': str(ROOT), 'LANG': 'C.UTF-8',
       'MYSQL_TEST_LOGIN_FILE': str(ROOT / 'absent-login-file'), 'MYSQL_HISTFILE': '/dev/null'}
PHASE = 'preflight'
NONCE = None
CODES = set('TARGET_PROVISION_UNCONFIRMED TARGET_COMMAND_REJECTED TARGET_DATABASE_PLAN_CHANGED TARGET_DATABASE_INVENTORY_CHANGED TARGET_PROVISION_MODULE_MISSING'.split())
APT_CODES = set('APT_DNS_FAILURE APT_TLS_FAILURE APT_SIGNATURE_FAILURE APT_METADATA_FAILURE APT_PACKAGE_UNAVAILABLE APT_DEPENDENCY_CONFLICT APT_LOCKED APT_COMMAND_REJECTED APT_COMMAND_UNAVAILABLE APT_COMMAND_TIMEOUT APT_OUTPUT_OVERSIZED'.split())


class Refused(Exception):
    pass


def require(condition, code='TARGET_NATIVE_ASSERTION_FAILED'):
    if not condition:
        raise Refused(code)


def progress(stage):
    global PHASE
    PHASE = stage
    with open('/dev/ttyS0', 'w') as console:
        console.write('ASTER_LIBVIRT_NATIVE_PROGRESS_' + NONCE + ' ' + stage + '\n')
        console.flush()


def run(argv, *, env=None, denied=None, timeout=1860, data=None):
    p = subprocess.run(list(map(str, argv)), input=data, env=env or ENV, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=timeout)
    require(len(p.stdout) <= 1024 * 1024 and len(p.stderr) <= 1024 * 1024, 'TARGET_NATIVE_OUTPUT_BOUND')
    if denied is not None:
        try:
            error = json.loads(p.stderr)
        except (ValueError, UnicodeError):
            raise Refused('TARGET_NATIVE_REFUSAL_UNCONFIRMED') from None
        require(p.returncode == 1 and not p.stdout and error == {'error': denied}, 'TARGET_NATIVE_REFUSAL_UNCONFIRMED')
    elif p.returncode:
        try:
            error = json.loads(p.stderr).get('error')
        except (ValueError, UnicodeError):
            error = None
        raise Refused(error if error in CODES | APT_CODES else 'TARGET_NATIVE_COMMAND_FAILED')
    return p


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def private(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as f:
        os.fchmod(f.fileno(), mode)
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())


def execute(metadata):
    progress('preflight')
    require(os.geteuid() == 0 and Path('/proc/1/comm').read_text().strip() == 'systemd')
    require(Path('/sys/class/dmi/id/product_name').read_text().strip() in
            ('Standard PC (i440FX + PIIX, 1996)', 'Standard PC (Q35 + ICH9, 2009)'))
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    require(release['ID'].strip('"') == 'ubuntu' and release['VERSION_ID'].strip('"') == metadata['ubuntu'])
    require(not Path('/dev/kvm').exists())
    require(sha(ROOT / 'aster-controller') == metadata['controller_binary_sha256'] and
            sha(ROOT / 'controller-fixture.test') == metadata['fixture_binary_sha256'])
    for path in ('/var/lib/mysql', '/etc/mysql', '/etc/libvirt', '/var/lib/libvirt', '/opt/aster-cloud',
                 '/var/lib/aster-cloud-installer', '/etc/aster-controller', '/var/lib/aster-controller-restore'):
        require(not Path(path).exists() and not Path(path).is_symlink())
    operation, controller = metadata['nonce'], 'native-target-' + metadata['nonce'][:12]
    inputs = Path('/var/lib/aster-controller-restore') / operation
    inputs.parent.mkdir(mode=0o700)
    inputs.mkdir(mode=0o700)
    run([ROOT / 'controller-fixture.test', '-test.run=^TestControllerSourceValidation$'], env={**ENV,
        'ASTER_SOURCE_CLI_FIXTURE': '1', 'ASTER_FIXTURE_DATA_PLAN': '1', 'ASTER_FIXTURE_DIR': str(inputs),
        'ASTER_FIXTURE_CONTROLLER': controller, 'ASTER_FIXTURE_OPERATION': operation,
        'ASTER_FIXTURE_SOURCE': metadata['source_sha']})
    files = {'bin/aster-controller': (ROOT / 'aster-controller').read_bytes(),
             'ui/index.html': b'<!doctype html><title>Native provisioning fixture, not UI acceptance</title>'}
    for name in ('install.py', 'controller-migration.py', 'provision.py'):
        files['templates/host-management/' + name] = (ROOT / name).read_bytes()
    files['manifest.json'] = json.dumps({'schema': 1, 'component': 'aster-cloud-controller',
        'platform': 'linux-amd64', 'version': '0.1.0-dev.1', 'release_kind': 'development',
        'source_commit': metadata['source_sha'], 'files': [{'path': name, 'sha256': hashlib.sha256(raw).hexdigest(),
        'size': len(raw), 'mode': '0755' if name.startswith('bin/') else '0644'} for name, raw in sorted(files.items())]}).encode()
    bundle = ROOT / 'controller.tar.gz'
    with tarfile.open(bundle, 'w:gz', format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(raw), 0o755 if name.startswith('bin/') else 0o644
            archive.addfile(info, io.BytesIO(raw))
    progress('controller-install')
    bundle_sha = sha(bundle)
    run(['/usr/bin/python3', '-I', ROOT / 'install.py', 'controller', '--bundle', bundle, '--sha256', bundle_sha,
         '--allow-development', '--apply'])
    version = Path('/opt/aster-cloud/controller/versions') / ('0.1.0-dev.1-' + bundle_sha[:16])
    helper = version / 'templates/host-management/controller-migration.py'
    def entry(action, denied=None):
        return run(['/usr/bin/python3', '-I', helper, action, '--operation', operation], denied=denied)
    progress('target-plan')
    entry('target-seal')
    result = json.loads(entry('target-database-plan').stdout)
    require(result['readonly'] and not result['database_restored'] and not result['migration_ready'])
    require(result['plan']['data']['charset'] == 'utf8mb4' and result['plan']['data']['collation'] == 'utf8mb4_bin' and
            len(result['plan']['data']['tables']) == 34 and result['plan']['data']['rows'] == 12)
    require(not (inputs / 'database').exists())
    seal = Path('/var/lib/aster-controller') / controller / 'target-restore.json'
    state = Path('/var/lib/aster-cloud-installer/controller/state.json')
    before = (sha(seal), sha(state))
    progress('target-provision')
    expected = {'database_provisioned': True, 'target_credentials_verified': True, 'database_restored': False,
                'target_restore_approved': False, 'migration_ready': False}
    require(json.loads(entry('target-provision').stdout) == expected)
    directory = inputs / 'database'
    private_files = ('mysql-provision.json', 'restore-provision.json', 'runtime-mysql-dsn', 'migration-mysql-dsn')
    hashes = {name: sha(directory / name) for name in private_files}
    for name in private_files:
        st = (directory / name).lstat()
        require(st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o600 and stat.S_ISREG(st.st_mode) and st.st_nlink == 1)
    run(['/usr/bin/systemctl', 'is-active', '--quiet', 'mysql.service'])
    spec = importlib.util.spec_from_file_location('actual_provision', version / 'templates/host-management/provision.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    database, runtime_user, migration_user = module.restore_database_names(operation)
    progress('target-credentials')
    binding = json.loads((directory / 'restore-provision.json').read_bytes())
    require(binding['operation_id'] == operation and binding['collation'] == 'utf8mb4_bin')
    raw_dsn = (directory / 'runtime-mysql-dsn').read_text().strip()
    prefix, suffix = runtime_user + ':', '@unix(/run/mysqld/mysqld.sock)/' + database
    require(raw_dsn.startswith(prefix) and raw_dsn.endswith(suffix))
    password = raw_dsn[len(prefix):-len(suffix)]
    options = '[client]\nuser=' + runtime_user + '\npassword="' + password.replace('\\', '\\\\').replace('"', '\\"') + '"\n'
    config = ROOT / 'runtime-test.cnf'
    private(config, options.encode())
    del options, password, raw_dsn
    runtime_command = ['/usr/bin/mysql', '--defaults-file=' + str(config), '--protocol=SOCKET',
        '--socket=/run/mysqld/mysqld.sock', '--database=' + database, '--batch', '--skip-column-names', '--skip-reconnect']
    run(runtime_command, data=b'SELECT COUNT(*) FROM aster_installer_ownership;\n')
    progress('target-grants')
    denied = subprocess.run(runtime_command, input=b'CREATE TABLE forbidden_runtime_ddl(id INT);\n', env=ENV,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    require(denied.returncode == 1 and not denied.stdout and re.match(rb'^ERROR 1142 \(42000\)', denied.stderr),
            'TARGET_NATIVE_REFUSAL_UNCONFIRMED')
    progress('resume')
    require(json.loads(entry('target-provision').stdout) == expected)
    require({name: sha(directory / name) for name in private_files} == hashes and (sha(seal), sha(state)) == before)
    progress('target-refusals')
    # Test-owned locked account: production never removes unknown accounts.
    module.mysql_sql(directory, "CREATE USER 'aster_native_foreign'@'localhost' ACCOUNT LOCK;\n")
    entry('target-provision', 'TARGET_PROVISION_UNCONFIRMED')
    require({name: sha(directory / name) for name in private_files} == hashes)
    module.mysql_sql(directory, "DROP USER 'aster_native_foreign'@'localhost';\n")
    credentials = directory / 'runtime-mysql-dsn'
    retained = ROOT / 'retained-runtime-dsn'
    before_auth = module.mysql_sql(directory, "SELECT SHA2(authentication_string,256) FROM mysql.user WHERE User='" + runtime_user + "' AND Host='localhost';\n")
    credentials.rename(retained)
    entry('target-provision', 'TARGET_PROVISION_UNCONFIRMED')
    require(not credentials.exists() and sha(retained) == hashes['runtime-mysql-dsn'])
    require(module.mysql_sql(directory, "SELECT SHA2(authentication_string,256) FROM mysql.user WHERE User='" + runtime_user + "' AND Host='localhost';\n") == before_auth)
    retained.rename(credentials)
    require((sha(seal), sha(state)) == before and not Path('/etc/aster-controller').exists())
    require(not Path('/etc/systemd/system/aster-controller.service').exists())
    # The empty owned DB remains unactivated, with its real provenance marker.
    info = module._query(directory, "SELECT JSON_OBJECT('tables',COUNT(*)) FROM information_schema.TABLES WHERE TABLE_SCHEMA='" + database + "';\n")
    require(info == {'tables': 1})
    true = 'passed real_apt real_systemd real_mysql actual_installer actual_controller target_sealed exact_encoding_preserved credentials_verified runtime_ddl_denied foreign_account_refused lost_credential_refused_without_reset same_operation_preserved source_fixture_synthetic'.split()
    false = 'database_restored source_host_export_verified node_takeover_verified migration_ready kvm_ready'.split()
    return {**{k: True for k in true}, **{k: False for k in false}, 'schema': 1, 'scenario': 'controller-provision',
            **{k: metadata[k] for k in ('source_sha', 'ubuntu', 'image_sha256')}}


def main():
    global NONCE
    metadata = json.loads((ROOT / 'metadata.json').read_bytes())
    NONCE = metadata['nonce']
    require(re.fullmatch(r'[0-9a-f]{32}', NONCE) is not None)
    try:
        report = execute(metadata)
    except Exception as error:
        report = {'schema': 1, 'passed': False, 'code': str(error) if isinstance(error, Refused) else 'TARGET_NATIVE_ASSERTION_FAILED',
                  'phase': PHASE, 'kvm_ready': False, **{k: metadata[k] for k in ('source_sha', 'ubuntu', 'image_sha256')}}
    with open('/dev/ttyS0', 'w') as console:
        console.write('ASTER_LIBVIRT_NATIVE_RESULT_' + NONCE + ' ' + base64.b64encode(json.dumps(report).encode()).decode() + '\n')
        console.flush()
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())

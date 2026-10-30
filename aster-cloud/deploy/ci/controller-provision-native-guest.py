#!/usr/bin/env python3
"""Fixed target-provisioning scenario in an owned signed Ubuntu TCG guest.

Source host metadata is synthetic. The controller-restore scenario additionally
imports an actual isolated MySQL snapshot, never real source-host authority.
This is NOT boot recovery, controller activation or node takeover.
The installer, root APT/systemd/MySQL and target coordinator are actual code.
"""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import select
import socket
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
CODES = set('TARGET_PROVISION_UNCONFIRMED TARGET_COMMAND_REJECTED TARGET_DATABASE_PLAN_CHANGED TARGET_DATABASE_INVENTORY_CHANGED TARGET_PROVISION_MODULE_MISSING TARGET_DEPENDENCIES_UNCONFIRMED TARGET_MYSQL_START_UNCONFIRMED TARGET_DATABASE_CREATE_UNCONFIRMED TARGET_DATABASE_INVENTORY_UNCONFIRMED TARGET_RESTORE_SERVER_INVENTORY_REJECTED TARGET_RESTORE_MAINTENANCE_IDENTITY_REJECTED TARGET_RESTORE_MAINTENANCE_PROVENANCE_REJECTED TARGET_RESTORE_MAINTENANCE_DRIFT_REJECTED TARGET_RESTORE_MAINTENANCE_OUTCOME_UNCONFIRMED TARGET_MATERIALS_UNCONFIRMED'.split())
CODES |= set('TARGET_VERIFICATION_DATA_ALREADY_STARTED TARGET_VERIFICATION_DATA_NOT_STARTED TARGET_VERIFICATION_DATA_APPROVAL_REQUIRED TARGET_VERIFICATION_DATA_APPROVAL_CHANGED TARGET_VERIFICATION_DATA_UNCONFIRMED TARGET_VERIFICATION_IDENTITY_REJECTED TARGET_VERIFICATION_GRANTS_REJECTED TARGET_VERIFICATION_BINDING_REJECTED TARGET_VERIFICATION_CREDENTIAL_REJECTED TARGET_VERIFICATION_CREATE_UNCONFIRMED TARGET_VERIFICATION_ACCOUNT_UNCONFIRMED TARGET_VERIFICATION_APPROVAL_REQUIRED TARGET_VERIFICATION_APPROVAL_CHANGED TARGET_VERIFICATION_CREDENTIAL_UNCONFIRMED TARGET_VERIFICATION_ACCOUNT_CHANGED'.split())
CODES |= set('TARGET_VERIFICATION_REVOCATION_STARTED TARGET_VERIFICATION_REVOCATION_BINDING_REJECTED TARGET_VERIFICATION_REVOCATION_UNCONFIRMED TARGET_VERIFICATION_REVOCATION_NOT_STARTED TARGET_VERIFICATION_CONNECTION_INVENTORY_UNCONFIRMED TARGET_VERIFICATION_SESSIONS_ACTIVE TARGET_VERIFICATION_REVOCATION_APPROVAL_REQUIRED TARGET_VERIFICATION_REVOCATION_APPROVAL_CHANGED'.split())
APT_CODES = set('APT_PLAN_UNSAFE APT_DNS_FAILURE APT_TLS_FAILURE APT_SIGNATURE_FAILURE APT_METADATA_FAILURE APT_PACKAGE_UNAVAILABLE APT_DEPENDENCY_CONFLICT APT_LOCKED APT_COMMAND_REJECTED APT_COMMAND_UNAVAILABLE APT_COMMAND_TIMEOUT APT_OUTPUT_OVERSIZED'.split())


class Refused(Exception):
    def __init__(self, code, *, refusal=None):
        super().__init__(code)
        self.refusal = refusal


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
            error = None
        if not (p.returncode == 1 and not p.stdout and error == {'error': denied}):
            # Never publish argv, stderr, DSNs or arbitrary exception text.
            # A refusal with a different cause is still a failed assertion.
            valid = isinstance(error, dict) and set(error) == {'error'} and isinstance(error['error'], str)
            observed = error['error'] if valid else None
            safe_codes = CODES | APT_CODES
            raise Refused('TARGET_NATIVE_REFUSAL_UNCONFIRMED', refusal={
                'expected': denied if denied in safe_codes else 'unrecognized',
                'observed': observed if observed in safe_codes else 'unrecognized',
                'exit_kind': {0: 'success', 1: 'refused'}.get(p.returncode, 'other'),
                'stdout_empty': not p.stdout, 'error_envelope_valid': valid})
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


INVENTORY_FIELDS = {'current_root', 'root_socket', 'tcp_disabled', 'mysqlx_active', 'roles', 'default_roles',
    'foreign_schemas', 'other_accounts', 'vendor_count', 'vendor_local', 'vendor_root_socket', 'vendor_password'}


def inventory_query(operation):
    """Fixed read-only probe, also executed in the actual private MySQL test."""
    require(re.fullmatch(r'[0-9a-f]{32}', operation) is not None)
    database, runtime, migration = 'aster_cloud_restore_' + operation, 'aster_r_' + operation[:23], 'aster_m_' + operation[:23]
    known = "Host='localhost' AND ((User='root' AND plugin='auth_socket') OR (User IN ('mysql.infoschema','mysql.session','mysql.sys') AND account_locked='Y') OR (User IN ('" + runtime + "','" + migration + "') AND plugin='caching_sha2_password'))"
    query = "SELECT JSON_OBJECT('current_root',CURRENT_USER()='root@localhost','tcp_disabled',@@skip_networking,"
    query += "'root_socket',(SELECT COUNT(*) FROM mysql.user WHERE User='root' AND Host='localhost' AND plugin='auth_socket' AND authentication_string IN ('','root')),"
    query += "'mysqlx_active',(SELECT COUNT(*) FROM information_schema.PLUGINS WHERE PLUGIN_NAME='mysqlx' AND PLUGIN_STATUS='ACTIVE'),"
    query += "'roles',(SELECT COUNT(*) FROM mysql.role_edges),'default_roles',(SELECT COUNT(*) FROM mysql.default_roles),"
    query += "'foreign_schemas',(SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME NOT IN ('mysql','sys','information_schema','performance_schema','" + database + "')),"
    query += "'other_accounts',(SELECT COUNT(*) FROM mysql.user WHERE User<>'debian-sys-maint' AND NOT (" + known + ")),"
    query += "'vendor_count',(SELECT COUNT(*) FROM mysql.user WHERE User='debian-sys-maint'),"
    query += "'vendor_local',(SELECT COUNT(*) FROM mysql.user WHERE User='debian-sys-maint' AND Host='localhost'),"
    query += "'vendor_root_socket',(SELECT COUNT(*) FROM mysql.user WHERE User='debian-sys-maint' AND Host='localhost' AND plugin='auth_socket' AND authentication_string='root'),"
    query += "'vendor_password',(SELECT COUNT(*) FROM mysql.user WHERE User='debian-sys-maint' AND plugin<>'auth_socket' AND account_locked='N'));\n"
    return query


def inventory_counts(raw):
    require(isinstance(raw, bytes) and len(raw) <= 2048, 'inventory_output_bound')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'inventory_json_invalid')
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeError):
        raise Refused('inventory_json_invalid') from None
    require(isinstance(value, dict) and set(value) == INVENTORY_FIELDS, 'inventory_fields_invalid')
    # MySQL JSON_OBJECT can encode a boolean system variable as JSON true/false,
    # unlike COUNT(*). Normalize only the two explicitly boolean expressions.
    for key in ('current_root', 'tcp_disabled'):
        require(type(value[key]) in (int, bool) and value[key] in (0, 1), 'inventory_counts_invalid')
        value[key] = int(value[key])
    require(all(type(v) is int and 0 <= v <= 65535 for v in value.values()), 'inventory_counts_invalid')
    return value


def inventory_diagnostics(operation):
    """Failure-only aggregate observation; never production admission.

    No usernames, authentication strings, credentials, SQL text or raw output
    leave this helper. A vendor-name count is NOT an account allowlist.
    """
    try:
        query = inventory_query(operation)
        p = subprocess.run(['/usr/bin/mysql', '--no-defaults', '--protocol=SOCKET', '--socket=/run/mysqld/mysqld.sock',
            '--user=root', '--batch', '--raw', '--skip-column-names', '--skip-reconnect', '--connect-timeout=3'],
            input=query.encode(), env=ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)
        require(len(p.stdout) <= 2048 and len(p.stderr) <= 2048, 'inventory_output_bound')
        require(p.returncode == 0, 'inventory_command_failed')
        return {'mysql_inventory': inventory_counts(p.stdout)}
    except subprocess.TimeoutExpired:
        return {'mysql_inventory_error': 'inventory_timeout'}
    except Refused as error:
        allowed = {'inventory_output_bound', 'inventory_command_failed', 'inventory_json_invalid',
                   'inventory_fields_invalid', 'inventory_counts_invalid'}
        return {'mysql_inventory_error': str(error) if str(error) in allowed else 'inventory_unavailable'}
    except Exception:
        return {'mysql_inventory_error': 'inventory_unavailable'}


def execute(metadata):
    progress('preflight')
    require(os.geteuid() == 0 and Path('/proc/1/comm').read_text().strip() == 'systemd')
    require(Path('/sys/class/dmi/id/product_name').read_text().strip() in
            ('Standard PC (i440FX + PIIX, 1996)', 'Standard PC (Q35 + ICH9, 2009)'))
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    require(release['ID'].strip('"') == 'ubuntu' and release['VERSION_ID'].strip('"') == metadata['ubuntu'])
    require(not Path('/dev/kvm').exists())
    require(sha(ROOT / 'aster-controller') == metadata['controller_binary_sha256'])
    if metadata['scenario'] == 'controller-provision':
        require(sha(ROOT / 'controller-fixture.test') == metadata['fixture_binary_sha256'])
    for path in ('/var/lib/mysql', '/etc/mysql', '/etc/libvirt', '/var/lib/libvirt', '/opt/aster-cloud',
                 '/var/lib/aster-cloud-installer', '/etc/aster-controller', '/var/lib/aster-controller-restore'):
        require(not Path(path).exists() and not Path(path).is_symlink())
    operation, controller = metadata['nonce'], 'native-target-' + metadata['nonce'][:12]
    inputs = Path('/var/lib/aster-controller-restore') / operation
    inputs.parent.mkdir(mode=0o700)
    inputs.mkdir(mode=0o700)
    scenario = metadata['scenario']
    require(scenario in ('controller-provision', 'controller-restore-data', 'controller-restore-sessions', 'controller-restore-configuration'))
    restoring = scenario != 'controller-provision'
    data_checks = scenario == 'controller-restore-data'
    session_checks = scenario == 'controller-restore-sessions'
    configuration_checks = scenario == 'controller-restore-configuration'
    provision_checks = not restoring or data_checks
    if restoring:
        for name in ('backup.age', 'recovery.key', 'request.json'):
            private(inputs / name, (ROOT / name).read_bytes())
    else:
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
            len(result['plan']['data']['tables']) == 34 and result['plan']['data']['rows'] == (18 if restoring else 12))
    require(not (inputs / 'database').exists())
    seal = Path('/var/lib/aster-controller') / controller / 'target-restore.json'
    state = Path('/var/lib/aster-cloud-installer/controller/state.json')
    before = (sha(seal), sha(state))
    progress('target-provision')
    expected = {'database_provisioned': True, 'target_credentials_verified': True, 'database_restored': False,
                'target_restore_approved': False, 'migration_ready': False}
    require(json.loads(entry('target-provision').stdout) == expected)
    directory = inputs / 'database'
    private_files = ('mysql-provision.json', 'restore-provision.json', 'runtime-mysql-dsn', 'migration-mysql-dsn',
                     'maintenance-auth-intent.json', 'maintenance-auth-verified.json')
    hashes = {name: sha(directory / name) for name in private_files}
    for name in private_files:
        st = (directory / name).lstat()
        require(st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o600 and stat.S_ISREG(st.st_mode) and st.st_nlink == 1)
    run(['/usr/bin/systemctl', 'is-active', '--quiet', 'mysql.service'])
    spec = importlib.util.spec_from_file_location('actual_provision', version / 'templates/host-management/provision.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    database, runtime_user, migration_user = module.restore_database_names(operation)
    if provision_checks:
        progress('target-maintenance')
        # The package-created maintenance account is hardened, not allowlisted by
        # name. Check real peer authentication and refusal without credential reset.
        maintenance = json.loads((directory / 'maintenance-auth-intent.json').read_bytes())
        require(maintenance['before']['mode'] in ('password', 'root-socket'))
        expected_maintenance = {'plugin': 'auth_socket', 'mapping': 'root', 'locked': 'N'}
        maintenance_sql = "SELECT JSON_OBJECT('plugin',plugin,'mapping',authentication_string,'locked',account_locked) FROM mysql.user WHERE User='debian-sys-maint' AND Host='localhost';\n"
        require(module._query(directory, maintenance_sql) == expected_maintenance)
        # Ubuntu's MySQL 8.0 has no --no-login-paths (introduced in 8.4).
        # Use the documented login-file override, as production bootstrap does.
        # Both OS identities can traverse this empty root-owned directory; an
        # inaccessible /root path must not masquerade as an authentication denial.
        client_home = Path('/run') / ('aster-native-mysql-client-' + NONCE)
        client_home.mkdir(mode=0o755)
        client_home.chmod(0o755)
        client_env = {**ENV, 'HOME': str(client_home), 'MYSQL_TEST_LOGIN_FILE': str(client_home / 'absent-login-file')}
        require(not list(client_home.iterdir()))
        maint_command = ['/usr/bin/mysql', '--no-defaults', '--protocol=SOCKET',
            '--socket=/run/mysqld/mysqld.sock', '--user=debian-sys-maint', '--batch', '--raw', '--skip-column-names', '--skip-reconnect', '--connect-timeout=5']
        progress('target-maintenance-root-login')
        require(run(maint_command, env=client_env, data=b'SELECT CURRENT_USER();\n').stdout == b'debian-sys-maint@localhost\n')
        progress('target-maintenance-nonroot-login')
        denied = subprocess.run(['/usr/sbin/runuser', '--preserve-environment', '--user', 'nobody', '--', *maint_command],
            input=b'SELECT CURRENT_USER();\n', env=client_env, cwd='/',
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        require(denied.returncode == 1 and not denied.stdout and re.match(rb'^ERROR (1045|1698) \(28000\)', denied.stderr),
                'TARGET_NATIVE_REFUSAL_UNCONFIRMED')
        require(not list(client_home.iterdir()))
        client_home.rmdir()  # Only the exact empty directory this fixture created.
        # Simulate loss of only the completion acknowledgement: immutable intent
        # plus exact authentication/grants can reconstruct that same confirmation.
        progress('target-maintenance-confirmation')
        confirmation = directory / 'maintenance-auth-verified.json'
        retained_confirmation = ROOT / 'retained-maintenance-confirmation.json'
        confirmation.rename(retained_confirmation)
        require(json.loads(entry('target-provision').stdout) == expected)
        require(sha(confirmation) == sha(retained_confirmation) == hashes['maintenance-auth-verified.json'])
        # Test-owned tampering is restored ONLY by this disposable fixture. The
        # production command must leave every changed credential untouched.
        progress('target-maintenance-drift')
        for alteration in ("IDENTIFIED WITH auth_socket AS 'nobody'", "IDENTIFIED WITH caching_sha2_password BY RANDOM PASSWORD"):
            module.mysql_sql(directory, "ALTER USER 'debian-sys-maint'@'localhost' " + alteration + ";\n")
            changed = module.mysql_sql(directory, "SELECT SHA2(CONCAT(plugin,CHAR(0),authentication_string),256) FROM mysql.user WHERE User='debian-sys-maint' AND Host='localhost';\n")
            entry('target-provision', 'TARGET_RESTORE_MAINTENANCE_IDENTITY_REJECTED' if "'nobody'" in alteration else 'TARGET_RESTORE_MAINTENANCE_DRIFT_REJECTED')
            require(module.mysql_sql(directory, "SELECT SHA2(CONCAT(plugin,CHAR(0),authentication_string),256) FROM mysql.user WHERE User='debian-sys-maint' AND Host='localhost';\n") == changed)
            require({name: sha(directory / name) for name in private_files} == hashes)
            module.mysql_sql(directory, "ALTER USER 'debian-sys-maint'@'localhost' IDENTIFIED WITH auth_socket AS 'root';\n")
        grant_database = database.replace('_', '\\_')
        module.mysql_sql(directory, "GRANT SELECT ON `" + grant_database + "`.* TO 'debian-sys-maint'@'localhost';\n")
        altered_grants = module.mysql_sql(directory, "SHOW GRANTS FOR 'debian-sys-maint'@'localhost';\n")
        entry('target-provision', 'TARGET_RESTORE_MAINTENANCE_DRIFT_REJECTED')
        require(module.mysql_sql(directory, "SHOW GRANTS FOR 'debian-sys-maint'@'localhost';\n") == altered_grants)
        module.mysql_sql(directory, "REVOKE SELECT ON `" + grant_database + "`.* FROM 'debian-sys-maint'@'localhost';\n")
        module.mysql_sql(directory, "CREATE USER 'debian-sys-maint'@'%' ACCOUNT LOCK;\n")
        entry('target-provision', 'TARGET_RESTORE_SERVER_INVENTORY_REJECTED')
        module.mysql_sql(directory, "DROP USER 'debian-sys-maint'@'%';\n")
        # auth_socket permits a same-named OS user as well as AS 'root'. A newly
        # introduced NSS principal must therefore block all further restore steps.
        progress('target-maintenance-nss')
        run(['/usr/sbin/useradd', '--no-create-home', '--no-user-group', '--gid', '65534',
             '--shell', '/usr/sbin/nologin', 'debian-sys-maint'])
        try:
            entry('target-provision', 'TARGET_RESTORE_MAINTENANCE_IDENTITY_REJECTED')
            require(module._query(directory, maintenance_sql) == expected_maintenance)
        finally:
            run(['/usr/sbin/userdel', 'debian-sys-maint'])
        require(json.loads(entry('target-provision').stdout) == expected)
        require({name: sha(directory / name) for name in private_files} == hashes)
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
    if provision_checks:
        progress('resume')
        require(json.loads(entry('target-provision').stdout) == expected)
        require({name: sha(directory / name) for name in private_files} == hashes and (sha(seal), sha(state)) == before)
        progress('target-refusals')
        # Test-owned locked account: production never removes unknown accounts.
        module.mysql_sql(directory, "CREATE USER 'aster_native_foreign'@'localhost' ACCOUNT LOCK;\n")
        entry('target-provision', 'TARGET_RESTORE_SERVER_INVENTORY_REJECTED')
        require({name: sha(directory / name) for name in private_files} == hashes)
        module.mysql_sql(directory, "DROP USER 'aster_native_foreign'@'localhost';\n")
        credentials = directory / 'runtime-mysql-dsn'
        retained = ROOT / 'retained-runtime-dsn'
        before_auth = module.mysql_sql(directory, "SELECT SHA2(authentication_string,256) FROM mysql.user WHERE User='" + runtime_user + "' AND Host='localhost';\n")
        credentials.rename(retained)
        entry('target-provision', 'TARGET_DATABASE_CREATE_UNCONFIRMED')
        require(not credentials.exists() and sha(retained) == hashes['runtime-mysql-dsn'])
        require(module.mysql_sql(directory, "SELECT SHA2(authentication_string,256) FROM mysql.user WHERE User='" + runtime_user + "' AND Host='localhost';\n") == before_auth)
        retained.rename(credentials)
    require((sha(seal), sha(state)) == before and not Path('/etc/aster-controller').exists())
    require(not Path('/etc/systemd/system/aster-controller.service').exists())
    # The empty owned DB remains unactivated, with its real provenance marker.
    info = module._query(directory, "SELECT JSON_OBJECT('tables',COUNT(*)) FROM information_schema.TABLES WHERE TABLE_SCHEMA='" + database + "';\n")
    require(info == {'tables': 1})
    true = 'passed real_apt real_systemd real_mysql actual_installer actual_controller target_sealed exact_encoding_preserved credentials_verified runtime_ddl_denied same_operation_preserved source_fixture_synthetic'.split()
    if provision_checks:
        true += 'foreign_account_refused lost_credential_refused_without_reset maintenance_authentication_verified maintenance_drift_refused maintenance_nonroot_denied'.split()
    false = 'database_restored source_host_export_verified node_takeover_verified migration_ready kvm_ready'.split()
    report = {**{k: True for k in true}, **{k: False for k in false}, 'schema': 1, 'scenario': metadata['scenario'],
              **{k: metadata[k] for k in ('source_sha', 'ubuntu', 'image_sha256')}}
    if restoring:
        if data_checks:
            # Restore the same owned provisioning operation after the deliberate
            # lost-credential refusal, without replacing passwords or the marker.
            require(json.loads(entry('target-provision').stdout) == expected)
            module.mysql_sql(directory, 'CREATE DATABASE aster_native_foreign;\n')
            entry('target-restore', 'TARGET_RESTORE_INVENTORY_UNCONFIRMED')
            require(not (directory / 'import-started.json').exists() and not (directory / 'import-approval.json').exists())
            require(module._query(directory, "SELECT JSON_OBJECT('schemas',COUNT(*)) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='aster_native_foreign';\n") == {'schemas': 1})
            # Only the fixture removes its own foreign DB; production never does.
            module.mysql_sql(directory, 'DROP DATABASE aster_native_foreign;\n')
        progress('target-import')
        if data_checks:
            entry('target-data-status', 'TARGET_IMPORT_NOT_STARTED')
            entry('target-materials', 'TARGET_IMPORT_NOT_STARTED')
            entry('target-revoke-sessions', 'TARGET_IMPORT_NOT_STARTED')
            require(not (inputs / 'runtime').exists() and not (inputs / 'materials-started.json').exists())
        imported = json.loads(entry('target-restore').stdout)
        require(imported == {'schema': 1, 'operation_id': operation, 'database_restored': True,
            'read_only_verification': True, 'target_restore_approved': False, 'migration_ready': False,
            'root_inventory_verified': True, 'data': {'tables': 34, 'rows': 18, 'exact_rows_verified': True,
                'declared_constraints_verified': True, 'provisioning_marker_preserved': True,
                'target_activation_approved': False, 'migration_ready': False}})
        # Independent SQL assertions: binary/empty/NULL, Unicode, microseconds,
        # bigint/uint64, deleted high auto increment and the old session row.
        values = run(runtime_command, data=b"SELECT HEX(capabilities),HEX(datacenter_id),heartbeat_at IS NULL,free_cpu,updated_at FROM controller_nodes WHERE id='node-a';\n").stdout
        require(values == b'00FF000A225C80\tE9A699E6B8AF\t1\t9223372036854775806\t2026-10-28 01:02:03.123456\n')
        require(run(runtime_command, data=b"SELECT LENGTH(capabilities) FROM controller_nodes WHERE id='node-b';\n").stdout == b'0\n')
        require(run(runtime_command, data=b'SELECT revision FROM controller_console_users;\n').stdout == b'18446744073709551614\n')
        require(run(runtime_command, data=b'SELECT COUNT(*) FROM controller_console_sessions;\n').stdout == b'1\n')
        require(run(runtime_command, data=b"SELECT AUTO_INCREMENT FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='controller_audit';\n").stdout == b'42\n')
        if data_checks:
            entry('target-revoke-sessions', 'TARGET_COMMAND_REJECTED')
            require(not (inputs / 'sessions-started.json').exists())
        progress('target-readback')
        records = private_files + ('import-approval.json', 'import-started.json', 'structure.json')
        committed_hashes = {name: sha(directory / name) for name in records}
        module.mysql_sql(directory, 'SET GLOBAL super_read_only=ON;\n')
        try:
            # MySQL itself rejects writes, including privileged writes. A lost
            # response/repeated root invocation must do only exact readback.
            if data_checks:
                require(json.loads(entry('target-restore').stdout) == imported)
                require(json.loads(entry('target-data-status').stdout) == imported)
            progress('target-materials')
            if data_checks:
                entry('target-material-status', 'TARGET_COMMAND_REJECTED')
                require(not (inputs / 'runtime').exists() and not (inputs / 'materials-started.json').exists())
            staged = json.loads(entry('target-materials').stdout)
            require(staged == {'schema': 1, 'operation_id': operation, 'material_references': 6,
                'materials_staged': True, 'read_only_verification': False, 'configuration_published': False,
                'sessions_revoked': False, 'migration_ready': False, 'root_inventory_verified': True,
                'database_restored': True, 'target_restore_approved': False})
            candidate = inputs / 'runtime'
            config = json.loads((candidate / 'config.json').read_bytes())
            require(config['controller_id'] == controller and config['nodes'] == [] and
                    Path(config['dsn_file']).read_bytes() == (directory / 'runtime-mysql-dsn').read_bytes().strip())
            for field, value in (('billing_token_file', b'b' * 64), ('admin_read_token_file', b'r' * 64),
                                 ('admin_write_token_file', b'w' * 64)):
                require(Path(config[field]).parent == candidate and Path(config[field]).read_bytes() == value)
            require(stat.S_IMODE(candidate.stat().st_mode) == 0o700)
            for path in candidate.iterdir():
                st = path.lstat()
                require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and
                        stat.S_IMODE(st.st_mode) == 0o600)
                require(b'aster_source:private-password' not in path.read_bytes())
            stage_hashes = {p.name: sha(p) for p in candidate.iterdir()}
            intent_hash = sha(inputs / 'materials-started.json')
            expected_stage = {**staged, 'read_only_verification': True}
            if data_checks:
                require(json.loads(entry('target-materials').stdout) == expected_stage)
                require(json.loads(entry('target-material-status').stdout) == expected_stage)
            # Staged files do not grant runtime admission, even with a complete
            # valid configuration and real restored database credentials.
            denied_runtime = subprocess.run([str(version / 'bin/aster-controller'), 'check', '-config', str(candidate / 'config.json')],
                env=ENV, capture_output=True, timeout=30)
            require(denied_runtime.returncode == 78 and not denied_runtime.stdout and
                    json.loads(denied_runtime.stderr).get('code') == 'CONTROLLER_MIGRATION_FENCED')
            if data_checks:
                material = Path(config['billing_token_file'])
                original = material.read_bytes()
                try:
                    material.write_bytes(original + b'changed')
                    entry('target-materials', 'TARGET_COMMAND_REJECTED')
                    entry('target-material-status', 'TARGET_COMMAND_REJECTED')
                    require(material.read_bytes() == original + b'changed')
                finally:
                    material.write_bytes(original)  # Fixture-only fault cleanup, not product repair.
            require({p.name: sha(p) for p in candidate.iterdir()} == stage_hashes and
                    sha(inputs / 'materials-started.json') == intent_hash)
        finally:
            module.mysql_sql(directory, 'SET GLOBAL super_read_only=OFF; SET GLOBAL read_only=OFF;\n')
        require({name: sha(directory / name) for name in records} == committed_hashes)
        report.update({key: True for key in ('database_restored', 'real_source_database_snapshot', 'exact_rows_verified',
            'runtime_materials_staged', 'runtime_candidate_remains_fenced')})
        report['session_browser_verified'] = False

        def finish():
            # The actual ordinary runtime remains refused in every scenario;
            # importing, revoking sessions or publishing never grants takeover.
            denied_runtime = subprocess.run([str(version / 'bin/aster-controller'), 'check', '-config', str(candidate / 'config.json')],
                env=ENV, capture_output=True, timeout=30)
            require(denied_runtime.returncode == 78 and not denied_runtime.stdout and
                    json.loads(denied_runtime.stderr).get('code') == 'CONTROLLER_MIGRATION_FENCED')
            require({name: sha(directory / name) for name in records} == committed_hashes and (sha(seal), sha(state)) == before)
            require({p.name: sha(p) for p in candidate.iterdir()} == stage_hashes and sha(inputs / 'materials-started.json') == intent_hash)
            require(Path('/etc/aster-controller').exists() == configuration_checks and
                    not Path('/etc/systemd/system/aster-controller.service').exists())
            return report

        if data_checks:
            entry('target-provision', 'TARGET_IMPORT_ALREADY_STARTED_USE_DATA_STATUS')
            progress('target-data-refusals')
            module.mysql_sql(directory, "UPDATE `" + database + "`.controller_nodes SET datacenter_id='changed' WHERE id='node-a';\n")
            entry('target-data-status', 'TARGET_COMMAND_REJECTED')
            entry('target-restore', 'TARGET_COMMAND_REJECTED')
            entry('target-material-status', 'TARGET_COMMAND_REJECTED')
            require({p.name: sha(p) for p in candidate.iterdir()} == stage_hashes)
            require(run(runtime_command, data=b"SELECT datacenter_id FROM controller_nodes WHERE id='node-a';\n").stdout == b'changed\n')
            module.mysql_sql(directory, "UPDATE `" + database + "`.controller_nodes SET datacenter_id=CONVERT(0xE9A699E6B8AF USING utf8mb4) WHERE id='node-a';\n")
            require(json.loads(entry('target-data-status').stdout) == imported)
            module.mysql_sql(directory, "ALTER TABLE `" + database + "`.controller_console_sessions DROP FOREIGN KEY controller_console_sessions_user_fk;\n")
            entry('target-data-status', 'TARGET_COMMAND_REJECTED')
            entry('target-restore', 'TARGET_COMMAND_REJECTED')
            module.mysql_sql(directory, "ALTER TABLE `" + database + "`.controller_console_sessions ADD CONSTRAINT controller_console_sessions_user_fk FOREIGN KEY(user_id) REFERENCES controller_console_users(id) ON DELETE CASCADE;\n")
            require(json.loads(entry('target-data-status').stdout) == imported)
            report.update({key: True for key in ('read_only_reentry_verified', 'modified_data_refused',
                'removed_constraint_refused', 'foreign_database_refused', 'runtime_material_drift_refused')})
            return finish()
        progress('target-sessions')
        if session_checks:
            entry('target-session-status', 'TARGET_COMMAND_REJECTED')
            require(not (inputs / 'sessions-started.json').exists())
            # Real SQL refusal after durable intent: no row mutation, no automatic
            # retry on ordinary reentry, explicit same-operation resume only.
            module.mysql_sql(directory, 'SET GLOBAL super_read_only=ON;\n')
            try:
                entry('target-revoke-sessions', 'TARGET_COMMAND_REJECTED')
                session_intent = inputs / 'sessions-started.json'
                require(session_intent.is_file() and stat.S_IMODE(session_intent.stat().st_mode) == 0o600)
                session_hash = sha(session_intent)
                entry('target-revoke-sessions', 'TARGET_COMMAND_REJECTED')
                entry('target-session-status', 'TARGET_COMMAND_REJECTED')
                require(run(runtime_command, data=b'SELECT COUNT(*) FROM controller_console_sessions;\n').stdout == b'1\n')
                require(run(runtime_command, data=b'SELECT COUNT(*) FROM controller_identity_audit;\n').stdout == b'0\n')
                require(sha(session_intent) == session_hash)
            finally:
                module.mysql_sql(directory, 'SET GLOBAL super_read_only=OFF; SET GLOBAL read_only=OFF;\n')
        revoked = json.loads(entry('target-session-resume' if session_checks else 'target-revoke-sessions').stdout)
        session_intent = inputs / 'sessions-started.json'
        if session_checks:
            require(sha(session_intent) == session_hash)
        session_hash = sha(session_intent)
        require(revoked == {'schema': 1, 'operation_id': operation, 'revoked_sessions': 1,
            'sessions_revoked': True, 'audit_appended': True, 'exact_database_verified': True,
            'read_only_verification': False, 'target_activation_approved': False, 'migration_ready': False,
            'root_inventory_verified': True, 'database_restored': True, 'target_restore_approved': False})
        readonly_revoked = {**revoked, 'read_only_verification': True}
        if session_checks:
            module.mysql_sql(directory, 'SET GLOBAL super_read_only=ON;\n')
            try:
                require(json.loads(entry('target-session-status').stdout) == readonly_revoked)
                require(json.loads(entry('target-revoke-sessions').stdout) == readonly_revoked)
                require(json.loads(entry('target-material-status').stdout) == {**expected_stage, 'sessions_revoked': True})
                require(run(runtime_command, data=b'SELECT COUNT(*) FROM controller_console_sessions;\n').stdout == b'0\n')
                require(run(runtime_command, data=b'SELECT id,actor,action,target FROM controller_identity_audit;\n').stdout ==
                        ('1\tcontroller-migration\tmigration.sessions_revoked\t' + operation + '\n').encode())
                entry('target-session-resume', 'TARGET_COMMAND_REJECTED')
                # Original-image status must not pretend the intentional session
                # transition left the entire restored database byte-identical.
                entry('target-data-status', 'TARGET_COMMAND_REJECTED')
            finally:
                module.mysql_sql(directory, 'SET GLOBAL super_read_only=OFF; SET GLOBAL read_only=OFF;\n')
            run(runtime_command, data=b"INSERT INTO controller_console_sessions VALUES(UNHEX(REPEAT('42',32)),NULL,'2026-10-28','2027-01-01');\n")
            entry('target-session-status', 'TARGET_COMMAND_REJECTED')
            entry('target-material-status', 'TARGET_COMMAND_REJECTED')
            run(runtime_command, data=b"DELETE FROM controller_console_sessions WHERE token_hash=UNHEX(REPEAT('42',32));\n")
            require(json.loads(entry('target-session-status').stdout) == readonly_revoked)
            require(sha(session_intent) == session_hash and {p.name: sha(p) for p in candidate.iterdir()} == stage_hashes)
            report.update({key: True for key in ('sessions_revoked', 'session_transition_exact_readback', 'session_transition_explicit_recovery')})
            return finish()
        require(configuration_checks)
        report['sessions_revoked'] = True
        progress('target-configuration-plan')
        cert_path, key_path = inputs / 'configuration-tls.crt', inputs / 'configuration-tls.key'
        private(cert_path, b'')
        private(key_path, b'')
        run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'ed25519', '-nodes', '-days', '3',
             '-subj', '/CN=source.invalid', '-addext', 'subjectAltName=DNS:source.invalid',
             '-out', cert_path, '-keyout', key_path])
        request = {'schema': 1, 'operation_id': operation,
                   'target_plan_sha256': json.loads((inputs / 'database-plan.json').read_bytes())['target_plan_sha256'],
                   'console_enabled': True, 'console_origin': 'https://source.invalid:9555',
                   'listen': '127.0.0.1:9555', 'tls_mode': 'replacement'}
        private(inputs / 'configuration-request.json', json.dumps(request, separators=(',', ':')).encode())
        planned = json.loads(entry('target-configuration-plan').stdout)
        require(set(planned) == {'schema','operation_id','plan','plan_sha256','readonly','sessions_revoked','exact_database_verified',
                                'configuration_published','migration_ready','root_inventory_verified','database_restored','target_restore_approved'} and
                all(planned[k] is True for k in ('readonly','sessions_revoked','exact_database_verified','root_inventory_verified','database_restored')) and
                all(planned[k] is False for k in ('configuration_published','migration_ready','target_restore_approved')) and
                planned['schema'] == 1 and planned['operation_id'] == operation)
        config_plan = planned['plan']
        require(config_plan['controller_id'] == controller and config_plan['source_console'] is None and
                config_plan['session_intent_sha256'] == session_hash and
                config_plan['request_sha256'] == sha(inputs / 'configuration-request.json') and
                all(config_plan[k] == request[k] for k in ('target_plan_sha256','console_enabled','console_origin','listen','tls_mode')) and
                [f['name'] for f in config_plan['files']] == ['config.json','console.json','server.crt','server.key'])
        module.mysql_sql(directory, 'SET GLOBAL super_read_only=ON;\n')
        try:
            require(json.loads(entry('target-configuration-plan').stdout) == planned)
        finally:
            module.mysql_sql(directory, 'SET GLOBAL super_read_only=OFF; SET GLOBAL read_only=OFF;\n')
        original_cert = cert_path.read_bytes()
        cert_path.write_bytes(b'unreviewed prefix\n' + original_cert)
        entry('target-configuration-plan', 'TARGET_COMMAND_REJECTED')
        cert_path.write_bytes(original_cert)  # Fixture restores only its own fault.
        run(runtime_command, data=b"INSERT INTO controller_console_sessions VALUES(UNHEX(REPEAT('43',32)),NULL,'2026-10-28','2027-01-01');\n")
        entry('target-configuration-plan', 'TARGET_COMMAND_REJECTED')
        run(runtime_command, data=b"DELETE FROM controller_console_sessions WHERE token_hash=UNHEX(REPEAT('43',32));\n")
        require(not (inputs / 'configuration-started.json').exists() and not (inputs / 'configuration-approval.json').exists() and
                not Path('/etc/aster-controller').exists() and not Path('/etc/systemd/system/aster-controller.service').exists() and
                sha(session_intent) == session_hash and {p.name: sha(p) for p in candidate.iterdir()} == stage_hashes)
        progress('target-configuration-publish')
        entry('target-configuration-publish', 'TARGET_COMMAND_REJECTED')
        approval = {'schema':1,'operation_id':operation,'target_plan_sha256':config_plan['target_plan_sha256'],
                    'configuration_plan_sha256':planned['plan_sha256']}
        private(inputs / 'configuration-approval.json', json.dumps(approval,separators=(',',':')).encode())
        destination = Path('/etc/aster-controller')
        destination.mkdir(mode=0o700)
        entry('target-configuration-publish', 'TARGET_COMMAND_REJECTED')
        require(not (inputs / 'configuration-started.json').exists() and not list(destination.iterdir()))
        destination.rmdir()  # Only the empty directory injected by this fixture.
        published = json.loads(entry('target-configuration-publish').stdout)
        require(set(published) == {'schema','operation_id','plan','plan_sha256','intent_sha256','read_only_verification',
                                  'configuration_published','target_activation_approved','migration_ready','sessions_revoked',
                                  'exact_database_verified','root_inventory_verified','database_restored','target_restore_approved'} and
                published['schema']==1 and published['operation_id']==operation and published['plan']==config_plan and
                published['plan_sha256']==planned['plan_sha256'] and
                all(published[k] is True for k in ('configuration_published','sessions_revoked','exact_database_verified','root_inventory_verified','database_restored')) and
                all(published[k] is False for k in ('read_only_verification','target_activation_approved','migration_ready','target_restore_approved')) and
                published['intent_sha256']==sha(inputs/'configuration-started.json'))
        publication_hashes = {p.name:sha(p) for p in destination.iterdir()}
        require(set(publication_hashes)=={'config.json','console.json','server.crt','server.key','manifest.json'} and
                all(publication_hashes[f['name']]==f['sha256'] for f in config_plan['files']))
        readonly_published = {**published,'read_only_verification':True}
        verification_inputs = {str(p.relative_to(inputs)):sha(p) for p in inputs.rglob('*') if p.is_file()}
        module.mysql_sql(directory, 'SET GLOBAL super_read_only=ON;\n')
        try:
            require(json.loads(entry('target-configuration-status').stdout)==readonly_published)
            require(json.loads(entry('target-configuration-publish').stdout)==readonly_published)
            verification = json.loads(entry('target-verification-plan').stdout)
            require(set(verification) == {'schema','operation_id','plan','plan_sha256','readonly','exact_database_verified',
                                         'configuration_published','sql_identity_prepared','service_started','migration_ready','root_inventory_verified'} and
                    verification['schema'] == 1 and verification['operation_id'] == operation and
                    all(verification[k] is True for k in ('readonly','exact_database_verified','configuration_published','root_inventory_verified')) and
                    all(verification[k] is False for k in ('sql_identity_prepared','service_started','migration_ready')))
            vp = verification['plan']
            require(vp['controller_id'] == controller and vp['operation_id'] == operation and
                    vp['target_plan_sha256'] == request['target_plan_sha256'] and
                    vp['configuration_plan_sha256'] == planned['plan_sha256'] and
                    vp['configuration_intent_sha256'] == published['intent_sha256'] and vp['session_intent_sha256'] == session_hash and
                    vp['console_origin'] == request['console_origin'] and vp['listen'] == request['listen'] and
                    vp['sql']['user'] == 'aster_v_' + operation[:23] and vp['sql']['database'] == 'aster_cloud_restore_' + operation and
                    len(vp['sql']['grants']) == 4)
        finally:
            module.mysql_sql(directory, 'SET GLOBAL super_read_only=OFF; SET GLOBAL read_only=OFF;\n')
        require({str(p.relative_to(inputs)):sha(p) for p in inputs.rglob('*') if p.is_file()} == verification_inputs)
        require(module.mysql_sql(directory, "SELECT COUNT(*) FROM mysql.user WHERE User='aster_v_"+operation[:23]+"';\n").strip() == b'0')
        entry('target-configuration-resume', 'TARGET_COMMAND_REJECTED')
        # Model a reachable pre-rename interruption with this fixture's own
        # bytes and original durable intent; this is not a power-cut test.
        stage = Path('/etc') / ('.aster-controller-configuration-' + operation)
        destination.rename(stage)
        (stage/'manifest.json').unlink()
        (stage/'console.json').unlink()
        entry('target-configuration-status','TARGET_COMMAND_REJECTED')
        entry('target-configuration-publish','TARGET_COMMAND_REJECTED')
        require(not (stage/'console.json').exists() and not destination.exists())
        require(json.loads(entry('target-configuration-resume').stdout)==published)
        require({p.name:sha(p) for p in destination.iterdir()}==publication_hashes and not stage.exists())
        config_bytes=(destination/'config.json').read_bytes()
        (destination/'config.json').write_bytes(config_bytes+b' ')
        entry('target-configuration-status','TARGET_COMMAND_REJECTED')
        entry('target-verification-plan','TARGET_COMMAND_REJECTED')
        require((destination/'config.json').read_bytes()==config_bytes+b' ')
        (destination/'config.json').write_bytes(config_bytes)
        progress('target-verification-account')
        vuser = 'aster_v_' + operation[:23]
        verification_names = ('verification-started.json','verification-mysql-dsn','verification-account.json')
        before_verification = {str(p.relative_to(inputs)):sha(p) for p in inputs.rglob('*') if p.is_file()}
        entry('target-verification-prepare','TARGET_VERIFICATION_APPROVAL_REQUIRED')
        require(not any((directory/name).exists() for name in verification_names))
        require(module._query(directory,"SELECT JSON_OBJECT('n',COUNT(*)) FROM mysql.user WHERE User='"+vuser+"';\n") == {'n':0})
        private(inputs/'verification-approval.json',json.dumps({'schema':1,'operation_id':operation,'plan_sha256':verification['plan_sha256']},separators=(',',':')).encode())
        # A collision is foreign, even if the username happens to be derived
        # from this operation. Never reset/adopt it or create an intent for it.
        module.mysql_sql(directory,"CREATE USER '"+vuser+"'@'localhost' IDENTIFIED BY RANDOM PASSWORD;\n")
        account_auth_sql = "SELECT SHA2(authentication_string,256) FROM mysql.user WHERE User='"+vuser+"' AND Host='localhost';\n"
        foreign_auth = module.mysql_sql(directory,account_auth_sql)
        entry('target-verification-prepare','TARGET_RESTORE_SERVER_INVENTORY_REJECTED')
        require(not any((directory/name).exists() for name in verification_names) and module.mysql_sql(directory,account_auth_sql)==foreign_auth)
        module.mysql_sql(directory,"DROP USER '"+vuser+"'@'localhost';\n")  # fixture owns this injected account
        progress('target-verification-create-and-authenticate')
        prepared = json.loads(entry('target-verification-prepare').stdout)
        expected_verification = {'schema':1,'operation_id':operation,'plan_sha256':verification['plan_sha256'],
            'credential_verified':True,'sql_identity_verified':True,'exact_database_verified':True,
            'service_started':False,'migration_ready':False,'read_only_verification':False,
            'sql_identity_prepared':True,'root_inventory_verified':True}
        require(prepared == expected_verification)
        prepared_hashes = {name:sha(directory/name) for name in verification_names}
        for name in verification_names:
            st = (directory/name).lstat()
            require(st.st_uid==0 and st.st_nlink==1 and stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode)==0o600)
        actual_auth = module.mysql_sql(directory,account_auth_sql)
        progress('target-verification-readonly-reentry')
        readonly_verification = {**expected_verification,'read_only_verification':True}
        module.mysql_sql(directory,'SET GLOBAL super_read_only=ON;\n')
        try:
            require(json.loads(entry('target-verification-status').stdout)==readonly_verification)
            require(json.loads(entry('target-verification-prepare').stdout)==expected_verification)
            # Lost completion ACK is recoverable by exact readback, but status
            # itself never creates the receipt. No SQL password/grant writes.
            completed = directory/'verification-account.json'
            retained = ROOT/'retained-verification-account.json'
            completed.rename(retained)
            entry('target-verification-status','TARGET_VERIFICATION_ACCOUNT_UNCONFIRMED')
            require(not completed.exists())
            require(json.loads(entry('target-verification-prepare').stdout)==expected_verification)
            require(completed.read_bytes()==retained.read_bytes())
            retained.unlink()
        finally:
            module.mysql_sql(directory,'SET GLOBAL super_read_only=OFF; SET GLOBAL read_only=OFF;\n')
        require({name:sha(directory/name) for name in verification_names}==prepared_hashes and module.mysql_sql(directory,account_auth_sql)==actual_auth)
        # Exact SQL policy is fail-closed; neither status nor prepare silently
        # removes an excessive grant or restores a missing privilege.
        progress('target-verification-grant-drift')
        account = "'"+vuser+"'@'localhost'"
        grant_target = '`'+database+'`.controller_console_users'
        module.mysql_sql(directory,'GRANT UPDATE ON '+grant_target+' TO '+account+';\n')
        extra_grants = module.mysql_sql(directory,'SHOW GRANTS FOR '+account+';\n')
        entry('target-verification-status','TARGET_VERIFICATION_GRANTS_REJECTED')
        entry('target-verification-prepare','TARGET_VERIFICATION_GRANTS_REJECTED')
        require(module.mysql_sql(directory,'SHOW GRANTS FOR '+account+';\n')==extra_grants)
        module.mysql_sql(directory,'REVOKE UPDATE ON '+grant_target+' FROM '+account+';\n')
        progress('target-verification-credential-drift')
        credential_path = directory/'verification-mysql-dsn'
        credential_raw = credential_path.read_bytes()
        credential_path.write_bytes((vuser+':'+'wrong-password-value-not-a-secret'+'@unix(/run/mysqld/mysqld.sock)/'+database+'\n').encode())
        entry('target-verification-prepare','TARGET_COMMAND_REJECTED')
        require(module.mysql_sql(directory,account_auth_sql)==actual_auth and sha(directory/'verification-account.json')==prepared_hashes['verification-account.json'])
        credential_path.write_bytes(credential_raw)
        module.mysql_sql(directory,"CREATE USER '"+vuser+"'@'127.0.0.1' IDENTIFIED BY RANDOM PASSWORD;\n")
        entry('target-verification-status','TARGET_RESTORE_SERVER_INVENTORY_REJECTED')
        module.mysql_sql(directory,"DROP USER '"+vuser+"'@'127.0.0.1';\n")  # fixture-owned fault only
        require(json.loads(entry('target-verification-status').stdout)==readonly_verification)
        require({name:sha(directory/name) for name in verification_names}==prepared_hashes)
        require(all(sha(inputs/name)==value for name,value in before_verification.items()))
        require((sha(seal),sha(state))==before and {p.name:sha(p) for p in destination.iterdir()}==publication_hashes)
        progress('target-verification-data-phase')
        entry('target-verification-data-status','TARGET_VERIFICATION_DATA_NOT_STARTED')
        entry('target-verification-runtime-check','TARGET_VERIFICATION_DATA_NOT_STARTED')
        entry('target-verification-data-begin','TARGET_VERIFICATION_DATA_APPROVAL_REQUIRED')
        require(not (inputs/'verification-data-started.json').exists())
        phase_start=datetime.now(timezone.utc)-timedelta(seconds=1)
        phase_approval={'schema':1,'operation_id':operation,
            'verification_plan_sha256':verification['plan_sha256'],
            'account_receipt_sha256':prepared_hashes['verification-account.json'],
            'started_at':phase_start.isoformat().replace('+00:00','Z'),
            'expires_at':(phase_start+timedelta(minutes=45)).isoformat().replace('+00:00','Z')}
        phase_approval_raw=json.dumps(phase_approval,separators=(',',':')).encode()
        private(inputs/'verification-data-approval.json',phase_approval_raw)
        phase=json.loads(entry('target-verification-data-begin').stdout)
        require(set(phase)=={'schema','operation_id','plan','plan_sha256','account_receipt_sha256','started_at','expires_at',
                'data','read_only_verification','service_started','migration_ready','root_inventory_verified'} and
                type(phase['schema']) is int and phase['schema']==1 and phase['operation_id']==operation and
                phase['plan']==verification['plan'] and phase['plan_sha256']==verification['plan_sha256'] and
                phase['account_receipt_sha256']==prepared_hashes['verification-account.json'] and
                phase['started_at']==phase_approval['started_at'] and phase['expires_at']==phase_approval['expires_at'] and
                phase['read_only_verification'] is False and phase['service_started'] is False and
                phase['migration_ready'] is False and phase['root_inventory_verified'] is True)
        phase_intent=inputs/'verification-data-started.json'
        phase_hash=sha(phase_intent)
        require(phase['data']=={'schema':1,'operation_id':operation,'phase_intent_sha256':phase_hash,
                'business_data_unchanged':True,'historical_audit_preserved':True,'authentication_data_validated':True,
                'read_only_verification':True,'current_sessions':0,'current_login_buckets':0,'appended_audit_rows':0,
                'target_activation_approved':False,'migration_ready':False})
        st=phase_intent.lstat()
        require(st.st_uid==0 and st.st_nlink==1 and stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode)==0o600)
        entry('target-verification-data-begin','TARGET_VERIFICATION_DATA_ALREADY_STARTED')
        require(sha(phase_intent)==phase_hash)
        def runtime_check(expected_phase):
            proof=json.loads(entry('target-verification-runtime-check').stdout)
            expected={'schema':1,'operation_id':operation,
                'phase':{k:v for k,v in expected_phase.items() if k!='root_inventory_verified'},
                'credential_verified':True,'sql_identity_verified':True,'readonly':True,
                'service_started':False,'migration_ready':False,'root_inventory_verified':True}
            require(proof==expected and type(proof['schema']) is int and
                all(type(proof[k]) is bool for k in ('credential_verified','sql_identity_verified','readonly',
                    'service_started','migration_ready','root_inventory_verified')) and sha(phase_intent)==phase_hash)
            require({name:sha(directory/name) for name in verification_names}==prepared_hashes)
        runtime_check({**phase,'read_only_verification':True})
        raw=(directory/'verification-mysql-dsn').read_text()
        prefix,suffix=vuser+':','@unix(/run/mysqld/mysqld.sock)/'+database+'\n'
        require(raw.startswith(prefix) and raw.endswith(suffix))
        password=raw[len(prefix):-len(suffix)].replace('\\','\\\\').replace('"','\\"')
        client_option=ROOT/'verification-test-client.cnf'
        private(client_option,('[client]\nuser='+vuser+'\npassword="'+password+'"\n').encode())
        del password,raw
        verification_client=['/usr/bin/mysql','--defaults-file='+str(client_option),'--protocol=SOCKET',
            '--socket=/run/mysqld/mysqld.sock','--database='+database,'--batch','--raw','--skip-column-names',
            '--skip-reconnect','--connect-timeout=5','--unbuffered']
        # Actual least-privilege SQL writes exercise the data transition, not
        # a browser login or permission to start a controller process.
        run(verification_client,data=b"INSERT INTO controller_console_sessions VALUES(UNHEX(REPEAT('44',32)),NULL,UTC_TIMESTAMP(6),DATE_ADD(UTC_TIMESTAMP(6),INTERVAL 10 MINUTE)); INSERT INTO controller_console_login_limits VALUES(UNHEX(REPEAT('45',32)),UTC_TIMESTAMP(6),1); INSERT INTO controller_identity_audit(actor,action,target,created_at) VALUES('anonymous','identity.login_failed',REPEAT('f',64),UTC_TIMESTAMP(6));\n")
        phase_readonly={**phase,'read_only_verification':True,
            'data':{**phase['data'],'current_sessions':1,'current_login_buckets':1,'appended_audit_rows':1}}
        require(json.loads(entry('target-verification-data-status').stdout)==phase_readonly)
        # The old entry must remain exact-image strict. Only the new preflight
        # combines full original-phase validation with real credential login.
        old_check=subprocess.run([str(version/'bin/aster-controller'),
            'migration-target-verification-credential-check','-operation',operation],
            env=ENV,capture_output=True,timeout=1860)
        require(old_check.returncode==1 and not old_check.stdout and
            json.loads(old_check.stderr).get('code')=='COMMAND_FAILED')
        runtime_check(phase_readonly)
        runtime_check(phase_readonly)  # no intent rewrite or deadline extension
        progress('target-verification-isolated-process')
        require(sha(ROOT/'verification-process.test') == metadata['verification_process_fixture_sha256'])
        spec = importlib.util.spec_from_file_location('native_verification_process', ROOT/'verification-process-native.py')
        process_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(process_module)
        process_module.accept(ROOT, inputs, controller, operation, module, directory, require, progress)
        # The actual HTTP tests used no login/CSRF creation; original auth and
        # business proofs must remain exactly at the prior phase, without reset.
        runtime_check(phase_readonly)
        entry('target-verification-prepare','TARGET_VERIFICATION_DATA_ALREADY_STARTED')
        entry('target-verification-status','TARGET_VERIFICATION_DATA_ALREADY_STARTED')
        progress('target-verification-data-drift')
        module.mysql_sql(directory,"UPDATE `"+database+"`.controller_nodes SET datacenter_id='changed' WHERE id='node-a';\n")
        entry('target-verification-data-status','TARGET_COMMAND_REJECTED')
        entry('target-verification-runtime-check','TARGET_COMMAND_REJECTED')
        module.mysql_sql(directory,"UPDATE `"+database+"`.controller_nodes SET datacenter_id=CONVERT(0xE9A699E6B8AF USING utf8mb4) WHERE id='node-a';\n")
        require(json.loads(entry('target-verification-data-status').stdout)==phase_readonly)
        (inputs/'verification-data-approval.json').write_bytes(json.dumps({**phase_approval,'account_receipt_sha256':'0'*64},separators=(',',':')).encode())
        entry('target-verification-data-status','TARGET_COMMAND_REJECTED')
        entry('target-verification-runtime-check','TARGET_COMMAND_REJECTED')
        require(sha(phase_intent)==phase_hash)
        (inputs/'verification-data-approval.json').write_bytes(phase_approval_raw)
        module.mysql_sql(directory,'SET GLOBAL super_read_only=ON;\n')
        try:
            require(json.loads(entry('target-verification-data-status').stdout)==phase_readonly)
            runtime_check(phase_readonly)
        finally:
            module.mysql_sql(directory,'SET GLOBAL super_read_only=OFF; SET GLOBAL read_only=OFF;\n')
        progress('target-verification-revoke-plan')
        revoke_plan = json.loads(entry('target-verification-revoke-plan').stdout)
        require(set(revoke_plan)=={'schema','operation_id','plan','plan_sha256','readonly','service_started','migration_ready'} and
                revoke_plan['schema']==1 and revoke_plan['operation_id']==operation and revoke_plan['readonly'] is True and
                revoke_plan['service_started'] is False and revoke_plan['migration_ready'] is False)
        require(revoke_plan['plan']=={'schema':1,'protocol':'aster.controller-verification-revocation/1',
            'operation_id':operation,'verification_plan_sha256':verification['plan_sha256'],
            'account_receipt_sha256':prepared_hashes['verification-account.json'],'database':database,'user':vuser})
        entry('target-verification-revoke','TARGET_VERIFICATION_REVOCATION_APPROVAL_REQUIRED')
        require(not (directory/'verification-revoke-started.json').exists())
        private(inputs/'verification-revoke-approval.json',json.dumps({'schema':1,'operation_id':operation,
                'revocation_plan_sha256':revoke_plan['plan_sha256']},separators=(',',':')).encode())
        entry('target-verification-revoke-status','TARGET_VERIFICATION_REVOCATION_NOT_STARTED')
        # Hold a real authenticated session, explicitly without thread event
        # instrumentation. Locking new logins must not be mistaken for drain.
        held=subprocess.Popen(verification_client,env=ENV,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        def held_query(sql):
            held.stdin.write(sql)
            held.stdin.flush()
            require(select.select([held.stdout],[],[],10)[0], 'TARGET_VERIFICATION_HELD_SESSION_UNCONFIRMED')
            value=held.stdout.readline()
            require(0<len(value)<=256,'TARGET_VERIFICATION_HELD_SESSION_UNCONFIRMED')
            return value
        try:
            require(held_query(b'SELECT CURRENT_USER();\n')==(vuser+'@localhost\n').encode())
            module.mysql_sql(directory,"UPDATE performance_schema.threads SET INSTRUMENTED='NO',HISTORY='NO' WHERE BINARY PROCESSLIST_USER='"+vuser+"';\n")
            progress('target-verification-revoke-active-session')
            entry('target-verification-revoke','TARGET_VERIFICATION_SESSIONS_ACTIVE')
            require(not (directory/'verification-revoked.json').exists())
            require(held_query(b'SELECT 17;\n')==b'17\n')  # no KILL or fake drain
            login=subprocess.run(verification_client,input=b'SELECT 1;\n',env=ENV,capture_output=True,timeout=20)
            require(login.returncode==1 and not login.stdout and re.match(rb'^ERROR 3118 \(HY000\)',login.stderr),
                    'TARGET_VERIFICATION_LOCK_DENIAL_UNCONFIRMED')
        finally:
            if held.stdin is not None:held.stdin.close();held.stdin=None
            try:held.wait(timeout=15)
            except subprocess.TimeoutExpired:
                held.terminate();held.wait(timeout=10)
            held.stdout.close();held.stderr.close()
            client_option.unlink()
        require(held.returncode==0)
        require(sha(directory/'verification-revoke-started.json')==revoke_plan['plan_sha256'])
        entry('target-verification-prepare','TARGET_VERIFICATION_REVOCATION_STARTED')
        # Ubuntu's actual MySQL 8.0 GTID daemon is not a client connection.
        # Require the independent positive shape, not absence by assumption.
        progress('target-verification-revoke-pending-auth')
        inventory = module.verification_connection_inventory(directory,vuser)
        require(inventory['active']==0 and inventory['pending']==0 and inventory['internal_gtid']==1,
                'TARGET_VERIFICATION_CONNECTION_INVENTORY_UNCONFIRMED')
        pending = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        pending.settimeout(10)
        connect_timeout = module._query(directory,"SELECT JSON_OBJECT('value',@@global.connect_timeout);\n")['value']
        require(type(connect_timeout) is int and 2<=connect_timeout<=31536000)
        try:
            # This deliberately incomplete handshake must outlive the full
            # archive verification under TCG. Only this owned fixture changes
            # its server timeout; production settings and job budgets do not.
            module.mysql_sql(directory,'SET GLOBAL connect_timeout=300;\n')
            pending.connect('/run/mysqld/mysqld.sock')
            greeting = pending.recv(4096)
            require(len(greeting)>5 and greeting[4]==10,'TARGET_VERIFICATION_CONNECTION_INVENTORY_UNCONFIRMED')
            inventory = module.verification_connection_inventory(directory,vuser)
            require(inventory['active']==0 and inventory['pending']==1 and inventory['internal_gtid']==1,
                    'TARGET_VERIFICATION_CONNECTION_INVENTORY_UNCONFIRMED')
            entry('target-verification-revoke-status','TARGET_VERIFICATION_SESSIONS_ACTIVE')
            require(not (directory/'verification-revoked.json').exists())
        finally:
            pending.close()
            module.mysql_sql(directory,'SET GLOBAL connect_timeout='+str(connect_timeout)+';\n')
        progress('target-verification-revoke-readonly-recovery')
        module.mysql_sql(directory,'SET GLOBAL super_read_only=ON;\n')
        try:
            # The lock is already effective. Status refuses missing completion;
            # explicit original revoke records only the verified outcome, with
            # SQL writes prohibited by MySQL itself.
            entry('target-verification-revoke-status','TARGET_VERIFICATION_REVOCATION_UNCONFIRMED')
            revoked=json.loads(entry('target-verification-revoke').stdout)
            expected_revoked={'schema':1,'operation_id':operation,'revocation_intent_sha256':revoke_plan['plan_sha256'],
                'account_receipt_sha256':prepared_hashes['verification-account.json'],'account_locked':True,
                'active_connections':0,'pending_authentication':0,'read_only_verification':False,
                'sql_identity_revoked':True,'service_started':False,'migration_ready':False,'root_inventory_verified':True}
            require(revoked==expected_revoked)
            revoked_sha=sha(directory/'verification-revoked.json')
            require(json.loads(entry('target-verification-revoke-status').stdout)=={**expected_revoked,'read_only_verification':True})
            require(json.loads(entry('target-verification-revoke').stdout)==expected_revoked and sha(directory/'verification-revoked.json')==revoked_sha)
            require(json.loads(entry('target-verification-data-status').stdout)==phase_readonly and sha(phase_intent)==phase_hash)
            entry('target-verification-runtime-check','TARGET_VERIFICATION_REVOCATION_STARTED')
        finally:
            module.mysql_sql(directory,'SET GLOBAL super_read_only=OFF; SET GLOBAL read_only=OFF;\n')
        progress('target-verification-revoke-drift')
        module.mysql_sql(directory,'ALTER USER '+account+' ACCOUNT UNLOCK;\n')  # fixture fault, never production
        entry('target-verification-revoke','TARGET_VERIFICATION_REVOCATION_BINDING_REJECTED')
        require(module._query(directory,"SELECT JSON_OBJECT('locked',account_locked) FROM mysql.user WHERE BINARY User='"+vuser+"';\n")=={'locked':'N'})
        module.mysql_sql(directory,'ALTER USER '+account+' ACCOUNT LOCK;\n')  # undo only the injected fault
        require({name:sha(directory/name) for name in verification_names}==prepared_hashes and module.mysql_sql(directory,account_auth_sql)==actual_auth)
        require(all(sha(inputs/name)==value for name,value in before_verification.items()))
        denied_published = subprocess.run([str(version/'bin/aster-controller'),'check','-config',str(destination/'config.json')],env=ENV,capture_output=True,timeout=30)
        require(denied_published.returncode==78 and not denied_published.stdout and
                json.loads(denied_published.stderr).get('code')=='CONTROLLER_MIGRATION_FENCED')
        require(not Path('/etc/systemd/system/aster-controller.service').exists() and
                sha(session_intent)==session_hash and {p.name:sha(p) for p in candidate.iterdir()}==stage_hashes)
        report.update({key: True for key in ('configuration_plan_verified', 'configuration_plan_readonly',
            'configuration_plan_tls_drift_refused', 'configuration_plan_requires_exact_session_postimage',
            'configuration_published', 'configuration_publication_readonly', 'configuration_partial_resume_verified',
            'published_configuration_remains_fenced', 'verification_sql_plan_bound_readonly',
            'verification_account_prepared', 'verification_account_exact_grants', 'verification_account_readonly_reentry',
            'verification_account_foreign_refused', 'verification_account_drift_not_repaired', 'verification_credential_authenticated',
            'verification_revocation_locked', 'verification_revocation_active_session_refused',
            'verification_revocation_readonly_recovery', 'verification_revocation_no_implicit_unlock',
            'verification_revocation_pending_auth_refused', 'verification_revocation_internal_thread_classified',
            'verification_data_phase_bound', 'verification_data_auth_delta_validated', 'verification_data_drift_refused',
            'verification_data_immutable_intent', 'verification_data_revocation_compatible',
            'verification_runtime_credential_revalidated', 'verification_runtime_preserves_original_phase',
            'verification_runtime_drift_and_revocation_refused', 'verification_isolated_https_sql',
            'verification_nonroot_no_new_privileges', 'verification_network_namespace_isolated',
            'verification_stop_expiry_parent_death_drained')})
        return finish()
    return report


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
        if report['code'] == 'TARGET_RESTORE_SERVER_INVENTORY_REJECTED' or report['code'].startswith('TARGET_RESTORE_MAINTENANCE_'):
            report['diagnostics'] = inventory_diagnostics(NONCE)
        if isinstance(error, Refused) and error.refusal is not None:
            report.setdefault('diagnostics', {})['refusal'] = error.refusal
    with open('/dev/ttyS0', 'w') as console:
        console.write('ASTER_LIBVIRT_NATIVE_RESULT_' + NONCE + ' ' + base64.b64encode(json.dumps(report).encode()).decode() + '\n')
        console.flush()
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""Fixed target-provisioning scenario in an owned signed Ubuntu TCG guest.

Source host metadata is synthetic. The controller-restore scenario additionally
imports an actual isolated MySQL snapshot, never real source-host authority.
This is NOT boot recovery, controller activation or node takeover.
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
CODES = set('TARGET_PROVISION_UNCONFIRMED TARGET_COMMAND_REJECTED TARGET_DATABASE_PLAN_CHANGED TARGET_DATABASE_INVENTORY_CHANGED TARGET_PROVISION_MODULE_MISSING TARGET_DEPENDENCIES_UNCONFIRMED TARGET_MYSQL_START_UNCONFIRMED TARGET_DATABASE_CREATE_UNCONFIRMED TARGET_DATABASE_INVENTORY_UNCONFIRMED TARGET_RESTORE_SERVER_INVENTORY_REJECTED TARGET_RESTORE_MAINTENANCE_IDENTITY_REJECTED TARGET_RESTORE_MAINTENANCE_PROVENANCE_REJECTED TARGET_RESTORE_MAINTENANCE_DRIFT_REJECTED TARGET_RESTORE_MAINTENANCE_OUTCOME_UNCONFIRMED'.split())
APT_CODES = set('APT_PLAN_UNSAFE APT_DNS_FAILURE APT_TLS_FAILURE APT_SIGNATURE_FAILURE APT_METADATA_FAILURE APT_PACKAGE_UNAVAILABLE APT_DEPENDENCY_CONFLICT APT_LOCKED APT_COMMAND_REJECTED APT_COMMAND_UNAVAILABLE APT_COMMAND_TIMEOUT APT_OUTPUT_OVERSIZED'.split())


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
    restoring = metadata['scenario'] == 'controller-restore'
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
    progress('target-maintenance')
    # The package-created maintenance account is hardened, not allowlisted by
    # name. Check real peer authentication and refusal without credential reset.
    maintenance = json.loads((directory / 'maintenance-auth-intent.json').read_bytes())
    require(maintenance['before']['mode'] in ('password', 'root-socket'))
    expected_maintenance = {'plugin': 'auth_socket', 'mapping': 'root', 'locked': 'N'}
    maintenance_sql = "SELECT JSON_OBJECT('plugin',plugin,'mapping',authentication_string,'locked',account_locked) FROM mysql.user WHERE User='debian-sys-maint' AND Host='localhost';\n"
    require(module._query(directory, maintenance_sql) == expected_maintenance)
    maint_command = ['/usr/bin/mysql', '--no-defaults', '--no-login-paths', '--protocol=SOCKET',
        '--socket=/run/mysqld/mysqld.sock', '--user=debian-sys-maint', '--batch', '--raw', '--skip-column-names', '--skip-reconnect', '--connect-timeout=5']
    require(run(maint_command, data=b'SELECT CURRENT_USER();\n').stdout == b'debian-sys-maint@localhost\n')
    denied = subprocess.run(['/usr/sbin/runuser', '--user', 'nobody', '--', *maint_command],
        input=b'SELECT CURRENT_USER();\n', env={**ENV, 'HOME': '/nonexistent'}, cwd='/',
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    require(denied.returncode == 1 and not denied.stdout and re.match(rb'^ERROR (1045|1698) \(28000\)', denied.stderr),
            'TARGET_NATIVE_REFUSAL_UNCONFIRMED')
    # Simulate loss of only the completion acknowledgement: immutable intent
    # plus exact authentication/grants can reconstruct that same confirmation.
    confirmation = directory / 'maintenance-auth-verified.json'
    retained_confirmation = ROOT / 'retained-maintenance-confirmation.json'
    confirmation.rename(retained_confirmation)
    require(json.loads(entry('target-provision').stdout) == expected)
    require(sha(confirmation) == sha(retained_confirmation) == hashes['maintenance-auth-verified.json'])
    # Test-owned tampering is restored ONLY by this disposable fixture. The
    # production command must leave every changed credential untouched.
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
    true = 'passed real_apt real_systemd real_mysql actual_installer actual_controller target_sealed exact_encoding_preserved credentials_verified runtime_ddl_denied foreign_account_refused lost_credential_refused_without_reset same_operation_preserved maintenance_authentication_verified maintenance_drift_refused maintenance_nonroot_denied source_fixture_synthetic'.split()
    false = 'database_restored source_host_export_verified node_takeover_verified migration_ready kvm_ready'.split()
    report = {**{k: True for k in true}, **{k: False for k in false}, 'schema': 1, 'scenario': metadata['scenario'],
              **{k: metadata[k] for k in ('source_sha', 'ubuntu', 'image_sha256')}}
    if restoring:
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
        entry('target-data-status', 'TARGET_IMPORT_NOT_STARTED')
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
        progress('target-readback')
        records = private_files + ('import-approval.json', 'import-started.json', 'structure.json')
        committed_hashes = {name: sha(directory / name) for name in records}
        module.mysql_sql(directory, 'SET GLOBAL super_read_only=ON;\n')
        try:
            # MySQL itself rejects writes, including privileged writes. A lost
            # response/repeated root invocation must do only exact readback.
            require(json.loads(entry('target-restore').stdout) == imported)
            require(json.loads(entry('target-data-status').stdout) == imported)
        finally:
            module.mysql_sql(directory, 'SET GLOBAL super_read_only=OFF; SET GLOBAL read_only=OFF;\n')
        require({name: sha(directory / name) for name in records} == committed_hashes)
        entry('target-provision', 'TARGET_IMPORT_ALREADY_STARTED_USE_DATA_STATUS')
        progress('target-data-refusals')
        module.mysql_sql(directory, "UPDATE `" + database + "`.controller_nodes SET datacenter_id='changed' WHERE id='node-a';\n")
        entry('target-data-status', 'TARGET_COMMAND_REJECTED')
        entry('target-restore', 'TARGET_COMMAND_REJECTED')
        require(run(runtime_command, data=b"SELECT datacenter_id FROM controller_nodes WHERE id='node-a';\n").stdout == b'changed\n')
        module.mysql_sql(directory, "UPDATE `" + database + "`.controller_nodes SET datacenter_id=CONVERT(0xE9A699E6B8AF USING utf8mb4) WHERE id='node-a';\n")
        require(json.loads(entry('target-data-status').stdout) == imported)
        module.mysql_sql(directory, "ALTER TABLE `" + database + "`.controller_console_sessions DROP FOREIGN KEY controller_console_sessions_user_fk;\n")
        entry('target-data-status', 'TARGET_COMMAND_REJECTED')
        entry('target-restore', 'TARGET_COMMAND_REJECTED')
        require({name: sha(directory / name) for name in records} == committed_hashes and (sha(seal), sha(state)) == before)
        require(not Path('/etc/aster-controller').exists() and not Path('/etc/systemd/system/aster-controller.service').exists())
        report.update({key: True for key in ('database_restored', 'real_source_database_snapshot', 'exact_rows_verified',
            'read_only_reentry_verified', 'modified_data_refused', 'removed_constraint_refused', 'foreign_database_refused')})
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
    with open('/dev/ttyS0', 'w') as console:
        console.write('ASTER_LIBVIRT_NATIVE_RESULT_' + NONCE + ' ' + base64.b64encode(json.dumps(report).encode()).decode() + '\n')
        console.flush()
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())

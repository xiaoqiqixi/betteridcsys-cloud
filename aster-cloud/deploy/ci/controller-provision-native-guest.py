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
CODES = set('TARGET_PROVISION_UNCONFIRMED TARGET_COMMAND_REJECTED TARGET_DATABASE_PLAN_CHANGED TARGET_DATABASE_INVENTORY_CHANGED TARGET_PROVISION_MODULE_MISSING TARGET_DEPENDENCIES_UNCONFIRMED TARGET_MYSQL_START_UNCONFIRMED TARGET_DATABASE_CREATE_UNCONFIRMED TARGET_DATABASE_INVENTORY_UNCONFIRMED TARGET_RESTORE_SERVER_INVENTORY_REJECTED TARGET_RESTORE_MAINTENANCE_IDENTITY_REJECTED TARGET_RESTORE_MAINTENANCE_PROVENANCE_REJECTED TARGET_RESTORE_MAINTENANCE_DRIFT_REJECTED TARGET_RESTORE_MAINTENANCE_OUTCOME_UNCONFIRMED TARGET_MATERIALS_UNCONFIRMED'.split())
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
        entry('target-revoke-sessions', 'TARGET_COMMAND_REJECTED')
        require(not (inputs / 'sessions-started.json').exists())
        progress('target-readback')
        records = private_files + ('import-approval.json', 'import-started.json', 'structure.json')
        committed_hashes = {name: sha(directory / name) for name in records}
        module.mysql_sql(directory, 'SET GLOBAL super_read_only=ON;\n')
        try:
            # MySQL itself rejects writes, including privileged writes. A lost
            # response/repeated root invocation must do only exact readback.
            require(json.loads(entry('target-restore').stdout) == imported)
            require(json.loads(entry('target-data-status').stdout) == imported)
            progress('target-materials')
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
            require(json.loads(entry('target-materials').stdout) == expected_stage)
            require(json.loads(entry('target-material-status').stdout) == expected_stage)
            # Staged files do not grant runtime admission, even with a complete
            # valid configuration and real restored database credentials.
            denied_runtime = subprocess.run([str(version / 'bin/aster-controller'), 'check', '-config', str(candidate / 'config.json')],
                env=ENV, capture_output=True, timeout=30)
            require(denied_runtime.returncode == 78 and not denied_runtime.stdout and
                    json.loads(denied_runtime.stderr).get('code') == 'CONTROLLER_MIGRATION_FENCED')
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
        progress('target-sessions')
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
        revoked = json.loads(entry('target-session-resume').stdout)
        require(revoked == {'schema': 1, 'operation_id': operation, 'revoked_sessions': 1,
            'sessions_revoked': True, 'audit_appended': True, 'exact_database_verified': True,
            'read_only_verification': False, 'target_activation_approved': False, 'migration_ready': False,
            'root_inventory_verified': True, 'database_restored': True, 'target_restore_approved': False})
        readonly_revoked = {**revoked, 'read_only_verification': True}
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
        require(set(planned) == {'schema','operation_id','plan','readonly','sessions_revoked','exact_database_verified',
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
        denied_runtime = subprocess.run([str(version / 'bin/aster-controller'), 'check', '-config', str(candidate / 'config.json')],
            env=ENV, capture_output=True, timeout=30)
        require(denied_runtime.returncode == 78 and not denied_runtime.stdout and
                json.loads(denied_runtime.stderr).get('code') == 'CONTROLLER_MIGRATION_FENCED')
        require({name: sha(directory / name) for name in records} == committed_hashes and (sha(seal), sha(state)) == before)
        require(not Path('/etc/aster-controller').exists() and not Path('/etc/systemd/system/aster-controller.service').exists())
        report.update({key: True for key in ('database_restored', 'real_source_database_snapshot', 'exact_rows_verified',
            'read_only_reentry_verified', 'modified_data_refused', 'removed_constraint_refused', 'foreign_database_refused',
            'runtime_materials_staged', 'runtime_material_drift_refused', 'runtime_candidate_remains_fenced',
            'sessions_revoked', 'session_transition_exact_readback', 'session_transition_explicit_recovery',
            'configuration_plan_verified', 'configuration_plan_readonly', 'configuration_plan_tls_drift_refused',
            'configuration_plan_requires_exact_session_postimage')})
        report.update({'configuration_published': False, 'session_browser_verified': False})
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

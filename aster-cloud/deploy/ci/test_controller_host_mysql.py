#!/usr/bin/env python3
"""Root worker: actual installer, installed ELF, systemd masks and native MySQL.

Only invoked by the nonce-database supervisor on a fresh disposable CI runner.
No fake systemctl, host-path override, production database, KVM or OS reboot.
"""
import argparse
import ast
import hashlib
import http.client
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import time

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('host_mysql_protocol', HERE / 'test_controller_fence_mysql.py')
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
require, receive, send = P.require, P.receive, P.send
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root', 'LANG': 'C.UTF-8', 'SYSTEMD_PAGER': 'cat'}
PHASE = 'preflight'
CLEANUP_COMPLETE = False


def run(argv, data=None, denied=False, timeout=90):
    result = subprocess.run(list(map(str, argv)), input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, env=ENV)
    require(len(result.stdout) <= 1024 * 1024 and len(result.stderr) <= 65536, 'SYSTEMD_GATE_OUTPUT_BOUND')
    if PHASE == 'install' and result.returncode and not denied:
        # Print only a verbatim STATIC diagnostic already reviewed in installer
        # source, never arbitrary subprocess output or a config/credential.
        tree = ast.parse((HERE.parent / 'install/install.py').read_text())
        known = {node.args[0].value for node in ast.walk(tree) if isinstance(node, ast.Call) and
                 isinstance(node.func, ast.Name) and node.func.id == 'fail' and node.args and
                 isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)}
        known.add('Installation input or protected host operation failed; details withheld to protect secrets')
        for message in known:
            if result.stderr == ('ERROR: ' + message + '\n').encode():
                raise RuntimeError('INSTALLER_REFUSED: ' + message)
    require((result.returncode != 0) if denied else (result.returncode == 0), 'SYSTEMD_GATE_COMMAND_' + PHASE)
    return result


def private(path, raw, mode=0o600):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(raw)


def worker(binary):
    global PHASE, CLEANUP_COMPLETE
    require(sys.platform == 'linux' and os.geteuid() == 0 and Path('/run/systemd/system').is_dir(), 'NATIVE_ROOT_SYSTEMD_REQUIRED')
    request = receive(sys.stdin.buffer)
    require(set(request) == {'nonce', 'socket', 'relay_port', 'source_sha', 'server_uuid'}, 'SYSTEMD_REQUEST_INVALID')
    nonce, source = request['nonce'], request['source_sha']
    require(isinstance(nonce, str) and re.fullmatch(r'[a-f0-9]{24}', nonce) and
            isinstance(source, str) and re.fullmatch(r'[a-f0-9]{40}', source) and
            type(request['relay_port']) is int and 1024 <= request['relay_port'] <= 65535, 'SYSTEMD_IDENTITY_INVALID')
    require(isinstance(request['server_uuid'], str) and re.fullmatch(r'[a-f0-9-]{36}', request['server_uuid']), 'FIXTURE_UUID_INVALID')
    controller = 'aster-fence-test-' + nonce
    database = 'aster_cloud_test_fence_' + nonce
    config_dir = Path('/etc/aster-controller')
    state = Path('/var/lib/aster-controller') / controller
    install_state = Path('/var/lib/aster-cloud-installer/controller')
    installed = Path('/opt/aster-cloud/controller')
    systemd = Path('/etc/systemd/system')
    case = Path('/var/lib/aster-host-test-' + nonce)
    unit = systemd / 'aster-controller.service'
    templates = [systemd / ('controller-heartbeat@.' + s) for s in ('service', 'timer')]
    names = ['aster-controller.service', 'controller-heartbeat@fixture-node.service', 'controller-heartbeat@fixture-node.timer']
    owned_roots = [config_dir, state, install_state.parent, installed.parent, case]
    require(all(not path.exists() and not path.is_symlink() for path in
                (Path('/opt/vps-billing'), Path('/opt/aster-billing'))), 'FINANCIAL_HOST_REFUSED')
    for path in owned_roots + [unit] + templates + [systemd / n for n in names[1:]]:
        require(not path.exists() and not path.is_symlink(), 'SYSTEMD_EXISTING_INSTALLATION_REFUSED')
    require(not run(['/usr/bin/systemctl', 'list-units', '--all', '--no-legend', '--plain',
                     'aster-controller*', 'controller-aster*', 'controller-heartbeat*']).stdout.strip(), 'SYSTEMD_FOREIGN_UNIT_REFUSED')
    def interrupted(*_):
        raise RuntimeError('SYSTEMD_WORKER_INTERRUPTED')
    signal.signal(signal.SIGTERM, interrupted)
    operation = secrets.token_hex(16)
    operations = [operation]
    owned, created_units, versions, foreign_process = [], [], None, None
    opt_fd, opt_before, opt_hardened = None, None, False
    try:
        for path in (case, config_dir):
            path.mkdir(mode=0o700)
            owned.append(path)
        PHASE = 'materials'
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        origin = 'https://localhost:' + str(port)
        tokens = {key: secrets.token_hex(32) for key in ('billing', 'read', 'write')}
        for key, value in tokens.items():
            private(config_dir / key, value.encode())
        private(config_dir / 'dsn', ('aster_ci:AsterCiFixtureOnly2026@tcp(127.0.0.1:' + str(request['relay_port']) +
                                    ')/' + database + '?parseTime=true').encode())
        run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
             '-keyout', config_dir / 'key.pem', '-out', config_dir / 'cert.pem', '-subj', '/CN=localhost',
             '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'])
        (config_dir / 'key.pem').chmod(0o600)
        der = ssl.PEM_cert_to_DER_cert((config_dir / 'cert.pem').read_text())
        config = {'schema': 1, 'controller_id': controller, 'listen': '127.0.0.1:' + str(port),
                  'tls_cert_file': str(config_dir / 'cert.pem'), 'tls_key_file': str(config_dir / 'key.pem'),
                  'dsn_file': str(config_dir / 'dsn'), 'billing_token_file': str(config_dir / 'billing'),
                  'admin_read_token_file': str(config_dir / 'read'), 'admin_write_token_file': str(config_dir / 'write'),
                  'heartbeat_ttl_seconds': 60, 'presets': [], 'nodes': [
                      {'id': 'fixture-node', 'datacenter_id': 'fixture', 'group_id': 'fixture',
                       'endpoint': 'https://127.0.0.1:9', 'allowed_cidrs': ['127.0.0.1/32'],
                       'ca_file': str(config_dir / 'cert.pem'), 'client_cert_file': str(config_dir / 'cert.pem'),
                       'client_key_file': str(config_dir / 'key.pem'), 'server_certificate_sha256': hashlib.sha256(der).hexdigest()}]}
        # A closed loopback port: a heartbeat may fail its connection, but can
        # never reach a real node or write a successful capability receipt.
        with socket.socket() as probe:
            require(probe.connect_ex(('127.0.0.1', 9)) != 0, 'LOOPBACK_FIXTURE_PORT_IN_USE')
        private(case / 'config.json', json.dumps(config).encode())
        private(case / 'approval.json', json.dumps({'schema': 1, 'component': 'aster-cloud-controller',
                'config_file': str(case / 'config.json'), 'console_origin': origin,
                'tls_ca_file': str(config_dir / 'cert.pem'), 'existing_administrator': True,
                'dedicated_database': True, 'database_name': database}).encode())
        files = {'bin/aster-controller': binary.read_bytes(),
                 'ui/index.html': b'<!doctype html><title>Installer fixture, not UI acceptance</title>',
                 'ui/empty.txt': b''}
        for name in ('controller-heartbeat@.service', 'controller-heartbeat@.timer'):
            files['templates/' + name] = (HERE.parent / name).read_bytes()
        for name in ('controller-migration.py', 'install.py'):
            files['templates/host-management/' + name] = (HERE.parent / 'install' / name).read_bytes()
        manifest = {'schema': 1, 'component': 'aster-cloud-controller', 'platform': 'linux-amd64',
                    'version': '0.1.0-dev.1', 'release_kind': 'development', 'source_commit': source,
                    'files': [{'path': k, 'sha256': hashlib.sha256(v).hexdigest(), 'size': len(v),
                               'mode': '0755' if k.startswith('bin/') else '0644'} for k, v in sorted(files.items())]}
        files['manifest.json'] = json.dumps(manifest).encode()
        bundle = case / 'controller.tar.gz'
        with tarfile.open(bundle, 'w:gz', format=tarfile.USTAR_FORMAT) as archive:
            for name, raw in sorted(files.items()):
                info = tarfile.TarInfo(name)
                info.size, info.mode = len(raw), 0o755 if name.startswith('bin/') else 0o644
                archive.addfile(info, io.BytesIO(raw))
        bundle_sha = hashlib.sha256(bundle.read_bytes()).hexdigest()
        PHASE = 'install'
        # Confirmed hosted image difference (run 40519867358): /opt is root
        # owned but 0777. Production MUST reject this ancestry. On this fresh,
        # disposable CI fixture only, hold its exact directory FD, narrow 0777
        # to 0755, and restore the original mode AFTER all owned services and
        # role files are removed. No chown, recursive chmod or production bypass.
        opt_fd = os.open('/opt', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        opt_before = os.fstat(opt_fd)
        require(opt_before.st_uid == 0 and stat.S_IMODE(opt_before.st_mode) in (0o755, 0o777), 'HOSTED_OPT_PROFILE_UNRECOGNIZED')
        if stat.S_IMODE(opt_before.st_mode) == 0o777:
            private(case / 'hosted-opt-preparation.json', json.dumps({'schema': 1, 'source_sha': source,
                    'device': opt_before.st_dev, 'inode': opt_before.st_ino, 'uid': opt_before.st_uid,
                    'gid': opt_before.st_gid, 'original_mode': '0777', 'temporary_mode': '0755'}).encode())
            os.fchmod(opt_fd, 0o755)
            opt_hardened = True
        require(stat.S_IMODE(os.fstat(opt_fd).st_mode) == 0o755, 'HOSTED_OPT_PREPARATION_FAILED')
        # Diagnose all other ancestry read-only, without weakening the installer
        # or changing any additional parent. Labels and metadata are bounded;
        # no secret paths, file contents or arbitrary stderr leave the fixture.
        paths = {'systemctl': Path('/usr/bin/systemctl'), 'bundle': bundle,
                 'approval': case / 'approval.json', 'source_config': case / 'config.json',
                 'destination_config': config_dir / 'config.json', 'unit': unit,
                 'versions': installed / 'versions', 'install_state': install_state}
        for key in ('tls_cert_file', 'tls_key_file', 'dsn_file', 'billing_token_file', 'admin_read_token_file', 'admin_write_token_file'):
            paths[key] = Path(config[key])
        for label, path in paths.items():
            for index, parent in enumerate([*reversed(path.parents), path]):
                try:
                    info = parent.lstat()
                except FileNotFoundError:
                    continue
                require(info.st_uid == 0 and not stat.S_ISLNK(info.st_mode) and not info.st_mode & 0o022,
                        'HOSTED_PATH_UNSAFE_' + label + '_' + str(index) + '_uid' + str(info.st_uid) +
                        '_mode' + oct(stat.S_IMODE(info.st_mode)) + '_link' + str(int(stat.S_ISLNK(info.st_mode))))
        # The explicit development channel is a test trust boundary, not a
        # publisher signature claim. Exercise the real installer, not receipts.
        owned += [state, install_state.parent, install_state, installed.parent, installed]
        created_units += [unit]
        run(['/usr/bin/python3', '-I', HERE.parent / 'install/install.py', 'controller', '--bundle', bundle,
             '--sha256', bundle_sha, '--allow-development', '--approval', case / 'approval.json', '--apply'])
        # Synthetic ownership receipt, paired to an actual native fixture DB.
        # Not a claim that root-socket provisioning ran in this service test.
        private(install_state / 'mysql-provision.json', json.dumps({
            'schema': 1, 'database': database, 'runtime_user': 'aster_ci',
            'migration_user': 'aster_fixture_migration', 'server_uuid': request['server_uuid'],
            'nonce': nonce + '0' * 40, 'status': 'dedicated-database-provisioned',
            'steps': ['database-created', 'runtime-created', 'runtime-granted', 'migration-created', 'migration-granted']}).encode())
        versions = installed / 'versions' / ('0.1.0-dev.1-' + bundle_sha[:16])
        exe, config_file = versions / 'bin/aster-controller', config_dir / 'config.json'
        helper = versions / 'templates/host-management/controller-migration.py'
        def cli(command, *flags, data=None, denied=False):
            return run([exe, command, '-config', config_file, *flags], data, denied)
        def migrate(action, op=None, denied=False):
            argv = ['/usr/bin/python3', '-I', helper, action] + (['--operation', op] if op else [])
            # Preserve only reviewed literal error codes from the public helper,
            # not arbitrary Python stderr, file contents or secret arguments.
            r = subprocess.run(list(map(str, argv)), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env=ENV, timeout=90)
            require(len(r.stdout) <= 65536 and len(r.stderr) <= 2048, 'HOST_COORDINATOR_OUTPUT_BOUND')
            if r.returncode and not denied:
                tree = ast.parse(helper.read_text())
                known = {node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and
                         isinstance(node.value, str) and re.fullmatch(r'[A-Z][A-Z0-9_]{2,95}', node.value)}
                try:
                    error = json.loads(r.stderr)
                except (ValueError, UnicodeError):
                    error = {}
                if set(error) == {'error'} and error['error'] in known:
                    raise RuntimeError('HOST_COORDINATOR_REFUSED: ' + error['error'])
            require((r.returncode != 0) if denied else (r.returncode == 0), 'SYSTEMD_GATE_COMMAND_' + PHASE)
            return json.loads(r.stderr if denied else r.stdout)
        PHASE = 'bootstrap'
        cli('migrate')
        cli('bootstrap-admin', '-email', 'migration-admin@example.invalid', '-name', 'Migration Test',
            '-console-origin', origin, '-password-stdin', data=secrets.token_urlsafe(32).encode() + b'\n')
        for path in templates:
            raw = (versions / 'templates' / path.name).read_bytes().replace(b'/opt/aster-cloud/bin/aster-controller', os.fsencode(exe))
            private(path, raw, 0o644)
            created_units.append(path)
        original_inode = unit.stat().st_ino
        context = ssl.create_default_context(cafile=str(config_dir / 'cert.pem'))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        def healthy():
            deadline = time.monotonic() + 25
            while time.monotonic() < deadline:
                conn = http.client.HTTPSConnection('127.0.0.1', port, context=context, timeout=2)
                try:
                    conn.request('GET', '/v1/health', headers={'Authorization': 'Bearer ' + tokens['read']})
                    response = conn.getresponse()
                    require(response.status == 200 and json.loads(response.read(65537))['controller_id'] == controller,
                            'SYSTEMD_TLS_HEALTH_FAILED')
                    return
                except (ConnectionRefusedError, TimeoutError):
                    time.sleep(0.05)
                finally:
                    conn.close()
            raise RuntimeError('SYSTEMD_TLS_HEALTH_TIMEOUT')
        run(['/usr/bin/systemctl', 'daemon-reload'])
        run(['/usr/bin/systemctl', 'start', names[0], names[2]])
        healthy()
        source_pid = run(['/usr/bin/systemctl', 'show', '--property=MainPID', '--value', names[0]]).stdout.strip().decode()
        require(source_pid.isdigit() and int(source_pid) > 1, 'REAL_SOURCE_PID_REQUIRED')
        source_start = Path('/proc', source_pid, 'stat').read_text().rsplit(')', 1)[1].split()[19]
        PHASE = 'plan'
        planned = migrate('plan')
        require(planned['readonly'] and planned['units'] == names and not planned['source_isolated'], 'SYSTEMD_PLAN_INVALID')
        refused_export = cli('migration-export', '-operation', operation, denied=True)
        require(refused_export.returncode == 1 and not refused_export.stdout and
                json.loads(refused_export.stderr).get('code') == 'COMMAND_FAILED', 'ACTIVE_SOURCE_EXPORT_NOT_REFUSED')
        # Actual unmanaged copy, not a mocked /proc listing or fake daemon.
        copy = case / 'aster-controller'
        shutil.copyfile(exe, copy)
        copy.chmod(0o700)
        with socket.socket() as spare:
            spare.bind(('127.0.0.1', 0))
            other_port = spare.getsockname()[1]
        other_config = dict(config, listen='127.0.0.1:' + str(other_port))
        private(case / 'foreign-config.json', json.dumps(other_config).encode())
        foreign_process = subprocess.Popen([str(copy), 'serve', '-config', str(case / 'foreign-config.json')],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV)
        require(migrate('plan', denied=True).get('error') == 'UNMANAGED_CONTROLLER_PROCESS', 'FOREIGN_PROCESS_ACCEPTED')
        require(foreign_process.poll() is None, 'FOREIGN_PROCESS_KILLED_BY_PLAN')
        foreign_process.terminate()
        foreign_process.communicate(timeout=45)
        foreign_process = None
        healthy()
        dropin = systemd / 'aster-controller.service.d'
        require(not dropin.exists() and not dropin.is_symlink(), 'FOREIGN_DROPIN_PATH_EXISTS')
        dropin.mkdir(mode=0o755)
        owned.append(dropin)
        private(dropin / 'fixture.conf', b'[Service]\nEnvironment=ASTER_FIXTURE=1\n', 0o644)
        run(['/usr/bin/systemctl', 'daemon-reload'])
        require(migrate('plan', denied=True).get('error') == 'UNMANAGED_UNIT_SETTINGS', 'CUSTOM_UNIT_NOT_REJECTED')
        require(json.loads(cli('migration-status').stdout)['phase'] == 'active', 'REFUSED_PLAN_FENCED_SOURCE')
        (dropin / 'fixture.conf').unlink()
        dropin.rmdir()
        run(['/usr/bin/systemctl', 'daemon-reload'])
        healthy()
        send(sys.stdout.buffer, {'phase': 'ready', 'controller_id': controller})
        require(receive(sys.stdin.buffer) == {'action': 'fence'}, 'SYSTEMD_FENCE_REQUIRED')
        PHASE = 'isolate'
        proof = migrate('isolate', operation)
        require(proof['source_isolated'] and not proof['migration_ready'], 'SYSTEMD_ISOLATION_INCOMPLETE')
        try:
            after_start = Path('/proc', source_pid, 'stat').read_text().rsplit(')', 1)[1].split()[19]
        except FileNotFoundError:
            after_start = None
        require(after_start != source_start, 'ORIGINAL_CONTROLLER_PROCESS_STILL_EXISTS')
        require(migrate('isolate', operation) == proof, 'SYSTEMD_ISOLATION_NOT_IDEMPOTENT')
        cli('migration-cancel', '-operation', operation, denied=True)
        for name in names:
            require((systemd / name).is_symlink() and os.readlink(systemd / name) == '/dev/null', 'SYSTEMD_MASK_MISSING')
            run(['/usr/bin/systemctl', 'start', name], denied=True)
            observed = run(['/usr/bin/systemctl', 'show', '--property=ActiveState,MainPID,ControlPID', name]).stdout.decode().splitlines()
            require('ActiveState=inactive' in observed or 'ActiveState=failed' in observed, 'INDEPENDENT_UNIT_STILL_ACTIVE')
            if name.endswith('.service'):
                require('MainPID=0' in observed and 'ControlPID=0' in observed, 'INDEPENDENT_UNIT_PROCESS_STILL_ACTIVE')
        run(['/usr/bin/systemctl', 'daemon-reload'])
        require(migrate('status', operation) == proof, 'SYSTEMD_RELOAD_REMOVED_ISOLATION')
        # Fixture-only fault injection. A new /dev/null link is NOT equivalent
        # to the owned original inode and must never be removed by resume.
        saved_mask = systemd / ('.aster-test-original-mask-' + nonce)
        require(not saved_mask.exists() and not saved_mask.is_symlink(), 'MASK_FAULT_PATH_EXISTS')
        unit.rename(saved_mask)
        try:
            os.symlink('/dev/null', unit)
            foreign_inode = unit.lstat().st_ino
            require(migrate('status', operation, denied=True).get('error') == 'PERSISTENT_MASK_CHANGED', 'FOREIGN_MASK_ACCEPTED')
            require(migrate('resume-source', operation, denied=True).get('error') == 'PERSISTENT_MASK_CHANGED' and
                    unit.lstat().st_ino == foreign_inode, 'FOREIGN_MASK_REPLACED')
        finally:
            if unit.is_symlink():
                unit.unlink()
            saved_mask.rename(unit)
        original_config = config_file.read_bytes()
        try:
            config_file.write_bytes(original_config + b'\n')
            require(migrate('status', operation, denied=True).get('error') == 'HOST_SOURCE_IDENTITY_CHANGED', 'CONFIG_DRIFT_ACCEPTED')
        finally:
            config_file.write_bytes(original_config)
        original_token = (config_dir / 'read').read_bytes()
        try:
            (config_dir / 'read').write_bytes(secrets.token_hex(32).encode())
            require(migrate('status', operation, denied=True).get('error') == 'HOST_SOURCE_IDENTITY_CHANGED',
                    'RUNTIME_TOKEN_DRIFT_ACCEPTED')
        finally:
            (config_dir / 'read').write_bytes(original_token)
        require(migrate('status', operation)['source_isolated'], 'FAULT_INJECTION_THAWED_SOURCE')
        require(migrate('resume-source', 'f' * 32, denied=True).get('error'), 'WRONG_OPERATION_NOT_DENIED')
        # A future export seal must forbid local activation; this fixture tests
        # refusal only and does not claim that export has been implemented.
        export = state / 'host-migrations' / operation / 'export-started.json'
        private(export, b'{"fixture_export_boundary":true}\n')
        require(migrate('resume-source', operation, denied=True).get('error') == 'EXPORTED_SOURCE_CANNOT_BE_RESUMED_LOCALLY',
                'EXPORTED_SOURCE_REACTIVATED')
        export.unlink()
        require(migrate('status', operation)['source_isolated'], 'DENIAL_REMOVED_ISOLATION')
        send(sys.stdout.buffer, {'phase': 'fenced', 'systemd_isolation': True, 'new_commands_denied': True})
        require(receive(sys.stdin.buffer) == {'action': 'cancel'}, 'SYSTEMD_RESUME_REQUIRED')
        PHASE = 'resume'
        restored = migrate('resume-source', operation)
        require(restored['phase'] == 'source-resumable' and not restored['service_start_requested'] and
                unit.stat().st_ino == original_inode, 'SOURCE_UNIT_NOT_EXACTLY_RESTORED')
        require(migrate('resume-source', operation) == restored and migrate('status', operation)['phase'] == 'source-resumable',
                'SYSTEMD_RESUME_NOT_IDEMPOTENT')
        run(['/usr/bin/systemctl', 'is-active', names[0]], denied=True)
        run(['/usr/bin/systemctl', 'start', names[0]])
        healthy()
        run(['/usr/bin/systemctl', 'stop', names[0]])
        PHASE = 'encrypted-export'
        exported_operation = secrets.token_hex(16)
        operations.append(exported_operation)
        require(migrate('isolate', exported_operation)['source_isolated'], 'EXPORT_SOURCE_NOT_ISOLATED')
        refused_export = cli('migration-export', '-operation', exported_operation, denied=True)
        require(refused_export.returncode == 1 and not refused_export.stdout and
                json.loads(refused_export.stderr).get('code') == 'COMMAND_FAILED', 'UNAUTHORIZED_EXPORT_NOT_REFUSED')
        exported = migrate('export', exported_operation)
        directory = state / 'host-migrations' / exported_operation
        archive, recovery = directory / 'backup.age', directory / 'recovery.key'
        raw = archive.read_bytes()
        require(raw.startswith(b'age-encryption.org/v1\n') and
                hashlib.sha256(raw).hexdigest() == exported['archive_sha256'] and
                len(raw) == exported['archive_bytes'] and exported['database_rows'] >= 16 and
                exported['source_readonly'] and exported['source_isolated'] and not exported['migration_ready'],
                'ENCRYPTED_EXPORT_UNCONFIRMED')
        for path in (archive, recovery):
            st = path.lstat()
            require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and
                    stat.S_IMODE(st.st_mode) == 0o600, 'BACKUP_MATERIAL_NOT_PRIVATE')
        inspected = json.loads(run([exe, 'migration-inspect', '-archive', archive, '-key-file', recovery,
                                    '-controller-id', controller, '-operation', exported_operation]).stdout)
        require(inspected['authenticated'] and inspected['content_integrity_verified'] and
                not inspected['target_restore_approved'] and not inspected['migration_ready'], 'ACTUAL_ARCHIVE_NOT_AUTHENTICATED')
        require(not any(directory.glob('.export-*')), 'EXPORT_LEFT_PLAINTEXT_SCRATCH')
        require(migrate('resume-source', exported_operation, denied=True).get('error') ==
                'EXPORTED_SOURCE_CANNOT_BE_RESUMED_LOCALLY', 'EXPORTED_SOURCE_RESUMED')
        require(migrate('export', exported_operation, denied=True).get('error') == 'EXPORT_ALREADY_STARTED' and
                hashlib.sha256(archive.read_bytes()).hexdigest() == exported['archive_sha256'], 'EXPORT_OVERWROTE_BACKUP')
        require(migrate('status', exported_operation)['source_isolated'], 'EXPORT_UNSEALED_SOURCE')
        send(sys.stdout.buffer, {'phase': 'complete', 'strict_tls': True, 'same_identity_restart': True,
                                'hosted_opt_parent_hardened': opt_hardened,
                                'encrypted_export_verified': True, 'exported_source_local_resume_denied': True})
    finally:
        # Fresh-path checks above establish ownership before any installation;
        # only this fixture's role files and exact operation stages are removed.
        if foreign_process is not None:
            foreign_process.terminate()
            try:
                foreign_process.communicate(timeout=45)
            except subprocess.TimeoutExpired:
                foreign_process.kill()
                foreign_process.communicate(timeout=5)
        if created_units:
            for name in names:
                loaded = run(['/usr/bin/systemctl', 'show', '--property=LoadState', '--value', name]).stdout.strip()
                if loaded in (b'loaded', b'masked'):
                    run(['/usr/bin/systemctl', 'stop', name])
                    properties = run(['/usr/bin/systemctl', 'show', '--property=MainPID,ControlPID,ActiveState', name]).stdout.decode().splitlines()
                    require('MainPID=0' in properties or name.endswith('.timer'), 'CLEANUP_MAIN_PROCESS_ACTIVE')
                    require('ControlPID=0' in properties or name.endswith('.timer'), 'CLEANUP_CONTROL_PROCESS_ACTIVE')
                    require('ActiveState=inactive' in properties or 'ActiveState=failed' in properties, 'CLEANUP_UNIT_ACTIVE')
        for path in [systemd / n for n in names] + created_units:
            if path.exists() or path.is_symlink():
                path.unlink()
        for owned_operation in operations:
            for index in range(len(names)):
                path = systemd / ('.aster-migration-' + owned_operation + '-' + str(index) + '.saved')
                if path.exists() or path.is_symlink():
                    path.unlink()
        run(['/usr/bin/systemctl', 'daemon-reload'])
        for path in reversed(owned):
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
        if opt_fd is not None:
            try:
                current, named = os.fstat(opt_fd), Path('/opt').lstat()
                require((current.st_dev, current.st_ino, current.st_uid, current.st_gid) ==
                        (opt_before.st_dev, opt_before.st_ino, opt_before.st_uid, opt_before.st_gid) and
                        (named.st_dev, named.st_ino) == (current.st_dev, current.st_ino) and
                        not stat.S_ISLNK(named.st_mode) and stat.S_IMODE(current.st_mode) == 0o755,
                        'HOSTED_OPT_IDENTITY_CHANGED_NO_RESTORE')
                if opt_hardened:
                    os.fchmod(opt_fd, stat.S_IMODE(opt_before.st_mode))
                require(stat.S_IMODE(os.fstat(opt_fd).st_mode) == stat.S_IMODE(opt_before.st_mode), 'HOSTED_OPT_RESTORE_FAILED')
            finally:
                os.close(opt_fd)
        CLEANUP_COMPLETE = True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--worker', action='store_true', required=True)
    args = parser.parse_args()
    try:
        worker(args.binary)
    except Exception as exc:
        print(json.dumps({'passed': False, 'phase': PHASE, 'cleanup_complete': CLEANUP_COMPLETE,
                          'code': str(exc) if isinstance(exc, RuntimeError) else 'SYSTEMD_MYSQL_ACCEPTANCE_FAILED'}), file=sys.stderr)
        raise SystemExit(1)

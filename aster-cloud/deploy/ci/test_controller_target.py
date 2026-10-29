#!/usr/bin/env python3
"""Actual root installer/coordinator/ELF target preparation on disposable Linux.

The independently encrypted source fixture has empty table files. This verifies
host preparation/admission ONLY, not SQL restore, a two-host migration, reboot,
node takeover, release authenticity or UI. No service/database is started.
"""
import argparse
import ast
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tarfile

HERE = Path(__file__).resolve().parent
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root', 'LANG': 'C.UTF-8'}
PHASE = 'preflight'


def require(ok, code):
    if not ok:
        raise RuntimeError(code)


def run(argv, env=None, denied=False, allowed_codes=(), timeout=180):
    r = subprocess.run(list(map(str, argv)), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       env=env or ENV, timeout=timeout, stdin=subprocess.DEVNULL)
    require(len(r.stdout) <= 65536 and len(r.stderr) <= 65536, 'TARGET_OUTPUT_BOUND_' + PHASE)
    if r.returncode and not denied:
        # Fixed reviewed codes only; never dump private fixture input/stderr.
        for code in allowed_codes:
            if r.stderr == ('ERROR: ' + code + '\n').encode() or r.stderr == (json.dumps({'error': code}) + '\n').encode():
                raise RuntimeError('TARGET_REFUSED_' + PHASE + ': ' + code)
    require((r.returncode != 0) if denied else r.returncode == 0, 'TARGET_COMMAND_' + PHASE)
    if denied:
        require(not r.stdout, 'TARGET_DENIAL_STDOUT_' + PHASE)
    return r


def private(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as f:
        os.fchmod(f.fileno(), mode)
        f.write(raw)


def main():
    global PHASE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--fixture-binary', type=Path, required=True)
    parser.add_argument('--source', required=True)
    args = parser.parse_args()
    require(sys.platform == 'linux' and os.geteuid() == 0 and Path('/run/systemd/system').is_dir(), 'TARGET_NATIVE_ROOT_REQUIRED')
    require(len(args.source) == 40 and all(c in '0123456789abcdef' for c in args.source), 'TARGET_SOURCE_REQUIRED')
    nonce, operation = secrets.token_hex(12), secrets.token_hex(16)
    controller = 'aster-target-test-' + nonce
    case = Path('/var/lib/aster-target-test-' + nonce)
    restore = Path('/var/lib/aster-controller-restore')
    inputs = restore / operation
    state = Path('/var/lib/aster-controller') / controller
    installed = Path('/opt/aster-cloud')
    installer = Path('/var/lib/aster-cloud-installer')
    config_dir = Path('/etc/aster-controller')
    unit = Path('/etc/systemd/system/aster-controller.service')
    for path in (case, restore, state, installed, installer, config_dir, unit, Path('/opt/vps-billing'), Path('/opt/aster-billing')):
        require(not path.exists() and not path.is_symlink(), 'TARGET_FRESH_FIXTURE_REQUIRED')
    require(not run(['/usr/bin/systemctl', 'list-units', '--all', '--no-pager', '--no-legend',
                     'aster-controller*', 'controller-heartbeat*']).stdout.strip(), 'TARGET_EXISTING_UNITS_REFUSED')
    owned = []
    opt_fd, opt_before, listener = None, None, None
    checks = []
    try:
        for path in (case, restore, inputs):
            path.mkdir(mode=0o700)
            owned.append(path)
        if not state.parent.exists():
            state.parent.mkdir(mode=0o700)
            owned.append(state.parent)
        parent_info = state.parent.lstat()
        require(parent_info.st_uid == 0 and stat.S_ISDIR(parent_info.st_mode) and
                stat.S_IMODE(parent_info.st_mode) == 0o700, 'TARGET_STATE_PARENT_UNSAFE')
        files = {'bin/aster-controller': args.binary.resolve(strict=True).read_bytes(),
                 'ui/index.html': b'<!doctype html><title>Target installer fixture, not UI acceptance</title>',
                 'ui/empty.txt': b''}
        for name in ('install.py', 'controller-migration.py', 'provision.py'):
            files['templates/host-management/' + name] = (HERE.parent / 'install' / name).read_bytes()
        manifest = {'schema': 1, 'component': 'aster-cloud-controller', 'platform': 'linux-amd64',
                    'version': '0.1.0-dev.1', 'release_kind': 'development', 'source_commit': args.source,
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
        # Disposable hosted-image preparation, never a production path bypass.
        # Keep the exact root /opt FD and restore its original 0755/0777 mode.
        opt_fd = os.open('/opt', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        opt_before = os.fstat(opt_fd)
        require(opt_before.st_uid == 0 and stat.S_IMODE(opt_before.st_mode) in (0o755, 0o777), 'TARGET_OPT_PROFILE_UNKNOWN')
        os.fchmod(opt_fd, 0o755)
        PHASE = 'software-install'
        owned += [installed, installer, state]
        tree = ast.parse((HERE.parent / 'install/install.py').read_text())
        codes = {node.args[0].value for node in ast.walk(tree) if isinstance(node, ast.Call) and
                 isinstance(node.func, ast.Name) and node.func.id == 'fail' and node.args and
                 isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)}
        run(['/usr/bin/python3', '-I', HERE.parent / 'install/install.py', 'controller', '--bundle', bundle,
             '--sha256', bundle_sha, '--allow-development', '--apply'], allowed_codes=codes)
        version = installed / 'controller/versions' / ('0.1.0-dev.1-' + bundle_sha[:16])
        binary, helper = version / 'bin/aster-controller', version / 'templates/host-management/controller-migration.py'
        install_state = installer / 'controller/state.json'
        original_installation = install_state.read_bytes()
        helper_tree = ast.parse(helper.read_text())
        codes = {arg.value for node in ast.walk(helper_tree) if isinstance(node, ast.Call)
                 for arg in node.args if isinstance(arg, ast.Constant) and isinstance(arg.value, str)
                 and arg.value.isupper()}
        def entry(action, denied=False):
            r = run(['/usr/bin/python3', '-I', helper, action, '--operation', operation],
                    denied=denied, allowed_codes=codes)
            if denied:
                # Preserve the exact accepted-denial set. On failure record only
                # a code present as a literal in the installed, owned helpers,
                # never raw stderr, file paths, credentials or arbitrary fields.
                try:
                    value = json.loads(r.stderr)
                except (ValueError, UnicodeError):
                    value = None
                code = value.get('error') if isinstance(value, dict) and set(value) == {'error'} else None
                known = set()
                for name in ('controller-migration.py', 'install.py', 'provision.py'):
                    tree = ast.parse((helper.parent / name).read_text())
                    known.update(node.value for node in ast.walk(tree) if isinstance(node, ast.Constant)
                                 and isinstance(node.value, str) and node.value.isupper()
                                 and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789' for c in node.value))
                diagnostic = code if isinstance(code, str) and code in known else 'UNRECOGNIZED_ERROR'
                require(r.returncode == 1 and code in {
                    'TARGET_COMMAND_REJECTED', 'TARGET_IMMUTABLE_PLAN_CHANGED',
                    'TARGET_CONTROLLER_UNIT_ALREADY_EXISTS', 'TARGET_CONFIGURATION_ALREADY_EXISTS',
                    'TARGET_INPUT_INVENTORY_CHANGED'},
                    'TARGET_DENIAL_NOT_CONFIRMED_' + PHASE + '_' + action + '_' + diagnostic)
            return r
        def fixture(directory, machine=None):
            env = {**ENV, 'ASTER_SOURCE_CLI_FIXTURE': '1', 'ASTER_FIXTURE_DIR': str(directory),
                   'ASTER_FIXTURE_CONTROLLER': controller, 'ASTER_FIXTURE_OPERATION': operation,
                   'ASTER_FIXTURE_SOURCE': args.source}
            if machine:
                env['ASTER_FIXTURE_MACHINE_SHA'] = machine
            run([args.fixture_binary.resolve(strict=True), '-test.run=^TestControllerSourceValidation$'], env=env)
        PHASE = 'independent-encrypted-source'
        fixture(inputs)
        originals = {name: (inputs / name).read_bytes() for name in ('request.json', 'backup.age', 'recovery.key')}
        PHASE = 'readonly-plan'
        # Independent real-systemd contract: an absent pattern exits nonzero,
        # whereas the standard unit is a successful positive query control.
        # No fake systemctl, ignored exit status or network error means success.
        absent = run(['/usr/bin/systemctl', 'list-unit-files', '--no-pager', '--no-legend',
                      'aster-target-absent-' + nonce + '*'], denied=True)
        present = run(['/usr/bin/systemctl', 'list-unit-files', '--full', '--no-pager', '--no-legend',
                       'systemd-journald.service'])
        require(absent.returncode > 0 and not absent.stdout and
                present.stdout.decode().split()[0] == 'systemd-journald.service', 'TARGET_SYSTEMD_QUERY_CONTRACT')
        plan = json.loads(entry('target-plan').stdout)
        require(plan['readonly'] and not plan['database_restored'] and not plan['target_restore_approved'] and
                not plan['migration_ready'] and plan['plan']['controller_id'] == controller and
                plan['plan']['source_commit'] == args.source, 'TARGET_PLAN_OVERCLAIM')
        require(not state.exists() and not config_dir.exists() and not unit.exists() and
                not (inputs / 'plan.json').exists(), 'TARGET_PLAN_WRITES')
        require(set(p.name for p in inputs.iterdir()) == set(originals), 'TARGET_PLAINTEXT_LEFTOVER')
        checks.append('real_systemd_empty_pattern_and_positive_query_control')
        checks.append('actual_installer_and_binary_readonly_fixed_input_plan')
        PHASE = 'input-and-host-negative'
        request_path = inputs / 'request.json'
        request_path.write_bytes(originals['request.json'][:-1] + b',"schema":1}')
        entry('target-plan', True)
        request_path.write_bytes(originals['request.json'])
        os.link(inputs / 'backup.age', case / 'cipher-hardlink')
        entry('target-plan', True)
        (case / 'cipher-hardlink').unlink()

        request = json.loads(originals['request.json'])
        (inputs / 'request.json').write_text(json.dumps({**request, 'source_commit': '0' * 40}))
        entry('target-plan', True)
        (inputs / 'request.json').write_bytes(originals['request.json'])
        (inputs / 'backup.age').write_bytes(originals['backup.age'][:-1])
        entry('target-seal', True)
        (inputs / 'backup.age').write_bytes(originals['backup.age'])
        (inputs / 'recovery.key').write_bytes(b'ASTER-CONTROLLER-RECOVERY-1:' + b'01' * 32 + b'\n')
        entry('target-seal', True)
        (inputs / 'recovery.key').write_bytes(originals['recovery.key'])
        (inputs / 'recovery.key').chmod(0o644)
        entry('target-plan', True)
        (inputs / 'recovery.key').chmod(0o600)
        (inputs / 'recovery.key').unlink()
        (inputs / 'recovery.key').symlink_to(case / 'does-not-exist')
        entry('target-plan', True)
        (inputs / 'recovery.key').unlink()
        private(inputs / 'recovery.key', originals['recovery.key'])
        stale = inputs / '.restore-verify-interrupted'
        stale.mkdir(mode=0o700)
        entry('target-seal', True)
        require(stale.exists(), 'TARGET_STALE_DATA_DELETED')
        stale.rmdir()
        config_dir.mkdir(mode=0o700)
        try:
            entry('target-seal', True)
        finally:
            config_dir.rmdir()
        private(unit, b'[Service]\nExecStart=/bin/false\n', 0o644)
        try:
            entry('target-seal', True)
        finally:
            unit.unlink()
        same_machine = case / 'same-machine'
        same_machine.mkdir(mode=0o700)
        fixture(same_machine, hashlib.sha256(Path('/etc/machine-id').read_bytes().strip()).hexdigest())
        for name in originals:
            (inputs / name).write_bytes((same_machine / name).read_bytes())
        entry('target-seal', True)
        for name, raw in originals.items():
            (inputs / name).write_bytes(raw)
        require(not state.exists() and not (inputs / 'plan.json').exists(), 'TARGET_REJECTION_WROTE_SEAL')
        checks.append('wrong_commit_cipher_key_mode_symlink_staging_config_unit_and_same_machine_refused')
        PHASE = 'foreign-target-history'
        state.mkdir(mode=0o700)
        private(state / 'foreign.json', b'FOREIGN_TARGET_SENTINEL')
        entry('target-seal', True)
        require((state / 'foreign.json').read_bytes() == b'FOREIGN_TARGET_SENTINEL' and
                not (state / 'target-restore.json').exists(), 'TARGET_FOREIGN_HISTORY_ADOPTED')
        require((inputs / 'plan.json').is_file(), 'TARGET_IMMUTABLE_PLAN_NOT_RETAINED')
        entry('target-status', True)
        # Remove only this injected fixture file; production never offers this
        # cleanup or treats rejection as permission to erase another host state.
        (state / 'foreign.json').unlink()
        checks.append('foreign_runtime_history_refused_without_deletion_or_activation')

        PHASE = 'seal'
        sealed = json.loads(entry('target-seal').stdout)
        require(sealed['phase'] == 'target-sealed' and sealed['admission_blocked'] and sealed['guarded_processes_drained'] and
                not sealed['source_isolated'] and not sealed['migration_ready'] and not sealed['database_restored'], 'TARGET_SEAL_OVERCLAIM')
        seal = state / 'target-restore.json'
        seal_raw = seal.read_bytes()
        require(json.loads(entry('target-seal').stdout) == sealed and json.loads(entry('target-status').stdout) == sealed and
                seal.read_bytes() == seal_raw, 'TARGET_SEAL_NOT_IDEMPOTENT')
        require(install_state.read_bytes() == original_installation and not config_dir.exists() and not unit.exists(), 'TARGET_SEAL_STARTED_OR_CONFIGURED')
        checks.append('durable_same_operation_seal_without_configuration_or_activation')
        PHASE = 'malformed-data-before-provision'
        entry('target-database-plan', True)
        entry('target-provision', True)
        entry('target-restore', True)
        entry('target-data-status', True)
        entry('target-materials', True)
        entry('target-material-status', True)
        entry('target-revoke-sessions', True)
        entry('target-session-status', True)
        entry('target-session-resume', True)
        entry('target-configuration-plan', True)
        entry('target-configuration-publish', True)
        entry('target-configuration-status', True)
        entry('target-configuration-resume', True)
        require(not (inputs / 'database').exists() and not (inputs / 'database-plan.json').exists() and
                not (inputs / 'runtime').exists() and not (inputs / 'materials-started.json').exists() and
                install_state.read_bytes() == original_installation and seal.read_bytes() == seal_raw,
                'TARGET_INVALID_RECORDS_REACHED_PROVISION')
        checks.append('authenticated_but_invalid_records_refused_before_provision')
        PHASE = 'runtime-admission'
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(0.2)
        config = {'schema': 1, 'controller_id': controller, 'listen': '127.0.0.1:9443',
                  'tls_cert_file': str(case / 'no-cert'), 'tls_key_file': str(case / 'no-key'),
                  'dsn_file': str(case / 'dsn'), 'heartbeat_ttl_seconds': 60, 'nodes': [], 'presets': []}
        for field in ('billing_token_file', 'admin_read_token_file', 'admin_write_token_file'):
            path = case / field
            private(path, secrets.token_hex(32).encode())
            config[field] = str(path)
        private(case / 'dsn', ('aster_ci:PRIVATE_SENTINEL@tcp(127.0.0.1:%d)/aster_cloud_test_target' % listener.getsockname()[1]).encode())
        private(case / 'runtime.json', json.dumps(config).encode())
        def denied_cli(command, *flags, fenced=True):
            r = run([binary, command, '-config', case / 'runtime.json', *flags], denied=True)
            if fenced:
                require(r.returncode == 78 and json.loads(r.stderr)['code'] == 'CONTROLLER_MIGRATION_FENCED', 'TARGET_NOT_FENCED_' + command)
            else:
                require(r.returncode == 1 and json.loads(r.stderr)['code'] == 'COMMAND_FAILED', 'TARGET_DENIAL_NOT_STRUCTURED')
        for command in ('check', 'migrate', 'serve', 'dispatch', 'reconcile', 'operation-dispatch', 'operation-reconcile',
                        'heartbeat', 'maintenance', 'register-nodes', 'bootstrap-admin'):
            denied_cli(command)
        denied_cli('migration-cancel', '-operation', operation)
        denied_cli('migration-fence', '-operation', operation)
        status = json.loads(run([binary, 'migration-status', '-config', case / 'runtime.json']).stdout)
        require(status['phase'] == 'target-sealed' and status['admission_blocked'], 'TARGET_RUNTIME_STATUS')
        try:
            connection, _ = listener.accept()
        except socket.timeout:
            pass
        else:
            connection.close()
            raise RuntimeError('TARGET_DATABASE_CONNECTION_OCCURRED')
        checks.append('all_runtime_dispatch_and_source_cancel_denied_before_database')
        PHASE = 'durable-corruption'
        saved_plan = (inputs / 'plan.json').read_bytes()
        changed = json.loads(saved_plan)
        changed['machine_id_sha256'] = '0' * 64
        (inputs / 'plan.json').write_text(json.dumps(changed))
        entry('target-seal', True)
        entry('target-status', True)
        require(seal.read_bytes() == seal_raw, 'TARGET_SEAL_OVERWRITTEN')
        (inputs / 'plan.json').write_bytes(saved_plan)
        seal.write_bytes(b'{truncated')
        denied_cli('check')
        denied_cli('migration-cancel', '-operation', operation)
        entry('target-status', True)
        entry('target-seal', True)
        require(seal.read_bytes() == b'{truncated', 'TARGET_CORRUPT_SEAL_RESET')
        seal.write_bytes(seal_raw)  # Fault injection cleanup, NOT production recovery.
        seal.chmod(0o644)
        denied_cli('check', fenced=False)
        seal.chmod(0o600)
        require(json.loads(entry('target-status').stdout) == sealed, 'TARGET_FINAL_STATUS')
        checks.append('immutable_plan_and_corrupt_seal_fail_closed_without_reset')
        report = {'schema': 1, 'passed': True, 'source_commit': args.source, 'checks': checks,
                          'actual_root_installer': True, 'actual_controller_binary': True,
                          'target_admission_sealed': True, 'synthetic_source_package': True,
                          'database_restored': False, 'source_host_export_verified': False,
                          'reboot_verified': False, 'node_takeover_verified': False, 'migration_ready': False}
    finally:
        if listener is not None:
            listener.close()
        for path in reversed(owned):
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
        if opt_fd is not None:
            current = os.fstat(opt_fd)
            require(current.st_ino == opt_before.st_ino and current.st_dev == opt_before.st_dev and current.st_uid == 0,
                    'TARGET_OPT_IDENTITY_CHANGED')
            os.fchmod(opt_fd, stat.S_IMODE(opt_before.st_mode))
            os.close(opt_fd)
        require(all(not p.exists() and not p.is_symlink() for p in owned), 'TARGET_FIXTURE_CLEANUP_INCOMPLETE')
    print(json.dumps({**report, 'owned_fixture_removed': True, 'hosted_opt_original_mode_restored': True}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'passed': False, 'phase': PHASE,
                          'code': str(error) if isinstance(error, RuntimeError) else 'TARGET_ACCEPTANCE_UNCONFIRMED'}), file=sys.stderr)
        raise SystemExit(1)

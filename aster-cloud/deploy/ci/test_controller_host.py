#!/usr/bin/env python3
"""Actual Linux/root controller CLI acceptance; no host services or real DB.

The loopback listener deliberately stalls a real CLI's MySQL handshake. That
proves its process-lifetime lease is held before external I/O, not that a SQL
transaction or whole-controller migration succeeded. Only owned children and
nonce-named state are removed. Run exclusively on disposable CI hosts.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import socket
import subprocess
import tempfile


def require(ok, code):
    if not ok:
        raise RuntimeError(code)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    args = parser.parse_args()
    require(platform.system() == 'Linux' and os.geteuid() == 0, 'LINUX_ROOT_REQUIRED')
    binary = args.binary.resolve(strict=True)
    require(binary.is_file(), 'BINARY_REQUIRED')
    nonce = secrets.token_hex(12)
    controller = 'aster-host-test-' + nonce
    state = Path('/var/lib/aster-controller') / controller
    require(not state.exists() and not state.is_symlink(), 'NEW_CASE_REQUIRED')
    case = Path(tempfile.mkdtemp(prefix='aster-host-test-', dir='/tmp'))
    child = None
    checks = []
    env = {'PATH': '/usr/bin:/bin', 'HOME': '/root', 'LANG': 'C.UTF-8'}
    try:
        exe = case / 'aster-controller'
        shutil.copyfile(binary, exe)
        exe.chmod(0o700)
        config_file = case / 'config.json'
        def private(path, data):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
        for name in ('billing', 'read', 'write'):
            private(case / name, secrets.token_hex(32).encode())
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(2)
        listener.settimeout(10)
        private(case / 'dsn', ('aster_ci:PRIVATE_SENTINEL@tcp(127.0.0.1:%d)/aster_cloud_test_host' % listener.getsockname()[1]).encode())
        config = {'schema': 1, 'controller_id': controller, 'listen': '127.0.0.1:9443',
                  'tls_cert_file': str(case / 'cert'), 'tls_key_file': str(case / 'key'),
                  'dsn_file': str(case / 'dsn'), 'billing_token_file': str(case / 'billing'),
                  'admin_read_token_file': str(case / 'read'), 'admin_write_token_file': str(case / 'write'),
                  'heartbeat_ttl_seconds': 60, 'nodes': [], 'presets': []}
        private(config_file, json.dumps(config).encode())
        def run(command, *flags, ok=True, path=config_file, code=None):
            argv = [str(exe), command]
            if command != 'migration-capabilities':
                argv += ['-config', str(path)]
            result = subprocess.run(argv + list(flags), stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=15)
            require(len(result.stdout) < 65536 and len(result.stderr) < 65536, 'OUTPUT_BOUND')
            require(b'PRIVATE_SENTINEL' not in result.stdout + result.stderr, 'SECRET_OUTPUT')
            require((result.returncode == 0) == ok, 'CLI_OUTCOME_' + command)
            if not ok:
                require(not result.stdout, 'DENIAL_STDOUT')
                event = json.loads(result.stderr)
                require(event.get('msg') == 'aster_command_failed', 'ERROR_ENVELOPE')
                if code:
                    require(event.get('code') == code, 'ERROR_CODE')
                return None
            return json.loads(result.stdout)
        caps = run('migration-capabilities')
        require(caps['runtime_fence'] is True and caps['migration_ready'] is False, 'CAPABILITIES')
        active = run('migration-status')
        require(active['phase'] == 'active' and active['admission_blocked'] is False, 'INITIAL_ACTIVE')
        checks.append('actual_cli_capabilities_and_root_state')

        # The connection cannot be accepted until the actual binary reaches DB
        # I/O. Do not simulate a lease by opening the runtime lock in this test.
        child = subprocess.Popen([str(exe), 'check', '-config', str(config_file)],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        connection, _ = listener.accept()
        require(child.poll() is None, 'REAL_COMMAND_NOT_RUNNING')
        operation = secrets.token_hex(16)
        fenced = run('migration-fence', '-operation', operation)
        require(fenced['phase'] == 'draining' and fenced['admission_blocked'] and not fenced['guarded_processes_drained'], 'LIVE_LEASE_NOT_DRAINED')
        require(not fenced['source_isolated'] and not fenced['migration_ready'], 'FALSE_MIGRATION_CLAIM')
        run('migration-cancel', '-operation', operation, ok=False, code='CONTROLLER_MIGRATION_BUSY')
        for command in ('check', 'migrate', 'serve', 'dispatch', 'operation-dispatch', 'heartbeat', 'maintenance', 'register-nodes', 'bootstrap-admin'):
            run(command, ok=False, code='CONTROLLER_MIGRATION_FENCED')
        run('migration-fence', '-operation', secrets.token_hex(16), ok=False)
        run('migration-status', '-on=false', ok=False)
        checks.append('live_process_drain_and_all_mutating_commands_fenced_before_database')
        child.terminate()
        out, err = child.communicate(timeout=10)
        require(b'PRIVATE_SENTINEL' not in out + err, 'CHILD_SECRET_OUTPUT')
        child = None
        connection.close()
        listener.close()
        stopped = run('migration-status')
        require(stopped['phase'] == 'fenced' and stopped['guarded_processes_drained'], 'PROCESS_EXIT_NOT_OBSERVED')
        require(run('migration-fence', '-operation', operation) == stopped, 'SAME_INTENT_NOT_IDEMPOTENT')
        run('check', ok=False, code='CONTROLLER_MIGRATION_FENCED')
        checks.append('new_process_denied_and_exit_observed_without_replay')

        # The privileged host coordinator seals its intent under control.lock
        # before touching systemd. Plain CLI cancellation must never thaw it.
        seal = state / 'host-migration.json'
        private(seal, json.dumps({'schema': 1, 'operation_id': operation}).encode())
        run('migration-cancel', '-operation', operation, ok=False)
        run('check', ok=False, code='CONTROLLER_MIGRATION_FENCED')
        seal.unlink()  # fixture cleanup only; normal removal belongs to coordinator
        checks.append('host_coordinator_seal_cannot_be_cancelled_by_plain_cli')

        changed_file = case / 'changed.json'
        private(changed_file, json.dumps({**config, 'listen': '127.0.0.1:9444'}).encode())
        run('migration-cancel', '-operation', operation, path=changed_file, ok=False)
        run('check', path=changed_file, ok=False, code='CONTROLLER_MIGRATION_FENCED')
        run('migration-cancel', '-operation', secrets.token_hex(16), ok=False)
        require(run('migration-cancel', '-operation', operation)['phase'] == 'active', 'CANCEL_NOT_ACTIVE')
        require(run('migration-cancel', '-operation', operation)['phase'] == 'active', 'CANCEL_NOT_IDEMPOTENT')
        run('migration-fence', '-operation', operation, ok=False)
        checks.append('config_and_operation_binding_and_retained_cancel_history')

        for operation in ('', '../escape', 'A' * 32, 'a' * 33):
            run('migration-fence', '-operation', operation, ok=False)
        second = secrets.token_hex(16)
        run('migration-fence', '-operation', second)
        # Deliberate disk damage and ownership faults; a fresh process must fail
        # closed. These are acceptance fault injections, never recovery advice.
        fence = state / 'fence.json'
        original = fence.read_bytes()
        fence.write_bytes(b'{truncated')
        run('check', ok=False, code='CONTROLLER_MIGRATION_FENCED')
        run('migration-status', ok=False)
        fence.write_bytes(original)
        fence.chmod(0o644)
        run('check', ok=False)
        fence.chmod(0o600)
        fence.unlink()
        fence.symlink_to(case / 'dsn')
        run('check', ok=False)
        fence.unlink()
        private(fence, original)
        os.link(fence, state / 'hardlink')
        run('check', ok=False)
        (state / 'hardlink').unlink()
        state.chmod(0o777)
        run('check', ok=False)
        state.chmod(0o700)
        run('migration-cancel', '-operation', second)
        checks.append('malformed_private_symlink_hardlink_and_directory_faults_fail_closed')
        print(json.dumps({'schema': 1, 'passed': True, 'checks': checks,
                          'real_controller_binary': True, 'real_mysql': False,
                          'systemd_isolation_verified': False, 'reboot_verified': False,
                          'source_isolated': False, 'migration_ready': False}, sort_keys=True))
    finally:
        if child is not None:
            child.terminate()
            try:
                child.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate(timeout=5)
        shutil.rmtree(case)
        if state.is_dir() and not state.is_symlink():
            shutil.rmtree(state)


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        # Fixture paths, credentials and child output never reach CI logs.
        print(json.dumps({'passed': False, 'code': str(exc) if isinstance(exc, RuntimeError) else 'HOST_CLI_ACCEPTANCE_FAILED'}), file=__import__('sys').stderr)
        raise SystemExit(1)

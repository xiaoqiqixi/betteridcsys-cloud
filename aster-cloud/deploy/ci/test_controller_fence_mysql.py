#!/usr/bin/env python3
"""Real controller process + strict HTTPS + private native MySQL fencing gate.

No node RPC, VM action, systemd mask or full host migration is claimed. The
unprivileged supervisor owns a fresh nonce-marked database; the root worker only
runs the real controller against it and owns its private config/process state.
"""
import argparse
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import select
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time


def require(ok, code):
    if not ok:
        raise RuntimeError(code)


def receive(stream, timeout=90):
    deadline, raw = time.monotonic() + timeout, bytearray()
    while len(raw) < 16384 and time.monotonic() < deadline:
        if not select.select([stream], [], [], max(0, deadline - time.monotonic()))[0]:
            break
        value = os.read(stream.fileno(), 1)
        if value == b'\n':
            return json.loads(raw)
        if not value:
            break
        raw.extend(value)
    raise RuntimeError('WORKER_PROTOCOL_FAILED')


def send(stream, value):
    stream.write(json.dumps(value).encode() + b'\n')
    stream.flush()


def worker(binary):
    require(sys.platform == 'linux' and os.geteuid() == 0, 'WORKER_LINUX_ROOT_REQUIRED')
    request = receive(sys.stdin.buffer)
    require(set(request) == {'nonce', 'socket'}, 'WORKER_REQUEST_INVALID')
    nonce, socket_path = request['nonce'], Path(request['socket'])
    require(isinstance(nonce, str) and re.fullmatch(r'[a-f0-9]{24}', nonce), 'WORKER_NONCE_INVALID')
    require(socket_path.is_absolute() and socket_path.name == 'mysql.sock' and
            re.fullmatch(r'aster-mysql\.[A-Za-z0-9]{8}', socket_path.parent.name) and
            socket_path.resolve(strict=True) == socket_path and stat.S_ISSOCK(socket_path.stat().st_mode) and
            socket_path.stat().st_uid != 0, 'WORKER_FIXTURE_SOCKET_INVALID')
    controller = 'aster-fence-test-' + nonce
    database = 'aster_cloud_test_fence_' + nonce
    state = Path('/var/lib/aster-controller') / controller
    require(not state.exists() and not state.is_symlink(), 'WORKER_STATE_EXISTS')
    case = Path(tempfile.mkdtemp(prefix='aster-fence-mysql-', dir='/tmp'))
    server = None
    env = {'PATH': '/usr/bin:/bin', 'HOME': '/root', 'LANG': 'C.UTF-8'}
    def interrupted(*_):
        raise RuntimeError('WORKER_INTERRUPTED')
    signal.signal(signal.SIGTERM, interrupted)
    try:
        exe = case / 'aster-controller'
        shutil.copyfile(binary, exe)
        exe.chmod(0o700)
        config_file = case / 'config.json'
        def private(path, raw):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
        tokens = {key: secrets.token_hex(32) for key in ('billing', 'read', 'write')}
        for key, value in tokens.items():
            private(case / key, value.encode())
        # Public disposable fixture credential; never consume a production DSN.
        private(case / 'dsn', ('aster_ci:AsterCiFixtureOnly2026@unix(' + str(socket_path) + ')/' + database + '?parseTime=true').encode())
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        origin = 'https://localhost:' + str(port)
        config = {'schema': 1, 'controller_id': controller, 'listen': '127.0.0.1:' + str(port),
                  'tls_cert_file': str(case / 'cert.pem'), 'tls_key_file': str(case / 'key.pem'),
                  'dsn_file': str(case / 'dsn'), 'billing_token_file': str(case / 'billing'),
                  'admin_read_token_file': str(case / 'read'), 'admin_write_token_file': str(case / 'write'),
                  'heartbeat_ttl_seconds': 60, 'nodes': [], 'presets': []}
        private(config_file, json.dumps(config).encode())
        result = subprocess.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                                 '-keyout', str(case / 'key.pem'), '-out', str(case / 'cert.pem'),
                                 '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=30)
        require(result.returncode == 0, 'WORKER_TLS_CREATION_FAILED')
        context = ssl.create_default_context(cafile=str(case / 'cert.pem'))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        def run(command, *flags, data=None, fenced=False):
            result = subprocess.run([str(exe), command, '-config', str(config_file)] + list(flags),
                                    input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=40)
            require(len(result.stdout) <= 65536 and len(result.stderr) <= 65536, 'WORKER_OUTPUT_BOUND')
            if fenced:
                require(result.returncode == 78 and not result.stdout and
                        json.loads(result.stderr).get('code') == 'CONTROLLER_MIGRATION_FENCED', 'WORKER_FENCE_DENIAL_INVALID')
                return None
            require(result.returncode == 0, 'WORKER_COMMAND_FAILED_' + command)
            return json.loads(result.stdout)
        run('migrate')
        run('bootstrap-admin', '-email', 'migration-admin@example.invalid', '-name', 'Migration Test',
            '-console-origin', origin, '-password-stdin', data=secrets.token_urlsafe(32).encode() + b'\n')
        def start():
            nonlocal server
            server = subprocess.Popen([str(exe), 'serve', '-config', str(config_file), '-console-origin', origin],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                require(server.poll() is None, 'WORKER_SERVER_EXITED')
                conn = http.client.HTTPSConnection('127.0.0.1', port, context=context, timeout=2)
                try:
                    conn.request('GET', '/v1/health', headers={'Authorization': 'Bearer ' + tokens['read']})
                    response = conn.getresponse()
                    body = response.read(65537)
                    require(len(body) <= 65536, 'WORKER_HEALTH_BOUND')
                    require(response.status == 200 and json.loads(body).get('controller_id') == controller, 'WORKER_HEALTH_IDENTITY')
                    return
                except (ConnectionRefusedError, TimeoutError):
                    time.sleep(0.05) # bounded readiness observation, never retry a write
                finally:
                    conn.close()
            raise RuntimeError('WORKER_HEALTH_TIMEOUT')
        start()
        send(sys.stdout.buffer, {'phase': 'ready', 'controller_id': controller})
        require(receive(sys.stdin.buffer) == {'action': 'fence'}, 'WORKER_FENCE_COMMAND_REQUIRED')
        operation = secrets.token_hex(16)
        state_before = run('migration-fence', '-operation', operation)
        require(state_before['admission_blocked'] and not state_before['source_isolated'], 'WORKER_FENCE_STATE')
        # This is the actual running HTTPS service noticing the persistent fence;
        # no signal is sent by the test to make this assertion pass.
        server.communicate(timeout=45)
        require(server.returncode == 0, 'WORKER_SERVER_NOT_GRACEFULLY_FENCED')
        server = None
        status = run('migration-status')
        require(status['guarded_processes_drained'] and status['phase'] == 'fenced', 'WORKER_NOT_DRAINED')
        for command in ('serve', 'check', 'migrate', 'bootstrap-admin', 'dispatch', 'operation-dispatch'):
            run(command, fenced=True)
        send(sys.stdout.buffer, {'phase': 'fenced', 'automatic_service_exit': True, 'new_commands_denied': True})
        require(receive(sys.stdin.buffer) == {'action': 'cancel'}, 'WORKER_CANCEL_COMMAND_REQUIRED')
        require(run('migration-cancel', '-operation', operation)['phase'] == 'active', 'WORKER_CANCEL_FAILED')
        start()
        # Explicit test teardown, not a migration success criterion.
        server.terminate()
        server.communicate(timeout=45)
        require(server.returncode == 0, 'WORKER_RESTART_TEARDOWN_FAILED')
        server = None
        send(sys.stdout.buffer, {'phase': 'complete', 'strict_tls': True, 'same_identity_restart': True})
    finally:
        if server is not None:
            server.terminate()
            try:
                server.communicate(timeout=45)
            except subprocess.TimeoutExpired:
                server.kill()
                server.communicate(timeout=5)
        shutil.rmtree(case)
        if state.is_dir() and not state.is_symlink():
            shutil.rmtree(state)


def supervisor(binary):
    require(os.geteuid() != 0, 'SUPERVISOR_MUST_BE_NONROOT')
    spec = importlib.util.spec_from_file_location('fence_native_grants', Path(__file__).with_name('test_cloud_mysql_grants.py'))
    g = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = g
    spec.loader.exec_module(g)
    fixture = g.validate_fixture()
    nonce = secrets.token_hex(12)
    database = 'aster_cloud_test_fence_' + nonce
    child, created, clean = None, False, False
    with tempfile.TemporaryDirectory(prefix='fence-', dir=fixture.root) as work:
        work = Path(work)
        admin = g.Client(fixture, work, fixture.admin_cnf)
        server_uuid = admin.run('SELECT @@server_uuid;').strip().decode()
        require(re.fullmatch(r'[a-f0-9-]{36}', server_uuid), 'FIXTURE_UUID_INVALID')
        require(admin.run("SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='" + database + "';").strip() == b'0', 'DATABASE_ALREADY_EXISTS')
        try:
            admin.run('CREATE DATABASE `' + database + '`; CREATE TABLE `' + database +
                      "`.contract_ownership(nonce CHAR(24) PRIMARY KEY,server_uuid CHAR(36)); INSERT INTO `" + database +
                      "`.contract_ownership VALUES('" + nonce + "','" + server_uuid + "');")
            created = True
            child = subprocess.Popen(['/usr/bin/sudo', '-n', '/usr/bin/python3', '-I', str(Path(__file__).resolve()),
                                      '--worker', '--binary', str(binary.resolve(strict=True))],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            send(child.stdin, {'nonce': nonce, 'socket': str(fixture.socket)})
            ready = receive(child.stdout)
            require(ready == {'phase': 'ready', 'controller_id': 'aster-fence-test-' + nonce}, 'SERVER_READY_PROTOCOL')
            # Seed two durable, synthetic unresolved receipts. No network member
            # is attached, and neither is eligible for automatic create dispatch.
            for index, state in enumerate(('sending', 'uncertain'), 1):
                identifier = str(index) * 32
                admin.run('INSERT INTO `' + database + "`.controller_jobs(operation_id,order_id,controller_id,request_sha256,request_json,instance_id,node_id,node_profile_sha256,node_request_sha256,node_request,state,created_at,updated_at) VALUES('" + identifier + "','" + identifier + "','aster-fence-test-" + nonce + "','" + 'a' * 64 + "','{}','" + identifier + "','fixture-node','" + 'b' * 64 + "','" + 'c' * 64 + "','{}','" + state + "','2026-01-01','2026-01-01');")
            dumper = fixture.mysql_root / 'bin/mysqldump'
            g.owned(dumper, os.geteuid(), executable=True)
            def snapshot():
                result = subprocess.run([str(dumper), '--defaults-file=' + str(fixture.admin_cnf), '--no-login-paths',
                                         '--protocol=SOCKET', '--socket=' + str(fixture.socket), '--single-transaction',
                                         '--no-tablespaces', '--skip-comments', '--skip-add-locks', '--skip-lock-tables',
                                         '--skip-triggers', '--hex-blob', '--order-by-primary', '--no-create-info',
                                         '--set-gtid-purged=OFF', database],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=admin.env, timeout=45)
                require(result.returncode == 0 and 0 < len(result.stdout) < 2 * 1024 * 1024, 'SNAPSHOT_FAILED')
                return hashlib.sha256(result.stdout).hexdigest()
            before = snapshot()
            send(child.stdin, {'action': 'fence'})
            require(receive(child.stdout) == {'phase': 'fenced', 'automatic_service_exit': True, 'new_commands_denied': True}, 'FENCE_PROTOCOL')
            require(snapshot() == before, 'FENCE_CHANGED_PERSISTED_DATABASE')
            send(child.stdin, {'action': 'cancel'})
            require(receive(child.stdout) == {'phase': 'complete', 'strict_tls': True, 'same_identity_restart': True}, 'CANCEL_PROTOCOL')
            child.stdin.close()
            child.stdin = None
            child.communicate(timeout=90)
            require(child.returncode == 0, 'WORKER_EXIT_FAILED')
            child = None
            require(snapshot() == before, 'RESTART_REPLAYED_OR_CHANGED_DATA')
            require(admin.run('SELECT state FROM `' + database + '`.controller_jobs ORDER BY operation_id;').splitlines() == [b'sending', b'uncertain'], 'UNKNOWN_RESULTS_CHANGED')
            report = {'schema': 1, 'passed': True, 'real_mysql': True, 'real_controller_process': True,
                      'strict_tls': True, 'host_trust_modified': False, 'automatic_service_drain': True,
                      'all_database_rows_unchanged': True, 'unknown_receipts_retained': 2,
                      'database_snapshot_sha256': before, 'same_identity_restart': True,
                      'node_rpc_performed': False, 'systemd_isolation_verified': False,
                      'reboot_verified': False, 'source_isolated': False, 'migration_ready': False}
        finally:
            if child is not None:
                if child.stdin:
                    child.stdin.close()
                    child.stdin = None
                # EOF/phase timeouts let the root worker perform its own bounded
                # cleanup. Never kill a guessed PID or delete a live database.
                child.communicate(timeout=180)
            if created:
                owner = admin.json("SELECT JSON_OBJECT('nonce',nonce,'uuid',server_uuid) FROM `" + database + "`.contract_ownership;")
                require(owner == {'nonce': nonce, 'uuid': server_uuid}, 'CLEANUP_OWNERSHIP_UNCONFIRMED')
                admin.run('DROP DATABASE `' + database + '`;')
                clean = admin.run("SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='" + database + "';").strip() == b'0'
        require(clean, 'CLEANUP_NOT_CONFIRMED')
        report['owned_database_removed'] = True
        print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--worker', action='store_true')
    args = parser.parse_args()
    try:
        (worker if args.worker else supervisor)(args.binary)
    except Exception as exc:
        print(json.dumps({'passed': False, 'code': str(exc) if isinstance(exc, RuntimeError) else 'FENCE_MYSQL_ACCEPTANCE_FAILED'}), file=sys.stderr)
        raise SystemExit(1)

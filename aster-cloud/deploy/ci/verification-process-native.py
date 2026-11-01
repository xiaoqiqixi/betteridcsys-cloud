#!/usr/bin/env python3
"""Disposable Linux root/non-root HTTPS + real minimum-SQL process acceptance.

Only called inside the owned TCG restore guest. The original managed launcher,
source-host export, successful staff login and browser/UI are NOT certified here.
"""
import base64
import ctypes
from datetime import datetime, timedelta, timezone
import fcntl
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import time


FAILURE_CODES = set('VERIFICATION_HOST_GUARD VERIFICATION_HOST_EXECUTABLE VERIFICATION_LISTENER VERIFICATION_SPAWN VERIFICATION_HANDSHAKE VERIFICATION_EARLY_EXIT VERIFICATION_CHILD_AUTHORITY VERIFICATION_CHILD_IDENTITY VERIFICATION_CHILD_GUARD VERIFICATION_CHILD_BOOTSTRAP VERIFICATION_CHILD_LISTENER VERIFICATION_CHILD_SQL VERIFICATION_CHILD_RECHECK VERIFICATION_CHILD_SERVICE'.split())

def fixture_failure(raw):
    code = raw.decode('ascii', errors='replace').removesuffix('\n')
    return code if len(raw) <= 128 and code in FAILURE_CODES else 'TARGET_NATIVE_ASSERTION_FAILED'

def empty_ipv4_route_snapshot(raw):
    """Validate the kernel's public /proc/<pid>/net/route wire format."""
    # fib_route_seq_start returns NULL before emitting a header if there is no
    # RT_TABLE_MAIN. Both v5.15 and v6.8 use this behavior. Do not accept arbitrary
    # single-line text, whitespace, or a route row merely because it is one line.
    header = (b'Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT').ljust(127, b' ') + b'\n'
    return raw == b'' or raw == header

def accept(root, inputs, controller, operation, module, directory, ui_directory, require, progress):
    require(os.geteuid() == 0)
    require(ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0)
    case = Path('/opt') / ('aster-verification-native-' + operation)
    case.mkdir(mode=0o755)
    case.chmod(0o755)  # public test ELF only; independent of the guest umask
    binary = case/'fixture'
    shutil.copyfile(root/'verification-process.test', binary)
    binary.chmod(0o755)
    plan = json.loads((inputs/'plan.json').read_text())
    dbplan = json.loads((inputs/'database-plan.json').read_text())
    phase = json.loads((inputs/'verification-data-approval.json').read_text())
    original_end = datetime.fromisoformat(phase['expires_at'].replace('Z', '+00:00'))
    configuration = json.loads(Path('/etc/aster-controller/config.json').read_text())
    require(configuration['controller_id'] == controller and configuration['listen'] == '127.0.0.1:9555')
    cfg = dict(controller=configuration, operation=operation, origin='https://source.invalid:9555',
        expires_at=phase['expires_at'], uid=65532, gid=65532,
        dsn=(directory/'verification-mysql-dsn').read_text().removesuffix('\n'),
        certificate_pem=base64.b64encode((inputs/'configuration-tls.crt').read_bytes()).decode(),
        private_key_pem=base64.b64encode((inputs/'configuration-tls.key').read_bytes()).decode(),
        ui_directory=str(ui_directory))
    cert = ssl.create_default_context(cafile=str(inputs/'configuration-tls.crt'))
    cert.minimum_version = ssl.TLSVersion.TLSv1_2
    state = Path('/var/lib/aster-controller')/controller
    original_seal = (state/'target-restore.json').read_bytes()
    vuser = 'aster_v_' + operation[:23]

    def probe_drained(expected):
        fd = os.open(state/'runtime.lock', os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                drained = True
            except BlockingIOError:
                drained = False
            require(drained == expected, "VERIFICATION_PROCESS_GUARD_LOCK")
        finally:
            os.close(fd)
        require((state/'target-restore.json').read_bytes() == original_seal, 'VERIFICATION_PROCESS_TARGET_SEAL')

    def request_bytes(method, path):
        with socket.create_connection(('127.0.0.1', 9555), timeout=2) as raw:
            with cert.wrap_socket(raw, server_hostname='source.invalid') as tls:
                tls.sendall((method+' '+path+' HTTP/1.1\r\nHost: source.invalid:9555\r\nConnection: close\r\nContent-Length: 0\r\n\r\n').encode())
                response = http.client.HTTPResponse(tls)
                response.begin()
                payload = response.read((5 << 20) + 1)
                require(len(payload) <= (5 << 20), 'VERIFICATION_PROCESS_STATIC_UI')
                return response.status, {name.lower(): value for name, value in response.getheaders()}, payload

    def request(method, path):
        status, _, payload = request_bytes(method, path)
        require(len(payload) <= 65536)
        return status, json.loads(payload)

    def static_ui():
        # Installed, manifest-bound root-owned fixture assets, not a mocked
        # handler. This proves transport/file isolation, not visual acceptance.
        for path, filename in (('/', 'index.html'), ('/index.html', 'index.html'),
                               ('/assets/native.js', 'assets/native.js'), ('/assets/native.css', 'assets/native.css')):
            status, headers, payload = request_bytes('GET', path)
            require(status == 200 and payload == (ui_directory/filename).read_bytes(), 'VERIFICATION_PROCESS_STATIC_UI')
            require(headers.get('cache-control') == 'no-store' and headers.get('x-content-type-options') == 'nosniff',
                    'VERIFICATION_PROCESS_STATIC_UI')
            csp = headers.get('content-security-policy', '')
            require(all(value in csp for value in ("script-src 'self'", "connect-src 'self'", "frame-ancestors 'none'")),
                    'VERIFICATION_PROCESS_STATIC_UI')
        status, headers, payload = request_bytes('HEAD', '/assets/native.js')
        require(status == 200 and not payload and headers.get('etag'), 'VERIFICATION_PROCESS_STATIC_UI')
        for path in ('/console', '/v1', '/api/unknown', '/console/v1/unknown', '/v1/unknown',
                     '/console%2fv1/auth/me', '/assets/%6eative.js', '/?', '/assets/native.js?cache=1'):
            status, _, payload = request_bytes('GET', path)
            require(status == 403 and json.loads(payload).get('error', {}).get('code') == 'MIGRATION_VERIFICATION_READ_ONLY',
                    'VERIFICATION_PROCESS_STATIC_UI')
        for path in ('/assets/native.js.map', '/assets/private.json', '/assets/../index.html', '/assets//native.js'):
            status, _, payload = request_bytes('GET', path)
            require(status == 404 and b'PRIVATE_' not in payload, 'VERIFICATION_PROCESS_STATIC_UI')
        for method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            status, body = request(method, '/assets/native.js')
            require(status == 403 and body.get('error', {}).get('code') == 'MIGRATION_VERIFICATION_READ_ONLY',
                    'VERIFICATION_PROCESS_STATIC_UI')
        # An asset becoming writable after startup must fail closed, not remain
        # available from a process cache. Restore only this injected mode fault.
        asset = ui_directory/'assets/native.js'
        try:
            asset.chmod(0o666)
            status, _, payload = request_bytes('GET', '/assets/native.js')
            require(status == 404 and b'nativeStaticFixture' not in payload, 'VERIFICATION_PROCESS_STATIC_UI')
        finally:
            asset.chmod(0o644)
        status, _, payload = request_bytes('GET', '/assets/native.js')
        require(status == 200 and payload == asset.read_bytes(), 'VERIFICATION_PROCESS_STATIC_UI')

    def child_of(parent):
        children = set()
        for task in (Path('/proc')/str(parent.pid)/'task').iterdir():
            try:
                children.update(map(int, (task/'children').read_text().split()))
            except FileNotFoundError:
                pass
        require(len(children) == 1, "VERIFICATION_PROCESS_CHILD_SET")
        child = children.pop()
        require(child > 1, "VERIFICATION_PROCESS_CHILD_SET")
        return child

    def restricted(child, parent):
        p = Path('/proc')/str(child)
        require((p/'ns/net').stat().st_ino != (Path('/proc')/str(parent.pid)/'ns/net').stat().st_ino, 'VERIFICATION_PROCESS_NAMESPACE')
        require((p/'cmdline').read_bytes().split(b'\0') == [str(binary).encode(), b'migration-verification-child', b''], 'VERIFICATION_PROCESS_COMMAND')
        require(set((p/'environ').read_bytes().split(b'\0')) == {b'PATH=/usr/bin:/bin', b'LANG=C', b''}, 'VERIFICATION_PROCESS_ENVIRONMENT')
        with (p/'net/route').open('rb') as stream:
            routes = stream.read(129)
        require(empty_ipv4_route_snapshot(routes), "VERIFICATION_PROCESS_NETWORK_ROUTES")
        # Independently query every IPv4 table through rtnetlink in the observed
        # child's namespace. Empty /proc bytes alone are not isolation proof.
        # This fixed read-only command neither creates a namespace nor adds a
        # link/route, and never queries a destination or publishes addresses.
        actual = subprocess.run(['/usr/bin/nsenter', '--target', str(child), '--net', '--',
                                 '/usr/sbin/ip', '-j', '-4', 'route', 'show', 'table', 'all'],
                                env={'PATH':'/usr/bin:/bin', 'LANG':'C'},
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        require(actual.returncode == 0 and not actual.stderr and len(actual.stdout) <= 65536,
                'VERIFICATION_PROCESS_NETWORK_ROUTES')
        try:
            tables = json.loads(actual.stdout)
        except (ValueError, UnicodeError):
            require(False, 'VERIFICATION_PROCESS_NETWORK_ROUTES')
        require(tables == [], 'VERIFICATION_PROCESS_NETWORK_ROUTES')
        progress('target-verification-routes-empty-file' if routes == b'' else 'target-verification-routes-header-only')
        seen = 0
        for task in (p/'task').iterdir():
            try:
                fields = dict(line.split(':', 1) for line in (task/'status').read_text().splitlines() if ':' in line)
            except FileNotFoundError:
                continue
            seen += 1
            require(fields['NoNewPrivs'].strip() == '1' and not fields['Groups'].strip(), 'VERIFICATION_PROCESS_THREAD_PRIVILEGES')
            for key in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb'):
                require(fields[key].strip() == '0000000000000000', 'VERIFICATION_PROCESS_THREAD_CAPABILITIES')
            for key in ('Uid', 'Gid'):
                require(fields[key].split() == ['65532']*4, 'VERIFICATION_PROCESS_THREAD_CREDENTIALS')
        require(seen > 0, "VERIFICATION_PROCESS_THREADS_MISSING")
        inode = (state/'runtime.lock').stat().st_ino
        inherited = 0
        for descriptor in (p/'fd').iterdir():
            try:
                inherited += descriptor.stat().st_ino == inode and descriptor.stat().st_dev == (state/'runtime.lock').stat().st_dev
            except FileNotFoundError:
                pass
        require(inherited == 1, "VERIFICATION_PROCESS_GUARD_COUNT")

    def sql_drained():
        deadline = time.monotonic()+10
        while True:
            raw = module.mysql_sql(directory, "SELECT COUNT(*) FROM performance_schema.threads WHERE PROCESSLIST_USER='"+vuser+"';\n")
            if raw.strip() == b'0':
                return
            require(time.monotonic() < deadline)
            time.sleep(.1)

    def require_parent_running(parent):
        if parent.poll() is None:
            return
        # This is fixed fixture output, never the child's private stderr/SQL.
        raw = parent.stdout.read(129)
        require(False, fixture_failure(raw))

    def run_case(mode):
        parent, child = None, None
        input_created = False
        path = root/('verification-process-'+mode+'.json')
        value = dict(cfg)
        if mode == 'expiry':
            end = datetime.now(timezone.utc)+timedelta(seconds=15)
            require(end < original_end)
            value['expires_at'] = end.isoformat().replace('+00:00', 'Z')
        if mode == 'bad-credential':
            value['dsn'] = vuser+':wrong-password-value-not-a-secret@unix(/run/mysqld/mysqld.sock)/aster_cloud_restore_'+operation
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            input_created = True
            with os.fdopen(fd, 'w') as f:
                json.dump({'config':value, 'configuration_sha':plan['canonical_configuration_sha256'],
                    'plan_sha':dbplan['target_plan_sha256']}, f)
            parent = subprocess.Popen([str(binary), 'native-process-fixture', str(path)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env={'PATH':'/usr/bin:/bin', 'LANG':'C'})
            if mode == 'bad-credential':
                # Keep stdin open: closing it would test cancellation, not actual
                # minimum-account authentication rejection.
                require(parent.wait(timeout=20) == 27)
                out, err = parent.communicate()
                require(out == b'VERIFICATION_CHILD_SQL\n' and not err, fixture_failure(out))
                probe_drained(True); sql_drained()
                return
            deadline = time.monotonic()+12
            while True:
                require_parent_running(parent)
                try:
                    code, body = request('GET', '/console/v1/auth/me')
                    require(code == 401)
                    break
                except (OSError, http.client.HTTPException):
                    require(time.monotonic() < deadline)
                    time.sleep(.1)
            progress('target-verification-process-identity')
            child = child_of(parent)
            restricted(child, parent)
            probe_drained(False)
            if mode == 'stop':
                progress('target-verification-process-static-ui')
                static_ui()
            progress('target-verification-process-write-denied')
            code, body = request('POST', '/console/v1/users')
            require(code == 403 and body.get('error', {}).get('code') == 'MIGRATION_VERIFICATION_READ_ONLY')
            progress('target-verification-process-'+mode+'-drain')
            if mode == 'stop':
                parent.stdin.write(b'stop\n'); parent.stdin.flush()
            elif mode == 'parent-death':
                parent.kill()  # this exact Popen child, never an imported PID
            code = parent.wait(timeout=25)
            require(code == (-9 if mode == 'parent-death' else 0))
            if mode == 'parent-death':
                deadline = time.monotonic()+10
                while True:
                    pid, status = os.waitpid(child, os.WNOHANG)
                    if pid == child:
                        require(os.WIFSIGNALED(status) and os.WTERMSIG(status) == 9)
                        break
                    require(time.monotonic() < deadline)
                    time.sleep(.1)
            require(not (Path('/proc')/str(child)).exists())
            out, err = parent.communicate()
            require(not out and not err)
            probe_drained(True); sql_drained()
            try:
                connection = socket.create_connection(('127.0.0.1',9555), timeout=1)
            except OSError:
                connection = None
            if connection is not None:
                connection.close()
                require(False)
        finally:
            if parent is not None and parent.poll() is None:
                parent.kill(); parent.wait(timeout=10)
            # Any outstanding child is killed by the actual parent-death signal;
            # the owned guest is stopped on fixture failure, not reused.
            if input_created:
                path.unlink(missing_ok=True)
    try:
        for mode in ('bad-credential', 'stop', 'expiry', 'parent-death'):
            progress('target-verification-process-' + mode)
            run_case(mode)
    finally:
        binary.unlink(missing_ok=True)
        case.rmdir()

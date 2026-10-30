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


def accept(root, inputs, controller, operation, module, directory, require, progress):
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
        private_key_pem=base64.b64encode((inputs/'configuration-tls.key').read_bytes()).decode())
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
            require(drained == expected)
        finally:
            os.close(fd)
        require((state/'target-restore.json').read_bytes() == original_seal)

    def request(method, path):
        with socket.create_connection(('127.0.0.1', 9555), timeout=2) as raw:
            with cert.wrap_socket(raw, server_hostname='source.invalid') as tls:
                tls.sendall((method+' '+path+' HTTP/1.1\r\nHost: source.invalid:9555\r\nConnection: close\r\nContent-Length: 0\r\n\r\n').encode())
                response = http.client.HTTPResponse(tls)
                response.begin()
                payload = response.read(65537)
                require(len(payload) <= 65536)
                return response.status, json.loads(payload)

    def child_of(parent):
        children = set()
        for task in (Path('/proc')/str(parent.pid)/'task').iterdir():
            try:
                children.update(map(int, (task/'children').read_text().split()))
            except FileNotFoundError:
                pass
        require(len(children) == 1)
        child = children.pop()
        require(child > 1)
        return child

    def restricted(child, parent):
        p = Path('/proc')/str(child)
        require((p/'ns/net').stat().st_ino != (Path('/proc')/str(parent.pid)/'ns/net').stat().st_ino)
        require((p/'cmdline').read_bytes().split(b'\0') == [str(binary).encode(), b'migration-verification-child', b''])
        require(set((p/'environ').read_bytes().split(b'\0')) == {b'PATH=/usr/bin:/bin', b'LANG=C', b''})
        rows = (p/'net/route').read_text().splitlines()
        require(len(rows) == 1)  # no routes, while the inherited TLS socket works
        seen = 0
        for task in (p/'task').iterdir():
            try:
                fields = dict(line.split(':', 1) for line in (task/'status').read_text().splitlines() if ':' in line)
            except FileNotFoundError:
                continue
            seen += 1
            require(fields['NoNewPrivs'].strip() == '1' and not fields['Groups'].strip())
            for key in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb'):
                require(fields[key].strip() == '0000000000000000')
            for key in ('Uid', 'Gid'):
                require(fields[key].split() == ['65532']*4)
        require(seen > 0)
        inode = (state/'runtime.lock').stat().st_ino
        inherited = 0
        for descriptor in (p/'fd').iterdir():
            try:
                inherited += descriptor.stat().st_ino == inode and descriptor.stat().st_dev == (state/'runtime.lock').stat().st_dev
            except FileNotFoundError:
                pass
        require(inherited == 1)

    def sql_drained():
        deadline = time.monotonic()+10
        while True:
            raw = module.mysql_sql(directory, "SELECT COUNT(*) FROM performance_schema.threads WHERE PROCESSLIST_USER='"+vuser+"';\n")
            if raw.strip() == b'0':
                return
            require(time.monotonic() < deadline)
            time.sleep(.1)

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
                require(not out and not err)
                probe_drained(True); sql_drained()
                return
            deadline = time.monotonic()+12
            while True:
                require(parent.poll() is None)
                try:
                    code, body = request('GET', '/console/v1/auth/me')
                    require(code == 401)
                    break
                except (OSError, http.client.HTTPException):
                    require(time.monotonic() < deadline)
                    time.sleep(.1)
            child = child_of(parent)
            restricted(child, parent)
            probe_drained(False)
            code, body = request('POST', '/console/v1/users')
            require(code == 403 and body.get('error', {}).get('code') == 'MIGRATION_VERIFICATION_READ_ONLY')
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

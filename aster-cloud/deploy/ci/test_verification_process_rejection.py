#!/usr/bin/env python3
"""Linux startup boundary: reach SQL refusal, not HTTPS/MySQL acceptance.

Runs before slow signed-guest tests to distinguish privilege/descriptor/namespace
startup failures from SQL fixtures. Never changes a host DB or authenticates an
existing account; the full native guest is still required for successful SQL.
"""
import argparse
import ctypes
import signal
from datetime import datetime, timedelta, timezone
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True


def route_format_probe():
    # Invoked only by the fixed unshare command below. A fast actual-kernel
    # regression catches /proc representation mistakes before the slow VM run.
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise RuntimeError('LINUX_ROOT_ROUTE_PROBE_REQUIRED')
    own = Path('/proc/self/ns/net').stat().st_ino
    parent = (Path('/proc')/str(os.getppid())/'ns/net').stat().st_ino
    if own == parent:
        raise RuntimeError('ROUTE_PROBE_NAMESPACE_UNCONFIRMED')
    spec = importlib.util.spec_from_file_location('owned_route_format', Path(__file__).with_name('verification-process-native.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with open('/proc/self/net/route', 'rb') as stream:
        raw = stream.read(129)
    if not module.empty_ipv4_route_snapshot(raw):
        raise RuntimeError('ROUTE_PROBE_KERNEL_FORMAT_REJECTED')
    observed = subprocess.run(['/usr/sbin/ip', '-j', '-4', 'route', 'show', 'table', 'all'],
        env={'PATH':'/usr/bin:/bin','LANG':'C'}, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
    if observed.returncode or observed.stderr or len(observed.stdout) > 65536 or json.loads(observed.stdout) != []:
        raise RuntimeError('ROUTE_PROBE_TABLES_NOT_EMPTY')
    print(json.dumps({'schema':1,'passed':True,'isolated_namespace':True,'all_ipv4_tables_empty':True}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture-binary', type=Path, required=True)
    parser.add_argument('--source', required=True)
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0 or not re.fullmatch('[0-9a-f]{40}', args.source):
        raise RuntimeError('LINUX_ROOT_SOURCE_REQUIRED')
    probe = subprocess.run(['/usr/bin/unshare', '--net', '--', '/usr/bin/python3', '-I',
        str(Path(__file__).resolve()), '--route-format-probe'], env={'PATH':'/usr/bin:/bin','LANG':'C'},
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    if probe.returncode:
        known = {'LINUX_ROOT_ROUTE_PROBE_REQUIRED','ROUTE_PROBE_NAMESPACE_UNCONFIRMED',
                 'ROUTE_PROBE_KERNEL_FORMAT_REJECTED','ROUTE_PROBE_TABLES_NOT_EMPTY'}
        code = probe.stderr.decode('ascii', errors='replace').removesuffix('\n')
        raise RuntimeError(code if len(probe.stderr) <= 128 and code in known else 'KERNEL_ROUTE_PREFLIGHT_UNCONFIRMED')
    if probe.stderr or len(probe.stdout) > 1024 or json.loads(probe.stdout) != {
            'schema':1,'passed':True,'isolated_namespace':True,'all_ipv4_tables_empty':True}:
        raise RuntimeError('KERNEL_ROUTE_PREFLIGHT_UNCONFIRMED')
    if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
        raise RuntimeError('SUBREAPER_REQUIRED')
    operation = secrets.token_hex(16)
    controller = 'aster-process-rejection-' + operation[:16]
    state = Path('/var/lib/aster-controller')/controller
    if state.exists() or state.is_symlink():
        raise RuntimeError('FRESH_CASE_REQUIRED')
    case = Path(tempfile.mkdtemp(prefix='aster-process-rejection-', dir='/tmp'))
    parent = None
    try:
        case.chmod(0o755)  # public ELF only; JSON below is independently 0600
        binary = case/'fixture'
        shutil.copyfile(args.fixture_binary.resolve(strict=True), binary)
        binary.chmod(0o755)
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            listen = '127.0.0.1:' + str(reservation.getsockname()[1])
        config = dict(schema=1, controller_id=controller, listen=listen,
            heartbeat_ttl_seconds=30, nodes=[], presets=[])
        for field in ('tls_cert_file','tls_key_file','dsn_file','billing_token_file','admin_read_token_file','admin_write_token_file'):
            config[field] = '/nonexistent/' + field
        private = case/'input.json'
        value = dict(config=dict(controller=config, operation=operation,
            origin='https://source.invalid', uid=65532, gid=65532,
            expires_at=(datetime.now(timezone.utc)+timedelta(minutes=1)).isoformat().replace('+00:00','Z'),
            dsn='aster_v_'+operation[:23]+':'+secrets.token_hex(24)+'@unix(/run/mysqld/mysqld.sock)/aster_cloud_restore_'+operation,
            certificate_pem='eA==',private_key_pem='eA=='),
            configuration_sha='1'*64, plan_sha='2'*64)
        fd = os.open(private, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd,'w') as stream:
            json.dump(value,stream)
        parent = subprocess.Popen([str(binary),'native-process-rejection',str(private)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={'PATH':'/usr/bin:/bin','LANG':'C'})
        # Keep stdin open: EOF would request cancellation, not SQL rejection.
        status = parent.wait(timeout=20)
        out, err = parent.communicate(timeout=5)
        if status != 27 or out != b'VERIFICATION_CHILD_SQL\n' or err:
            known = set('VERIFICATION_HOST_GUARD VERIFICATION_HOST_EXECUTABLE VERIFICATION_LISTENER VERIFICATION_SPAWN VERIFICATION_HANDSHAKE VERIFICATION_EARLY_EXIT VERIFICATION_CHILD_AUTHORITY VERIFICATION_CHILD_IDENTITY VERIFICATION_CHILD_GUARD VERIFICATION_CHILD_BOOTSTRAP VERIFICATION_CHILD_LISTENER VERIFICATION_CHILD_RECHECK VERIFICATION_CHILD_SERVICE'.split())
            code = out.decode('ascii', errors='replace').removesuffix('\n')
            raise RuntimeError(code if code in known else 'PROCESS_REJECTION_UNCONFIRMED')
        fd = os.open(state/'runtime.lock', os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
        finally:
            os.close(fd)
        print(json.dumps(dict(schema=1, source_sha=args.source, passed=True,
            real_linux_processes=True, reached_minimum_sql_check=True, guard_drained=True,
            kernel_route_snapshot_verified=True,
            http_started=False, mysql_verified=False, migration_ready=False),sort_keys=True))
    finally:
        if parent is not None and parent.poll() is None:
            parent.kill(); parent.wait(timeout=10)
        # Only this dedicated subreaper's unreaped fixture descendants may be
        # signalled; never act on a PID imported from a file or user input.
        children = Path('/proc/self/task')/str(os.getpid())/'children'
        for raw in children.read_text().split():
            pid = int(raw)
            try:
                os.waitid(os.P_PID,pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
                os.kill(pid,signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(pid,0)
        shutil.rmtree(case)
        if state.is_dir() and not state.is_symlink():
            shutil.rmtree(state)


if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['--route-format-probe']:
            route_format_probe()
        else:
            main()
    except RuntimeError as exc:
        # All RuntimeError values above are fixed literals or allowlisted codes.
        print(str(exc),file=sys.stderr)
        raise SystemExit(1)
    except (OSError, ValueError, subprocess.SubprocessError):
        print('PROCESS_REJECTION_UNCONFIRMED',file=sys.stderr)
        raise SystemExit(1)

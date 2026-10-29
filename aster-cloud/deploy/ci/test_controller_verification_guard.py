#!/usr/bin/env python3
"""Real root/non-root Linux process and lock handoff, not HTTP/SQL activation.

Only nonce-named owned files/processes are used. The compiled fixture exercises
the public host API; no production test command, fake flock, or fake proc tree.
"""
import argparse
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time


def require(value, code):
    if not value:
        raise RuntimeError(code)


def line(fd):
    result = b''
    deadline = time.monotonic() + 15
    while not result.endswith(b'\n'):
        remaining = deadline - time.monotonic()
        require(remaining > 0 and select.select([fd], [], [], remaining)[0], 'PROCESS_NOTICE_TIMEOUT')
        data = os.read(fd, 1)
        require(bool(data) and len(result) < 4096, 'PROCESS_NOTICE_INVALID')
        result += data
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture-binary', type=Path, required=True)
    parser.add_argument('--source', required=True)
    args = parser.parse_args()
    require(sys.platform == 'linux' and os.geteuid() == 0, 'LINUX_ROOT_REQUIRED')
    require(re.fullmatch('[0-9a-f]{40}', args.source), 'SOURCE_REQUIRED')
    # Adopt only this process's orphaned descendants so their actual exit can be
    # waited on. Never identify or kill a stranger using a copied PID file.
    require(ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0, 'SUBREAPER_REQUIRED')
    nonce, operation = secrets.token_hex(12), secrets.token_hex(16)
    controller = 'aster-verify-guard-' + nonce
    state = Path('/var/lib/aster-controller') / controller
    require(not state.exists() and not state.is_symlink(), 'FRESH_CASE_REQUIRED')
    case = Path(tempfile.mkdtemp(prefix='aster-verify-guard-', dir='/tmp'))
    parent, child_pid = None, None
    descriptors = []
    try:
        # This directory contains only the public test ELF; no secrets or keys.
        case.chmod(0o755)
        binary = case/'fixture'
        shutil.copyfile(args.fixture_binary.resolve(strict=True), binary)
        binary.chmod(0o755)
        child_read, child_write = os.pipe()
        notice_read, notice_write = os.pipe()
        descriptors += [child_read, child_write, notice_read, notice_write]
        env = {'PATH': '/usr/bin:/bin', 'ASTER_GUARD_FIXTURE_ROLE': 'parent',
               'ASTER_GUARD_FIXTURE_ID': controller, 'ASTER_GUARD_FIXTURE_OPERATION': operation}
        # Go's ExtraFiles convention is used by the fixture parent. dup2 is in
        # a small separate exec shim, never preexec_fn in a threaded process.
        shim = 'import os,sys,fcntl; a,b=map(int,sys.argv[1:3]); x=fcntl.fcntl(a,fcntl.F_DUPFD_CLOEXEC,10); y=fcntl.fcntl(b,fcntl.F_DUPFD_CLOEXEC,10); os.dup2(x,3,inheritable=True); os.dup2(y,4,inheritable=True); os.close(x); os.close(y); [os.close(fd) for fd in {a,b}-{3,4}]; os.execve(sys.argv[3],[sys.argv[3],"-test.run=^TestNativeVerificationLeaseFixture$"],os.environ)'
        parent = subprocess.Popen([sys.executable, '-I', '-c', shim, str(child_read), str(notice_write), str(binary)],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  pass_fds=(child_read, notice_write), env=env)
        for fd in (child_read, notice_write):
            os.close(fd); descriptors.remove(fd)
        reply = json.loads(line(parent.stdout.fileno()))
        require(set(reply) == {'child_pid'} and type(reply['child_pid']) is int and reply['child_pid'] > 1, 'CHILD_ID_INVALID')
        child_pid = reply['child_pid']
        require(line(notice_read) == b'ready\n', 'NONROOT_CHILD_NOT_READY')
        seal = (state/'target-restore.json').read_bytes()
        seal_sha = hashlib.sha256(seal).hexdigest()
        require(stat.S_IMODE(state.stat().st_mode) == 0o700, 'STATE_NOT_PRIVATE')

        def probe(expected):
            fd = os.open(state/'runtime.lock', os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                drained = False
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    drained = True
                except BlockingIOError:
                    pass
                require(drained == expected, 'FALSE_PROCESS_DRAIN')
            finally:
                os.close(fd)
            require(hashlib.sha256((state/'target-restore.json').read_bytes()).hexdigest() == seal_sha, 'SEAL_CHANGED')

        def child_command(command):
            os.write(child_write, (command+'\n').encode())
            require(line(notice_read) == (command+'\n').encode(), 'CHILD_COMMAND_UNCONFIRMED')

        probe(False)
        child_command('unlock')
        probe(False)  # child LOCK_UN cannot affect the parent's separate OFD
        child_command('lock')
        probe(False)
        out, err = parent.communicate(b'exit\n', timeout=10)
        require(parent.returncode == 0 and not out and not err, 'PARENT_EXIT_UNCONFIRMED')
        parent = None
        probe(False)  # parent exit cannot release the still-live child's OFD
        os.write(child_write, b'exit\n')
        deadline = time.monotonic() + 10
        while True:
            pid, status = os.waitpid(child_pid, os.WNOHANG)
            if pid:
                require(os.waitstatus_to_exitcode(status) == 0, 'CHILD_EXIT_FAILED')
                child_pid = None
                break
            require(time.monotonic() < deadline, 'CHILD_EXIT_UNCONFIRMED')
            time.sleep(0.05)
        probe(True)
        print(json.dumps({'schema': 1, 'source_sha': args.source, 'passed': True, 'real_linux_processes': True,
                          'nonroot_child': True, 'independent_parent_child_locks': True,
                          'parent_descriptor_not_inherited': True,
                          'child_unlock_retains_parent_guard': True, 'parent_exit_retains_child_guard': True,
                          'both_processes_exited_before_drain': True, 'target_seal_unchanged': True,
                          'http_started': False, 'mysql_verified': False, 'migration_ready': False}, sort_keys=True))
    finally:
        if parent is not None:
            if parent.poll() is None:
                parent.kill()
            parent.communicate(timeout=10)
        if child_pid is not None:
            # This is our known, not-yet-reaped descendant, never an arbitrary PID.
            try:
                os.kill(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(child_pid, 0)
        # A fixture may fail after fork but before reporting its child's PID.
        # As this dedicated subreaper has spawned only the one fixture parent,
        # all remaining direct children are our adopted fixture descendants.
        children = Path('/proc/self/task')/str(os.getpid())/'children'
        for raw_pid in children.read_text().split():
            pid = int(raw_pid)
            try:
                os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(pid, 0)
        for fd in descriptors:
            os.close(fd)
        shutil.rmtree(case)
        if state.is_dir() and not state.is_symlink():
            shutil.rmtree(state)


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print('VERIFICATION_GUARD_FAILED_' + type(exc).__name__ + ': ' + str(exc), file=sys.stderr)
        raise SystemExit(1)

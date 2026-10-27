#!/usr/bin/env python3
"""CI-only real terminal selection -> anonymous verified download/readonly plan.

Never accepts an executable, URL, shell, apply/start flag or environment override.
The root CI runner has already checked out the reviewed exact main commit.
"""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import pty
import select
import signal
import stat
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--role', choices=('controller', 'node'), required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0 or not args.evidence.is_absolute() or args.evidence.exists() or args.evidence.is_symlink():
        raise RuntimeError('new absolute evidence and disposable Linux root runner required')
    tool = Path(__file__).resolve().parents[1] / 'install/cloud.py'
    if not tool.is_file() or tool.is_symlink():
        raise RuntimeError('reviewed unified entry missing')
    pid, fd = pty.fork()
    if pid == 0:
        os.execve('/usr/bin/python3', ['/usr/bin/python3', '-I', str(tool), '--download-only',
                                    '--evidence', str(args.evidence)], {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': '/root'})
    output, selected, state = bytearray(), False, None
    deadline = time.monotonic() + 12 * 60
    try:
        while time.monotonic() < deadline:
            if select.select([fd], [], [], 0.1)[0]:
                try:
                    data = os.read(fd, 65536)
                except OSError as exc:
                    if exc.errno != errno.EIO:
                        raise
                    data = b''
                output.extend(data)
                if len(output) > 4 * 1024 * 1024:
                    raise RuntimeError('bounded installer output exceeded')
                if not selected and '无默认选项：'.encode() in output:
                    os.write(fd, b'1\n' if args.role == 'controller' else b'2\n')
                    selected = True
            found, status = os.waitpid(pid, os.WNOHANG)
            if found:
                state = status
                break
        if state is None or not selected or os.waitstatus_to_exitcode(state) != 0:
            raise RuntimeError('actual unified bootstrap refused or timed out; no host apply was requested')
        info = args.evidence.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0 or not 0 < info.st_size <= 1024 * 1024:
            raise RuntimeError('public proof inode rejected')
        proof = json.loads(args.evidence.read_bytes())
        if not (proof.get('passed') is True and proof.get('role') == args.role and
                proof.get('host_apply') is False and proof.get('service_started') is False and
                proof.get('publisher_signature_reverified') is True and proof.get('production_installer_plan') is True):
            raise RuntimeError('public proof failed; no installation success claimed')
        print(json.dumps({'schema': 1, 'role': args.role, 'unified_role_menu_exercised': True,
                          'entry_sha256': hashlib.sha256(tool.read_bytes()).hexdigest(),
                          'public_proof_sha256': hashlib.sha256(args.evidence.read_bytes()).hexdigest(),
                          'host_apply': False, 'service_started': False}, sort_keys=True))
    finally:
        os.close(fd)
        if state is None:
            # This is the dedicated child session created above, never a host service.
            try:
                os.killpg(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            os.waitpid(pid, 0)


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, ValueError, KeyError):
        print('Unified public download acceptance failed; diagnostics withheld, no host apply requested.', file=sys.stderr)
        raise SystemExit(1)

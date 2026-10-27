#!/usr/bin/env python3
"""Actual command/controlling-terminal tests, never fake release signatures."""
import errno
import json
import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import sys
import time
import unittest

TOOL = Path(__file__).resolve().parents[1] / 'install/cloud.py'


def terminal(choice, *arguments):
    pid, fd = pty.fork()
    if pid == 0:
        os.execv(sys.executable, [sys.executable, '-I', str(TOOL), *arguments])
    output, sent, status = bytearray(), False, None
    deadline = time.monotonic() + 15
    try:
        while time.monotonic() < deadline:
            readable, _, _ = select.select([fd], [], [], 0.05)
            if readable:
                try:
                    data = os.read(fd, 4096)
                except OSError as exc:
                    if exc.errno != errno.EIO:
                        raise
                    data = b''
                output.extend(data)
                if len(output) > 16384:
                    raise AssertionError('terminal output exceeds test bound')
                if not sent and '无默认选项：'.encode() in output:
                    os.write(fd, choice)
                    sent = True
            found, state = os.waitpid(pid, os.WNOHANG)
            if found:
                status = state
                break
        if status is None:
            raise AssertionError('terminal did not exit')
        return os.waitstatus_to_exitcode(status), output.decode('utf-8', errors='replace')
    finally:
        os.close(fd)
        if status is None:
            os.kill(pid, signal.SIGTERM)
            os.waitpid(pid, 0)


class UnifiedInstallCLI(unittest.TestCase):
    def test_controller_and_node_share_one_actual_terminal_menu(self):
        for choice, role in ((b'1\n', 'controller'), (b'2\n', 'node')):
            with self.subTest(role=role):
                code, output = terminal(choice, '--select-only')
                self.assertEqual(code, 0, output)
                self.assertIn('安装云主控', output)
                self.assertIn('安装 KVM 被控', output)
                row = next(line for line in output.splitlines() if line.startswith('{'))
                self.assertEqual(json.loads(row), {'role': role, 'downloaded': False, 'installed': False})

    def test_cancel_and_blank_never_default_to_a_role(self):
        for choice, expected in ((b'0\n', 0), (b'\n', 1), (b'3\n', 1), (b'1; id\n', 1)):
            with self.subTest(choice=choice):
                code, output = terminal(choice, '--select-only')
                self.assertEqual(code, expected, output)
                self.assertNotIn('"role":', output)

    def test_eof_and_oversized_answer_never_start_downloads(self):
        for choice in (b'\x04', b'1' * 80 + b'\n'):
            code, output = terminal(choice, '--select-only')
            self.assertEqual(code, 1, output)
            self.assertNotIn('"role":', output)

    def test_explicit_automation_role_retains_the_same_selection_contract(self):
        for role in ('controller', 'node'):
            result = subprocess.run([sys.executable, '-I', str(TOOL), role, '--select-only'],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['role'], role)

    def test_pipe_input_without_a_controlling_terminal_is_not_an_approval(self):
        result = subprocess.run([sys.executable, '-I', str(TOOL), '--select-only'],
                                input='1\n', capture_output=True, text=True, timeout=10, start_new_session=True)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn('"role":', result.stdout)

    def test_cannot_inject_apply_start_url_or_change_readonly_evidence_mode(self):
        for arguments in (('--apply',), ('--start',), ('--url', 'https://example.invalid/'),
                          ('--evidence', '/tmp/no-write'), ('--select-only', '--resume'),
                          ('--select-only', '--download-only')):
            with self.subTest(arguments=arguments):
                result = subprocess.run([sys.executable, '-I', str(TOOL), 'controller', *arguments],
                                        capture_output=True, text=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()

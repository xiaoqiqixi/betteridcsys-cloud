#!/usr/bin/env python3
"""CLI contracts with simulated OS/APT boundaries, never native acceptance."""
import contextlib
import io
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name('prepare-cloud-runner.py')


class CloudRunnerCLI(unittest.TestCase):
    def setUp(self):
        self.case = tempfile.TemporaryDirectory(prefix='cloud-prep-test-')
        self.addCleanup(self.case.cleanup)
        self.root = Path(self.case.name).resolve()
        self.env_file = self.root / 'job-env'
        self.env_file.write_text('')
        self.env = dict(GITHUB_ACTIONS='true', RUNNER_ENVIRONMENT='github-hosted',
                        GITHUB_REPOSITORY='xiaoqiqixi/betteridcsys-cloud', GITHUB_REPOSITORY_ID='1435344151',
                        GITHUB_REF='refs/heads/main', GITHUB_EVENT_NAME='push', GITHUB_SHA='a' * 40,
                        GITHUB_RUN_ID='123456', GITHUB_RUN_ATTEMPT='1',
                        RUNNER_TEMP=str(self.root), GITHUB_ENV=str(self.env_file))
        self.commands = []

    def call(self, action, *, version='24.04', env=None):
        read_text = Path.read_text

        def read(path, *args, **kwargs):
            if str(path) == '/etc/os-release':
                return 'ID=ubuntu\nVERSION_ID="' + version + '"\n'
            return read_text(path, *args, **kwargs)

        def run(command, **kwargs):
            self.commands.append(command)
            return subprocess.CompletedProcess(command, 0)

        output, errors = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, self.env if env is None else env, clear=True), \
                patch.object(sys, 'argv', [str(SCRIPT), action]), \
                patch('platform.system', return_value='Linux'), patch('platform.machine', return_value='x86_64'), \
                patch.object(Path, 'read_text', read), patch('subprocess.run', side_effect=run), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            try:
                runpy.run_path(str(SCRIPT), run_name='__main__')
            except SystemExit as error:
                code = error.code
            else:
                code = 0
        return code, output.getvalue(), errors.getvalue()

    def test_preparation_is_cloud_only_and_exports_a_private_owned_case(self):
        code, output, error = self.call('prepare')
        self.assertEqual(code, 0, error)
        report = json.loads(output)
        self.assertFalse(report['native_acceptance_passed'])
        line = self.env_file.read_text().strip()
        self.assertTrue(line.startswith('ASTER_NATIVE_FIXTURE_ROOT='))
        case = Path(line.split('=', 1)[1])
        self.assertEqual(case.parent, self.root)
        self.assertRegex(case.name, r'^aster-cloud-ci\.[a-z0-9_]{8}$')
        self.assertEqual(case.stat().st_mode & 0o777, 0o700)
        self.assertEqual(len(self.commands), 2)
        self.assertIn('update', self.commands[0])
        self.assertIn('libaio1t64', self.commands[1])
        for name in ('mysql-server', 'nginx', 'libvirt-daemon-system', 'systemd'):
            self.assertNotIn(name, self.commands[1])

    def test_cleanup_deletes_only_its_own_case_without_following_links(self):
        self.assertEqual(self.call('prepare')[0], 0)
        case = Path(self.env_file.read_text().strip().split('=', 1)[1])
        outside = self.root / 'outside'
        outside.mkdir()
        (outside / 'keep').write_text('unchanged')
        (case / 'link').symlink_to(outside, target_is_directory=True)
        env = dict(self.env, ASTER_NATIVE_FIXTURE_ROOT=str(case))
        self.commands.clear()
        code, output, error = self.call('cleanup', env=env)
        self.assertEqual(code, 0, error)
        self.assertTrue(json.loads(output)['removed'])
        self.assertFalse(case.exists())
        self.assertEqual((outside / 'keep').read_text(), 'unchanged')
        self.assertEqual(self.commands, [])

    def test_other_repositories_events_platforms_and_root_cannot_prepare(self):
        for key, value in (('GITHUB_REPOSITORY', 'xiaoqiqixi/betteridcsys'),
                           ('GITHUB_REPOSITORY_ID', '1418618420'), ('GITHUB_ACTIONS', 'false'),
                           ('RUNNER_ENVIRONMENT', 'self-hosted'), ('GITHUB_REF', 'refs/heads/other'),
                           ('GITHUB_EVENT_NAME', 'pull_request_target'), ('GITHUB_SHA', 'main'),
                           ('GITHUB_RUN_ID', '0'), ('GITHUB_RUN_ATTEMPT', '1\nINJECT=1')):
            with self.subTest(key=key):
                code, _, _ = self.call('prepare', env=dict(self.env, **{key: value}))
                self.assertEqual(code, 1)
        self.assertEqual(self.call('prepare', version='26.04')[0], 1)
        with patch('os.geteuid', return_value=0):
            self.assertEqual(self.call('prepare')[0], 1)
        self.assertEqual(self.commands, [])
        self.assertEqual(self.env_file.read_text(), '')
        self.assertEqual(list(self.root.glob('aster-cloud-ci.*')), [])

    def test_environment_output_cannot_be_a_symlink_or_shared_writable_file(self):
        link = self.root / 'env-link'
        link.symlink_to(self.env_file)
        self.assertEqual(self.call('prepare', env=dict(self.env, GITHUB_ENV=str(link)))[0], 1)
        self.env_file.chmod(0o666)
        self.assertEqual(self.call('prepare')[0], 1)
        self.assertEqual(self.commands, [])
        self.assertEqual(self.env_file.read_text(), '')

    def test_jammy_uses_its_own_runtime_libraries_and_no_unsigned_apt(self):
        code, _, error = self.call('prepare', version='22.04')
        self.assertEqual(code, 0, error)
        for name in ('libaio1', 'libssl3', 'libtirpc3'):
            self.assertIn(name, self.commands[1])
        self.assertNotIn('libaio1t64', self.commands[1])
        for command in self.commands:
            for option in ('APT::Get::AllowUnauthenticated=false', 'Acquire::AllowInsecureRepositories=false',
                           'Acquire::AllowDowngradeToInsecureRepositories=false'):
                self.assertIn(option, command)

    def test_cleanup_refuses_foreign_run_marker_and_outside_path(self):
        self.assertEqual(self.call('prepare')[0], 0)
        case = Path(self.env_file.read_text().strip().split('=', 1)[1])
        self.commands.clear()
        changed = dict(self.env, ASTER_NATIVE_FIXTURE_ROOT=str(case), GITHUB_RUN_ID='999')
        self.assertEqual(self.call('cleanup', env=changed)[0], 1)
        self.assertTrue(case.is_dir())
        self.assertEqual(self.call('cleanup', env=dict(self.env, ASTER_NATIVE_FIXTURE_ROOT=str(self.root)))[0], 1)
        marker = case / '.cloud-ci-owner.json'
        marker.unlink()
        marker.symlink_to(self.env_file)
        self.assertEqual(self.call('cleanup', env=dict(self.env, ASTER_NATIVE_FIXTURE_ROOT=str(case)))[0], 1)
        self.assertTrue(case.is_dir())
        self.assertEqual(self.commands, [])

    def test_missing_fixture_cleanup_is_noop_and_arguments_are_not_commands(self):
        code, output, error = self.call('cleanup')
        self.assertEqual(code, 0, error)
        self.assertFalse(json.loads(output)['removed'])
        self.assertEqual(self.call('/bin/sh')[0], 2)
        self.assertEqual(self.commands, [])


if __name__ == '__main__':
    unittest.main()

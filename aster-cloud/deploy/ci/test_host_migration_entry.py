#!/usr/bin/env python3
"""Public CLI parsing/safety surface, never a claim of systemd acceptance."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

ENTRY = Path(__file__).resolve().parents[1] / 'install/controller-migration.py'


class HostMigrationEntry(unittest.TestCase):
    def invoke(self, *args):
        return subprocess.run([sys.executable, '-I', str(ENTRY), *args], capture_output=True, timeout=10)

    def test_capabilities_keep_source_isolation_distinct_from_completed_migration(self):
        r = self.invoke('capabilities')
        self.assertEqual(r.returncode, 0)
        value = json.loads(r.stdout)
        self.assertEqual(value['protocol'], 'aster.controller-migration/1')
        self.assertEqual(value['actions'], ['plan', 'isolate', 'status', 'resume-source', 'export', 'target-plan', 'target-seal', 'target-status', 'target-database-plan', 'target-provision', 'target-restore', 'target-data-status', 'target-materials', 'target-material-status', 'target-revoke-sessions', 'target-session-status', 'target-session-resume', 'target-configuration-plan', 'target-configuration-publish', 'target-configuration-status', 'target-configuration-resume', 'target-verification-plan', 'target-verification-prepare', 'target-verification-status'])
        self.assertIs(value['export_restore'], False)
        self.assertIs(value['migration_ready'], False)

    def test_no_paths_shell_unit_or_implicit_resume_overrides(self):
        for args in [(), ('isolate',), ('export',), ('target-plan',), ('target-provision',), ('target-restore',), ('target-materials',), ('target-material-status', '--destination', '/tmp'), ('target-materials', '--dsn', 'PRIVATE_SENTINEL'), ('target-restore', '--sql', 'PRIVATE_SENTINEL'), ('target-data-status', '--root', '/tmp'), ('target-database-plan', '--dsn', 'PRIVATE_SENTINEL'), ('target-provision', '--database', 'foreign'), ('target-provision', '--resume'), ('target-seal', '--operation', '../escape'), ('target-status', '--root', '/tmp'), ('export', '--operation', '../escape'), ('isolate', '--operation', '../escape'),
                     ('plan', '--unit', 'ssh.service'), ('plan', '--root', '/tmp'),
                     ('plan', '--config', 'PRIVATE_SENTINEL'), ('plan', '--shell', '/bin/sh'),
                     ('resume-source', '--operation', 'A' * 32)]:
            with self.subTest(args=args):
                r = self.invoke(*args)
                self.assertNotEqual(r.returncode, 0)
                self.assertEqual(r.stdout, b'')
                self.assertNotIn(b'PRIVATE_SENTINEL', r.stderr)

    def test_session_commands_accept_only_the_fixed_operation(self):
        for action in ('target-revoke-sessions', 'target-session-status', 'target-session-resume'):
            for args in ((), ('--operation', '../escape'), ('--operation', 'a' * 32, '--force'),
                         ('--operation', 'a' * 32, '--intent', 'PRIVATE_SENTINEL'),
                         ('--operation', 'a' * 32, '--dsn', 'PRIVATE_SENTINEL'),
                         ('--operation', 'a' * 32, '--timestamp', '2026-10-28')):
                with self.subTest(action=action, args=args):
                    r = self.invoke(action, *args)
                    self.assertEqual(r.returncode, 1)
                    self.assertEqual(r.stdout, b'')
                    self.assertNotIn(b'PRIVATE_SENTINEL', r.stderr)

    def test_configuration_plan_has_no_freeform_host_or_secret_overrides(self):
        for args in ((), ('--operation', '../escape'), ('--operation', 'a' * 32, '--force'),
                     ('--operation', 'a' * 32, '--config', 'PRIVATE_SENTINEL'),
                     ('--operation', 'a' * 32, '--origin', 'https://foreign.invalid'),
                     ('--operation', 'a' * 32, '--cert', 'PRIVATE_SENTINEL'),
                     ('--operation', 'a' * 32, '--session-proof', 'PRIVATE_SENTINEL')):
            with self.subTest(args=args):
                r = self.invoke('target-configuration-plan', *args)
                self.assertEqual(r.returncode, 1)
                self.assertEqual(r.stdout, b'')
                self.assertNotIn(b'PRIVATE_SENTINEL', r.stderr)

    def test_publication_commands_never_accept_free_paths_or_implicit_approval(self):
        for action in ('target-configuration-publish','target-configuration-status','target-configuration-resume'):
            for extra in ((), ('--operation','../escape'), ('--operation','a'*32,'--approve'),
                          ('--operation','a'*32,'--force'), ('--operation','a'*32,'--destination','/etc'),
                          ('--operation','a'*32,'--approval','PRIVATE_SENTINEL')):
                with self.subTest(action=action,extra=extra):
                    result=self.invoke(action,*extra)
                    self.assertEqual(result.returncode,1)
                    self.assertEqual(result.stdout,b'')
                    self.assertNotIn(b'PRIVATE_SENTINEL',result.stderr)



    def test_verification_account_commands_accept_no_credentials_or_grant_overrides(self):
        for action in ('target-verification-prepare','target-verification-status'):
            for extra in ((), ('--operation','../escape'), ('--operation','a'*32,'--password','PRIVATE_SENTINEL'),
                          ('--operation','a'*32,'--user','root'), ('--operation','a'*32,'--grant','ALL'),
                          ('--operation','a'*32,'--force'), ('--operation','a'*32,'--start'),
                          ('--operation','a'*32,'--approval','PRIVATE_SENTINEL')):
                with self.subTest(action=action,extra=extra):
                    result=self.invoke(action,*extra)
                    self.assertEqual(result.returncode,1)
                    self.assertEqual(result.stdout,b'')
                    self.assertNotIn(b'PRIVATE_SENTINEL',result.stderr)

    def test_verification_plan_accepts_only_an_exact_operation(self):
        for extra in ((), ('--operation','../escape'), ('--operation','a'*32,'--dsn','PRIVATE_SENTINEL'),
                      ('--operation','a'*32,'--grant','ALL'), ('--operation','a'*32,'--start'),
                      ('--operation','a'*32,'--force'), ('--operation','a'*32,'--config','PRIVATE_SENTINEL')):
            with self.subTest(extra=extra):
                result=self.invoke('target-verification-plan',*extra)
                self.assertEqual(result.returncode,1)
                self.assertEqual(result.stdout,b'')
                self.assertNotIn(b'PRIVATE_SENTINEL',result.stderr)

if __name__ == '__main__':
    unittest.main()

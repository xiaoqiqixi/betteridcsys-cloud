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
        self.assertEqual(value['actions'], ['plan', 'isolate', 'status', 'resume-source', 'export', 'target-plan', 'target-seal', 'target-status', 'target-database-plan', 'target-provision', 'target-restore', 'target-data-status'])
        self.assertIs(value['export_restore'], False)
        self.assertIs(value['migration_ready'], False)

    def test_no_paths_shell_unit_or_implicit_resume_overrides(self):
        for args in [(), ('isolate',), ('export',), ('target-plan',), ('target-provision',), ('target-restore',), ('target-restore', '--sql', 'PRIVATE_SENTINEL'), ('target-data-status', '--root', '/tmp'), ('target-database-plan', '--dsn', 'PRIVATE_SENTINEL'), ('target-provision', '--database', 'foreign'), ('target-provision', '--resume'), ('target-seal', '--operation', '../escape'), ('target-status', '--root', '/tmp'), ('export', '--operation', '../escape'), ('isolate', '--operation', '../escape'),
                     ('plan', '--unit', 'ssh.service'), ('plan', '--root', '/tmp'),
                     ('plan', '--config', 'PRIVATE_SENTINEL'), ('plan', '--shell', '/bin/sh'),
                     ('resume-source', '--operation', 'A' * 32)]:
            with self.subTest(args=args):
                r = self.invoke(*args)
                self.assertNotEqual(r.returncode, 0)
                self.assertEqual(r.stdout, b'')
                self.assertNotIn(b'PRIVATE_SENTINEL', r.stderr)


if __name__ == '__main__':
    unittest.main()

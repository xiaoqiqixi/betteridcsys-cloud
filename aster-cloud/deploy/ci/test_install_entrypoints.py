#!/usr/bin/env python3
"""Published command/document CLI contracts; no host install or fake crypto proof."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
TOOL = Path(__file__).with_name('check_install_entrypoints.py')
URL = 'https://raw.githubusercontent.com/xiaoqiqixi/betteridcsys/8092c3cc0517c69562e8a5cdd94bc5e389e1bc8e/aster-cloud/deploy/install/release_verify.py'
# Independent literal copied from the observed immutable public Release body.
CONTROLLER = "bash -o pipefail -c 'curl --fail --silent --show-error --proto \"=https\" --tlsv1.2 --connect-timeout 10 --max-time 60 --max-filesize 1048576 " + URL + " | sudo /usr/bin/python3 -I - controller'"
NODE = CONTROLLER.replace(" - controller'", " - node'")


class InstallEntrypoints(unittest.TestCase):
    def run_check(self, path, *args):
        return subprocess.run([sys.executable, str(TOOL), '--readme', str(path), *args], capture_output=True, text=True, timeout=10)

    def test_user_readme_has_both_real_role_commands(self):
        result = self.run_check(ROOT / 'README.md')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['roles'], ['controller', 'node'])

    def test_mutable_source_or_bypass_or_missing_role_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'README.md'
            canonical = '# Install\n```sh\n' + CONTROLLER + '\n```\n```sh\n' + NODE + '\n```\n'
            for changed in (canonical.replace('8092c3cc0517c69562e8a5cdd94bc5e389e1bc8e', 'main'),
                            canonical.replace(' --fail', ''), canonical.replace(' -I ', ' '),
                            canonical.replace(" - controller'", " - controller --apply'"),
                            canonical.replace(NODE, CONTROLLER), canonical.replace('python3', 'bash')):
                with self.subTest(command=changed[:80]):
                    path.write_text(changed)
                    result = self.run_check(path)
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertIn('Published command check refused:', result.stderr)
            path.write_text(canonical)
            self.assertEqual(self.run_check(path).returncode, 0)

    def test_bootstrap_bytes_must_match_published_immutable_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            readme = Path(directory) / 'README.md'
            readme.write_text('```sh\n' + CONTROLLER + '\n```\n```sh\n' + NODE + '\n```\n')
            wrong = Path(directory) / 'bootstrap.py'; wrong.write_bytes(b'# changed bootstrap\n')
            result = self.run_check(readme, '--bootstrap', str(wrong))
            self.assertEqual(result.returncode, 1)
            self.assertIn('bootstrap digest mismatch', result.stderr)
            result = self.run_check(readme, '--bootstrap', str(ROOT / 'aster-cloud/deploy/install/release_verify.py'))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIs(json.loads(result.stdout)['bootstrap_matches_published_bytes'], True)

    def test_live_metadata_must_match_release_id_state_and_exact_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            readme = Path(directory) / 'README.md'
            text = '```sh\n' + CONTROLLER + '\n```\n```sh\n' + NODE + '\n```\n'
            readme.write_text(text)
            path = Path(directory) / 'release.json'
            valid = {'id': 425041579, 'tag_name': 'cloud-v0.1.0-rc.1', 'draft': False, 'prerelease': True,
                     'html_url': 'https://github.com/xiaoqiqixi/betteridcsys/releases/tag/cloud-v0.1.0-rc.1', 'body': text}
            path.write_text(json.dumps(valid))
            result = self.run_check(readme, '--release-metadata', str(path))
            self.assertEqual(result.returncode, 0, result.stderr)
            for key, value in (('id', 1), ('draft', True), ('prerelease', False), ('tag_name', 'cloud-v0.1.0'), ('body', text.replace('8092c3cc0517c69562e8a5cdd94bc5e389e1bc8e', 'main'))):
                with self.subTest(key=key):
                    path.write_text(json.dumps(dict(valid, **{key: value})))
                    result = self.run_check(readme, '--release-metadata', str(path))
                    self.assertEqual(result.returncode, 1)
                    self.assertIn('public release identity or documented commands changed', result.stderr)


if __name__ == '__main__':
    unittest.main()

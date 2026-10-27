#!/usr/bin/env python3
"""Offline evidence/secret guard regressions; not actual browser acceptance."""
import copy
import tempfile
import unittest
from pathlib import Path
from members_browser_contract import (
    MEMBERS_ACCEPTANCE, MEMBERS_CHECKS, MEMBERS_SCREENSHOTS,
    validate_members_browser_report,
)


class MembersBrowserContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name)
        self.report = {
            'members_acceptance': dict(MEMBERS_ACCEPTANCE),
            'members_checks': [{'name': name, 'passed': True} for name in sorted(MEMBERS_CHECKS)],
            'members_screenshots': sorted(MEMBERS_SCREENSHOTS),
        }
        # Only the file signature guard is under test; these are not UI screenshots.
        for name in MEMBERS_SCREENSHOTS:
            (self.output / name).write_bytes(b'\x89PNG\r\n\x1a\n')

    def validate(self, value=None):
        return validate_members_browser_report(self.report if value is None else value, self.output)

    def test_complete_fixed_contract(self):
        self.assertEqual(self.validate(), MEMBERS_SCREENSHOTS)
        self.assertEqual(len(MEMBERS_CHECKS), 18)
        self.assertEqual(len(MEMBERS_SCREENSHOTS), 6)

    def test_wrong_or_coerced_values_rejected(self):
        for key, value in MEMBERS_ACCEPTANCE.items():
            for bad in ([int(value), not value, 'true', None] if isinstance(value, bool) else [True, str(value), value + 1, None]):
                with self.subTest(key=key, bad=bad):
                    candidate = copy.deepcopy(self.report)
                    candidate['members_acceptance'][key] = bad
                    with self.assertRaises(ValueError):
                        self.validate(candidate)

    def test_secret_or_unknown_proof_fields_rejected(self):
        for field in ('password', 'viewer_password', 'cookie', 'ids', 'cursor', 'raw_response', 'extra'):
            candidate = copy.deepcopy(self.report)
            candidate['members_acceptance'][field] = 'sensitive-placeholder'
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(candidate)

    def test_missing_summary_and_wrong_structures_rejected(self):
        for value in ({}, [], None, False):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_members_browser_report(value, self.output)
        for key in self.report:
            for value in (None, False, {}, 'bad'):
                candidate = copy.deepcopy(self.report); candidate[key] = value
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    self.validate(candidate)

    def test_missing_duplicate_unknown_or_unpassed_checks_rejected(self):
        candidates = []
        for index in range(len(MEMBERS_CHECKS)):
            candidate = copy.deepcopy(self.report); candidate['members_checks'].pop(index); candidates.append(candidate)
        for bad in ({'name': 'fake', 'passed': True}, {'name': sorted(MEMBERS_CHECKS)[0], 'passed': True}, {'name': sorted(MEMBERS_CHECKS)[1], 'passed': 1}, {'name': sorted(MEMBERS_CHECKS)[1], 'passed': False}, {'name': sorted(MEMBERS_CHECKS)[1], 'passed': True, 'password': 'secret'}, {'name': [], 'passed': True}):
            candidate = copy.deepcopy(self.report); candidate['members_checks'][1] = bad; candidates.append(candidate)
        for candidate in candidates:
            with self.subTest(checks=candidate['members_checks']), self.assertRaises(ValueError):
                self.validate(candidate)

    def test_each_screenshot_required(self):
        for name in MEMBERS_SCREENSHOTS:
            file = self.output / name; data = file.read_bytes(); file.unlink()
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.validate()
            file.write_bytes(data)

    def test_no_path_injection_or_duplicate_names(self):
        for value in ('../private.png', '/tmp/private.png', 'secret.json', sorted(MEMBERS_SCREENSHOTS)[1], None, {}):
            candidate = copy.deepcopy(self.report); candidate['members_screenshots'][0] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.validate(candidate)

    def test_symlinks_and_non_png_are_rejected(self):
        file = self.output / sorted(MEMBERS_SCREENSHOTS)[0]; file.unlink()
        target = self.output / 'private.png'; target.write_bytes(b'\x89PNG\r\n\x1a\n')
        file.symlink_to(target)
        with self.assertRaises(ValueError): self.validate()
        file.unlink(); file.write_text('not-a-real-PNG')
        with self.assertRaises(ValueError): self.validate()

    def test_integration_retains_separate_original_evidence(self):
        root = Path(__file__).parent
        shell = (root / 'network-browser.sh').read_text()
        browser = (root / 'network-browser.mjs').read_text()
        members = (root / 'members-browser.mjs').read_text()
        self.assertIn('await membersBrowserAcceptance({ page, output, report, base, credentials })', browser)
        self.assertIn('credentials.members_page?.viewer_password', browser)
        self.assertIn('validate_members_browser_report(report, output)', shell)
        self.assertIn('set(business_screenshots) | required_sidebar | required_members', shell)
        self.assertIn("== 52", shell)
        self.assertIn("len(sidebar_screenshots) == 12", shell)
        self.assertIn("len(report.get('checks', [])) >= 163", shell)
        self.assertIn('len(sidebar_checks) >= 53', shell)
        self.assertIn("value.get('members_unchanged') is True", shell)
        for forbidden in ('route.fulfill(', 'route.fetch(', 'ignoreHTTPSErrors', 'storageState(', 'addInitScript('):
            self.assertNotIn(forbidden, members)
        self.assertNotIn('report.checks.push', members)
        self.assertNotIn('report.screenshots.push', members)


if __name__ == '__main__':
    unittest.main()

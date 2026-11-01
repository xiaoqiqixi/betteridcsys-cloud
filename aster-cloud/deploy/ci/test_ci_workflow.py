#!/usr/bin/env python3
"""PR admission and documented job inventory; full YAML is checked by actionlint."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = (ROOT/'.github/workflows/ci.yml').read_text()
DOC = (ROOT/'docs/development/README.md').read_text()
JOBS = dict(re.findall(r'^  ([a-z][a-z0-9-]+):\n(.*?)(?=^  [a-z][a-z0-9-]+:|\Z)',
                       WORKFLOW.split('jobs:\n', 1)[1], re.M | re.S))
SAME_REPO = "if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository"


class WorkflowContract(unittest.TestCase):
    def test_pull_requests_have_read_only_checks_and_main_runs_finish(self):
        events = WORKFLOW.split('permissions:', 1)[0]
        self.assertRegex(events, r'(?m)^  pull_request:\s*$')
        self.assertNotIn('pull_request_target:', events)
        self.assertIn('permissions:\n  contents: read\n', WORKFLOW)
        self.assertIn("group: checks-${{ github.ref == 'refs/heads/main' && github.sha || github.ref }}", WORKFLOW)
        self.assertIn("cancel-in-progress: ${{ github.ref != 'refs/heads/main' }}", WORKFLOW)
        for job in ('go-unit', 'frontend'):
            self.assertNotRegex(JOBS[job], r'(?m)^    if:')

    def test_native_jobs_run_on_same_repo_prs_and_skip_forks(self):
        for job, body in JOBS.items():
            if job.startswith('native-') or job == 'network-browser' or 'secrets.' in body:
                with self.subTest(job=job):
                    self.assertIn('    '+SAME_REPO+'\n', body)
        self.assertNotIn('secrets.', JOBS['go-unit']+JOBS['frontend'])

    def test_documented_inventory_matches_expanded_matrices(self):
        documented = {job: int(count) for job, count in re.findall(r'\| `([a-z][a-z0-9-]+)` \| ([0-9]+) \|', DOC)}
        self.assertEqual(set(documented), set(JOBS))
        total = 0
        for job, body in JOBS.items():
            count = 1
            if '      matrix:\n' in body:
                matrix = body.split('      matrix:\n', 1)[1].split('    runs-on:', 1)[0]
                if '        include:\n' in matrix:
                    count = len(re.findall(r'^          - ', matrix, re.M))
                else:
                    axes = re.findall(r'^        [a-z]+: \[([^\]]+)\]', matrix, re.M)
                    self.assertTrue(axes, 'unrecognized matrix: '+job)
                    for axis in axes:
                        count *= len(axis.split(','))
            self.assertEqual(documented[job], count, job)
            total += count
        self.assertEqual(total, 18)
        self.assertIn('**18 项任务**', DOC)


if __name__ == '__main__':
    unittest.main()

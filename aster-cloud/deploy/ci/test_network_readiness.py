#!/usr/bin/env python3
"""Read-only host-observation/time contracts, not real host readiness proof."""
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('network_readiness_contract', HERE/'network-readiness.py')
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


class NetworkReadiness(unittest.TestCase):
    def observe(self, sequence):
        # Inject only the external OS observation and monotonic clock boundaries.
        # There is no mocked harness/validator, VM, crypto or production module.
        now = [0.0]
        samples = []
        def clock(): return now[0]
        def sleep(seconds):
            self.assertEqual(seconds, 5)
            now[0] += seconds
        def snapshot():
            samples.append(now[0])
            return sequence(now[0])
        return r.wait_for_network(snapshot, clock, sleep), samples

    @staticmethod
    def state(version=0):
        return {'addresses': [{'ifindex': version+1, 'private_value': 'NOT_FOR_OUTPUT'}],
                'routes': [], 'firewall': {}}

    def test_an_initial_snapshot_is_not_readiness(self):
        report, times = self.observe(lambda _: self.state())
        self.assertTrue(report['ready'])
        self.assertEqual(times[-1], 60)
        self.assertEqual(report['samples'], 13)
        self.assertEqual(report['transitions'], 0)
        self.assertEqual(report['stable_seconds'], 60)
        self.assertNotIn('NOT_FOR_OUTPUT', json.dumps(report))

    def test_late_interface_change_restarts_stability_before_any_test_work(self):
        report, times = self.observe(lambda at: self.state(int(at>=55)))
        self.assertEqual(times[-1], 85)
        self.assertEqual(report['transitions'], 1)
        self.assertEqual(report['stable_seconds'], 30)
        self.assertNotIn('NOT_FOR_OUTPUT', json.dumps(report))

    def test_routes_and_firewall_are_not_excluded_from_readiness(self):
        for section in ('routes','firewall'):
            def observed(at):
                value=self.state()
                if at>=55:value[section]={'changed':True}
                return value
            with self.subTest(section=section):
                report,times=self.observe(observed)
                self.assertEqual(times[-1],85)
                self.assertEqual(report['transitions'],1)

    def test_continuous_change_exhausts_budget_without_claiming_ready(self):
        with self.assertRaisesRegex(r.NotReady, '^HOST_NETWORK_NOT_READY$'):
            self.observe(lambda at:self.state(int(at)))

    def test_missing_or_unreadable_observation_never_becomes_a_baseline(self):
        for value in ({}, {'addresses': [], 'routes': []}, None):
            with self.subTest(value=value), self.assertRaises(r.NotReady):
                self.observe(lambda _:value)
        def unreadable(_): raise OSError('PRIVATE_COMMAND_ERROR')
        with self.assertRaisesRegex(r.NotReady, '^HOST_NETWORK_OBSERVATION_UNAVAILABLE$'):
            self.observe(unreadable)

    def test_clock_regression_or_stalled_clock_is_refused_with_bounded_samples(self):
        for clock in (lambda:0.0, iter([0.0, -1.0]).__next__):
            with self.subTest(clock=clock), self.assertRaises(r.NotReady):
                r.wait_for_network(lambda:self.state(),clock,lambda _:None)

    def test_slow_first_read_does_not_count_as_observed_stability(self):
        now=[0.0]
        first=[True]
        def read():
            if first[0]:now[0]+=60;first[0]=False
            return self.state()
        def sleep(seconds):now[0]+=seconds
        report=r.wait_for_network(read,lambda:now[0],sleep)
        self.assertEqual(report['elapsed_seconds'],90)
        self.assertEqual(report['stable_seconds'],30)

    def test_workflow_waits_before_each_native_harness_without_changing_its_guard(self):
        workflow=(HERE.parents[2]/'.github/workflows/ci.yml').read_text()
        for job in ('native-libvirt','native-controller-provision'):
            with self.subTest(job=job):
                section=re.search(r'^  '+job+r':\n(.*?)(?=^  [a-z][a-z-]*:|\Z)',workflow,re.M|re.S).group(1)
                command='python3 -I aster-cloud/deploy/ci/network-readiness.py'
                self.assertEqual(section.count(command),1)
                self.assertLess(section.index(command),section.index('python3 -I aster-cloud/deploy/ci/libvirt-native.py'))
                self.assertIn('host_network_pre_vm_proof',section)
                self.assertIn('host_network_proof',section)
        self.assertIn('python3 -B aster-cloud/deploy/ci/test_network_readiness.py',workflow)

    def test_cli_cannot_shorten_readiness_or_skip_network_checks(self):
        for args in (['--skip'],['--retry'],['--minimum','0'],['--deadline','0']):
            with self.subTest(args=args):
                result=subprocess.run([sys.executable,'-I',str(HERE/'network-readiness.py'),*args],capture_output=True,timeout=10)
                self.assertEqual(result.returncode,2)


if __name__=='__main__':
    unittest.main(verbosity=2)

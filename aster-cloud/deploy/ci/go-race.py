#!/usr/bin/env python3
"""Run all cloud Go packages once; isolate the memory-hard archive CLI suite.

This changes scheduling, not coverage, per-package deadlines, race detection,
archive cryptography, or native-test routing. No output includes the test DSN.
"""
import argparse
import re
import subprocess
import sys

NATIVE = '^(TestRootTLSConnectorUsesExistingProtectedTransport|TestNativeOVSParserFlows|TestNativeOVSParserMeters|TestNativeNATPacketFlowAndRevocation|TestNativeNATInternetEgressAndRevocation)$'
CONTROLLER = 'aster/cloud/cmd/aster-controller'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-mysql', action='store_true')
    args = parser.parse_args()
    found = subprocess.run(['go', 'list', '-mod=readonly', './...'], text=True, capture_output=True)
    packages = found.stdout.splitlines()
    if found.returncode or CONTROLLER not in packages or len(packages) != len(set(packages)) or not all(
            re.fullmatch(r'aster/cloud/[a-zA-Z0-9_/-]+', p) and '/..' not in p for p in packages):
        print('GO_PACKAGE_DISCOVERY_REJECTED', file=sys.stderr)
        return 1
    common = ['go', 'test', '-mod=readonly', '-race', '-count=1', '-v', '-timeout=10m']
    if args.native_mysql:
        common += ['-skip', NATIVE]
    for group in ([CONTROLLER], [p for p in packages if p != CONTROLLER]):
        if group:
            result = subprocess.run(common + group)
            if result.returncode:
                return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

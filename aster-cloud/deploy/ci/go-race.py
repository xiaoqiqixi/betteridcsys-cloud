#!/usr/bin/env python3
"""Run every cloud Go test once; give memory-hard source validation its own process.

This changes scheduling, not coverage, per-package deadlines, race detection,
archive cryptography, or native-test routing. No output includes the test DSN.
"""
import argparse
import re
import subprocess
import sys

NATIVE = '^(TestRootTLSConnectorUsesExistingProtectedTransport|TestNativeOVSParserFlows|TestNativeOVSParserMeters|TestNativeNATPacketFlowAndRevocation|TestNativeNATInternetEgressAndRevocation)$'
CONTROLLER = 'aster/cloud/cmd/aster-controller'
SOURCE = '^TestControllerSourceValidation$'


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
    native_skip = ['-skip', NATIVE] if args.native_mysql else []
    # A source validation test can fit the same 10-minute bound while the entire
    # CLI package cannot. Isolate that complete test, not a regex-selected subset
    # of its negative cases. The second invocation explicitly excludes it.
    controller_skip = SOURCE + ('|' + NATIVE if args.native_mysql else '')
    groups = [common + ['-run', SOURCE, *native_skip, CONTROLLER],
              common + ['-skip', controller_skip, CONTROLLER]]
    others = [p for p in packages if p != CONTROLLER]
    if others:
        groups.append(common + native_skip + others)
    for command in groups:
        result = subprocess.run(command)
        if result.returncode:
            return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

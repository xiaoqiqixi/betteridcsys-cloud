#!/usr/bin/env python3
"""Go timestamp compatibility, including Python 3.10's restricted ISO parser."""
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


manager = load('timestamp_manager', ROOT/'install/controller-migration.py')
native = load('timestamp_native', ROOT/'ci/verification-process-native.py')


class TimestampTests(unittest.TestCase):
    def test_zero_to_nine_fractional_digits_and_offsets(self):
        for digits in range(10):
            fraction = '123456789'[:digits]
            for suffix, offset in [('Z', 0), ('+08:30', 510), ('-04:15', -255)]:
                with self.subTest(digits=digits, suffix=suffix):
                    value = '2026-11-01T12:34:56' + ('.'+fraction if fraction else '') + suffix
                    expected = datetime(2026, 11, 1, 12, 34, 56,
                        int(fraction.ljust(6, '0')[:6]), timezone(timedelta(minutes=offset)))
                    self.assertEqual(manager.parse_rfc3339(value), expected)
        self.assertEqual(manager.parse_rfc3339('2026-11-01T12:34:56.999999999Z').microsecond, 999999)

    def test_strict_rejections(self):
        for value in [None, 1, '', '2026-11-01', '2026-11-01T12:34:56',
                      '2026-11-01T12:34:56.Z', '2026-11-01T12:34:56.1234567890Z',
                      '2026-11-01 12:34:56Z', '2026-11-01t12:34:56z',
                      '2026-11-01T12:34:56,123Z', '2026-11-01T12:34:56+00:00:00',
                      '2026-11-01T12:34:56+24:00', '2026-11-01T12:34:56+00:60',
                      '2026-02-29T12:34:56Z', '2026-11-01T24:34:56Z',
                      '2026-11-01T12:60:56Z', '2026-11-01T12:34:60Z',
                      '2026-11-01T12:34:56Z\n']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                manager.parse_rfc3339(value)

    def test_native_acceptance_uses_the_installed_parser(self):
        with tempfile.TemporaryDirectory() as root:
            version = Path(root)
            entry = version/'templates/host-management/controller-migration.py'
            entry.parent.mkdir(parents=True)
            entry.write_bytes((ROOT/'install/controller-migration.py').read_bytes())
            for digits in range(1, 10):
                value = '2026-11-01T12:34:56.'+'123456789'[:digits]+'Z'
                self.assertEqual(native.phase_expiry(version, value), manager.parse_rfc3339(value))


if __name__ == '__main__':
    unittest.main()

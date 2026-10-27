#!/usr/bin/env python3
"""Verify the vendored public protocol only; no billing implementation or IO."""
from pathlib import Path
import hashlib
import json
root = Path(__file__).resolve().parents[1]
base = root / 'contracts/billing'
metadata = json.loads((base / 'UPSTREAM.json').read_text())
assert metadata['schema'] == 1
expected = metadata['files']
assert len(expected) == 8
actual = {p.relative_to(root).as_posix() for p in base.rglob('*.go')}
assert actual == set(expected), 'Unexpected/missing billing protocol source'
for name, digest in expected.items():
    p = root / name
    assert p.is_file() and not p.is_symlink()
    assert hashlib.sha256(p.read_bytes()).hexdigest() == digest, 'Billing protocol changed without an explicit compatibility update'
assert (base / 'go.mod').read_text() == 'module aster/billing\n\ngo 1.26.0\n'
print('PASS: eight pinned public protocol/transport sources; no financial backend dependency')

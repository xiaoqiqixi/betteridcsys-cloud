#!/usr/bin/env python3
"""Keep the documented resource observation envelope and protocol contexts aligned."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ProtocolDocs(unittest.TestCase):
    def test_observation_fields_and_transport_disambiguation(self):
        source = (ROOT/'internal/control/resource_view.go').read_text()
        doc = (ROOT/'docs/RESOURCE_PROTOCOLS.md').read_text()
        fields = set(re.findall(r'json:"([a-z_]+)"', source.split('func (a App)', 1)[0]))
        paragraph = next(line for line in doc.splitlines() if line.startswith('HTTP 资源视图的 JSON 字段固定为'))
        self.assertEqual(set(re.findall(r'`([a-z_]+)`', paragraph)), fields)
        self.assertIn('Protocol: "aster.resource/1"', source)
        for context in ('HTTPS GET `/v1/resources/{resource_id}`', '`X-Aster-Owner-Ref`',
                        'Unix socket RPC', '`resource.aster-cloud`', '`aster.controller/1`'):
            self.assertIn(context, doc)
        for reference in re.findall(r'\]\(([^)]+)\)', doc):
            if not reference.startswith('https://'):
                self.assertTrue((ROOT/'docs'/reference).is_file(), reference)
        self.assertIn('RESOURCE_PROTOCOLS.md', (ROOT/'docs/ARCHITECTURE.md').read_text())


if __name__ == '__main__':
    unittest.main()

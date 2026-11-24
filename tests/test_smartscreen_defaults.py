import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

from smartscreen.defaults import EXPECTED_FILTER_SHA256, extract, section_offset


def small_pe():
    """Two sections with different RVA/file deltas, including virtual-only tail."""
    raw = bytearray(0xa00)
    raw[:2] = b'MZ'
    struct.pack_into('<I', raw, 60, 0x80)
    raw[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<H', raw, 0x86, 2)
    struct.pack_into('<H', raw, 0x94, 0)
    for location, name, rva, offset in [(0x98, b'.rdata', 0x2000, 0x600),
                                       (0xc0, b'.data', 0x3000, 0x800)]:
        raw[location:location + len(name)] = name
        struct.pack_into('<IIII', raw, location + 8, 0x400, rva, 0x200, offset)
    return bytes(raw)


class DefaultExtractionTests(unittest.TestCase):
    def test_section_mapping_uses_each_sections_file_offset(self):
        self.assertEqual(section_offset(small_pe(), 0x2040, 32), ('.rdata', 0x640))
        self.assertEqual(section_offset(small_pe(), 0x3040, 32), ('.data', 0x840))

    def test_virtual_only_and_cross_section_ranges_are_rejected(self):
        for rva, size in [(0x3200, 1), (0x31f0, 32), (0x4000, 1)]:
            with self.subTest(rva=rva), self.assertRaises(ValueError):
                section_offset(small_pe(), rva, size)

    def test_truncated_section_is_rejected(self):
        with self.assertRaises(ValueError):
            section_offset(small_pe()[:0x810], 0x3040, 32)

    def test_unrecognized_binary_is_rejected_before_creating_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / 'different.dll'
            binary.write_bytes(small_pe())
            with self.assertRaisesRegex(ValueError, 'Unrecognized DLL build'):
                extract(binary, root / 'output')
            self.assertFalse((root / 'output').exists())

    def test_identified_binary_extraction_and_provenance(self):
        binary = Path(__file__).resolve().parents[1] / 'artifacts/smartscreen.dll'
        if not binary.exists():
            self.skipTest('Identified lab DLL not installed')
        with tempfile.TemporaryDirectory() as temporary:
            report = extract(binary, temporary)
            bloom = report['customSynchronousLookupUris']
            body = Path(bloom['body']).read_bytes()
            self.assertEqual(len(body), 35302)
            self.assertEqual(hashlib.sha256(body).hexdigest(), EXPECTED_FILTER_SHA256)
            self.assertEqual(bloom['native_initial_version'], '0')
            self.assertEqual(bloom['file_offset'], '0x31cdd0')
            self.assertEqual(bloom['summary']['filter']['hash_count'], 13)
            self.assertTrue(bloom['summary']['filter']['valid'])
            self.assertIn('not an HTTP response', bloom['origin'])
            settings = report['customSettings']
            self.assertEqual(json.loads(Path(settings['body']).read_bytes()), {'forceService': False})
            self.assertIn('reconstructed', settings['origin'])
            self.assertTrue((Path(temporary) / 'builtin_report.json').exists())


if __name__ == '__main__':
    unittest.main()

"""Offline integrity, provenance, and missing-data behavior checks."""
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

from smartscreen.offline import analyze_url


def bloom(byte):
    # A tiny valid native header and deterministic all-zero/all-one controls.
    return struct.pack('<II8sIII', 29, 10, b'murmur3\0', 1, 8, 123) + bytes([byte])


class OfflineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.feeds = self.root / 'feeds'
        self.feeds.mkdir()

    def save(self, name, body, status=200, **updates):
        metadata = {'http_status': status, 'collected_utc': '2020-01-02T03:04:05Z',
                    'endpoint': 'https://example.invalid/saved-feed',
                    'headers': {'ETag': '"saved-version"', 'Date': 'Thu, 02 Jan 2020 03:04:05 GMT'},
                    'response_sha256': hashlib.sha256(body).hexdigest(), 'response_size': len(body),
                    'body_file': '/a/previous/location/ignored.bin'}
        metadata.update(updates)
        (self.feeds / (name + '.response.json')).write_text(json.dumps(metadata))
        (self.feeds / (name + '.bin')).write_bytes(body)
        return metadata

    def entries(self, report):
        return {item['id']: item for item in report['datasets']}

    def test_hits_are_membership_with_original_timestamps_and_no_cloud_verdict(self):
        self.save('topTraffic', hashlib.sha256(b'e\0x\0a\0m\0p\0l\0e\0.\0c\0o\0m\0').digest()[:16])
        self.save('synchronousLookupUris', bloom(255))
        self.save('customSynchronousLookupUris', bloom(0))
        report = analyze_url('https://example.com/a', self.feeds)
        entries = self.entries(report)
        self.assertTrue(entries['topTraffic']['membership'])
        self.assertTrue(entries['synchronousLookupUris']['membership'])
        self.assertFalse(entries['customSynchronousLookupUris']['membership'])
        self.assertEqual(report['analyzed_dataset_count'], 3)
        self.assertIsNone(report['cloud_verdict'])
        self.assertFalse(report['is_complete_blocklist'])
        self.assertEqual(report['network_requests'], 0)
        for item in entries.values():
            self.assertIsNone(item['cloud_verdict'])
            self.assertFalse(item['is_blocklist'])
            self.assertEqual(item['metadata']['collected_utc'], '2020-01-02T03:04:05Z')
            self.assertEqual(item['metadata']['etag'], '"saved-version"')
            self.assertTrue(item['integrity']['sha256_matches'])

    def test_304_is_unknown_even_if_old_body_is_left_in_directory(self):
        self.save('customSynchronousLookupUris', b'', status=304)
        (self.feeds / 'customSynchronousLookupUris.bin').write_bytes(bloom(255))
        entry = self.entries(analyze_url('https://example.com', self.feeds))['customSynchronousLookupUris']
        self.assertEqual(entry['state'], 'not_modified_without_verified_cache')
        self.assertIsNone(entry['membership'])
        self.assertTrue(entry['body_ignored'])
        self.assertNotIn('lookup', entry)
        (self.feeds / 'customSynchronousLookupUris.bin').unlink()
        entry = self.entries(analyze_url('https://example.com', self.feeds))['customSynchronousLookupUris']
        self.assertIsNone(entry['membership'])
        self.assertFalse(entry['body_ignored'])

    def test_hash_and_size_mismatch_do_not_create_negative_membership(self):
        self.save('synchronousLookupUris', bloom(255))
        (self.feeds / 'synchronousLookupUris.bin').write_bytes(bloom(0))
        self.save('customSynchronousLookupUris', bloom(255), response_size=30)
        entries = self.entries(analyze_url('https://example.com', self.feeds))
        for name in ('synchronousLookupUris', 'customSynchronousLookupUris'):
            self.assertEqual(entries[name]['state'], 'integrity_mismatch')
            self.assertIsNone(entries[name]['membership'])
            self.assertNotIn('lookup', entries[name])

    def test_corrupt_metadata_does_not_hide_other_valid_feed(self):
        (self.feeds / 'topTraffic.response.json').write_text('{not json')
        self.save('synchronousLookupUris', bloom(255))
        self.save('customSynchronousLookupUris', bloom(255), response_sha256='not-a-sha256')
        entries = self.entries(analyze_url('https://example.com', self.feeds))
        self.assertEqual(entries['topTraffic']['state'], 'invalid_metadata')
        self.assertEqual(entries['customSynchronousLookupUris']['state'], 'invalid_metadata')
        self.assertTrue(entries['synchronousLookupUris']['membership'])

    def test_missing_body_or_metadata_is_unknown_and_wrong_format_rejected(self):
        self.save('topTraffic', bytes(16))
        (self.feeds / 'topTraffic.bin').unlink()
        (self.feeds / 'synchronousLookupUris.bin').write_bytes(bloom(0))
        self.save('customSynchronousLookupUris', b'{"not":"a native filter"}')
        entries = self.entries(analyze_url('https://example.com', self.feeds))
        self.assertEqual(entries['topTraffic']['state'], 'missing_body')
        self.assertEqual(entries['synchronousLookupUris']['state'], 'missing_metadata')
        self.assertEqual(entries['customSynchronousLookupUris']['state'], 'invalid_body')
        self.assertTrue(all(item['membership'] is None for item in entries.values()))

    def test_native_default_is_separate_from_unavailable_custom_download(self):
        self.save('customSynchronousLookupUris', b'', status=304)
        defaults = self.root / 'defaults'
        defaults.mkdir()
        raw = bloom(255)
        (defaults / 'builtin_customSynchronousLookupUris.bin').write_bytes(raw)
        report = {'source': {'sha256': 'a' * 64, 'version': 'test-control'},
                  'customSynchronousLookupUris': {
                      'origin': 'synthetic test control, not HTTP', 'native_initial_version': '0',
                      'summary': {'sha256': hashlib.sha256(raw).hexdigest(), 'size': len(raw)}}}
        (defaults / 'builtin_report.json').write_text(json.dumps(report))
        result = analyze_url('https://example.com', self.feeds, defaults)
        self.assertIsNone(self.entries(result)['customSynchronousLookupUris']['membership'])
        fallback = result['native_defaults'][0]
        self.assertTrue(fallback['membership'])
        self.assertEqual(fallback['origin'], 'native_dll_fallback')
        self.assertFalse(fallback['current_service_contents'])
        self.assertIsNone(fallback['metadata']['http_status'])
        (defaults / 'builtin_customSynchronousLookupUris.bin').write_bytes(bloom(0))
        fallback = analyze_url('https://example.com', self.feeds, defaults)['native_defaults'][0]
        self.assertEqual(fallback['state'], 'integrity_mismatch')
        self.assertIsNone(fallback['membership'])

    def test_missing_native_provenance_does_not_override_download(self):
        self.save('customSynchronousLookupUris', bloom(0))
        defaults = self.root / 'defaults'
        defaults.mkdir()
        (defaults / 'builtin_customSynchronousLookupUris.bin').write_bytes(bloom(255))
        result = analyze_url('https://example.com', self.feeds, defaults)
        self.assertFalse(self.entries(result)['customSynchronousLookupUris']['membership'])
        self.assertEqual(result['native_defaults'][0]['state'], 'invalid_metadata')
        self.assertIsNone(result['native_defaults'][0]['membership'])

    def test_manifest_corruption_is_reported_without_discarding_verified_data(self):
        (self.feeds / 'manifest.json').write_text('[]')
        self.save('synchronousLookupUris', bloom(255))
        result = analyze_url('https://example.com', self.feeds)
        self.assertIn('snapshot_metadata_error', result)
        self.assertTrue(self.entries(result)['synchronousLookupUris']['membership'])

    def test_unsupported_url_and_missing_directory_fail_explicitly(self):
        with self.assertRaisesRegex(ValueError, 'Raw Unicode'):
            analyze_url('https://éxample.com', self.feeds)
        with self.assertRaisesRegex(ValueError, 'does not exist'):
            analyze_url('https://example.com', self.root / 'missing')
        with self.assertRaisesRegex(ValueError, 'does not exist'):
            analyze_url('https://example.com', self.feeds, self.root / 'missing')


if __name__ == '__main__':
    unittest.main()

import json
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from smartscreen.data import bloom_header, check_bloom_key, check_feed_url, check_toptraffic_key, compare_data, compare_snapshots, feed_url_candidates, inspect_data, inspect_file, murmur3_x64_128, read_data


def bloom(payload=b'\x01', bits=7, hashes=3, seed=10):
    return struct.pack('<II', len(payload) + 28, seed) + b'murmur3\0' + struct.pack('<III', hashes, bits, 12) + payload


class FeedInspectionTests(unittest.TestCase):
    def test_native_filter_fields_and_unused_bits(self):
        report = bloom_header(bloom(b'\x81'))
        self.assertTrue(report['valid'])
        self.assertEqual(report['seed'], 10)
        self.assertEqual(report['hash_count'], 3)
        self.assertEqual(report['bit_count'], 7)
        self.assertEqual(report['set_bit_count'], 1)
        self.assertEqual(report['unknown_u32_at_24'], 12)

    def test_rejects_native_invalid_shapes_without_guessing(self):
        malformed = [bloom(bits=20), bloom(hashes=101), bloom(hashes=0), b'\0' * 4 + bloom()[4:]]
        for raw in malformed:
            with self.subTest(raw=raw):
                self.assertFalse(bloom_header(raw)['valid'])

    def test_null_json_is_json_not_binary(self):
        self.assertEqual(inspect_data(b'null')['format'], 'json')

    def test_bounded_file_input(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / 'data.bin'
            file.write_bytes(b'abcd')
            with self.assertRaises(ValueError):
                read_data(file, max_bytes=3)
            self.assertEqual(inspect_file(file)['size'], 4)

    def test_real_filter_matches_native_reader_constraints(self):
        file = Path(__file__).resolve().parents[1] / 'analysis/datasets/synchronousLookupUris.bin'
        if not file.exists():
            self.skipTest('Saved live dataset absent')
        data = inspect_file(file)['filter']
        self.assertTrue(data['valid'])
        self.assertEqual((data['seed'], data['hash_count'], data['bit_count']), (10, 13, 231))

    def test_real_toptraffic_known_host_matches(self):
        file = Path(__file__).resolve().parents[1] / 'analysis/datasets/topTraffic.bin'
        if not file.exists():
            self.skipTest('Saved live dataset absent')
        raw = file.read_bytes()
        expected = {'www.google.com': 'feb2133225a527f9f5fcc1355e1225f2',
                    'www.example.com': 'c4282674e3f3c3c7c900fc04c50d0a7b'}
        for key, record in expected.items():
            report = check_toptraffic_key(raw, key)
            self.assertTrue(report['present'])
            self.assertEqual(report['record_hex'], record)
            self.assertFalse(report['native_url_candidate_generation_supported'])

    def test_exact_key_lookup_does_not_add_candidate_normalization(self):
        record = bytes.fromhex('feb2133225a527f9f5fcc1355e1225f2')
        self.assertTrue(check_toptraffic_key(record, 'www.google.com')['present'])
        for key in ('WWW.GOOGLE.COM', 'https://www.google.com/', 'not-in-this-fixture.invalid'):
            self.assertFalse(check_toptraffic_key(record, key)['present'])

    def test_key_lookup_validates_input(self):
        for raw, key in [(b'bad', 'a'), (b'', None), (b'', '\ud800')]:
            with self.assertRaises(ValueError):
                check_toptraffic_key(raw, key)

    def test_v2_model_summary_does_not_report_zero_v1_weights(self):
        raw = json.dumps({'models': [{'name': 'v2', 'bias': -2, 'terms': [
            {'features': ['title'], 'lengthWeight': -.2, 'tokenWeights': [{'key': 'a', 'value': 1}]}]}]}).encode()
        model = inspect_data(raw)['models'][0]
        self.assertEqual(model['token_weight_count'], 1)
        self.assertEqual(model['terms'][0]['features'], ['title'])
        self.assertNotIn('weight_count', model)


class BloomMembershipTests(unittest.TestCase):
    def test_murmur_known_vectors(self):
        vectors = [(b'', '00000000000000000000000000000000'),
                   (b'foo', '6145f501578671e2877dba2be487af7e'),
                   (bytes(range(16)), '303f9091b524494445e82f76566490ab'),
                   (bytes(range(31)), '94d02ca3e1d33d05905400b4ef9ae59e'),
                   (bytes(range(32)), '0f502fb622906dc65111c3346e0a051c')]
        for value, expected in vectors:
            self.assertEqual(murmur3_x64_128(value).hex(), expected)

    def test_seed_and_input_validation(self):
        for data, seed in [(b'a', -1), (b'a', 0x100000000), (b'a', True), ('a', 0)]:
            with self.assertRaises(ValueError):
                murmur3_x64_128(data, seed)

    def test_saved_filter_positive_and_exact_probe_vector(self):
        path = Path(__file__).resolve().parents[1] / 'analysis/datasets/synchronousLookupUris.bin'
        if not path.exists():
            self.skipTest('Saved live dataset absent')
        raw = path.read_bytes()
        report = check_bloom_key(raw, 'example.com')
        self.assertEqual(report['hash_hex'], 'd0c2fe03fb6e1861ecbe4fda44f2ab9d')
        self.assertEqual(report['probe_indexes'], [79, 66, 37, 8, 226, 197, 168, 155, 126, 113, 84, 55, 42])
        self.assertTrue(report['possibly_present'])
        self.assertTrue(check_bloom_key(raw, 'demo.smartscreen.msft.net')['possibly_present'])
        self.assertFalse(check_bloom_key(raw, 'www.example.com')['possibly_present'])
        self.assertFalse(check_bloom_key(raw, 'https://demo.smartscreen.msft.net/')['possibly_present'])

    def test_single_missing_probe_bit_makes_key_absent(self):
        # Independently fixed seed-10 probe vector for example.com, including
        # uint64 overflow before modulus; simply taking (h1+i*h2)%231 differs.
        indexes = [79, 66, 37, 8, 226, 197, 168, 155, 126, 113, 84, 55, 42]
        payload = bytearray(29)
        for index in indexes:
            payload[index // 8] |= 1 << (index % 8)
        self.assertTrue(check_bloom_key(bloom(bytes(payload), bits=231, hashes=13), 'example.com')['possibly_present'])
        payload[79 // 8] &= ~(1 << (79 % 8))
        self.assertFalse(check_bloom_key(bloom(bytes(payload), bits=231, hashes=13), 'example.com')['possibly_present'])

    def test_degenerate_filter_matches_native_zero_probe_behavior(self):
        report = check_bloom_key(bloom(b'', bits=0, hashes=0), 'anything')
        self.assertTrue(report['possibly_present'])
        self.assertTrue(report['degenerate_empty_filter'])
        with self.assertRaises(ValueError):
            check_bloom_key(bloom(b'', bits=0, hashes=1), 'anything')

    def test_invalid_filter_and_invalid_unicode_fail(self):
        for raw, key in [(bloom(bits=100), 'a'), (bloom(), None), (bloom(), '\ud800')]:
            with self.assertRaises(ValueError):
                check_bloom_key(raw, key)


class URLFeedTests(unittest.TestCase):
    def test_native_uri_fixture_matches_supported_subset(self):
        path = Path(__file__).resolve().parents[1] / 'analysis/feed_expansion/native_uri_validation.json'
        if not path.exists():
            self.skipTest('Native URI validation artifact absent')
        count = 0
        for case in json.loads(path.read_text())['cases']:
            try:
                actual = feed_url_candidates(case['input'])
            except ValueError:
                continue
            with self.subTest(url=case['input']):
                self.assertNotIn('error', case)
                self.assertEqual(actual['canonical_url'], case['canonical'])
                self.assertEqual(actual['candidates'], case['candidates'])
            count += 1
        self.assertGreaterEqual(count, 80)

    def test_candidate_scope_has_explicit_rejections(self):
        for value in ('https://caf\u00e9.example/', 'https://[fe80::1%25eth0]/',
                      'https://example.com:65536/', 'https://example.com:invalid/',
                      'https://u%00p@example.com/', 'https://example.com/a\n',
                      'ftp://example.com/', 'https://.example.com/'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                feed_url_candidates(value)

    def test_extended_native_uri_matrices(self):
        root = Path(__file__).resolve().parents[1] / 'analysis/feed_expansion'
        paths = [root / (name + '.json') for name in ('native_uri_extended', 'native_uri_adversarial', 'native_uri_boundary')]
        if not all(path.exists() for path in paths):
            self.skipTest('Extended native URI artifacts absent')
        count = 0
        for path in paths:
            for case in json.loads(path.read_text())['cases']:
                try:
                    actual = feed_url_candidates(case['input'])
                except ValueError:
                    continue
                with self.subTest(url=case['input']):
                    self.assertNotIn('error', case)
                    self.assertEqual(actual['canonical_url'], case['canonical'])
                    self.assertEqual(actual['candidates'], case['candidates'])
                count += 1
        self.assertGreaterEqual(count, 390)

    def test_recursive_percent_and_component_specific_escaping(self):
        report = feed_url_candidates('https://example.com/%252541/a%2fb?Q=%255c%23#%2523')
        self.assertEqual(report['canonical_url'], 'https://example.com/a/a/b?q=\\%23##')
        self.assertEqual(report['candidates'][0], 'example.com/a/a/b?q=\\%23##')
        self.assertEqual(feed_url_candidates('https://example.com/a//../b')['canonical_url'], 'https://example.com/a/b')

    def test_encoded_credentials_are_removed_at_native_parse_stage(self):
        for url in ('https://u%252fp%40example.com:8443/A', 'https://u%2fp@example.com/A'):
            self.assertEqual(feed_url_candidates(url)['canonical_url'], 'https://example.com/a')

    def test_numeric_ip_forms_and_no_dns_suffixes(self):
        for host in ('127.1', '2130706433', '0177.0.0.1', '0x7f000001'):
            report = feed_url_candidates('https://' + host + '/A')
            self.assertEqual(report['host_type'], 'ipv4')
            self.assertEqual(report['candidates'], ['127.0.0.1/a', '127.0.0.1'])
        report = feed_url_candidates('https://[::ffff:192.000.002.001]:8443/A')
        self.assertEqual(report['host_type'], 'ipv6')
        self.assertEqual(report['candidates'][-1], '[0000:0000:0000:0000:0000:ffff:c000:0201]')

    def test_serialized_international_url_preserves_encoded_utf8(self):
        report = feed_url_candidates('https://XN--CAF-DMA.example/caf%C3%A9')
        self.assertEqual(report['canonical_url'], 'https://xn--caf-dma.example/caf%c3%a9')

    def test_toptraffic_stops_at_first_host_match(self):
        raw = bytes.fromhex('feb2133225a527f9f5fcc1355e1225f2')
        report = check_feed_url(raw, 'HTTPS://WWW.GOOGLE.COM/Path', 'topTraffic')
        self.assertTrue(report['present'])
        self.assertEqual(report['matched_candidate'], 'www.google.com')
        self.assertEqual(report['tested_candidate_count'], 2)
        self.assertEqual(report['canonical_url'], 'https://www.google.com/path')

    def test_bloom_url_lookup_preserves_custom_kind(self):
        path = Path(__file__).resolve().parents[1] / 'analysis/datasets/synchronousLookupUris.bin'
        if not path.exists():
            self.skipTest('Saved live dataset absent')
        report = check_feed_url(path.read_bytes(), 'https://EXAMPLE.COM/path', 'customSynchronousLookupUris')
        self.assertTrue(report['possibly_present'])
        self.assertEqual(report['matched_candidate'], 'example.com')
        self.assertEqual(report['kind'], 'customSynchronousLookupUris')
        self.assertEqual(report['candidate_results'][-1]['kind'], 'customSynchronousLookupUris')
        self.assertEqual(check_bloom_key(path.read_bytes(), 'example.com')['kind'], 'murmur3_filter')

    def test_candidate_report_limit(self):
        with self.assertRaises(ValueError):
            feed_url_candidates('https://example.com/' + '/'.join(['a'] * 129))

    def test_unsupported_feed_type_fails(self):
        with self.assertRaises(ValueError):
            check_feed_url(b'{}', 'https://example.com/')


class FeedComparisonTests(unittest.TestCase):
    def test_opaque_record_changes_have_exact_counts_and_bounded_details(self):
        a, b, c, d = (bytes([n]) * 16 for n in range(4))
        result = compare_data(a + b, b + c + d, 'topTraffic', limit=1)
        self.assertEqual(result['added'], {'count': 2, 'items': [c.hex()], 'truncated': True})
        self.assertEqual(result['removed']['count'], 1)
        self.assertEqual(result['removed']['items'], [a.hex()])

    def test_duplicate_records_and_order_are_distinguished(self):
        a, b = b'a' * 16, b'b' * 16
        reordered = compare_data(a + b, b + a, 'topTraffic')
        self.assertTrue(reordered['record_order_changed'])
        result = compare_data(a + b, a + b + b, 'topTraffic')
        self.assertEqual(result['multiplicity_changes']['items'][0]['after'], 2)
        self.assertEqual(result['added']['count'], 0)

    def test_model_weights_compare_by_key_despite_reordering(self):
        a = {'models': [{'name': 'title', 'bias': 1, 'weights': [{'key': 'a', 'value': 1}, {'key': 'b', 'value': 2}]}]}
        b = {'models': [{'name': 'title', 'bias': 1, 'weights': [{'key': 'b', 'value': 3}, {'key': 'a', 'value': 1}]}]}
        result = compare_data(json.dumps(a).encode(), json.dumps(b).encode())
        self.assertEqual(result['changes']['count'], 1)
        self.assertEqual(result['changes']['items'][0]['path'], '/models/@name/title/weights/@key/b/value')

    def test_v2_token_weights_compare_by_key_inside_ordered_terms(self):
        a = {'models': [{'name': 'v2', 'terms': [{'tokenWeights': [{'key': 'a', 'value': 1}, {'key': 'b', 'value': 2}]}]}]}
        b = {'models': [{'name': 'v2', 'terms': [{'tokenWeights': [{'key': 'b', 'value': 3}, {'key': 'a', 'value': 1}]}]}]}
        result = compare_data(json.dumps(a).encode(), json.dumps(b).encode())
        self.assertEqual(result['changes']['count'], 1)
        self.assertEqual(result['changes']['items'][0]['path'], '/models/@name/v2/terms/0/tokenWeights/@key/b/value')

    def test_equivalent_json_spacing_and_model_order(self):
        a = {'models': [{'name': 'b'}, {'name': 'a'}]}
        b = {'models': [{'name': 'a'}, {'name': 'b'}]}
        report = compare_data(json.dumps(a).encode(), json.dumps(b, indent=2).encode())
        self.assertTrue(report['changed'])
        self.assertTrue(report['semantic_equal'])

    def test_duplicate_model_names_preserve_array_semantics(self):
        a = {'models': [{'name': 'a', 'bias': 1}, {'name': 'a', 'bias': 2}]}
        b = {'models': [{'name': 'a', 'bias': 2}, {'name': 'a', 'bias': 1}]}
        report = compare_data(json.dumps(a).encode(), json.dumps(b).encode())
        self.assertEqual(report['changes']['count'], 2)
        self.assertIn('/models/0/', report['changes']['items'][0]['path'])

    def test_change_paths_escape_unusual_json_keys(self):
        report = compare_data(b'{"a/b~c":1}', b'{"a/b~c":2}')
        self.assertEqual(report['changes']['items'][0]['path'], '/a~1b~0c')

    def test_bloom_bit_changes_exclude_padding(self):
        report = compare_data(bloom(b'\x01'), bloom(b'\x82'))
        self.assertTrue(report['bit_positions_comparable'])
        self.assertEqual(report['bits_set']['items'], [1])
        self.assertEqual(report['bits_cleared']['items'], [0])

    def test_different_bloom_seed_prevents_misleading_bit_comparison(self):
        report = compare_data(bloom(), bloom(seed=11))
        self.assertFalse(report['bit_positions_comparable'])
        self.assertNotIn('bits_set', report)

    def test_format_changes_are_explicit(self):
        self.assertEqual(compare_data(b'{}', b'\xff')['comparison'], 'format_changed')

    def test_invalid_limits_fail(self):
        for limit in [-1, True, 10001]:
            with self.assertRaises(ValueError):
                compare_data(b'{}', b'{}', limit=limit)

    def test_zero_limit_keeps_exact_change_count(self):
        result = compare_data(b'{"a":1,"b":2}', b'{"a":2,"b":3}', limit=0)
        self.assertEqual(result['changes'], {'count': 2, 'items': [], 'truncated': True})

    def test_missing_304_body_is_not_an_empty_dataset(self):
        with tempfile.TemporaryDirectory() as directory:
            before, after = Path(directory) / 'before', Path(directory) / 'after'
            before.mkdir(); after.mkdir()
            (before / 'customSettings.bin').write_bytes(b'{"a":1}')
            (after / 'customSettings.response.json').write_text('{"http_status":304,"headers":{}}')
            report = compare_snapshots(before, after)
            self.assertEqual(report['counts'], {'uncomparable': 1})
            self.assertEqual(report['datasets'][0]['after_metadata']['http_status'], 304)

    def test_directory_metadata_errors_are_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            before, after = Path(directory) / 'before', Path(directory) / 'after'
            before.mkdir(); after.mkdir()
            for path in (before, after):
                (path / 'edgeSettings.bin').write_bytes(b'{}')
                (path / 'edgeSettings.response.json').write_text('invalid')
            report = compare_snapshots(before, after)
            self.assertEqual(report['counts'], {'unchanged': 1})
            self.assertIn('before_metadata_error', report['datasets'][0])

    def test_snapshot_report_bounds_dataset_array(self):
        with tempfile.TemporaryDirectory() as directory:
            before, after = Path(directory) / 'before', Path(directory) / 'after'
            before.mkdir(); after.mkdir()
            for name in ('a', 'b'):
                (before / (name + '.bin')).write_bytes(b'x')
                (after / (name + '.bin')).write_bytes(b'y')
            report = compare_snapshots(before, after, limit=1)
            self.assertEqual(report['dataset_count'], 2)
            self.assertEqual(report['counts']['changed'], 2)
            self.assertEqual(len(report['datasets']), 1)
            self.assertTrue(report['datasets_truncated'])

    def test_snapshot_reports_digest_mismatch_separately_from_byte_diff(self):
        with tempfile.TemporaryDirectory() as directory:
            before, after = Path(directory) / 'before', Path(directory) / 'after'
            before.mkdir(); after.mkdir()
            for path in (before, after):
                (path / 'edgeSettings.bin').write_bytes(b'{}')
            (before / 'edgeSettings.response.json').write_text(json.dumps({
                'http_status': 200, 'response_sha256': hashlib.sha256(b'{}').hexdigest()}))
            (after / 'edgeSettings.response.json').write_text(json.dumps({
                'http_status': 200, 'response_sha256': '0' * 64}))
            report = compare_snapshots(before, after)
            self.assertEqual(report['counts'], {'unchanged': 1})
            self.assertEqual(report['integrity_mismatch_count'], 1)
            item = report['datasets'][0]
            self.assertEqual(item['before_integrity']['status'], 'match')
            self.assertEqual(item['after_integrity']['status'], 'mismatch')


if __name__ == '__main__':
    unittest.main()

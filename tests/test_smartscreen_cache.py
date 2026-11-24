"""Routing cache semantics, provenance boundaries, and native parity fixtures."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from smartscreen.cache import (cache_candidates, import_response, import_response_file,
                              inspect_native_cache, lookup_cache, merge_caches, native_cache_key,
                              EDGE_READER, LEGACY_READER)

ROOT = Path(__file__).resolve().parents[1]
T0 = '2026-01-01T00:00:00.0000000Z'


def action(uri='example.com', inheritance='path', result='allow', age=10000000):
    return {'$type': 'cache', 'key': {'uri': uri, 'inheritance': inheritance},
            'maxAge': age, 'result': {'$type': result}, 'responseCategory': 'Allowed'}


def imported(actions, when=T0, scope='navigation', semantics=LEGACY_READER):
    return import_response({'actions': actions}, received_at=when, scope=scope, context='fixture-runtime', semantics=semantics)


class CacheTests(unittest.TestCase):
    def test_native_preimages_and_typed_candidate_parity(self):
        inputs = json.loads((ROOT / 'tests/fixtures/native/native_key_preimages.json').read_text())
        names = ('none', 'path', 'all')
        for case in inputs['cases']:
            with self.subTest(case=case):
                self.assertEqual(native_cache_key(case['input'], names[case['inheritance']], LEGACY_READER)['sha256_preimage'],
                                 case['native_sha256_preimage'])
        segments = json.loads((ROOT / 'tests/fixtures/native/native_segments.json').read_text())
        for case in segments['cases']:
            with self.subTest(url=case['input']):
                observed = [{'text': item['canonical_uri'], 'segment_type': item['inheritance_value']}
                            for item in cache_candidates(case['input'], LEGACY_READER)['cache_candidates']]
                self.assertEqual(observed, case['candidates'])

    def test_ttl_uses_100ns_and_exact_expiry_boundary(self):
        cache = imported([action(age=1)])
        self.assertEqual(cache['entries'][0]['expires_utc'], '2026-01-01T00:00:00.0000001Z')
        self.assertEqual(lookup_cache(cache, 'https://example.com/a', at=T0)['state'], 'hit')
        self.assertEqual(lookup_cache(cache, 'https://example.com/a', at='2026-01-01T00:00:00.0000001Z')['state'], 'expired')
        example = imported([action(age=100800000000)])
        self.assertEqual(example['entries'][0]['max_age_seconds'], 10080)
        self.assertEqual(example['entries'][0]['expires_utc'], '2026-01-01T02:48:00.0000000Z')

    def test_inheritance_is_typed_not_generic_prefix_matching(self):
        path = imported([action()])
        self.assertEqual(lookup_cache(path, 'https://example.com/a', T0)['state'], 'hit')
        self.assertEqual(lookup_cache(path, 'https://example.com', T0)['state'], 'miss')
        self.assertEqual(lookup_cache(path, 'https://x.example.com/a', T0)['state'], 'miss')
        all_children = imported([action(inheritance='all')])
        self.assertEqual(lookup_cache(all_children, 'https://x.example.com/a', T0)['state'], 'hit')
        self.assertEqual(lookup_cache(all_children, 'https://example.com/a', T0)['state'], 'miss')
        exact = imported([action(uri='example.com/a', inheritance='none')])
        self.assertEqual(lookup_cache(exact, 'http://EXAMPLE.COM/a', T0)['state'], 'hit')
        self.assertEqual(lookup_cache(exact, 'http://example.com/a/b', T0)['state'], 'miss')

    def test_edge_wire_maxage_is_microseconds_and_clock_has_microsecond_precision(self):
        cache = imported([action(age=1)], when='2026-01-01T00:00:00.0000007Z', semantics=EDGE_READER)
        entry = cache['entries'][0]
        self.assertEqual(entry['max_age_unit'], 'microseconds')
        self.assertEqual(entry['max_age_ticks'], 10)
        self.assertEqual(entry['expires_utc'], '2026-01-01T00:00:00.0000010Z')
        self.assertEqual(lookup_cache(cache, 'https://example.com/a', '2026-01-01T00:00:00.0000009Z')['state'], 'hit')
        self.assertEqual(lookup_cache(cache, 'https://example.com/a', '2026-01-01T00:00:00.0000010Z')['state'], 'expired')
        example = imported([action(age=100800000000)], semantics=EDGE_READER)
        self.assertEqual(example['entries'][0]['max_age_seconds'], 100800)
        self.assertEqual(example['entries'][0]['expires_utc'], '2026-01-02T04:00:00.0000000Z')

    def test_most_specific_candidate_wins_and_expired_one_falls_through(self):
        cache = imported([action(result='call_server', age=100000000),
                          action('example.com/a', 'none', 'evaluate', 1)])
        before = lookup_cache(cache, 'https://example.com/a', T0)
        self.assertEqual(before['routing_action'], 'evaluate')
        after = lookup_cache(cache, 'https://example.com/a', '2026-01-01T00:00:00.0000001Z')
        self.assertEqual(after['routing_action'], 'call_server')
        self.assertEqual(len(after['expired_matches']), 1)
        self.assertIsNone(after['cloud_verdict'])

    def test_duplicate_live_key_is_not_replaced_and_expired_reinsert_is_unknown(self):
        one = imported([action(age=10000000)])
        two = imported([action(result='call_server', age=100000000)], '2026-01-01T00:00:00.5000000Z')
        combined = merge_caches([one, two])
        self.assertEqual(lookup_cache(combined, 'https://example.com/a', '2026-01-01T00:00:00.7500000Z')['routing_action'], 'allow')
        self.assertEqual(lookup_cache(combined, 'https://example.com/a', '2026-01-01T00:00:02Z')['state'], 'expired')
        late = imported([action(result='call_server')], '2026-01-01T00:00:01Z')
        self.assertEqual(lookup_cache(merge_caches([one, late]), 'https://example.com/a', '2026-01-01T00:00:01Z')['state'], 'unknown')

    def test_missing_time_scope_and_multiple_contexts_remain_unknown(self):
        unknown = import_response({'actions': [action()]})
        self.assertEqual(lookup_cache(unknown, 'https://example.com/a', T0)['state'], 'unknown')
        mixed = merge_caches([imported([action()]), imported([action(result='evaluate')], scope='download')])
        self.assertEqual(lookup_cache(mixed, 'https://example.com/a', T0)['state'], 'unknown')
        self.assertEqual(lookup_cache(mixed, 'https://example.com/a', T0, 'download')['routing_action'], 'evaluate')

    def test_exact_edge_inheritance_order_full_hash_and_overwrite(self):
        candidates = cache_candidates('https://example.com/a')['cache_candidates']
        self.assertEqual([(item['canonical_uri'], item['inheritance']) for item in candidates],
                         [('example.com/a', 'none'), ('example.com/a', 'path'), ('example.com/a', 'all'),
                          ('example.com', 'path'), ('example.com', 'all'), ('com', 'all')])
        self.assertEqual(len(candidates[0]['native_key']), 64)
        cache = imported([action()], semantics=EDGE_READER)
        self.assertEqual(lookup_cache(cache, 'https://example.com', T0)['state'], 'hit')
        later = imported([action(result='evaluate', age=100000000)], '2026-01-01T00:00:00.5000000Z', semantics=EDGE_READER)
        hit = lookup_cache(merge_caches([cache, later]), 'https://example.com/a', '2026-01-01T00:00:02Z')
        self.assertEqual(hit['routing_action'], 'evaluate')
        self.assertEqual(hit['superseded_insertions'], 1)
        with self.assertRaisesRegex(ValueError, 'different'):
            merge_caches([cache, imported([action()])])

    def test_unknown_or_different_profile_context_is_not_silently_combined(self):
        one = import_response({'actions': [action()]}, received_at=T0, scope='navigation')
        two = import_response({'actions': [action(result='evaluate')]}, received_at=T0, scope='navigation')
        self.assertEqual(lookup_cache(merge_caches([one, two]), 'https://example.com/a', T0)['state'], 'unknown')
        for identity in ({'client': {'id': 'one'}}, {'client': {'id': 'two'}}):
            record = {'http_status': 200, 'collected_utc': T0, 'response': {'actions': [action()]},
                      'endpoint': 'https://example.invalid/api/browser/edge/navigate/3/sync',
                      'request_profile': {'identity': identity}}
            if identity['client']['id'] == 'one':
                one = import_response(record)
            else:
                two = import_response(record)
        self.assertEqual(lookup_cache(merge_caches([one, two]), 'https://example.com/a', T0)['state'], 'unknown')

    def test_reject_unknown_result_and_nonpositive_ttl_has_no_cache(self):
        rejected = imported([action(result='block')])
        self.assertEqual(len(rejected['rejected']), 1)
        self.assertEqual(lookup_cache(rejected, 'https://example.com/a', T0)['state'], 'unknown')
        self.assertEqual(lookup_cache(imported([action(age=0)]), 'https://example.com/a', T0)['state'], 'no_cache')
        self.assertEqual(lookup_cache(imported([]), 'https://example.com/a', T0)['state'], 'no_cache')

    def test_exact_recorded_sdk_versions_select_reader_and_conflicts_fail(self):
        raw = {'actions': [action(age=10000000)]}
        old = import_response(raw | {'request_client_version': '1.2.2312.1'}, received_at=T0, scope='navigation')
        new = import_response(raw | {'request_client_version': '1.2.2609.3'}, received_at=T0, scope='navigation')
        self.assertEqual(old['reader_semantics'], LEGACY_READER)
        self.assertEqual(old['entries'][0]['wire_time_unit'], '100_nanoseconds')
        self.assertEqual(old['entries'][0]['max_age_seconds'], 1)
        self.assertEqual(new['reader_semantics'], EDGE_READER)
        self.assertEqual(new['entries'][0]['wire_time_unit'], 'microseconds')
        self.assertEqual(new['entries'][0]['max_age_seconds'], 10)
        self.assertEqual(new['reader_selection_basis'], 'binary_matched_request_client_version')
        packed = import_response(raw | {'request_client_version': '281483737628675'}, received_at=T0, scope='navigation')
        self.assertEqual(packed['reader_semantics'], EDGE_READER)
        equivalent = import_response(raw | {'request_client_version': '1.2.2609.3',
                                             'request_profile': {'identity': {'client': {'version': '281483737628675'}}}})
        self.assertEqual(equivalent['reader_selection_basis'], 'binary_matched_request_client_version')
        unknown = import_response(raw | {'request_client_version': '1.2.2401.3'})
        self.assertEqual(unknown['reader_selection_basis'], 'default_edge_reader_assumption')
        with self.assertRaisesRegex(ValueError, 'conflicts'):
            import_response(raw | {'request_client_version': '1.2.2312.1'}, semantics=EDGE_READER)
        with self.assertRaisesRegex(ValueError, 'conflicts'):
            import_response(raw | {'request_client_version': '1.2.2312.1',
                                   'request_profile': {'identity': {'client': {'version': '1.2.2609.3'}}}})

    def test_derived_entry_tampering_rejected_and_http_errors_not_imported(self):
        cache = imported([action()])
        cache['entries'][0]['routing_action'] = 'call_server'
        self.assertEqual(lookup_cache(cache, 'https://example.com/a', T0)['state'], 'unknown')
        error = import_response({'http_status': 500, 'response': {'actions': [action()]}, 'collected_utc': T0})
        self.assertEqual(error['entries'], [])
        self.assertEqual(len(error['rejected']), 1)

    def test_recorded_endpoint_scope_and_raw_wire_integrity(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'one.response.json'
            raw_path = Path(directory) / 'one.response.bin'
            body = {'actions': [action()]}
            raw = json.dumps(body).encode()
            record = {'http_status': 200, 'response': body, 'collected_utc': T0,
                      'endpoint': 'https://dl-edge.smartscreen.microsoft.com/api/browser/edge/download/3',
                      'response_sha256': hashlib.sha256(raw).hexdigest(), 'response_size': len(raw)}
            path.write_text(json.dumps(record))
            raw_path.write_bytes(raw)
            cache = import_response_file(path)
            self.assertEqual(cache['entries'][0]['scope'], 'download')
            self.assertTrue(cache['entries'][0]['provenance']['wire_bytes_verified'])
            with self.assertRaisesRegex(ValueError, 'conflicts'):
                import_response(record, scope='navigation')
            raw_path.write_bytes(raw + b' ')
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                import_response_file(path)

    def test_native_persisted_format_is_separate_from_response_replay(self):
        path = ROOT / 'analysis/current_lab/snapshot/local/uriCache_'
        if not path.exists():
            self.skipTest('Lab cache snapshot is not included')
        native = inspect_native_cache(path, T0)
        self.assertEqual(native['format'], 'edge_persisted_cache_v1')
        self.assertEqual(native['entry_count'], 1)
        self.assertEqual(native['entries'][0]['raw_entry']['result'], 1)
        self.assertEqual(native['entries'][0]['routing_action'], 'evaluate')
        self.assertEqual(native['entries'][0]['expiration_unit'], 'unix_microseconds')
        self.assertFalse(native['is_complete_blocklist'])
        with self.assertRaisesRegex(ValueError, 'response cache'):
            lookup_cache(native, 'https://example.com', T0)

    def test_native_full_key_and_legacy_fallback_and_expiration(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'uriCache_'
            pointer = Path(directory) / 'uriCache'
            pointer.write_bytes(b'uriCache_')
            key = native_cache_key('example.com', 'path')
            item = {'file_hash': key['native_key'], 'result': 1, 'expiration_time': 1767225601000000,
                    'response_category': 'Allowed', 'server_context': 'test'}
            path.write_text(json.dumps({'version': 1, 'cache_data': [item]}))
            observed = inspect_native_cache(pointer, T0, 'https://example.com/a')
            self.assertEqual(observed['lookup']['routing_action'], 'evaluate')
            self.assertFalse(observed['lookup']['legacy_key_fallback'])
            self.assertIsNotNone(observed['pointer'])
            self.assertEqual(inspect_native_cache(path, '2026-01-01T00:00:01Z', 'https://example.com/a')['lookup']['state'], 'expired')
            item['file_hash'] = key['legacy_native_key']
            path.write_text(json.dumps({'version': 1, 'cache_data': [item]}))
            self.assertTrue(inspect_native_cache(path, T0, 'https://example.com/a')['lookup']['legacy_key_fallback'])
            path.write_text(json.dumps({'version': 1, 'cache_data': [item, item | {'expiration_time': 0}]}))
            self.assertEqual(inspect_native_cache(path, T0, 'https://example.com/a')['lookup']['state'], 'unknown')


if __name__ == '__main__':
    unittest.main()

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from smartscreen.feedcache import cache_feed_response, lookup_cached_feed


class FeedCacheTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.identity = {'client': {'version': '123', 'data': {'topTraffic': '0', 'edgeSettings': '2.0-0'}},
                         'device': {'id': 'first-device'}, 'user': {'onlineIdTicket': 'not-persisted'}}
        self.endpoint = 'https://data-edge.smartscreen.microsoft.com/feed?mode=one'
        self.raw = b'verified feed bytes'

    def response(self, status=200, raw=None, etag='"version-one"'):
        raw = self.raw if raw is None else raw
        return {'endpoint': self.endpoint, 'http_status': status,
                'response_sha256': hashlib.sha256(raw).hexdigest(), 'response_size': len(raw),
                'headers': {} if etag is None else {'ETag': etag}, 'collected_utc': '2026-11-23T00:00:00Z'}

    def save(self, response=None, raw=None, **kwargs):
        return cache_feed_response(self.directory.name, 'topTraffic', response or self.response(),
                                   self.raw if raw is None else raw,
                                   identity=kwargs.pop('identity', self.identity),
                                   requested_version=kwargs.pop('requested_version', '0'),
                                   **kwargs)

    def lookup(self, **kwargs):
        return lookup_cached_feed(self.directory.name, 'topTraffic', endpoint=kwargs.pop('endpoint', self.endpoint),
                                  identity=kwargs.pop('identity', self.identity), **kwargs)

    def test_roundtrip_and_matching_304_preserves_200_provenance(self):
        saved = self.save()
        self.assertEqual(saved['state'], 'stored')
        profile = copy.deepcopy(self.identity)
        profile['client']['data']['topTraffic'] = 'version-one'
        reused = self.save(self.response(304, b'', None), b'', identity=profile, requested_version='version-one')
        self.assertEqual(reused['state'], 'not_modified_cached')
        self.assertEqual(reused['http_status'], 304)
        self.assertEqual(reused['origin_http_status'], 200)
        self.assertEqual(Path(reused['body_file']).read_bytes(), self.raw)

    def test_304_without_cache_is_explicit(self):
        result = self.save(self.response(304, b'', None), b'', requested_version='version-one')
        self.assertEqual(result['state'], 'not_modified_unavailable')
        self.assertEqual(result['reason'], 'cache_missing')
        self.assertNotIn('body_file', result)

    def test_old_or_unconditional_validator_cannot_reuse(self):
        self.save()
        for version in ('0', None, 'W/"version-one"'):
            result = self.save(self.response(304, b'', None), b'', requested_version=version)
            self.assertEqual(result['reason'], 'request_validator_mismatch')
        self.assertIsNotNone(self.lookup())

    def test_response_validator_must_match_when_present(self):
        self.save()
        result = self.save(self.response(304, b'', '"version-two"'), b'', requested_version='version-one')
        self.assertEqual(result['reason'], 'response_validator_mismatch')

    def test_scope_preserves_query_identity_other_feed_method_and_auth(self):
        self.save()
        self.assertIsNone(self.lookup(endpoint=self.endpoint.replace('one', 'two')))
        for field, value in [('version', '456'), ('data', {'topTraffic': '0', 'edgeSettings': '1.0-0'})]:
            profile = copy.deepcopy(self.identity)
            profile['client'][field] = value
            self.assertIsNone(self.lookup(identity=profile))
        profile = copy.deepcopy(self.identity)
        profile['device']['id'] = 'second-device'
        self.assertIsNone(self.lookup(identity=profile))
        self.assertIsNone(self.lookup(method='GET'))
        self.assertIsNone(self.lookup(auth_id='another-id'))

    def test_reject_body_metadata_mismatch_without_overwriting(self):
        saved = self.save()
        for key, value in [('response_sha256', '0' * 64), ('response_size', 1000)]:
            record = self.response()
            record[key] = value
            with self.assertRaises(ValueError):
                self.save(record)
        self.assertEqual(self.lookup()['sha256'], saved['sha256'])

    def test_corrupt_or_missing_body_never_reused(self):
        saved = self.save()
        body = Path(saved['body_file'])
        body.write_bytes(b'x' * len(self.raw))
        result = self.save(self.response(304, b'', None), b'', requested_version='version-one')
        self.assertEqual(result['reason'], 'cache_body_digest_mismatch')
        self.assertIsNone(self.lookup())
        body.unlink()
        self.assertIsNone(self.lookup())

    def test_metadata_cannot_redirect_body_path(self):
        saved = self.save()
        path = Path(saved['metadata_file'])
        entry = json.loads(path.read_text())
        entry['sha256'] = '../../outside'
        path.write_text(json.dumps(entry))
        self.assertIsNone(self.lookup())

    def test_errors_and_unsupported_responses_preserve_previous_body(self):
        saved = self.save()
        cases = [(self.response(500), 'http_status_not_cacheable'),
                 (self.response(etag=None), 'missing_or_unsupported_validator'),
                 (self.response(etag='W/"version-one"'), 'missing_or_unsupported_validator')]
        partial = self.response()
        partial['headers']['Content-Range'] = 'bytes 0-4/10'
        cases.append((partial, 'partial_content'))
        no_store = self.response()
        no_store['headers']['Cache-Control'] = 'private, no-store'
        cases.append((no_store, 'cache_control_no_store'))
        for record, reason in cases:
            self.assertEqual(self.save(record)['reason'], reason)
            self.assertEqual(self.lookup()['sha256'], saved['sha256'])

    def test_unexpected_304_body_is_not_cached(self):
        self.save()
        result = self.save(self.response(304), requested_version='version-one')
        self.assertEqual(result['reason'], 'unexpected_304_body')

    def test_identity_secrets_are_not_stored(self):
        self.save()
        for path in Path(self.directory.name).rglob('*.json'):
            self.assertNotIn('not-persisted', path.read_text())
            self.assertNotIn('first-device', path.read_text())

    def test_size_bound_and_invalid_inputs(self):
        with self.assertRaises(ValueError):
            self.save(max_bytes=2)
        with self.assertRaises(ValueError):
            self.save(identity=[])
        with self.assertRaises(ValueError):
            self.lookup(method='DELETE')
        self.assertIsNone(self.lookup())


if __name__ == '__main__':
    unittest.main()

"""Exercise lists -> cache -> saved snapshot -> offline membership end to end."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from smartscreen import ENDPOINTS, SmartScreenClient, response_record
from smartscreen.offline import analyze_url


class FeedCacheIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.cache = self.root / 'cache'
        self.endpoint = 'https://data-edge.smartscreen.microsoft.com/api/browser/edge/data/toptraffic/3?scope=one'
        self.profile = {'client': {'version': '123', 'data': {}}, 'device': {'id': 'test-device'}}
        self.body = hashlib.sha256('example.com'.encode('utf-16-le')).digest()[:16]
        self.counter = 0

    def run_lists(self, status=200, *, profile=None, override=None, directory=None,
                  response_etag=None, advertised=True):
        self.counter += 1
        directory = directory or self.root / ('snapshot' + str(self.counter))
        profile = copy.deepcopy(self.profile if profile is None else profile)
        original_profile = copy.deepcopy(profile)
        calls = []

        def transport(endpoint, payload=None, method=None, **kwargs):
            calls.append({'endpoint': endpoint, 'payload': copy.deepcopy(payload), 'method': method, **kwargs})
            if endpoint == ENDPOINTS['actions']:
                action = {'$type': 'data', 'id': 'topTraffic', 'uri': self.endpoint, 'verb': 'POST'}
                raw = json.dumps({'actions': [action] if advertised else []}).encode()
                return response_record(endpoint, 200, {'content-type': 'application/json'}, raw), raw
            raw = self.body if status == 200 else b''
            headers = {'ETag': '"feed-version"'} if status == 200 else {}
            if response_etag is not None:
                headers['ETag'] = response_etag
            return response_record(endpoint, status, headers, raw), raw

        client = SmartScreenClient(client_version=override)
        with patch.object(client, 'request', side_effect=transport):
            result = client.lists(profile, directory, self.cache)
        self.assertEqual(profile, original_profile, 'lists mutated the caller identity')
        return directory, result, calls

    def offline(self, directory):
        report = analyze_url('https://example.com/a', directory)
        return report, next(item for item in report['datasets'] if item['id'] == 'topTraffic')

    def test_200_then_matching_304_materializes_verified_offline_snapshot(self):
        first, first_result, _ = self.run_lists()
        first_meta = json.loads((first / 'topTraffic.response.json').read_text())
        self.assertEqual(first_meta['feed_cache']['state'], 'stored')
        second, result, calls = self.run_lists(304)
        self.assertEqual(calls[1]['dataset_version'], 'feed-version')
        self.assertEqual(calls[1]['payload']['identity']['client']['data']['topTraffic'], 'feed-version')
        self.assertEqual((second / 'topTraffic.bin').read_bytes(), self.body)
        self.assertEqual(result['downloads'][0]['state'], 'not_modified_cached')
        report, entry = self.offline(second)
        self.assertEqual(entry['state'], 'analyzed')
        self.assertTrue(entry['membership'])
        self.assertEqual(entry['origin'], 'revalidated_cached_http_200')
        self.assertEqual(entry['metadata']['http_status'], 304)
        self.assertEqual(entry['metadata']['cached_body']['collected_utc'], first_meta['collected_utc'])
        self.assertIsNone(report['cloud_verdict'])

    def test_other_profile_cannot_reuse_and_leftover_body_remains_unknown(self):
        first, _, _ = self.run_lists()
        changed = copy.deepcopy(self.profile)
        changed['device']['id'] = 'another-device'
        directory, result, calls = self.run_lists(304, profile=changed, directory=first)
        self.assertEqual(calls[1]['dataset_version'], '0')
        self.assertTrue((directory / 'topTraffic.bin').exists())
        self.assertEqual(result['downloads'][0]['state'], 'not_modified_no_body')
        _, entry = self.offline(directory)
        self.assertEqual(entry['state'], 'not_modified_without_verified_cache')
        self.assertIsNone(entry['membership'])
        self.assertTrue(entry['body_ignored'])

    def test_reused_directory_does_not_promote_unadvertised_historical_body(self):
        first, _, _ = self.run_lists()
        directory, _, calls = self.run_lists(directory=first, advertised=False)
        self.assertEqual(len(calls), 1)
        _, entry = self.offline(directory)
        self.assertEqual(entry['state'], 'not_advertised_in_snapshot')
        self.assertIsNone(entry['membership'])
        self.assertTrue(entry['body_ignored'])
        self.assertEqual((directory / 'topTraffic.bin').read_bytes(), self.body)

    def test_explicit_version_is_not_replaced_by_cached_version(self):
        first, _, _ = self.run_lists()
        explicit = copy.deepcopy(self.profile)
        explicit['client']['data']['topTraffic'] = 'explicit-other-version'
        directory, _, calls = self.run_lists(304, profile=explicit, directory=first)
        self.assertEqual(calls[1]['dataset_version'], 'explicit-other-version')
        metadata = json.loads((directory / 'topTraffic.response.json').read_text())
        self.assertEqual(metadata['feed_cache']['reason'], 'request_validator_mismatch')
        self.assertIsNone(self.offline(directory)[1]['membership'])

    def test_client_version_override_is_applied_to_request_and_cache_scope(self):
        self.run_lists(override='456')
        matched, result, calls = self.run_lists(304, override='456')
        self.assertEqual(calls[0]['payload']['identity']['client']['version'], '456')
        self.assertEqual(calls[1]['payload']['identity']['client']['version'], '456')
        self.assertEqual(result['downloads'][0]['state'], 'not_modified_cached')
        self.assertTrue(self.offline(matched)[1]['membership'])
        mismatch, result, calls = self.run_lists(304, override='789')
        self.assertEqual(calls[1]['dataset_version'], '0')
        self.assertIsNone(self.offline(mismatch)[1]['membership'])
        self.assertEqual(result['downloads'][0]['state'], 'not_modified_no_body')

    def test_endpoint_query_change_does_not_reuse_same_feed_version(self):
        self.run_lists()
        self.endpoint = self.endpoint.replace('scope=one', 'scope=two')
        directory, result, calls = self.run_lists(304)
        self.assertEqual(calls[1]['dataset_version'], '0')
        self.assertIsNone(self.offline(directory)[1]['membership'])

    def test_malformed_cached_304_provenance_is_unknown(self):
        self.run_lists()
        directory, _, _ = self.run_lists(304)
        path = directory / 'topTraffic.response.json'
        valid = json.loads(path.read_text())
        mutations = [
            ('origin_http_status', 304), ('dataset_id', 'customSynchronousLookupUris'),
            ('endpoint', self.endpoint + '&different=true'), ('etag', '"wrong"'),
            ('version', 'wrong'), ('scope_sha256', None), ('size', True), ('sha256', 'invalid')]
        for field, value in mutations:
            with self.subTest(field=field):
                altered = copy.deepcopy(valid)
                altered['feed_cache'][field] = value
                path.write_text(json.dumps(altered))
                _, entry = self.offline(directory)
                self.assertEqual(entry['state'], 'invalid_metadata')
                self.assertIsNone(entry['membership'])
        path.write_text(json.dumps(valid))

    def test_nonempty_304_digest_cannot_validate_snapshot(self):
        self.run_lists()
        directory, _, _ = self.run_lists(304)
        path = directory / 'topTraffic.response.json'
        metadata = json.loads(path.read_text())
        metadata['response_sha256'] = hashlib.sha256(b'not empty').hexdigest()
        path.write_text(json.dumps(metadata))
        self.assertEqual(self.offline(directory)[1]['state'], 'invalid_metadata')

    def test_contradictory_revalidation_record_is_rejected(self):
        self.run_lists()
        directory, _, _ = self.run_lists(304)
        path = directory / 'topTraffic.response.json'
        valid = json.loads(path.read_text())
        for field, value in [('http_status', 500), ('requested_version', 'different-version'),
                             ('body_source', 'unverified_local_file')]:
            with self.subTest(field=field):
                metadata = copy.deepcopy(valid)
                metadata['feed_cache'][field] = value
                path.write_text(json.dumps(metadata))
                entry = self.offline(directory)[1]
                self.assertEqual(entry['state'], 'invalid_metadata')
                self.assertIsNone(entry['membership'])

    def test_conflicting_case_insensitive_etags_are_rejected(self):
        self.run_lists()
        directory, _, _ = self.run_lists(304)
        path = directory / 'topTraffic.response.json'
        metadata = json.loads(path.read_text())
        metadata['headers'] = {'ETag': '"wrong-version"', 'etag': '"feed-version"'}
        path.write_text(json.dumps(metadata))
        self.assertEqual(self.offline(directory)[1]['state'], 'invalid_metadata')

    def test_corrupt_cache_and_corrupt_materialized_snapshot_fail_closed(self):
        directory, _, _ = self.run_lists()
        metadata = json.loads((directory / 'topTraffic.response.json').read_text())
        Path(metadata['feed_cache']['body_file']).write_bytes(b'x' * len(self.body))
        directory, result, calls = self.run_lists(304, directory=directory)
        self.assertEqual(calls[1]['dataset_version'], '0')
        self.assertIsNone(self.offline(directory)[1]['membership'])
        self.run_lists()  # A fresh verified full body repairs the cache entry.
        directory, _, _ = self.run_lists(304)
        (directory / 'topTraffic.bin').write_bytes(b'y' * len(self.body))
        entry = self.offline(directory)[1]
        self.assertEqual(entry['state'], 'integrity_mismatch')
        self.assertIsNone(entry['membership'])

    def test_http_failure_does_not_relabel_leftover_bytes_as_current(self):
        first, _, _ = self.run_lists()
        directory, _, _ = self.run_lists(503, directory=first)
        entry = self.offline(directory)[1]
        self.assertEqual(entry['state'], 'http_response_unavailable')
        self.assertTrue(entry['body_ignored'])
        self.assertIsNone(entry['membership'])


if __name__ == '__main__':
    unittest.main()

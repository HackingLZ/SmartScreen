"""Custom-settings initial acquisition and remote-body provenance regressions."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from smartscreen import ENDPOINTS, SmartScreenClient, response_record


BASELINE = 'F95BA787499AB4FA9EFFF472CE383A14'
REMOTE_VERSION = '3FA91A37E06EB3DAD5B57925CFD0BDB0'
BODY = b'{"forceServiceDetermination":false,"inScopeProcessPatterns":[]}'


class CustomFeedAcquisitionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.cache = self.root / 'cache'
        self.endpoint = 'https://data-edge.smartscreen.microsoft.com/api/browser/edge/data/categoryBrowsers/3?reset=true'
        self.profile = {'device': {'enterprise': {}, 'onlineIdTicket': ''},
                        'client': {'version': '281483737628675', 'data': {}}}

    def fetch(self, statuses, *, profile=None, dataset='customSettings', cache=False, advertised=True, folder='snapshot'):
        statuses = iter(statuses)
        calls = []
        profile = copy.deepcopy(self.profile if profile is None else profile)
        before = copy.deepcopy(profile)

        def request(endpoint, payload=None, method=None, **kwargs):
            calls.append({'endpoint': endpoint, 'payload': copy.deepcopy(payload), **kwargs})
            if endpoint == ENDPOINTS['actions']:
                action = {'$type': 'data', 'id': dataset, 'uri': self.endpoint, 'verb': 'POST'}
                raw = json.dumps({'actions': [action] if advertised else []}).encode()
                return response_record(endpoint, 200, {'Content-Type': 'application/json'}, raw), raw
            status = next(statuses)  # An unbounded retry fails this test immediately.
            raw = BODY if status == 200 else b''
            headers = {'ETag': '"' + REMOTE_VERSION + '"'} if status == 200 else {}
            return response_record(endpoint, status, headers, raw), raw

        client = SmartScreenClient()
        with patch.object(client, 'request', side_effect=request):
            result = client.lists(profile, self.root / folder, self.cache if cache else None)
        self.assertEqual(profile, before)
        metadata_path = self.root / folder / (dataset + '.response.json')
        metadata = json.loads(metadata_path.read_text()) if metadata_path.exists() else None
        return result, calls, metadata

    def test_implicit_zero_bootstraps_body_version_and_preserves_attempts(self):
        result, calls, metadata = self.fetch([304, 200])
        self.assertEqual(len(calls), 3)
        self.assertEqual(calls[0]['payload']['identity']['client']['data']['customSettings'], '0')
        self.assertEqual(calls[1]['payload']['identity']['client']['data']['customSettings'], '0')
        self.assertEqual(calls[2]['payload']['identity']['client']['data']['customSettings'], BASELINE)
        self.assertEqual(calls[2]['dataset_version'], BASELINE)
        self.assertEqual(result['requested_dataset_versions']['customSettings'], '0')
        self.assertEqual(metadata['requested_dataset_version'], BASELINE)
        self.assertEqual(metadata['http_status'], 200)
        self.assertEqual([a['http_status'] for a in metadata['acquisition']['attempts']], [304, 200])
        self.assertFalse(metadata['acquisition']['builtin_body_used'])
        self.assertEqual((self.root / 'snapshot/customSettings.bin').read_bytes(), BODY)

    def test_explicit_zero_is_never_overridden(self):
        profile = copy.deepcopy(self.profile)
        profile['client']['data']['customSettings'] = '0'
        result, calls, metadata = self.fetch([304], profile=profile)
        self.assertEqual(len(calls), 2)
        self.assertNotIn('acquisition', metadata)
        self.assertEqual(result['downloads'][0]['state'], 'not_modified_no_body')

    def test_first_success_or_failure_does_not_retry(self):
        for status in (200, 403, 503):
            with self.subTest(status=status):
                _, calls, metadata = self.fetch([status], folder=str(status))
                self.assertEqual(len(calls), 2)
                self.assertNotIn('acquisition', metadata)

    def test_second_304_remains_unavailable_without_inventing_body(self):
        result, calls, metadata = self.fetch([304, 304], cache=True)
        self.assertEqual(len(calls), 3)
        self.assertEqual(result['downloads'][0]['state'], 'not_modified_no_body')
        self.assertEqual(metadata['feed_cache']['state'], 'not_modified_unavailable')
        self.assertFalse((self.root / 'snapshot/customSettings.bin').exists())

    def test_custom_bloom_has_no_version_bootstrap(self):
        _, calls, metadata = self.fetch([304], dataset='customSynchronousLookupUris')
        self.assertEqual(len(calls), 2)
        self.assertNotIn('acquisition', metadata)

    def test_unadvertised_feed_is_not_requested(self):
        _, calls, metadata = self.fetch([], advertised=False)
        self.assertEqual(len(calls), 1)
        self.assertIsNone(metadata)

    def test_bootstrap_200_is_reused_only_as_verified_remote_cache(self):
        _, _, first = self.fetch([304, 200], cache=True, folder='first')
        self.assertEqual(first['feed_cache']['state'], 'stored')
        self.assertEqual(first['feed_cache']['version'], REMOTE_VERSION)
        result, calls, metadata = self.fetch([304], cache=True, folder='second')
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1]['payload']['identity']['client']['data']['customSettings'], REMOTE_VERSION)
        self.assertEqual(metadata['feed_cache']['state'], 'not_modified_cached')
        self.assertEqual(metadata['feed_cache']['origin_http_status'], 200)
        self.assertNotIn('acquisition', metadata)
        self.assertEqual(result['downloads'][0]['body_origin'], 'previous_verified_http_200')
        self.assertEqual((self.root / 'second/customSettings.bin').read_bytes(), BODY)


if __name__ == '__main__':
    unittest.main()

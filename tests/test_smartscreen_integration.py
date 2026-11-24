import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import smartscreen


class FakeResponse:
    status = 200
    headers = {'Content-Type': 'application/json'}

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def read(self, limit):
        return b'{"result":{"$type":"allow"}}'


class IntegrationTests(unittest.TestCase):
    def test_profile_version_changes_http_header(self):
        profile = smartscreen.identity()
        profile['client']['version'] = '1234567890'
        payload = smartscreen.url_payload('https://example.com/', profile=profile)
        client = smartscreen.SmartScreenClient(transport='urllib')
        with patch.object(client.opener, 'open', return_value=FakeResponse()) as opened:
            client.request(smartscreen.ENDPOINTS['url'], payload)
        request = opened.call_args.args[0]
        self.assertEqual(request.get_header('User-agent'), 'SmartScreen/1234567890')
        self.assertEqual(json.loads(request.data)['identity']['client']['version'], '1234567890')

    def test_explicit_version_updates_wire_body_without_mutating_input(self):
        payload = smartscreen.url_payload('https://example.com/')
        client = smartscreen.SmartScreenClient(transport='urllib', client_version='1234')
        with patch.object(client.opener, 'open', return_value=FakeResponse()) as opened:
            record, _ = client.request(smartscreen.ENDPOINTS['url'], payload)
        request = opened.call_args.args[0]
        self.assertEqual(request.get_header('User-agent'), 'SmartScreen/1234')
        self.assertEqual(json.loads(request.data)['identity']['client']['version'], '1234')
        self.assertEqual(payload['identity']['client']['version'], smartscreen.CLIENT_VERSION)
        self.assertEqual(record['request_client_version'], '1234')

    def test_http_error_does_not_become_verdict(self):
        record = smartscreen.response_record('https://example.test/', 503, {}, b'{"rating":"allow"}')
        self.assertIsNone(record['verdict'])
        self.assertEqual(record['response']['rating'], 'allow')
        self.assertFalse(record['http_ok'])

    def test_shell_rating_code_is_not_the_verdict(self):
        record = smartscreen.response_record('https://example.test/', 200, {},
            b'{"rating":"UNKN:100","$type":"block","responseCategory":"Untrusted"}')
        self.assertEqual(record['verdict'], 'block')
        self.assertEqual(record['response_category'], 'Untrusted')
        self.assertEqual(record['response']['rating'], 'UNKN:100')
        self.assertEqual(record['verdict_source'], '$type')

    def test_file_hash_rejects_whitespace_and_boolean_size(self):
        for digest, size in [('12' * 31 + '  ', 1), ('12' * 32, True)]:
            with self.assertRaises(ValueError):
                smartscreen.file_payload(digest, size, 'example.exe', 'https://example.com/')

    def test_invalid_timeout_fails_before_network(self):
        for value in (float('nan'), float('inf'), 0, -1):
            with self.assertRaises(ValueError):
                smartscreen.SmartScreenClient(timeout=value)

    def test_batch_output_cannot_clobber_input(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'jobs.jsonl'
            original = '{"type":"url","url":"https://example.com/"}\n'
            path.write_text(original)
            with patch('sys.argv', ['smartscreen', '-o', str(path), 'batch', str(path)]), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    smartscreen.main()
            self.assertEqual(error.exception.code, 2)
            self.assertEqual(path.read_text(), original)

    def test_cli_offline_compare_emits_json(self):
        with tempfile.TemporaryDirectory() as root:
            before, after = Path(root) / 'before.bin', Path(root) / 'after.bin'
            before.write_bytes(b'a' * 16)
            after.write_bytes(b'b' * 16)
            output = io.StringIO()
            with patch('sys.argv', ['smartscreen', 'compare-feeds', str(before), str(after), '--kind', 'topTraffic']), contextlib.redirect_stdout(output):
                self.assertEqual(smartscreen.main(), 0)
            self.assertIsInstance(json.loads(output.getvalue()), dict)

    def test_lists_preserves_versions_needed_for_custom_feed_discovery(self):
        profile = smartscreen.identity()
        profile['client']['data'] = {'customSynchronousLookupUris': '3155378975999999999-0'}
        with patch.object(smartscreen.SmartScreenClient, 'request', return_value=({'response': {'actions': []}}, b'')) as request:
            smartscreen.SmartScreenClient().lists(profile)
        sent = request.call_args.args[1]['identity']['client']['data']
        self.assertEqual(sent['customSynchronousLookupUris'], '3155378975999999999-0')
        self.assertEqual(sent['topTraffic'], '0')
        self.assertEqual(sent['edgeSettings'], '2.0-0')
        self.assertEqual(profile['client']['data'], {'customSynchronousLookupUris': '3155378975999999999-0'})

    def test_lists_rejects_invalid_versions_before_sending(self):
        profile = smartscreen.identity()
        profile['client']['data'] = []
        with patch.object(smartscreen.SmartScreenClient, 'request') as request:
            with self.assertRaises(ValueError):
                smartscreen.SmartScreenClient().lists(profile)
        request.assert_not_called()

    def test_feed_request_sends_native_full_body_headers(self):
        client = smartscreen.SmartScreenClient(transport='urllib')
        with patch.object(client.opener, 'open', return_value=FakeResponse()) as opened:
            client.request(smartscreen.ENDPOINTS['actions'], {'identity': smartscreen.identity()},
                           accept='application/octet-stream;', dataset_version='3155378975999999999-0')
        request = opened.call_args.args[0]
        self.assertEqual(request.get_header('If-none-match'), '"3155378975999999999-0"')
        self.assertEqual(request.get_header('Accept'), 'application/octet-stream;')
        self.assertEqual(request.get_header('Authorization'), smartscreen.request_headers(request.data)['Authorization'])

    def test_dataset_headers_reject_control_characters(self):
        client = smartscreen.SmartScreenClient(transport='urllib')
        with patch.object(client.opener, 'open') as opened:
            for options in ({'dataset_version': '0\r\nX-Test: injected'}, {'accept': 'text/plain\nX-Test: injected'}, {'dataset_version': '"quoted"'}):
                with self.assertRaises(ValueError):
                    client.request(smartscreen.ENDPOINTS['actions'], **options)
        opened.assert_not_called()

    def test_cli_can_query_bloom_key_offline(self):
        import struct
        # One-bit fixture with all bits set establishes CLI routing only.
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'filter.bin'
            path.write_bytes(struct.pack('<II8sIII', 29, 10, b'murmur3\0', 1, 1, 0) + b'\x01')
            output = io.StringIO()
            with patch('sys.argv', ['smartscreen', 'inspect-data', str(path), '--key', 'example.com']), contextlib.redirect_stdout(output), patch.object(smartscreen.SmartScreenClient, 'request') as request:
                self.assertEqual(smartscreen.main(), 0)
            result = json.loads(output.getvalue())
            self.assertEqual(result['exact_key_match']['key'], 'example.com')
            self.assertEqual(result['format'], 'murmur3_filter')
            request.assert_not_called()

    def test_model_cli_exports_exact_document_and_token_match(self):
        import hashlib
        document = {'sampleBuckets': {'uriLookup': 0.01}, 'models': [{
            'name': 'example', 'bias': -2, 'terms': [{
                'features': ['title'], 'delimiters': ' ', 'lengthWeight': -0.2,
                'tokenWeights': [{'key': hashlib.md5(b'welcome').hexdigest(), 'value': -0.3}]}]}]}
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'settings.bin'
            path.write_text(json.dumps(document))
            output = io.StringIO()
            with patch('sys.argv', ['smartscreen', 'inspect-model', str(path), '--full', '--token', 'WELCOME']), contextlib.redirect_stdout(output), patch.object(smartscreen.SmartScreenClient, 'request') as request:
                self.assertEqual(smartscreen.main(), 0)
            result = json.loads(output.getvalue())
            self.assertEqual(result['document'], document)
            self.assertEqual(result['token_lookup']['match_count'], 1)
            self.assertFalse(result['token_lookup']['is_verdict'])
            request.assert_not_called()

    def test_cli_url_feed_lookup_reports_matching_host_candidate(self):
        import hashlib
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'topTraffic.bin'
            path.write_bytes(hashlib.sha256('www.example.com'.encode('utf-16le')).digest()[:16])
            output = io.StringIO()
            with patch('sys.argv', ['smartscreen', 'inspect-data', str(path), '--kind', 'topTraffic', '--url', 'https://WWW.Example.COM/Docs/']), contextlib.redirect_stdout(output), patch.object(smartscreen.SmartScreenClient, 'request') as request:
                self.assertEqual(smartscreen.main(), 0)
            lookup = json.loads(output.getvalue())['url_lookup']
            self.assertTrue(lookup['present'])
            self.assertEqual(lookup['matched_candidate'], 'www.example.com')
            self.assertEqual(lookup['canonical_url'], 'https://www.example.com/docs')
            self.assertEqual(lookup['tested_candidate_count'], 2)
            request.assert_not_called()

    def test_candidate_cli_maps_domains_without_network_or_verdict(self):
        with tempfile.TemporaryDirectory() as root:
            feed, candidates = Path(root) / 'top.bin', Path(root) / 'names.txt'
            feed.write_bytes(bytes.fromhex('feb2133225a527f9f5fcc1355e1225f2'))
            candidates.write_text('google.com\n')
            output = io.StringIO()
            with patch('sys.argv', ['smartscreen', 'map-candidates', str(feed), str(candidates), '--kind', 'topTraffic', '--domain-variants']), contextlib.redirect_stdout(output), patch.object(smartscreen.SmartScreenClient, 'request') as request:
                self.assertEqual(smartscreen.main(), 0)
            report = json.loads(output.getvalue())
            self.assertEqual(report['matched_hash_count'], 1)
            self.assertEqual(report['matches'][0]['candidates'], ['www.google.com'])
            self.assertFalse(report['is_blocklist'])
            request.assert_not_called()

    def test_offline_url_cli_preserves_unknown_cloud_and_missing_feeds(self):
        import hashlib
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            raw = bytes.fromhex('feb2133225a527f9f5fcc1355e1225f2')
            (directory / 'topTraffic.bin').write_bytes(raw)
            (directory / 'topTraffic.response.json').write_text(json.dumps({
                'http_status': 200, 'response_size': len(raw), 'response_sha256': hashlib.sha256(raw).hexdigest(),
                'headers': {'ETag': '"fixture"'}, 'collected_utc': '2026-11-23T00:00:00+00:00'}))
            output = io.StringIO()
            with patch('sys.argv', ['smartscreen', 'offline-url', 'https://www.google.com/', '--feeds', root]), contextlib.redirect_stdout(output), patch.object(smartscreen.SmartScreenClient, 'request') as request:
                self.assertEqual(smartscreen.main(), 0)
            report = json.loads(output.getvalue())
            self.assertEqual(report['network_requests'], 0)
            self.assertIsNone(report['cloud_verdict'])
            self.assertFalse(report['is_complete_blocklist'])
            self.assertTrue(report['datasets'][0]['membership'])
            self.assertIsNone(report['datasets'][1]['membership'])
            request.assert_not_called()

    def test_score_title_cli_is_local_and_explains_selected_model(self):
        document = {'models': [{'name': 'fixture', 'bias': -2, 'terms': [{
            'features': ['title'], 'delimiters': ' ', 'tokenWeights': [
                {'key': '0f4137ed1502b5045d6083aa258b5c42', 'value': 4.5}]}]}]}
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'model.json'
            path.write_text(json.dumps(document))
            output = io.StringIO()
            with patch('sys.argv', ['smartscreen', 'score-title', str(path), 'Windows WINDOWS']), contextlib.redirect_stdout(output), patch.object(smartscreen.SmartScreenClient, 'request') as request:
                self.assertEqual(smartscreen.main(), 0)
            report = json.loads(output.getvalue())
            self.assertEqual(report['raw_score'], 2.5)
            self.assertTrue(report['raw_score_positive'])
            self.assertFalse(report['is_verdict'])
            self.assertEqual([token['applied'] for token in report['terms'][0]['tokens']], [True, False])
            request.assert_not_called()


if __name__ == '__main__':
    unittest.main()

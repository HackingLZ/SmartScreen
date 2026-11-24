import base64
import hashlib
import json
from pathlib import Path
import re
import struct
import tempfile
import unittest
from unittest.mock import patch

from smartscreen.auth import authorization, cs64
from smartscreen import (SmartScreenClient, check_url, encode_request, file_payload,
                        identity, prepare_request, request_headers, response_record, url_payload,
                        NoRedirect, EDGE_AUTH_ID, ENDPOINTS)
from smartscreen.data import inspect_data

ROOT = Path(__file__).resolve().parents[1]


class AuthenticationTests(unittest.TestCase):
    def test_matches_independent_saved_wire_capture(self):
        path = ROOT / 'local/private/checkappexec.microsoft.com'
        if not path.exists():
            self.skipTest('Original private wire capture is not installed')
        text = path.read_text()
        header = re.search(r'SmartScreenHash ([A-Za-z0-9+/=]+)', text).group(1)
        expected = json.loads(base64.b64decode(header))
        candidate = text[text.index('{'):]
        _, length = json.JSONDecoder().raw_decode(candidate)
        body = candidate[:length].encode()
        key = base64.b64decode(expected['key'])
        self.assertEqual(hashlib.md5(body).digest(), key)
        self.assertEqual(cs64(body, key), base64.b64decode(expected['hash']))

    def test_authorization_covers_exact_utf8_wire_bytes(self):
        body = encode_request({'destination': {'uri': 'https://example.com/caf\u00e9'}})
        token = json.loads(base64.b64decode(authorization(body).split(' ', 1)[1]))
        self.assertEqual(base64.b64decode(token['key']), hashlib.md5(body).digest())
        self.assertNotEqual(authorization(body), authorization(body + b' '))

    def test_native_tail_rule_and_short_input(self):
        key = bytes(range(16))
        self.assertEqual(cs64(b'abcdefgh', key), cs64(b'abcdefghx', key))
        with self.assertRaises(ValueError):
            cs64(b'short', key)
        with self.assertRaises(ValueError):
            cs64(b'abcdefgh', key[:8])


class ClientTests(unittest.TestCase):
    def test_empty_success_is_not_allow(self):
        record = response_record('https://example.test/', 200, {}, b'{}')
        self.assertIsNone(record['verdict'])

    def test_url_and_file_schemas_have_explicit_verdicts(self):
        for body, verdict in [(b'{"result":{"$type":"warn","responseCategory":"Malicious"}}', 'warn'),
                              (b'{"rating":"unknown"}', 'unknown')]:
            self.assertEqual(response_record(ENDPOINTS['file'], 200, {}, body)['verdict'], verdict)

    def test_bare_ratings_require_observed_endpoint_and_enum(self):
        for endpoint, rating in [(ENDPOINTS['file'], 'UNKN:100'),
                                 (ENDPOINTS['file'], 'future_label'),
                                 (ENDPOINTS['shell'], 'unknown'),
                                 ('https://example.test/', 'allow')]:
            record = response_record(endpoint, 200, {}, encode_request({'rating': rating}))
            self.assertIsNone(record['verdict'])
            self.assertEqual(record['rating'], rating)

    def test_unknown_fields_are_preserved(self):
        document = {'rating': 'future_label', 'new_schema': {'a': [1, 2, 3]}}
        self.assertEqual(response_record('https://example.test/', 200, {}, encode_request(document))['response'], document)

    def test_binary_response_is_not_misrepresented_as_text(self):
        result = response_record('https://example.test/', 200, {'Content-Type': 'application/octet-stream'}, b'\xff\0\x80')
        self.assertIsNone(result['response'])
        self.assertIsNone(result['response_text'])
        self.assertEqual(result['response_size'], 3)

    def test_rejects_untrusted_service_and_credentials(self):
        for url in ['http://nav-edge.smartscreen.microsoft.com/',
                    'https://nav-edge.smartscreen.microsoft.com.attacker.test/',
                    'https://user:password@nav-edge.smartscreen.microsoft.com/',
                    'https://nav-edge.smartscreen.microsoft.com:444/']:
            with self.assertRaises(ValueError):
                check_url(url, service=True)

    def test_redirect_does_not_forward_request(self):
        self.assertIsNone(NoRedirect().redirect_request(None, None, 302, '', {}, 'https://example.test/'))

    def test_file_metadata_contains_no_contents(self):
        payload = file_payload('12' * 32, 99, 'hello.exe', 'https://example.com/')
        self.assertEqual(base64.b64decode(payload['file']['hash']), b'\x12' * 32)
        self.assertEqual(payload['file']['size'], '99')
        self.assertEqual(payload['file']['path']['fileName'], 'hello.exe')
        self.assertEqual(set(payload['file']), {'authenticode', 'fileId', 'hash', 'path', 'size', 'version'})

    def test_profiles_are_independent(self):
        profile = identity()
        payload = url_payload('https://example.com/', profile=profile)
        payload['identity']['device']['onlineIdTicket'] = 'modified'
        self.assertEqual(profile['device']['onlineIdTicket'], '')

    def test_prepared_request_is_signed_over_saved_body(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            payload = url_payload('https://example.com/')
            prepare_request(directory, 'https://nav-edge.smartscreen.microsoft.com/api/browser/edge/navigate/3/sync', payload, EDGE_AUTH_ID)
            body = (directory / 'request.json').read_bytes()
            expected = request_headers(body)['Authorization']
            self.assertIn(expected, (directory / 'curl.conf').read_text())
            self.assertEqual(json.loads(body), payload)

    def test_list_discovery_requests_initial_versions(self):
        result = {'http_status': 200, 'response': {'actions': [
            {'$type': 'data', 'id': 'topTraffic', 'uri': 'https://data-edge.smartscreen.microsoft.com/data', 'verb': 'POST'},
            {'$type': 'ping', 'uri': 'https://ping-edge.smartscreen.microsoft.com/'},
        ]}}
        with patch.object(SmartScreenClient, 'request', return_value=(result, b'')) as request:
            report = SmartScreenClient().lists()
        self.assertEqual(len(report['datasets']), 1)
        self.assertEqual(request.call_args.args[1]['identity']['client']['data']['topTraffic'], '0')


class DatasetTests(unittest.TestCase):
    def test_top_traffic_records_are_lossless(self):
        raw = bytes(range(16)) + bytes(range(16, 32))
        data = inspect_data(raw, 'topTraffic')
        self.assertEqual(data['record_count'], 2)
        self.assertTrue(data['lexicographically_sorted'])
        with self.assertRaises(ValueError):
            inspect_data(raw + b'x', 'topTraffic')

    def test_filter_header_preserves_unverified_values(self):
        raw = struct.pack('<II', 29, 10) + b'murmur3\0' + struct.pack('<III', 13, 231, 12) + b'x'
        data = inspect_data(raw)
        self.assertEqual(data['header_u32_at_20'], 231)
        self.assertEqual(data['payload_size'], 1)

    def test_settings_json_is_identified_despite_binary_mime(self):
        data = inspect_data(b'{"models":[{"name":"example","weights":[{"key":"x","value":1}]}]}')
        self.assertEqual(data['models'][0]['weight_count'], 1)


if __name__ == '__main__':
    unittest.main()

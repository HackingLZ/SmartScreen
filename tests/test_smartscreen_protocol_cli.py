import base64
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import smartscreen


class ProtocolCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def invoke(self, *args):
        output = io.StringIO()
        with patch('sys.argv', ['smartscreen', *map(str, args)]), contextlib.redirect_stdout(output):
            status = smartscreen.main()
        return status, json.loads(output.getvalue()) if output.getvalue() else None

    def test_conditional_get_preparation_uses_plain_auth_and_quoted_etag(self):
        directory = self.root / 'prepared'
        with patch.object(smartscreen.SmartScreenClient, 'request', side_effect=AssertionError('network')):
            status, _ = self.invoke('--prepare', directory, 'request', smartscreen.DATA_ENDPOINTS['topTraffic'],
                                   '--method', 'GET', '--dataset-version', '0', '--accept', 'application/octet-stream;')
        self.assertEqual(status, 0)
        config = (directory / 'curl.conf').read_text()
        headers = [json.loads(line.split(' = ', 1)[1]) for line in config.splitlines() if line.startswith('header = ')]
        self.assertIn('If-None-Match: "0"', headers)
        self.assertIn('Accept: application/octet-stream;', headers)
        authorization = next(h.split('SmartScreenPlain ', 1)[1] for h in headers if h.startswith('Authorization:'))
        self.assertEqual(json.loads(base64.b64decode(authorization)), {'authId': smartscreen.EDGE_AUTH_ID})
        self.assertIn('request = "GET"', config)
        self.assertFalse((directory / 'request.json').exists())

    def test_live_raw_request_forwards_conditional_headers(self):
        record = smartscreen.response_record(smartscreen.DATA_ENDPOINTS['topTraffic'], 304, {}, b'')
        with patch.object(smartscreen.SmartScreenClient, 'request', return_value=(record, b'')) as send:
            status, result = self.invoke('request', smartscreen.DATA_ENDPOINTS['topTraffic'],
                                        '--method', 'GET', '--dataset-version', '123', '--accept', 'application/octet-stream;')
        self.assertEqual(status, 1)  # A raw 304 is not a standalone usable feed body.
        self.assertIsNone(result['verdict'])
        self.assertEqual(send.call_args.kwargs, {'method': 'GET', 'dataset_version': '123', 'accept': 'application/octet-stream;'})

    def test_header_injection_rejected_before_prepared_artifacts(self):
        for options in ({'accept': 'x\r\nHeader: value'}, {'dataset_version': '"0"'}, {'method': 'DELETE'}):
            target = self.root / 'invalid'
            with self.assertRaises(ValueError):
                smartscreen.prepare_request(target, smartscreen.DATA_ENDPOINTS['topTraffic'], None,
                                            smartscreen.EDGE_AUTH_ID, **options)
            self.assertFalse(target.exists())

    def test_offline_inspection_and_correlation_make_no_requests(self):
        response = self.root / 'response.json'
        response.write_text('{"rating":"UNKN:100","$type":"block","serverContext":"private-context"}')
        parsed = self.root / 'parsed.json'
        parsed.write_text('{"transactions":[]}')
        with patch.object(smartscreen.SmartScreenClient, 'request', side_effect=AssertionError('network')):
            status, report = self.invoke('inspect-protocol', response)
            self.assertEqual(status, 0)
            self.assertNotIn('private-context', json.dumps(report))
            status, report = self.invoke('correlate-contexts', parsed)
            self.assertEqual(status, 0)

    def test_offline_output_cannot_clobber_hardlink_input(self):
        source = self.root / 'source.json'
        source.write_text('{"transactions":[]}')
        target = self.root / 'target.json'
        os.link(source, target)
        for command in ('inspect-protocol', 'correlate-contexts'):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                self.invoke('-o', target, command, source)
        self.assertEqual(source.read_text(), '{"transactions":[]}')

    def test_saved_file_rating_decisions_survive_protocol_inspection(self):
        from smartscreen.protocol import inspect_protocol
        for rating in ('allow', 'unknown'):
            record = smartscreen.response_record(smartscreen.ENDPOINTS['file'], 200, {},
                                                json.dumps({'rating': rating}).encode())
            report = inspect_protocol(record)
            self.assertEqual(report['decision'], rating)
            self.assertEqual(report['decision_source'], 'rating')

    def test_rating_needs_known_endpoint_enum_and_success(self):
        from smartscreen.protocol import inspect_protocol
        for endpoint, status, rating in [(smartscreen.ENDPOINTS['file'], 503, 'allow'),
                                        (smartscreen.ENDPOINTS['shell'], 200, 'unknown'),
                                        (smartscreen.ENDPOINTS['file'], 200, 'UNKN:100')]:
            record = smartscreen.response_record(endpoint, status, {}, json.dumps({'rating': rating}).encode())
            self.assertIsNone(inspect_protocol(record)['decision'])
        self.assertIsNone(inspect_protocol({'rating': 'allow'})['decision'])

    def test_explicit_type_takes_precedence_over_file_rating(self):
        from smartscreen.protocol import inspect_protocol
        record = smartscreen.response_record(smartscreen.ENDPOINTS['file'], 200, {},
                                            b'{"result":{"$type":"warn"},"rating":"allow"}')
        self.assertEqual(inspect_protocol(record)['decision'], 'warn')


if __name__ == '__main__':
    unittest.main()

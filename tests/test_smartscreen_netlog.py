import base64
import copy
import gzip
import json
from pathlib import Path
import tempfile
import unittest

from smartscreen.netlog import PREFACE, parse_netlog


def frame(payload, stream=1, kind=0, flags=0):
    return len(payload).to_bytes(3, 'big') + bytes([kind, flags]) + stream.to_bytes(4, 'big') + payload


class Capture:
    def __init__(self):
        self.document = {'constants': {'logEventTypes': {}, 'logSourceType': {'URL_REQUEST': 1}}, 'events': []}
        self.session = 10
        self.socket = 20
        self.event('HTTP2_SESSION_INITIALIZED', self.session, 11,
                   protocol='h2', source_dependency={'id': self.socket, 'type': 10})

    def event(self, kind, source, source_type, **params):
        event_types = self.document['constants']['logEventTypes']
        if kind not in event_types:
            event_types[kind] = len(event_types) + 1
        self.document['events'].append({'type': event_types[kind], 'source': {'id': source, 'type': source_type},
                                        'time': str(len(self.document['events'])), 'phase': 0, 'params': params})

    def headers(self, direction, stream=1, fin=False, status=200, path='/api/browser/edge/navigate/3', extra=()):
        if direction == 'request':
            headers = [':method: POST', ':authority: nav-edge.smartscreen.microsoft.com', ':scheme: https', ':path: ' + path]
            dependency = {'source_dependency': {'id': 30 + stream, 'type': 17}}
            self.event('HTTP_STREAM_JOB_BOUND_TO_REQUEST', 30 + stream, 17, source_dependency={'id': 40 + stream, 'type': 1})
            self.event('URL_REQUEST_START_JOB', 40 + stream, 1, method='POST', url='https://nav-edge.smartscreen.microsoft.com' + path)
        else:
            headers, dependency = [':status: ' + str(status)], {}
        self.event('HTTP2_SESSION_' + ('SEND' if direction == 'request' else 'RECV') + '_HEADERS',
                   self.session, 11, headers=headers + list(extra), stream_id=stream, fin=fin, **dependency)

    def data_metadata(self, direction, payload, stream=1, fin=True):
        self.event('HTTP2_SESSION_' + ('SEND' if direction == 'request' else 'RECV') + '_DATA',
                   self.session, 11, size=len(payload), stream_id=stream, fin=fin)

    def bytes(self, direction, payload, splits=(), *, kind=None):
        start = 0
        for end in list(splits) + [len(payload)]:
            segment = payload[start:end]
            self.event(kind or ('SSL_SOCKET_BYTES_SENT' if direction == 'request' else 'SSL_SOCKET_BYTES_RECEIVED'),
                       self.socket, 10, byte_count=len(segment), bytes=base64.b64encode(segment).decode())
            start = end

    def body(self, direction, payload, stream=1, *, fin=True, padding=None, splits=()):
        wire = bytes([padding]) + payload + bytes(padding) if padding is not None else payload
        self.data_metadata(direction, wire, stream, fin)
        self.bytes(direction, frame(wire, stream, flags=(1 if fin else 0) | (8 if padding is not None else 0)), splits)

    def parse(self, **kwargs):
        return parse_netlog(self.document, **kwargs)


class NetlogTests(unittest.TestCase):
    def test_segmented_preface_and_multiplexed_frame_reassembly(self):
        c = Capture()
        c.headers('request', 1)
        c.headers('request', 3)
        parts = [(b'{"a":', 1, False), (b'{"b":2}', 3, True), (b'1}', 1, True)]
        wire = PREFACE + frame(b'', stream=0, kind=4)
        for payload, stream, fin in parts:
            c.data_metadata('request', payload, stream, fin)
            wire += frame(payload, stream, flags=int(fin))
        c.bytes('request', wire, splits=(1, 8, 23, 25, 34, 39, 52, len(wire) - 2))
        result = c.parse(redact_sensitive=False)
        transactions = {row['stream_id']: row for row in result['transactions']}
        for stream, expected in [(1, {'a': 1}), (3, {'b': 2})]:
            body = transactions[stream]['request']['body']
            self.assertTrue(body['complete'], body['errors'])
            self.assertEqual(body['json'], expected)
        self.assertEqual(transactions[1]['url_request_source'], '1:41')
        self.assertGreater(len(transactions[1]['request']['body']['frames'][0]['provenance']), 1)

    def test_padded_gzip_response_and_multiple_frames(self):
        c = Capture()
        payload = gzip.compress(b'{"result":{"$type":"evaluate"}}', mtime=0)
        c.headers('request', fin=True)
        c.headers('response', extra=('content-encoding: gzip', 'content-length: ' + str(len(payload))))
        c.body('response', payload[:12], fin=False, padding=5, splits=(2, 11))
        c.body('response', payload[12:], padding=0, splits=(8, 10))
        body = c.parse()['transactions'][0]['response']['body']
        self.assertTrue(body['complete'], body['errors'])
        self.assertEqual(body['json']['result']['$type'], 'evaluate')
        self.assertEqual(body['wire_size'], len(payload))
        self.assertEqual(body['logged_frame_payload_size'], len(payload) + 7)

    def test_empty_headers_end_stream_and_informational_status(self):
        c = Capture()
        c.headers('request', fin=True)
        c.headers('response', status=100)
        c.headers('response', status=204, fin=True)
        transaction = c.parse()['transactions'][0]
        self.assertEqual(transaction['http_status'], 204)
        self.assertTrue(transaction['request']['body']['complete'])
        self.assertTrue(transaction['response']['body']['complete'])
        self.assertEqual(len(transaction['response']['header_blocks']), 2)

    def test_trailers_do_not_replace_final_headers(self):
        c = Capture()
        c.headers('request', fin=True)
        c.headers('response', status=403)
        c.body('response', b'{"result":"unknown"}', fin=False)
        c.event('HTTP2_SESSION_RECV_HEADERS', c.session, 11, stream_id=1,
                headers=['x-trailer: done'], fin=True)
        c.bytes('response', frame(b'compressed-placeholder', kind=1, flags=5))
        transaction = c.parse()['transactions'][0]
        self.assertEqual(transaction['http_status'], 403)
        self.assertTrue(transaction['response']['body']['complete'])
        self.assertNotIn('verdict', transaction)

    def test_tls_socket_bytes_never_treated_as_plaintext(self):
        c = Capture()
        c.headers('request')
        payload = b'{"a":1}'
        c.data_metadata('request', payload)
        c.bytes('request', frame(payload, flags=1), kind='SOCKET_BYTES_SENT')
        body = c.parse()['transactions'][0]['request']['body']
        self.assertFalse(body['complete'])
        self.assertEqual(body['state'], 'missing_bytes')
        self.assertIsNone(body['json'])

    def test_missing_bytes_stop_reassembly_without_guessing(self):
        c = Capture()
        c.headers('request')
        payload = b'{"a":1}'
        c.data_metadata('request', payload)
        c.event('SSL_SOCKET_BYTES_SENT', c.socket, 10, byte_count=3)
        c.bytes('request', frame(payload, flags=1))
        report = c.parse()
        self.assertEqual(report['issues'][0]['kind'], 'plaintext_byte_gap')
        self.assertFalse(report['transactions'][0]['request']['body']['complete'])

    def test_truncated_frame_is_not_a_complete_body(self):
        c = Capture()
        c.headers('request')
        c.data_metadata('request', b'{"a":1}')
        c.bytes('request', frame(b'{"a":1}', flags=1)[:-2])
        report = c.parse()
        self.assertEqual(report['issues'][0]['kind'], 'incomplete_http2_frame')
        self.assertIsNone(report['transactions'][0]['request']['body']['json'])

    def test_padding_and_content_length_errors(self):
        c = Capture()
        c.headers('request', extra=('content-length: 2',))
        c.data_metadata('request', b'\x09ab')
        c.bytes('request', frame(b'\x09ab', flags=9))
        body = c.parse()['transactions'][0]['request']['body']
        self.assertIn('Invalid DATA padding', body['errors'])
        self.assertFalse(body['complete'])

    def test_body_and_decompression_limits(self):
        c = Capture()
        c.headers('request')
        c.body('request', b'{"message":"too long"}')
        body = c.parse(max_body_bytes=8)['transactions'][0]['request']['body']
        self.assertEqual(body['wire_size'], 8)
        self.assertFalse(body['complete'])
        c = Capture()
        c.headers('request', fin=True)
        c.headers('response', extra=('content-encoding: gzip',))
        c.body('response', gzip.compress(b'x' * 10000, mtime=0))
        body = c.parse(max_body_bytes=100)['transactions'][0]['response']['body']
        self.assertTrue(body['complete'])
        self.assertIn('max_body_bytes', body['decode_error'])

    def test_sensitive_redaction_default_and_explicit_exact_export(self):
        c = Capture()
        c.headers('request', extra=('authorization: SmartScreenHash secret-signature', 'cookie: account=secret-cookie'))
        payload = json.dumps({'identity': {'device': {'onlineIdTicket': 'secret-ticket',
                                                     'customId': 'secret-custom', 'id': 'secret-id'}},
                              'serverContext': 'explicit-protocol-binding'}).encode()
        c.body('request', payload)
        report = c.parse()
        encoded = json.dumps(report)
        for secret in ['secret-signature', 'secret-cookie', 'secret-ticket', 'secret-custom', 'secret-id',
                       base64.b64encode(payload).decode()]:
            self.assertNotIn(secret, encoded)
        body = report['transactions'][0]['request']['body']
        self.assertIsNone(body['wire_base64'])
        self.assertTrue(body['json']['identity']['device']['onlineIdTicket']['redacted'])
        raw = c.parse(redact_sensitive=False)['transactions'][0]['request']['body']
        self.assertEqual(base64.b64decode(raw['wire_base64']), payload)
        self.assertEqual(raw['json']['identity']['device']['onlineIdTicket'], 'secret-ticket')

    def test_incomplete_live_json_recovers_only_contiguous_complete_events(self):
        c = Capture()
        c.headers('request', fin=True)
        prefix = '{"constants":' + json.dumps(c.document['constants']) + ',"events":['
        text = prefix + ','.join(json.dumps(row) for row in c.document['events']) + ',{"params":'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'netlog.json'
            path.write_text(text)
            report = parse_netlog(path)
        self.assertEqual(report['event_count'], len(c.document['events']))
        self.assertFalse(report['source']['complete_json'])
        self.assertTrue(any(row['kind'] == 'unparsed_event_tail' for row in report['issues']))

    def test_same_stream_id_on_separate_sessions_does_not_mix(self):
        c = Capture()
        c.headers('request')
        c.body('request', b'{"session":10}')
        c.session, c.socket = 50, 60
        c.event('HTTP2_SESSION_INITIALIZED', 50, 11, protocol='h2', source_dependency={'id': 60, 'type': 10})
        c.headers('request')
        c.body('request', b'{"session":50}')
        bodies = [row['request']['body']['json'] for row in c.parse()['transactions']]
        self.assertEqual(bodies, [{'session': 10}, {'session': 50}])

    def test_navigation_followup_binding_requires_more_than_url(self):
        c = Capture()
        common = {'destination': {'uri': 'https://example.test/'}, 'correlationId': 'same-explicit-id'}
        c.headers('request', 1)
        c.body('request', json.dumps(common).encode(), 1)
        c.headers('response', 1)
        c.body('response', b'{"serverContext":"opaque-binding","result":{"$type":"evaluate"}}', 1)
        c.headers('request', 3, path='/api/browser/edge/navigationcomplete/3')
        c.body('request', json.dumps(dict(common, serverContext='opaque-binding')).encode(), 3)
        c.headers('request', 5, path='/api/browser/edge/navigationcomplete/3')
        c.body('request', json.dumps({'destination': common['destination']}).encode(), 5)
        followups = c.parse()['navigation_sequences']['followups']
        self.assertTrue(followups[0]['unique_explicit_binding'])
        self.assertIn('serverContext_matches_response_root', followups[0]['candidates'][0]['basis'])
        self.assertFalse(followups[1]['unique_explicit_binding'])

    def test_unknown_encoding_preserves_wire_evidence(self):
        c = Capture()
        c.headers('request', fin=True)
        c.headers('response', extra=('content-encoding: br',))
        c.body('response', b'undecoded')
        body = c.parse(redact_sensitive=False)['transactions'][0]['response']['body']
        self.assertTrue(body['complete'])
        self.assertIn('Unsupported content-encoding', body['decode_error'])
        self.assertEqual(base64.b64decode(body['wire_base64']), b'undecoded')

    def test_utf8_bom_json_in_gzip_keeps_exact_bytes(self):
        c = Capture()
        c.headers('request', fin=True)
        c.headers('response', extra=('content-encoding: gzip',))
        decoded = b'\xef\xbb\xbf{"bom":true}'
        c.body('response', gzip.compress(decoded, mtime=0))
        body = c.parse(redact_sensitive=False)['transactions'][0]['response']['body']
        self.assertEqual(body['json'], {'bom': True})
        self.assertTrue(body['utf8_bom'])
        self.assertEqual(base64.b64decode(body['decoded_base64']), decoded)

    def test_trailer_secrets_and_invalid_base64_are_not_exposed(self):
        c = Capture()
        c.headers('request', fin=True)
        c.headers('response', fin=True, extra=('set-cookie: session=private-trailer',))
        result = c.parse()
        self.assertNotIn('private-trailer', json.dumps(result))
        c.event('SSL_SOCKET_BYTES_RECEIVED', c.socket, 10, byte_count=1, bytes='!invalid!')
        result = c.parse()
        self.assertTrue(any(row['kind'] == 'plaintext_byte_gap' for row in result['issues']))
        self.assertFalse(result['transactions'][0]['response']['body']['complete'])

    def test_zero_uuid_is_not_a_shared_correlation_identifier(self):
        c = Capture()
        request = {'correlationId': '00000000-0000-0000-0000-000000000000',
                   'destination': {'uri': 'https://example.test/'}}
        c.headers('request', 1)
        c.body('request', json.dumps(request).encode(), 1)
        c.headers('request', 3, path='/api/browser/edge/navigationcomplete/3')
        c.body('request', json.dumps(request).encode(), 3)
        followup = c.parse()['navigation_sequences']['followups'][0]
        self.assertFalse(followup['unique_explicit_binding'])
        self.assertEqual(followup['candidates'][0]['basis'], ['same_destination_uri'])

    def test_input_validation_and_no_mutation(self):
        c = Capture()
        c.headers('request', fin=True)
        before = copy.deepcopy(c.document)
        c.parse()
        self.assertEqual(c.document, before)
        for options in ({'max_body_bytes': 0}, {'hosts': 'example.test'}, {'redact_sensitive': 'yes'}):
            with self.assertRaises(ValueError):
                c.parse(**options)
        with self.assertRaises(ValueError):
            parse_netlog({'constants': {}, 'events': None})


if __name__ == '__main__':
    unittest.main()

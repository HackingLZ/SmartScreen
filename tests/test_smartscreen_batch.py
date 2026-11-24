import base64
import copy
from contextlib import closing
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock

from smartscreen import identity
from smartscreen.batch import HistoryStore, MAX_LINE_BYTES, prepare_job, run_batch


def response(verdict='allow', status=200, category=None, headers=None):
    body = {} if verdict is None else {'rating': verdict, 'unfamiliar_field': {'keep': True}}
    raw = json.dumps(body).encode()
    return ({'http_status': status, 'verdict': verdict, 'response_category': category,
             'response': body, 'headers': headers or {}}, raw)


class FakeClient:
    auth_id = 'test-auth-id'
    client_version = '123'

    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []

    def request(self, endpoint, payload):
        self.calls.append((endpoint, copy.deepcopy(payload)))
        item = next(self.responses)
        if isinstance(item, BaseException):
            raise item
        return item


class FlushingOutput(io.StringIO):
    def __init__(self):
        super().__init__()
        self.flushes = 0

    def flush(self):
        self.flushes += 1
        super().flush()


class BatchTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.input = self.root / 'input.jsonl'
        self.db = self.root / 'history.sqlite3'

    def tearDown(self):
        self.directory.cleanup()

    def jobs(self, jobs):
        self.input.write_text(''.join(json.dumps(job) + '\n' for job in jobs), encoding='utf-8')

    def run_jobs(self, responses, **kwargs):
        client = FakeClient(responses)
        output, sleep = FlushingOutput(), Mock()
        summary = run_batch(self.input, output, client=client, sleep_fn=sleep, **kwargs)
        records = [json.loads(line) for line in output.getvalue().splitlines()]
        return summary, records, client, sleep, output

    def test_successful_unknown_is_distinct_from_empty_success(self):
        self.jobs([{'type': 'url', 'url': 'https://example.com/'},
                   {'type': 'url', 'url': 'https://example.org/'}])
        summary, records, _, sleep, output = self.run_jobs([response('unknown'), response(None)])
        self.assertEqual([r['status'] for r in records], ['verdict', 'no_verdict'])
        self.assertFalse(summary['success'])
        self.assertEqual(summary['failed'], 1)
        self.assertEqual(summary['not_run'], 0)
        self.assertEqual(output.flushes, 2)
        sleep.assert_called_once_with(1.0)

    def test_malformed_line_aborts_all_requests(self):
        self.input.write_text('{"type":"url","url":"https://example.com/"}\nno-json\n')
        summary, records, client, _, _ = self.run_jobs([])
        self.assertEqual(client.calls, [])
        self.assertEqual([r['status'] for r in records], ['not_run_preflight_failed', 'invalid_input'])
        self.assertEqual((summary['failed'], summary['not_run']), (1, 1))

    def test_unknown_fields_and_boolean_sizes_are_rejected(self):
        self.jobs([{'type': 'url', 'url': 'https://example.com/', 'refferrer': 'typo'},
                   {'type': 'hash', 'sha256': '00' * 32, 'size': True, 'name': 'a.exe', 'source': 'https://example.com/'}])
        summary, records, client, _, _ = self.run_jobs([])
        self.assertEqual(summary['failed'], 2)
        self.assertTrue(all(r['status'] == 'invalid_input' for r in records))
        self.assertEqual(client.calls, [])

    def test_duplicate_keys_and_nonfinite_json_are_rejected(self):
        self.input.write_text('{"type":"url","url":"https://example.com/","url":"https://example.org/"}\n'
                              '{"type":"url","url":"https://example.com/","identity":{"x":NaN}}\n')
        summary, _, client, _, _ = self.run_jobs([])
        self.assertEqual(summary['failed'], 2)
        self.assertEqual(client.calls, [])

    def test_max_jobs_does_not_send_a_partial_batch(self):
        self.jobs([{'type': 'url', 'url': 'https://example.com/'}] * 3)
        summary, records, client, _, _ = self.run_jobs([], max_jobs=1)
        self.assertFalse(summary['input_complete'])
        self.assertEqual(len(records), 2)
        self.assertEqual(records[1]['error']['type'], 'InputLimitExceeded')
        self.assertEqual(client.calls, [])

    def test_empty_and_oversized_input_are_explicit_failures(self):
        for text in ['', ' ' * (MAX_LINE_BYTES + 10) + '\n']:
            self.input.write_text(text)
            summary, records, client, _, _ = self.run_jobs([])
            self.assertFalse(summary['success'])
            self.assertEqual(records[0]['status'], 'invalid_input')
            self.assertEqual(client.calls, [])

    def test_relative_file_paths_and_hash_equivalence(self):
        raw = b'Harmless test fixture\n' * 100000
        (self.root / 'fixture.bin').write_bytes(raw)
        file_job = {'type': 'file', 'path': 'fixture.bin', 'source': 'https://example.com/sample.exe', 'name': 'sample.exe'}
        prepared_file = prepare_job(file_job, base_dir=self.root)
        prepared_hash = prepare_job({'type': 'hash', 'sha256': hashlib.sha256(raw).hexdigest(),
                                     'size': len(raw), 'name': 'sample.exe', 'source': file_job['source']})
        self.assertEqual(prepared_file['query_key'], prepared_hash['query_key'])
        self.assertEqual(prepared_file['target']['size'], len(raw))
        self.assertEqual(base64.b64decode(prepared_file['payload']['file']['hash']), hashlib.sha256(raw).digest())

    def test_missing_file_prevents_other_requests(self):
        self.jobs([{'type': 'url', 'url': 'https://example.com/'},
                   {'type': 'file', 'path': 'missing.exe', 'source': 'https://example.com/'}])
        _, records, client, _, _ = self.run_jobs([])
        self.assertEqual(records[1]['status'], 'invalid_input')
        self.assertEqual(client.calls, [])

    def test_correlation_id_and_job_label_do_not_split_history(self):
        job = {'type': 'url', 'url': 'https://example.com/'}
        first, second = prepare_job(job), prepare_job(dict(job, id='label'))
        self.assertNotEqual(first['payload']['correlationId'], second['payload']['correlationId'])
        self.assertEqual(first['query_key'], second['query_key'])
        different_referrer = prepare_job(dict(job, referrer='https://example.org/'))
        self.assertNotEqual(first['query_key'], different_referrer['query_key'])
        self.assertNotEqual(first['query_key'], prepare_job(job, client_version='456')['query_key'])
        self.assertNotEqual(first['query_key'], prepare_job(job, auth_id='different')['query_key'])

    def test_effective_version_matches_body_and_header_identity(self):
        profile = identity()
        profile['client']['version'] = '345'
        job = {'type': 'url', 'url': 'https://example.com/', 'identity': profile}
        inferred = prepare_job(job)
        self.assertEqual(inferred['context']['client_version'], '345')
        overridden = prepare_job(job, client_version='678')
        self.assertEqual(overridden['payload']['identity']['client']['version'], '678')
        self.assertEqual(overridden['context']['client_version'], '678')
        self.assertEqual(profile['client']['version'], '345')
        self.assertNotEqual(inferred['query_key'], overridden['query_key'])

    def test_download_and_shell_jobs_use_distinct_wire_surfaces(self):
        self.jobs([
            {'type': 'download', 'url': 'https://example.com/download.exe', 'referrer': 'https://example.org/'},
            {'type': 'hash', 'sha256': '12' * 32, 'size': 42, 'name': 'sample.exe',
             'source': 'https://example.com/download.exe', 'surface': 'shell'},
        ])
        summary, records, client, _, _ = self.run_jobs([response('allow'), response('unknown')])
        self.assertTrue(summary['success'])
        self.assertIn('/download/3', client.calls[0][0])
        self.assertEqual(client.calls[0][1]['referrer']['uri'], 'https://example.org/')
        self.assertIn('/beforeExecute/2', client.calls[1][0])
        self.assertEqual(records[1]['context']['surface'], 'shell')
        browser = prepare_job({'type': 'hash', 'sha256': '12' * 32, 'size': 42, 'name': 'sample.exe',
                               'source': 'https://example.com/download.exe'})
        shell = prepare_job({'type': 'hash', 'sha256': '12' * 32, 'size': 42, 'name': 'sample.exe',
                             'source': 'https://example.com/download.exe', 'surface': 'shell'})
        self.assertNotEqual(browser['query_key'], shell['query_key'])

    def test_unsupported_surface_prevents_batch_queries(self):
        self.jobs([{'type': 'hash', 'sha256': '12' * 32, 'size': 42, 'name': 'sample.exe',
                    'source': 'https://example.com/', 'surface': 'typo'}])
        summary, records, client, _, _ = self.run_jobs([])
        self.assertEqual(summary['failed'], 1)
        self.assertEqual(records[0]['status'], 'invalid_input')
        self.assertEqual(client.calls, [])

    def test_identity_tokens_are_redacted_with_stable_fingerprint(self):
        profile = identity()
        profile['device']['onlineIdTicket'] = 'PRIVATE_TICKET_VALUE'
        job = {'type': 'url', 'url': 'https://example.com/', 'identity': profile}
        self.jobs([job])
        _, records, client, _, output = self.run_jobs([response()], history=self.db)
        self.assertNotIn('PRIVATE_TICKET_VALUE', output.getvalue())
        self.assertEqual(client.calls[0][1]['identity']['device']['onlineIdTicket'], 'PRIVATE_TICKET_VALUE')
        context = records[0]['context']['payload']['identity']['device']['onlineIdTicket']
        self.assertTrue(context['redacted'])
        self.assertEqual(len(context['sha256']), 64)
        with HistoryStore(self.db, readonly=True) as history:
            self.assertNotIn('PRIVATE_TICKET_VALUE', json.dumps(history.query()))
        alternate = copy.deepcopy(job)
        alternate['identity']['device']['onlineIdTicket'] = 'DIFFERENT_TICKET'
        self.assertNotEqual(prepare_job(job)['query_key'], prepare_job(alternate)['query_key'])

    def test_http_failure_does_not_replace_prior_successful_verdict(self):
        self.jobs([{'type': 'url', 'url': 'https://example.com/'}])
        self.run_jobs([response('allow')], history=self.db)
        _, failed, _, _, _ = self.run_jobs([response('allow', status=500)], history=self.db)
        self.assertEqual(failed[0]['status'], 'http_error')
        self.assertIsNone(failed[0]['verdict'])
        _, changed, _, _, _ = self.run_jobs([response('unknown')], history=self.db)
        row = changed[0]
        self.assertEqual(row['history']['previous_observation']['status'], 'http_error')
        self.assertEqual(row['history']['previous_verdict']['verdict'], 'allow')
        self.assertTrue(row['history']['verdict_changed'])
        self.assertEqual(json.loads(base64.b64decode(row['raw_response_base64']))['rating'], 'unknown')
        with HistoryStore(self.db, readonly=True) as history:
            self.assertEqual(len(history.query(query_key=row['query_key'])), 3)
            self.assertEqual(history.query(limit=1)[0]['verdict'], 'unknown')

    def test_rate_limit_stops_remaining_jobs(self):
        self.jobs([{'type': 'url', 'url': 'https://example.com/'}] * 3)
        for code in (429, 503):
            summary, records, client, sleep, _ = self.run_jobs([response(None, code, headers={'Retry-After': '120'})])
            self.assertEqual(len(client.calls), 1)
            self.assertEqual(summary['requests_sent'], 1)
            self.assertEqual(summary['not_run'], 2)
            self.assertEqual(records[1]['status'], 'not_run_service_unavailable')
            self.assertEqual(records[1]['error']['retry_after'], '120')
            sleep.assert_not_called()

    def test_transport_error_is_persisted_and_later_item_runs(self):
        self.jobs([{'type': 'url', 'url': 'https://example.com/'}] * 2)
        summary, records, _, _, _ = self.run_jobs([OSError('transport failed'), response('unknown')], history=self.db)
        self.assertEqual([r['status'] for r in records], ['request_error', 'verdict'])
        self.assertFalse(summary['success'])
        with HistoryStore(self.db, readonly=True) as history:
            self.assertEqual(len(history.query()), 2)

    def test_unserializable_response_retains_exact_raw_body(self):
        self.jobs([{'type': 'url', 'url': 'https://example.com/'}])
        raw = b'{"unrecognized":NaN}'
        bad = {'http_status': 200, 'verdict': None, 'response': {'unrecognized': float('nan')}}
        summary, records, _, _, _ = self.run_jobs([(bad, raw)])
        self.assertEqual(records[0]['status'], 'request_error')
        self.assertEqual(base64.b64decode(records[0]['raw_response_base64']), raw)
        self.assertEqual(summary['failed'], 1)

    def test_keyboard_interrupt_records_unsent_jobs(self):
        self.jobs([{'type': 'url', 'url': 'https://example.com/'}] * 2)
        summary, records, client, _, _ = self.run_jobs([KeyboardInterrupt()])
        self.assertEqual([r['status'] for r in records], ['interrupted', 'not_run_interrupted'])
        self.assertEqual(len(client.calls), 1)
        self.assertFalse(summary['success'])

    def test_output_failure_stops_requests_but_history_is_durable(self):
        self.jobs([{'type': 'url', 'url': 'https://example.com/'}] * 3)
        client = FakeClient([response(), response(), response()])
        output = Mock()
        output.write.side_effect = [None, OSError('disk full')]
        with self.assertRaises(OSError):
            run_batch(self.input, output, client=client, history=self.db, sleep_fn=Mock())
        self.assertEqual(len(client.calls), 2)
        with HistoryStore(self.db, readonly=True) as history:
            self.assertEqual(len(history.query()), 2)

    def test_readonly_history_never_creates_missing_database(self):
        with self.assertRaises(FileNotFoundError):
            HistoryStore(self.db, readonly=True)
        self.assertFalse(self.db.exists())

    def test_unrelated_sqlite_database_is_not_modified(self):
        with closing(sqlite3.connect(self.db)) as connection:
            connection.execute('CREATE TABLE unrelated(value TEXT)')
        with self.assertRaises(ValueError):
            HistoryStore(self.db)
        with closing(sqlite3.connect(self.db)) as connection:
            names = [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        self.assertEqual(names, ['unrelated'])


if __name__ == '__main__':
    unittest.main()

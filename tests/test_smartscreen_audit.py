import base64
import json
import unittest

from smartscreen.audit import audit, endpoint, file_hash
from tools.lab import fetch_script, ps_literal


def capture(body=None, url='https://nav-edge.smartscreen.microsoft.com/api/browser/edge/navigate/3/sync'):
    return {'log': {'entries': [{
        'request': {'url': url, 'headers': [{'name': 'Authorization', 'value': 'SECRET_AUTH'}],
                    'postData': {'text': json.dumps({
                        'identity': {'onlineIdTicket': 'SECRET_TICKET'},
                        'destination': {'uri': 'https://example.test/?token=SECRET_QUERY'},
                        'config': {'user': {'uriReputation': {'level': 'warn', 'enforcedByPolicy': True}}},
                    })}},
        'response': {'status': 200, 'headers': [{'name': 'Set-Cookie', 'value': 'SECRET_COOKIE'}],
                     'content': {} if body is None else {'text': json.dumps(body)}},
    }]}}


class AuditTests(unittest.TestCase):
    def test_http_success_is_not_a_trust_verdict(self):
        report = audit(capture({'revision': 5, 'sample_rate': 1}))
        record = report['records'][0]
        self.assertEqual(record['cloud_verdict'], 'not_interpreted')
        self.assertEqual(record['observation']['ui_action'], 'not_observed')
        self.assertIn('client_enforcement_not_observed', record['evidence_gaps'])

    def test_captured_headers_identities_and_url_queries_are_not_exported(self):
        report = audit(capture({'reason': 'SECRET_RESPONSE', 'token': 'SECRET_TOKEN'}))
        text = json.dumps(report)
        self.assertNotIn('SECRET_', text)
        self.assertNotIn('example.test', text)

    def test_raw_enum_is_preserved_without_interpretation(self):
        record = audit(capture({'result': {'determination': 42}}))['records'][0]
        self.assertEqual(record['response_candidate_fields'][0]['raw_value'], 42)
        self.assertEqual(record['cloud_verdict'], 'not_interpreted')

    def test_missing_response_and_empty_json_are_distinct(self):
        missing = audit(capture())['records'][0]
        empty = audit(capture({}))['records'][0]
        self.assertEqual(missing['response_body_state'], 'not_captured')
        self.assertEqual(empty['response_body_state'], 'json')

    def test_base64_har_body(self):
        har = capture()
        har['log']['entries'][0]['response']['content'] = {
            'text': base64.b64encode(b'{"action":"warn"}').decode(), 'encoding': 'base64',
        }
        record = audit(har)['records'][0]
        self.assertEqual(record['response_candidate_fields'][0]['raw_value'], 'warn')

    def test_host_suffix_spoof_and_maps_are_excluded(self):
        self.assertIsNone(endpoint('https://nav-edge.smartscreen.microsoft.com.attacker.test/api/browser/edge/navigate/3'))
        self.assertIsNone(endpoint('https://wdcp.microsoft.com/wdcp.svc/bond/submitreport'))
        self.assertEqual(endpoint('https://checkappexec.microsoft.com/windows/shell/service/beforeExecute/2')['surface'], 'shell_execution')

    def test_observations_remain_separate_from_protocol(self):
        record = audit(capture({'action': 'allow'}), {'observations': [{
            'entry_index': 0, 'ui_action': 'blocked', 'effective_policy_confirmed': True,
        }]})['records'][0]
        self.assertEqual(record['observation']['ui_action'], 'blocked')
        self.assertEqual(record['response_candidate_fields'][0]['raw_value'], 'allow')
        self.assertEqual(record['cloud_verdict'], 'not_interpreted')

    def test_invalid_observation_is_rejected(self):
        for observation in [
            {'entry_index': 2}, {'entry_index': 0, 'ui_action': 'clean'},
            {'entry_index': 0, 'effective_policy_confirmed': 'false'},
        ]:
            with self.assertRaises(ValueError):
                audit(capture(), {'observations': [observation]})

    def test_file_hash_formats(self):
        raw = b'\x12' * 32
        self.assertEqual(file_hash({'file': {'hash': base64.b64encode(raw).decode()}}), raw.hex())
        self.assertIsNone(file_hash({'file': {'hash': 'not a hash'}}))

    def test_remote_paths_are_literals(self):
        self.assertEqual(ps_literal("C:\\test'file.exe"), "'C:\\test''file.exe'")
        self.assertIn("$p = 'C:\\$(whoami).exe'", fetch_script('C:\\$(whoami).exe'))


if __name__ == '__main__':
    unittest.main()

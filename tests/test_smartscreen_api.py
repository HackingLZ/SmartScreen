import base64
import json
from pathlib import Path
import unittest

from smartscreen import response_record
from smartscreen.api import API_ROUTES, api_catalog, download_payload, shell_payload, summarize_presentation


class ApiPayloadTests(unittest.TestCase):
    def test_download_contract_and_source_context(self):
        payload = download_payload('https://example.com/app.exe', referrer='https://example.org/')
        self.assertEqual(payload['type'], 'download')
        self.assertEqual(payload['destination']['uri'], 'https://example.com/app.exe')
        self.assertEqual(payload['referrer']['uri'], 'https://example.org/')
        self.assertNotIn('file', payload)

    def test_shell_contract_contains_hash_and_no_file_bytes(self):
        payload = shell_payload('12' * 32, 55, 'benign.exe', 'https://example.com/app.exe')
        self.assertEqual(base64.b64decode(payload['file']['hash']), b'\x12' * 32)
        self.assertEqual(payload['file']['size'], '55')
        self.assertEqual(payload['file']['path']['fileName'], 'benign.exe')
        self.assertEqual(set(payload['file']), {'authenticode', 'fileId', 'hash', 'path', 'size', 'version'})
        self.assertNotIn('synchronous', payload)
        self.assertNotIn('userAgent', payload)

    def test_profile_and_config_are_not_mutated(self):
        profile = {'client': {'version': '123'}, 'device': {'onlineIdTicket': ''}}
        config = {'user': {'uriReputation': {'level': 'warn'}}}
        payload = download_payload('https://example.com/', profile=profile, config=config)
        payload['identity']['client']['version'] = '456'
        payload['config']['user']['uriReputation']['level'] = 'modified'
        self.assertEqual(profile['client']['version'], '123')
        self.assertEqual(config['user']['uriReputation']['level'], 'warn')

    def test_invalid_file_metadata_rejected_before_network(self):
        invalid = [('12' * 31, 55, 'test.exe'), ('gg' * 32, 55, 'test.exe'),
                   ('12' * 32, -1, 'test.exe'), ('12' * 32, True, 'test.exe'),
                   ('12' * 32, 55, '')]
        for digest, size, name in invalid:
            with self.subTest(digest=digest, size=size, name=name), self.assertRaises(ValueError):
                shell_payload(digest, size, name, 'https://example.com/')

    def test_invalid_context_types_rejected(self):
        with self.assertRaises(ValueError):
            download_payload('https://example.com/', profile=[])
        with self.assertRaises(ValueError):
            download_payload('https://example.com/', config='warn')

    def test_catalog_preserves_package_validation_scope(self):
        catalog = {entry['name']: entry for entry in api_catalog()}
        self.assertEqual(catalog['shell']['validation'], 'live_validated')
        self.assertEqual(catalog['package-install']['validation'], 'live_validated')
        self.assertEqual(catalog['package-install']['reader'], 'smartscreen-1.2.2312.1-prefix4096')
        self.assertIn('not established', catalog['package-install']['context'])
        catalog['shell']['validation'] = 'changed'
        self.assertEqual(API_ROUTES['shell']['validation'], 'live_validated')


class ShellResponseTests(unittest.TestCase):
    def test_native_shell_type_is_distinct_from_rating_code(self):
        data = b'{"$type":"block","rating":"UNKN:100","responseCategory":"Untrusted"}'
        record = response_record(API_ROUTES['shell']['endpoint'], 200, {}, data)
        self.assertEqual(record['verdict'], 'block')
        self.assertEqual(record['response']['rating'], 'UNKN:100')
        self.assertEqual(record['response_category'], 'Untrusted')

    def test_template_text_without_script_or_visibility_claims(self):
        html = ('<div id="messageTitle">Windows <b>protected</b> your PC</div>'
                '<div id="messageBody">An unrecognized app.</div>'
                '<button id="runBtn" style="display:none">Run <span>anyway</span></button>'
                '<script>alert("never execute")</script>')
        result = summarize_presentation({'html': html})
        self.assertEqual(result['message_title'], 'Windows protected your PC')
        self.assertEqual(result['buttons_in_template'][0]['text'], 'Run anyway')
        self.assertNotIn('never execute', json.dumps(result))
        self.assertNotIn('enabled', result['buttons_in_template'][0])

    def test_absent_html(self):
        self.assertEqual(summarize_presentation({'rating': 'allow'}), {'present': False})

    def test_saved_live_shell_controls_if_available(self):
        root = Path(__file__).resolve().parents[1] / 'analysis/api_expansion'
        if not (root / 'shell_baseline.response.json').exists():
            self.skipTest('Saved live evidence is not installed')
        good = json.loads((root / 'shell_baseline.response.json').read_text())['response']
        unknown = json.loads((root / 'shell_unknown.response.json').read_text())['response']
        self.assertEqual(good['$type'], 'allow')
        self.assertEqual(unknown['$type'], 'block')
        self.assertEqual(unknown['rating'], 'UNKN:100')
        self.assertTrue(summarize_presentation(unknown)['present'])


if __name__ == '__main__':
    unittest.main()

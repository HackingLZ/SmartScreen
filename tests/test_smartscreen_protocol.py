"""Protocol interpretation and capture-correlation regression tests."""
import copy
import json
from pathlib import Path
import unittest

from smartscreen.protocol import (correlate_contexts, describe_context,
                                 inspect_protocol, protocol_catalog)


CONTEXT = '1;11111111-2222-3333-4444-555555555555;PHSH:100;1'


def transaction(identifier, response=None, events=None, complete=True):
    return {'id': identifier,
            'request': {'body': {'complete': complete, 'json': {'events': events} if events is not None else {}}},
            'response': {'body': {'complete': complete, 'json': response}}}


class ProtocolInspectionTests(unittest.TestCase):
    def test_rating_does_not_become_decision_or_confidence(self):
        result = inspect_protocol({'rating': 'UNKN:100'})
        self.assertIsNone(result['decision'])
        self.assertEqual(result['rating'], 'UNKN:100')
        self.assertNotIn('confidence', result)
        self.assertEqual(inspect_protocol({'result': {'rating': 'MALW:090'}})['rating'], 'MALW:090')

    def test_nested_decision_is_preserved_even_when_category_allowed(self):
        result = inspect_protocol({'result': {'$type': 'evaluate', 'responseCategory': 'Allowed'}, 'serverContext': CONTEXT})
        self.assertEqual(result['decision'], 'evaluate')
        self.assertEqual(result['decision_source'], 'result.$type')
        self.assertEqual(result['response_category'], 'Allowed')
        self.assertNotIn(CONTEXT, json.dumps(result))

    def test_error_status_and_304_do_not_produce_decisions(self):
        for status in (304, 401, 500, '200'):
            result = inspect_protocol({'http_status': status, 'response': {'$type': 'block'}})
            self.assertIsNone(result['decision'])
        self.assertIsNone(inspect_protocol({'http_status': 200, 'response': None})['decision'])

    def test_context_shape_and_explicit_raw_opt_in(self):
        a = describe_context(CONTEXT)
        self.assertEqual(a['semicolon_field_count'], 4)
        self.assertNotIn('raw', a)
        self.assertEqual(describe_context(CONTEXT, include_sensitive=True)['raw'], CONTEXT)
        self.assertFalse(describe_context({})['valid_string'])
        with self.assertRaises(ValueError):
            describe_context('x' * 65537)

    def test_telemetry_omits_identity_credentials_and_urls_by_default(self):
        payload = {'identity': {'onlineIdTicket': 'SECRET'}, 'samplingRates': {'serverCall': 1.0, 'bad': 4},
                   'events': [{'$type': 'serverCall', 'telemetry': CONTEXT},
                              {'$type': 'lookup', 'destination': {'uri': 'https://private.example/path'}},
                              {'$type': 'userAction', 'action': 'navigateAway', 'target': 'https://target.example/'}]}
        before = copy.deepcopy(payload)
        result = inspect_protocol(payload)
        self.assertEqual(result['event_type_counts']['serverCall'], 1)
        self.assertEqual(result['sampling_rates'], {'serverCall': 1.0})
        for text in ['SECRET', 'private.example', 'target.example', CONTEXT]:
            self.assertNotIn(text, json.dumps(result))
        included = inspect_protocol(payload, include_sensitive=True)
        self.assertIn('private.example', json.dumps(included))
        self.assertNotIn('SECRET', json.dumps(included))
        self.assertEqual(payload, before)

    def test_reports_are_bounded_and_malformed_events_remain_visible(self):
        events = [{'$type': 'type' + str(i)} for i in range(100)] + [None]
        result = inspect_protocol({'events': events}, limit=2)
        self.assertEqual(result['event_count'], 101)
        self.assertEqual(len(result['events']), 2)
        self.assertEqual(result['events_omitted'], 99)
        self.assertLessEqual(len(result['event_type_counts']), 64)
        self.assertEqual(inspect_protocol({'events': [None]})['events'][0]['valid_object'], False)

    def test_scareware_schema_is_stringified_and_static_only(self):
        payload = {'data': [{'name': 'scareware', 'featureData': json.dumps({'verdict': 'block', 'url': 'https://test.example/'})}]}
        result = inspect_protocol(payload)
        self.assertEqual(result['event_name'], 'evaluateModel')
        self.assertEqual(result['validation'], 'native_static_only')
        self.assertEqual(result['items'][0]['verdict'], 'block')
        self.assertTrue(result['items'][0]['url_present'])
        self.assertNotIn('test.example', json.dumps(result))
        payload['data'][0]['featureData'] = {'verdict': 'block'}
        self.assertFalse(inspect_protocol(payload)['items'][0]['feature_data_is_string'])
        self.assertEqual(inspect_protocol({'data': []})['kind'], 'response')

    def test_duplicate_contexts_are_not_assigned_unique_requests(self):
        response = {'serverContext': CONTEXT, 'result': {'serverContext': CONTEXT, '$type': 'block'}}
        data = {'transactions': [transaction('a', response), transaction('b', response),
                                 transaction('t', events=[{'$type': 'serverCall', 'telemetry': CONTEXT}]),
                                 transaction('incomplete', {'serverContext': 'other'}, complete=False)]}
        result = correlate_contexts(data)
        self.assertEqual(result['response_context_count'], 4)
        self.assertEqual(result['distinct_response_context_count'], 1)
        self.assertEqual(result['matched_server_call_event_count'], 1)
        self.assertEqual(result['correlations'][0]['matching_response_count'], 4)
        self.assertEqual({r['transaction_id'] for r in result['correlations'][0]['matching_responses']}, {'a', 'b'})

    def test_correlation_requires_complete_bodies_and_bounds_total_sources(self):
        response = {'serverContext': CONTEXT}
        events = [{'$type': 'serverCall', 'telemetry': CONTEXT}] * 6
        data = {'transactions': [transaction(str(i), response) for i in range(6)] + [transaction('t', events=events)]}
        result = correlate_contexts(data, limit=2)
        self.assertEqual(result['matched_server_call_event_count'], 6)
        self.assertEqual(sum(len(row['matching_responses']) for row in result['correlations']), 2)
        data['transactions'][-1]['request']['body']['complete'] = False
        self.assertEqual(correlate_contexts(data)['server_call_event_count'], 0)

    def test_invalid_and_excessively_nested_documents_fail_cleanly(self):
        for value in [None, [], b'nope', {'events': None}, {'x': float('nan')}, {'x': object()}]:
            with self.subTest(value=str(value)[:80]), self.assertRaises(ValueError):
                inspect_protocol(value)
        nested = {}; nested['cycle'] = nested
        with self.assertRaises(ValueError):
            inspect_protocol(nested)
        for limit in (-1, 1001, True):
            with self.assertRaises(ValueError):
                inspect_protocol({}, limit=limit)

    def test_catalog_copies_and_no_unverified_download_or_reporting_claims(self):
        catalog = protocol_catalog()
        bloom = next(x for x in catalog if x['name'] == 'customBloom-get')
        self.assertEqual(bloom['validation'], 'live_304_without_base')
        self.assertIsNone(next(x for x in catalog if x['name'] == 'scareware-event')['network_endpoint'])
        catalog[0]['required_headers']['If-None-Match'] = 'changed'
        self.assertNotEqual(protocol_catalog()[0]['required_headers']['If-None-Match'], 'changed')

    def test_real_native_capture_context_reuse(self):
        path = Path(__file__).resolve().parents[1] / 'analysis/native_browser/parsed_final.json'
        if not path.exists():
            self.skipTest('Local native capture not distributed')
        result = correlate_contexts(path.read_bytes())
        self.assertEqual(result['server_call_event_count'], 4)
        self.assertEqual(result['matched_server_call_event_count'], 4)
        self.assertGreater(result['response_context_count'], result['distinct_response_context_count'])


if __name__ == '__main__':
    unittest.main()

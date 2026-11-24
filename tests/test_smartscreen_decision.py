import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from smartscreen.decision import (
    ARRAY_SIGNALS, CONTEXT_FIELDS, REQUIRED_CONTEXT_FIELDS, STRING_SIGNALS,
    explain_url, navigationcomplete_payload,
)


def context():
    return {'userAgent': 'Explicit test client',
            'correlationId': 'c966c8f0-5c24-4e75-a0ef-befc930288d6',
            'identity': {'client': {'version': 'test'}}, 'config': {'test': True},
            'destination': {'uri': 'https://example.com/', 'ip': None},
            'referrer': {'uri': '', 'ip': None}, 'type': 'top',
            'synchronous': True, 'forceServiceDetermination': True}


def response(kind='allow', category='Allowed', status=200):
    return {'http_status': status,
            'response': {'result': {'$type': kind, 'responseCategory': category},
                         'actions': [{'$type': 'cache', 'result': 'call_server'}]}}


class NavigationCompleteTests(unittest.TestCase):
    def test_explicit_context_and_exact_serializer_nulls(self):
        original = context()
        signals = {'title': 'Example documentation', 'certSubjectOrganizationNames': ['Example']}
        result = navigationcomplete_payload(original, [{'name': 'test-model', 'score': 1}], signals)
        self.assertEqual(set(result), set(CONTEXT_FIELDS) | {'models', 'signals'})
        self.assertEqual(result['models'], [{'name': 'test-model', 'score': 1.0}])
        self.assertIsNone(result['signals']['faviconUrl'])
        self.assertIsNone(result['signals']['certIssuerOrganizationNames'])
        self.assertEqual(result['signals']['redirectChain'], [])
        self.assertEqual(result['signals']['enhancedRedirectChain'], {})
        self.assertEqual(set(result['signals']), set(STRING_SIGNALS) | set(ARRAY_SIGNALS) |
                         {'redirectChain', 'enhancedRedirectChain'})
        result['identity']['client']['version'] = 'changed'
        result['signals']['certSubjectOrganizationNames'].append('Changed')
        self.assertEqual(original['identity']['client']['version'], 'test')
        self.assertEqual(signals['certSubjectOrganizationNames'], ['Example'])
        json.dumps(result, allow_nan=False)

    def test_absent_signal_object_is_null_and_server_context_optional(self):
        result = navigationcomplete_payload(context(), [], None)
        self.assertIsNone(result['signals'])
        self.assertNotIn('serverContext', result)
        ctx = context()
        ctx['serverContext'] = 'opaque prior response'
        self.assertNotIn('serverContext', navigationcomplete_payload(ctx, [], None))
        self.assertEqual(navigationcomplete_payload(ctx, [], None, server_context='override')['serverContext'], 'override')

    def test_required_context_is_not_invented(self):
        for key in REQUIRED_CONTEXT_FIELDS:
            ctx = context()
            del ctx[key]
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'Missing explicit'):
                navigationcomplete_payload(ctx, [], None)
        for key, value in [('correlationId', 'not-a-uuid'), ('type', 'download'),
                           ('identity', None), ('config', []), ('userAgent', None)]:
            ctx = context()
            ctx[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                navigationcomplete_payload(ctx, [], None)

    def test_captured_native_empty_context_fields_and_rich_signals(self):
        ctx = context()
        ctx['userAgent'] = ''
        ctx['correlationId'] = '00000000-0000-0000-0000-000000000000'
        del ctx['config']
        del ctx['referrer']
        signals = {'title': 'Windows Security Alert', 'enhancedRedirectChain': {
            'redirectSource': None, 'referrerChain': [{'url': 'https://example.com/',
                'navigationInitiation': 1, 'referrerUrl': '', 'type': 1,
                'navigationTimeMsec': 1795478450847.0, 'isRetargeting': False,
                'ipAddresses': [], 'serverRedirectChainByEntry': []}]}}
        result = navigationcomplete_payload(ctx, [{'name': 'techScamTitleModel:2019-10-07',
                                                   'score': 16.3673437735292}], signals)
        self.assertEqual(result['userAgent'], '')
        self.assertEqual(result['referrer'], {})
        self.assertNotIn('config', result)
        self.assertNotIn('serverContext', result)
        self.assertEqual(result['signals']['enhancedRedirectChain'], signals['enhancedRedirectChain'])
        result['signals']['enhancedRedirectChain']['referrerChain'][0]['url'] = 'changed'
        self.assertEqual(signals['enhancedRedirectChain']['referrerChain'][0]['url'], 'https://example.com/')

    def test_sanitized_native_http_redirect_and_https_followups_roundtrip(self):
        directory = Path(__file__).resolve().parents[1] / 'tests/fixtures/navigation'
        for name in ('followup_http_title.json', 'followup_http_redirect.json',
                     'followup_https_title_instrumented.json'):
            fixture = json.loads((directory / name).read_text())
            original = fixture['request']['json']
            with self.subTest(fixture=name):
                actual = navigationcomplete_payload(original, original['models'], original['signals'])
                self.assertEqual(actual, original)
                self.assertEqual(fixture['response']['http_status'], 200)
                self.assertEqual(fixture['response']['json']['result']['$type'], 'allow')
                self.assertNotIn('onlineIdTicket', original['identity']['device'])

    def test_rich_redirect_shape_and_coupling_validation(self):
        directory = Path(__file__).resolve().parents[1] / 'tests/fixtures/navigation'
        fixture = json.loads((directory / 'followup_http_redirect.json').read_text())['request']['json']
        mutations = [
            lambda s: s['enhancedRedirectChain']['referrerChain'][0].update(navigationInitiation=2),
            lambda s: s['enhancedRedirectChain']['referrerChain'][0].update(ipAddresses=['not-an-ip']),
            lambda s: s['enhancedRedirectChain']['referrerChain'][0].update(serverRedirectChainByEntry=[]),
            lambda s: s['enhancedRedirectChain']['referrerChain'][0].update(navigationTimeMsec=float('inf')),
            lambda s: s['enhancedRedirectChain'].update(redirectSource='unvalidated'),
        ]
        for mutation in mutations:
            signals = copy.deepcopy(fixture['signals'])
            mutation(signals)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                navigationcomplete_payload(fixture, fixture['models'], signals)

    def test_navigation_context_must_be_serialized_supported_url(self):
        for value in [{'uri': 'https://example.com/'}, {'uri': '', 'ip': None},
                      {'uri': 'https://例え.test/', 'ip': None},
                      {'uri': 'https://example.com/', 'ip': 4}]:
            ctx = context()
            ctx['destination'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                navigationcomplete_payload(ctx, [], None)

    def test_bad_scores_and_ambiguous_models_rejected(self):
        for score in [True, '1', None, float('nan'), float('inf'), 10 ** 400]:
            with self.subTest(score_type=type(score)), self.assertRaises(ValueError):
                navigationcomplete_payload(context(), [{'name': 'model', 'score': score}], None)
        for model in [{'score': 1}, {'name': '', 'score': 1},
                      {'name': 'model', 'score': 1, 'isTest': True}]:
            with self.subTest(model=model), self.assertRaises(ValueError):
                navigationcomplete_payload(context(), [model], None)

    def test_unknown_signals_and_unvalidated_rich_redirects_rejected(self):
        bad = [{'unknown': 1}, {1: 'title'}, {'title': []}, {'certIssuerDomainComponents': 'example'},
               {'certSubjectOrganizationNames': [None]}, {'redirectChain': None},
               {'redirectChain': [{'uri': 'https://example.com/'}]},
               {'enhancedRedirectChain': {'redirectSource': None}}]
        for signals in bad:
            with self.subTest(signals=signals), self.assertRaises(ValueError):
                navigationcomplete_payload(context(), [], signals)


class DecisionEvidenceTests(unittest.TestCase):
    def test_no_observations_does_not_predict_a_verdict(self):
        report = explain_url('https://example.com/')
        self.assertEqual(report['network_requests'], 0)
        self.assertFalse(report['is_execution_trace'])
        self.assertFalse(report['is_complete_blocklist'])
        self.assertEqual(report['final_enforcement'], 'unknown')
        self.assertTrue(all(stage['executed_in_browser'] == 'unknown' for stage in report['stages']))
        names = [stage['stage'] for stage in report['stages']]
        self.assertLess(names.index('top_traffic'), names.index('uri_routing_cache'))
        self.assertLess(names.index('cloud_actions'), names.index('cloud_result'))
        browser = report['stages'][-1]
        self.assertTrue(browser['observations']['blocking_page_boundary_statically_traced'])
        self.assertEqual(browser['observations']['runtime_gates'], 'unknown')
        self.assertEqual(browser['observations']['enforcement'], 'unknown')

    def test_snapshot_membership_is_observation_only(self):
        snapshot = {'datasets': [{'id': 'topTraffic', 'state': 'analyzed', 'membership': True},
                                 {'id': 'synchronousLookupUris', 'state': 'analyzed', 'membership': True},
                                 {'id': 'customSynchronousLookupUris', 'state': 'not_applicable', 'membership': False}]}
        with patch('smartscreen.decision.analyze_url', return_value=snapshot) as analyze:
            report = explain_url('https://example.com/', feeds='saved')
        analyze.assert_called_once_with('https://example.com/', 'saved', None)
        stages = {stage['stage']: stage for stage in report['stages']}
        self.assertTrue(stages['top_traffic']['observations']['snapshot_membership'])
        self.assertIsNone(stages['synchronous_lookup_filter']['observations']['custom_bloom_snapshot_membership'])
        self.assertEqual(report['final_enforcement'], 'unknown')

    def test_http_failure_and_other_2xx_never_become_allow(self):
        for status in [503, 429, 201, None, '200', True]:
            report = explain_url('https://example.com/', cloud_response=response(status=status))
            cloud = report['cloud_response']
            with self.subTest(status=status):
                self.assertEqual(cloud['state'], 'http_failure_or_unvalidated_status')
                self.assertIsNone(cloud['result_type'])
                self.assertEqual(cloud['actions'], [])
                self.assertEqual(report['final_enforcement'], 'unknown')

    def test_recognized_cloud_result_and_cache_action_are_distinct(self):
        original = response('warn', 'Phishing')
        report = explain_url('https://example.com/', cloud_response=original)
        cloud = report['cloud_response']
        self.assertEqual(cloud['state'], 'recognized_native_result_fields')
        self.assertFalse(cloud['full_native_parse_validated'])
        self.assertEqual(cloud['result_type'], 'warn')
        self.assertEqual(cloud['binding_to_input_url'], 'not_verified')
        self.assertEqual(cloud['actions'][0]['role'], 'routing_cache_update')
        self.assertFalse(cloud['actions'][0]['is_verdict'])
        self.assertEqual(cloud['supplied_response'], original)
        cloud['supplied_response']['response']['result']['$type'] = 'changed'
        self.assertEqual(original['response']['result']['$type'], 'warn')

    def test_unrecognized_or_raw_result_keeps_uncertainty(self):
        for kind, category in [('weird', 'Allowed'), ('allow', 'Other'), ([], 'Allowed'), ('allow', {})]:
            report = explain_url('https://example.com/', cloud_response=response(kind, category))
            self.assertEqual(report['cloud_response']['state'], 'unrecognized_result_or_category')
            self.assertNotIn('native_dispatch', report['cloud_response'])
        raw = response()['response']
        self.assertEqual(explain_url('https://example.com/', cloud_response=raw)['cloud_response']['state'],
                         'recognized_fields_without_transport_proof')
        self.assertEqual(explain_url('https://example.com/', cloud_response={'http_status': 200})['cloud_response']['state'],
                         'invalid_or_missing_response_object')

    def test_cache_only_hit_routes_and_wrong_url_rejected(self):
        for state in ['hit', 'expired', 'miss', 'unknown', 'no_cache']:
            cache = {'state': state, 'routing_action': 'allow', 'input_url': 'https://example.com/'}
            report = explain_url('https://example.com/', cache_observation=cache)
            stage = next(x for x in report['stages'] if x['stage'] == 'uri_routing_cache')
            self.assertEqual(stage['observations']['routing_action_if_reached'], 'allow' if state == 'hit' else None)
            self.assertEqual(report['final_enforcement'], 'unknown')
        for cache in [{'result': 1}, {'state': 'hit', 'routing_action': 'block'},
                      {'state': 'hit', 'routing_action': 'allow', 'input_url': 'https://other.example/'}]:
            with self.subTest(cache=cache), self.assertRaises(ValueError):
                explain_url('https://example.com/', cache_observation=cache)

    def test_title_model_positive_is_not_enforcement(self):
        settings = {'models': [{'name': 'test-model', 'bias': 1, 'samplingRate': 0.5,
                               'terms': [{'features': ['title'], 'delimiters': ' ', 'tokenWeights': []}]}]}
        report = explain_url('https://example.com/', title='Example documentation', settings=settings)
        stage = next(x for x in report['stages'] if x['stage'] == 'title_and_other_models')
        self.assertTrue(stage['observations']['title_score']['raw_score_positive'])
        self.assertFalse(stage['observations']['title_score']['is_verdict'])
        self.assertEqual(stage['observations']['sampling'], 'not_simulated')
        self.assertEqual(report['final_enforcement'], 'unknown')
        settings['models'].append(copy.deepcopy(settings['models'][0]))
        settings['models'][1]['name'] = 'other'
        self.assertEqual(explain_url('https://example.com/', title='Example', settings=settings,
                                     model_name='other')['final_enforcement'], 'unknown')

    def test_incomplete_inputs_fail_before_reading_feeds(self):
        for kwargs in [{'title': 'Example'}, {'settings': {}}, {'model_name': 'model'},
                       {'defaults': 'defaults'}, {'navigation_type': 'bad'}]:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                explain_url('https://example.com/', **kwargs)
        with self.assertRaises(ValueError):
            explain_url('https://例え.test/')


if __name__ == '__main__':
    unittest.main()

import copy
import hashlib
import json
import unittest
from pathlib import Path

from smartscreen.model import inspect_models, lookup_token, native_token_hash, score_title, MAX_TITLE_BYTES


WINDOWS_HASH = '0f4137ed1502b5045d6083aa258b5c42'
WELCOME_HASH = '40be4e59b9a2a2b5dffb918c0e86b3d7'


def fixture():
    return {'geoidMaps': {'example': 'https://example.invalid/'}, 'sampleBuckets': {'error': 1.0},
            'models': [{'name': 'example-title', 'bias': -2.0, 'samplingRate': 0.001,
                        'terms': [{'features': ['title'], 'delimiters': ' |', 'lengthWeight': -0.2,
                                   'tokenWeights': [{'key': WINDOWS_HASH, 'value': 4.5},
                                                    {'key': WELCOME_HASH, 'value': -0.3}]}]}]}


class ModelTests(unittest.TestCase):
    def test_native_ascii_hash_known_vectors(self):
        self.assertEqual(native_token_hash('WiNdOwS'), WINDOWS_HASH)
        self.assertEqual(native_token_hash('WELCOME'), WELCOME_HASH)
        self.assertEqual(native_token_hash(''), 'd41d8cd98f00b204e9800998ecf8427e')
        self.assertNotEqual(native_token_hash(' windows'), WINDOWS_HASH)

    def test_non_ascii_not_silently_unicode_casefolded(self):
        self.assertEqual(native_token_hash('WİNDOWS'), hashlib.md5('wİndows'.encode()).hexdigest())
        self.assertNotEqual(native_token_hash('ÉCOLE'), native_token_hash('école'))
        self.assertNotEqual(native_token_hash('é'), native_token_hash('e\u0301'))
        result = lookup_token(fixture(), 'ÉCOLE')
        self.assertEqual(result['normalized_candidate'], 'École')
        with self.assertRaises(ValueError):
            native_token_hash(b'windows')
        with self.assertRaisesRegex(ValueError, 'surrogates'):
            native_token_hash('\ud800')

    def test_inspection_exact_metadata_and_full_export(self):
        source = fixture()
        result = inspect_models(json.dumps(source).encode(), include_weights=True)
        self.assertEqual(result['document'], source)
        self.assertEqual(result['settings_metadata']['sampleBuckets'], {'error': 1.0})
        term = result['models'][0]['terms'][0]
        self.assertEqual(term['weights']['count'], 2)
        self.assertEqual(term['weights']['key_length_counts'], {32: 2})
        self.assertTrue(term['weights']['all_keys_lowercase_hex32'])
        self.assertEqual(term['weights']['minimum'], -0.3)
        self.assertTrue(result['models'][0]['scoring_supported'])
        result['document']['models'][0]['terms'][0]['tokenWeights'][0]['value'] = 99
        self.assertEqual(source['models'][0]['terms'][0]['tokenWeights'][0]['value'], 4.5)

    def test_match_is_weight_not_verdict_and_no_match_not_safe(self):
        result = lookup_token(fixture(), 'WINDOWS')
        self.assertEqual(result['match_count'], 1)
        self.assertEqual(result['matches'][0]['weight'], 4.5)
        self.assertEqual(result['matches'][0]['term_index'], 0)
        self.assertEqual(result['normalized_candidate'], 'windows')
        self.assertFalse(result['is_verdict'])
        missing = lookup_token(fixture(), 'unseen')
        self.assertEqual(missing['matches'], [])
        self.assertFalse(missing['is_verdict'])
        self.assertNotIn('verdict', missing)
        self.assertNotIn('score', missing)

    def test_legacy_hash_remains_unconfirmed(self):
        source = {'models': [{'name': 'legacy', 'bias': 0, 'features': ['title'],
                              'weights': [{'key': WINDOWS_HASH, 'value': 1}]}]}
        self.assertIn('Unconfirmed', lookup_token(source, 'windows')['hash_scope'])
        result = inspect_models(source)
        self.assertIn('require terms', result['models'][0]['native_compatibility'])
        self.assertIn('MissingTerms', result['models'][0]['native_compatibility'])
        self.assertEqual(result['models'][0]['native_parser_addresses']['edge_158'], '0x18775de48')
        self.assertFalse(result['models'][0]['scoring_supported'])

    def test_duplicates_retained_not_overwritten(self):
        source = fixture()
        source['models'][0]['terms'][0]['tokenWeights'].append({'key': WINDOWS_HASH, 'value': 8})
        result = inspect_models(source)
        self.assertEqual(result['models'][0]['terms'][0]['weights']['duplicate_key_count'], 1)
        self.assertEqual([x['weight'] for x in lookup_token(source, 'windows')['matches']], [4.5, 8])

    def test_model_selection_and_multi_term_matches(self):
        source = fixture()
        source['models'][0]['terms'].append(copy.deepcopy(source['models'][0]['terms'][0]))
        source['models'].append(copy.deepcopy(source['models'][0]))
        source['models'][1]['name'] = 'another'
        with self.assertRaises(ValueError):
            lookup_token(source, 'windows')
        with self.assertRaises(ValueError):
            lookup_token(source, 'windows', 'missing')
        result = lookup_token(source, 'windows', 'another')
        self.assertEqual([x['term_index'] for x in result['matches']], [0, 1])

    def test_semantic_document_identity_ignores_json_spacing(self):
        source = fixture()
        before = inspect_models(source)['document_semantic_sha256']
        after = inspect_models(json.dumps(source, indent=4, sort_keys=True))['document_semantic_sha256']
        self.assertEqual(before, after)
        source['models'][0]['bias'] = -3
        self.assertNotEqual(before, inspect_models(source)['document_semantic_sha256'])

    def test_reject_malformed_or_ambiguous_data(self):
        bad = [b'\xff', '{', {}, {'models': None}, {'models': [None]}]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(ValueError):
                inspect_models(value)
        for field, value in [('bias', float('nan')), ('bias', True), ('terms', {})]:
            source = fixture()
            source['models'][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                inspect_models(source)
        for field, value in [('features', 'title'), ('delimiters', []), ('lengthWeight', False),
                             ('logLengthWeights', {}), ('useDistinctTokens', 1),
                             ('tokenWeights', [{'key': 'abc', 'value': float('inf')}])]:
            source = fixture()
            source['models'][0]['terms'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                inspect_models(source)
        source = fixture()
        source['models'][0]['weights'] = []
        with self.assertRaisesRegex(ValueError, 'mixes'):
            inspect_models(source)

    def test_saved_v2_response_candidate(self):
        path = Path(__file__).resolve().parents[1] / 'analysis/model_expansion/settings_v2_initial.bin'
        if not path.exists():
            self.skipTest('Optional saved live response absent')
        document = path.read_bytes()
        result = inspect_models(document)
        model = result['models'][0]
        self.assertEqual(model['name'], 'techScamTitleModel:2019-10-07')
        self.assertEqual(model['terms'][0]['weights']['count'], 981)
        self.assertEqual(lookup_token(document, 'Windows')['matches'][0]['weight'], 4.57597838745397)
        self.assertEqual(lookup_token(document, 'Welcome')['matches'][0]['weight'], -0.358078470242815)

    def test_score_default_distinct_and_explicit_repetition(self):
        source = fixture()
        source['models'][0]['terms'][0].pop('lengthWeight')
        repeated = score_title(source, 'WINDOWS windows')
        self.assertEqual(repeated['raw_score'], 2.5)
        self.assertEqual([token['applied'] for token in repeated['terms'][0]['tokens']], [True, False])
        self.assertFalse(repeated['is_verdict'])
        self.assertTrue(repeated['raw_score_positive'])
        source['models'][0]['terms'][0]['useDistinctTokens'] = False
        self.assertEqual(score_title(source, 'WINDOWS windows')['raw_score'], 7.0)

    def test_score_empty_tokens_and_no_final_empty_tail(self):
        source = fixture()
        term = source['models'][0]['terms'][0]
        term.pop('lengthWeight')
        term['tokenWeights'].append({'key': 'd41d8cd98f00b204e9800998ecf8427e', 'value': 0.5})
        result = score_title(source, '  WINDOWS ')
        self.assertEqual([token['text'] for token in result['terms'][0]['tokens']], ['', '', 'WINDOWS'])
        self.assertEqual(result['raw_score'], 3.0)
        self.assertEqual(score_title(source, '')['raw_score'], -2.0)
        self.assertEqual(score_title(source, ' ')['raw_score'], -1.5)

    def test_logarithmic_length_counts_only_ascii_letters(self):
        source = fixture()
        term = source['models'][0]['terms'][0]
        term.pop('lengthWeight')
        term['tokenWeights'] = []
        term['logLengthWeights'] = [10, 20, 30, 40]
        self.assertEqual(score_title(source, '12!?')['raw_score'], -2.0)
        self.assertEqual(score_title(source, 'A12 B!')['raw_score'], 28.0)
        result = score_title(source, 'Abc123')
        self.assertEqual(result['terms'][0]['log_length_index'], 2)
        self.assertEqual(result['raw_score'], 28.0)
        self.assertEqual(score_title(source, 'A' * 100)['raw_score'], 38.0)

    def test_zero_score_is_not_positive_and_sampling_does_not_change_score(self):
        source = fixture()
        term = source['models'][0]['terms'][0]
        term.pop('lengthWeight')
        source['models'][0]['bias'] = -4.5
        source['models'][0]['samplingRate'] = 1.0
        result = score_title(source, 'Windows')
        self.assertEqual(result['raw_score'], 0.0)
        self.assertFalse(result['raw_score_positive'])
        self.assertEqual(result['sampling_rate'], 1.0)
        self.assertNotIn('selected', result)
        self.assertNotIn('blocked', result)

    def test_scorer_rejects_unvalidated_shapes_and_numeric_overflow(self):
        for field, value in [('features', ['url']), ('features', ['title', 'title']),
                             ('delimiters', '\u2003')]:
            source = fixture()
            source['models'][0]['terms'][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                score_title(source, 'Windows')
        for title in ['\ud800', 'x' * (MAX_TITLE_BYTES + 1), '😀' * (MAX_TITLE_BYTES // 4 + 1), None]:
            with self.subTest(title_length=len(title) if isinstance(title, str) else None), self.assertRaises(ValueError):
                score_title(fixture(), title)
        source = fixture()
        source['models'][0]['bias'] = 10 ** 400
        self.assertEqual(inspect_models(source)['models'][0]['bias'], 10 ** 400)
        self.assertFalse(inspect_models(source)['models'][0]['scoring_supported'])
        with self.assertRaisesRegex(ValueError, 'binary64'):
            score_title(source, 'Windows')
        source = fixture()
        source['models'][0]['terms'][0]['lengthWeight'] = 1e308
        with self.assertRaisesRegex(ValueError, 'non-finite'):
            score_title(source, 'Windows')

    def test_unicode_byte_length_ascii_alpha_and_literal_separators(self):
        source = fixture()
        term = source['models'][0]['terms'][0]
        term['lengthWeight'] = 0.5
        term['tokenWeights'] = []
        term['logLengthWeights'] = [10, 20, 30, 40]
        result = score_title(source, 'AéZ😀中')
        self.assertEqual(result['terms'][0]['byte_length'], 11)
        self.assertEqual(result['terms'][0]['alphabetic_count'], 2)
        self.assertEqual(result['raw_score'], -2 + 5.5 + 30)
        self.assertEqual(result['terms'][0]['tokens'][0]['normalized'], 'aéz😀中')
        tokens = score_title(source, 'x\u00a0y\u2003z ÉCOLE')['terms'][0]['tokens']
        self.assertEqual([x['text'] for x in tokens], ['x\u00a0y\u2003z', 'ÉCOLE'])
        self.assertFalse(result['is_verdict'])

    def test_saved_native_unicode_score_oracle(self):
        base = Path(__file__).resolve().parents[1] / 'analysis/model_completion'
        if not (base / 'native_unicode_scores.json').exists():
            self.skipTest('Optional native Unicode fixture absent')
        cases = json.loads((base / 'unicode_cases.json').read_text())['cases']
        native = {case['name']: case for case in json.loads((base / 'native_unicode_scores.json').read_text())['cases']}
        for case in cases:
            terms = []
            for term in case['terms']:
                item = {key: value for key, value in term.items() if key != 'weights'}
                item['features'] = ['title']
                item['tokenWeights'] = [{'key': key, 'value': value} for key, value in term.get('weights', {}).items()]
                terms.append(item)
            document = {'models': [{'name': case['name'], 'bias': case['bias'], 'terms': terms}]}
            with self.subTest(name=case['name']):
                self.assertNotIn('error', native[case['name']])
                result = score_title(document, case['title'])
                self.assertEqual(result['raw_score'], native[case['name']]['native_score'])
                self.assertEqual([token['text'] for term in result['terms'] for token in term['tokens']],
                                 native[case['name']]['native_tokens'])

    def test_saved_browser_unicode_score_oracle(self):
        root = Path(__file__).resolve().parents[1]
        report = root / 'analysis/model_completion/browser_comparison.json'
        if not report.exists():
            self.skipTest('Optional saved native browser comparison absent')
        evidence = json.loads(report.read_text())
        settings = (root / 'analysis/model_expansion/settings_v2_initial.bin').read_bytes()
        self.assertEqual(evidence['observed_case_count'], 6)
        self.assertEqual(evidence['missing_case_ids'], [])
        self.assertTrue(evidence['validation_passed'])
        self.assertEqual(evidence['settings_sha256'], hashlib.sha256(settings).hexdigest())
        for case in evidence['cases']:
            with self.subTest(case=case['case_id']):
                self.assertTrue(case['title_preserved'])
                for observed in case['observations']:
                    result = score_title(settings, observed['observed_title'], observed['model_name'])
                    self.assertEqual(result['raw_score'], observed['native_score'])
                    self.assertFalse(result['is_verdict'])

    def test_saved_native_score_oracle(self):
        base = Path(__file__).resolve().parents[1] / 'analysis/model_expansion'
        if not (base / 'native_scores.json').exists():
            self.skipTest('Optional saved native instruction-emulation fixture absent')
        cases = json.loads((base / 'score_cases.json').read_text())['cases']
        native = {case['name']: case for case in json.loads((base / 'native_scores.json').read_text())['cases']}
        for case in cases:
            terms = []
            for term in case['terms']:
                item = {key: value for key, value in term.items() if key != 'weights'}
                item['features'] = ['title']
                item['tokenWeights'] = [{'key': key, 'value': value} for key, value in term.get('weights', {}).items()]
                terms.append(item)
            document = {'models': [{'name': 'validation', 'bias': case.get('bias', 0), 'terms': terms}]}
            with self.subTest(case=case['name']):
                self.assertNotIn('error', native[case['name']])
                result = score_title(document, case['title'])
                self.assertEqual(result['raw_score'], native[case['name']]['native_score'])
                self.assertEqual([t['text'] for term in result['terms'] for t in term['tokens']],
                                 native[case['name']]['native_tokens'])


if __name__ == '__main__':
    unittest.main()

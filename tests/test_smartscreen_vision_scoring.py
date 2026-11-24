"""Native arithmetic probes and scoring/configuration boundary checks."""
from copy import deepcopy
import json
from pathlib import Path
import unittest

from smartscreen.vision_scoring import (analyze_embedding, f32, knn_scores,
                                       normalize_embedding, softmax_probabilities)

ROOT = Path(__file__).resolve().parents[1]


def label(name, scam, first):
    return {'name': name, 'is_scam': scam, 'vector': [first] + [0.0] * 511}


def pool(threshold=80):
    return {'scam_score_threshold': threshold,
            'text_tensors': [label('scam', True, 0.01), label('benign', False, 0.0)]}


def document(pools=None, consensus=0):
    return {'tensors': {'vti-b-p32-visual': [{'tensor_set_id': 1, 'consensus_threshold': consensus,
                                             'scam_score_to_use': 'softmax', 'label_pool': pools or [pool()]}]}}


class VisionScoringTests(unittest.TestCase):
    def test_original_arm64_arithmetic_probe_parity(self):
        observed = json.loads((ROOT / 'tests/fixtures/native/scoring_native.json').read_text())
        self.assertEqual(len(observed['cases']), 19)
        for row in observed['cases']:
            with self.subTest(row=row):
                self.assertNotIn('error', row)
                if row['kind'] == 'softmax':
                    self.assertEqual(softmax_probabilities(row['logits'], row['scale']), row['native_probabilities'])
                else:
                    result = knn_scores([0], [], [[value] for value in row['distances_fixture']], row['near_match_boost'])['knn2']
                    self.assertEqual(result['available'], row['native_available'])
                    if result['available']:
                        self.assertEqual(result['score'], row['native_score'])
                        self.assertEqual(result['near_match'], row['native_near_match'])

    def test_normalization_and_invalid_numeric_inputs(self):
        self.assertEqual(normalize_embedding([3, 4]), [f32(0.6), f32(0.8)])
        for invalid in ([0, 0], [float('nan'), 1], [float('inf')], [True], ['1'], [3e38]):
            with self.assertRaises(ValueError): normalize_embedding(invalid)
        with self.assertRaisesRegex(ValueError, 'dimension'):
            analyze_embedding([1, 0], document())
        with self.assertRaisesRegex(ValueError, 'overflows'):
            knn_scores([3e38], [[0]], [[0]] * 5)

    def test_softmax_integer_truncation_and_consensus_equality(self):
        result = analyze_embedding([1.0] + [0.0] * 511, document([pool(73), pool(74)], consensus=1), include_embedding=True)
        config = result['tensor_sets'][0]
        self.assertEqual([item['scores']['softmax']['score'] for item in config['pools']], [73, 73])
        self.assertEqual(config['classification'], 'scam')
        self.assertEqual(config['consensus']['softmax']['positive_pools'], 1)
        self.assertIsNone(result['browser_decision'])
        self.assertIsNone(result['cloud_verdict'])
        self.assertEqual(result['normalized_embedding'][0], 1.0)
        default = analyze_embedding([1.0] + [0.0] * 511, document([pool(73), pool(74)]))
        self.assertEqual(default['classification'], 'not_scam')

    def test_native_set_mode_gate_and_unknown_knn(self):
        data = document()
        config = data['tensors']['vti-b-p32-visual'][0]
        config['scam_score_to_use'] = 'knn2'
        self.assertEqual(analyze_embedding([1.0] + [0.0] * 511, data)['tensor_sets'][0]['selected_score'], 'softmax')
        config['knn_data'] = {}
        result = analyze_embedding([1.0] + [0.0] * 511, data)
        self.assertEqual(result['tensor_sets'][0]['selected_score'], 'knn2')
        self.assertEqual(result['classification'], 'unknown')

    def test_knn_top_five_votes_and_mixed_tie_unknown(self):
        votes = knn_scores([0], [[0.02], [0.04]], [[0.01], [0.03], [0.05], [0.2], [0.3]], False)
        self.assertEqual(votes['knn']['score'], 60)
        self.assertEqual(votes['knn2']['score'], 60)
        tied = knn_scores([0], [[0.01], [0.05]], [[0.02], [0.03], [0.04], [0.05], [0.5]], False)
        self.assertFalse(tied['knn']['available'])
        self.assertIn('tie', tied['knn']['reason'])

    def test_knn_near_match_consistency_failure_is_unknown(self):
        scores = knn_scores([0], [[0.0]] * 5, [[0.009]] * 5, True)
        self.assertFalse(scores['knn']['available'])
        self.assertFalse(scores['knn2']['available'])
        self.assertIn('consistency', scores['knn']['reason'])

    def test_signed_vector_document_schema_and_resolution_selection(self):
        path = ROOT / 'analysis/scareware_discovery/extracted/ProvenanceDataTensors/2026.2.23.1/provenance-data-vectors.json'
        if not path.exists(): self.skipTest('Signed vector artifact unavailable')
        result = analyze_embedding([1.0] + [0.0] * 511, json.loads(path.read_text()), image_size=(1920, 1080))
        self.assertEqual(len(result['tensor_sets']), 2)
        self.assertEqual(len(result['tensor_sets'][0]['pools']), 4)
        self.assertEqual(result['tensor_sets'][0]['consensus']['softmax']['required_pools'], 4)
        second = result['tensor_sets'][1]['pools'][0]
        self.assertEqual(second['dataset_selection']['index'], 1)
        self.assertEqual(second['dataset_selection']['distance'], 0.0)
        self.assertEqual(second['threshold'], 80)

    def test_malformed_config_fails_explicitly(self):
        data = document()
        bad = deepcopy(data)
        bad['tensors']['vti-b-p32-visual'][0]['label_pool'][0]['text_tensors'][0]['vector'] = [0]
        with self.assertRaises(ValueError): analyze_embedding([1.0] + [0.0] * 511, bad)
        with self.assertRaises(ValueError): analyze_embedding([1.0] + [0.0] * 511, data, selected_set_index=1)
        with self.assertRaises(ValueError): analyze_embedding([1.0] + [0.0] * 511, data, default_threshold=101)


if __name__ == '__main__':
    unittest.main()

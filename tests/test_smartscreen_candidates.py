import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from smartscreen.candidates import iter_candidates, map_candidates, map_candidate_file, map_candidate_files


class CandidateTests(unittest.TestCase):
    def test_real_toptraffic_vector_and_domain_forms(self):
        raw = bytes.fromhex('feb2133225a527f9f5fcc1355e1225f2')
        result = map_candidates(raw, ['GOOGLE.COM.', 'missing.example'], kind='topTraffic', domain_variants=True)
        self.assertEqual(result['matches'][0]['candidates'], ['www.google.com'])
        self.assertEqual(result['candidate_coverage_fraction'], 1)
        self.assertEqual(result['hash_attempts'], 4)
        self.assertFalse(result['complete_original_plaintext_recovery'])
        self.assertFalse(result['is_blocklist'])
        self.assertFalse(result['is_reputation_verdict'])

    def test_literal_keys_are_not_normalized(self):
        raw = bytes.fromhex('feb2133225a527f9f5fcc1355e1225f2')
        result = map_candidates(raw, ['WWW.GOOGLE.COM', 'www.google.com'], kind='topTraffic')
        self.assertEqual(result['matches'][0]['candidates'], ['www.google.com'])

    def test_duplicate_records_and_bounded_output_preserve_counts(self):
        record = bytes.fromhex('feb2133225a527f9f5fcc1355e1225f2')
        result = map_candidates(record * 2, ['www.google.com'] * 3, kind='topTraffic', limit=0)
        self.assertEqual(result['stored_record_count'], 2)
        self.assertEqual(result['unique_stored_hashes'], 1)
        self.assertEqual(result['matched_hash_count'], 1)
        self.assertTrue(result['matches_truncated'])
        self.assertEqual(result['matches'], [])

    def test_model_hashes_count_unique_normalized_candidates(self):
        raw = json.dumps({'models': [{'name': 'example', 'bias': 0, 'terms': [{
            'features': ['title'], 'delimiters': ' ', 'tokenWeights': [
                {'key': '0f4137ed1502b5045d6083aa258b5c42', 'value': 4.5}]}]}]}).encode()
        result = map_candidates(raw, ['Windows', 'WINDOWS', 'WİNDOWS', 'missing'], kind='model')
        self.assertEqual(result['matches'][0]['candidates'], ['windows'])
        self.assertEqual(result['unsupported_candidates_skipped'], 0)
        self.assertEqual(result['multiple_candidate_hash_count'], 0)
        self.assertEqual(result['matches'][0]['model_weights'][0]['weight'], 4.5)

    def test_model_unicode_association_preserves_native_byte_normalization(self):
        digest = hashlib.md5('École'.encode('utf-8')).hexdigest()
        raw = json.dumps({'models': [{'name': 'example', 'bias': 0, 'terms': [{
            'features': ['title'], 'delimiters': ' ',
            'tokenWeights': [{'key': digest, 'value': 0.5}]}]}]}).encode()
        result = map_candidates(raw, ['ÉCOLE', 'École', 'école', '\ud800'], kind='model')
        self.assertEqual(result['matches'][0]['candidates'], ['École'])
        self.assertEqual(result['hash_attempts'], 3)
        self.assertEqual(result['unsupported_candidates_skipped'], 1)
        self.assertIn('UTF-8 bytes with ASCII-only lowercase', result['hash_algorithm'])

    def test_legacy_and_bloom_are_not_labeled_recovered(self):
        raw = json.dumps({'models': [{'name': 'old', 'bias': 0, 'features': ['title'], 'weights': []}]}).encode()
        with self.assertRaisesRegex(ValueError, 'Legacy'):
            map_candidates(raw, ['a'], kind='model')
        with self.assertRaisesRegex(ValueError, 'Bloom'):
            map_candidates(b'', ['a'], kind='synchronousLookupUris')

    def test_empty_data_has_no_fabricated_coverage(self):
        result = map_candidates(b'', ['example.com'], kind='topTraffic')
        self.assertIsNone(result['candidate_coverage_fraction'])
        self.assertFalse(result['complete_original_plaintext_recovery'])

    def test_limit_failure_does_not_return_partial_report(self):
        with self.assertRaisesRegex(ValueError, 'no partial'):
            map_candidates(b'', ['a', 'b'], kind='topTraffic', max_candidates=1)
        for value in [True, -1, 10000001]:
            with self.assertRaises(ValueError):
                map_candidates(b'', [], kind='topTraffic', max_candidates=value)

    def test_ranked_domains_and_provenance(self):
        with tempfile.TemporaryDirectory() as root:
            candidates, dataset = Path(root) / 'names.csv', Path(root) / 'feed.bin'
            candidates.write_text('1,google.com\n2,example.com\n')
            dataset.write_bytes(bytes.fromhex('feb2133225a527f9f5fcc1355e1225f2'))
            result = map_candidate_file(dataset, candidates, kind='topTraffic', domain_variants=True, input_format='ranked-domains')
            self.assertEqual(result['candidate_source']['sha256'], hashlib.sha256(candidates.read_bytes()).hexdigest())
            self.assertEqual(result['matched_hash_count'], 1)
            candidates.write_text('not-ranked,example.com\n')
            with self.assertRaises(ValueError):
                list(iter_candidates(candidates, 'ranked-domains'))
            candidates.write_text('1,"unterminated\n')
            with self.assertRaisesRegex(ValueError, 'Malformed'):
                list(iter_candidates(candidates, 'ranked-domains'))

    def test_multiple_candidate_sources_union_without_double_count(self):
        with tempfile.TemporaryDirectory() as root:
            a, b, dataset = [Path(root) / name for name in ('a.txt', 'b.txt', 'data.bin')]
            a.write_text('google.com\n')
            b.write_text('www.google.com\nexample.com\n')
            dataset.write_bytes(bytes.fromhex('feb2133225a527f9f5fcc1355e1225f2'))
            result = map_candidate_files(dataset, [a, b], kind='topTraffic', domain_variants=True)
            self.assertEqual(result['input_candidates'], 3)
            self.assertEqual(result['matched_hash_count'], 1)
            self.assertEqual(len(result['candidate_sources']), 2)
            self.assertEqual(result['matches'][0]['candidates'], ['www.google.com'])

    def test_long_candidate_line_is_bounded(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'words'
            path.write_text('a' * 8193)
            with self.assertRaisesRegex(ValueError, '8192'):
                list(iter_candidates(path))


if __name__ == '__main__':
    unittest.main()

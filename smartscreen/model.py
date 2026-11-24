#!/usr/bin/env python3
"""Offline inspection of readable SmartScreen settings and hashed token weights.

The native term-model helper lowercases ASCII bytes and hashes UTF-8 tokens
with MD5 in the default C-runtime locale. It does not Unicode-casefold tokens.
This module does not reconstruct unknown words or claim a browser verdict.
"""
import argparse
import copy
import hashlib
import json
import math
import re
from collections import Counter
from pathlib import Path


NATIVE_DLL_SHA256 = '561e2abcd612a85ce3ae2be9fc978fd2809614120154350fbb02bdc19783204c'
EDGE_DLL_SHA256 = '788fe22e3a1a893f042a8bcdeef0765f0fd39c665d46de4f02c28bc5437f7173'
MAX_TITLE_BYTES = 16384  # Local tool resource bound, not a claimed native limit.
SCORING_LIMITATION = (
    'Offline scoring supports UTF-8 titles, ASCII delimiters and native title-only '
    'term models in the default C-runtime locale. Changed native locales are '
    'unvalidated. Unicode characters are not casefolded or normalized. '
    'A positive raw score is a native model-selection condition, not a cloud '
    'verdict or browser/Windows enforcement decision. Nonpositive models can '
    'also be selected by native sampling. Individual token weights are not verdicts.'
)


def _number(value, label):
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or isinstance(value, float) and not math.isfinite(value)):
        raise ValueError(f'{label} must be a finite JSON number')
    return value


def _weights(values, label):
    if not isinstance(values, list):
        raise ValueError(f'{label} must be an array')
    for index, entry in enumerate(values):
        where = f'{label}[{index}]'
        if not isinstance(entry, dict) or not isinstance(entry.get('key'), str):
            raise ValueError(f'{where} requires a string key')
        if not entry['key']:
            raise ValueError(f'{where}.key must not be empty')
        _number(entry.get('value'), where + '.value')
    return values


def _features(value, label):
    if not isinstance(value, list) or any(not isinstance(x, str) or not x for x in value):
        raise ValueError(f'{label} must be an array of nonempty strings')


def _document(document):
    if isinstance(document, (bytes, str)):
        try:
            document = json.loads(document)
        except (ValueError, UnicodeError) as exc:
            raise ValueError('Settings must be valid UTF-8 JSON') from exc
    if not isinstance(document, dict) or not isinstance(document.get('models'), list):
        raise ValueError('Settings require a models array')
    # JSON output must remain standards compliant, including unrecognized metadata.
    try:
        json.dumps(document, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError('Settings must contain only finite JSON values') from exc
    for index, model in enumerate(document['models']):
        where = f'models[{index}]'
        if not isinstance(model, dict) or not isinstance(model.get('name'), str) or not model['name']:
            raise ValueError(f'{where} requires a nonempty name')
        _number(model.get('bias'), where + '.bias')
        for field in ('threshold', 'samplingRate'):
            if field in model:
                _number(model[field], where + '.' + field)
        if 'terms' in model:
            if not isinstance(model['terms'], list):
                raise ValueError(f'{where}.terms must be an array')
            if 'weights' in model:
                raise ValueError(f'{where} mixes legacy weights and native terms')
            for number, term in enumerate(model['terms']):
                label = f'{where}.terms[{number}]'
                if not isinstance(term, dict):
                    raise ValueError(f'{label} must be an object')
                _features(term.get('features'), label + '.features')
                if not isinstance(term.get('delimiters'), str):
                    raise ValueError(f'{label}.delimiters must be a string')
                if 'lengthWeight' in term:
                    _number(term['lengthWeight'], label + '.lengthWeight')
                if 'logLengthWeights' in term:
                    if not isinstance(term['logLengthWeights'], list):
                        raise ValueError(f'{label}.logLengthWeights must be an array')
                    for item in term['logLengthWeights']:
                        _number(item, label + '.logLengthWeights entry')
                if 'useDistinctTokens' in term and not isinstance(term['useDistinctTokens'], bool):
                    raise ValueError(f'{label}.useDistinctTokens must be boolean')
                _weights(term.get('tokenWeights', []), label + '.tokenWeights')
        elif 'weights' in model:
            _features(model.get('features'), where + '.features')
            _weights(model['weights'], where + '.weights')
        else:
            raise ValueError(f'{where} has neither terms nor legacy weights')
    return document


def _summary(weights):
    values = [item['value'] for item in weights]
    keys = [item['key'] for item in weights]
    return {
        'count': len(weights), 'unique_keys': len(set(keys)),
        'duplicate_key_count': len(keys) - len(set(keys)),
        'key_length_counts': dict(sorted(Counter(map(len, keys)).items())),
        'all_keys_lowercase_hex32': bool(keys) and all(re.fullmatch('[0-9a-f]{32}', key) for key in keys),
        'minimum': min(values) if values else None,
        'maximum': max(values) if values else None,
        'positive_count': sum(value > 0 for value in values),
        'negative_count': sum(value < 0 for value in values),
        'zero_count': sum(value == 0 for value in values),
    }


def _schema(model):
    return 'native_terms' if 'terms' in model else 'legacy_weights'


def inspect_models(document, *, include_weights=False):
    """Return validated model metadata; optionally retain all exact JSON values.

    ``document`` is decoded JSON, or JSON bytes/text (not a filesystem path).
    No network, title classification or dictionary enumeration occurs.
    """
    document = _document(document)
    models = []
    for model in document['models']:
        item = {key: copy.deepcopy(value) for key, value in model.items()
                if key not in ('weights', 'terms')}
        item['schema'] = _schema(model)
        item['scoring_supported'] = False
        try:
            _validate_score_model(model)
            item['scoring_supported'] = True
        except ValueError as exc:
            item['scoring_unsupported_reason'] = str(exc)
        if 'terms' in model:
            item['terms'] = []
            for index, term in enumerate(model['terms']):
                detail = {key: copy.deepcopy(value) for key, value in term.items() if key != 'tokenWeights'}
                detail.update({'index': index, 'weights': _summary(term.get('tokenWeights', []))})
                if include_weights:
                    detail['tokenWeights'] = copy.deepcopy(term.get('tokenWeights', []))
                item['terms'].append(detail)
            item['token_hash_scope'] = 'MD5 of UTF-8 bytes with ASCII-only lowercase in the default C-runtime locale'
        else:
            item['weight_summary'] = _summary(model['weights'])
            item['token_hash_scope'] = 'Unconfirmed for this legacy schema'
            item['native_compatibility'] = ('Both collected DLL and Edge 158 parsers require terms; '
                                            'legacy weights alone are rejected as MalformedModel::MissingTerms')
            item['native_parser_addresses'] = {'smartscreen_dll': '0x1800304a0', 'edge_158': '0x18775de48'}
            if include_weights:
                item['weights'] = copy.deepcopy(model['weights'])
        models.append(item)
    canonical = json.dumps(document, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)
    result = {
        'schema_version': 1, 'format': 'SmartScreen settings JSON',
        'model_count': len(models), 'models': models,
        'document_semantic_sha256': hashlib.sha256(canonical.encode('utf-8')).hexdigest(),
        'settings_metadata': copy.deepcopy({key: value for key, value in document.items() if key != 'models'}),
        'scoring_limitation': SCORING_LIMITATION,
        'evidence': {'native_dll_sha256': NATIVE_DLL_SHA256,
                     'lowercase_function': '0x180038028',
                     'token_hash_function': '0x180034140',
                     'md5_provider_constructor': '0x180014258'},
    }
    if include_weights:
        result['document'] = copy.deepcopy(document)
    return result


def _utf8(value, label):
    """Encode valid Unicode without normalization or replacement of surrogates."""
    if not isinstance(value, str):
        raise ValueError(f'{label} must be a string')
    try:
        return value.encode('utf-8')
    except UnicodeEncodeError as exc:
        raise ValueError(f'{label} must contain valid Unicode scalar values; lone surrogates are unsupported') from exc


def _normalized_token(token):
    return _utf8(token, 'Token').lower().decode('utf-8')


def native_token_hash(token):
    """Hash UTF-8 bytes with the native default-C-locale ASCII-only lowercase.

    Unlike str.lower()/casefold(), this preserves non-ASCII characters, Unicode
    normalization and combining marks. Nondefault native locales are unvalidated.
    """
    encoded = _utf8(token, 'Token')
    return hashlib.md5(encoded.lower(), usedforsecurity=False).hexdigest()


def lookup_token(document, token, model_name=None):
    """Look up one explicit UTF-8 candidate, without inferring a title verdict.

    For legacy data the same calculation is exposed as an unconfirmed hypothesis.
    A matching digest is a candidate association, not reversal of a stored word.
    """
    document = _document(document)
    candidates = [model for model in document['models'] if model_name is None or model['name'] == model_name]
    if len(candidates) != 1:
        raise ValueError('Select exactly one existing model with model_name')
    model = candidates[0]
    digest = native_token_hash(token)
    matches = []
    if 'terms' in model:
        for index, term in enumerate(model['terms']):
            for entry in term.get('tokenWeights', []):
                if entry['key'] == digest:
                    matches.append({'term_index': index, 'features': copy.deepcopy(term['features']),
                                    'weight': entry['value'], 'entry': copy.deepcopy(entry)})
    else:
        for entry in model['weights']:
            if entry['key'] == digest:
                matches.append({'features': copy.deepcopy(model['features']), 'weight': entry['value'],
                                'entry': copy.deepcopy(entry)})
    return {
        'schema_version': 1, 'model': model['name'], 'model_schema': _schema(model),
        'candidate': token, 'normalized_candidate': _normalized_token(token), 'digest': digest,
        'hash_algorithm': 'MD5 of UTF-8 bytes with ASCII-only lowercase',
        'native_locale': 'C (default runtime branch)',
        'hash_scope': ('Native term helper, corroborated by live v2 candidate matches'
                       if 'terms' in model else 'Unconfirmed hypothesis for legacy weights'),
        'match_count': len(matches), 'matches': matches,
        'is_verdict': False, 'scoring_limitation': SCORING_LIMITATION,
        'interpretation': ('A digest match associates this explicit candidate with a stored weight; '
                           'it does not recover all original words. No match is not a safe verdict.'),
    }


def _validate_score_model(model):
    if 'terms' not in model:
        raise ValueError('Legacy weights do not have validated title-scoring semantics')
    _score_float(model['bias'])
    for index, term in enumerate(model['terms']):
        if term['features'] != ['title']:
            raise ValueError(f'Term {index} must have exactly features=["title"] for title scoring')
        try:
            term['delimiters'].encode('ascii')
        except UnicodeEncodeError as exc:
            raise ValueError(f'Term {index} has unvalidated non-ASCII delimiters') from exc
        weights = term.get('tokenWeights', [])
        if 'lengthWeight' in term:
            _score_float(term['lengthWeight'])
        for value in term.get('logLengthWeights', []):
            _score_float(value)
        for entry in weights:
            _score_float(entry['value'])
        keys = [entry['key'] for entry in weights]
        if len(keys) != len(set(keys)):
            raise ValueError(f'Term {index} contains duplicate token-weight keys')
        if any(re.fullmatch('[0-9a-f]{32}', key) is None for key in keys):
            raise ValueError(f'Term {index} requires lowercase 32-hex token-weight keys')


def _score_float(value):
    try:
        result = float(value)
    except (ValueError, OverflowError) as exc:
        raise ValueError('Scoring values must be representable as finite binary64 numbers') from exc
    if not math.isfinite(result):
        raise ValueError('Scoring values must be representable as finite binary64 numbers')
    return result


def _title_tokens(title, delimiters):
    """Native byte tokenizer: emit on each delimiter, omit only final empty tail."""
    separators = set(delimiters)
    tokens, start = [], 0
    for index, char in enumerate(title):
        if char in separators:
            tokens.append(title[start:index])
            start = index + 1
    if start < len(title):
        tokens.append(title[start:])
    return tokens


def score_title(document, title, model_name=None):
    """Explain a v2 title model using Edge 158 ARM64 default-locale byte semantics.

    Executes no browser or network requests. The returned score is a local model
    output. Sampling, other feature types, nondefault native locale behavior,
    and enforcement are intentionally outside this deterministic API.
    """
    document = _document(document)
    candidates = [model for model in document['models'] if model_name is None or model['name'] == model_name]
    if len(candidates) != 1:
        raise ValueError('Select exactly one existing model with model_name')
    model = candidates[0]
    _validate_score_model(model)
    encoded = _utf8(title, 'Title')
    if len(encoded) > MAX_TITLE_BYTES:
        raise ValueError(f'Title exceeds this tool\'s {MAX_TITLE_BYTES}-byte scoring limit')
    alphabetic_count = sum(65 <= value <= 90 or 97 <= value <= 122 for value in encoded)
    terms, term_total = [], 0.0
    for index, term in enumerate(model['terms']):
        term_score = 0.0
        length_contribution = 0.0
        if 'lengthWeight' in term:
            length_contribution = _score_float(term['lengthWeight']) * len(encoded)
            term_score += length_contribution
        log_weights = term.get('logLengthWeights')
        log_index, log_contribution = None, 0.0
        if log_weights and alphabetic_count:
            # ARM64 FRINTA rounds to nearest with ties away from zero. The
            # logarithm is nonnegative because the letter count is at least 1.
            log_index = min(math.floor(math.log(alphabetic_count) + 0.5) + 1,
                            len(log_weights) - 1)
            log_contribution = _score_float(log_weights[log_index])
            term_score += log_contribution
        weights = {entry['key']: _score_float(entry['value']) for entry in term.get('tokenWeights', [])}
        distinct = term.get('useDistinctTokens', True)
        seen, tokens = set(), []
        for token in _title_tokens(title, term['delimiters']):
            digest = native_token_hash(token)
            applied = not distinct or digest not in seen
            weight = weights.get(digest, 0.0)
            contribution = weight if applied else 0.0
            if applied:
                term_score += weight
            tokens.append({'text': token, 'normalized': _normalized_token(token), 'digest': digest,
                           'matched': digest in weights, 'weight': weight,
                           'applied': applied, 'contribution': contribution})
            seen.add(digest)
        term_total += term_score
        terms.append({'index': index, 'features': ['title'], 'delimiters': term['delimiters'],
                      'use_distinct_tokens': distinct, 'byte_length': len(encoded),
                      'length_weight': term.get('lengthWeight'), 'length_contribution': length_contribution,
                      'alphabetic_count': alphabetic_count, 'log_length_index': log_index,
                      'log_length_contribution': log_contribution,
                      'tokens': tokens, 'raw_contribution': term_score})
    bias = _score_float(model['bias'])
    score = bias + term_total
    if not math.isfinite(score) or any(not math.isfinite(term['raw_contribution']) for term in terms):
        raise ValueError('Model arithmetic produced a non-finite score')
    return {
        'schema_version': 1, 'model': model['name'], 'model_schema': 'native_terms',
        'title': title, 'input_scope': 'UTF-8 title bytes; ASCII delimiters; native title-only terms',
        'native_locale': 'C (default runtime branch)',
        'normalization': 'UTF-8 encoding; ASCII-only byte lowercase; no Unicode casefold or normalization',
        'bias': bias, 'term_total': term_total, 'terms': terms, 'raw_score': score,
        'raw_score_positive': score > 0.0,
        'positive_selection_test': 'raw_score > 0.0', 'is_verdict': False,
        'sampling_rate': model.get('samplingRate'), 'is_test_model': model.get('isTest', False),
        'selection_note': 'Native selection can also include a nonpositive score through sampling; sampling is not run here.',
        'scoring_limitation': SCORING_LIMITATION,
        'evidence': {'edge_version': '158.0.4370.33', 'architecture': 'ARM64',
                     'edge_dll_sha256': EDGE_DLL_SHA256, 'model_score_function': '0x18dce543c',
                     'term_score_function': '0x18dce7740', 'tokenizer_function': '0x18dce7ddc',
                     'selection_function': '0x18dce4da0',
                     'lowercase_function': '0x184842938', 'isalpha_function': '0x184841ec8',
                     'locale_condition': '0x19396ceb0 == 0',
                     'unicode_validation': 'analysis/model_completion/native_bytes.json and native_unicode_scores.json',
                     'browser_validation': '6 benign UTF-8 titles preserved exactly; 7 native Edge 158 followup scores match Python in analysis/model_completion/browser_comparison.json',
                     'validation': 'Native Ghidra instruction emulation with explicit library shims and a CPU-validated FRINTA workaround'}
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file', type=Path)
    parser.add_argument('--token')
    parser.add_argument('--title', help='Compute the offline UTF-8 title score using native default-locale byte rules')
    parser.add_argument('--model')
    parser.add_argument('--full', action='store_true', help='Include every original JSON value and weight')
    args = parser.parse_args(argv)
    try:
        document = args.file.read_bytes()
        result = inspect_models(document, include_weights=args.full)
        if args.token is not None:
            result['token_lookup'] = lookup_token(document, args.token, args.model)
        if args.title is not None:
            result['title_score'] = score_title(document, args.title, args.model)
        if args.model is not None and args.token is None and args.title is None:
            parser.error('--model requires --token or --title')
        print(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False))
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

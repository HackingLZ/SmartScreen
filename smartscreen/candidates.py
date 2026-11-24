#!/usr/bin/env python3
"""Associate explicit offline candidates with hashed feed records.

This does not enumerate a SmartScreen blocklist, contact candidate domains,
invert hashes, or assign reputation. Bloom filters cannot support exact record
recovery and are deliberately excluded from this operation.
"""
import argparse
import csv
import hashlib
import json
from itertools import chain
from pathlib import Path
import re

from smartscreen.data import inspect_data, read_data
from smartscreen.model import inspect_models, native_token_hash

MAX_CANDIDATE_FILE_BYTES = 256 * 1024 * 1024


def iter_candidates(path, input_format='lines'):
    """Yield bounded UTF-8 lines or the domain column of rank,domain CSV."""
    if input_format not in ('lines', 'ranked-domains'):
        raise ValueError('Unknown candidate input format')
    if Path(path).stat().st_size > MAX_CANDIDATE_FILE_BYTES:
        raise ValueError('Candidate file exceeds 256 MiB')
    with Path(path).open(encoding='utf-8-sig', newline='') as source:
        while True:
            line = source.readline(8193)
            if not line:
                break
            if len(line) > 8192:
                raise ValueError('Candidate line exceeds 8192 characters')
            value = line.rstrip('\r\n')
            if not value:
                continue
            if input_format == 'ranked-domains':
                try:
                    row = next(csv.reader([value], strict=True))
                except csv.Error as error:
                    raise ValueError('Malformed ranked-domain CSV') from error
                if len(row) != 2 or not row[0].isdigit() or not row[1]:
                    raise ValueError('Ranked-domain CSV requires rank,domain rows')
                value = row[1]
            yield value


def _domains(value):
    host = value.lower().rstrip('.')
    if len(host) > 253 or not all(re.fullmatch(r'[a-z0-9_-]{1,63}', x) for x in host.split('.')):
        raise ValueError('Domain variants require plain ASCII DNS hostnames')
    bare = host[4:] if host.startswith('www.') else host
    return list(dict.fromkeys((bare, 'www.' + bare)))


def map_candidates(raw, candidates, *, kind, domain_variants=False, model_name=None,
                   max_candidates=1000000, limit=50000):
    """Report candidate associations and exact coverage of enumerable hashes.

    Coverage counts stored hashes with at least one matching supplied candidate;
    it is never a claim that all original plaintexts were recovered.
    """
    if type(max_candidates) is not int or not 1 <= max_candidates <= 10000000:
        raise ValueError('max_candidates must be between 1 and 10000000')
    if type(limit) is not int or not 0 <= limit <= 100000:
        raise ValueError('limit must be between 0 and 100000')
    if kind not in ('topTraffic', 'model'):
        raise ValueError('Only topTraffic and native model token hashes are enumerable; Bloom positives are probabilistic')
    if domain_variants and kind != 'topTraffic':
        raise ValueError('Domain variants apply only to topTraffic')
    records = {}
    if kind == 'topTraffic':
        summary = inspect_data(raw, kind)
        for offset in range(0, len(raw), 16):
            records.setdefault(raw[offset:offset + 16].hex(), []).append(offset // 16)
        record_count = summary['record_count']
        algorithm = 'SHA256 first 16 bytes over exact UTF-16LE candidate'
    else:
        document = json.loads(raw)
        inspect_models(document)
        models = [x for x in document['models'] if model_name is None or x['name'] == model_name]
        if len(models) != 1:
            raise ValueError('Select exactly one model with model_name')
        model = models[0]
        model_name = model['name']
        if 'terms' not in model:
            raise ValueError('Legacy model hashing is unverified; candidate coverage would be misleading')
        record_count = 0
        for index, term in enumerate(model['terms']):
            for weight in term.get('tokenWeights', []):
                if not re.fullmatch(r'[0-9a-f]{32}', weight['key']):
                    raise ValueError('Model contains token keys outside the verified MD5 format')
                records.setdefault(weight['key'], []).append({
                    'term_index': index, 'features': term['features'], 'weight': weight['value']})
                record_count += 1
        algorithm = 'MD5 over UTF-8 bytes with ASCII-only lowercase (native default C-runtime locale)'
    matches = {}
    input_count = attempts = skipped = 0
    for value in candidates:
        input_count += 1
        if input_count > max_candidates:
            raise ValueError('Candidate count exceeds configured maximum; no partial report produced')
        if not isinstance(value, str) or len(value) > 8192:
            raise ValueError('Candidates must be strings of at most 8192 characters')
        try:
            variants = _domains(value) if domain_variants else [value]
        except ValueError:
            skipped += 1
            continue
        for candidate in variants:
            try:
                if kind == 'topTraffic':
                    key = hashlib.sha256(candidate.encode('utf-16le')).digest()[:16].hex()
                else:
                    key = native_token_hash(candidate)
                    candidate = candidate.encode('utf-8').lower().decode('utf-8')
            except (UnicodeError, ValueError):
                skipped += 1
                continue
            attempts += 1
            if key in records:
                matches.setdefault(key, set()).add(candidate)
    details = [{'hash': key, 'candidates': sorted(values),
                'record_indexes' if kind == 'topTraffic' else 'model_weights': records[key]}
               for key, values in sorted(matches.items())]
    return {'schema_version': 1, 'operation': 'offline_candidate_association',
            'kind': kind, 'model': model_name, 'dataset_sha256': hashlib.sha256(raw).hexdigest(),
            'hash_algorithm': algorithm, 'domain_variants': domain_variants,
            'input_candidates': input_count, 'hash_attempts': attempts,
            'unsupported_candidates_skipped': skipped, 'stored_record_count': record_count,
            'unique_stored_hashes': len(records), 'matched_hash_count': len(matches),
            'unmatched_hash_count': len(records) - len(matches),
            'candidate_coverage_fraction': len(matches) / len(records) if records else None,
            'multiple_candidate_hash_count': sum(len(x) > 1 for x in matches.values()),
            'matches': details[:limit], 'matches_truncated': len(details) > limit,
            'is_blocklist': False, 'is_reputation_verdict': False,
            'complete_original_plaintext_recovery': False,
            'interpretation': 'Coverage measures stored hashes matched by supplied candidates. TopTraffic membership is not a blocked-URL list. Candidate associations do not prove unique original plaintexts or current cloud reputation.'}


def map_candidate_file(dataset, candidates, **options):
    return map_candidate_files(dataset, [candidates], **options)


def map_candidate_files(dataset, paths, **options):
    paths = list(paths)
    if not 1 <= len(paths) <= 32:
        raise ValueError('Supply between 1 and 32 candidate files')
    input_format = options.pop('input_format', 'lines')
    result = map_candidates(read_data(dataset), chain.from_iterable(iter_candidates(path, input_format) for path in paths), **options)
    sources = []
    for path in paths:
        digest = hashlib.sha256()
        with Path(path).open('rb') as source:
            for block in iter(lambda: source.read(1024 * 1024), b''):
                digest.update(block)
        sources.append({'path': str(path), 'format': input_format, 'sha256': digest.hexdigest()})
    result['candidate_sources'] = sources
    if len(sources) == 1:
        result['candidate_source'] = sources[0]
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dataset', type=Path)
    parser.add_argument('candidates', type=Path, nargs='+')
    parser.add_argument('--kind', required=True, choices=('topTraffic', 'model'))
    parser.add_argument('--input-format', choices=('lines', 'ranked-domains'), default='lines')
    parser.add_argument('--domain-variants', action='store_true', help='Test lowercase bare and www. hostname forms')
    parser.add_argument('--model')
    parser.add_argument('--max-candidates', type=int, default=1000000)
    parser.add_argument('--limit', type=int, default=50000)
    parser.add_argument('-o', '--output', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.output and args.output.resolve() in [args.dataset.resolve()] + [path.resolve() for path in args.candidates]:
            raise ValueError('Output must differ from input files')
        result = map_candidate_files(args.dataset, args.candidates, kind=args.kind,
                                    input_format=args.input_format, domain_variants=args.domain_variants,
                                    model_name=args.model, max_candidates=args.max_candidates, limit=args.limit)
        encoded = json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False) + '\n'
        if args.output:
            args.output.write_text(encoded, encoding='utf-8')
        else:
            print(encoded, end='')
    except (OSError, ValueError, csv.Error) as error:
        parser.error(str(error))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

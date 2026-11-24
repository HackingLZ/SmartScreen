"""Analyze a URL against saved SmartScreen feeds without making network requests.

The local feeds are not a complete blocklist. Their membership results do not
establish a cloud reputation verdict or reproduce browser enforcement.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

from smartscreen.data import check_feed_url, feed_url_candidates, inspect_data, read_data


FEED_ROLES = {
    'topTraffic': 'Top-traffic candidate hash membership; a hit is not a safety verdict.',
    'synchronousLookupUris': 'Public synchronous-lookup candidate Bloom membership; a hit is not a block verdict.',
    'customSynchronousLookupUris': 'Custom synchronous-lookup candidate Bloom membership; a hit is not a block verdict.',
}
_METADATA_LIMIT = 1024 * 1024


def _read_object(path):
    value = json.loads(read_data(path, _METADATA_LIMIT))
    if not isinstance(value, dict):
        raise ValueError('Expected a JSON object')
    return value


def _digest(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-fA-F]{64}', value):
        raise ValueError('Missing or invalid SHA-256 metadata')
    return value.lower()


def _entry(name, origin):
    return {'id': name, 'origin': origin, 'role': FEED_ROLES[name],
            'state': 'unavailable', 'membership': None, 'membership_type':
            'candidate_hash_membership' if name == 'topTraffic' else 'probabilistic_bloom_membership',
            'cloud_verdict': None, 'is_blocklist': False}


def _verify_body(path, expected_digest, expected_size=None):
    raw = read_data(path)
    actual = hashlib.sha256(raw).hexdigest()
    integrity = {'expected_sha256': _digest(expected_digest), 'actual_sha256': actual,
                 'actual_size': len(raw), 'sha256_matches': actual == expected_digest.lower()}
    if expected_size is not None:
        if type(expected_size) is not int or expected_size < 0:
            raise ValueError('Invalid response size metadata')
        integrity['expected_size'] = expected_size
        integrity['size_matches'] = len(raw) == expected_size
    return raw, integrity


def _evaluate(entry, raw, url):
    summary = inspect_data(raw, entry['id'])
    wanted = 'opaque_128bit_records' if entry['id'] == 'topTraffic' else 'murmur3_filter'
    if summary['format'] != wanted:
        raise ValueError('Unexpected dataset format for ' + entry['id'])
    result = check_feed_url(raw, url, entry['id'])
    field = 'present' if entry['id'] == 'topTraffic' else 'possibly_present'
    entry.update({'state': 'analyzed', 'membership': result[field], 'lookup': result,
                  'dataset': summary})


def _downloaded_feed(directory, name, url):
    entry = _entry(name, 'downloaded_snapshot')
    metadata_file = directory / (name + '.response.json')
    body_file = directory / (name + '.bin')
    entry.update({'metadata_file': str(metadata_file), 'body_file': str(body_file)})
    if not metadata_file.is_file():
        entry.update({'state': 'missing_metadata',
                      'reason': 'A body without its response metadata cannot be verified.',
                      'body_ignored': body_file.exists()})
        return entry
    try:
        metadata = _read_object(metadata_file)
        headers = metadata.get('headers', {})
        if not isinstance(headers, dict) or any(not isinstance(key, str) or not isinstance(value, str)
                                                for key, value in headers.items()):
            raise ValueError('Response headers must map strings to strings')
        status = metadata.get('http_status')
        if type(status) is not int or not 100 <= status <= 599:
            raise ValueError('Missing or invalid HTTP status metadata')
        lowered = {}
        for key, value in headers.items():
            key = key.lower()
            if key in lowered and lowered[key] != value:
                raise ValueError('Conflicting duplicate response header')
            lowered[key] = value
        entry['metadata'] = {key: metadata[key] for key in
                             ('schema_version', 'collected_utc', 'endpoint', 'http_status',
                              'response_sha256', 'response_size', 'requested_dataset_version')
                             if key in metadata}
        entry['metadata'].update({'headers': headers, 'etag': lowered.get('etag'),
                                  'server_date': lowered.get('date'),
                                  'last_modified': lowered.get('last-modified')})
        cache = metadata.get('feed_cache')
        verified_revalidation = status == 304 and isinstance(cache, dict) and cache.get('state') == 'not_modified_cached'
        if verified_revalidation:
            requested = metadata.get('requested_dataset_version')
            if (cache.get('origin_http_status') != 200 or cache.get('dataset_id') != name
                    or cache.get('http_status') != 304
                    or cache.get('requested_version') != requested
                    or cache.get('body_source') != 'previous_verified_http_200'
                    or cache.get('endpoint') != metadata.get('endpoint')
                    or not isinstance(requested, str) or cache.get('etag') != '"' + requested + '"'
                    or cache.get('version') != requested
                    or ('etag' in lowered and lowered['etag'] != cache['etag'])
                    or metadata.get('response_size') != 0
                    or metadata.get('response_sha256') != hashlib.sha256(b'').hexdigest()):
                raise ValueError('Invalid cached-body revalidation provenance')
            _digest(cache.get('scope_sha256'))
            expected = _digest(cache.get('sha256'))
            size = cache.get('size')
            if type(size) is not int or size < 0:
                raise ValueError('Invalid cached-body size')
            entry['origin'] = 'revalidated_cached_http_200'
            entry['metadata']['cached_body'] = {key:cache.get(key) for key in
                ('collected_utc','etag','sha256','size','scope_sha256','origin_http_status')}
        elif status != 200:
            entry.update({'state': 'not_modified_without_verified_cache' if status == 304 else 'http_response_unavailable',
                          'body_ignored': body_file.exists(),
                          'reason': 'HTTP 304 supplies no dataset. This helper needs a saved HTTP 200 body and matching metadata; it does not infer an empty list or associate an unverified leftover file with a 304.'
                          if status == 304 else 'Only complete HTTP 200 dataset bodies are analyzed.'})
            return entry
        else:
            expected = _digest(metadata.get('response_sha256'))
            size = metadata.get('response_size')
            if size is not None and (type(size) is not int or size < 0):
                raise ValueError('Invalid response size metadata')
    except (OSError, ValueError, UnicodeError, RecursionError) as error:
        entry.update({'state': 'invalid_metadata', 'error': str(error)})
        return entry
    try:
        raw, integrity = _verify_body(body_file, expected, size)
        entry['integrity'] = integrity
        if not integrity['sha256_matches'] or not integrity.get('size_matches', True):
            entry.update({'state': 'integrity_mismatch', 'reason': 'Body bytes do not match the saved HTTP response metadata; no membership was evaluated.'})
            return entry
        _evaluate(entry, raw, url)
    except FileNotFoundError:
        entry.update({'state': 'missing_body', 'reason': 'The saved HTTP 200 body is unavailable.'})
    except (OSError, ValueError, UnicodeError, RecursionError) as error:
        entry.update({'state': 'invalid_body', 'error': str(error)})
    return entry


def _native_default(directory, url):
    name = 'customSynchronousLookupUris'
    entry = _entry(name, 'native_dll_fallback')
    report_file = directory / 'builtin_report.json'
    body_file = directory / 'builtin_customSynchronousLookupUris.bin'
    entry.update({'metadata_file': str(report_file), 'body_file': str(body_file),
                  'current_service_contents': False,
                  'interpretation': 'Separately supplied DLL fallback bytes, not a downloaded custom feed or evidence of the current server list. This does not establish that a running browser uses this fallback.'})
    try:
        report = _read_object(report_file)
        item = report.get(name)
        source = report.get('source')
        if not isinstance(item, dict) or not isinstance(item.get('summary'), dict) or not isinstance(source, dict):
            raise ValueError('Missing native fallback provenance or summary')
        _digest(source.get('sha256'))
        expected = _digest(item['summary'].get('sha256'))
        size = item['summary'].get('size')
        if type(size) is not int or size < 0:
            raise ValueError('Invalid native fallback size metadata')
        entry['metadata'] = {'source': source, 'origin': item.get('origin'),
                             'native_initial_version': item.get('native_initial_version'),
                             'rva': item.get('rva'), 'file_offset': item.get('file_offset'),
                             'response_sha256': None, 'http_status': None}
    except (OSError, ValueError, UnicodeError, RecursionError) as error:
        entry.update({'state': 'invalid_metadata', 'error': str(error)})
        return entry
    try:
        raw, integrity = _verify_body(body_file, expected, size)
        entry['integrity'] = integrity
        if not integrity['sha256_matches'] or not integrity['size_matches']:
            entry.update({'state': 'integrity_mismatch', 'reason': 'Fallback body differs from its extraction report.'})
            return entry
        _evaluate(entry, raw, url)
    except FileNotFoundError:
        entry.update({'state': 'missing_body', 'reason': 'The extracted native fallback body is unavailable.'})
    except (OSError, ValueError, UnicodeError, RecursionError) as error:
        entry.update({'state': 'invalid_body', 'error': str(error)})
    return entry


def analyze_url(url, feeds, defaults=None):
    """Return local membership evidence for a URL and saved snapshot directory.

    feeds and optional defaults accept str or pathlib.Path. The former uses
    DATASET.bin plus DATASET.response.json for the three FEED_ROLES. The latter
    accepts smartscreen.defaults output. Recorded body paths are not followed,
    so moved snapshot directories remain usable and stay self-contained.

    Unsupported URLs and nonexistent directories raise ValueError. Unavailable,
    corrupt or unverifiable datasets are reported individually with membership
    None; valid neighboring datasets can still be analyzed. No network is used.
    """
    candidates = feed_url_candidates(url)
    directory = Path(feeds)
    if not directory.is_dir():
        raise ValueError('Feed snapshot directory does not exist: ' + str(directory))
    default_directory = Path(defaults) if defaults is not None else None
    if default_directory is not None and not default_directory.is_dir():
        raise ValueError('Native defaults directory does not exist: ' + str(default_directory))
    report = {
        'schema_version': 1, 'operation': 'offline_url_analysis', 'input_url': url,
        'analyzed_utc': datetime.now(timezone.utc).isoformat(),
        'network_requests': 0, 'cloud_verdict': None, 'is_complete_blocklist': False,
        'url_candidates': candidates, 'feeds_directory': str(directory),
        'interpretation': 'Local snapshot membership only. Top-traffic membership does not prove a URL is safe, and a synchronous-lookup Bloom hit does not prove it is blocked. A Bloom hit may be a false positive; a miss is not a clean cloud verdict.',
        'freshness': 'Collection timestamps and server ETags are preserved below. Snapshot data is historical; current service state is not checked.',
        'datasets': [],
        'native_defaults': []}
    manifest_file = directory / 'manifest.json'
    unadvertised = set()
    manifest_error = None
    discovery_failed = False
    if manifest_file.is_file():
        try:
            manifest = _read_object(manifest_file)
            omitted = manifest.get('unadvertised_datasets', [])
            if not isinstance(omitted, list) or any(not isinstance(name, str) for name in omitted):
                raise ValueError('Manifest unadvertised_datasets must be a list of names')
            unadvertised = set(omitted)
            discovery_failed = manifest.get('discovery_http_status', 200) != 200
            report['snapshot_metadata'] = {key: manifest[key] for key in
                                           ('schema_version', 'collected_utc', 'client_version',
                                            'discovery_endpoint', 'discovery_http_status',
                                            'unadvertised_datasets') if key in manifest}
        except (OSError, ValueError, UnicodeError, RecursionError) as error:
            manifest_error = str(error)
            report['snapshot_metadata_error'] = manifest_error
    for name in FEED_ROLES:
        if name in unadvertised or discovery_failed:
            entry = _entry(name, 'downloaded_snapshot')
            entry.update({'state': 'discovery_failed' if discovery_failed else 'not_advertised_in_snapshot',
                          'body_ignored': (directory / (name + '.bin')).exists(),
                          'reason': 'The latest snapshot manifest does not establish an advertised dataset body. Older files remain available for explicit historical inspection.'})
            report['datasets'].append(entry)
        else:
            report['datasets'].append(_downloaded_feed(directory, name, url))
    if default_directory is not None:
        report['native_defaults'] = [_native_default(default_directory, url)]
    report['analyzed_dataset_count'] = sum(item['state'] == 'analyzed' for item in report['datasets'])
    report['unavailable_dataset_count'] = len(report['datasets']) - report['analyzed_dataset_count']
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('url')
    parser.add_argument('--feeds', type=Path, required=True, help='Saved dataset snapshot directory')
    parser.add_argument('--defaults', type=Path, help='Optional separately extracted native fallback directory')
    args = parser.parse_args(argv)
    try:
        result = analyze_url(args.url, args.feeds, args.defaults)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()

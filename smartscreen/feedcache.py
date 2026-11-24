"""Conservative, content-verified cache for full SmartScreen feed responses.

A 304 is usable only with a previously verified 200 body for the same request
scope and the exact validator sent by this request.  No body is fabricated for
an unconditional 304.  This cache does not interpret a feed as a blocklist.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

MAX_BYTES = 32 * 1024 * 1024


def _scope(dataset_id, endpoint, identity, method, auth_id):
    if not isinstance(dataset_id, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', dataset_id):
        raise ValueError('Invalid dataset id')
    if not isinstance(endpoint, str) or not endpoint.startswith('https://'):
        raise ValueError('An exact HTTPS endpoint is required')
    if method not in ('GET', 'POST') or not isinstance(auth_id, str):
        raise ValueError('Invalid request method or auth id')
    if not isinstance(identity, dict):
        raise ValueError('Identity must be an object')
    profile = copy.deepcopy(identity)
    client = profile.get('client')
    if isinstance(client, dict) and isinstance(client.get('data'), dict):
        # Only this feed's version changes during its revalidation. Preserve
        # other feed versions conservatively because their influence is not
        # universally established for all server-side dataset implementations.
        client['data'].pop(dataset_id, None)
    encoded = json.dumps({'dataset_id': dataset_id, 'endpoint': endpoint,
                          'identity': profile, 'method': method, 'auth_id': auth_id},
                         sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                         allow_nan=False).encode('ascii')
    return hashlib.sha256(encoded).hexdigest()


def _headers(response):
    result = {}
    for key, value in response.get('headers', {}).items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ValueError('Response headers must contain strings')
        key = key.lower()
        if key in result and result[key] != value:
            raise ValueError('Conflicting duplicate response header')
        result[key] = value
    return result


def _validator(value):
    # The native client sends a single quoted, non-weak dataset version.
    if not isinstance(value, str) or not re.fullmatch(r'"[\x21\x23-\x7e]{1,256}"', value):
        return None
    return value[1:-1]


def _atomic_write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.feed-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _read_entry(root, scope, max_bytes):
    entry_path = root / scope / 'entry.json'
    try:
        if entry_path.stat().st_size > 16384:
            return None, 'cache_metadata_too_large'
        entry = json.loads(entry_path.read_text(encoding='utf-8'))
        digest = entry.get('sha256')
        if (entry.get('schema_version') != 1 or entry.get('scope_sha256') != scope
                or not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest)
                or _validator(entry.get('etag')) is None or entry.get('origin_http_status') != 200
                or entry.get('version') != _validator(entry.get('etag'))
                or type(entry.get('size')) is not int or not 0 <= entry['size'] <= max_bytes):
            return None, 'cache_metadata_invalid'
        body = root / scope / (digest + '.bin')
        if body.stat().st_size != entry['size']:
            return None, 'cache_body_size_mismatch'
        with body.open('rb') as handle:
            raw = handle.read(max_bytes + 1)
        if len(raw) > max_bytes or hashlib.sha256(raw).hexdigest() != digest:
            return None, 'cache_body_digest_mismatch'
        return {**entry, 'body_file': str(body), 'metadata_file': str(entry_path)}, None
    except FileNotFoundError:
        return None, 'cache_missing'
    except (ValueError, TypeError, AttributeError, UnicodeError):
        return None, 'cache_metadata_invalid'


def lookup_cached_feed(cache_dir, dataset_id, *, endpoint, identity,
                       method='POST', auth_id='', max_bytes=MAX_BYTES):
    """Return verified cache metadata or None; never return unverified body paths.

    Identity is the effective request identity, including protocol overrides.
    Scope retains the entire endpoint/query and all identity fields except this
    dataset's mutable version. No identity or authorization token is persisted.
    """
    if type(max_bytes) is not int or max_bytes <= 0:
        raise ValueError('max_bytes must be a positive integer')
    scope = _scope(dataset_id, endpoint, identity, method, auth_id)
    entry, _ = _read_entry(Path(cache_dir), scope, max_bytes)
    return entry


def cache_feed_response(cache_dir, dataset_id, response, raw, *, identity,
                        requested_version, method='POST', auth_id='', max_bytes=MAX_BYTES):
    """Persist a verified full 200 response or safely resolve a matching 304.

    Returns JSON-compatible state/provenance. Ignored or unusable responses do
    not overwrite the last verified entry. A returned body_file always names
    a content-verified full response; the current HTTP response stays distinct.
    """
    if not isinstance(response, dict) or not isinstance(raw, bytes):
        raise ValueError('Response metadata and raw bytes are required')
    if type(max_bytes) is not int or max_bytes <= 0 or len(raw) > max_bytes:
        raise ValueError('Invalid response size limit or oversized body')
    endpoint = response.get('endpoint')
    scope = _scope(dataset_id, endpoint, identity, method, auth_id)
    root = Path(cache_dir)
    status = response.get('http_status')
    result = {'schema_version': 1, 'dataset_id': dataset_id, 'scope_sha256': scope,
              'http_status': status, 'requested_version': requested_version}
    headers = _headers(response)
    digest = hashlib.sha256(raw).hexdigest()
    if response.get('response_sha256') != digest or response.get('response_size') != len(raw):
        raise ValueError('Response body does not match recorded SHA-256 and size')
    if status == 200:
        version = _validator(headers.get('etag'))
        if version is None or 'content-range' in headers:
            return {**result, 'state': 'not_cached',
                    'reason': 'missing_or_unsupported_validator' if version is None else 'partial_content'}
        if 'no-store' in [value.strip() for value in headers.get('cache-control', '').lower().split(',')]:
            return {**result, 'state': 'not_cached', 'reason': 'cache_control_no_store'}
        entry = {'schema_version': 1, 'scope_sha256': scope, 'dataset_id': dataset_id,
                 'endpoint': endpoint, 'method': method, 'etag': headers['etag'],
                 'version': version, 'sha256': digest, 'size': len(raw),
                 'origin_http_status': 200, 'collected_utc': response.get('collected_utc')}
        body = root / scope / (digest + '.bin')
        _atomic_write(body, raw)
        metadata = root / scope / 'entry.json'
        _atomic_write(metadata, (json.dumps(entry, indent=2) + '\n').encode('utf-8'))
        return {**result, **entry, 'state': 'stored', 'body_file': str(body),
                'metadata_file': str(metadata)}
    if status == 304:
        if raw:
            return {**result, 'state': 'not_modified_unavailable', 'reason': 'unexpected_304_body'}
        entry, reason = _read_entry(root, scope, max_bytes)
        if entry is None:
            return {**result, 'state': 'not_modified_unavailable', 'reason': reason}
        if not isinstance(requested_version, str) or entry['etag'] != '"' + requested_version + '"':
            return {**result, 'state': 'not_modified_unavailable', 'reason': 'request_validator_mismatch'}
        if 'etag' in headers and headers['etag'] != entry['etag']:
            return {**result, 'state': 'not_modified_unavailable', 'reason': 'response_validator_mismatch'}
        return {**result, **entry, 'http_status': 304, 'state': 'not_modified_cached',
                'body_source': 'previous_verified_http_200'}
    return {**result, 'state': 'not_cached', 'reason': 'http_status_not_cacheable'}

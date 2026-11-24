"""Read saved SmartScreen cache evidence without querying or changing the browser.

Response cache actions contain routing instructions, not a complete blocklist.
The replay format below is Python-owned JSON, separate from Edge's persisted
cache format. Native reader evidence is in analysis/cache_expansion/.
"""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from smartscreen.data import feed_url_candidates, read_data

FORMAT = 'smartscreen_response_cache_v1'
LEGACY_READER = 'smartscreen_dll_1.0.0.79_arm64'
EDGE_READER = 'edge_158.0.4370.33_arm64'
DEFAULT_READER = EDGE_READER
READER_SEMANTICS = (EDGE_READER, LEGACY_READER)
CLIENT_VERSION_READERS = {'1.2.2312.1': LEGACY_READER, '1.2.2609.3': EDGE_READER}
# Native request identities encode four 16-bit version components as decimal.
# Match only these two observed versions; do not infer readers for other builds.
CLIENT_VERSION_NORMALIZED = {version: version for version in CLIENT_VERSION_READERS}
for _version, _reader in tuple(CLIENT_VERSION_READERS.items()):
    _packed = str(sum(int(part) << shift for part, shift in zip(_version.split('.'), (48, 32, 16, 0))))
    CLIENT_VERSION_READERS[_packed] = _reader
    CLIENT_VERSION_NORMALIZED[_packed] = _version
READER_SHA256 = {
    LEGACY_READER: '561e2abcd612a85ce3ae2be9fc978fd2809614120154350fbb02bdc19783204c',
    EDGE_READER: '788fe22e3a1a893f042a8bcdeef0765f0fd39c665d46de4f02c28bc5437f7173',
}
INHERITANCE = {'none': 0, 'path': 1, 'all': 2}
ROUTING_ACTIONS = ('allow', 'evaluate', 'call_server')
SCOPES = ('navigation', 'download')
TICKS_PER_SECOND = 10000000
MAX_ENTRIES = 10000
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _ticks(value=None):
    if value is None:
        value = datetime.now(timezone.utc)
    extra = 0
    if isinstance(value, str):
        match = re.fullmatch(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,7}))?(Z|[+-]\d\d:\d\d)', value)
        if not match:
            raise ValueError('Time must be timezone-aware ISO 8601 with at most seven fractional digits')
        fraction = (match[2] or '').ljust(7, '0')
        extra = int(fraction[6])
        value = datetime.fromisoformat(match[1] + '.' + fraction[:6] + ('+00:00' if match[3] == 'Z' else match[3]))
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError('Time must be a timezone-aware datetime or ISO 8601 string')
    delta = value.astimezone(timezone.utc) - _EPOCH
    return (delta.days * 86400 + delta.seconds) * TICKS_PER_SECOND + delta.microseconds * 10 + extra


def _utc(ticks):
    seconds, fraction = divmod(ticks, TICKS_PER_SECOND)
    try:
        base = _EPOCH + timedelta(seconds=seconds)
    except OverflowError as error:
        raise ValueError('Timestamp is outside the supported calendar range') from error
    return base.strftime('%Y-%m-%dT%H:%M:%S') + '.%07dZ' % fraction


def _scope(endpoint):
    if not isinstance(endpoint, str):
        return None
    path = urlsplit(endpoint).path
    if path == '/api/browser/edge/navigate/3/sync':
        return 'navigation'
    if path in ('/api/browser/edge/download/3', '/api/browser/edge/downloadcomplete/3'):
        return 'download'
    return None


def _canonical_key(uri):
    if not isinstance(uri, str) or not uri:
        raise ValueError('Cache key.uri must be a nonempty string')
    url = uri if re.match(r'(?i)^https?://', uri) else 'http://' + uri
    return feed_url_candidates(url)['candidates'][0]


def native_cache_key(uri, inheritance, semantics=DEFAULT_READER):
    """SHA256(candidate + enum), with the explicitly selected build's truncation."""
    if semantics not in READER_SEMANTICS:
        raise ValueError('Unsupported cache reader semantics')
    if inheritance not in INHERITANCE:
        raise ValueError('Unsupported cache inheritance')
    canonical = _canonical_key(uri)
    preimage = canonical + str(INHERITANCE[inheritance])
    digest = hashlib.sha256(preimage.encode('utf-8')).hexdigest()
    return {'canonical_uri': canonical, 'inheritance': inheritance,
            'inheritance_value': INHERITANCE[inheritance], 'sha256_preimage': preimage,
            'native_key': digest if semantics == EDGE_READER else digest[:16],
            'legacy_native_key': digest[:16]}


def cache_candidates(url, semantics=DEFAULT_READER):
    """Native URL candidates; build-specific inheritance mappings from native code.

    URI parsing/iteration has legacy p-code parity. The Edge 158 expansion into
    multiple inheritance probes is established by that binary's static reader.
    """
    prepared = feed_url_candidates(url)
    host = urlsplit(prepared['canonical_url']).netloc
    suffixes = set('.'.join(host.split('.')[index:]) for index in range(1, len(host.split('.')))) if prepared['host_type'] == 'dns' else set()
    candidates = []
    for index, candidate in enumerate(prepared['candidates']):
        kind = 0 if index == 0 else (2 if candidate in suffixes else 1)
        modes = {0: (0, 1, 2), 1: (1, 2), 2: (2,)}[kind] if semantics == EDGE_READER else (kind,)
        for mode in modes:
            item = native_cache_key(candidate, ('none', 'path', 'all')[mode], semantics)
            candidates.append(item | {'segment_type': kind, 'candidate_index': index})
    return prepared | {'cache_candidates': candidates}


def _action_entry(action, received_at, scope, provenance, semantics=DEFAULT_READER):
    if not isinstance(action, dict) or str(action.get('$type', '')).lower() != 'cache':
        raise ValueError('Expected a cache action')
    key, result = action.get('key'), action.get('result')
    if not isinstance(key, dict) or not isinstance(result, dict):
        raise ValueError('Cache action requires key and result objects')
    inheritance = key.get('inheritance')
    routing = result.get('$type')
    if not isinstance(inheritance, str) or not isinstance(routing, str):
        raise ValueError('Cache inheritance and result.$type must be strings')
    inheritance, routing = inheritance.lower(), routing.lower()
    if routing not in ROUTING_ACTIONS:
        raise ValueError('Unsupported cache result: only allow, evaluate, and call_server are validated')
    derived = native_cache_key(key.get('uri'), inheritance, semantics)
    age = action.get('maxAge', 0)
    if type(age) is not int or not -(1 << 63) <= age < 1 << 63:
        raise ValueError('maxAge must be a signed 64-bit integer in the selected reader build\'s duration unit')
    if scope is not None and scope not in SCOPES:
        raise ValueError('Cache scope must be navigation or download')
    recorded_version = provenance.get('request_client_version') if isinstance(provenance, dict) else None
    matched_reader = CLIENT_VERSION_READERS.get(recorded_version)
    if matched_reader is not None and matched_reader != semantics:
        raise ValueError('Recorded request client version conflicts with selected cache reader')
    received = _ticks(received_at) if received_at is not None else None
    clock_tick = 10 if semantics == EDGE_READER else 1
    native_received = received // clock_tick if received is not None else None
    native_expiry = native_received + age if native_received is not None else None
    if native_expiry is not None and not -(1 << 63) <= native_expiry < 1 << 63:
        raise ValueError('Cache expiry overflows the native signed clock range')
    expiry = native_expiry * clock_tick if native_expiry is not None else None
    return derived | {'routing_action': routing, 'scope': scope,
                      'reader_semantics': semantics, 'reader_binary_sha256': READER_SHA256[semantics],
                      'wire_time_unit': 'microseconds' if semantics == EDGE_READER else '100_nanoseconds',
                      'max_age_value': age,
                      'max_age_unit': 'microseconds' if semantics == EDGE_READER else '100_nanoseconds',
                      'max_age_ticks': age * clock_tick,
                      'max_age_seconds': age * clock_tick / TICKS_PER_SECOND,
                      'clock_precision': 'microseconds' if semantics == EDGE_READER else '100_nanoseconds',
                      'received_utc': _utc(received) if received is not None else None,
                      'expires_utc': _utc(expiry) if expiry is not None else None,
                      'cacheable': age > 0, 'server_context': action.get('serverContext'),
                      'response_category': action.get('responseCategory'),
                      'raw_action': action, 'provenance': provenance}


def import_response(record, source=None, received_at=None, scope=None, context=None, semantics=None):
    """Import explicit cache actions from one raw response or saved response record.

    Missing collection time/scope is preserved as unknown and cannot yield a hit.
    recorded response_sha256 is provenance only: a parsed JSON object cannot by
    itself prove the original HTTP byte representation. Use import_response_file
    to verify a sibling .bin when available.
    """
    if not isinstance(record, dict):
        raise ValueError('Response must be a JSON object')
    if semantics is not None and semantics not in READER_SEMANTICS:
        raise ValueError('Unsupported cache reader semantics')
    if context is not None and (not isinstance(context, str) or not context or len(context) > 256):
        raise ValueError('Explicit cache context must be a nonempty string of at most 256 characters')
    if scope is not None and scope not in SCOPES:
        raise ValueError('Cache scope must be navigation or download')
    wrapped = 'response' in record or 'http_status' in record
    endpoint = record.get('endpoint') if wrapped else None
    detected_scope = _scope(endpoint)
    if scope is not None and detected_scope is not None and scope != detected_scope:
        raise ValueError('Explicit scope conflicts with the recorded endpoint')
    scope = scope or detected_scope
    timestamp = received_at if received_at is not None else record.get('collected_utc') if wrapped else None
    if timestamp is not None:
        timestamp = _utc(_ticks(timestamp))
    request = record.get('request')
    profile = record.get('request_profile')
    if profile is None and isinstance(request, dict):
        profile = request.get('profile')
    identity = profile.get('identity') if isinstance(profile, dict) else None
    client = identity.get('client') if isinstance(identity, dict) else None
    identity_version = client.get('version') if isinstance(client, dict) else None
    recorded_versions = {value for value in (record.get('request_client_version'), identity_version)
                         if isinstance(value, str) and value}
    versions = {CLIENT_VERSION_NORMALIZED.get(value, value) for value in recorded_versions}
    if len(versions) > 1:
        raise ValueError('Recorded request client version conflicts with captured request identity')
    client_version = next(iter(versions), None)
    matched_reader = CLIENT_VERSION_READERS.get(client_version)
    if semantics is not None and matched_reader is not None and semantics != matched_reader:
        raise ValueError('Recorded request client version conflicts with selected cache reader')
    selection_basis = 'explicit_reader' if semantics is not None else 'binary_matched_request_client_version' if matched_reader else 'default_edge_reader_assumption'
    semantics = semantics or matched_reader or DEFAULT_READER
    identity_hash = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(',', ':')).encode()).hexdigest() if isinstance(identity, dict) else None
    context_key = 'explicit:' + context if context is not None else None
    if context_key is None and identity_hash is not None:
        context_key = 'request_identity_sha256:' + identity_hash
    observation_id = hashlib.sha256(json.dumps(record, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    provenance = {'source': str(source) if source is not None else None,
                  'endpoint': endpoint, 'http_status': record.get('http_status') if wrapped else None,
                  'recorded_response_sha256': record.get('response_sha256') if wrapped else None,
                  'received_time_basis': 'caller_supplied' if received_at is not None else 'recorded_collection_time' if timestamp else 'unknown',
                  'wire_bytes_verified': False, 'observation_id': observation_id,
                  'request_identity_sha256': identity_hash,
                  'request_client_version': client_version,
                  'recorded_request_client_versions': sorted(recorded_versions),
                  'reader_selection_basis': selection_basis,
                  'cache_context': context_key,
                  'context_basis': 'caller_asserted_same_runtime_and_profile' if context is not None else 'captured_request_identity' if context_key else 'single_response_only'}
    output = {'schema_version': 1, 'format': FORMAT, 'entries': [], 'rejected': [],
              'reader_semantics': semantics, 'reader_selection_basis': selection_basis,
              'request_client_version': client_version,
              'reader_binary_sha256': READER_SHA256[semantics],
              'ignored_action_count': 0, 'cloud_verdict': None, 'is_complete_blocklist': False,
              'context_assumption': 'Replay requires one runtime/profile cache context. Captured request identity establishes matching identity fields, not continuity of a browser process. Multiple response observations without matching context remain unknown.',
              'interpretation': 'Offline response-action evidence using the explicitly named reader build. Expiry uses the supplied/recorded collection time as an approximation of native insertion time. This file is not a browser cache dump or proof that a running browser inserted these actions.'}
    if wrapped and (type(record.get('http_status')) is not int or not 200 <= record['http_status'] < 300):
        output['rejected'].append({'source': source, 'error': 'Only successful HTTP responses can contribute cache actions'})
        return output
    body = record.get('response') if wrapped else record
    if not isinstance(body, dict):
        output['rejected'].append({'source': source, 'error': 'Response body is not a JSON object'})
        return output
    actions = body.get('actions', [])
    if not isinstance(actions, list) or len(actions) > MAX_ENTRIES:
        raise ValueError('Response actions must be a bounded list')
    for index, action in enumerate(actions):
        if not isinstance(action, dict) or str(action.get('$type', '')).lower() != 'cache':
            output['ignored_action_count'] += 1
            continue
        try:
            entry = _action_entry(action, timestamp, scope, provenance | {'action_index': index}, semantics)
            output['entries'].append(entry)
        except (ValueError, TypeError) as error:
            output['rejected'].append({'action_index': index, 'source': source,
                                       'raw_action': action, 'error': str(error)})
    output['entry_count'] = len(output['entries'])
    return output


def import_response_file(path, received_at=None, scope=None, context=None, semantics=None):
    """Import a record; check its sibling raw response when one is present."""
    path = Path(path)
    record = json.loads(read_data(path))
    verified = False
    raw_path = path.with_suffix('.bin')
    if raw_path != path and raw_path.is_file():
        raw = read_data(raw_path)
        if not isinstance(record, dict) or record.get('response_sha256') != hashlib.sha256(raw).hexdigest():
            raise ValueError('Raw response SHA-256 differs from saved metadata')
        if record.get('response_size', len(raw)) != len(raw) or json.loads(raw) != record.get('response'):
            raise ValueError('Raw response bytes differ from the saved parsed response')
        verified = True
    result = import_response(record, str(path), received_at, scope, context, semantics)
    for entry in result['entries']:
        entry['provenance']['wire_bytes_verified'] = verified
    return result


def merge_caches(caches):
    """Combine imports without silently replacing duplicate native keys."""
    output = import_response({'actions': []})
    first = True
    for cache in caches:
        if not isinstance(cache, dict) or cache.get('format') != FORMAT or not isinstance(cache.get('entries'), list):
            raise ValueError('Expected response cache import documents')
        if first and cache.get('reader_semantics') in READER_SEMANTICS:
            output['reader_semantics'] = cache['reader_semantics']
            output['reader_binary_sha256'] = READER_SHA256[cache['reader_semantics']]
            output['reader_selection_basis'] = 'merged_single_reader; see entry provenance'
            first = False
        if cache.get('reader_semantics') != output['reader_semantics']:
            raise ValueError('Cannot merge different or unspecified cache reader semantics')
        output['entries'].extend(cache['entries'])
        output['rejected'].extend(cache.get('rejected', []))
        output['ignored_action_count'] += cache.get('ignored_action_count', 0)
        if len(output['entries']) > MAX_ENTRIES:
            raise ValueError('Combined cache exceeds entry limit')
    output['entry_count'] = len(output['entries'])
    return output


def lookup_cache(cache, url, at=None, scope=None):
    """Look up response-action routing evidence, preserving ambiguity and expiry.

    First unexpired native candidate wins. Edge 158 replaces duplicate keys.
    The legacy DLL retains an existing key; reinsertions after its expiry are
    unknown because periodic eviction timing is absent from saved responses.
    """
    if not isinstance(cache, dict) or cache.get('format') != FORMAT or not isinstance(cache.get('entries'), list):
        raise ValueError('Expected a response cache import document')
    semantics = cache.get('reader_semantics')
    if semantics not in READER_SEMANTICS:
        raise ValueError('Cache reader semantics are unspecified or unsupported')
    if len(cache['entries']) > MAX_ENTRIES or (scope is not None and scope not in SCOPES):
        raise ValueError('Invalid cache size or scope')
    now = _ticks(at)
    prepared = cache_candidates(url, semantics)
    report = {'schema_version': 1, 'format': FORMAT, 'operation': 'offline_cache_lookup',
              'reader_semantics': semantics, 'reader_binary_sha256': cache.get('reader_binary_sha256'),
              'context_assumption': cache.get('context_assumption'),
              'input_url': url, 'at_utc': _utc(now), 'state': 'miss', 'routing_action': None,
              'cloud_verdict': None, 'is_complete_blocklist': False, 'scope': scope,
              'candidates': prepared['cache_candidates'], 'expired_matches': [],
              'rejected_entries': [], 'network_requests': 0,
              'interpretation': 'Historical cache routing evidence only. allow/evaluate/call_server are cache instructions, not a current cloud or browser UI verdict.'}
    entries = []
    for index, item in enumerate(cache['entries']):
        try:
            if not isinstance(item, dict):
                raise ValueError('Entry is not an object')
            parsed = _action_entry(item.get('raw_action'), item.get('received_utc'), item.get('scope'), item.get('provenance'), semantics)
            for field in ('native_key', 'canonical_uri', 'inheritance', 'routing_action', 'expires_utc', 'reader_semantics', 'wire_time_unit'):
                if parsed[field] != item.get(field):
                    raise ValueError('Derived entry field does not match original action: ' + field)
            entries.append(parsed)
        except (ValueError, TypeError) as error:
            report['rejected_entries'].append({'index': index, 'error': str(error)})
    if report['rejected_entries']:
        return report | {'state': 'unknown', 'reason': 'Corrupt imported entries prevent a reliable precedence decision.'}
    scopes = {entry['scope'] for entry in entries if entry['scope'] is not None}
    if scope is None:
        if len(scopes) > 1:
            return report | {'state': 'unknown', 'reason': 'Multiple navigation contexts are present; supply scope.'}
        scope = next(iter(scopes), None)
        report['scope'] = scope
    relevant = [entry for entry in entries if entry['scope'] in (None, scope) or scope is None]
    provenances = [entry.get('provenance') for entry in relevant]
    if any(not isinstance(value, dict) or not value.get('observation_id') for value in provenances):
        return report | {'state': 'unknown', 'reason': 'Cache provenance is missing or corrupt.'}
    observations = {value['observation_id'] for value in provenances}
    contexts = {value.get('cache_context') for value in provenances}
    identities = {value.get('request_identity_sha256') for value in provenances if value.get('request_identity_sha256') is not None}
    if len(identities) > 1:
        return report | {'state': 'unknown', 'reason': 'Captured request identities differ; they cannot be treated as one profile cache.'}
    if len(observations) > 1 and (len(contexts) != 1 or None in contexts):
        return report | {'state': 'unknown', 'reason': 'Responses cannot be associated with one runtime/profile cache context; import with a shared explicit context only when that assumption is justified.'}
    for candidate in report['candidates']:
        matches = [entry for entry in entries if entry['native_key'] == candidate['native_key']
                   and (entry['scope'] is None or scope is None or entry['scope'] == scope)]
        matches = [entry for entry in matches if entry['cacheable']]
        if not matches:
            continue
        if any(entry['received_utc'] is None or entry['scope'] is None for entry in matches):
            return report | {'state': 'unknown', 'reason': 'Matching action has unknown receipt time or navigation context.'}
        matches.sort(key=lambda entry: _ticks(entry['received_utc']))
        observed = [entry for entry in matches if _ticks(entry['received_utc']) <= now]
        if not observed:
            return report | {'state': 'unknown', 'reason': 'Matching actions were observed after the requested lookup time.'}
        first = observed[-1] if semantics == EDGE_READER else observed[0]
        if semantics == LEGACY_READER and any(_ticks(entry['received_utc']) >= _ticks(first['expires_utc']) for entry in observed[1:]):
            return report | {'state': 'unknown', 'reason': 'A duplicate key was reinserted after expiry; native periodic eviction timing is unavailable.', 'matching_entries': observed}
        if now >= _ticks(first['expires_utc']):
            report['expired_matches'].append(first)
            continue
        return report | {'state': 'hit', 'routing_action': first['routing_action'],
                         'matched_candidate': candidate, 'entry': first,
                         'provenance': first['provenance'], 'expires_utc': first['expires_utc'],
                         'duplicate_insertions_ignored': len(observed) - 1 if semantics == LEGACY_READER else 0,
                         'superseded_insertions': len(observed) - 1 if semantics == EDGE_READER else 0}
    if report['rejected_entries'] or cache.get('rejected'):
        report.update({'state': 'unknown', 'reason': 'Some cache evidence was rejected; a complete miss cannot be established.'})
    elif report['expired_matches']:
        report['state'] = 'expired'
    elif not entries or not any(entry['cacheable'] for entry in entries):
        report['state'] = 'no_cache'
    return report


def inspect_native_cache(path, at=None, url=None):
    """Read Edge version-1 persisted cache data using the exact Edge 158 reader.

    file_hash is the full SHA256 cache key (older 16-hex keys are supported by
    the native fallback lookup). expiration_time uses Unix microseconds, and
    result is the cache-routing enum, separate from cloud/UI response enums.
    Raw fields are preserved; optional URL lookup never visits the URL.
    """
    path = Path(path)
    raw = read_data(path)
    pointer = None
    # Observed Edge current-file indirections contain only the sibling basename.
    # Never follow paths supplied by arbitrary JSON fields or traversal tokens.
    if raw in (b'uriCache_', b'downloadCache_'):
        pointer = {'file': str(path), 'sha256': hashlib.sha256(raw).hexdigest(),
                   'target_basename': raw.decode('ascii')}
        path = path.with_name(raw.decode('ascii'))
        raw = read_data(path)
    document = json.loads(raw)
    if not isinstance(document, dict) or type(document.get('version')) is not int or document['version'] != 1 or not isinstance(document.get('cache_data'), list):
        raise ValueError('Expected an Edge version-1 cache_data JSON document')
    if len(document['cache_data']) > MAX_ENTRIES:
        raise ValueError('Native cache exceeds entry limit')
    now = _ticks(at)
    entries, rejected = [], []
    for index, item in enumerate(document['cache_data']):
        if not isinstance(item, dict) or not isinstance(item.get('file_hash'), str) or not re.fullmatch(r'(?:[0-9a-f]{64}|[0-9a-f]{16})', item['file_hash']) or type(item.get('result')) is not int or type(item.get('expiration_time')) is not int or not -(1 << 63) <= item['expiration_time'] < 1 << 63:
            rejected.append({'index': index, 'raw_entry': item, 'error': 'Unsupported persisted entry schema'})
        else:
            try:
                expiry = item['expiration_time'] * 10
                entry = {'index': index, 'raw_entry': item,
                         'routing_action': ROUTING_ACTIONS[item['result']] if 0 <= item['result'] < 3 else None,
                         'expires_utc': _utc(expiry), 'expiration_unit': 'unix_microseconds',
                         'expiry_status': 'expired' if now // 10 >= item['expiration_time'] else 'unexpired',
                         'interpretation': 'Historical cache routing instruction. response_category is metadata, not a substitute for result or a cloud/UI verdict.'}
                entries.append(entry)
            except ValueError as error:
                rejected.append({'index': index, 'raw_entry': item, 'error': str(error)})
    report = {'schema_version': 1, 'format': 'edge_persisted_cache_v1', 'file': str(path),
            'pointer': pointer,
            'reader_semantics': EDGE_READER, 'reader_binary_sha256': READER_SHA256[EDGE_READER],
            'sha256': hashlib.sha256(raw).hexdigest(), 'size': len(raw),
            'native_version': document['version'], 'entries': entries, 'rejected': rejected,
            'entry_count': len(entries), 'cloud_verdict': None, 'routing_action': None,
            'is_complete_blocklist': False, 'at_utc': _utc(now), 'network_requests': 0,
            'interpretation': 'A local cache snapshot containing only stored observations; hash identifiers cannot be reversed into a complete plaintext URL list.'}
    if url is not None:
        prepared = cache_candidates(url, EDGE_READER)
        lookup = {'input_url': url, 'state': 'miss', 'routing_action': None, 'cloud_verdict': None,
                  'candidates': prepared['cache_candidates'], 'expired_matches': [],
                  'interpretation': 'Lookup within this supplied snapshot only. No current browser state, profile, policy, or cloud verdict is inferred.'}
        if rejected:
            lookup.update({'state': 'unknown', 'reason': 'Malformed persisted entries prevent a reliable precedence decision.'})
        else:
            hashes = [entry['raw_entry']['file_hash'] for entry in entries]
            if len(hashes) != len(set(hashes)):
                lookup.update({'state': 'unknown', 'reason': 'Duplicate persisted hash keys have ambiguous load order and expiration handling.'})
                report['lookup'] = lookup
                return report
            for candidate in prepared['cache_candidates']:
                matched = False
                for key in (candidate['native_key'], candidate['legacy_native_key']):
                    matches = [entry for entry in entries if entry['raw_entry']['file_hash'] == key]
                    fresh = [entry for entry in matches if entry['expiry_status'] == 'unexpired']
                    if fresh:
                        winner = fresh[-1]
                        lookup.update({'state': 'hit' if winner['routing_action'] is not None else 'unknown',
                                       'routing_action': winner['routing_action'], 'entry': winner,
                                       'matched_candidate': candidate,
                                       'matched_key': key, 'legacy_key_fallback': len(key) == 16,
                                       'expires_utc': winner['expires_utc']})
                        matched = True
                        break
                    lookup['expired_matches'].extend(matches)
                if matched:
                    break
            else:
                if lookup['expired_matches']:
                    lookup['state'] = 'expired'
                elif not entries:
                    lookup['state'] = 'no_cache'
        report['lookup'] = lookup
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    importing = sub.add_parser('import', help='Import cache actions from saved JSON responses')
    importing.add_argument('responses', nargs='+', type=Path)
    importing.add_argument('--scope', choices=SCOPES)
    importing.add_argument('--received-at')
    importing.add_argument('--context', help='Explicit assertion that imported responses share one runtime/profile cache')
    importing.add_argument('--reader', choices=READER_SEMANTICS,
                           help='Reader override; known captured SDK versions auto-select, otherwise Edge158 is an explicit assumption')
    importing.add_argument('--output', type=Path)
    lookup = sub.add_parser('lookup', help='Look up one URL in imported response cache evidence')
    lookup.add_argument('cache', type=Path)
    lookup.add_argument('url')
    lookup.add_argument('--at')
    lookup.add_argument('--scope', choices=SCOPES)
    native = sub.add_parser('inspect-native', help='Read an Edge version-1 persisted cache JSON file')
    native.add_argument('file', type=Path)
    native.add_argument('--at')
    native.add_argument('--url', help='Optional local-only URL lookup against this native cache snapshot')
    args = parser.parse_args(argv)
    try:
        if args.command == 'import':
            result = merge_caches(import_response_file(path, args.received_at, args.scope, args.context, args.reader) for path in args.responses)
        elif args.command == 'lookup':
            result = lookup_cache(json.loads(read_data(args.cache)), args.url, args.at, args.scope)
        else:
            result = inspect_native_cache(args.file, args.at, args.url)
        rendered = json.dumps(result, indent=2) + '\n'
        if args.command == 'import' and args.output is not None:
            args.output.write_text(rendered)
        else:
            print(rendered, end='')
    except (OSError, ValueError, TypeError) as error:
        parser.error(str(error))


if __name__ == '__main__':
    main()

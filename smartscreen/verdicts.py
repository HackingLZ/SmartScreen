"""Export observed URL reputation from verified batch records, entirely offline.

This is a corpus of historical server observations, never a complete SmartScreen
blocklist. Export selection happens after the latest verdict for each exact
request context has been found, so a newer allow withdraws an older warning.
"""
import base64
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
from urllib.parse import urlsplit

MAX_LINE_BYTES = 8 * 1024 * 1024
MAX_INPUT_BYTES = 512 * 1024 * 1024
ENDPOINT_KINDS = {
    'https://nav-edge.smartscreen.microsoft.com/api/browser/edge/navigate/3/sync': 'url',
    'https://dl-edge.smartscreen.microsoft.com/api/browser/edge/download/3': 'download',
}


def _json(text):
    def pairs(items):
        value = {}
        for key, child in items:
            if key in value:
                raise ValueError('Duplicate JSON key: ' + key)
            value[key] = child
        return value
    def constant(value):
        raise ValueError('Non-finite JSON value: ' + value)
    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


def _time(value):
    if not isinstance(value, str):
        raise ValueError('Observation time must be an ISO timestamp')
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None:
        raise ValueError('Observation time must include its UTC offset')
    return result.astimezone(timezone.utc)


def _url(value):
    if not isinstance(value, str) or len(value) > 16384 or any(ord(c) < 32 for c in value):
        raise ValueError('Invalid observed URL')
    parsed = urlsplit(value)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('Expected an absolute HTTP(S) URL without credentials')
    return value


def iter_records(path):
    """Read bounded JSONL or an existing history database without changing it."""
    path = Path(path).resolve()
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError('Observation input exceeds 512 MiB')
    with path.open('rb') as source:
        is_database = source.read(16) == b'SQLite format 3\0'
    if is_database:
        connection = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)
        try:
            connection.execute('PRAGMA query_only=ON')
            version = connection.execute('PRAGMA user_version').fetchone()[0]
            if version != 1:
                raise ValueError('Unsupported SmartScreen history database version')
            for index, (text,) in enumerate(connection.execute('SELECT record_json FROM ss_observations ORDER BY id'), 1):
                if not isinstance(text, str) or len(text.encode()) > MAX_LINE_BYTES:
                    raise ValueError('Observation record exceeds 8 MiB')
                yield index, _json(text)
        finally:
            connection.close()
    else:
        with path.open('rb') as source:
            index = 0
            while True:
                line = source.readline(MAX_LINE_BYTES + 1)
                if not line:
                    break
                index += 1
                if len(line) > MAX_LINE_BYTES:
                    raise ValueError('Observation record exceeds 8 MiB')
                yield index, _json(line.decode('utf-8-sig' if index == 1 else 'utf-8'))


def _observation(record):
    if not isinstance(record, dict):
        raise ValueError('Batch observation must be an object')
    context = record.get('context')
    if not isinstance(context, dict):
        raise ValueError('Missing request context')
    query_key = hashlib.sha256(_canonical(context).encode()).hexdigest()
    if record.get('query_key') != query_key:
        raise ValueError('Request context digest mismatch')
    endpoint = context.get('endpoint')
    kind = ENDPOINT_KINDS.get(endpoint)
    if kind is None:
        return None, 'not_url_reputation'
    payload = context.get('payload')
    if not isinstance(payload, dict) or not isinstance(payload.get('destination'), dict):
        raise ValueError('Missing destination in request context')
    url = _url(payload['destination'].get('uri'))
    if record.get('target', {}).get('url') != url or record.get('kind') != kind:
        raise ValueError('Target does not match request context')
    when = _time(record.get('observed_utc'))
    attempt = {'query_key': query_key, 'url': url, 'kind': kind, 'endpoint': endpoint,
               'observed_utc': when.isoformat(), 'status': record.get('status'),
               'http_status': record.get('http_status')}
    if record.get('status') != 'verdict':
        return attempt, 'no_verdict'
    response = record.get('response_record')
    if not isinstance(response, dict):
        raise ValueError('Missing response record')
    status = response.get('http_status')
    if type(status) is not int or not 200 <= status < 300 or record.get('http_status') != status:
        raise ValueError('Verdict requires a successful matching HTTP status')
    if response.get('endpoint') != endpoint:
        raise ValueError('Response endpoint does not match request context')
    encoded = record.get('raw_response_base64')
    if not isinstance(encoded, str):
        raise ValueError('Missing exact response bytes')
    raw = base64.b64decode(encoded, validate=True)
    digest = hashlib.sha256(raw).hexdigest()
    if response.get('response_sha256') != digest or response.get('response_size') != len(raw):
        raise ValueError('Response digest or length mismatch')
    parsed = _json(raw)
    if parsed != response.get('response') or not isinstance(parsed, dict):
        raise ValueError('Parsed response does not match saved bytes')
    result = parsed.get('result')
    if not isinstance(result, dict) or not isinstance(result.get('$type'), str):
        raise ValueError('No explicit URL result in response')
    verdict = result['$type']
    category = result.get('responseCategory')
    if verdict != record.get('verdict') or verdict != response.get('verdict'):
        raise ValueError('Stored verdict disagrees with response bytes')
    if category != record.get('response_category') or category != response.get('response_category'):
        raise ValueError('Stored category disagrees with response bytes')
    attempt.update(verdict=verdict, response_category=category, response_sha256=digest,
                   response_size=len(raw), integrity='saved_bytes_verified',
                   policy_context=payload.get('config'),
                   server_context=result.get('serverContext', parsed.get('serverContext')),
                   is_microsoft_demo=(urlsplit(url).hostname or '').lower() in
                       {'demo.smartscreen.msft.net', 'nav.smartscreen.msft.net'},
                   freshness='historical_observation_no_validated_expiry',
                   url_scope='exact_submitted_url', enforcement='not_observed')
    return attempt, None


def export_observed(paths, *, verdicts=('warn', 'block'), kinds=('url',), max_records=100000):
    """Select latest successful explicit results per exact request context."""
    if type(max_records) is not int or not 1 <= max_records <= 1000000:
        raise ValueError('max_records must be between 1 and 1000000')
    if not verdicts or any(v not in {'allow', 'warn', 'block', 'unknown', 'evaluate', 'call_server'} for v in verdicts):
        raise ValueError('Unsupported or empty verdict selection')
    if not kinds or any(k not in {'url', 'download'} for k in kinds):
        raise ValueError('Unsupported or empty kind selection')
    latest, attempts, rejected, reasons = {}, {}, [], Counter()
    sources, count = [], 0
    for path in paths:
        path = Path(path).resolve()
        sources.append(str(path))
        for index, record in iter_records(path):
            count += 1
            if count > max_records:
                raise ValueError('Observation count exceeds max_records; no partial export produced')
            try:
                value, reason = _observation(record)
                if reason:
                    reasons[reason] += 1
                if value is None:
                    continue
                key = value['query_key']
                ordering = (_time(value['observed_utc']), count)
                if key not in attempts or ordering > attempts[key][0]:
                    attempts[key] = (ordering, {k: value[k] for k in ('observed_utc','status','http_status')})
                if reason is None and (key not in latest or ordering > latest[key][0]):
                    value['source'] = {'path': str(path), 'record': index}
                    latest[key] = (ordering, value)
            except (ValueError, TypeError, KeyError, AttributeError) as error:
                reasons['invalid_record'] += 1
                if len(rejected) < 100:
                    rejected.append({'source':str(path),'record':index,'error':str(error)})
    entries = []
    for key, (_, value) in latest.items():
        if value['verdict'] in verdicts and value['kind'] in kinds:
            value['last_attempt'] = attempts[key][1]
            entries.append(value)
    entries.sort(key=lambda value: (value['url'], value['kind'], value['query_key']))
    return {'schema_version': 1, 'format': 'smartscreen_observed_url_verdicts',
            'generated_utc': datetime.now(timezone.utc).isoformat(), 'network_requests': 0,
            'is_complete_blocklist': False, 'coverage': 'supplied_observations_only',
            'selection': {'verdicts':list(verdicts),'kinds':list(kinds),
                          'latest_successful_verdict_per_request_context':True},
            'summary': {'input_records':count,'latest_contexts':len(latest),'exported':len(entries),
                        'skipped':dict(reasons),'validation_complete':not reasons['invalid_record']},
            'sources': sources, 'rejected_records': rejected, 'entries': entries,
            'limitations': ['No cloud completeness or present-day enforcement is implied.',
                           'Missing URLs have unknown reputation, not an allow verdict.',
                           'Warnings, blocks and policy contexts remain distinct.',
                           'An integrity digest verifies saved bytes, not their external origin.']}


def lookup_observed(catalog, url):
    """Exact URL search in an exported corpus; absence always means unknown."""
    _url(url)
    if not isinstance(catalog, dict) or catalog.get('format') != 'smartscreen_observed_url_verdicts' or catalog.get('schema_version') != 1:
        raise ValueError('Not a supported observed-verdict export')
    entries = catalog.get('entries')
    if not isinstance(entries, list) or len(entries) > 1000000:
        raise ValueError('Invalid observed-verdict entries')
    matches = [entry for entry in entries if isinstance(entry, dict) and entry.get('url') == url]
    return {'url':url,'network_requests':0,'status':'historical_matches' if matches else 'unknown',
            'matches':matches,'cloud_verdict':None,'enforcement':'not_observed',
            'is_complete_blocklist':False,'matching':'exact_submitted_url_only'}

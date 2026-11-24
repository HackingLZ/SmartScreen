"""Bounded SmartScreen JSONL batches and local SQLite result history.

All input is validated before requests. File jobs send streamed SHA-256 metadata,
never file contents. Each output line is an independent, flushed result record.
"""
import base64
import copy
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import time
import uuid

from smartscreen import (ENDPOINTS, EDGE_AUTH_ID, SmartScreenClient, apply_client_version,
                        check_url, client_version_for, file_payload, url_payload)

MAX_JOBS = 1000
MAX_LINE_BYTES = 64 * 1024
SENSITIVE_KEYS = {'onlineidticket', 'authorization', 'password', 'cookie', 'cookies',
                  'access_token', 'refresh_token', 'accesstoken', 'refreshtoken'}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def redact_context(value):
    if isinstance(value, dict):
        return {key: ({'redacted': True, 'sha256': hashlib.sha256(canonical(child).encode()).hexdigest()}
                      if key.casefold() in SENSITIVE_KEYS and child not in (None, '')
                      else redact_context(child)) for key, child in value.items()}
    if isinstance(value, list):
        return [redact_context(child) for child in value]
    return value


def _text(value, field):
    if not isinstance(value, str) or not value or len(value) > 16384 or any(ord(c) < 32 for c in value):
        raise ValueError(field + ' must be a nonempty string without control characters')
    return value


def _filename(value):
    value = _text(value, 'name')
    if value in ('.', '..') or '/' in value or '\\' in value:
        raise ValueError('name must be a file name, not a path')
    return value


def _hash_file(path):
    digest, count = hashlib.sha256(), 0
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError('File input must be a regular file')
    with path.open('rb') as source:
        # fstat describes the open file, including when the input is a symlink.
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('File input must be a regular file')
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
            count += len(chunk)
        after = os.fstat(source.fileno())
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns) or count != after.st_size:
        raise ValueError('File changed while its metadata was collected')
    return digest.hexdigest(), count


def prepare_job(job, *, base_dir=None, profile=None, auth_id=EDGE_AUTH_ID, client_version=None):
    """Validate one job and return its payload plus credential-redacted stable context."""
    if not isinstance(job, dict):
        raise ValueError('Each JSONL line must contain an object')
    kind = job.get('type')
    allowed = {
        'url': {'type', 'id', 'url', 'referrer', 'identity'},
        'download': {'type', 'id', 'url', 'referrer', 'identity'},
        'file': {'type', 'id', 'path', 'source', 'name', 'identity', 'surface', 'referrer'},
        'hash': {'type', 'id', 'sha256', 'size', 'name', 'source', 'identity', 'surface', 'referrer'},
    }
    if not isinstance(kind, str) or kind not in allowed:
        raise ValueError('Job type must be url, download, file, or hash')
    extra = set(job) - allowed[kind]
    if extra:
        raise ValueError('Unsupported job fields: ' + ', '.join(sorted(extra)))
    if 'id' in job:
        _text(job['id'], 'id')
    selected_profile = job.get('identity', profile)
    if selected_profile is not None and not isinstance(selected_profile, dict):
        raise ValueError('identity must be an object')
    if selected_profile is not None:
        for key in ('user', 'device', 'caller', 'client'):
            if key in selected_profile and not isinstance(selected_profile[key], dict):
                raise ValueError('identity.' + key + ' must be an object')
    referrer = job.get('referrer')
    if referrer is not None:
        referrer = check_url(_text(referrer, 'referrer'))
    surface = job.get('surface', 'browser')
    if surface not in ('browser', 'shell'):
        raise ValueError('surface must be browser or shell')
    if kind in ('url', 'download'):
        target = {'url': check_url(_text(job.get('url'), 'url'))}
        if referrer is not None:
            target['referrer'] = referrer
        endpoint = ENDPOINTS[kind]
        if kind == 'download':
            from smartscreen.api import download_payload
            payload = download_payload(target['url'], referrer=referrer, profile=selected_profile)
        else:
            payload = url_payload(target['url'], referrer, selected_profile)
    else:
        source = check_url(_text(job.get('source'), 'source'))
        if kind == 'file':
            path = Path(_text(job.get('path'), 'path')).expanduser()
            if not path.is_absolute():
                path = Path(base_dir or Path.cwd()) / path
            sha256, size = _hash_file(path)
            name = _filename(job.get('name', path.name))
        else:
            sha256 = job.get('sha256')
            if not isinstance(sha256, str) or not re.fullmatch('[0-9a-fA-F]{64}', sha256):
                raise ValueError('sha256 must contain exactly 64 hexadecimal characters')
            sha256 = sha256.lower()
            size = job.get('size')
            if type(size) is not int or size < 0:
                raise ValueError('size must be a nonnegative integer')
            name = _filename(job.get('name'))
        target = {'sha256': sha256, 'size': size, 'name': name, 'source': source, 'surface': surface}
        if referrer is not None:
            target['referrer'] = referrer
        if surface == 'shell':
            from smartscreen.api import shell_payload
            endpoint = ENDPOINTS['shell']
            payload = shell_payload(sha256, size, name, source, referrer=referrer, profile=selected_profile)
        else:
            endpoint = ENDPOINTS['file']
            payload = file_payload(sha256, size, name, source, selected_profile)
            if referrer is not None:
                payload['referrer'] = {'uri': referrer, 'ip': None}
    payload = apply_client_version(payload, client_version)
    effective_version = client_version_for(payload, client_version)
    stable_payload = copy.deepcopy(payload)
    stable_payload.pop('correlationId', None)
    context = redact_context({'method': 'POST', 'endpoint': endpoint, 'payload': stable_payload,
                              'surface': surface, 'auth_id': auth_id, 'client_version': effective_version})
    # File and hash jobs with identical wire metadata intentionally share a query key.
    query_key = hashlib.sha256(canonical(context).encode()).hexdigest()
    return {'kind': kind, 'job_id': job.get('id'), 'target': target, 'endpoint': endpoint,
            'payload': payload, 'query_key': query_key, 'context': context}


def _strict_json(text):
    def reject_constant(value):
        raise ValueError('Non-finite JSON constant: ' + value)
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate JSON object key: ' + key)
            result[key] = value
        return result
    return json.loads(text, parse_constant=reject_constant, object_pairs_hook=object_pairs)


def preflight(input_path, *, max_jobs=100, profile=None, auth_id=EDGE_AUTH_ID, client_version=None):
    if type(max_jobs) is not int or not 1 <= max_jobs <= MAX_JOBS:
        raise ValueError('max_jobs must be between 1 and ' + str(MAX_JOBS))
    path = Path(input_path)
    rows, input_complete = [], True
    with path.open('rb') as source:
        line_no = 0
        while True:
            raw = source.readline(MAX_LINE_BYTES + 1)
            if not raw:
                break
            line_no += 1
            if line_no > max_jobs:
                rows.append({'line_no': line_no, 'error': {'type': 'InputLimitExceeded',
                            'message': 'Input exceeds max_jobs; no requests were sent'}})
                input_complete = False
                break
            try:
                if len(raw) > MAX_LINE_BYTES:
                    raise ValueError('JSONL line exceeds ' + str(MAX_LINE_BYTES) + ' bytes')
                job = _strict_json(raw.decode('utf-8-sig' if line_no == 1 else 'utf-8'))
                planned = prepare_job(job, base_dir=path.resolve().parent, profile=profile,
                                      auth_id=auth_id, client_version=client_version)
                rows.append({'line_no': line_no, 'job': planned})
            except (ValueError, OSError, TypeError, KeyError) as error:
                rows.append({'line_no': line_no, 'error': {'type': type(error).__name__,
                                                        'message': str(error)}})
                if len(raw) > MAX_LINE_BYTES:
                    # Stop rather than reading an unbounded malformed line/file.
                    input_complete = False
                    break
    if not rows:
        rows.append({'line_no': 0, 'error': {'type': 'EmptyInput', 'message': 'Input contains no jobs'}})
    return rows, input_complete


class HistoryStore:
    """Append-only observation history with separate successful-verdict comparison."""
    def __init__(self, path, readonly=False):
        self.path = Path(path).expanduser().resolve()
        self.readonly = readonly
        if readonly:
            if not self.path.is_file():
                raise FileNotFoundError('History database does not exist: ' + str(self.path))
            self.connection = sqlite3.connect(self.path.as_uri() + '?mode=ro', uri=True, isolation_level=None)
        else:
            self.connection = sqlite3.connect(str(self.path), isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        try:
            version = self.connection.execute('PRAGMA user_version').fetchone()[0]
            if version not in (0, 1):
                raise ValueError('Unsupported SmartScreen history schema version')
            tables = {r[0] for r in self.connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            if readonly or tables:
                if 'ss_observations' not in tables:
                    raise ValueError('Not a SmartScreen history database')
            if not readonly:
                self.connection.execute('''CREATE TABLE IF NOT EXISTS ss_observations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, query_key TEXT, run_id TEXT NOT NULL,
                    line_no INTEGER NOT NULL, observed_utc TEXT NOT NULL, status TEXT NOT NULL,
                    http_status INTEGER, verdict_json TEXT, record_json TEXT NOT NULL)''')
                self.connection.execute('CREATE INDEX IF NOT EXISTS ss_query_history ON ss_observations(query_key,id)')
                self.connection.execute('PRAGMA user_version=1')
        except Exception:
            self.connection.close()
            raise

    def close(self):
        self.connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    @staticmethod
    def _brief(row):
        if row is None:
            return None
        record = json.loads(row['record_json'])
        return {'id': row['id'], 'observed_utc': record['observed_utc'], 'status': record['status'],
                'http_status': record.get('http_status'), 'verdict': record.get('verdict'),
                'response_category': record.get('response_category')}

    def append(self, record):
        if self.readonly:
            raise ValueError('History is read-only')
        stored = copy.deepcopy(record)
        canonical(stored)  # Validate before opening the write transaction.
        query_key = stored.get('query_key')
        self.connection.execute('BEGIN IMMEDIATE')
        try:
            previous = verdict_row = None
            if query_key:
                previous = self.connection.execute('SELECT * FROM ss_observations WHERE query_key=? ORDER BY id DESC LIMIT 1', (query_key,)).fetchone()
                verdict_row = self.connection.execute("SELECT * FROM ss_observations WHERE query_key=? AND status='verdict' ORDER BY id DESC LIMIT 1", (query_key,)).fetchone()
            prior_verdict = self._brief(verdict_row)
            comparable = stored['status'] == 'verdict' and prior_verdict is not None
            stored['history'] = {
                'previous_observation': self._brief(previous), 'previous_verdict': prior_verdict,
                'verdict_changed': stored.get('verdict') != prior_verdict['verdict'] if comparable else None,
                'category_changed': stored.get('response_category') != prior_verdict['response_category'] if comparable else None,
            }
            cursor = self.connection.execute('''INSERT INTO ss_observations
                (query_key,run_id,line_no,observed_utc,status,http_status,verdict_json,record_json)
                VALUES (?,?,?,?,?,?,?,?)''', (query_key, stored['run_id'], stored['line_no'],
                stored['observed_utc'], stored['status'], stored.get('http_status'),
                canonical(stored.get('verdict')), canonical(stored)))
            stored['history']['observation_id'] = cursor.lastrowid
            self.connection.execute('UPDATE ss_observations SET record_json=? WHERE id=?',
                                    (canonical(stored), cursor.lastrowid))
            self.connection.execute('COMMIT')
            return stored
        except Exception:
            self.connection.execute('ROLLBACK')
            raise

    def query(self, *, limit=100, query_key=None):
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError('History limit must be between 1 and 1000')
        if query_key is not None and (not isinstance(query_key, str) or not re.fullmatch('[0-9a-fA-F]{64}', query_key)):
            raise ValueError('query_key must be a complete SHA-256 identifier')
        sql = 'SELECT record_json FROM ss_observations'
        arguments = []
        if query_key is not None:
            sql += ' WHERE query_key=?'
            arguments.append(query_key.lower())
        sql += ' ORDER BY id DESC LIMIT ?'
        arguments.append(limit)
        return [json.loads(row[0]) for row in self.connection.execute(sql, arguments)]


def _base_record(row, run_id):
    record = {'schema_version': 1, 'run_id': run_id, 'line_no': row['line_no'], 'observed_utc': utc_now(),
              'query_key': None, 'verdict': None, 'response_category': None, 'http_status': None}
    if 'job' in row:
        job = row['job']
        record.update({key: job[key] for key in ('kind', 'job_id', 'target', 'query_key', 'context')})
        record['request'] = redact_context(job['payload'])
    return record


def run_batch(input_path, output_stream, *, client=None, history=None, profile=None,
              delay=1.0, max_jobs=100, sleep_fn=time.sleep):
    """Stream JSONL results; return a summary. Non-success remains explicit.

    `history` accepts an open HistoryStore or a database path. Paths inside file
    jobs are relative to the input JSONL directory. Output is a writable text
    stream owned by the caller. A write failure stops work; already committed
    history remains available. No automatic retries are performed.
    """
    if isinstance(delay, bool) or not isinstance(delay, (int, float)) or not math.isfinite(delay) or not 0.25 <= delay <= 3600:
        raise ValueError('delay must be between 0.25 and 3600 seconds')
    if not hasattr(output_stream, 'write') or not hasattr(output_stream, 'flush'):
        raise TypeError('output_stream must be a writable text stream')
    client = client or SmartScreenClient()
    rows, input_complete = preflight(input_path, max_jobs=max_jobs, profile=profile,
                                    auth_id=getattr(client, 'auth_id', EDGE_AUTH_ID),
                                    client_version=getattr(client, 'client_version', None))
    own_history = history is not None and not isinstance(history, HistoryStore)
    store = HistoryStore(history) if own_history else history
    run_id = str(uuid.uuid4())
    summary = {'schema_version': 1, 'run_id': run_id, 'input_complete': input_complete,
               'records': 0, 'requests_sent': 0, 'counts': {}, 'failed': 0, 'not_run': 0, 'success': False}
    invalid = any('error' in row for row in rows)
    stopped = None
    try:
        for row in rows:
            record = _base_record(row, run_id)
            if invalid:
                if 'error' in row:
                    record.update({'status': 'invalid_input', 'error': row['error']})
                else:
                    record.update({'status': 'not_run_preflight_failed',
                                   'error': {'type': 'PreflightFailed', 'message': 'Another input line failed validation; no requests were sent'}})
            elif stopped:
                record.update({'status': stopped['status'], 'error': stopped['error']})
            else:
                job = row['job']
                try:
                    if summary['requests_sent']:
                        sleep_fn(delay)
                    summary['requests_sent'] += 1
                    response, raw = client.request(job['endpoint'], job['payload'])
                    if not isinstance(response, dict) or type(response.get('http_status')) is not int or not isinstance(raw, bytes):
                        raise ValueError('Client returned an invalid response record')
                    http_status = response['http_status']
                    record.update({'http_status': http_status,
                                   'raw_response_base64': base64.b64encode(raw).decode('ascii')})
                    canonical(response)
                    record['response_record'] = response
                    if 200 <= http_status < 300:
                        record['verdict'] = response.get('verdict')
                        record['response_category'] = response.get('response_category')
                        record['status'] = 'verdict' if record['verdict'] is not None else 'no_verdict'
                    else:
                        record['status'] = 'http_error'
                        record['error'] = {'type': 'HttpError', 'message': 'SmartScreen returned HTTP ' + str(http_status)}
                    if http_status in (429, 503):
                        retry_after = next((v for k, v in response.get('headers', {}).items() if k.lower() == 'retry-after'), None)
                        stopped = {'status': 'not_run_service_unavailable', 'error': {
                            'type': 'ServiceBackoff', 'http_status': http_status, 'retry_after': retry_after,
                            'message': 'Batch stopped after HTTP ' + str(http_status) + '; remaining jobs were not sent'}}
                        record['retry_after'] = retry_after
                except KeyboardInterrupt:
                    record.update({'status': 'interrupted', 'error': {'type': 'KeyboardInterrupt', 'message': 'Batch interrupted'}})
                    stopped = {'status': 'not_run_interrupted', 'error': {'type': 'KeyboardInterrupt', 'message': 'Earlier batch item was interrupted'}}
                except (OSError, ValueError, TypeError, subprocess.TimeoutExpired) as error:
                    record.update({'status': 'request_error', 'error': {'type': type(error).__name__, 'message': str(error)}})
            if store is not None:
                record = store.append(record)
            output_stream.write(canonical(record) + '\n')
            output_stream.flush()
            summary['records'] += 1
            status = record['status']
            summary['counts'][status] = summary['counts'].get(status, 0) + 1
            if status.startswith('not_run_'):
                summary['not_run'] += 1
            elif status != 'verdict':
                summary['failed'] += 1
        summary['success'] = input_complete and summary['records'] > 0 and summary['counts'].get('verdict', 0) == summary['records']
        summary['completed_utc'] = utc_now()
        return summary
    finally:
        if own_history:
            store.close()

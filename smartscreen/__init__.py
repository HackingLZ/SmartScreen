#!/usr/bin/env python3
"""SmartScreen API/feed client with optional local scareware image inference."""
import argparse
import base64
import copy
import contextlib
from datetime import datetime, timezone
import gzip
import hashlib
import json
import math
import re
from pathlib import Path
import ssl
import sqlite3
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid

from smartscreen.auth import authorization, EDGE_AUTH_ID

ENDPOINTS = {
    'url': 'https://nav-edge.smartscreen.microsoft.com/api/browser/edge/navigate/3/sync',
    'url-async': 'https://nav-edge.smartscreen.microsoft.com/api/browser/edge/navigate/3',
    'download': 'https://dl-edge.smartscreen.microsoft.com/api/browser/edge/download/3',
    'file': 'https://app-edge.smartscreen.microsoft.com/api/browser/edge/downloadcomplete/3',
    'actions': 'https://ping-edge.smartscreen.microsoft.com/api/browser/edge/actions/3',
    'shell': 'https://checkappexec.microsoft.com/windows/shell/service/beforeExecute/2',
}
DATA_ENDPOINTS = {
    'topTraffic': 'https://data-edge.smartscreen.microsoft.com/api/browser/edge/data/toptraffic/3',
    'synchronousLookupUris': 'https://data-edge.smartscreen.microsoft.com/api/browser/edge/data/bloomfilter/x/3',
    'customSynchronousLookupUris': 'https://data-edge.smartscreen.microsoft.com/api/browser/edge/data/bloomfilter/e5/3',
    'edgeSettings': 'https://data-edge.smartscreen.microsoft.com/api/browser/edge/data/settings/3',
    'customSettings': 'https://data-edge.smartscreen.microsoft.com/api/browser/edge/data/categoryBrowsers/3',
}
CLIENT_VERSION = str((1 << 48) | (2 << 32) | (2312 << 16) | 1)
DATASETS = ('topTraffic', 'customSynchronousLookupUris', 'edgeSettings', 'synchronousLookupUris', 'customSettings')
INITIAL_DATASET_VERSIONS = {name: ('2.0-0' if name == 'edgeSettings' else '0') for name in DATASETS}
CONFIG = {
    'user': {'uriReputation': {'enforcedByPolicy': False, 'level': 'warn'}},
    'device': {'appControl': {'level': 'anywhere'},
               'appReputation': {'enforcedByPolicy': False, 'level': 'warn'}},
}


def identity():
    return {
        'user': {'locale': 'en-US'},
        'device': {'id': None, 'customId': None, 'onlineIdTicket': '', 'family': 3,
                   'locale': 'en-US', 'osVersion': '10.0.22621',
                   'browser': {'internetExplorer': ''}, 'netJoinStatus': 0,
                   'enterprise': {}, 'cloudSku': False, 'architecture': 12},
        'caller': {'locale': 'en-US', 'name': '', 'version': '158.0.4370.33'},
        'client': {'version': CLIENT_VERSION, 'data': {}},
    }


def check_url(url, service=False):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in (('https',) if service else ('http', 'https')) or not parsed.hostname:
        raise ValueError('Expected an absolute HTTP(S) URL')
    if parsed.username or parsed.password:
        raise ValueError('URLs with embedded credentials are not supported')
    if service:
        host = parsed.hostname.lower()
        if parsed.port not in (None, 443) or not (
            host == 'checkappexec.microsoft.com' or
            host == 'smartscreen-prod.microsoft.com' or
            host.endswith('.smartscreen.microsoft.com') or host.endswith('.ss.wd.microsoft.us')
        ):
            raise ValueError('Service requests require an identified Microsoft SmartScreen HTTPS host')
    return url


def url_payload(url, referrer=None, profile=None, *, synchronous=True):
    if type(synchronous) is not bool:
        raise ValueError('synchronous must be a bool')
    return {
        'userAgent': 'Mozilla/5.0 (Windows NT 10.0; Win64; ARM64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36 Edg/158.0.0.0',
        'identity': copy.deepcopy(profile) if profile is not None else identity(),
        'config': copy.deepcopy(CONFIG), 'destination': {'uri': check_url(url), 'ip': None},
        'referrer': {'uri': check_url(referrer) if referrer else '', 'ip': None},
        'type': 'top', 'forceServiceDetermination': False,
        'correlationId': str(uuid.uuid4()), 'synchronous': synchronous,
    }


def file_payload(sha256, size, filename, source, profile=None):
    if not isinstance(sha256, str) or not re.fullmatch(r'[0-9a-fA-F]{64}', sha256):
        raise ValueError('SHA-256 must contain 64 hexadecimal characters')
    raw_hash = bytes.fromhex(sha256)
    if type(size) is not int or size < 0:
        raise ValueError('File size must be nonnegative')
    if not isinstance(filename, str) or not filename or '\0' in filename:
        raise ValueError('Filename must be a nonempty string without NUL bytes')
    payload = url_payload(source, profile=profile)
    for field in ('userAgent', 'type', 'forceServiceDetermination', 'synchronous'):
        del payload[field]
    payload['file'] = {'authenticode': {}, 'fileId': None,
                       'hash': base64.b64encode(raw_hash).decode(),
                       'path': {'driveType': 3, 'fileName': filename},
                       'size': str(size), 'version': 1}
    return payload


def encode_request(payload):
    return json.dumps(payload, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def client_version_for(payload=None, override=None):
    version = override
    if version is None and isinstance(payload, dict):
        client = payload.get('identity', {}).get('client', {}) if isinstance(payload.get('identity'), dict) else {}
        if isinstance(client, dict):
            version = client.get('version')
    version = CLIENT_VERSION if version is None else str(version)
    if not re.fullmatch(r'[0-9]{1,20}', version) or int(version) > 0xffffffffffffffff:
        raise ValueError('SmartScreen client version must be a packed unsigned 64-bit decimal integer')
    return version


def apply_client_version(payload, override=None):
    """Apply an explicit protocol version consistently without mutating caller data."""
    if override is None or payload is None:
        return payload
    if not isinstance(payload, dict):
        raise ValueError('A client-version override requires a JSON object body')
    payload = copy.deepcopy(payload)
    device_identity = payload.setdefault('identity', {})
    if not isinstance(device_identity, dict) or not isinstance(device_identity.get('client', {}), dict):
        raise ValueError('Request identity and identity.client must be objects')
    device_identity.setdefault('client', {})['version'] = client_version_for(override=override)
    return payload


def request_headers(body, auth_id=EDGE_AUTH_ID, client_version=CLIENT_VERSION):
    if body is None:
        auth = 'SmartScreenPlain ' + base64.b64encode(encode_request({'authId': auth_id})).decode()
    else:
        auth = authorization(body, auth_id)
    return {'Authorization': auth, 'User-Agent': 'SmartScreen/' + client_version_for(override=client_version),
            'Content-Type': 'application/json; charset=utf-8', 'Accept': '*/*'}


def decision_fields(value, path='$'):
    """Expose exact server fields; never infer 'clean' from an empty response."""
    result = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = path + '.' + key
            if key.lower() in {'verdict', 'rating', 'determination', 'reputation', 'category', 'confidence', 'ttl', 'maxage', 'responsecategory', '$type'}:
                result.append({'path': child_path, 'value': child})
            result.extend(decision_fields(child, child_path))
    elif isinstance(value, list):
        for i, child in enumerate(value):
            result.extend(decision_fields(child, path + '[' + str(i) + ']'))
    return result


def response_record(url, status, headers, raw):
    try:
        parsed = json.loads(raw)
    except (ValueError, UnicodeError):
        parsed = None
    content_type = next((v for k, v in dict(headers).items() if k.lower() == 'content-type'), '')
    result = parsed.get('result') if isinstance(parsed, dict) else None
    rating = parsed.get('rating') if isinstance(parsed, dict) else None
    http_ok = 200 <= status < 300
    verdict = category = verdict_source = None
    if http_ok and isinstance(parsed, dict):
        if isinstance(result, dict) and '$type' in result:
            verdict, verdict_source = result['$type'], 'result.$type'
        elif '$type' in parsed:
            verdict, verdict_source = parsed['$type'], '$type'
        elif (url == ENDPOINTS['file'] and isinstance(rating, str)
              and rating in {'allow', 'unknown'}):
            verdict, verdict_source = rating, 'rating'
        category = result.get('responseCategory') if isinstance(result, dict) else parsed.get('responseCategory')
    return {'schema_version': 1, 'collected_utc': datetime.now(timezone.utc).isoformat(),
            'endpoint': url, 'http_status': status, 'headers': dict(headers),
            'http_ok': http_ok,
            'response_sha256': hashlib.sha256(raw).hexdigest(), 'response_size': len(raw),
            'response': parsed, 'response_text': raw.decode('utf-8', errors='replace') if parsed is None and content_type.startswith('text/') else None,
            'verdict': verdict, 'response_category': category, 'rating': rating,
            'verdict_source': verdict_source,
            'decision_fields': decision_fields(parsed),
            'interpretation': 'Server fields are preserved verbatim. HTTP success alone is not a reputation verdict.'}


class SmartScreenClient:
    def __init__(self, timeout=25, auth_id=EDGE_AUTH_ID, max_bytes=32 * 1024 * 1024, transport='auto', client_version=None):
        if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError('Timeout must be positive and finite')
        if type(max_bytes) is not int or max_bytes <= 0:
            raise ValueError('Response size limit must be a positive integer')
        if transport not in ('auto', 'curl', 'urllib'):
            raise ValueError('Unrecognized transport')
        self.timeout, self.auth_id, self.max_bytes = timeout, auth_id, max_bytes
        self.client_version = client_version_for(override=client_version) if client_version is not None else None
        self.transport = ('curl' if shutil.which('curl') else 'urllib') if transport == 'auto' else transport
        self.opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))

    def request(self, endpoint, payload=None, method=None, *, accept=None, dataset_version=None):
        check_url(endpoint, service=True)
        if method not in (None, 'GET', 'POST'):
            raise ValueError('Supported request methods are GET and POST')
        payload = apply_client_version(payload, self.client_version)
        body = encode_request(payload) if payload is not None else None
        version = client_version_for(payload, self.client_version)
        headers = request_headers(body, self.auth_id, version)
        if accept is not None:
            if not isinstance(accept, str) or not re.fullmatch(r'[\x20-\x7e]{1,256}', accept):
                raise ValueError('Accept must be a short printable ASCII header value')
            headers['Accept'] = accept
        if dataset_version is not None:
            if not isinstance(dataset_version, str) or not re.fullmatch(r'[\x21\x23-\x7e]{1,256}', dataset_version):
                raise ValueError('Dataset version must be a printable unquoted ETag value')
            headers['If-None-Match'] = '"' + dataset_version + '"'
        if self.transport == 'curl':
            return self._curl(endpoint, body, method, version, headers)
        request = urllib.request.Request(endpoint, data=body, headers=headers,
                                         method=method or ('POST' if body is not None else 'GET'))
        try:
            response = self.opener.open(request, timeout=self.timeout)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read(self.max_bytes + 1)
            if len(raw) > self.max_bytes:
                raise ValueError('Response exceeds configured size limit')
            if response.headers.get('Content-Encoding', '').lower() == 'gzip':
                raw = gzip.decompress(raw)
                if len(raw) > self.max_bytes:
                    raise ValueError('Expanded response exceeds configured size limit')
            record = response_record(endpoint, response.status, response.headers, raw)
            record['transport'] = 'urllib'
            record['request_client_version'] = version
            return record, raw

    def _curl(self, endpoint, body, method, version=CLIENT_VERSION, headers=None):
        # Python owns request serialization and signing; curl provides optional HTTP transport.
        with tempfile.TemporaryDirectory(prefix='smartscreen-') as directory:
            root = Path(directory)
            headers_path, body_path = root / 'headers', root / 'body'
            config = ['url = ' + json.dumps(endpoint), 'request = ' + json.dumps(method or ('POST' if body is not None else 'GET'))]
            for key, value in (headers if headers is not None else request_headers(body, self.auth_id, version)).items():
                config.append('header = ' + json.dumps(key + ': ' + value))
            if body is not None:
                payload_path = root / 'request'
                payload_path.write_bytes(body)
                config.append('data-binary = ' + json.dumps('@' + str(payload_path)))
            run = subprocess.run(['curl', '-sS', '--config', '-', '--no-insecure', '--no-location', '--max-time', str(self.timeout),
                                  '--connect-timeout', str(min(10, self.timeout)),
                                  '--max-filesize', str(self.max_bytes), '--proto', '=https',
                                  '--dump-header', str(headers_path), '--output', str(body_path),
                                  '--write-out', '%{http_code}'], input='\n'.join(config) + '\n',
                                 text=True, capture_output=True, timeout=self.timeout + 5)
            if run.returncode:
                raise OSError(run.stderr.strip() or 'curl transport failed')
            if body_path.exists() and body_path.stat().st_size > self.max_bytes:
                raise ValueError('Response exceeds configured size limit')
            raw = body_path.read_bytes() if body_path.exists() else b''
            headers = {}
            for line in headers_path.read_text(encoding='iso-8859-1').splitlines():
                if line.startswith('HTTP/'):
                    headers = {}
                elif ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
            record = response_record(endpoint, int(run.stdout.strip()), headers, raw)
            record['transport'] = 'curl'
            record['request_client_version'] = version
            return record, raw

    def lists(self, profile=None, download=None, cache_dir=None):
        profile = copy.deepcopy(profile) if profile is not None else identity()
        if not isinstance(profile, dict) or not isinstance(profile.get('client', {}), dict):
            raise ValueError('Identity and identity.client must be objects')
        versions = profile.setdefault('client', {}).setdefault('data', {})
        if not isinstance(versions, dict):
            raise ValueError('Identity client.data must be an object of dataset versions')
        explicit_versions = set(versions)
        for name in DATASETS:
            versions.setdefault(name, INITIAL_DATASET_VERSIONS[name])
        if any(not isinstance(value, str) or not re.fullmatch(r'[\x21\x23-\x7e]{1,256}', value)
               for value in versions.values()):
            raise ValueError('Dataset versions must be printable unquoted ETag strings')
        if cache_dir is not None and download is None:
            raise ValueError('A feed cache requires a download snapshot directory')
        profile = apply_client_version({'identity': profile}, self.client_version)['identity']
        payload = {'identity': profile}
        record, _ = self.request(ENDPOINTS['actions'], payload)
        document = record['response'] if isinstance(record['response'], dict) else {}
        actions = document.get('actions', [])
        datasets = [a for a in actions if isinstance(a, dict) and a.get('$type') == 'data']
        record['datasets'] = datasets
        record['requested_dataset_versions'] = dict(versions)
        record['unadvertised_datasets'] = [name for name in DATASETS if not any(a.get('id') == name for a in datasets)]
        if download:
            from smartscreen.data import inspect_data
            download = Path(download)
            download.mkdir(parents=True, exist_ok=True)
            saved = []
            for action in datasets:
                name, verb = action.get('id'), action.get('verb', 'GET')
                if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', name) or verb not in {'GET', 'POST'}:
                    saved.append({'id': name, 'skipped': 'Unrecognized dataset id or method', 'action': action})
                    continue
                requested_version = versions.get(name, '0')
                feed_identity = copy.deepcopy(profile)
                if cache_dir is not None:
                    from smartscreen.feedcache import lookup_cached_feed, cache_feed_response
                    cached = lookup_cached_feed(cache_dir, name, endpoint=action['uri'],
                                                identity=feed_identity, method=verb, auth_id=self.auth_id)
                    if cached is not None and name not in explicit_versions:
                        requested_version = cached['version']
                        feed_identity['client']['data'][name] = requested_version
                result, raw = self.request(action['uri'], {'identity': feed_identity} if verb == 'POST' else None, verb,
                                           accept='application/octet-stream;', dataset_version=requested_version)
                result['requested_dataset_version'] = requested_version
                cache_state = None
                if cache_dir is not None:
                    cache_state = cache_feed_response(cache_dir, name, result, raw, identity=feed_identity,
                                                     requested_version=requested_version, method=verb, auth_id=self.auth_id)
                    result['feed_cache'] = cache_state
                if (name == 'customSettings' and verb == 'POST' and name not in explicit_versions
                        and requested_version == '0' and result['http_status'] == 304 and not raw
                        and (cache_state is None or cache_state['state'] != 'not_modified_cached')):
                    # Edge's builtin version is a request baseline, never a cached HTTP body.
                    # The service advertises this feed at version 0 but returns a body only
                    # after the native baseline is supplied in identity.client.data.
                    first_attempt = copy.deepcopy(result)
                    requested_version = 'F95BA787499AB4FA9EFFF472CE383A14'
                    feed_identity['client']['data'][name] = requested_version
                    result, raw = self.request(action['uri'], {'identity': feed_identity}, verb,
                                               accept='application/octet-stream;', dataset_version=requested_version)
                    result['requested_dataset_version'] = requested_version
                    cache_state = None
                    if cache_dir is not None:
                        cache_state = cache_feed_response(cache_dir, name, result, raw, identity=feed_identity,
                                                         requested_version=requested_version, method=verb, auth_id=self.auth_id)
                        result['feed_cache'] = cache_state
                    result['acquisition'] = {
                        'strategy': 'custom_settings_native_version_bootstrap',
                        'discovery_version': versions[name],
                        'bootstrap_version': requested_version,
                        'version_source': 'Edge 158.0.4370.33 native builtin and clean-profile wire capture',
                        'builtin_body_used': False,
                        'attempts': [first_attempt, copy.deepcopy(result)],
                    }
                metadata_path = download / (name + '.response.json')
                saved_item = {'id': name, 'http_status': result['http_status'], 'metadata': str(metadata_path)}
                if result['http_status'] == 200:
                    path = download / (name + '.bin')
                    path.write_bytes(raw)
                    result['dataset'] = inspect_data(raw, name)
                    result['body_file'] = str(path)
                    saved_item.update({'body': str(path), 'size': len(raw), 'summary': result['dataset']})
                elif result['http_status'] == 304:
                    if cache_state and cache_state['state'] == 'not_modified_cached':
                        path = download / (name + '.bin')
                        cached_raw = Path(cache_state['body_file']).read_bytes()
                        if hashlib.sha256(cached_raw).hexdigest() != cache_state['sha256'] or len(cached_raw) != cache_state['size']:
                            raise ValueError('Cached feed changed before snapshot materialization')
                        path.write_bytes(cached_raw)
                        result['dataset'] = inspect_data(cached_raw, name)
                        result['body_file'] = str(path)
                        saved_item.update({'state': 'not_modified_cached', 'body':str(path),
                                           'size':len(cached_raw),'summary':result['dataset'],
                                           'body_origin':'previous_verified_http_200'})
                    else:
                        saved_item['state'] = 'not_modified_no_body'
                metadata_path.write_text(json.dumps(result, indent=2) + '\n')
                saved.append(saved_item)
            record['downloads'] = saved
            manifest = {'schema_version': 1, 'collected_utc': record['collected_utc'],
                        'client_version': client_version_for(payload, self.client_version),
                        'requested_dataset_versions': dict(versions),
                        'discovery_endpoint': ENDPOINTS['actions'], 'discovery_http_status': record['http_status'],
                        'unadvertised_datasets': record['unadvertised_datasets'],
                        'datasets': saved}
            manifest_path = download / 'manifest.json'
            manifest_path.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
            record['manifest'] = str(manifest_path)
        return record


def prepare_request(directory, endpoint, payload, auth_id, client_version=None, *,
                    method=None, accept=None, dataset_version=None):
    """Save fresh wire bytes for inspection or use with curl --config."""
    if method not in (None, 'GET', 'POST'):
        raise ValueError('Supported request methods are GET and POST')
    payload = apply_client_version(payload, client_version)
    body = encode_request(payload) if payload is not None else None
    headers = request_headers(body, auth_id, client_version_for(payload, client_version))
    if accept is not None:
        if not isinstance(accept, str) or not re.fullmatch(r'[\x20-\x7e]{1,256}', accept):
            raise ValueError('Accept must be a short printable ASCII header value')
        headers['Accept'] = accept
    if dataset_version is not None:
        if not isinstance(dataset_version, str) or not re.fullmatch(r'[\x21\x23-\x7e]{1,256}', dataset_version):
            raise ValueError('Dataset version must be a printable unquoted ETag value')
        headers['If-None-Match'] = '"' + dataset_version + '"'
    config = ['url = ' + json.dumps(check_url(endpoint, service=True)),
              'request = ' + json.dumps(method or ('POST' if body is not None else 'GET')),
              'max-time = 25', 'connect-timeout = 10', 'no-insecure', 'no-location']
    directory.mkdir(parents=True, exist_ok=True)
    for key, value in headers.items():
        config.append('header = ' + json.dumps(key + ': ' + value))
    if body is not None:
        path = (directory / 'request.json').resolve()
        path.write_bytes(body)
        config.append('data-binary = ' + json.dumps('@' + str(path)))
    (directory / 'curl.conf').write_text('\n'.join(config) + '\n')
    return {'prepared': str(directory), 'endpoint': endpoint, 'body_size': len(body) if body else 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--timeout', type=float, default=25)
    parser.add_argument('--transport', choices=['auto', 'urllib', 'curl'], default='auto', help='auto uses curl when available, otherwise standard-library HTTPS')
    parser.add_argument('--auth-id', default=EDGE_AUTH_ID)
    parser.add_argument('--identity', type=Path, help='Optional caller/device/client identity JSON')
    parser.add_argument('--client-version', help='Packed decimal protocol version, applied to identity and HTTP User-Agent')
    parser.add_argument('--prepare', type=Path, help='Write fresh request bytes and curl config without sending')
    parser.add_argument('-o', '--output', type=Path, help='Save complete response record as JSON')
    parser.add_argument('--body-output', type=Path, help='Save exact response bytes, including binary datasets')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('endpoints', help='Show observed API endpoints and validation status without network requests')
    url = sub.add_parser('url', help='Retrieve URL reputation')
    url.add_argument('url')
    url.add_argument('--referrer')
    url.add_argument('--mode', choices=('sync', 'async'), default='sync', help='async uses the native Edge navigate/3 route; evaluate requires page-model follow-up')
    netlog = sub.add_parser('inspect-netlog', help='Parse captured SmartScreen HTTP/2 bodies and correlate navigation stages offline')
    netlog.add_argument('file', type=Path)
    netlog.add_argument('--include-sensitive', action='store_true', help='Include exact captured local body bytes and credentials; default reports redact them')
    protocol = sub.add_parser('inspect-protocol', help='Inspect response codes, telemetry or scareware envelopes offline')
    protocol.add_argument('file', type=Path)
    protocol.add_argument('--kind', choices=('auto', 'response', 'telemetry', 'scareware', 'netlog'), default='auto')
    protocol.add_argument('--include-sensitive', action='store_true', help='Include captured contexts and URLs; identity fields remain omitted')
    protocol.add_argument('--limit', type=int, default=100)
    contexts = sub.add_parser('correlate-contexts', help='Compare exact serverContext strings in a parsed NetLog offline')
    contexts.add_argument('file', type=Path, help='JSON output from inspect-netlog')
    contexts.add_argument('--limit', type=int, default=100)
    download = sub.add_parser('download', help='Query the browser download pre-check reputation API')
    download.add_argument('url')
    download.add_argument('--referrer')
    sub.add_parser('actions', help='Retrieve server actions and advertised dataset updates')
    lists = sub.add_parser('lists', help='Discover datasets using settings format 2; explicit profile versions are preserved')
    lists.add_argument('--download', type=Path, help='Fetch advertised datasets and save bytes, headers, and decoded summaries')
    lists.add_argument('--feed-cache', type=Path, help='Persist verified full bodies and reuse them only for matching conditional 304 responses')
    inspect = sub.add_parser('inspect-data', help='Decode a downloaded feed locally')
    inspect.add_argument('file', type=Path)
    inspect.add_argument('--kind', choices=DATASETS)
    lookup = inspect.add_mutually_exclusive_group()
    lookup.add_argument('--key', help='Check an exact top-traffic or Bloom key; no URL normalization is applied')
    lookup.add_argument('--url', help='Generate native-compatible candidates for supported ASCII HTTP(S) URLs')
    model = sub.add_parser('inspect-model', help='Read model metadata and test feature hashes locally')
    model.add_argument('file', type=Path)
    model.add_argument('--token', help='Look up one candidate token without producing a title verdict')
    model.add_argument('--model', help='Model name to search with --token (defaults to the sole model)')
    model.add_argument('--full', action='store_true', help='Include all model weights and the complete JSON document')
    score = sub.add_parser('score-title', help='Evaluate a supported local title model; not a cloud or enforcement verdict')
    score.add_argument('file', type=Path)
    score.add_argument('title')
    score.add_argument('--model')
    vision_fetch = sub.add_parser('vision-download', help='Download and verify the local scareware model, vectors and allowlist')
    vision_fetch.add_argument('directory', type=Path)
    vision_fetch.add_argument('--edge-version', default='158.0.4370.33')
    vision_fetch.add_argument('--architecture', choices=('arm64', 'x64', 'x86'), default='arm64')
    vision_fetch.add_argument('--download-timeout', type=float, default=600)
    vision_inspect = sub.add_parser('inspect-vision', help='Inspect a verified scareware model bundle locally')
    vision_inspect.add_argument('directory', type=Path)
    vision_score = sub.add_parser('score-image', help='Run the extracted scareware image model locally')
    vision_score.add_argument('image', type=Path)
    vision_score.add_argument('--assets', type=Path, required=True, help='Directory created by vision-download')
    vision_score.add_argument('--scaling', choices=('ShortEdge', 'CropCenter', 'Resize'), default='ShortEdge')
    vision_score.add_argument('--resize-method', choices=('resize_good', 'resize_better', 'resize_best', 'resize_box', 'resize_hamming1', 'resize_lanczos3'), default='resize_lanczos3')
    vision_score.add_argument('--tensor-set-index', type=int, default=0, help='Zero-based set index; researched native fallback is 0')
    vision_score.add_argument('--include-embedding', action='store_true')
    vision_score.add_argument('--threads', type=int, default=1)
    offline = sub.add_parser('offline-url', help='Check downloaded URL feed membership without contacting Microsoft')
    offline.add_argument('url')
    offline.add_argument('--feeds', type=Path, required=True)
    offline.add_argument('--defaults', type=Path, help='Optional separately extracted native fallback directory')
    candidates = sub.add_parser('map-candidates', help='Associate a local candidate list with stored hashes; never a blocklist export')
    candidates.add_argument('dataset', type=Path)
    candidates.add_argument('candidates', type=Path, nargs='+')
    candidates.add_argument('--kind', required=True, choices=('topTraffic', 'model'))
    candidates.add_argument('--input-format', choices=('lines', 'ranked-domains'), default='lines')
    candidates.add_argument('--domain-variants', action='store_true')
    candidates.add_argument('--model')
    candidates.add_argument('--max-candidates', type=int, default=1000000)
    candidates.add_argument('--limit', type=int, default=50000)
    compare = sub.add_parser('compare-feeds', help='Compare two feed files or snapshot directories locally')
    compare.add_argument('before', type=Path)
    compare.add_argument('after', type=Path)
    compare.add_argument('--kind', choices=DATASETS)
    compare.add_argument('--limit', type=int, default=100, help='Maximum reported changes; total counts remain available')
    batch = sub.add_parser('batch', help='Query JSONL jobs sequentially and record SQLite history')
    batch.add_argument('input', type=Path)
    batch.add_argument('--history', type=Path, default=Path('local/history.sqlite3'))
    batch.add_argument('--delay', type=float, default=1.0)
    batch.add_argument('--max-jobs', type=int, default=100)
    history = sub.add_parser('history', help='Read previously recorded batch results without network requests')
    history.add_argument('database', nargs='?', type=Path, default=Path('local/history.sqlite3'))
    history.add_argument('--limit', type=int, default=20)
    history.add_argument('--query-key')
    export = sub.add_parser('export-verdicts', help='Export latest observed URL warnings/blocks from batch JSONL or SQLite; not a global blocklist')
    export.add_argument('inputs', type=Path, nargs='+')
    export.add_argument('--verdict', action='append', choices=('allow','warn','block','unknown','evaluate','call_server'), help='Repeat to select verdicts; default warn and block')
    export.add_argument('--kind', action='append', choices=('url','download'), help='Repeat to select surfaces; default url')
    export.add_argument('--max-records', type=int, default=100000)
    observed = sub.add_parser('observed-url', help='Look up an exact URL in a historical verdict export, entirely offline')
    observed.add_argument('url')
    observed.add_argument('--catalog', type=Path, required=True)
    importing = sub.add_parser('cache-import', help='Import server cache actions as local routing evidence')
    importing.add_argument('responses', nargs='+', type=Path)
    importing.add_argument('--scope', choices=('navigation','download'))
    importing.add_argument('--received-at', help='Explicit ISO insertion-time approximation; otherwise use recorded collection time')
    importing.add_argument('--context', type=Path, help='Explicit shared runtime/profile/policy context JSON for combining response actions')
    from smartscreen.cache import READER_SEMANTICS
    importing.add_argument('--reader', choices=READER_SEMANTICS,
                           help='Override native reader; known recorded SDKs select automatically, otherwise an explicit Edge158 assumption is reported')
    cache_lookup = sub.add_parser('cache-url', help='Replay validated URI cache routing rules locally')
    cache_lookup.add_argument('url')
    cache_lookup.add_argument('--cache', type=Path, required=True)
    cache_lookup.add_argument('--at', help='ISO time for historical lookup; default now')
    cache_lookup.add_argument('--scope', choices=('navigation','download'))
    native_cache = sub.add_parser('inspect-cache', help='Parse a saved native Edge cache or its sibling pointer file')
    native_cache.add_argument('file', type=Path)
    native_cache.add_argument('--at')
    native_cache.add_argument('--url', help='Look up a supplied URL candidate in the current Edge persisted cache')
    explain = sub.add_parser('explain-url', help='Explain recovered conditional decision stages using supplied local evidence')
    explain.add_argument('url')
    explain.add_argument('--feeds', type=Path)
    explain.add_argument('--defaults', type=Path)
    explain.add_argument('--title')
    explain.add_argument('--settings', type=Path)
    explain.add_argument('--model')
    explain.add_argument('--cloud-response', type=Path)
    explain.add_argument('--cache', type=Path)
    explain.add_argument('--at')
    explain.add_argument('--navigation-type', choices=('top','frame','subresource','download'), default='top')
    completion = sub.add_parser('navigation-complete', help='Send or prepare the native page-model follow-up with explicit context, models and signals')
    completion.add_argument('--context', type=Path, required=True)
    completion.add_argument('--models', type=Path, required=True)
    completion.add_argument('--signals', type=Path, required=True)
    completion.add_argument('--server-context')
    signature = sub.add_parser('inspect-signature', help='Inspect PE metadata and optional Windows SIP/catalog trust without executing the file')
    signature.add_argument('file', type=Path)
    signature.add_argument('--windows-trust', action='store_true', help='Also run Windows cached WinVerifyTrust; no network retrieval or catalog search')
    signature.add_argument('--windows-catalog', action='store_true', help='Enumerate matching local catalogs and cached Windows member trust, keeping each observation separate')
    signature.add_argument('--catalog-index', type=int, help='Explicitly select this catalog observation for wire metadata; requires --windows-catalog')
    inspect_package = sub.add_parser('inspect-package', help='Read Appx/MSIX footprint metadata locally; no installation or signature trust validation')
    inspect_package.add_argument('path', type=Path, help='Individual Appx/MSIX archive or installed package directory')
    inspect_package.add_argument('--full-name', help='Explicit package full name; required outside Windows')
    package = sub.add_parser('package', help='Prepare or query package-install reputation metadata without installing the package')
    package.add_argument('path', type=Path, help='Individual Appx/MSIX archive or installed package directory')
    package.add_argument('--full-name', help='Explicit package full name; required outside Windows')
    package.add_argument('--location', required=True, help='Original package URI or path, according to --location-type')
    package.add_argument('--location-type', choices=('uri', 'path'), default='uri')
    package.add_argument('--dependencies', type=Path, help='JSON array of dependency package rows containing fullName,name,publisher,hash,signature')
    package.add_argument('--config', type=Path, help='Explicit package reputation policy configuration JSON; omitted by default')
    package.add_argument('--ux-enabled', action='store_true', help='Set the request uxEnabled field; does not display UI or install anything')
    file = sub.add_parser('file', help='Query metadata and SHA-256 of a local file; file bytes are not uploaded')
    file.add_argument('file', type=Path)
    file.add_argument('--source', required=True)
    file.add_argument('--referrer')
    file.add_argument('--surface', choices=['browser', 'shell'], default='browser')
    file.add_argument('--include-signatures', action='store_true', help='Add recovered embedded signature metadata; unknown validity and chain fields are omitted')
    file.add_argument('--signature-windows-trust', action='store_true', help='With --include-signatures, add a cached Windows trust observation')
    file.add_argument('--signature-windows-catalog', action='store_true', help='With --include-signatures, collect local catalog membership and cached trust')
    file.add_argument('--signature-catalog-index', type=int, help='Explicit catalog observation to enrich from; requires --signature-windows-catalog')
    hash_parser = sub.add_parser('hash', help='Query file reputation from explicit metadata')
    hash_parser.add_argument('sha256')
    hash_parser.add_argument('--size', required=True, type=int)
    hash_parser.add_argument('--name', required=True)
    hash_parser.add_argument('--source', required=True)
    hash_parser.add_argument('--referrer')
    hash_parser.add_argument('--surface', choices=['browser', 'shell'], default='browser')
    raw = sub.add_parser('request', help='Use an explicitly specified SmartScreen endpoint and JSON body')
    raw.add_argument('endpoint')
    raw.add_argument('--json', type=Path)
    raw.add_argument('--method', choices=('GET', 'POST'))
    raw.add_argument('--accept', help='Explicit HTTP Accept value')
    raw.add_argument('--dataset-version', help='Unquoted dataset ETag for If-None-Match')
    args = parser.parse_args()
    package_inputs = []
    try:
        if args.command in {'inspect-package', 'package'}:
            from smartscreen.package import FOOTPRINT, extract_package
            if args.command == 'inspect-package' and (args.prepare or args.body_output):
                raise ValueError('Package inspection is an offline JSON operation')
            package_inputs = [path for path in (args.path, args.identity,
                getattr(args, 'dependencies', None), getattr(args, 'config', None)) if path is not None]
            package_outputs = [path for path in (args.output, args.body_output) if path is not None]
            if args.prepare:
                package_outputs += [args.prepare / name for name in ('request.json', 'curl.conf')]
            if args.path.is_dir():
                package_root = args.path.resolve()
                if any(target.resolve() == package_root or package_root in target.resolve().parents
                       for target in package_outputs):
                    raise ValueError('Package outputs and prepared artifacts must remain outside the input package directory')
                package_inputs += [args.path / name for name in FOOTPRINT]
                # A destination with multiple hard links could alias any package
                # payload file, not just its three footprint files. Inspect names
                # and inodes only; do not read or execute package payloads.
                if any(target.is_file() and target.stat().st_nlink > 1 for target in package_outputs):
                    for candidate in args.path.rglob('*'):
                        if candidate.is_file():
                            package_inputs.append(candidate)
                            if len(package_inputs) > 100000:
                                raise ValueError('Package output alias check exceeds the file-count limit')
            if any(target.resolve() == source.resolve() or
                   (target.exists() and source.exists() and target.samefile(source))
                   for target in package_outputs for source in package_inputs):
                raise ValueError('Package output must not overwrite package, identity, dependency, or config inputs')
            if args.command == 'inspect-package':
                result = extract_package(args.path, full_name=args.full_name)
                output = json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False) + '\n'
                if args.output:
                    args.output.write_text(output, encoding='utf-8')
                else:
                    print(output, end='')
                return 0
        if args.command in {'inspect-protocol', 'correlate-contexts'}:
            from smartscreen.protocol import inspect_protocol, correlate_contexts, MAX_DOCUMENT_BYTES
            if args.prepare or args.body_output:
                raise ValueError('Protocol inspection is an offline JSON operation')
            if args.output and (args.output.resolve() == args.file.resolve() or
                    (args.output.exists() and args.file.exists() and args.output.samefile(args.file))):
                raise ValueError('Protocol output must not overwrite its input')
            with args.file.open('rb') as source:
                document = source.read(MAX_DOCUMENT_BYTES + 1)
            if args.command == 'inspect-protocol':
                result = inspect_protocol(document, kind=args.kind,
                                          include_sensitive=args.include_sensitive, limit=args.limit)
            else:
                result = correlate_contexts(document, limit=args.limit)
            output = json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False) + '\n'
            if args.output:
                args.output.write_text(output, encoding='utf-8')
            else:
                print(output, end='')
            return 0
        if args.command == 'inspect-netlog':
            from smartscreen.netlog import parse_netlog
            if args.prepare or args.body_output:
                raise ValueError('Netlog inspection is an offline JSON operation')
            if args.output and (args.output.resolve() == args.file.resolve() or
                    (args.output.exists() and args.file.exists() and args.output.samefile(args.file))):
                raise ValueError('Netlog output must not overwrite the input capture')
            result = parse_netlog(args.file, redact_sensitive=not args.include_sensitive)
            output = json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False) + '\n'
            if args.output:
                args.output.write_text(output, encoding='utf-8')
            else:
                print(output, end='')
            return 0
        if args.command == 'inspect-signature':
            from smartscreen.signatures import extract_signatures
            if args.prepare or args.body_output:
                raise ValueError('Signature inspection does not support --prepare or --body-output')
            if args.output and (args.output.resolve() == args.file.resolve() or
                    (args.output.exists() and args.file.exists() and args.output.samefile(args.file))):
                raise ValueError('Signature output must not overwrite the input file')
            result = extract_signatures(args.file, verify_windows=args.windows_trust,
                                        lookup_catalog=args.windows_catalog, catalog_index=args.catalog_index)
            output = json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False) + '\n'
            if args.output:
                args.output.write_text(output, encoding='utf-8')
            else:
                print(output, end='')
            return 0
        if args.command in {'vision-download', 'inspect-vision', 'score-image'}:
            from smartscreen.vision_assets import fetch_assets, verify_bundle
            if args.prepare or args.body_output:
                raise ValueError('Vision commands do not support --prepare or --body-output')
            asset_root = (args.assets if args.command == 'score-image' else args.directory).resolve()
            if args.output:
                output_path = args.output.resolve()
                if output_path == asset_root or asset_root in output_path.parents:
                    raise ValueError('Save the result outside the managed asset directory')
                protected = [args.image] if args.command == 'score-image' else []
                if asset_root.is_dir() and args.output.exists():
                    protected += [path for path in asset_root.rglob('*') if path.is_file()]
                for source_path in protected:
                    if (output_path == source_path.resolve() or
                            (args.output.exists() and source_path.exists() and args.output.samefile(source_path))):
                        raise ValueError('Vision output must differ from the image and asset inputs')
            if args.command == 'vision-download':
                result = fetch_assets(args.directory, edge_version=args.edge_version,
                                      architecture=args.architecture,
                                      timeout=args.download_timeout, transport=args.transport)
            elif args.command == 'inspect-vision':
                from smartscreen.vision import inspect_vision
                assets = verify_bundle(args.directory, verify_signatures=True)
                result = inspect_vision(args.directory / assets['paths']['model'],
                                        args.directory / assets['paths']['vectors'])
                result['assets'] = assets
            else:
                from smartscreen.vision import ScarewareClassifier
                classifier = ScarewareClassifier.from_bundle(args.assets, scaling=args.scaling,
                    resize_method=args.resize_method, selected_set_index=args.tensor_set_index,
                    threads=args.threads)
                result = classifier.score_image(args.image, include_embedding=args.include_embedding)
            output = json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False) + '\n'
            if args.output:
                args.output.write_text(output, encoding='utf-8')
            else:
                print(output, end='')
            return 0
        if args.command in {'cache-import','cache-url','inspect-cache','explain-url','navigation-complete'}:
            from smartscreen.data import read_data
            from smartscreen.cache import import_response_file, merge_caches, lookup_cache, inspect_native_cache
            paths = []
            if args.command == 'navigation-complete':
                from smartscreen.decision import navigationcomplete_payload, NAVIGATIONCOMPLETE_ENDPOINT
                if args.prepare and args.body_output:
                    raise ValueError('--body-output requires a live response, not --prepare')
                if not math.isfinite(args.timeout) or args.timeout <= 0:
                    raise ValueError('Timeout must be positive and finite')
                paths = [args.context,args.models,args.signals]
                context = json.loads(read_data(args.context))
                if args.identity:
                    if not isinstance(context, dict):
                        raise ValueError('Navigation context must be an object')
                    context['identity'] = json.loads(read_data(args.identity))
                    paths.append(args.identity)
                payload = navigationcomplete_payload(context,
                    json.loads(read_data(args.models)), json.loads(read_data(args.signals)),
                    server_context=args.server_context)
                planned = {(args.prepare / name).resolve() for name in ('request.json','curl.conf')} if args.prepare else set()
                if planned.intersection(path.resolve() for path in paths):
                    raise ValueError('Prepared output must differ from source inputs')
                if args.output and args.output.resolve() in planned:
                    raise ValueError('JSON report must differ from prepared wire files')
                destinations = [path for path in (args.output, args.body_output) if path is not None]
                if args.prepare:
                    destinations += [args.prepare / name for name in ('request.json', 'curl.conf')]
                for destination in destinations:
                    for source in paths:
                        if destination.resolve() == source.resolve() or (destination.exists() and source.exists() and destination.samefile(source)):
                            raise ValueError('Navigation output must differ from source inputs')
                if args.output and args.body_output and (args.output.resolve() == args.body_output.resolve() or
                        (args.output.exists() and args.body_output.exists() and args.output.samefile(args.body_output))):
                    raise ValueError('JSON report and raw response must use different files')
            elif args.prepare or args.body_output:
                raise ValueError('Cache and decision explanation commands are offline JSON operations')
            if args.command == 'cache-import':
                paths = args.responses + [path.with_suffix('.bin') for path in args.responses]
                if args.context:
                    paths.append(args.context)
                context = json.loads(read_data(args.context)) if args.context else None
                result = merge_caches(import_response_file(path,args.received_at,args.scope,context=context,
                                                           semantics=args.reader) for path in args.responses)
            elif args.command == 'cache-url':
                paths = [args.cache]
                result = lookup_cache(json.loads(read_data(args.cache)),args.url,args.at,args.scope)
            elif args.command == 'inspect-cache':
                paths = [args.file]
                result = inspect_native_cache(args.file,args.at,url=args.url)
                paths.append(Path(result['file']))
            elif args.command == 'explain-url':
                from smartscreen.decision import explain_url
                paths = [path for path in (args.settings,args.cloud_response,args.cache) if path is not None]
                if args.output:
                    for directory in (args.feeds,args.defaults):
                        if directory and args.output.resolve().parent == directory.resolve():
                            raise ValueError('Write decision reports outside input snapshot directories')
                cache_observation = lookup_cache(json.loads(read_data(args.cache)),args.url,args.at,
                    'download' if args.navigation_type == 'download' else 'navigation') if args.cache else None
                result = explain_url(args.url,feeds=args.feeds,defaults=args.defaults,title=args.title,
                    settings=read_data(args.settings) if args.settings else None,model_name=args.model,
                    cloud_response=json.loads(read_data(args.cloud_response)) if args.cloud_response else None,
                    cache_observation=cache_observation,navigation_type=args.navigation_type)
            if args.output and args.output.resolve() in {path.resolve() for path in paths}:
                raise ValueError('Output must differ from input evidence files')
            if args.command == 'navigation-complete':
                if args.prepare:
                    result = prepare_request(args.prepare,NAVIGATIONCOMPLETE_ENDPOINT,payload,args.auth_id,args.client_version)
                    result['requests_sent'] = 0
                else:
                    result, raw_body = SmartScreenClient(args.timeout, args.auth_id, transport=args.transport,
                        client_version=args.client_version).request(NAVIGATIONCOMPLETE_ENDPOINT, payload)
                    result['requests_sent'] = 1
                    if args.body_output:
                        args.body_output.write_bytes(raw_body)
                result['validation'] = 'native_capture_and_benign_replay'
            output = json.dumps(result,indent=2,ensure_ascii=False,allow_nan=False)+'\n'
            if args.output:
                args.output.write_text(output,encoding='utf-8')
            else:
                print(output,end='')
            return 1 if result.get('rejected') or ('http_status' in result and not 200 <= result['http_status'] < 300) else 0
        if args.command in {'export-verdicts','observed-url'}:
            from smartscreen.verdicts import export_observed, lookup_observed
            if args.prepare or args.body_output:
                raise ValueError('Observed-verdict commands are offline JSON operations')
            inputs = args.inputs if args.command == 'export-verdicts' else [args.catalog]
            if args.output and args.output.resolve() in {path.resolve() for path in inputs}:
                raise ValueError('Output must differ from input files')
            if args.command == 'export-verdicts':
                result = export_observed(inputs, verdicts=args.verdict or ('warn','block'),
                                         kinds=args.kind or ('url',), max_records=args.max_records)
            else:
                from smartscreen.data import read_data
                result = lookup_observed(json.loads(read_data(args.catalog)), args.url)
            output = json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False) + '\n'
            if args.output:
                args.output.write_text(output, encoding='utf-8')
            else:
                print(output, end='')
            return 0 if result.get('summary', {}).get('validation_complete', True) else 1
        if args.command in {'inspect-data', 'compare-feeds', 'inspect-model', 'map-candidates', 'offline-url', 'score-title'}:
            from smartscreen.data import inspect_file, compare_data, compare_snapshots, read_data
            if args.prepare:
                raise ValueError('Feed inspection and comparison are offline commands')
            if args.command == 'offline-url':
                from smartscreen.offline import analyze_url
                result = analyze_url(args.url, args.feeds, args.defaults)
            elif args.command == 'score-title':
                from smartscreen.model import score_title
                result = score_title(read_data(args.file), args.title, model_name=args.model)
            elif args.command == 'map-candidates':
                from smartscreen.candidates import map_candidate_files
                if args.output and args.output.resolve() in [args.dataset.resolve()] + [path.resolve() for path in args.candidates]:
                    raise ValueError('Output must differ from input files')
                result = map_candidate_files(args.dataset, args.candidates, kind=args.kind,
                    input_format=args.input_format, domain_variants=args.domain_variants,
                    model_name=args.model, max_candidates=args.max_candidates, limit=args.limit)
            elif args.command == 'inspect-model':
                from smartscreen.model import inspect_models, lookup_token
                raw = read_data(args.file)
                result = inspect_models(raw, include_weights=args.full)
                if args.model is not None and args.token is None:
                    raise ValueError('--model selects the model for --token')
                if args.token is not None:
                    result['token_lookup'] = lookup_token(raw, args.token, model_name=args.model)
            elif args.command == 'inspect-data':
                result = inspect_file(args.file, args.kind)
                if args.key is not None:
                    from smartscreen.data import check_toptraffic_key, check_bloom_key
                    if args.kind == 'topTraffic':
                        result['exact_key_match'] = check_toptraffic_key(read_data(args.file), args.key)
                    elif result['format'] == 'murmur3_filter':
                        result['exact_key_match'] = check_bloom_key(read_data(args.file), args.key, args.kind)
                    else:
                        raise ValueError('--key requires a topTraffic or Murmur3 Bloom dataset')
                if args.url is not None:
                    from smartscreen.data import check_feed_url
                    result['url_lookup'] = check_feed_url(read_data(args.file), args.url, args.kind)
            elif args.before.is_dir() and args.after.is_dir():
                result = compare_snapshots(args.before, args.after, args.limit)
            elif args.before.is_file() and args.after.is_file():
                result = compare_data(read_data(args.before), read_data(args.after), args.kind, args.limit)
            else:
                raise ValueError('Compare two existing files or two existing snapshot directories')
            output = json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False) + '\n'
            if args.output:
                args.output.write_text(output, encoding='utf-8')
            else:
                print(output, end='')
            return 0
        if args.command == 'endpoints':
            from smartscreen.api import api_catalog
            from smartscreen.protocol import protocol_catalog
            routes = {name: {'name': name, 'url': url, 'validation': 'live_validated'}
                      for name, url in ENDPOINTS.items()}
            for route in api_catalog():
                routes[route['name']] = {**route, 'url': route['endpoint']}
            from smartscreen.decision import NAVIGATIONCOMPLETE_ENDPOINT
            routes['navigationcomplete'] = {'name':'navigationcomplete','url':NAVIGATIONCOMPLETE_ENDPOINT,
                'validation':'native_capture_and_benign_replay','schema_evidence':'analysis/native_browser/',
                'note':'Captured Edge 158 page-model follow-up. Requires explicit page signals and model scores; server reply alone does not establish enforcement.'}
            result = {'api': list(routes.values()), 'protocol': protocol_catalog(),
                      'data': DATA_ENDPOINTS,
                      'data_note': 'Use lists for current advertised URLs. Custom settings acquisition uses a documented native-baseline retry; custom Bloom remains unavailable in this lab.',
                      'initial_dataset_versions': INITIAL_DATASET_VERSIONS,
                      'client_version': CLIENT_VERSION, 'auth_id': args.auth_id}
            output = json.dumps(result, indent=2) + '\n'
            if args.output:
                args.output.write_text(output, encoding='utf-8')
            else:
                print(output, end='')
            return 0
        if not math.isfinite(args.timeout) or args.timeout <= 0:
            raise ValueError('Timeout must be positive and finite')
        profile = json.loads(args.identity.read_text()) if args.identity else None
        if profile is not None and not isinstance(profile, dict):
            raise ValueError('Identity JSON must be an object')
        if args.client_version is not None:
            profile = identity() if profile is None else profile
            if not isinstance(profile.get('client', {}), dict):
                raise ValueError('Identity client must be an object')
            profile.setdefault('client', {})['version'] = client_version_for(override=args.client_version)
        if args.command == 'batch':
            from smartscreen.batch import run_batch
            if args.prepare or args.body_output:
                raise ValueError('Batch outputs JSONL records; --prepare and --body-output do not apply')
            if args.output and args.output.resolve() in {args.input.resolve(), args.history.resolve()}:
                raise ValueError('Batch output must differ from its input and history database')
            if args.input.resolve() == args.history.resolve():
                raise ValueError('Batch input must differ from its history database')
            client = SmartScreenClient(args.timeout, args.auth_id, transport=args.transport, client_version=args.client_version)
            stream = args.output.open('w', encoding='utf-8') if args.output else contextlib.nullcontext(sys.stdout)
            with stream as output_stream:
                summary = run_batch(args.input, output_stream, client=client, history=args.history,
                                    profile=profile, delay=args.delay, max_jobs=args.max_jobs)
            print(json.dumps({'batch_summary': summary}, ensure_ascii=False), file=sys.stderr)
            return 0 if summary.get('failed', 0) == 0 and summary.get('not_run', 0) == 0 else 1
        if args.command == 'history':
            from smartscreen.batch import HistoryStore
            if args.prepare or args.body_output:
                raise ValueError('History is an offline JSON query; --prepare and --body-output do not apply')
            if args.output and args.output.resolve() == args.database.resolve():
                raise ValueError('History output must differ from the database')
            with HistoryStore(args.database, readonly=True) as store:
                result = store.query(limit=args.limit, query_key=args.query_key)
            output = json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False) + '\n'
            if args.output:
                args.output.write_text(output, encoding='utf-8')
            else:
                print(output, end='')
            return 0
        if args.command == 'lists':
            if args.prepare:
                raise ValueError('Use actions with --identity for an offline prepared list-discovery request')
            result = SmartScreenClient(args.timeout, args.auth_id, transport=args.transport, client_version=args.client_version).lists(profile, args.download, args.feed_cache)
            output = json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False) + '\n'
            if args.output:
                args.output.write_text(output, encoding='utf-8')
            else:
                print(output, end='')
            successful = result['http_status'] == 200 and all(
                item.get('http_status') in (200, 304) for item in result.get('downloads', []))
            return 0 if successful else 1
        signature_metadata = None
        package_metadata = None
        if args.command == 'url':
            endpoint = ENDPOINTS['url' if args.mode == 'sync' else 'url-async']
            payload = url_payload(args.url, args.referrer, profile, synchronous=args.mode == 'sync')
        elif args.command == 'download':
            from smartscreen.api import download_payload
            endpoint, payload = ENDPOINTS['download'], download_payload(args.url, args.referrer, profile)
        elif args.command == 'package':
            from smartscreen.package import ENDPOINT as PACKAGE_ENDPOINT, extract_package, package_payload
            package_metadata = extract_package(args.path, full_name=args.full_name)
            dependencies = json.loads(args.dependencies.read_text()) if args.dependencies else None
            config = json.loads(args.config.read_text()) if args.config else None
            endpoint = PACKAGE_ENDPOINT
            payload = package_payload(package_metadata['package'], args.location,
                dependencies=dependencies, location_type=args.location_type, profile=profile,
                config=config, ux_enabled=args.ux_enabled)
        elif args.command == 'actions':
            endpoint, payload = ENDPOINTS['actions'], {'identity': profile if profile is not None else identity()}
        elif args.command in {'file', 'hash'}:
            if args.command == 'file':
                if (args.signature_windows_trust or args.signature_windows_catalog or args.signature_catalog_index is not None) and not args.include_signatures:
                    raise ValueError('Signature trust/catalog options require --include-signatures')
                destinations = [args.output, args.body_output]
                if args.prepare:
                    destinations += [args.prepare / name for name in ('request.json', 'curl.conf')]
                for destination in destinations:
                    if destination and (destination.resolve() == args.file.resolve() or
                            (destination.exists() and args.file.exists() and destination.samefile(args.file))):
                        raise ValueError('File-query output must not overwrite the input file')
                digest = hashlib.sha256()
                size = 0
                with args.file.open('rb') as input_file:
                    for chunk in iter(lambda: input_file.read(1024 * 1024), b''):
                        digest.update(chunk)
                        size += len(chunk)
                sha256, name = digest.hexdigest(), args.file.name
                if args.include_signatures:
                    from smartscreen.signatures import extract_signatures
                    signature_metadata = extract_signatures(args.file, verify_windows=args.signature_windows_trust,
                                                            lookup_catalog=args.signature_windows_catalog,
                                                            catalog_index=args.signature_catalog_index)
                    if signature_metadata['file_sha256'] != sha256 or signature_metadata['size'] != size:
                        raise ValueError('File changed between hashing and signature extraction')
                    if signature_metadata['wire_error']:
                        raise ValueError(signature_metadata['wire_error'])
            else:
                sha256, size, name = args.sha256, args.size, args.name
            if args.surface == 'shell':
                from smartscreen.api import shell_payload
                endpoint, payload = ENDPOINTS['shell'], shell_payload(
                    sha256, size, name, args.source, referrer=args.referrer, profile=profile)
            else:
                endpoint, payload = ENDPOINTS['file'], file_payload(sha256, size, name, args.source, profile)
                if args.referrer:
                    payload['referrer']['uri'] = check_url(args.referrer)
            if signature_metadata is not None:
                payload['file']['authenticode'] = signature_metadata['wire_metadata']
        else:
            endpoint = args.endpoint
            payload = json.loads(args.json.read_text()) if args.json else None
        protected_inputs = [path for path in (args.identity, getattr(args, 'json', None)) if path is not None]
        protected_inputs += package_inputs
        planned_outputs = [path for path in (args.output, args.body_output) if path is not None]
        if args.prepare:
            if args.body_output:
                raise ValueError('--body-output requires a live response, not --prepare')
            planned_outputs += [args.prepare / name for name in ('request.json', 'curl.conf')]
        def same_path(left, right):
            return left.resolve() == right.resolve() or (left.exists() and right.exists() and left.samefile(right))
        if any(same_path(target, source) for target in planned_outputs for source in protected_inputs):
            raise ValueError('Request output must differ from identity and payload inputs')
        if any(same_path(left, right) for index, left in enumerate(planned_outputs) for right in planned_outputs[index + 1:]):
            raise ValueError('Response and prepared request artifacts must use different files')
        request_options = ({'method': args.method, 'accept': args.accept,
                            'dataset_version': args.dataset_version} if args.command == 'request' else {})
        if args.prepare:
            result = prepare_request(args.prepare, endpoint, payload, args.auth_id, args.client_version, **request_options)
        else:
            result, raw_body = SmartScreenClient(args.timeout, args.auth_id, transport=args.transport, client_version=args.client_version).request(endpoint, payload, **request_options)
            if endpoint == ENDPOINTS['shell']:
                from smartscreen.api import summarize_presentation
                result['presentation'] = summarize_presentation(result['response'])
            if args.body_output:
                args.body_output.write_bytes(raw_body)
        if package_metadata is not None:
            result['local_package_metadata'] = package_metadata
        if signature_metadata is not None:
            result['local_signature_metadata'] = {key: signature_metadata[key] for key in
                ('file_sha256', 'size', 'embedded_signature_present', 'windows_trust',
                 'catalog_lookup', 'windows_catalogs', 'selected_catalog_index', 'format', 'wire_origin',
                 'wire_metadata', 'wire_scope', 'schema_evidence', 'limits')}
        output = json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False) + '\n'
        if args.output:
            args.output.write_text(output, encoding='utf-8')
        else:
            print(output, end='')
        if not args.prepare and not 200 <= result['http_status'] < 300:
            return 1
    except (OSError, ValueError, RuntimeError, urllib.error.URLError, subprocess.TimeoutExpired, sqlite3.Error) as error:
        parser.exit(2, str(error) + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

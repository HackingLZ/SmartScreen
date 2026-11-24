"""Reconstruct HTTP/2 exchanges from Chromium Everything netlogs, offline.

Only SSL_SOCKET_BYTES_* events on an explicitly linked HTTP/2 session are
treated as plaintext HTTP/2. TCP SOCKET_BYTES_* may contain TLS ciphertext and
are never decoded. Decoded HTTP2_SESSION_* header events provide headers;
this module does not guess HPACK state. Bodies are demultiplexed by session,
stream and direction, even when frame headers/payloads span byte events.
"""
import argparse
import base64
from collections import defaultdict, deque
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import zlib
from urllib.parse import urlsplit

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
DEFAULT_MAX_BODY = 16 * 1024 * 1024
DEFAULT_MAX_FILE = 256 * 1024 * 1024
_WHITESPACE = re.compile(r'\s*')


def _source(value):
    if not isinstance(value, dict) or 'id' not in value or 'type' not in value:
        return None
    if any(type(value[key]) not in (int, str) for key in ('id', 'type')):
        return None
    return str(value['type']) + ':' + str(value['id'])


def _document(source, max_file_bytes):
    if isinstance(source, dict):
        return source, {'kind': 'in_memory', 'complete_json': True}, []
    path = Path(source)
    if path.stat().st_size > max_file_bytes:
        raise ValueError('Netlog exceeds max_file_bytes')
    raw = path.read_bytes()
    if len(raw) > max_file_bytes:
        raise ValueError('Netlog grew beyond max_file_bytes while reading')
    text = raw.decode('utf-8-sig')
    provenance = {'kind': 'file', 'path': str(path), 'size': len(raw),
                  'sha256': hashlib.sha256(raw).hexdigest(), 'complete_json': True}
    try:
        document = json.loads(text)
    except json.JSONDecodeError as original:
        # Chromium writes constants and an events array before closing the file.
        # Parse only complete event objects; never skip malformed middle records.
        decoder = json.JSONDecoder()
        opening = re.match(r'\s*\{\s*"constants"\s*:\s*', text)
        if not opening:
            raise ValueError('Not a Chromium netlog JSON document') from original
        try:
            constants, position = decoder.raw_decode(text, opening.end())
        except json.JSONDecodeError as error:
            raise ValueError('Incomplete or invalid netlog constants') from error
        array = re.match(r'\s*,\s*"events"\s*:\s*\[', text[position:])
        if not array:
            raise ValueError('Netlog has no recoverable events array') from original
        position += array.end()
        events, issues, array_closed = [], [], False
        while True:
            position = _WHITESPACE.match(text, position).end()
            if position == len(text):
                break
            if text[position] == ']':
                array_closed = True
                position += 1
                break
            try:
                event, end = decoder.raw_decode(text, position)
            except json.JSONDecodeError as error:
                issues.append({'kind': 'unparsed_event_tail', 'character_offset': position,
                               'error': str(error), 'remaining_characters': len(text) - position})
                break
            if not isinstance(event, dict):
                issues.append({'kind': 'invalid_event', 'event_index': len(events),
                               'character_offset': position})
                break
            events.append(event)
            position = end
            position = _WHITESPACE.match(text, position).end()
            if position < len(text) and text[position] == ',':
                position += 1
            elif position < len(text) and text[position] != ']':
                issues.append({'kind': 'invalid_event_separator', 'character_offset': position})
                break
        provenance.update(complete_json=False, events_array_closed=array_closed,
                          parsed_event_count=len(events), unparsed_tail_characters=len(text) - position)
        issues.append({'kind': 'unfinished_or_invalid_json', 'error': str(original),
                       'note': 'Only the contiguous complete event prefix was recovered.'})
        return {'constants': constants, 'events': events}, provenance, issues
    if not isinstance(document, dict):
        raise ValueError('Netlog root must be an object')
    return document, provenance, []


def _headers(lines):
    result = []
    if isinstance(lines, dict):
        lines = [str(name) + ': ' + str(value) for name, value in lines.items()]
    if not isinstance(lines, list):
        return result
    for line in lines:
        if not isinstance(line, str):
            continue
        separator = line.find(':', 1 if line.startswith(':') else 0)
        if separator < 0:
            result.append({'name': None, 'value': line, 'raw': line})
        else:
            result.append({'name': line[:separator].strip().lower(), 'value': line[separator + 1:].strip(), 'raw': line})
    return result


def _header(headers, name):
    return [row['value'] for row in headers if row['name'] == name]


def _one_header(headers, name):
    values = _header(headers, name)
    return values[-1] if values else None


def _selected(url, hosts):
    try:
        host = (urlsplit(url).hostname or '').lower()
    except ValueError:
        return False
    if hosts is not None:
        return host in hosts
    return (host == 'smartscreen.microsoft.com' or host.endswith('.smartscreen.microsoft.com') or
            host.endswith('.ss.wd.microsoft.us') or
            host in ('checkappexec.microsoft.com', 'smartscreen-prod.microsoft.com'))


def _body():
    return {'data': bytearray(), 'frames': [], 'errors': [], 'ended': False,
            'observed_bytes': 0, 'frame_payload_bytes': 0, 'metadata_bytes': 0, 'metadata_data_events': [],
            'metadata_end': False, 'header_end': False, 'limited': False}


class _Framer:
    def __init__(self, direction, callback, issues, socket_source):
        self.direction, self.callback, self.issues = direction, callback, issues
        self.socket_source = socket_source
        self.buffer, self.segments = bytearray(), deque()
        self.prefix_checked, self.failed = False, False

    def _consume(self, size):
        data = bytes(self.buffer[:size])
        del self.buffer[:size]
        provenance = []
        remaining = size
        while remaining:
            segment = self.segments[0]
            consumed = min(remaining, segment['remaining'])
            provenance.append({'event_index': segment['event_index'],
                               'event_byte_start': segment['offset'],
                               'event_byte_end': segment['offset'] + consumed})
            segment['remaining'] -= consumed
            segment['offset'] += consumed
            remaining -= consumed
            if not segment['remaining']:
                self.segments.popleft()
        return data, provenance

    def add(self, data, index):
        if self.failed:
            return
        self.buffer.extend(data)
        if data:
            self.segments.append({'remaining': len(data), 'offset': 0, 'event_index': index})
        if not self.buffer:
            return
        if not self.prefix_checked:
            if self.direction == 'request' and self.buffer and PREFACE.startswith(self.buffer):
                if len(self.buffer) < len(PREFACE):
                    return
            if self.buffer.startswith(PREFACE):
                self._consume(len(PREFACE))
            self.prefix_checked = True
        while len(self.buffer) >= 9:
            length = int.from_bytes(self.buffer[:3], 'big')
            kind, flags = self.buffer[3], self.buffer[4]
            stream = int.from_bytes(self.buffer[5:9], 'big') & 0x7fffffff
            # All24-bit lengths are legal after settings negotiation. Keep a
            # bounded frame buffer and never resynchronize by guessing bytes.
            if len(self.buffer) < 9 + length:
                return
            frame, provenance = self._consume(9 + length)
            self.callback(kind, flags, stream, frame[9:], provenance)

    def gap(self, index, reason):
        self.issues.append({'kind': 'plaintext_byte_gap', 'socket_source': self.socket_source,
                            'direction': self.direction, 'event_index': index, 'reason': reason})
        self.failed = True
        self.buffer.clear()
        self.segments.clear()

    def finish(self):
        if self.buffer:
            self.issues.append({'kind': 'incomplete_http2_frame', 'socket_source': self.socket_source,
                                'direction': self.direction, 'buffered_bytes': len(self.buffer),
                                'event_indices': [row['event_index'] for row in self.segments]})


def _inflate(data, encoding, limit):
    modes = [31] if encoding in ('gzip', 'x-gzip') else [15, -15]
    last_error = None
    for mode in modes:
        try:
            decoder = zlib.decompressobj(mode)
            output = decoder.decompress(data, limit + 1)
            if len(output) > limit or decoder.unconsumed_tail:
                raise ValueError('Decoded body exceeds max_body_bytes')
            output += decoder.flush(max(1, limit + 1 - len(output)))
            if len(output) > limit:
                raise ValueError('Decoded body exceeds max_body_bytes')
            if not decoder.eof or decoder.unused_data:
                raise ValueError('Compressed body is incomplete or contains an unsupported trailing member')
            return output
        except zlib.error as error:
            last_error = error
    raise ValueError('Invalid compressed body: ' + str(last_error))


def _render_body(body, headers, max_body_bytes, direction_gap):
    data = bytes(body['data'])
    errors = list(body['errors'])
    lengths = _header(headers, 'content-length')
    declared = None
    if lengths:
        if any(not value.isdecimal() for value in lengths) or len(set(lengths)) != 1:
            errors.append('Invalid or conflicting content-length headers')
        else:
            declared = int(lengths[0])
            if declared != body['observed_bytes']:
                errors.append('Captured DATA length does not match content-length')
    if body['metadata_bytes'] != body['frame_payload_bytes']:
        errors.append('Raw DATA frame payload length does not match logged HTTP2_SESSION_DATA events')
    if direction_gap:
        errors.append('Plaintext capture contains a gap; exact body reconstruction is not established')
    ended = body['ended'] or body['header_end']
    if not ended:
        errors.append('No complete END_STREAM captured')
    if body['limited']:
        errors.append('Captured body exceeds max_body_bytes; retained bytes are a prefix')
    complete = ended and not errors
    state = 'complete' if complete else ('missing_bytes' if not data and body['metadata_bytes'] else 'incomplete')
    result = {'state': state, 'complete': complete, 'wire_size': len(data),
              'observed_data_size': body['observed_bytes'],
              'observed_frame_payload_size': body['frame_payload_bytes'],
              'logged_frame_payload_size': body['metadata_bytes'],
              'declared_content_length': declared, 'wire_sha256': hashlib.sha256(data).hexdigest(),
              'wire_base64': base64.b64encode(data).decode('ascii'), 'errors': errors,
              'wire_sha256_scope': 'complete_body' if complete else 'retained_partial_body',
              'frames': body['frames'], 'data_event_indices': body['metadata_data_events'],
              'end_stream_observed': ended, 'json': None, 'text': None}
    if not complete:
        return result
    encodings = [value.strip().lower() for header in _header(headers, 'content-encoding')
                 for value in header.split(',') if value.strip().lower() != 'identity']
    result['content_encodings'] = encodings
    decoded = data
    try:
        for encoding in reversed(encodings):
            if encoding not in ('gzip', 'x-gzip', 'deflate'):
                raise ValueError('Unsupported content-encoding: ' + encoding)
            decoded = _inflate(decoded, encoding, max_body_bytes)
        result.update(decoded_size=len(decoded), decoded_sha256=hashlib.sha256(decoded).hexdigest(),
                      decoded_base64=base64.b64encode(decoded).decode('ascii'))
        result['utf8_bom'] = decoded.startswith(b'\xef\xbb\xbf')
        result['text'] = decoded.decode('utf-8-sig')
    except (ValueError, UnicodeError) as error:
        result['decode_error'] = str(error)
        return result
    if decoded:
        try:
            result['json'] = json.loads(result['text'], parse_constant=lambda value: (_ for _ in ()).throw(ValueError('Nonfinite JSON number ' + value)))
        except (ValueError, RecursionError) as error:
            result['json_error'] = str(error)
    return result


def _redaction(value):
    encoded = value.encode('utf-8') if isinstance(value, str) else json.dumps(value, sort_keys=True).encode('utf-8')
    return {'redacted': True, 'sha256': hashlib.sha256(encoded).hexdigest(), 'bytes': len(encoded)}


def _redact_json(value, path=()):
    if isinstance(value, list):
        return [_redact_json(item, path) for item in value]
    if not isinstance(value, dict):
        return value
    output = {}
    for key, item in value.items():
        lower = key.lower()
        sensitive = lower in {'onlineidticket', 'customid', 'access_token', 'refresh_token',
                              'password', 'authorization', 'cookie', 'set-cookie',
                              'deviceid', 'userid', 'accountid', 'email'}
        sensitive |= lower == 'id' and any(part in ('device', 'user', 'account') for part in path)
        output[key] = _redaction(item) if sensitive and item not in (None, '') else _redact_json(item, path + (lower,))
    return output


def _sanitize_transaction(transaction):
    for direction in ('request', 'response'):
        side = transaction[direction]
        # Headers are shared with header-block lists, so replace raw text too.
        for block in side['header_blocks']:
            for header in block['headers']:
                if header['name'] in ('authorization', 'proxy-authorization', 'cookie', 'set-cookie'):
                    if isinstance(header['value'], str):
                        header['value'] = _redaction(header['value'])
                    header['raw'] = None
        body = side['body']
        body['wire_base64'] = None
        body.pop('decoded_base64', None)
        if body['json'] is not None:
            body['json'] = _redact_json(body['json'])
        body['text'] = None
        body['raw_bytes_omitted'] = 'Default sensitive-data redaction; opt in explicitly for exact local export.'
    return transaction


def correlate_navigation(transactions):
    """Link complete navigation bodies only by explicit shared evidence.

    A URL-only candidate is reported as unverified. Missing follow-ups never
    imply that no model ran, a page was safe, or a request was suppressed.
    """
    initial, followups = [], []
    for transaction in transactions:
        request = transaction['request']['body'].get('json')
        if not isinstance(request, dict) or not transaction['request']['body']['complete']:
            continue
        path = urlsplit(transaction['url']).path
        if '/navigationcomplete/' in path:
            followups.append(transaction)
        elif '/navigate/' in path:
            initial.append(transaction)
    records = []
    for followup in followups:
        request = followup['request']['body']['json']
        destination = request.get('destination', {})
        destination = destination.get('uri') if isinstance(destination, dict) else None
        candidates = []
        followup_index = min((block['event_index'] for block in followup['request']['header_blocks']), default=float('inf'))
        for navigation in initial:
            prior_index = min((block['event_index'] for block in navigation['request']['header_blocks']), default=float('inf'))
            if prior_index >= followup_index:
                continue
            prior = navigation['request']['body']['json']
            prior_destination = prior.get('destination', {})
            prior_destination = prior_destination.get('uri') if isinstance(prior_destination, dict) else None
            response = navigation['response']['body'].get('json')
            response = response if isinstance(response, dict) else {}
            result = response.get('result', {})
            result = result if isinstance(result, dict) else {}
            basis = []
            correlation = request.get('correlationId')
            if (correlation and correlation != '00000000-0000-0000-0000-000000000000' and
                    correlation == prior.get('correlationId')):
                basis.append('same_correlationId')
            context = request.get('serverContext')
            if isinstance(context, str) and context:
                if context == response.get('serverContext'):
                    basis.append('serverContext_matches_response_root')
                if context == result.get('serverContext'):
                    basis.append('serverContext_matches_response_result')
            if destination and destination == prior_destination:
                basis.append('same_destination_uri')
            if basis:
                verified = any(item != 'same_destination_uri' for item in basis)
                candidates.append({'navigation_id': navigation['id'], 'basis': basis,
                                   'explicit_binding': verified,
                                   'destination_conflict': bool(destination and prior_destination and destination != prior_destination)})
        records.append({'followup_id': followup['id'], 'candidates': candidates,
                        'unique_explicit_binding': sum(row['explicit_binding'] and not row['destination_conflict'] for row in candidates) == 1,
                        'is_browser_enforcement_evidence': False})
    return {'initial_navigation_ids': [row['id'] for row in initial],
            'followups': records, 'note': 'URL equality alone is not proof of request binding; absence from a capture is not an enforcement verdict.'}


def parse_netlog(source, *, hosts=None, max_body_bytes=DEFAULT_MAX_BODY,
                 max_file_bytes=DEFAULT_MAX_FILE, redact_sensitive=True):
    """Return an offline HTTP/2 evidence report, preserving captured wire bytes.

    source is a netlog path or decoded object. hosts=None selects Microsoft
    SmartScreen hosts; hosts=[] selects all hosts for protocol diagnostics.
    No headers or body fields are fabricated. By default credentials/device
    identifiers are replaced by digests and raw bodies are omitted. Explicit
    redact_sensitive=False enables exact local export and may expose captured
    OS account tokens even when the browser uses an isolated profile.
    """
    for name, value in [('max_body_bytes', max_body_bytes), ('max_file_bytes', max_file_bytes)]:
        if type(value) is not int or value < 1:
            raise ValueError(name + ' must be a positive integer')
    if type(redact_sensitive) is not bool:
        raise ValueError('redact_sensitive must be a bool')
    if hosts is not None:
        if not isinstance(hosts, (list, tuple, set)) or any(not isinstance(host, str) or not host for host in hosts):
            raise ValueError('hosts must be an explicit collection of host names')
        hosts = {host.lower() for host in hosts}
    document, source_info, issues = _document(source, max_file_bytes)
    constants, events = document.get('constants', {}), document.get('events')
    if not isinstance(constants, dict) or not isinstance(events, list):
        raise ValueError('Netlog requires constants object and events array')
    for field in ('logEventTypes', 'logSourceType'):
        mapping = constants.get(field, {})
        if not isinstance(mapping, dict) or any(type(value) not in (int, str) for value in mapping.values()):
            raise ValueError('Netlog ' + field + ' must map names to numeric/string identifiers')
    event_types = {value: key for key, value in constants.get('logEventTypes', {}).items()}
    source_types = {value: key for key, value in constants.get('logSourceType', {}).items()}
    def name(event):
        value = event.get('type')
        return event_types.get(value, value) if type(value) in (int, str) else None
    sessions, jobs, url_sources, event_refs = {}, {}, {}, {}
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            issues.append({'kind': 'invalid_event', 'event_index': index})
            continue
        key, params, kind = _source(event.get('source')), event.get('params', {}), name(event)
        if not isinstance(params, dict):
            continue
        event_refs[index] = {'event_index': index, 'type': kind, 'time': event.get('time'),
                             'source': event.get('source')}
        try:
            milliseconds = int(constants['timeTickOffset']) + int(event['time'])
            event_refs[index]['utc'] = datetime.fromtimestamp(milliseconds / 1000, timezone.utc).isoformat()
        except (KeyError, TypeError, ValueError, OverflowError, OSError):
            pass
        if kind == 'HTTP2_SESSION_INITIALIZED' and key:
            socket = _source(params.get('source_dependency'))
            if params.get('protocol') == 'h2' and socket:
                sessions[key] = {'socket': socket, 'event_index': index,
                                 'source': event['source'], 'socket_source': params['source_dependency']}
        elif kind == 'HTTP_STREAM_JOB_BOUND_TO_REQUEST' and key:
            jobs[key] = _source(params.get('source_dependency'))
        elif kind == 'URL_REQUEST_START_JOB' and key:
            url_sources.setdefault(key, []).append({'url': params.get('url'), 'method': params.get('method'),
                                                    'event_index': index})
    streams = {}
    def get_stream(session, stream):
        key = (session, stream)
        if key not in streams:
            streams[key] = {'session': session, 'stream_id': stream, 'request': _body(), 'response': _body(),
                            'request_headers': [], 'response_headers': [], 'request_header_blocks': [],
                            'response_header_blocks': [], 'request_source': None, 'reset_events': []}
        return streams[key]
    # Header and DATA metadata establish stream identity independently of byte captures.
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            continue
        params, kind, session = event.get('params', {}), name(event), _source(event.get('source'))
        if not isinstance(params, dict) or type(params.get('stream_id')) is not int or not 0 < params['stream_id'] < 2 ** 31:
            continue
        if kind not in ('HTTP2_SESSION_SEND_HEADERS', 'HTTP2_SESSION_RECV_HEADERS',
                        'HTTP2_SESSION_SEND_DATA', 'HTTP2_SESSION_RECV_DATA',
                        'HTTP2_SESSION_SEND_RST_STREAM', 'HTTP2_SESSION_RECV_RST_STREAM'):
            continue
        stream = get_stream(session, params['stream_id'])
        direction = 'request' if '_SEND_' in kind else 'response'
        body = stream[direction]
        if kind.endswith('_HEADERS'):
            headers = _headers(params.get('headers'))
            block = {'event_index': index, 'headers': headers, 'fin': params.get('fin')}
            stream[direction + '_header_blocks'].append(block)
            # Final response replaces informational1xx; later trailer blocks
            # are retained separately and must not erase status/header fields.
            status = _one_header(headers, ':status')
            if direction == 'request' and _one_header(headers, ':method'):
                stream['request_headers'] = headers
            elif direction == 'response' and status:
                if status.isdecimal() and int(status) >= 200:
                    stream['response_headers'] = headers
            if params.get('fin') is True:
                body['header_end'] = True
            if direction == 'request':
                dependency = params.get('source_dependency', {})
                dep = _source(dependency)
                dep_type = dependency.get('type') if dep else None
                stream['request_source'] = jobs.get(dep) or (dep if source_types.get(dep_type, dep_type) == 'URL_REQUEST' else None)
        elif kind.endswith('_DATA'):
            size = params.get('size')
            if type(size) is int and size >= 0:
                body['metadata_bytes'] += size
            else:
                body['errors'].append('Invalid HTTP2_SESSION_DATA size')
            body['metadata_data_events'].append(index)
            body['metadata_end'] |= params.get('fin') is True
        else:
            stream['reset_events'].append({'event_index': index, 'direction': direction,
                                           'error_code': params.get('error_code'), 'description': params.get('description')})
    socket_sessions = defaultdict(list)
    for session, details in sessions.items():
        socket_sessions[details['socket']].append(session)
    framers = {}
    for socket, linked in socket_sessions.items():
        if len(linked) != 1:
            issues.append({'kind': 'ambiguous_http2_socket_binding', 'socket_source': socket, 'sessions': linked})
            continue
        session = linked[0]
        for direction in ('request', 'response'):
            def frame(kind, flags, stream_id, payload, provenance, session=session, direction=direction):
                if kind not in (0, 1, 3):
                    return
                if stream_id == 0:
                    issues.append({'kind': 'invalid_http2_stream_zero', 'frame_type': kind,
                                   'session': session, 'provenance': provenance})
                    return
                stream, body = get_stream(session, stream_id), get_stream(session, stream_id)[direction]
                if kind == 3:
                    if len(payload) != 4:
                        body['errors'].append('Invalid RST_STREAM length')
                    stream['reset_events'].append({'direction': direction, 'raw_frame': provenance,
                                                   'error_code': int.from_bytes(payload, 'big')})
                    return
                if kind == 1:
                    if flags & 1:
                        body['ended'] = True
                    return
                if body['ended']:
                    body['errors'].append('DATA frame appeared after END_STREAM')
                body['frame_payload_bytes'] += len(payload)
                if flags & 8:
                    if not payload or payload[0] > len(payload) - 1:
                        body['errors'].append('Invalid DATA padding')
                        return
                    payload = payload[1:len(payload) - payload[0]]
                body['observed_bytes'] += len(payload)
                remaining = max_body_bytes - len(body['data'])
                body['data'].extend(payload[:max(0, remaining)])
                body['limited'] |= len(payload) > remaining
                body['frames'].append({'payload_size': len(payload), 'flags': flags, 'provenance': provenance})
                body['ended'] |= bool(flags & 1)
            framers[(socket, direction)] = _Framer(direction, frame, issues, socket)
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            continue
        kind = name(event)
        if kind not in ('SSL_SOCKET_BYTES_SENT', 'SSL_SOCKET_BYTES_RECEIVED'):
            continue
        direction = 'request' if kind.endswith('_SENT') else 'response'
        framer = framers.get((_source(event.get('source')), direction))
        if framer is None:
            continue
        params = event.get('params', {})
        if not isinstance(params, dict):
            framer.gap(index, 'Invalid byte-event parameters')
            continue
        try:
            encoded = params.get('bytes')
            count = params.get('byte_count')
            if encoded is None:
                if count != 0:
                    framer.gap(index, 'Byte payload not captured; Everything mode is required')
                continue
            data = base64.b64decode(encoded, validate=True)
            if count is not None and count != len(data):
                framer.gap(index, 'byte_count differs from decoded payload length')
                continue
            framer.add(data, index)
        except (ValueError, TypeError) as error:
            framer.gap(index, 'Invalid base64 byte payload: ' + str(error))
    for framer in framers.values():
        framer.finish()
    transactions = []
    for (session, stream_id), stream in sorted(streams.items(), key=lambda row: (str(row[0][0]), row[0][1])):
        request_headers, response_headers = stream['request_headers'], stream['response_headers']
        scheme, authority, path = (_one_header(request_headers, name) for name in (':scheme', ':authority', ':path'))
        url = scheme + '://' + authority + path if scheme and authority and path else None
        header_index = min((row['event_index'] for row in stream['request_header_blocks']), default=-1)
        source_candidates = [row for row in url_sources.get(stream['request_source'], [])
                             if row['event_index'] <= header_index]
        source_request = source_candidates[-1] if source_candidates else None
        url_binding = 'HTTP2_SESSION_SEND_HEADERS pseudo-headers' if url else 'URL_REQUEST_START_JOB dependency at request time'
        if url is None and source_request:
            url = source_request['url']
        if not url or (hosts != set() and not _selected(url, hosts)):
            continue
        details = sessions.get(session, {})
        socket = details.get('socket')
        direction_bodies = {}
        for direction, headers in [('request', request_headers), ('response', response_headers)]:
            framer = framers.get((socket, direction))
            body = stream[direction]
            if stream['reset_events'] and not (body['ended'] or body['header_end']):
                body['errors'].append('Stream reset before END_STREAM')
            direction_bodies[direction] = _render_body(body, headers, max_body_bytes,
                                                       framer is None or framer.failed)
        status = _one_header(response_headers, ':status')
        indices = {block['event_index'] for direction in ('request', 'response')
                   for block in stream[direction + '_header_blocks']}
        for direction in ('request', 'response'):
            indices.update(stream[direction]['metadata_data_events'])
            for frame in stream[direction]['frames']:
                indices.update(span['event_index'] for span in frame['provenance'])
        transaction = {
            'id': 'http2:' + str(session) + ':' + str(stream_id), 'protocol': 'h2',
            'session_source': details.get('source', {'key': session}), 'stream_id': stream_id,
            'socket_source': details.get('socket_source'), 'url_request_source': stream['request_source'],
            'url': url, 'method': _one_header(request_headers, ':method') or (source_request or {}).get('method'),
            'url_binding': url_binding,
            'http_status': int(status) if status and status.isdecimal() else None,
            'request': {'headers': request_headers, 'header_blocks': stream['request_header_blocks'],
                        'body': direction_bodies['request']},
            'response': {'headers': response_headers, 'header_blocks': stream['response_header_blocks'],
                         'body': direction_bodies['response']},
            'reset_events': stream['reset_events'],
            'provenance': [event_refs[index] for index in sorted(indices) if index in event_refs],
            'native_browser_enforcement': 'not_observed_by_network_capture',
        }
        transactions.append(_sanitize_transaction(transaction) if redact_sensitive else transaction)
    return {'format': 'smartscreen_chromium_netlog_v1', 'source': source_info,
            'client_info': constants.get('clientInfo'), 'time_tick_offset': constants.get('timeTickOffset'),
            'event_count': len(events), 'http2_session_count': len(sessions),
            'http2_stream_count': len(streams), 'transaction_count': len(transactions),
            'transactions': transactions, 'issues': issues,
            'navigation_sequences': correlate_navigation(transactions),
            'limits': {'max_body_bytes': max_body_bytes, 'max_file_bytes': max_file_bytes},
            'redact_sensitive': redact_sensitive,
            'scope': 'HTTP/2 plaintext SSL byte events plus decoded headers; HTTP/1 and HTTP/3 bodies are not reconstructed.',
            'network_requests': 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('netlog', type=Path)
    parser.add_argument('-o', '--output', type=Path)
    parser.add_argument('--host', action='append', help='Select an exact service host; repeat for multiple')
    parser.add_argument('--all-hosts', action='store_true')
    parser.add_argument('--include-sensitive', action='store_true', help='Explicitly retain exact local bodies and credentials')
    parser.add_argument('--max-body-bytes', type=int, default=DEFAULT_MAX_BODY)
    args = parser.parse_args()
    if args.all_hosts and args.host:
        parser.error('--all-hosts and --host are mutually exclusive')
    if args.output and args.output.resolve() == args.netlog.resolve():
        parser.error('Output must differ from the source netlog')
    try:
        result = parse_netlog(args.netlog, hosts=[] if args.all_hosts else args.host,
                              max_body_bytes=args.max_body_bytes, redact_sensitive=not args.include_sensitive)
    except (ValueError, OSError) as error:
        parser.error(str(error))
    encoded = json.dumps(result, indent=2, ensure_ascii=False) + '\n'
    if args.output:
        args.output.write_text(encoded, encoding='utf-8')
    else:
        print(encoded, end='')


if __name__ == '__main__':
    main()

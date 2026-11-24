"""Offline inspection of observed SmartScreen protocol data.

This module does not send telemetry, feedback, or scareware reports. It separates
server decisions from opaque codes and correlates strings by exact equality only.
Native-code and live-control evidence lives in analysis/protocol_expansion/.
"""
import copy
import hashlib
import json
import math
from collections import Counter


MAX_DOCUMENT_BYTES = 8 * 1024 * 1024
MAX_NODES = 200000
MAX_DEPTH = 40
_BASE = 'https://data-edge.smartscreen.microsoft.com/api/browser/edge/data/'
_CATALOG = [
    {'name': 'topTraffic-get', 'method': 'GET', 'endpoint': _BASE + 'toptraffic/3',
     'authentication': 'SmartScreenPlain', 'validation': 'live_validated',
     'required_headers': {'If-None-Match': '"<dataset-version>"'},
     'initial_version': '0', 'observed_statuses': [200, 304],
     'body_kind': 'topTraffic', 'evidence': 'analysis/protocol_expansion/get_controls/'},
    {'name': 'publicBloom-get', 'method': 'GET', 'endpoint': _BASE + 'bloomfilter/x/3',
     'authentication': 'SmartScreenPlain', 'validation': 'live_validated',
     'required_headers': {'If-None-Match': '"<dataset-version>"'},
     'initial_version': '0', 'observed_statuses': [200],
     'body_kind': 'synchronousLookupUris',
     'scope': 'Public feed; not the current Edge custom Bloom or a malicious-URL verdict list.',
     'evidence': 'analysis/protocol_expansion/get_controls/public_bloom_etag/'},
    {'name': 'customBloom-get', 'method': 'GET', 'endpoint': _BASE + 'bloomfilter/e5/3',
     'authentication': 'SmartScreenPlain', 'validation': 'live_304_without_base',
     'required_headers': {'If-None-Match': '"<dataset-version>"'},
     'observed_statuses': [304], 'body_kind': 'customSynchronousLookupUris',
     'scope': 'Exact advertised query string was retained. Both native 0 and historical starting version returned no body. Availability remains unknown.',
     'evidence': 'analysis/protocol_expansion/get_controls/custom_bloom_native_get/'},
    {'name': 'actions-get', 'method': 'GET',
     'endpoint': 'https://ping-edge.smartscreen.microsoft.com/api/browser/edge/actions/3',
     'authentication': 'SmartScreenPlain', 'validation': 'live_method_rejected',
     'observed_statuses': [405], 'allow_header': 'POST',
     'evidence': 'analysis/protocol_expansion/get_controls/actions/'},
    {'name': 'telemetry', 'method': 'POST',
     'endpoint': 'https://telem-edge.smartscreen.microsoft.com/api/browser/edge/telemetry/3',
     'validation': 'native_capture', 'observed_statuses': [200],
     'root_fields': ['executionTime', 'random', 'samplingRates', 'config',
                     'correlationId', 'identity', 'userAgent', 'events'],
     'captured_event_types': ['scenario', 'serverCall', 'lookup', 'userAction'],
     'evidence': 'analysis/native_browser/parsed_final.json',
     'scope': 'Capture inspection only; no report submission helper.'},
    {'name': 'scareware-event', 'event_name': 'evaluateModel',
     'validation': 'native_static_only', 'network_endpoint': None,
     'envelope': {'data': [{'name': 'scareware', 'featureData': '<JSON string>'}]},
     'feature_data_fields': {'verdict': 'block', 'url': '<URL string>'},
     'native_sender': 'msedge.dll 158.0.4370.33 ARM64: 0x18966b360',
     'native_serializer': '0x18966b4d8',
     'scope': 'Internal event submission to a virtual interface is recovered; the final wire envelope/route has not been captured.',
     'evidence': 'analysis/protocol_expansion/report_auth_context.json'},
]


def protocol_catalog():
    """Return independent evidence-scoped route and event descriptions."""
    return copy.deepcopy(_CATALOG)


def _load(document):
    if isinstance(document, (str, bytes, bytearray)):
        if len(document) > MAX_DOCUMENT_BYTES:
            raise ValueError('Protocol document exceeds the size limit')
        try:
            document = json.loads(document)
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise ValueError('Protocol document must be valid JSON') from exc
    if not isinstance(document, dict):
        raise ValueError('Protocol document must be a JSON object')
    pending = [(document, 0)]
    nodes = size = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise ValueError('Protocol document exceeds structural limits')
        if isinstance(item, dict):
            if len(item) > MAX_NODES - nodes:
                raise ValueError('Protocol document exceeds structural limits')
            for key, value in item.items():
                if not isinstance(key, str):
                    raise ValueError('Protocol object keys must be strings')
                size += len(key.encode('utf-8', errors='surrogatepass'))
                pending.append((value, depth + 1))
        elif isinstance(item, list):
            if len(item) > MAX_NODES - nodes:
                raise ValueError('Protocol document exceeds structural limits')
            pending.extend((value, depth + 1) for value in item)
        elif isinstance(item, str):
            size += len(item.encode('utf-8', errors='surrogatepass'))
        elif item is not None and not isinstance(item, (bool, int, float)):
            raise ValueError('Protocol document contains non-JSON values')
        elif isinstance(item, float) and not math.isfinite(item):
            raise ValueError('Protocol numbers must be finite')
        if size > MAX_DOCUMENT_BYTES:
            raise ValueError('Protocol document exceeds the size limit')
    return document


def _limit(limit):
    if type(limit) is not int or not 0 <= limit <= 1000:
        raise ValueError('Report limit must be an integer from 0 to 1000')
    return limit


def _text(value, maximum=512):
    if not isinstance(value, str):
        return None
    return value if len(value) <= maximum else value[:maximum] + '[truncated]'


def _digest(value):
    return hashlib.sha256(value.encode('utf-8', errors='surrogatepass')).hexdigest()


def describe_context(value, *, include_sensitive=False):
    """Describe an opaque serverContext without treating any token as a score."""
    if type(include_sensitive) is not bool:
        raise ValueError('include_sensitive must be a boolean')
    if value is None:
        return {'present': False}
    if not isinstance(value, str):
        return {'present': True, 'valid_string': False}
    if len(value) > 65536:
        raise ValueError('serverContext exceeds the size limit')
    fields = value.split(';')
    result = {'present': True, 'valid_string': True, 'sha256': _digest(value),
              'length': len(value), 'semicolon_field_count': len(fields),
              'field_lengths': [len(field) for field in fields[:16]],
              'interpretation': 'Opaque server-supplied context. Exact equality supports reuse/correlation, not request uniqueness, confidence, or an enforcement decision.'}
    if include_sensitive:
        result['raw'] = _text(value, 4096)
        result['raw_truncated'] = len(value) > 4096
    return result


def _response(document, sensitive):
    wrapper = 'http_status' in document and 'response' in document
    status = document.get('http_status') if wrapper else None
    body = document.get('response') if wrapper else document
    if not isinstance(body, dict):
        return {'kind': 'response', 'http_status': status, 'decision': None,
                'server_contexts': [], 'rating': None,
                'interpretation': 'No JSON response object; no decision inferred.'}
    nested = body.get('result')
    decision_body = nested if isinstance(nested, dict) and '$type' in nested else body
    source = 'result.$type' if decision_body is nested else '$type'
    decision = _text(decision_body.get('$type'))
    # A saved client record supplies the route and status needed to distinguish
    # the observed browser file rating enum from unrelated opaque rating codes.
    file_rating = False
    if wrapper and type(status) is int and 200 <= status < 300:
        from smartscreen import ENDPOINTS
        value = body.get('rating')
        if (document.get('endpoint') == ENDPOINTS['file'] and '$type' not in body
                and not (isinstance(nested, dict) and '$type' in nested)
                and isinstance(value, str) and value in {'allow', 'unknown'}):
            decision, source, file_rating = value, 'rating', True
    if status is not None and (type(status) is not int or not 200 <= status < 300):
        decision = None
    contexts = []
    for path, obj in [('$', body), ('$.result', nested)]:
        if isinstance(obj, dict) and 'serverContext' in obj:
            contexts.append({'path': path + '.serverContext',
                             **describe_context(obj['serverContext'], include_sensitive=sensitive)})
    rating = body.get('rating') if 'rating' in body else (nested or {}).get('rating') if isinstance(nested, dict) else None
    return {'kind': 'response', 'http_status': status, 'decision': decision,
            'decision_source': source if decision is not None else None,
            'response_category': _text(decision_body.get('responseCategory')),
            'rating': _text(rating), 'rating_present': 'rating' in body or isinstance(nested, dict) and 'rating' in nested,
            'server_contexts': contexts,
            'interpretation': ('Recognized browser-file rating enum using the saved endpoint and successful HTTP status. '
                               if file_rating else 'Decision comes from the server $type field; other ratings are preserved without inferred semantics. ')
                              + 'Numeric code portions are not calibrated confidence. A server decision does not establish local browser or Windows enforcement.'}


def _telemetry(document, sensitive, limit):
    events = document.get('events')
    if not isinstance(events, list):
        raise ValueError('Telemetry events must be an array')
    counts = Counter()
    rows = []
    for index, event in enumerate(events):
        event_type = _text(event.get('$type'), 128) if isinstance(event, dict) else None
        counts[event_type or '<missing-or-invalid>'] += 1
        if index >= limit:
            continue
        row = {'index': index, 'type': event_type, 'valid_object': isinstance(event, dict)}
        if isinstance(event, dict):
            row['fields'] = sorted(_text(key, 128) for key in event)[:64]
            if event_type == 'serverCall':
                row['context'] = describe_context(event.get('telemetry'), include_sensitive=sensitive)
            for key in ('action', 'name', 'type'):
                if isinstance(event.get(key), str):
                    row[key if key != 'type' else 'lookup_type'] = _text(event[key])
            if sensitive:
                destination = event.get('destination')
                if isinstance(destination, dict):
                    row['destination_uri'] = _text(destination.get('uri'), 4096)
                if 'target' in event:
                    row['target'] = _text(event['target'], 4096)
        rows.append(row)
    rates = document.get('samplingRates')
    rate_summary = None
    if isinstance(rates, dict):
        rate_summary = {_text(key, 128): value for key, value in list(rates.items())[:64]
                        if type(value) in (int, float) and 0 <= value <= 1}
    count_rows = counts.most_common(64)
    return {'kind': 'telemetry', 'event_count': len(events), 'event_type_counts': dict(count_rows),
            'event_types_omitted': max(0, len(counts) - 64),
            'events': rows, 'events_omitted': max(0, len(events) - limit),
            'sampling_rates': rate_summary,
            'identity_omitted': 'identity' in document,
            'interpretation': 'Observed event fields only. Identity and credentials are always omitted. Telemetry receipt or a client-reported action is not independent proof of enforcement.'}


def _scareware(document, sensitive, limit):
    data = document.get('data')
    if not isinstance(data, list):
        raise ValueError('Scareware event data must be an array')
    rows = []
    for index, item in enumerate(data[:limit]):
        row = {'index': index, 'valid_object': isinstance(item, dict)}
        if isinstance(item, dict):
            row['name'] = _text(item.get('name'))
            features = item.get('featureData')
            row['feature_data_is_string'] = isinstance(features, str)
            if isinstance(features, str):
                row['feature_data_sha256'] = _digest(features)
                try:
                    parsed = _load(features)
                except ValueError:
                    row['feature_data_valid_json_object'] = False
                else:
                    row['feature_data_valid_json_object'] = True
                    row['verdict'] = _text(parsed.get('verdict'))
                    row['url_present'] = isinstance(parsed.get('url'), str)
                    if sensitive:
                        row['url'] = _text(parsed.get('url'), 4096)
        rows.append(row)
    return {'kind': 'scareware', 'event_name': 'evaluateModel', 'validation': 'native_static_only',
            'item_count': len(data), 'items': rows, 'items_omitted': max(0, len(data) - limit),
            'interpretation': 'Recovered internal event envelope, not a captured HTTP request. The embedded verdict is a client report, not a cloud response. No report is submitted.'}


def _body(transaction, side):
    obj = transaction.get(side)
    body = obj.get('body') if isinstance(obj, dict) else None
    if not isinstance(body, dict) or body.get('complete') is not True:
        return None
    return body.get('json') if isinstance(body.get('json'), dict) else None


def correlate_contexts(document, *, limit=100):
    """Match complete NetLog response contexts to complete serverCall events.

    Matching values can occur in several responses. Every matching response is
    reported; this deliberately does not choose a unique request association.
    """
    document = _load(document)
    limit = _limit(limit)
    transactions = document.get('transactions')
    if not isinstance(transactions, list):
        raise ValueError('Parsed NetLog transactions must be an array')
    responses, events = {}, []
    for index, transaction in enumerate(transactions):
        if not isinstance(transaction, dict):
            continue
        identifier = _text(transaction.get('id')) or 'transaction[' + str(index) + ']'
        response = _body(transaction, 'response')
        if response is not None:
            for path, obj in [('$', response), ('$.result', response.get('result'))]:
                if isinstance(obj, dict) and isinstance(obj.get('serverContext'), str):
                    context = obj['serverContext']
                    responses.setdefault(context, []).append({'transaction_id': identifier, 'path': path + '.serverContext'})
        request = _body(transaction, 'request')
        if request is not None and isinstance(request.get('events'), list):
            for event_index, event in enumerate(request['events']):
                if isinstance(event, dict) and event.get('$type') == 'serverCall' and isinstance(event.get('telemetry'), str):
                    events.append((identifier, event_index, event['telemetry']))
    rows, matched, source_budget = [], 0, limit
    for identifier, index, context in events:
        sources = responses.get(context, [])
        matched += bool(sources)
        if len(rows) < limit:
            kept_sources = sources[:source_budget]
            source_budget -= len(kept_sources)
            rows.append({'transaction_id': identifier, 'event_index': index, 'context_sha256': _digest(context),
                         'matching_response_count': len(sources), 'matching_responses': kept_sources,
                         'matching_responses_omitted': len(sources) - len(kept_sources)})
    return {'kind': 'netlog', 'response_context_count': sum(map(len, responses.values())),
            'distinct_response_context_count': len(responses), 'server_call_event_count': len(events),
            'matched_server_call_event_count': matched, 'correlations': rows,
            'correlations_omitted': max(0, len(events) - limit),
            'interpretation': 'Exact string equality in complete parsed bodies only. Repeated contexts are not unique request IDs; no temporal or causal association is inferred.'}


def inspect_protocol(document, *, kind='auto', include_sensitive=False, limit=100):
    """Inspect response, telemetry, scareware envelope, or parsed NetLog offline."""
    document = _load(document)
    limit = _limit(limit)
    if type(include_sensitive) is not bool:
        raise ValueError('include_sensitive must be a boolean')
    if kind == 'auto':
        if 'transactions' in document:
            kind = 'netlog'
        elif 'events' in document:
            kind = 'telemetry'
        elif isinstance(document.get('data'), list) and any(
                isinstance(item, dict) and item.get('name') == 'scareware' for item in document['data']):
            kind = 'scareware'
        else:
            kind = 'response'
    if kind == 'response':
        return _response(document, include_sensitive)
    if kind == 'telemetry':
        return _telemetry(document, include_sensitive, limit)
    if kind == 'scareware':
        return _scareware(document, include_sensitive, limit)
    if kind == 'netlog':
        return correlate_contexts(document, limit=limit)
    raise ValueError('Unknown protocol document kind')

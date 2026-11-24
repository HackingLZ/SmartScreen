"""Explain captured SmartScreen routing evidence without predicting enforcement.

This module performs no network or browser operations. Native ordering is based
on Edge 158.0.4370.33 ARM64; snapshot membership and caller-supplied observations
do not establish which branches a live browser actually executed.
"""
import argparse
import copy
import json
import ipaddress
import math
from pathlib import Path
import uuid

from smartscreen.data import feed_url_candidates
from smartscreen.model import score_title
from smartscreen.offline import analyze_url


EDGE_SHA256 = '788fe22e3a1a893f042a8bcdeef0765f0fd39c665d46de4f02c28bc5437f7173'
NAVIGATIONCOMPLETE_ENDPOINT = 'https://postnav-edge.smartscreen.microsoft.com/api/browser/edge/navigationcomplete/3'
EVIDENCE = 'analysis/decision_expansion/findings.md'
STRING_SIGNALS = (
    'title', 'faviconUrl', 'certIssuerCommonName', 'certIssuerLocalityName',
    'certIssuerStateOrProvinceName', 'certIssuerCountryName',
    'certSubjectCommonName', 'certSubjectLocalityName',
    'certSubjectStateOrProvinceName', 'certSubjectCountryName', 'certValidFrom', 'certValidTo',
)
ARRAY_SIGNALS = (
    'certIssuerStreetAddresses', 'certIssuerOrganizationNames',
    'certIssuerOrganizationUnitNames', 'certIssuerDomainComponents',
    'certSubjectStreetAddresses', 'certSubjectOrganizationNames',
    'certSubjectOrganizationUnitNames', 'certSubjectDomainComponents',
)
CONTEXT_FIELDS = ('userAgent', 'correlationId', 'identity', 'config', 'destination', 'referrer', 'type')
REQUIRED_CONTEXT_FIELDS = ('userAgent', 'correlationId', 'identity', 'destination', 'type')
CATEGORIES = {'allowed', 'customallowlist', 'customblocklist', 'custompolicy', 'casbpolicy',
              'untrusted', 'phishing', 'malicious', 'pua', 'techscam', 'exploit'}
RESULT_ROUTES = {
    'allow': 'Native allow-result completion branch.',
    'evaluate': 'Native asynchronous page-model evaluation; selection can cause navigationcomplete cloud lookup.',
    'warn': 'Native warning-result completion branch, with a separate remembered user-override check.',
    'block': 'Native block-result completion branch; the warning-only override check does not apply here.',
}


def _object(value, label):
    if not isinstance(value, dict):
        raise ValueError(label + ' must be a JSON object')
    if any(not isinstance(key, str) for key in value):
        raise ValueError(label + ' must have string object keys')
    try:
        serialized = json.dumps(value, allow_nan=False, ensure_ascii=False)
    except (ValueError, TypeError, RecursionError) as exc:
        raise ValueError(label + ' must contain finite JSON values') from exc
    if len(serialized.encode('utf-8')) > 8 * 1024 * 1024:
        raise ValueError(label + ' exceeds this tool\'s 8 MiB input limit')
    return copy.deepcopy(value)


def _string(value, label, *, empty=True):
    if not isinstance(value, str) or (not empty and not value) or '\0' in value:
        raise ValueError(label + ' must be a string without NUL bytes')
    if len(value.encode('utf-8')) > 16384:
        raise ValueError(label + ' exceeds this tool\'s 16,384-byte string limit')
    return value


def navigationcomplete_payload(context, models, signals, *, server_context=None):
    """Prepare the recovered request shape, including a fresh native capture.

    context must explicitly supply common navigation fields, such as a caller-
    prepared request. No identity, page data, scores, or correlation ID is
    invented. The captured native follow-up uses an empty userAgent, zero UUID,
    absent config/serverContext and an empty referrer object; those values are
    valid, but the caller must explicitly supply userAgent and correlationId.
    Config is optional. A missing referrer produces the captured empty object.
    server_context is explicit-only: a prior response value is not inherited.
    Rich signals support the captured HTTP redirect chain, TLS certificate
    fields and referrer-chain shape; unknown redirect-source/enum variants are
    rejected. This function sends nothing.
    """
    context = _object(context, 'Navigation context')
    missing = [key for key in REQUIRED_CONTEXT_FIELDS if key not in context]
    if missing:
        raise ValueError('Missing explicit navigation context: ' + ', '.join(missing))
    payload = {key: context[key] for key in CONTEXT_FIELDS if key in context}
    payload.setdefault('referrer', {})
    _string(payload['userAgent'], 'userAgent')
    _string(payload['correlationId'], 'correlationId', empty=False)
    try:
        uuid.UUID(payload['correlationId'])
    except (ValueError, AttributeError) as exc:
        raise ValueError('correlationId must be a UUID string') from exc
    for key in ('identity', 'config'):
        if key in payload:
            _object(payload[key], key)
    if payload['type'] not in ('top', 'frame', 'subresource'):
        raise ValueError('Model navigation type must be top, frame, or subresource')
    for key in ('destination', 'referrer'):
        navigation = _object(payload[key], key)
        if key == 'referrer' and not navigation:
            continue
        if set(navigation) != {'uri', 'ip'}:
            raise ValueError(key + ' requires exactly uri and ip')
        _string(navigation['uri'], key + '.uri', empty=key == 'referrer')
        if navigation['uri']:
            feed_url_candidates(navigation['uri'])
        if navigation['ip'] is not None:
            _string(navigation['ip'], key + '.ip', empty=False)
    if not isinstance(models, list) or len(models) > 256:
        raise ValueError('models must be an array of at most 256 explicit model results')
    payload['models'] = []
    for index, model in enumerate(models):
        model = _object(model, f'models[{index}]')
        if set(model) != {'name', 'score'}:
            raise ValueError('Each model result requires exactly name and score')
        _string(model['name'], 'Model name', empty=False)
        number = model['score']
        if isinstance(number, bool) or not isinstance(number, (int, float)):
            raise ValueError('Model score must be a finite number')
        try:
            number = float(number)
        except OverflowError as exc:
            raise ValueError('Model score must be representable as binary64') from exc
        if not math.isfinite(number):
            raise ValueError('Model score must be finite')
        payload['models'].append({'name': model['name'], 'score': number})
    if signals is None:
        payload['signals'] = None
    else:
        signals = _object(signals, 'Signals')
        unknown = set(signals) - set(STRING_SIGNALS) - set(ARRAY_SIGNALS) - {'redirectChain', 'enhancedRedirectChain'}
        if unknown:
            raise ValueError('Unvalidated signal fields: ' + ', '.join(sorted(unknown)))
        normalized = {}
        for key in STRING_SIGNALS:
            value = signals.get(key)
            normalized[key] = None if value is None else _string(value, 'signals.' + key)
        for key in ARRAY_SIGNALS:
            value = signals.get(key)
            if value is not None:
                if not isinstance(value, list) or len(value) > 256:
                    raise ValueError('signals.' + key + ' must be null or a bounded string array')
                for item in value:
                    _string(item, 'signals.' + key + ' entry')
            normalized[key] = value
        chain = signals.get('redirectChain', [])
        if not isinstance(chain, list) or len(chain) > 256:
            raise ValueError('signals.redirectChain must be a bounded array')
        for item in chain:
            if not isinstance(item, dict) or set(item) != {'uri'}:
                raise ValueError('Each redirectChain entry requires exactly uri')
            feed_url_candidates(_string(item['uri'], 'Redirect URI', empty=False))
        enhanced = signals.get('enhancedRedirectChain', {})
        if not isinstance(enhanced, dict):
            raise ValueError('signals.enhancedRedirectChain must be an object')
        if enhanced:
            if set(enhanced) != {'redirectSource', 'referrerChain'} or enhanced['redirectSource'] is not None:
                raise ValueError('Only captured redirectSource:null plus referrerChain is validated')
            referrers = enhanced['referrerChain']
            if not isinstance(referrers, list) or len(referrers) > 256:
                raise ValueError('enhancedRedirectChain.referrerChain must be a bounded array')
            referrer_fields = {'url', 'navigationInitiation', 'referrerUrl', 'type',
                               'navigationTimeMsec', 'isRetargeting', 'ipAddresses',
                               'serverRedirectChainByEntry'}
            for entry in referrers:
                if not isinstance(entry, dict) or set(entry) != referrer_fields:
                    raise ValueError('Referrer-chain entry has unvalidated or missing fields')
                for key in ('url', 'referrerUrl'):
                    value = _string(entry[key], 'referrerChain.' + key, empty=key == 'referrerUrl')
                    if value:
                        feed_url_candidates(value)
                for key in ('navigationInitiation', 'type'):
                    if type(entry[key]) is not int or entry[key] != 1:
                        raise ValueError('Only captured referrer-chain ' + key + '=1 is validated')
                number = entry['navigationTimeMsec']
                try:
                    valid_time = type(number) in (int, float) and math.isfinite(number) and 0 <= number <= 2 ** 53
                except OverflowError:
                    valid_time = False
                if not valid_time:
                    raise ValueError('navigationTimeMsec must be a finite nonnegative timestamp')
                if type(entry['isRetargeting']) is not bool:
                    raise ValueError('isRetargeting must be a bool')
                for key in ('ipAddresses', 'serverRedirectChainByEntry'):
                    if not isinstance(entry[key], list) or len(entry[key]) > 256:
                        raise ValueError('referrerChain.' + key + ' must be a bounded array')
                    for value in entry[key]:
                        _string(value, 'referrerChain.' + key + ' entry', empty=False)
                        if key == 'ipAddresses':
                            try:
                                ipaddress.ip_address(value)
                            except ValueError as exc:
                                raise ValueError('referrerChain.ipAddresses requires IP literals') from exc
                        else:
                            feed_url_candidates(value)
        if chain:
            expected = [entry['uri'] for entry in chain] + [payload['destination']['uri']]
            if not enhanced or not any(entry['serverRedirectChainByEntry'] == expected and
                                       entry['url'] == payload['destination']['uri']
                                       for entry in enhanced['referrerChain']):
                raise ValueError('redirectChain requires the captured coupled source-to-destination enhanced redirect sequence')
        normalized.update(redirectChain=chain, enhancedRedirectChain=enhanced)
        payload['signals'] = normalized
    if server_context is not None:
        payload['serverContext'] = _string(server_context, 'serverContext')
    return payload


def _cloud_evidence(document):
    if document is None:
        return {'state': 'not_supplied', 'result_type': None, 'response_category': None, 'actions': []}
    supplied = _object(document, 'Cloud response')
    wrapper = 'http_status' in supplied or 'response' in supplied
    body = supplied.get('response') if wrapper else supplied
    status = supplied.get('http_status') if wrapper else None
    report = {'state': 'provided_without_transport_metadata', 'http_status': status,
              'result_type': None, 'response_category': None, 'actions': [],
              'binding_to_input_url': 'not_verified', 'full_native_parse_validated': False,
              'supplied_response': supplied}
    if wrapper and (type(status) is not int or status != 200):
        report['state'] = 'http_failure_or_unvalidated_status'
        report['interpretation'] = 'The recovered native navigation path dispatches response JSON only after HTTP 200.'
        return report
    if not isinstance(body, dict):
        report['state'] = 'invalid_or_missing_response_object'
        return report
    actions = body.get('actions', [])
    if not isinstance(actions, list):
        report['actions_error'] = 'Actions must be an array; native processing is unknown for this malformed input.'
    else:
        for index, action in enumerate(actions):
            kind = action.get('$type') if isinstance(action, dict) else None
            report['actions'].append({'index': index, 'type': kind,
                                      'role': 'routing_cache_update' if kind == 'cache' else 'separate_response_action',
                                      'is_verdict': False, 'value': copy.deepcopy(action)})
    result = body.get('result')
    if not isinstance(result, dict):
        report['state'] = 'missing_navigation_result'
        return report
    kind, category = result.get('$type'), result.get('responseCategory')
    report['result_type'] = kind
    report['response_category'] = category
    recognized = isinstance(kind, str) and kind.lower() in RESULT_ROUTES
    known_category = isinstance(category, str) and category.lower() in CATEGORIES
    if not recognized or not known_category:
        report['state'] = 'unrecognized_result_or_category'
        report['interpretation'] = 'Exact server fields retained; native dispatch is not inferred.'
    else:
        report['state'] = 'recognized_native_result_fields' if wrapper else 'recognized_fields_without_transport_proof'
        report['native_dispatch'] = RESULT_ROUTES[kind.lower()]
        report['interpretation'] = 'A response instruction is not an observed browser UI or enforcement outcome.'
    return report


def explain_url(url, *, feeds=None, defaults=None, title=None, settings=None,
                model_name=None, cloud_response=None, cache_observation=None, navigation_type='top'):
    """Combine local evidence with the statically recovered conditional stages.

    feeds/defaults are optional snapshot directories. settings is JSON bytes,
    text or a decoded document. cache_observation is an existing cache analyzer
    result, never raw numeric cache entries. All supplied evidence is historical
    and the stages below are conditional rules, not a recorded execution trace.
    """
    candidates = feed_url_candidates(url)
    if navigation_type not in ('top', 'frame', 'download', 'subresource'):
        raise ValueError('Unknown navigation type')
    if defaults is not None and feeds is None:
        raise ValueError('Native defaults require a feed snapshot directory')
    local = analyze_url(url, feeds, defaults) if feeds is not None else None
    if (title is None) != (settings is None):
        raise ValueError('Title and settings must be supplied together')
    if model_name is not None and settings is None:
        raise ValueError('Model selection requires title and settings')
    scored = score_title(settings, title, model_name) if title is not None else None
    cloud = _cloud_evidence(cloud_response)
    cache = _object(cache_observation, 'Cache observation') if cache_observation is not None else None
    cache_route = None
    if cache is not None:
        if cache.get('state') not in ('hit', 'expired', 'miss', 'unknown', 'no_cache'):
            raise ValueError('Cache observation must come from a cache analyzer with an explicit state')
        if cache.get('routing_action') not in (None, 'allow', 'evaluate', 'call_server'):
            raise ValueError('Unrecognized cache routing_action; numeric cache enums are format-specific')
        if cache.get('state') == 'hit':
            cache_route = cache.get('routing_action')
        if cache.get('input_url', url) != url:
            raise ValueError('Cache observation belongs to a different input URL')
    datasets = {entry['id']: entry for entry in local['datasets']} if local else {}
    def membership(name):
        entry = datasets.get(name)
        return entry.get('membership') if entry and entry.get('state') == 'analyzed' else None
    def stage(name, function, rule, observations=None):
        return {'stage': name, 'native_function': function, 'rule': rule,
                'observations': observations or {}, 'executed_in_browser': 'unknown'}
    stages = [
        stage('browser_input_and_policy', '0x1835af170 / 0x1819c9b7c',
              'The identified browser path passes GURL::spec(). Policy, loopback handling, initial synchronous state, and feature flags precede lookup.',
              {'serialized_ascii_url_supported': True, 'navigation_type': navigation_type}),
        stage('synchronous_lookup_filter', '0x1819c9b7c / 0x1819cdeac',
              'The examined Edge path consults custom Bloom when synchronous state needs resolution, and for subresources. A zero subresource result skips later lookup. Other zero results mark asynchronous handling, not a safe verdict.',
              {'custom_bloom_snapshot_membership': membership('customSynchronousLookupUris'),
               'ordinary_bloom_snapshot_membership': membership('synchronousLookupUris'),
               'active_runtime_feed_or_fallback': 'unknown'}),
        stage('top_traffic', '0x1819ce864 / 0x1819cf53c',
              'When eligible (not synchronous and forceServiceDetermination disabled), a top-traffic hit completes this lookup branch before URI cache and cloud. The topTrafficHit sample bucket controls telemetry, not this membership return.',
              {'snapshot_membership': membership('topTraffic'), 'runtime_eligibility': 'unknown'}),
        stage('uri_routing_cache', '0x1819ce864 / 0x1819d4fc0',
              'If reached: allow completes locally; evaluate invokes model evaluation; call_server or no applicable routing entry proceeds to the navigation service. Persisted numeric enums must be decoded for their exact format.',
              {'routing_action_if_reached': cache_route, 'cache_observation': cache}),
        stage('title_and_other_models', '0x18dcde440 / 0x18dcdf7b0 / 0x18dce4da0',
              'Cache or cloud evaluate can invoke asynchronous models. A positive raw score or sampled nonpositive model selects the navigationcomplete cloud path. Download navigation is excluded from this evaluator. A score alone does not block.',
              {'title_score': scored, 'evaluation_requested_in_runtime': 'unknown', 'sampling': 'not_simulated'}),
        stage('cloud_actions', '0x18dcd9a00',
              'After a valid HTTP 200 response is parsed, response actions are processed before result dispatch. Cache actions update routing state; they are not the current navigation verdict.',
              {'response_state': cloud['state'], 'actions': cloud['actions']}),
        stage('cloud_result', '0x18dcd9a00 / 0x18cab0878',
              'Recognized result types dispatch to allow, evaluate, warn, or block completion branches. Category and type are distinct; transport failure is not an allow result.',
              {key: value for key, value in cloud.items() if key not in ('actions', 'supplied_response')}),
        stage('completion_and_warning_override', '0x1819f4ff0',
              'Completion is one-shot. The warn branch checks remembered user override; block uses a distinct completion state. Native callbacks then carry result and metadata to browser integration.',
              {'remembered_override': 'unknown', 'completion_or_timeout_state': 'unknown'}),
        stage('browser_ui_and_enforcement', '0x181a71090 / 0x1819c93f0 / 0x1839bb470 / 0x1839bc708 / 0x183e3e748',
              'The SDK adapts response category and posts completion to SmartScreenUrlCheckerImpl. The browser derives a threat type and selects synchronous or asynchronous handling; the latter reaches a source-labelled MaybeShowBlockingPage path. Lifecycle, cancellation, page state, policy and user interaction still gate the actual UI.',
              {'blocking_page_boundary_statically_traced': True, 'runtime_gates': 'unknown',
               'enforcement': 'unknown'}),
    ]
    return {'schema_version': 1, 'operation': 'explain_url_decision_evidence', 'input_url': url,
            'network_requests': 0, 'is_execution_trace': False, 'is_complete_blocklist': False,
            'final_enforcement': 'unknown', 'url_candidates': candidates, 'local_feeds': local,
            'cloud_response': cloud, 'stages': stages,
            'evidence': {'edge_version': '158.0.4370.33', 'architecture': 'ARM64',
                         'edge_dll_sha256': EDGE_SHA256, 'writeup': EVIDENCE},
            'limits': ['Historical snapshots do not identify the active runtime data or cache.',
                       'A supplied response is not cryptographically bound to this input URL by this tool.',
                       'The older standalone DLL checks ordinary then custom Bloom; the identified Edge path uses custom Bloom. These binaries are not interchangeable.',
                       'No complete local malicious-URL table is established by these routing structures.']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('url')
    parser.add_argument('--feeds', type=Path)
    parser.add_argument('--defaults', type=Path)
    parser.add_argument('--title')
    parser.add_argument('--settings', type=Path)
    parser.add_argument('--model')
    parser.add_argument('--cloud-response', type=Path)
    parser.add_argument('--cache-observation', type=Path)
    parser.add_argument('--type', default='top', choices=('top', 'frame', 'download', 'subresource'))
    args = parser.parse_args(argv)
    try:
        result = explain_url(args.url, feeds=args.feeds, defaults=args.defaults, title=args.title,
                             settings=args.settings.read_bytes() if args.settings else None,
                             model_name=args.model,
                             cloud_response=json.loads(args.cloud_response.read_text()) if args.cloud_response else None,
                             cache_observation=json.loads(args.cache_observation.read_text()) if args.cache_observation else None,
                             navigation_type=args.type)
        print(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False))
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

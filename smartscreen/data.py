#!/usr/bin/env python3
"""Inspect SmartScreen datasets while preserving unknown binary fields."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import re
import ipaddress
from urllib.parse import SplitResult
from collections import Counter

MAX_DATA_BYTES = 32 * 1024 * 1024
MAX_REPORT_ITEMS = 10000


def read_data(path, max_bytes=MAX_DATA_BYTES):
    """Bounded input loading for standalone files and snapshot directories."""
    with Path(path).open('rb') as source:
        raw = source.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError('Dataset exceeds the %d-byte input limit' % max_bytes)
    return raw


def _json(raw):
    try:
        return True, json.loads(raw)
    except (ValueError, UnicodeError, RecursionError):
        return False, None


def _limit(value):
    if type(value) is not int or not 0 <= value <= MAX_REPORT_ITEMS:
        raise ValueError('Report limit must be between 0 and %d' % MAX_REPORT_ITEMS)
    return value


def bloom_header(raw):
    """Decode the native 28-byte Murmur3 header, preserving unverified fields.

    Static evidence: FUN_1800b9538 (validation), FUN_1800ba138 (seed,
    double hashing/count/modulus), FUN_1800ba7b0 (LSB-first bit access).
    """
    if len(raw) < 28 or raw[8:16] != b'murmur3\0':
        raise ValueError('Expected the native Murmur3 filter header')
    size, seed = struct.unpack_from('<II', raw)
    count, bits, unknown = struct.unpack_from('<III', raw, 16)
    errors = []
    if size != len(raw):
        errors.append('declared_size_mismatch')
    if count == 0 and bits != 0:
        errors.append('zero_hash_count_with_nonempty_filter')
    if count > 100:
        errors.append('hash_count_exceeds_native_limit')
    if len(raw) != 28 + (bits + 7) // 8:
        errors.append('bit_payload_size_mismatch')
    payload = raw[28:]
    usable = payload[:(bits + 7) // 8]
    ones = sum(bin(value).count('1') for value in usable)
    if usable and bits % 8 and len(usable) == (bits + 7) // 8:
        ones -= bin(usable[-1] & ~((1 << (bits % 8)) - 1)).count('1')
    return {'declared_size': size, 'seed': seed, 'algorithm': 'murmur3',
            'hash_count': count, 'bit_count': bits, 'unknown_u32_at_24': unknown,
            'payload_size': len(payload), 'set_bit_count': ones,
            'bit_order': 'least_significant_bit_first', 'valid': not errors,
            'validation_errors': errors}


def inspect_data(raw, kind=None):
    result = {'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'kind': kind}
    is_json, decoded = _json(raw)
    if is_json:
        result['format'] = 'json'
        if isinstance(decoded, dict):
            result['keys'] = list(decoded)
            if isinstance(decoded.get('models'), list):
                models = []
                for model in decoded['models']:
                    if not isinstance(model, dict):
                        continue
                    summary = {k: model[k] for k in ('name', 'threshold', 'bias', 'features', 'samplingRate') if k in model}
                    if isinstance(model.get('weights'), list):
                        summary['weight_count'] = len(model['weights'])
                    if isinstance(model.get('terms'), list):
                        summary['term_count'] = len(model['terms'])
                        summary['terms'] = [{k: term[k] for k in ('features', 'delimiters', 'lengthWeight') if k in term} |
                                            {'token_weight_count': len(term['tokenWeights']) if isinstance(term.get('tokenWeights'), list) else None}
                                            for term in model['terms'] if isinstance(term, dict)]
                        summary['token_weight_count'] = sum(term['token_weight_count'] or 0 for term in summary['terms'])
                    models.append(summary)
                result['models'] = models
        return result
    if kind == 'topTraffic':
        if len(raw) % 16:
            raise ValueError('Top-traffic data is not a sequence of 16-byte records')
        entries = [raw[i:i + 16] for i in range(0, len(raw), 16)]
        result.update({'format': 'opaque_128bit_records', 'record_count': len(entries),
                       'unique_count': len(set(entries)), 'lexicographically_sorted': entries == sorted(entries),
                       'record_encoding': 'first_16_bytes_of_sha256_over_utf16le_candidate',
                       'note': 'SHA256/UTF-16LE truncation is verified. Exact-key lookup and native-validated serialized HTTP(S) URL candidates are supported; raw Unicode and synthetic fallback forms remain unsupported. Records cannot be decoded into a complete plaintext list.'})
        return result
    if len(raw) >= 28 and raw[8:16] == b'murmur3\0':
        header = bloom_header(raw)
        result.update({'format': 'murmur3_filter', 'declared_size': struct.unpack_from('<I', raw)[0],
                       'header_u32_at_4': struct.unpack_from('<I', raw, 4)[0], 'algorithm': 'murmur3',
                       'header_u32_at_16': struct.unpack_from('<I', raw, 16)[0],
                       'header_u32_at_20': struct.unpack_from('<I', raw, 20)[0],
                       'header_u32_at_24': struct.unpack_from('<I', raw, 24)[0],
                       'payload_size': len(raw) - 28, 'filter': header,
                       'note': 'Hashing, probes and bit order follow the native reader. Exact-key membership and native-validated serialized HTTP(S) URL candidates are supported. Offset 24 remains unnamed and is not consumed by the recovered membership reader.'})
        return result
    result['format'] = 'unknown_binary'
    result['prefix_hex'] = raw[:32].hex()
    return result


def inspect_file(path, kind=None):
    """Inspect a dataset file without making network requests."""
    report = inspect_data(read_data(path), kind)
    report['file'] = str(path)
    return report


def check_toptraffic_key(raw, key):
    """Check an exact candidate string, without imitating native URL preparation.

    Native FUN_18009ba80 hashes UTF-16 candidate text using the Sha256 object
    initialized by FUN_1800144a0, then searches 16-byte records. Two benign
    known-host matches against the saved feed independently verify this mapping.
    A match says nothing about browser enforcement or overall URL reputation.
    """
    if len(raw) % 16:
        raise ValueError('Top-traffic data is not a sequence of 16-byte records')
    if not isinstance(key, str):
        raise ValueError('The exact candidate key must be a string')
    try:
        encoded = key.encode('utf-16le')
    except UnicodeEncodeError as error:
        raise ValueError('Candidate key is not valid Unicode') from error
    record = hashlib.sha256(encoded).digest()[:16]
    found = any(raw[index:index + 16] == record for index in range(0, len(raw), 16))
    return {'kind': 'topTraffic', 'operation': 'exact_candidate_key_lookup',
            'key': key, 'encoding': 'utf-16le_without_terminator',
            'hash': 'sha256_first_16_bytes', 'record_hex': record.hex(), 'present': found,
            'native_url_candidate_generation_supported': False,
            'interpretation': 'Exact candidate hash membership only. This is not a URL reputation or enforcement verdict; no URL normalization is performed.'}


def murmur3_x64_128(data, seed=0):
    """Native MurmurHash3 x64_128, returning little-endian h1 followed by h2.

    Constants and rotations match FUN_1800149d8 in the captured ARM64 DLL.
    This implementation uses unsigned 64-bit arithmetic and a uint32 seed.
    """
    if not isinstance(data, bytes):
        raise ValueError('Hash input must be bytes')
    if type(seed) is not int or not 0 <= seed <= 0xffffffff:
        raise ValueError('Murmur3 seed must be an unsigned 32-bit integer')
    mask = 0xffffffffffffffff
    c1, c2 = 0x87c37b91114253d5, 0x4cf5ad432745937f

    def rotate(value, count):
        return ((value << count) | (value >> (64 - count))) & mask

    def mix(value):
        value = ((value ^ (value >> 33)) * 0xff51afd7ed558ccd) & mask
        value = ((value ^ (value >> 33)) * 0xc4ceb9fe1a85ec53) & mask
        return value ^ (value >> 33)

    h1 = h2 = seed
    end = len(data) - len(data) % 16
    for offset in range(0, end, 16):
        k1, k2 = struct.unpack_from('<QQ', data, offset)
        h1 ^= (rotate((k1 * c1) & mask, 31) * c2) & mask
        h1 = ((rotate(h1, 27) + h2) * 5 + 0x52dce729) & mask
        h2 ^= (rotate((k2 * c2) & mask, 33) * c1) & mask
        h2 = ((rotate(h2, 31) + h1) * 5 + 0x38495ab5) & mask
    tail = data[end:]
    if len(tail) > 8:
        k2 = int.from_bytes(tail[8:], 'little')
        h2 ^= (rotate((k2 * c2) & mask, 33) * c1) & mask
    if tail:
        k1 = int.from_bytes(tail[:8], 'little')
        h1 ^= (rotate((k1 * c1) & mask, 31) * c2) & mask
    h1 ^= len(data)
    h2 ^= len(data)
    h1 = (h1 + h2) & mask
    h2 = (h2 + h1) & mask
    h1, h2 = mix(h1), mix(h2)
    h1 = (h1 + h2) & mask
    h2 = (h2 + h1) & mask
    return struct.pack('<QQ', h1, h2)


def check_bloom_key(raw, key, kind=None):
    """Evaluate one exact UTF-16LE key with the native Bloom membership rules.

    A positive is probabilistic membership, not a reputation or enforcement
    decision. URL canonicalization/candidate generation is not performed.
    """
    header = bloom_header(raw)
    if not header['valid']:
        raise ValueError('Invalid Bloom filter: ' + ', '.join(header['validation_errors']))
    if not isinstance(key, str):
        raise ValueError('The exact candidate key must be a string')
    try:
        encoded = key.encode('utf-16le')
    except UnicodeEncodeError as error:
        raise ValueError('Candidate key is not valid Unicode') from error
    if header['bit_count'] == 0 and header['hash_count'] != 0:
        raise ValueError('Zero-bit filter with nonzero hash count would divide by zero in the native membership reader')
    digest = murmur3_x64_128(encoded, header['seed'])
    h1, h2 = struct.unpack('<QQ', digest)
    indexes = [((h1 + i * h2) & 0xffffffffffffffff) % header['bit_count']
               for i in range(header['hash_count'])]
    values = [bool(raw[28 + index // 8] & (1 << (index % 8))) for index in indexes]
    return {'kind': kind or 'murmur3_filter', 'operation': 'exact_candidate_key_lookup',
            'key': key, 'encoding': 'utf-16le_without_terminator', 'hash': 'murmur3_x64_128',
            'hash_hex': digest.hex(), 'seed': header['seed'], 'hash_count': header['hash_count'],
            'bit_count': header['bit_count'], 'probe_indexes': indexes, 'probe_values': values,
            'possibly_present': all(values), 'degenerate_empty_filter': not indexes,
            'native_url_candidate_generation_supported': False,
            'interpretation': 'Exact candidate Bloom membership only. A positive can be a false positive and is not a URL reputation or enforcement verdict. No URL normalization is performed.'}


def _decode_percent(value, protected=()):
    for unused in range(1000):
        decoded = re.sub(r'%([0-9a-fA-F]{2})',
                         lambda match: match.group(0).lower() if int(match.group(1), 16) in protected
                         else chr(int(match.group(1), 16)), value)
        if decoded == value:
            return value
        value = decoded
    raise ValueError('URL exceeds the native 1000-pass decoding limit')


def _ascii_lower(value):
    return value.translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'))


def _prepare_uri_ascii(value):
    protected = set(range(32)) | set(range(127, 256)) | {ord('#'), ord('?')}
    for unused in range(1000):
        match = re.match(r'(?i)^(https?:[/\\]{2})([^/?#\\]*)(.*)$', value)
        if match:
            authority = match[2]
            if '@' in authority:
                userinfo, authority = authority.rsplit('@', 1)
                if re.search(r'%(?![0-9a-fA-F]{2})', userinfo) or any(int(code, 16) < 32 or int(code, 16) >= 127 for code in re.findall(r'%([0-9a-fA-F]{2})', userinfo)):
                    raise ValueError('Malformed/control-byte userinfo uses native fallback behavior and is unsupported')
                value = match[1] + authority + match[3]
            if '%' not in authority:
                return value
            if any(int(code, 16) in protected for code in re.findall(r'%([0-9a-fA-F]{2})', authority)):
                raise ValueError('Protected percent-encoded authority delimiters require native fallback handling')
        changed = re.sub(r'%([0-9a-fA-F]{2})',
                         lambda match: match.group(0).lower() if int(match.group(1), 16) in protected
                         else chr(int(match.group(1), 16)), value)
        if changed == value:
            return value
        value = changed
    raise ValueError('URL exceeds the native 1000-pass parsing limit')


def _uri_component(value, escaped):
    value = _ascii_lower(_decode_percent(value))
    return ''.join('%%%02x' % ord(ch) if ord(ch) < 32 or ord(ch) >= 127 or ch in escaped else ch for ch in value)


def _uri_path(value):
    value = _uri_component(value, ' ?#,<>|`{}^"%').replace('\\', '/')
    output, index = [], 0
    # Native dot-segment removal occurs before duplicate-slash removal.
    while index < len(value):
        if value.startswith('/..', index) and (index + 3 == len(value) or value[index + 3] == '/'):
            while output and output[-1] != '/':
                output.pop()
            if output:
                output.pop()
            index += 3
        elif value.startswith('/.', index) and (index + 2 == len(value) or value[index + 2] == '/'):
            index += 2
        else:
            output.append(value[index])
            index += 1
    return re.sub('/+', '/', ''.join(output)).rstrip('/')


def _legacy_ipv4(host):
    parts = host.split('.')
    if not 1 <= len(parts) <= 4:
        return None
    values = []
    for part in parts:
        if re.fullmatch(r'0x[0-9a-f]+', part):
            digits, base = part[2:], 16
        elif re.fullmatch(r'[0-9]+', part):
            if len(part) > 1 and part.startswith('0'):
                if any(ch not in '01234567' for ch in part):
                    return None
                digits, base = part, 8
            else:
                digits, base = part, 10
        else:
            return None
        value = 0
        for digit in digits:
            updated = (value * base + int(digit, 16)) & 0xffffffff
            if updated < value:
                return None
            value = updated
        values.append(value)
    if any(value > 255 for value in values[:-1]) or values[-1] >= 1 << (8 * (5 - len(values))):
        return None
    integer = values[-1]
    for index, value in enumerate(values[:-1]):
        integer |= value << (24 - index * 8)
    return str(ipaddress.IPv4Address(integer))


def feed_url_candidates(url):
    """Native-validated HTTP(S) candidate generation with explicit limitations.

    Supports ASCII/punycode hosts, valid IP literals and numeric IPv4 forms,
    userinfo/ports, recursive percent escapes, and native component escaping.
    Raw Unicode stays unsupported: the core native reader truncates UTF-8 and
    upstream browser IDN preprocessing has not been established.
    """
    if not isinstance(url, str) or not url or len(url) > 4096:
        raise ValueError('URL must be a nonempty string of at most 4096 characters')
    if any(ord(ch) >= 128 for ch in url):
        raise ValueError('Raw Unicode URL input is unsupported: supply the browser-serialized punycode/percent-encoded URL; native core UTF-8 truncation is not treated as browser-equivalent IDN handling')
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in url):
        raise ValueError('Raw control characters require native preprocessing; percent-encoded controls are supported')
    prepared = _prepare_uri_ascii(url.strip(' '))
    pieces = re.split(r'([?#])', prepared, maxsplit=1)
    prepared = pieces[0].replace('\\', '/') + ''.join(pieces[1:])
    if prepared.startswith(' '):
        raise ValueError('Encoded leading whitespace is outside supported URL parsing scope')
    parsed = re.fullmatch(r'(?i)(https?)://([^/?#]*)(.*)', prepared)
    if not parsed or not parsed[2]:
        raise ValueError('Only absolute HTTP(S) URLs are supported')
    path_query, fragment_mark, fragment_text = parsed[3].partition('#')
    path_text, query_mark, query_text = path_query.partition('?')
    # Splitting explicitly avoids Python-version-dependent IPv6 validation in
    # urlsplit; native-compatible literal validation follows below.
    parts = SplitResult(parsed[1], parsed[2], path_text, query_text, fragment_text)
    authority = parts.netloc.rsplit('@', 1)[-1]
    # Validate numeric port syntax even though the native canonical text omits it.
    if authority.startswith('['):
        close = authority.find(']')
        if close < 0 or '%' in authority[:close]:
            raise ValueError('IPv6 zone identifiers or malformed literals are unsupported')
        suffix = authority[close + 1:]
        literal = authority[1:close]
        if '.' in literal:
            prefix, separator, tail = literal.rpartition(':')
            octets = tail.split('.')
            if len(octets) != 4 or any(not re.fullmatch(r'[0-9]{1,3}', octet) or int(octet) > 255 for octet in octets):
                raise ValueError('Unsupported embedded IPv4 syntax in IPv6 address')
            literal = prefix + separator + '.'.join(str(int(octet)) for octet in octets)
        packed = ipaddress.IPv6Address(literal).packed
        host = '[' + ':'.join('%04x' % word for word in struct.unpack('>8H', packed)) + ']'
        host_type = 'ipv6'
    else:
        original_host, separator, port = authority.partition(':')
        suffix = separator + port
        original_host = _ascii_lower(original_host)
        host = _legacy_ipv4(original_host)
        host_type = 'ipv4' if host is not None else 'dns'
        if host is None:
            host = original_host[:-1] if original_host.endswith('.') else original_host
            if not host or len(host) > 253 or any(not re.fullmatch(r'[a-z0-9_-]{1,63}', label) for label in host.split('.')):
                raise ValueError('Unsupported DNS hostname or encoded authority delimiter')
    if suffix and (not suffix.startswith(':') or (suffix[1:] and (not suffix[1:].isdigit() or int(suffix[1:]) > 65535))):
        raise ValueError('Invalid URL port; synthetic native fallback URLs are outside supported scope')
    labels = host.split('.') if host_type == 'dns' else [host]
    path = _uri_path(parts.path)
    has_query = '?' in prepared.split('#', 1)[0]
    has_fragment = '#' in prepared
    query = '?' + _uri_component(parts.query, ' #"\'%') if has_query else ''
    fragment = '#' + _uri_component(parts.fragment, ' \'"%') if has_fragment else ''
    candidate = host + path + query + fragment
    candidates = [candidate]
    if has_fragment:
        candidate = candidate[:-(len(fragment))]
        candidates.append(candidate)
    if has_query:
        candidate = candidate[:-(len(query))]
        candidates.append(candidate)
    while '/' in candidate:
        candidate = candidate.rsplit('/', 1)[0]
        candidates.append(candidate)
    for index in range(1, len(labels)):
        candidates.append('.'.join(labels[index:]))
    if len(candidates) > 128:
        raise ValueError('URL exceeds the 128-candidate report limit')
    return {'input_url': url, 'canonical_url': parts.scheme.lower() + '://' + host + path + query + fragment,
            'candidates': candidates, 'candidate_count': len(candidates),
            'scope': 'native_validated_http_url_subset', 'host_type': host_type,
            'normalization': 'Recursive percent decoding, ASCII lowercase, native component escaping, credential/port removal, IP formatting and path cleanup; fragment/query/path removal followed by DNS suffixes only',
            'limits': 'Raw Unicode, controls, IPv6 zones, malformed authorities and native synthetic fallback URLs remain unsupported. Supply browser-serialized punycode/percent-encoded forms for international URLs. This is not a reputation or enforcement verdict.'}


def check_feed_url(raw, url, kind=None):
    """Check native-style URL candidates within the explicitly supported subset."""
    prepared = feed_url_candidates(url)
    if kind == 'topTraffic':
        inspect_data(raw, kind)
        operation = check_toptraffic_key
        field = 'present'
        feed_kind = kind
    elif len(raw) >= 28 and raw[8:16] == b'murmur3\0':
        operation = lambda data, key: check_bloom_key(data, key, kind)
        field = 'possibly_present'
        feed_kind = kind or 'murmur3_filter'
    else:
        raise ValueError('URL lookup requires a native Murmur3 filter or explicit --kind topTraffic')
    results, match = [], None
    for key in prepared['candidates']:
        result = operation(raw, key)
        results.append(result)
        if result[field]:
            match = key
            break
    return prepared | {'kind': feed_kind, 'operation': 'url_candidate_feed_lookup', field: match is not None,
                       'matched_candidate': match, 'tested_candidate_count': len(results),
                       'candidate_results': results,
                       'interpretation': 'Stops at the first feed hit, as the native wrapper does. Bloom hits can be false positives. This is not a SmartScreen reputation or enforcement verdict.'}


def _preview(value):
    if isinstance(value, str) and len(value) > 512:
        return {'type': 'string', 'length': len(value), 'prefix': value[:512], 'truncated': True}
    if isinstance(value, (dict, list)):
        encoded = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
        return {'type': type(value).__name__, 'length': len(value), 'sha256': hashlib.sha256(encoded).hexdigest()}
    return value


def _escape(value):
    return str(value).replace('~', '~0').replace('/', '~1')


def _named(items, key):
    if not all(isinstance(item, dict) and isinstance(item.get(key), str) for item in items):
        return None
    result = {item[key]: item for item in items}
    return result if len(result) == len(items) else None


def _json_changes(before, after, path='', field=None):
    # Model/weight order is not a semantic change when names/keys are unique.
    if isinstance(before, list) and isinstance(after, list) and field in ('models', 'weights', 'tokenWeights'):
        key = 'name' if field == 'models' else 'key'
        a, b = _named(before, key), _named(after, key)
        if a is not None and b is not None:
            yield from _json_changes(a, b, path + '/@' + key)
            return
    if type(before) is not type(after):
        yield {'path': path or '/', 'change': 'type_changed', 'before': _preview(before), 'after': _preview(after)}
    elif isinstance(before, dict):
        for key in sorted(before.keys() | after.keys()):
            child_path = path + '/' + _escape(key)
            if key not in before:
                yield {'path': child_path, 'change': 'added', 'after': _preview(after[key])}
            elif key not in after:
                yield {'path': child_path, 'change': 'removed', 'before': _preview(before[key])}
            else:
                yield from _json_changes(before[key], after[key], child_path, key)
    elif isinstance(before, list):
        for index in range(max(len(before), len(after))):
            child_path = path + '/' + str(index)
            if index >= len(before):
                yield {'path': child_path, 'change': 'added', 'after': _preview(after[index])}
            elif index >= len(after):
                yield {'path': child_path, 'change': 'removed', 'before': _preview(before[index])}
            else:
                yield from _json_changes(before[index], after[index], child_path)
    elif before != after:
        yield {'path': path or '/', 'change': 'changed', 'before': _preview(before), 'after': _preview(after)}


def _collect(changes, limit):
    samples, count = [], 0
    for change in changes:
        if count < limit:
            samples.append(change)
        count += 1
    return {'count': count, 'items': samples, 'truncated': count > limit}


def compare_data(before, after, kind=None, limit=100):
    """Compare complete datasets with exact counts and bounded detail arrays."""
    _limit(limit)
    a, b = inspect_data(before, kind), inspect_data(after, kind)
    report = {'kind': kind, 'before': a, 'after': b, 'changed': before != after, 'detail_limit': limit}
    if a['format'] != b['format']:
        report['comparison'] = 'format_changed'
    elif a['format'] == 'opaque_128bit_records':
        ac = Counter(before[i:i + 16] for i in range(0, len(before), 16))
        bc = Counter(after[i:i + 16] for i in range(0, len(after), 16))
        added, removed = bc.keys() - ac.keys(), ac.keys() - bc.keys()
        report.update({'comparison': 'opaque_records',
                       'added': _collect((value.hex() for value in sorted(added)), limit),
                       'removed': _collect((value.hex() for value in sorted(removed)), limit),
                       'multiplicity_changes': _collect(({'record': value.hex(), 'before': ac[value], 'after': bc[value]}
                                                        for value in sorted(ac.keys() & bc.keys()) if ac[value] != bc[value]), limit),
                       'record_order_changed': before != after and ac == bc})
    elif a['format'] == 'json':
        changes = _collect(_json_changes(json.loads(before), json.loads(after)), limit)
        report.update({'comparison': 'json', 'changes': changes, 'semantic_equal': changes['count'] == 0,
                       'path_note': 'Unique model names and weights/tokenWeights keys are compared as named maps; terms and ordinary arrays retain their order.'})
    elif a['format'] == 'murmur3_filter':
        ah, bh = a['filter'], b['filter']
        header_keys = ('seed', 'algorithm', 'hash_count', 'bit_count', 'unknown_u32_at_24')
        changes = [{'field': key, 'before': ah[key], 'after': bh[key]} for key in header_keys if ah[key] != bh[key]]
        compatible = ah['valid'] and bh['valid'] and all(ah[k] == bh[k] for k in ('seed', 'algorithm', 'hash_count', 'bit_count'))
        report.update({'comparison': 'bloom_filter', 'header_changes': changes, 'bit_positions_comparable': compatible})
        if compatible:
            def positions(added):
                for byte_index, (av, bv) in enumerate(zip(before[28:], after[28:])):
                    changed = (bv & ~av) if added else (av & ~bv)
                    for bit in range(8):
                        index = byte_index * 8 + bit
                        if index < ah['bit_count'] and changed & (1 << bit):
                            yield index
            report['bits_set'] = _collect(positions(True), limit)
            report['bits_cleared'] = _collect(positions(False), limit)
        else:
            report['note'] = 'Bit changes are not assigned comparable positions when shape/hash parameters differ or validation fails.'
    else:
        report['comparison'] = 'opaque_bytes'
    return report


def _snapshot(directory):
    directory = Path(directory)
    if not directory.is_dir():
        raise ValueError('Snapshot must be a directory: ' + str(directory))
    result = {}
    for path in sorted(directory.glob('*.bin')):
        result.setdefault(path.stem, {})['body'] = path
    for path in sorted(directory.glob('*.response.json')):
        name = path.name[:-len('.response.json')]
        entry = result.setdefault(name, {})
        entry['metadata_file'] = str(path)
        try:
            metadata = json.loads(read_data(path))
            if not isinstance(metadata, dict):
                raise ValueError('Response record must be an object')
            headers = metadata.get('headers', {})
            headers = {k.lower(): v for k, v in headers.items()} if isinstance(headers, dict) else {}
            entry['metadata'] = {'http_status': metadata.get('http_status'), 'etag': headers.get('etag'),
                                  'endpoint': metadata.get('endpoint'), 'response_sha256': metadata.get('response_sha256')}
        except (OSError, ValueError, RecursionError) as error:
            entry['metadata_error'] = str(error)
    return result


def compare_snapshots(before, after, limit=100):
    """Compare directories produced by lists --download; missing 304 bodies stay unknown."""
    _limit(limit)
    a, b = _snapshot(before), _snapshot(after)
    details = []
    counts = Counter()
    integrity_mismatches = 0
    for name in sorted(a.keys() | b.keys()):
        av, bv = a.get(name, {}), b.get(name, {})
        item = {'id': name, 'before_metadata': av.get('metadata'), 'after_metadata': bv.get('metadata')}
        if name not in a:
            item['state'] = 'added_dataset'
        elif name not in b:
            item['state'] = 'removed_dataset'
        elif av.get('body') and bv.get('body'):
            try:
                item['data'] = compare_data(read_data(av['body']), read_data(bv['body']), name, limit)
                item['state'] = 'changed' if item['data']['changed'] else 'unchanged'
            except (OSError, ValueError, RecursionError) as error:
                item.update({'state': 'uncomparable', 'error': str(error)})
        else:
            item.update({'state': 'uncomparable', 'reason': 'One or both snapshots lack a body; a 304 response does not establish empty contents.'})
        for side, entry in [('before', av), ('after', bv)]:
            if entry.get('metadata_error'):
                item[side + '_metadata_error'] = entry['metadata_error']
            metadata = entry.get('metadata') or {}
            if entry.get('body') and metadata.get('http_status') == 200 and metadata.get('response_sha256'):
                expected = metadata['response_sha256']
                try:
                    actual = hashlib.sha256(read_data(entry['body'])).hexdigest()
                    matched = isinstance(expected, str) and expected.lower() == actual
                    item[side + '_integrity'] = {'status': 'match' if matched else 'mismatch',
                                                'expected_sha256': expected, 'actual_sha256': actual}
                    integrity_mismatches += int(not matched)
                except (OSError, ValueError) as error:
                    item[side + '_integrity'] = {'status': 'unverified', 'error': str(error)}
            elif entry.get('body'):
                item[side + '_integrity'] = {'status': 'unverified',
                    'reason': 'No HTTP 200 response SHA256 is available for this body.'}
        counts[item['state']] += 1
        details.append(item)
    return {'comparison': 'feed_snapshots', 'before_directory': str(before), 'after_directory': str(after),
            'dataset_count': len(details), 'counts': dict(counts), 'datasets': details[:limit],
            'datasets_truncated': len(details) > limit, 'detail_limit': limit,
            'integrity_mismatch_count': integrity_mismatches,
            'integrity_note': 'Dataset states describe actual file bytes. Integrity fields compare HTTP 200 response hashes with those bytes; a mismatch makes captured provenance unreliable.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file', type=Path, help='File to inspect, or the word compare followed by two files/directories')
    parser.add_argument('comparison_paths', nargs='*', type=Path)
    parser.add_argument('--kind', choices=['topTraffic', 'synchronousLookupUris', 'customSynchronousLookupUris', 'edgeSettings', 'customSettings'])
    parser.add_argument('--export-records', type=Path, help='Export opaque top-traffic records as newline-delimited hex')
    parser.add_argument('--key', help='Check one exact topTraffic or synchronousLookupUris candidate (no URL normalization or reputation verdict)')
    parser.add_argument('--url', help='Check URL candidates within the native-validated serialized HTTP(S) subset')
    parser.add_argument('--limit', type=int, default=100, help='Maximum reported changes per detail array (exact counts retained)')
    parser.add_argument('-o', '--output', type=Path)
    args = parser.parse_args()
    try:
        if str(args.file) == 'compare':
            if len(args.comparison_paths) != 2 or args.export_records or args.key is not None or args.url is not None:
                raise ValueError('compare requires two paths and does not accept --export-records, --key or --url')
            before, after = args.comparison_paths
            report = (compare_snapshots(before, after, args.limit) if before.is_dir() or after.is_dir()
                      else compare_data(read_data(before), read_data(after), args.kind, args.limit))
            raw = None
        else:
            if args.comparison_paths:
                raise ValueError('Inspection takes one input file')
            raw = read_data(args.file)
            report = inspect_data(raw, args.kind)
            if args.url is not None:
                if args.key is not None:
                    raise ValueError('--url and --key are mutually exclusive')
                report['url_lookup'] = check_feed_url(raw, args.url, args.kind)
            if args.key is not None:
                if args.kind == 'topTraffic':
                    report['key_lookup'] = check_toptraffic_key(raw, args.key)
                elif args.kind in ('synchronousLookupUris', 'customSynchronousLookupUris'):
                    report['key_lookup'] = check_bloom_key(raw, args.key, args.kind)
                else:
                    raise ValueError('--key requires --kind topTraffic, synchronousLookupUris or customSynchronousLookupUris')
        if args.export_records:
            if report['format'] != 'opaque_128bit_records':
                raise ValueError('Record export requires --kind topTraffic')
            args.export_records.write_text(''.join(raw[i:i + 16].hex() + '\n' for i in range(0, len(raw), 16)))
        output = json.dumps(report, indent=2, allow_nan=False) + '\n'
        if args.output:
            args.output.write_text(output, encoding='utf-8')
        else:
            print(output, end='')
    except (OSError, ValueError, RecursionError) as error:
        parser.exit(2, str(error) + '\n')

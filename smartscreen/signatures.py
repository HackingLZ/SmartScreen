"""Read embedded PE publisher metadata without executing files or fetching certificates.

Metadata parsing is not signature/trust validation. Optional Windows WinVerifyTrust
uses only the local certificate cache and checks embedded signatures, not catalogs.
Wire fields follow the recovered SmartScreen AuthenticodeInformation serializer.
"""
import base64
import contextlib
import ctypes
import datetime
import hashlib
import json
import os
from pathlib import Path
import stat
import struct

MAX_CERTIFICATE_BYTES = 32 * 1024 * 1024
MAX_CERTIFICATES = 128
MAX_SIGNATURES = 16
SCHEMA_EVIDENCE = 'analysis/signatures/native_schema.json:180055df0,1800ea710'
DIGESTS = {'1.3.14.3.2.26': 'SHA1', '2.16.840.1.101.3.4.2.1': 'SHA256',
           '2.16.840.1.101.3.4.2.2': 'SHA384', '2.16.840.1.101.3.4.2.3': 'SHA512'}
SIGNED_DATA = '1.2.840.113549.1.7.2'
SPC_INDIRECT_DATA = '1.3.6.1.4.1.311.2.1.4'
NESTED_SIGNATURE = '1.3.6.1.4.1.311.2.4.1'


class SignatureDependencyError(ValueError):
    pass


def _b64(value):
    return base64.b64encode(value).decode('ascii')


class _DER:
    """Bounded definite-length ASN.1 reader; does not implement arbitrary BER."""
    def __init__(self, data, start=0, end=None, depth=0):
        end = len(data) if end is None else end
        if depth > 24 or start + 2 > end:
            raise ValueError('Truncated or excessively nested DER')
        self.data, self.start, self.depth = data, start, depth
        self.tag = data[start]
        if self.tag & 31 == 31:
            raise ValueError('Unsupported high-tag-number DER')
        cursor = start + 2
        length = data[start + 1]
        if length & 128:
            count = length & 127
            if not 1 <= count <= 4 or cursor + count > end or data[cursor] == 0:
                raise ValueError('Invalid DER length')
            length = int.from_bytes(data[cursor:cursor + count], 'big')
            cursor += count
            if length < 128:
                raise ValueError('Nonminimal DER length')
        self.content_start, self.end = cursor, cursor + length
        if self.end > end:
            raise ValueError('DER value exceeds its container')

    @property
    def value(self):
        return self.data[self.content_start:self.end]

    @property
    def raw(self):
        return self.data[self.start:self.end]

    def children(self, expected=None):
        if expected is not None and self.tag != expected:
            raise ValueError('Unexpected DER container tag')
        cursor, result = self.content_start, []
        while cursor < self.end:
            if len(result) >= 4096:
                raise ValueError('DER container exceeds item limit')
            child = _DER(self.data, cursor, self.end, self.depth + 1)
            result.append(child)
            cursor = child.end
        return result


def _oid(value):
    if value.tag != 6 or not value.value:
        raise ValueError('Expected a DER object identifier')
    numbers, current = [], 0
    for byte in value.value:
        current = (current << 7) | (byte & 127)
        if current > 2 ** 63:
            raise ValueError('Oversized OID component')
        if not byte & 128:
            numbers.append(current)
            current = 0
    if value.value[-1] & 128 or not numbers:
        raise ValueError('Truncated object identifier')
    first = numbers.pop(0)
    return '.'.join(map(str, [min(first // 40, 2), first - min(first // 40, 2) * 40] + numbers))


def _simple_name(name):
    # CERT_NAME_RDN_TYPE + CERT_SIMPLE_NAME_STR: forward RDN values without OIDs.
    def quote(value):
        if not isinstance(value, str):
            raise ValueError('Unsupported non-string certificate name')
        if value != value.strip() or any(c in value for c in ',+="<>#;\n'):
            return '"' + value.replace('"', '""') + '"'
        return value
    return ', '.join(' + '.join(quote(attr.value) for attr in rdn) for rdn in name.rdns)


def _certificate(cert, raw):
    def date(name):
        value = getattr(cert, name + '_utc', None)
        if value is None:
            value = getattr(cert, name).replace(tzinfo=datetime.timezone.utc)
        return value.isoformat()
    return {'sha1': hashlib.sha1(raw).hexdigest(), 'sha256': hashlib.sha256(raw).hexdigest(),
            'serial_number_hex': format(cert.serial_number, 'x'),
            'subject': cert.subject.rfc4514_string(), 'issuer': cert.issuer.rfc4514_string(),
            'subject_name_simple': _simple_name(cert.subject),
            'issuer_name_simple': _simple_name(cert.issuer),
            'not_before': date('not_valid_before'), 'not_after': date('not_valid_after'),
            'name_format': 'CERT_SIMPLE_NAME_STR reconstruction; native ANSI rendering is only oracle-checked for captured ASCII names'}


def _signed_data(raw, *, depth=0):
    try:
        from cryptography import x509
        from cryptography.exceptions import UnsupportedAlgorithm
    except ImportError as error:
        raise SignatureDependencyError('Embedded certificate extraction requires the optional cryptography package') from error
    try:
        return _parse_signed_data(raw, x509, depth=depth)
    except (x509.InvalidVersion, x509.DuplicateExtension,
            x509.UnsupportedGeneralNameType, UnsupportedAlgorithm) as error:
        raise ValueError('Unsupported or malformed embedded X.509 certificate: ' + str(error)) from error


def _parse_signed_data(raw, x509, *, depth=0):
    if depth > 4:
        raise ValueError('Nested signature depth limit exceeded')
    root = _DER(raw)
    if any(raw[root.end:]):
        raise ValueError('Nonzero bytes follow the CMS object')
    ci = root.children(0x30)
    if len(ci) != 2 or _oid(ci[0]) != SIGNED_DATA:
        raise ValueError('WIN_CERTIFICATE is not PKCS#7 SignedData')
    explicit = ci[1].children(0xa0)
    if len(explicit) != 1:
        raise ValueError('Malformed SignedData wrapper')
    fields = explicit[0].children(0x30)
    if len(fields) < 4 or fields[-1].tag != 0x31:
        raise ValueError('Malformed SignedData fields')
    content = fields[2].children(0x30)
    if not content:
        raise ValueError('Missing signed content type')
    content_type = _oid(content[0])
    image_digest = None
    if content_type == SPC_INDIRECT_DATA and len(content) == 2:
        wrapped = content[1].children(0xa0)
        if len(wrapped) != 1:
            raise ValueError('Malformed Authenticode content')
        indirect = _DER(wrapped[0].value) if wrapped[0].tag == 4 else wrapped[0]
        indirect_fields = indirect.children(0x30)
        if len(indirect_fields) != 2:
            raise ValueError('Malformed SpcIndirectDataContent')
        digest = indirect_fields[1].children(0x30)
        if len(digest) != 2 or digest[1].tag != 4:
            raise ValueError('Malformed signed image digest')
        algorithm = digest[0].children(0x30)
        if not algorithm:
            raise ValueError('Missing image digest algorithm')
        oid = _oid(algorithm[0])
        name = DIGESTS.get(oid)
        if name and len(digest[1].value) != hashlib.new(name.lower()).digest_size:
            raise ValueError('Image digest length disagrees with algorithm')
        image_digest = {'algorithm_oid': oid, 'algorithm': name, 'hex': digest[1].value.hex()}
    certs, certificate_objects = [], []
    for item in fields[3:-1]:
        if item.tag != 0xa0:
            continue
        for certificate in item.children():
            if certificate.tag != 0x30:
                continue
            if len(certs) >= MAX_CERTIFICATES:
                raise ValueError('Certificate count limit exceeded')
            cert = x509.load_der_x509_certificate(certificate.raw)
            certs.append(_certificate(cert, certificate.raw))
            certificate_objects.append(cert)
    signers, nested = [], []
    for info in fields[-1].children(0x31):
        if len(signers) >= MAX_SIGNATURES:
            raise ValueError('Signer count limit exceeded')
        signer = info.children(0x30)
        if len(signer) < 5:
            raise ValueError('Malformed SignerInfo')
        sid = signer[1]
        matches = []
        if sid.tag == 0x30:
            identifier = sid.children(0x30)
            if len(identifier) != 2 or identifier[1].tag != 2:
                raise ValueError('Malformed issuer-and-serial signer identifier')
            serial = int.from_bytes(identifier[1].value, 'big', signed=True)
            matches = [index for index, cert in enumerate(certificate_objects)
                       if cert.serial_number == serial and cert.issuer.public_bytes() == identifier[0].raw]
        elif sid.tag == 0x80:
            for index, cert in enumerate(certificate_objects):
                try:
                    if cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest == sid.value:
                        matches.append(index)
                except x509.ExtensionNotFound:
                    pass
        else:
            raise ValueError('Unsupported signer identifier')
        certificate_index = matches[0] if len(matches) == 1 else None
        unsigned = signer[-1].children() if signer[-1].tag == 0xa1 else []
        attribute_oids = []
        for attribute in unsigned:
            parts = attribute.children(0x30)
            if len(parts) != 2:
                raise ValueError('Malformed unsigned signer attribute')
            oid = _oid(parts[0])
            attribute_oids.append(oid)
            if oid == NESTED_SIGNATURE:
                for value in parts[1].children(0x31):
                    nested.append(_signed_data(value.raw, depth=depth + 1))
                    if len(nested) > MAX_SIGNATURES:
                        raise ValueError('Nested signature count limit exceeded')
        signers.append({'certificate_index': certificate_index,
                        'certificate_match_count': len(matches),
                        'unsigned_attribute_oids': attribute_oids})
    return {'content_type': content_type, 'image_digest': image_digest,
            'cms_sha256': hashlib.sha256(root.raw).hexdigest(), 'cms_size': len(root.raw),
            'cms_base64': _b64(root.raw), 'certificates': certs, 'signers': signers,
            'nested_signatures': nested, 'cryptographic_signature_valid': None,
            'trust_valid': None, 'timestamp_valid': None}


def _pe_certificates(stream, size):
    def read(offset, length):
        if offset < 0 or length < 0 or offset + length > size:
            raise ValueError('PE field exceeds file bounds')
        stream.seek(offset)
        value = stream.read(length)
        if len(value) != length:
            raise ValueError('File changed during metadata extraction')
        return value
    if size < 2 or read(0, 2) != b'MZ':
        return None, []
    if size < 64:
        raise ValueError('Truncated DOS header')
    nt = struct.unpack('<I', read(60, 4))[0]
    header = read(nt, 24)
    if header[:4] != b'PE\0\0':
        raise ValueError('Invalid PE signature')
    optional_size = struct.unpack_from('<H', header, 20)[0]
    optional = read(nt + 24, optional_size)
    if len(optional) < 2:
        raise ValueError('Missing PE optional header')
    magic = struct.unpack_from('<H', optional)[0]
    directory = {0x10b: 96, 0x20b: 112}.get(magic)
    if directory is None or len(optional) < directory:
        raise ValueError('Unsupported or truncated PE optional header')
    count = struct.unpack_from('<I', optional, directory - 4)[0]
    section_count = struct.unpack_from('<H', header, 6)[0]
    if section_count > 4096:
        raise ValueError('Excessive PE section count')
    section_table = read(nt + 24 + optional_size, section_count * 40)
    sections = [{'size': struct.unpack_from('<I', section_table, index * 40 + 16)[0],
                 'offset': struct.unpack_from('<I', section_table, index * 40 + 20)[0]}
                for index in range(section_count)]
    description = {'machine': struct.unpack_from('<H', header, 4)[0], 'optional_header_magic': magic,
                   'headers_size': struct.unpack_from('<I', optional, 60)[0],
                   'section_table_end': nt + 24 + optional_size + section_count * 40,
                   'checksum_offset': nt + 24 + 64, 'security_directory_offset': nt + 24 + directory + 32,
                   'sections': sections}
    if count <= 4:
        return description, []
    if len(optional) < directory + 40:
        raise ValueError('Truncated certificate data directory')
    offset, length = struct.unpack_from('<II', optional, directory + 32)
    description.update({'certificate_table_offset': offset, 'certificate_table_size': length})
    if not offset and not length:
        return description, []
    if not offset or length < 8 or offset % 8 or length > MAX_CERTIFICATE_BYTES:
        raise ValueError('Invalid or oversized PE certificate table')
    table = read(offset, length)
    cursor, records = 0, []
    while cursor < length:
        if len(records) >= MAX_SIGNATURES or cursor + 8 > length:
            raise ValueError('Truncated or excessive WIN_CERTIFICATE entries')
        entry_length, revision, kind = struct.unpack_from('<IHH', table, cursor)
        if entry_length < 8 or cursor + entry_length > length:
            raise ValueError('Invalid WIN_CERTIFICATE length')
        records.append({'offset': offset + cursor, 'length': entry_length,
                        'revision': revision, 'certificate_type': kind,
                        'data': table[cursor + 8:cursor + entry_length]})
        next_offset = (cursor + entry_length + 7) & ~7
        if next_offset > length or any(table[cursor + entry_length:next_offset]):
            raise ValueError('Invalid WIN_CERTIFICATE alignment padding')
        cursor = next_offset
    return description, records


def _image_digest(stream, size, pe, algorithm):
    """Hash standard contiguous PE raw sections and an EOF certificate table.

    Refuse ambiguous/nonstandard layouts instead of guessing Windows SIP behavior.
    This validates the image digest only, not the CMS signature or trust chain.
    """
    headers = pe['headers_size']
    checksum, directory = pe['checksum_offset'], pe['security_directory_offset']
    if not pe['section_table_end'] <= headers <= size or not 0 <= checksum + 4 <= directory < directory + 8 <= headers:
        raise ValueError('Unsupported Authenticode layout: inconsistent PE header bounds')
    certificate_offset = pe.get('certificate_table_offset', 0)
    certificate_size = pe.get('certificate_table_size', 0)
    if certificate_size and certificate_offset + certificate_size != size:
        raise ValueError('Unsupported Authenticode layout: certificate table is not at EOF')
    limit = certificate_offset if certificate_size else size
    if headers > limit:
        raise ValueError('Unsupported Authenticode layout: certificate table overlaps headers')
    ranges = [(0, checksum), (checksum + 4, directory), (directory + 8, headers)]
    cursor = headers
    for section in sorted((item for item in pe['sections'] if item['size']), key=lambda item: item['offset']):
        start, end = section['offset'], section['offset'] + section['size']
        if start != cursor or end > limit:
            raise ValueError('Unsupported Authenticode layout: section gaps, overlaps or out-of-bounds data')
        ranges.append((start, end))
        cursor = end
    ranges.append((cursor, limit))
    digest = hashlib.new(algorithm.lower())
    for start, end in ranges:
        stream.seek(start)
        remaining = end - start
        while remaining:
            part = stream.read(min(1024 * 1024, remaining))
            if not part:
                raise ValueError('File changed during Authenticode hashing')
            digest.update(part)
            remaining -= len(part)
    return digest.hexdigest()


def _verify_image_digests(stream, size, pe, entries):
    cache = {}
    def visit(signed):
        value = signed.get('image_digest')
        if value:
            algorithm = value['algorithm']
            if not algorithm:
                value.update({'computed_hex': None, 'matches_file': None, 'verification_error': 'Unsupported image hash algorithm'})
            else:
                if algorithm not in cache:
                    try:
                        cache[algorithm] = (_image_digest(stream, size, pe, algorithm), None)
                    except ValueError as error:
                        cache[algorithm] = (None, str(error))
                actual, error = cache[algorithm]
                value.update({'computed_hex': actual, 'matches_file': actual == value['hex'] if actual else None,
                              'verification_error': error})
        for child in signed.get('nested_signatures', []):
            visit(child)
    for entry in entries:
        if 'signed_data' in entry:
            visit(entry['signed_data'])


def _windows_authenticode(state):
    """Copy recovered metadata while the successful WinTrust state remains alive."""
    from ctypes import wintypes as w
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        raise ValueError('Native metadata export currently supports Windows64 only')
    P = ctypes.c_void_p
    class BLOB(ctypes.Structure):
        _fields_ = [('size', w.DWORD), ('data', P)]
    class ALGORITHM(ctypes.Structure):
        _fields_ = [('oid', ctypes.c_char_p), ('parameters', BLOB)]
    class INDIRECT(ctypes.Structure):
        _fields_ = [('oid', ctypes.c_char_p), ('value', BLOB), ('algorithm', ALGORITHM), ('digest', BLOB)]
    class SIP(ctypes.Structure):
        _fields_ = [('size', w.DWORD), ('subject_guid', ctypes.c_byte * 16), ('sip', P),
                    ('catalog_sip', P), ('subject', P), ('catalog_subject', P),
                    ('indirect', ctypes.POINTER(INDIRECT))]
    class PROVIDER(ctypes.Structure):
        _fields_ = [('size', w.DWORD), ('trust_data', P), ('opened_file', w.BOOL),
                    ('parent', P), ('action', P), ('provider', P), ('error', w.DWORD),
                    ('security', w.DWORD), ('policy', w.DWORD), ('functions', P),
                    ('error_count', w.DWORD), ('errors', P), ('store_count', w.DWORD),
                    ('stores', P), ('encoding', w.DWORD), ('message', P),
                    ('signer_count', w.DWORD), ('signers', P), ('private_count', w.DWORD),
                    ('private', P), ('subject_choice', w.DWORD), ('sip', ctypes.POINTER(SIP))]
    class SIGNER(ctypes.Structure):
        _fields_ = [('size', w.DWORD), ('time', w.FILETIME), ('cert_count', w.DWORD),
                    ('certs', P), ('kind', w.DWORD), ('signer_info', P), ('error', w.DWORD),
                    ('counter_count', w.DWORD), ('counters', P), ('chain', P)]
    class PROVIDER_CERT(ctypes.Structure):
        _fields_ = [('size', w.DWORD), ('cert', P)]
    class TRUST_STATUS(ctypes.Structure):
        _fields_ = [('error', w.DWORD), ('info', w.DWORD)]
    class CHAIN(ctypes.Structure):
        _fields_ = [('size', w.DWORD), ('status', TRUST_STATUS), ('count', w.DWORD),
                    ('items', ctypes.POINTER(P))]
    class ELEMENT(ctypes.Structure):
        _fields_ = [('size', w.DWORD), ('cert', P)]
    class OID_INFO(ctypes.Structure):
        _fields_ = [('size', w.DWORD), ('oid', ctypes.c_char_p), ('name', w.LPCWSTR),
                    ('group', w.DWORD), ('algorithm', w.DWORD), ('extra', BLOB),
                    ('cng_algorithm', w.LPCWSTR), ('cng_extra', w.LPCWSTR)]
    if (PROVIDER.message.offset, PROVIDER.sip.offset, SIP.indirect.offset,
            INDIRECT.algorithm.offset, INDIRECT.digest.offset, SIGNER.chain.offset) != (0x70, 0xa0, 0x38, 0x18, 0x30, 0x38):
        raise ValueError('Unsupported native metadata structure layout')
    wintrust, crypt32 = ctypes.WinDLL('wintrust.dll'), ctypes.WinDLL('crypt32.dll')
    provider_from_state = wintrust.WTHelperProvDataFromStateData
    provider_from_state.argtypes, provider_from_state.restype = [P], ctypes.POINTER(PROVIDER)
    signer_from_chain = wintrust.WTHelperGetProvSignerFromChain
    signer_from_chain.argtypes, signer_from_chain.restype = [P, w.DWORD, w.BOOL, w.DWORD], ctypes.POINTER(SIGNER)
    cert_from_chain = wintrust.WTHelperGetProvCertFromChain
    cert_from_chain.argtypes, cert_from_chain.restype = [P, w.DWORD], ctypes.POINTER(PROVIDER_CERT)
    context = provider_from_state(state)
    if not context or context.contents.size < ctypes.sizeof(PROVIDER):
        raise ValueError('Native trust provider data unavailable')
    provider = context.contents
    if (not provider.sip or provider.sip.contents.size < ctypes.sizeof(SIP)
            or not provider.sip.contents.indirect or not provider.message):
        raise ValueError('Native SIP digest/message unavailable')
    indirect = provider.sip.contents.indirect.contents
    if not indirect.algorithm.oid:
        raise ValueError('Native digest algorithm OID unavailable')
    if not indirect.digest.data or not 1 <= indirect.digest.size <= 128:
        raise ValueError('Invalid native image digest')
    find_oid = crypt32.CryptFindOIDInfo
    find_oid.argtypes, find_oid.restype = [w.DWORD, P, w.DWORD], ctypes.POINTER(OID_INFO)
    oid = ctypes.create_string_buffer(indirect.algorithm.oid)
    algorithm = None
    for group in [0x40000001, 0x40000004]:
        found = find_oid(1, oid, group)
        if found and found.contents.size >= OID_INFO.cng_algorithm.offset + ctypes.sizeof(P):
            algorithm = found.contents.cng_algorithm
            if algorithm:
                break
    if not algorithm:
        raise ValueError('Native CNG digest algorithm unavailable')
    signer_pointer = signer_from_chain(context, 0, False, 0)
    if not signer_pointer or signer_pointer.contents.size < ctypes.sizeof(SIGNER):
        raise ValueError('Native selected signer unavailable')
    signer = signer_pointer.contents
    selected_cert = cert_from_chain(signer_pointer, 0)
    if not selected_cert or selected_cert.contents.size < ctypes.sizeof(PROVIDER_CERT) or not selected_cert.contents.cert:
        raise ValueError('Native selected signer certificate unavailable')
    certificate = selected_cert.contents.cert
    property_get = crypt32.CertGetCertificateContextProperty
    property_get.argtypes, property_get.restype = [P, w.DWORD, P, ctypes.POINTER(w.DWORD)], w.BOOL
    def thumbprint(cert):
        output, length = ctypes.create_string_buffer(20), w.DWORD(20)
        if not property_get(cert, 3, output, ctypes.byref(length)) or length.value != 20:
            raise ValueError('Native SHA1 certificate property unavailable')
        return output.raw
    name_get = crypt32.CertGetNameStringA
    name_get.argtypes, name_get.restype = [P, w.DWORD, w.DWORD, P, P, w.DWORD], w.DWORD
    codepage = ctypes.WinDLL('kernel32.dll').GetACP()
    def name(issuer=False):
        style = w.DWORD(1)
        count = name_get(certificate, 2, int(issuer), ctypes.byref(style), None, 0)
        if not 1 <= count <= 65536:
            raise ValueError('Native certificate name length invalid')
        output = ctypes.create_string_buffer(count)
        if not name_get(certificate, 2, int(issuer), ctypes.byref(style), output, count):
            raise ValueError('Native certificate name unavailable')
        return output.value.decode('cp' + str(codepage))
    issuer_hash = b'\0' * 20
    if signer.chain:
        chain = ctypes.cast(signer.chain, ctypes.POINTER(CHAIN)).contents
        if chain.size < ctypes.sizeof(CHAIN):
            raise ValueError('Unsupported native chain context layout')
        if chain.count and chain.items and chain.items[0]:
            simple = ctypes.cast(chain.items[0], ctypes.POINTER(CHAIN)).contents
            if simple.size < ctypes.sizeof(CHAIN):
                raise ValueError('Unsupported native simple chain layout')
            if simple.count >= 2 and simple.items and simple.items[1]:
                issuer = ctypes.cast(simple.items[1], ctypes.POINTER(ELEMENT)).contents
                if issuer.size < ctypes.sizeof(ELEMENT):
                    raise ValueError('Unsupported native chain element layout')
                if issuer.cert:
                    issuer_hash = thumbprint(issuer.cert)
    message_get = crypt32.CryptMsgGetParam
    message_get.argtypes, message_get.restype = [P, w.DWORD, w.DWORD, P, ctypes.POINTER(w.DWORD)], w.BOOL
    count = w.DWORD()
    if not message_get(provider.message, 29, 0, None, ctypes.byref(count)) or not 1 <= count.value <= MAX_CERTIFICATE_BYTES:
        raise ValueError('Native encoded signing message unavailable or oversized')
    message = ctypes.create_string_buffer(count.value)
    if not message_get(provider.message, 29, 0, message, ctypes.byref(count)):
        raise ValueError('Native encoded signing message extraction failed')
    signing_time = 0
    counter = signer_from_chain(context, 0, True, 0)
    if counter and counter.contents.size < ctypes.sizeof(SIGNER):
        raise ValueError('Unsupported native countersigner layout')
    if counter and counter.contents.kind == 0x10:
        timestamp = counter.contents.time
        ticks = (timestamp.dwHighDateTime << 32) | timestamp.dwLowDateTime
        signing_time = (ticks - 116444736000000000) // 10
    return {'hashAlgo': algorithm, 'valid': True,
            'hash': _b64(ctypes.string_at(indirect.digest.data, indirect.digest.size)),
            'signing': {'message': _b64(message.raw[:count.value]), 'time': str(signing_time)},
            'signer': {'hash': _b64(thumbprint(certificate)), 'subjectName': name()},
            'issuer': {'hash': _b64(issuer_hash), 'subjectName': name(True)}}


def windows_trust(path, *, include_metadata=False):
    """Check one file with WinVerifyTrust, suppressing UI and network retrieval.

    Does not search system catalogs or claim full SmartScreen signature selection
    parity. The explicit cache-only flag may produce a different result from Edge.
    """
    with _locked_windows_file(path) as stream:
        return _windows_trust_locked(path, stream, include_metadata=include_metadata)


@contextlib.contextmanager
def _locked_windows_file(path):
    """Open one unbuffered Windows read handle while denying writes and deletion."""
    if os.name != 'nt':
        raise ValueError('Windows cached trust verification requires Windows')
    from ctypes import wintypes as w
    import msvcrt
    kernel = ctypes.WinDLL('kernel32.dll', use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, ctypes.c_void_p, w.DWORD, w.DWORD, w.HANDLE]
    create.restype = w.HANDLE
    # Share read only: the object cannot be written, deleted or replaced while
    # hashing and WinVerifyTrust consume this same opened file handle.
    handle = create(str(Path(path).resolve()), 0x80000000, 1, None, 3, 0x80, None)
    if handle == w.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except Exception:
        close = kernel.CloseHandle
        close.argtypes, close.restype = [w.HANDLE], w.BOOL
        close(handle)
        raise
    with os.fdopen(descriptor, 'rb', buffering=0) as stream:
        yield stream


def _windows_trust_locked(path, stream, *, include_metadata):
    from ctypes import wintypes as w
    import msvcrt
    before = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
        before.update(chunk)
    stream.seek(0)
    class GUID(ctypes.Structure):
        _fields_ = [('data1', w.DWORD), ('data2', w.WORD), ('data3', w.WORD), ('data4', ctypes.c_ubyte * 8)]
    class FILE_INFO(ctypes.Structure):
        _fields_ = [('size', w.DWORD), ('path', w.LPCWSTR), ('file', w.HANDLE), ('subject', ctypes.c_void_p)]
    class TRUST_DATA(ctypes.Structure):
        _fields_ = [('size', w.DWORD), ('policy', ctypes.c_void_p), ('sip', ctypes.c_void_p),
                    ('ui', w.DWORD), ('revocation', w.DWORD), ('choice', w.DWORD),
                    ('file_info', ctypes.POINTER(FILE_INFO)), ('action', w.DWORD),
                    ('state', w.HANDLE), ('url', w.LPCWSTR), ('flags', w.DWORD),
                    ('context', w.DWORD), ('settings', ctypes.c_void_p)]
    action = GUID(0x00aac56b, 0xcd44, 0x11d0, (ctypes.c_ubyte * 8)(0x8c, 0xc2, 0, 0xc0, 0x4f, 0xc2, 0x95, 0xee))
    info = FILE_INFO(ctypes.sizeof(FILE_INFO), str(Path(path).resolve()),
                     msvcrt.get_osfhandle(stream.fileno()), None)
    data = TRUST_DATA()
    data.size, data.ui, data.choice, data.action = ctypes.sizeof(data), 2, 1, 1
    data.file_info = ctypes.pointer(info)
    data.flags = 0x7000  # Native 0x6000 (disable MD2/4 + MOTW), plus cache-only.
    function = ctypes.WinDLL('wintrust.dll').WinVerifyTrust
    function.argtypes = [w.HWND, ctypes.POINTER(GUID), ctypes.POINTER(TRUST_DATA)]
    function.restype = w.LONG
    metadata, metadata_error = None, None
    try:
        status = function(w.HWND(-1), ctypes.byref(action), ctypes.byref(data)) & 0xffffffff
        if include_metadata and status == 0:
            try:
                metadata = _windows_authenticode(data.state)
            except (ValueError, OSError) as error:
                metadata_error = str(error)
    finally:
        data.action = 2
        function(w.HWND(-1), ctypes.byref(action), ctypes.byref(data))
    after = hashlib.sha256()
    stream.seek(0)
    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
        after.update(chunk)
    if before.digest() != after.digest():
        raise ValueError('File changed during native trust observation')
    return {'method': 'WinVerifyTrust/WINTRUST_ACTION_GENERIC_VERIFY_V2',
            'status_hex': '0x%08x' % status, 'trusted': status == 0,
            'file_sha256': before.hexdigest(), 'authenticode': metadata, 'metadata_error': metadata_error,
            'file_binding': 'Same read handle hashed and passed to WinVerifyTrust; FILE_SHARE_READ denies writes and deletion during verification.',
            'cache_only': True, 'provider_flags': '0x00007000', 'catalog_lookup': 'not_performed',
            'checked_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'scope': 'Current Windows cached trust observation; not portable trust or full native SmartScreen selection parity'}


def _non_pe_format(stream, path, size):
    """Identify containers only; Windows registered SIP performs non-PE extraction."""
    stream.seek(0)
    header = stream.read(8)
    suffix = path.suffix.lower()
    if header == bytes.fromhex('d0cf11e0a1b11ae1'):
        return ('msi' if suffix in ('.msi', '.msp', '.mst') else 'compound_file'), None
    if suffix in ('.appx', '.msix', '.appxbundle', '.msixbundle') and header.startswith(b'PK\x03\x04'):
        return 'appx_container', None
    if suffix in ('.ps1', '.psm1', '.psd1', '.ps1xml', '.cdxml', '.mof', '.vbs', '.js', '.wsf'):
        if size > 8*1024*1024:
            return 'script', None
        stream.seek(0)
        raw = stream.read()
        marker = '# SIG # Begin signature block'
        return 'script', marker.encode() in raw or marker.encode('utf-16le') in raw or marker.encode('utf-16be') in raw
    return 'other', False


def extract_signatures(path, *, verify_windows=False, lookup_catalog=False, catalog_index=None):
    """Extract PE metadata, optional Windows SIP trust, and explicit catalog observations."""
    if type(verify_windows) is not bool or type(lookup_catalog) is not bool:
        raise ValueError('verify_windows and lookup_catalog must be boolean')
    if catalog_index is not None and (type(catalog_index) is not int or catalog_index < 0 or not lookup_catalog):
        raise ValueError('catalog_index requires explicit catalog lookup and a nonnegative integer')
    path = Path(path)
    with path.open('rb') as stream:
        initial = os.fstat(stream.fileno())
        size = initial.st_size
        if not stat.S_ISREG(initial.st_mode):
            raise ValueError('Signature input must be a regular file')
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
        pe, entries = _pe_certificates(stream, size)
        signatures = []
        for entry in entries:
            row = {key: value for key, value in entry.items() if key != 'data'}
            if entry['certificate_type'] == 2 and entry['revision'] in (0x100, 0x200):
                try:
                    row['signed_data'] = _signed_data(entry['data'])
                except SignatureDependencyError:
                    if not (verify_windows or lookup_catalog):
                        raise
                    row['portable_parse_skipped'] = 'cryptography unavailable; explicit Windows provider export requested'
            else:
                row['unsupported_certificate_type'] = True
            signatures.append(row)
        _verify_image_digests(stream, size, pe, signatures)
        format_name, non_pe_marker = ('pe', None) if pe else _non_pe_format(stream, path, size)
        final = os.fstat(stream.fileno())
        if (initial.st_size, initial.st_mtime_ns) != (final.st_size, final.st_mtime_ns):
            raise ValueError('File changed during signature extraction')
    report = {'schema_version': 1, 'kind': 'embedded_signature_metadata', 'path': str(path),
              'file_sha256': digest.hexdigest(), 'size': size,
              'format': format_name, 'format_identification': 'PE headers' if pe else 'Container magic/extension; Windows SIP is authoritative for supported non-PE signing', 'pe': pe,
              'embedded_certificate_table_present': bool(entries),
              'embedded_signature_present': any(row['certificate_type'] == 2 for row in signatures) if pe else None,
              'signature_block_marker_present': non_pe_marker, 'signatures': signatures,
              'windows_trust': None, 'catalog_lookup': 'not_performed', 'windows_catalogs': None,
              'selected_catalog_index': catalog_index,
              'schema_evidence': SCHEMA_EVIDENCE,
              'limits': ['Embedded certificate metadata is an unverified publisher claim until separately validated.',
                         'Certificate chain, CMS signature and timestamp are not cryptographically verified by the portable parser; image digest equality is checked separately for supported PE layouts.',
                         'No embedded signature does not mean unsigned: catalog, MSI, script and package signing are separate.',
                         'Native chain issuer selection and ANSI name rendering may differ from portable metadata.']}
    if verify_windows:
        report['windows_trust'] = windows_trust(path, include_metadata=True)
        report['windows_trust']['signature_origin'] = 'embedded' if pe else 'registered_sip'
        if not pe and report['windows_trust']['trusted']:
            report['embedded_signature_present'] = True
        # Re-bind the native result to the same bytes after the path-based API call.
        h = hashlib.sha256()
        with path.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                h.update(chunk)
        if h.hexdigest() != report['file_sha256']:
            raise ValueError('File changed during Windows trust verification')
    if lookup_catalog:
        from smartscreen.catalog import windows_catalog_trust
        report['windows_catalogs'] = windows_catalog_trust(path)
        if report['windows_catalogs']['file_sha256'] != report['file_sha256']:
            raise ValueError('File changed between extraction and catalog verification')
        report['catalog_lookup'] = 'performed'
    try:
        report['wire_metadata'] = authenticode_from_report(report)
        report['wire_error'] = None
    except ValueError as error:
        report['wire_metadata'] = None
        report['wire_error'] = str(error)
    report['wire_origin'] = ('catalog' if catalog_index is not None else ('embedded' if pe else 'registered_sip')) if report['wire_metadata'] else None
    if catalog_index is not None:
        report['wire_scope'] = 'Explicitly selected catalog provider metadata; selected catalog provenance retained, not an embedded signer.'
    elif report.get('windows_trust') and report['windows_trust'].get('authenticode'):
        report['wire_scope'] = 'Complete recovered Authenticode fields from explicit cached Windows provider state; catalog choice and native runtime policy remain separate.'
    else:
        report['wire_scope'] = 'Partial recovered schema; unknown valid, chain issuer hash and timestamp fields are omitted.'
    return report


def authenticode_from_report(report):
    """Return supported partial wire fields; never turn certificate presence into valid=true."""
    try:
        return _authenticode_from_report(report)
    except (KeyError, TypeError, IndexError, AttributeError) as error:
        raise ValueError('Malformed signature metadata report') from error


def _authenticode_from_report(report):
    if not isinstance(report, dict) or report.get('schema_version') != 1:
        raise ValueError('Expected an extracted signature report')
    if report.get('selected_catalog_index') is not None:
        from smartscreen.catalog import catalog_authenticode
        return catalog_authenticode(report.get('windows_catalogs'), report['selected_catalog_index'], file_sha256=report.get('file_sha256'))
    trust = report.get('windows_trust')
    successful_trust = isinstance(trust, dict) and trust.get('trusted') is True and trust.get('status_hex') == '0x00000000'
    if successful_trust:
        file_hash = report.get('file_sha256')
        if not isinstance(file_hash, str) or len(file_hash) != 64 or trust.get('file_sha256') != file_hash:
            raise ValueError('Native trust observation is not bound to this file SHA256')
        bytes.fromhex(file_hash)
    if isinstance(trust, dict) and isinstance(trust.get('authenticode'), dict):
        if not successful_trust:
            raise ValueError('Native Authenticode metadata is not bound to successful trust for this file')
        return json.loads(json.dumps(trust['authenticode'], allow_nan=False))
    entries = report.get('signatures')
    if not isinstance(entries, list):
        raise ValueError('Signature entries must be an array')
    if not entries:
        return {}
    # Multiple signatures require native signature selection; do not choose silently.
    if len(entries) != 1 or not isinstance(entries[0], dict):
        raise ValueError('Wire enrichment requires exactly one embedded certificate entry')
    signed = entries[0].get('signed_data')
    if not isinstance(signed, dict):
        return {}
    if signed.get('nested_signatures') or len(signed.get('signers', [])) != 1:
        raise ValueError('Multiple/nested signers require native signature selection before wire enrichment')
    index = signed['signers'][0]['certificate_index']
    digest = signed.get('image_digest')
    if index is None or not digest or digest['algorithm'] not in DIGESTS.values():
        return {}
    if digest.get('matches_file') is not True:
        raise ValueError('Wire enrichment requires a matching computed Authenticode image digest; ' +
                         (digest.get('verification_error') or 'embedded digest does not match the file'))
    cert = signed['certificates'][index]
    result = {'hashAlgo': digest['algorithm'], 'hash': _b64(bytes.fromhex(digest['hex'])),
              'signer': {'hash': _b64(bytes.fromhex(cert['sha1'])),
                         'subjectName': cert['subject_name_simple']},
              'issuer': {'subjectName': cert['issuer_name_simple']}}
    if successful_trust:
        result['valid'] = True
    return result


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file', type=Path)
    parser.add_argument('--windows-trust', action='store_true')
    parser.add_argument('--windows-catalog', action='store_true')
    parser.add_argument('--catalog-index', type=int)
    args = parser.parse_args()
    try:
        print(json.dumps(extract_signatures(args.file, verify_windows=args.windows_trust,
                                           lookup_catalog=args.windows_catalog, catalog_index=args.catalog_index), indent=2, allow_nan=False))
    except (OSError, ValueError) as error:
        parser.exit(2, str(error) + '\n')

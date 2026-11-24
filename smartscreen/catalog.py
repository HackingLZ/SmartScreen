"""Read Windows catalog membership and cached trust without altering catalog stores.

Catalog signatures are reported separately from embedded file signatures. Member
and catalog files stay locked against writes/deletion while native trust reads them.
"""
import base64
import ctypes
import datetime
import hashlib
import json
import os
import re
from pathlib import Path

from smartscreen.signatures import _locked_windows_file, _windows_authenticode


def catalog_authenticode(observation, index, *, file_sha256):
    """Select one explicitly requested, successful, file-bound catalog observation.

    The caller retains the observation and index as provenance; returned wire
    fields describe the catalog-selected signer, never an embedded signer.
    """
    if type(index) is not int or index < 0:
        raise ValueError('Catalog index must be a nonnegative integer')
    if not isinstance(file_sha256, str) or not re.fullmatch('[0-9a-f]{64}', file_sha256):
        raise ValueError('Expected a file SHA256')
    if (not isinstance(observation, dict) or observation.get('kind') != 'windows_catalog_observations'
            or observation.get('schema_version') != 1 or observation.get('file_sha256') != file_sha256
            or observation.get('catalog_lookup') != 'performed'):
        raise ValueError('Catalog observation is not bound to this file SHA256')
    rows = observation.get('catalogs')
    if not isinstance(rows, list) or index >= len(rows) or not isinstance(rows[index], dict):
        raise ValueError('Catalog index does not select an observation')
    row = rows[index]
    value = row.get('authenticode')
    if (row.get('trusted') is not True or row.get('status_hex') != '0x00000000'
            or row.get('signature_origin') != 'catalog' or not isinstance(value, dict)
            or value.get('valid') is not True):
        raise ValueError('Selected catalog has no successfully verified native metadata')
    try:
        digest = bytes.fromhex(row['member_hash'])
        algorithm = row['member_hash_algorithm']
        if (algorithm not in ('SHA1', 'SHA256') or len(digest) != {'SHA1':20,'SHA256':32}[algorithm]
                or value['hashAlgo'] != algorithm
                or base64.b64decode(value['hash'], validate=True) != digest):
            raise ValueError('Catalog metadata digest does not match the verified member hash')
        return json.loads(json.dumps(value, allow_nan=False))
    except (KeyError, TypeError) as error:
        raise ValueError('Malformed catalog metadata') from error


def _sha256(stream):
    stream.seek(0)
    digest = hashlib.sha256()
    for part in iter(lambda: stream.read(1024 * 1024), b''):
        digest.update(part)
    stream.seek(0)
    return digest.hexdigest()


def _types():
    from ctypes import wintypes as w
    P = ctypes.c_void_p
    class GUID(ctypes.Structure):
        _fields_ = [('data1', w.DWORD), ('data2', w.WORD), ('data3', w.WORD), ('data4', ctypes.c_ubyte * 8)]
    class CATALOG_INFO(ctypes.Structure):
        _fields_ = [('size', w.DWORD), ('path', w.WCHAR * 260)]
    class CATALOG_TRUST(ctypes.Structure):
        _fields_ = [('size', w.DWORD), ('version', w.DWORD), ('catalog_path', w.LPCWSTR),
                    ('member_tag', w.LPCWSTR), ('member_path', w.LPCWSTR), ('member_handle', w.HANDLE),
                    ('hash', P), ('hash_size', w.DWORD), ('catalog_context', P), ('admin', w.HANDLE)]
    class TRUST_DATA(ctypes.Structure):
        _fields_ = [('size', w.DWORD), ('policy', P), ('sip', P), ('ui', w.DWORD),
                    ('revocation', w.DWORD), ('choice', w.DWORD), ('subject', P),
                    ('action', w.DWORD), ('state', w.HANDLE), ('url', w.LPCWSTR),
                    ('flags', w.DWORD), ('context', w.DWORD), ('settings', P)]
    class DRIVER_INFO(ctypes.Structure):
        _fields_ = [('size', w.DWORD), ('reserved1', P), ('reserved2', P),
                    ('platform', w.DWORD), ('version', w.DWORD), ('version_string', w.WCHAR * 260),
                    ('signed_by', w.WCHAR * 260), ('signer_cert', P),
                    ('low_major', w.DWORD), ('low_minor', w.DWORD),
                    ('high_major', w.DWORD), ('high_minor', w.DWORD),
                    ('low_build', w.DWORD), ('high_build', w.DWORD)]
    return w, GUID, CATALOG_INFO, CATALOG_TRUST, TRUST_DATA, DRIVER_INFO


def _guid(kind, cls):
    if kind == 'native-driver':
        return cls(0xf750e6c3, 0x38ee, 0x11d1, (ctypes.c_ubyte * 8)(0x85, 0xe5, 0, 0xc0, 0x4f, 0xc2, 0x95, 0xee))
    return cls(0x00aac56b, 0xcd44, 0x11d0, (ctypes.c_ubyte * 8)(0x8c, 0xc2, 0, 0xc0, 0x4f, 0xc2, 0x95, 0xee))


def _verify_catalog(path, stream, catalog, admin, member_hash, *, policy, include_metadata):
    import msvcrt
    w, GUID, _, CATALOG_TRUST, TRUST_DATA, DRIVER_INFO = _types()
    if not Path(catalog).is_absolute() or str(catalog).startswith(('\\\\', '//')):
        raise ValueError('Catalog verification requires a local absolute catalog path')
    with _locked_windows_file(catalog) as catalog_stream:
        catalog_sha256 = _sha256(catalog_stream)
        raw_hash = ctypes.create_string_buffer(member_hash)
        info = CATALOG_TRUST()
        info.size = ctypes.sizeof(info)
        info.catalog_path, info.member_path = catalog, str(Path(path).resolve())
        info.member_tag = member_hash.hex().upper()
        info.member_handle, info.admin = msvcrt.get_osfhandle(stream.fileno()), admin
        info.hash, info.hash_size = ctypes.cast(raw_hash, ctypes.c_void_p), len(member_hash)
        data = TRUST_DATA()
        data.size, data.ui, data.choice, data.action = ctypes.sizeof(data), 2, 2, 1
        data.subject, data.flags = ctypes.addressof(info), 0x7000
        driver = DRIVER_INFO()
        if policy == 'native-driver':
            driver.size = ctypes.sizeof(driver)
            data.policy = ctypes.addressof(driver)
        action = _guid(policy, GUID)
        verify = ctypes.WinDLL('wintrust.dll').WinVerifyTrust
        verify.argtypes, verify.restype = [w.HWND, ctypes.POINTER(GUID), ctypes.POINTER(TRUST_DATA)], w.LONG
        metadata, metadata_error = None, None
        try:
            status = verify(w.HWND(-1), ctypes.byref(action), ctypes.byref(data)) & 0xffffffff
            if status == 0 and include_metadata:
                try:
                    metadata = _windows_authenticode(data.state)
                except (ValueError, OSError) as error:
                    metadata_error = str(error)
        finally:
            data.action = 2
            verify(w.HWND(-1), ctypes.byref(action), ctypes.byref(data))
            if driver.signer_cert:
                free = ctypes.WinDLL('crypt32.dll').CertFreeCertificateContext
                free.argtypes, free.restype = [ctypes.c_void_p], w.BOOL
                free(driver.signer_cert)
        if _sha256(catalog_stream) != catalog_sha256:
            raise ValueError('Catalog changed during verification')
        return {'catalog_path': catalog, 'catalog_sha256': catalog_sha256,
                'member_hash': member_hash.hex(), 'member_tag': info.member_tag,
                'status_hex': '0x%08x' % status, 'trusted': status == 0,
                'authenticode': metadata, 'metadata_error': metadata_error,
                'metadata_hash_matches_member': (base64.b64decode(metadata['hash']) == member_hash) if metadata else None,
                'signature_origin': 'catalog', 'policy': policy, 'provider_flags': '0x00007000'}


def windows_catalog_trust(path, *, include_metadata=True, algorithms=('SHA256', 'SHA1'),
                          policy='native-driver', max_catalogs=32):
    """Enumerate local matching catalogs and verify each member with cached WinTrust.

    No first-catalog choice is silently treated as the file's embedded signature.
    SHA1 mirrors the recovered older SmartScreen path; SHA256 extends discovery
    through the documented CryptCATAdmin*2 APIs. Catalog databases are not edited.
    """
    if os.name != 'nt':
        raise ValueError('Windows catalog lookup requires Windows')
    if policy not in ('native-driver', 'generic'):
        raise ValueError('Catalog policy must be native-driver or generic')
    if type(include_metadata) is not bool or type(max_catalogs) is not int or not 1 <= max_catalogs <= 128:
        raise ValueError('Invalid catalog lookup limits/options')
    if (not isinstance(algorithms, (list, tuple)) or not algorithms or
            len(set(algorithms)) != len(algorithms) or any(x not in ('SHA1', 'SHA256') for x in algorithms)):
        raise ValueError('Catalog algorithms must be a nonempty unique SHA1/SHA256 list')
    import msvcrt
    w, GUID, CATALOG_INFO, _, _, _ = _types()
    library = ctypes.WinDLL('wintrust.dll', use_last_error=True)
    acquire = library.CryptCATAdminAcquireContext2
    acquire.argtypes, acquire.restype = [ctypes.POINTER(w.HANDLE), ctypes.POINTER(GUID), w.LPCWSTR, ctypes.c_void_p, w.DWORD], w.BOOL
    release = library.CryptCATAdminReleaseContext
    release.argtypes, release.restype = [w.HANDLE, w.DWORD], w.BOOL
    release_catalog = library.CryptCATAdminReleaseCatalogContext
    release_catalog.argtypes, release_catalog.restype = [w.HANDLE, w.HANDLE, w.DWORD], w.BOOL
    calculate = library.CryptCATAdminCalcHashFromFileHandle2
    calculate.argtypes, calculate.restype = [w.HANDLE, w.HANDLE, ctypes.POINTER(w.DWORD), ctypes.c_void_p, w.DWORD], w.BOOL
    enumerate_catalog = library.CryptCATAdminEnumCatalogFromHash
    enumerate_catalog.argtypes, enumerate_catalog.restype = [w.HANDLE, ctypes.c_void_p, w.DWORD, w.DWORD, ctypes.POINTER(w.HANDLE)], w.HANDLE
    catalog_info = library.CryptCATCatalogInfoFromContext
    catalog_info.argtypes, catalog_info.restype = [w.HANDLE, ctypes.POINTER(CATALOG_INFO), w.DWORD], w.BOOL
    rows, hashes, truncated = [], {}, False
    with _locked_windows_file(path) as stream:
        file_sha256 = _sha256(stream)
        handle = msvcrt.get_osfhandle(stream.fileno())
        subsystem = _guid('native-driver', GUID)
        for algorithm in algorithms:
            admin = w.HANDLE()
            if not acquire(ctypes.byref(admin), ctypes.byref(subsystem), algorithm, None, 0):
                raise ctypes.WinError(ctypes.get_last_error())
            current = None
            try:
                size = w.DWORD()
                stream.seek(0)
                calculate(admin, handle, ctypes.byref(size), None, 0)
                if not 1 <= size.value <= 128:
                    raise ValueError('Catalog hash API returned an invalid size')
                buffer = ctypes.create_string_buffer(size.value)
                stream.seek(0)
                if not calculate(admin, handle, ctypes.byref(size), buffer, 0):
                    raise ctypes.WinError(ctypes.get_last_error())
                member_hash = buffer.raw[:size.value]
                hashes[algorithm] = member_hash.hex()
                previous = w.HANDLE()
                while True:
                    current = enumerate_catalog(admin, buffer, size.value, 0, ctypes.byref(previous))
                    if not current:
                        break
                    if len(rows) >= max_catalogs:
                        truncated = True
                        break
                    info = CATALOG_INFO()
                    info.size = ctypes.sizeof(info)
                    if not catalog_info(current, ctypes.byref(info), 0):
                        raise ctypes.WinError(ctypes.get_last_error())
                    row = _verify_catalog(path, stream, info.path, admin, member_hash,
                                          policy=policy, include_metadata=include_metadata)
                    row['member_hash_algorithm'] = algorithm
                    rows.append(row)
                    previous.value = current
                if truncated:
                    break
            finally:
                if current:
                    release_catalog(admin, current, 0)
                release(admin, 0)
        if _sha256(stream) != file_sha256:
            raise ValueError('Member file changed during catalog lookup')
    return {'schema_version': 1, 'kind': 'windows_catalog_observations', 'path': str(path),
            'file_sha256': file_sha256, 'member_hashes': hashes, 'catalogs': rows,
            'trusted_catalog_count': sum(row['trusted'] for row in rows),
            'catalog_lookup': 'performed', 'truncated': truncated, 'cache_only': True,
            'checked_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'file_binding': 'Member and each catalog locked against writes/deletion; member handle supplied to native hashing and WinTrust.',
            'scope': 'Local catalog membership plus current cached Windows trust; catalog signer is not an embedded file signer or a SmartScreen enforcement verdict.',
            'native_evidence': 'analysis/signature_catalog_expansion/native_catalog_package.json:1800e8a00,1800e94f0'}


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file', type=Path)
    parser.add_argument('--policy', choices=('native-driver', 'generic'), default='native-driver')
    args = parser.parse_args()
    try:
        print(json.dumps(windows_catalog_trust(args.file, policy=args.policy), indent=2))
    except (OSError, ValueError) as error:
        parser.exit(2, str(error) + '\n')

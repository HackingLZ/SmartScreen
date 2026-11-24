"""Verify the native-pinned CRX3 signer and safely extract data files, never execute them.

Format/algorithms follow Chromium components/crx_file/crx3.proto and crx_verifier.cc.
Requires cryptography for signature verification; all extraction uses Python stdlib.
"""
import hashlib
import io
import json
import stat
import struct
import zipfile
from pathlib import Path, PurePosixPath
import base64
import datetime
import math
import re
import secrets
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid


MAX_HEADER = 1024 * 1024
MAX_ARCHIVE = 1024 * 1024 * 1024
UPDATE_URL = 'https://edge.microsoft.com/componentupdater/api/v1/update'
DEFAULT_EDGE_VERSION = '158.0.4370.33'
# Public signing-key SHA256 values recovered from this verified Edge158 ARM64 binary.
# See analysis/scareware_discovery/component_ids.json for addresses and evidence.
COMPONENTS = {
    'model': {'id': 'jpinkpebmplndiafioikiciobeafamld', 'directory': 'ProvenanceData',
              'key_sha256': '9f8daf41cfbd38058e8a828e14050cb33198c95e14e01f8a7be953a1939c1ea5',
              'payload': 'vti-b-p32-visual.quant.ort'},
    'vectors': {'id': 'fmbfidpnnknmblionmcahabilfoageoe', 'directory': 'ProvenanceDataTensors',
                'key_sha256': '5c1583fddadc1b8edc207018b5e064e46a156732c3e0d355675e93ca21bc3cf8',
                'payload': 'provenance-data-vectors.json'},
    'allowlist': {'id': 'kieecehchjjaaepgajdhcehijkehdenm', 'directory': 'ProvenanceDataAllowList',
                  'key_sha256': 'a8442472799004f6093724789a4734dc2b6201e71073864967019c497e3d86ac',
                  'payload': 'techscam-detection-allowlist.json'},
}


def _digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(part)
    return h.hexdigest()


def _version(value):
    if not isinstance(value, str) or not re.fullmatch(r'\d{1,10}(?:\.\d{1,10}){3}', value):
        raise ValueError('Expected a four-part numeric version')
    return tuple(map(int, value.split('.')))


def make_update_request(edge_version=DEFAULT_EDGE_VERSION, architecture='arm64'):
    """Create an anonymous standalone profile using the verified Edge4.0 wire schema.

    Hardware/OS fields describe the request profile, not the computer running Python.
    No reputation queries, site URLs, feedback, event reports or roll-call pings.
    """
    _version(edge_version)
    if architecture not in ('arm64', 'x64', 'x86'):
        raise ValueError('Unsupported architecture')
    apps = []
    for component in COMPONENTS.values():
        rollout = secrets.randbelow(100) / 100
        cohort = 'rrf@%.2f' % rollout
        apps.append({'appid': component['id'], 'brand': 'INBX', 'cohort': cohort,
                     'enabled': True, 'installdate': -1, 'lang': 'en-US',
                     'version': '0.0.0.0', 'updatecheck': {}, 'targetingattributes': {
                         'AppCohort': cohort, 'AppRollout': rollout,
                         'AppMajorVersion': edge_version.split('.')[0], 'AppVersion': edge_version,
                         'IsInternalUser': False, 'Priority': False,
                         'Updater': 'Omaha', 'UpdaterVersion': '1.3.319.41'}})
    request = {'@os': 'win', '@updater': 'msedge', 'acceptformat': 'crx3,download,run,xz,zucc',
               'apps': apps, 'arch': architecture, 'dedup': 'cr', 'domainjoined': False,
               'hw': {'avx': 0, 'physmemory': 8, 'sse': 0, 'sse2': 0, 'sse3': 0,
                      'sse41': 0, 'sse42': 0, 'ssse3': 0}, 'ismachine': 1,
               'os': {'arch': architecture, 'deviceformfactor': 'desktop', 'platform': 'Windows',
                      'version': '10.0.22621.4317'},
               'prodversion': edge_version, 'updaterversion': edge_version, 'protocol': '4.0',
               'requestid': '{' + str(uuid.uuid4()) + '}', 'sessionid': '{' + str(uuid.uuid4()) + '}',
               'updaters': {'autoupdatecheckenabled': True, 'ismachine': 1, 'lastchecked': 0,
                            'laststarted': 0, 'name': 'Omaha', 'updatepolicy': -1, 'version': '1.3.319.41'}}
    return {'request': request}


def parse_update_response(raw):
    """Accept complete signed-package pipelines for exactly the three known IDs."""
    try:
        return _parse_update_response(raw)
    except (KeyError, TypeError, AttributeError, IndexError) as exc:
        raise ValueError('Malformed component updater response') from exc


def _parse_update_response(raw):
    document = json.loads(raw.removeprefix(b")]}'\n"))
    response = document['response']
    if response.get('protocol') != '4.0':
        raise ValueError('Unsupported updater response protocol')
    known = {value['id']: (role, value) for role, value in COMPONENTS.items()}
    downloads = {}
    for app in response.get('apps', []):
        if app.get('appid') not in known:
            continue
        role, component = known[app['appid']]
        if role in downloads:
            raise ValueError('Duplicate component response')
        update = app.get('updatecheck', {})
        if app.get('status') != 'ok' or update.get('status') != 'ok':
            raise ValueError('Component update unavailable for ' + role)
        version = update.get('nextversion')
        _version(version)
        chosen = None
        for pipeline in update.get('pipelines', []):
            operations = pipeline.get('operations', [])
            if [op.get('type') for op in operations] == ['download', 'crx3']:
                chosen = operations
                break
        if chosen is None:
            raise ValueError('No complete CRX3 download pipeline for ' + role)
        download, install = chosen
        digest = download.get('out', {}).get('sha256', '')
        size = download.get('size')
        if not re.fullmatch(r'[a-fA-F0-9]{64}', digest) or install.get('in', {}).get('sha256') != digest:
            raise ValueError('Invalid pipeline content hashes')
        if type(size) is not int or not 12 <= size <= MAX_ARCHIVE:
            raise ValueError('Invalid package size')
        url = download.get('urls', [{}])[0].get('url', '')
        parts = urllib.parse.urlsplit(url)
        # Microsoft's current signed component CDN advertises HTTP. Authenticity
        # is established separately using the native-pinned package signature.
        if (parts.scheme not in ('http', 'https') or
                parts.hostname != 'msedge.b.tlu.dl.delivery.mp.microsoft.com' or
                parts.username or parts.password or parts.port not in (None, 80, 443) or
                any(ord(c) < 33 or ord(c) > 126 for c in url)):
            raise ValueError('Unexpected component download URL')
        downloads[role] = {**component, 'role': role, 'version': version,
                           'url': url, 'sha256': digest.lower(), 'size': size}
    if set(downloads) != set(COMPONENTS):
        raise ValueError('Updater did not supply all three components')
    return downloads


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _http(url, destination, *, body=None, headers=None, timeout=600, max_bytes=MAX_ARCHIVE, transport='auto'):
    destination = Path(destination)
    _output_path(destination.parent, destination.name)
    selected = ('curl' if shutil.which('curl') else 'urllib') if transport == 'auto' else transport
    response_headers = {}
    if selected == 'curl':
        with tempfile.TemporaryDirectory(prefix='vision-http-', dir=destination.parent) as temporary:
            root = Path(temporary)
            config = ['url = ' + json.dumps(url), 'request = ' + json.dumps('POST' if body is not None else 'GET')]
            config += ['header = ' + json.dumps(key + ': ' + value) for key, value in (headers or {}).items()]
            if body is not None:
                (root / 'request').write_bytes(body)
                config.append('data-binary = ' + json.dumps('@' + str(root / 'request')))
            run = subprocess.run(['curl', '-sS', '--config', '-', '--no-insecure', '--no-location',
                                  '--proto', '=http,https', '--max-time', str(timeout),
                                  '--connect-timeout', str(min(15, timeout)), '--max-filesize', str(max_bytes),
                                  '--dump-header', str(root / 'headers'), '--output', str(destination),
                                  '--write-out', '%{http_code}'], input='\n'.join(config) + '\n',
                                 text=True, capture_output=True, timeout=timeout + 5)
            if run.returncode:
                raise OSError(run.stderr.strip() or 'curl transport failed')
            status = int(run.stdout.strip())
            for line in (root / 'headers').read_text(encoding='iso-8859-1').splitlines():
                if line.startswith('HTTP/'):
                    response_headers = {}
                elif ':' in line:
                    name, value = line.split(':', 1)
                    response_headers[name.strip().lower()] = value.strip()
    elif selected == 'urllib':
        opener = urllib.request.build_opener(_NoRedirect())
        request = urllib.request.Request(url, data=body, headers=headers or {}, method='POST' if body is not None else 'GET')
        try:
            response = opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            response = error
        with response, destination.open('wb') as output:
            status, response_headers = response.status, dict(response.headers.items())
            size = 0
            while True:
                chunk = response.read(min(1024 * 1024, max_bytes + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                if size > max_bytes:
                    raise ValueError('Download exceeds configured limit')
                output.write(chunk)
    else:
        raise ValueError('Unknown transport')
    if destination.stat().st_size > max_bytes:
        raise ValueError('Download exceeds configured limit')
    return {'http_status': status, 'headers': response_headers, 'transport': selected,
            'size': destination.stat().st_size, 'sha256': _digest(destination)}


def _inside(root, value):
    if not isinstance(value, str) or Path(value).is_absolute():
        raise ValueError('Bundle paths must be relative strings')
    path = (root / value).resolve()
    if root.resolve() not in path.parents:
        raise ValueError('Bundle path escapes its directory')
    return path


def _output_path(root, value):
    """Reject existing final symlinks, including links to another file inside root."""
    path = root / value
    if path.is_symlink():
        raise ValueError('Refusing symlink output: ' + str(path))
    _inside(root, value)
    if path.exists() and not path.is_file():
        raise ValueError('Output target is not a regular file: ' + str(path))
    return path


def _atomic_write(root, value, data):
    path = _output_path(root, value)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(prefix='vision-write-', dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
        # replace() does not follow a link created at the final leaf after our check.
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _json_object(value, label):
    if not isinstance(value, dict):
        raise ValueError(label + ' must be a JSON object')
    return value


def _sha256_value(value, label):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-fA-F]{64}', value):
        raise ValueError(label + ' must be a SHA256 hex string')
    return value.lower()


def _materialize(root, downloads, package_paths, provenance):
    root = Path(root).resolve()
    paths, digests, components = {}, {}, {}
    for role, row in downloads.items():
        source = Path(package_paths[role]).resolve()
        if source.stat().st_size != row['size']:
            raise ValueError('Package size mismatch for ' + role)
        destination = _inside(root, str(Path('components') / row['directory'] / row['version']))
        report = extract(source, destination, COMPONENTS[role]['key_sha256'], row['sha256'])
        manifest = _json_object(json.loads((destination / 'manifest.json').read_text(encoding='utf-8-sig')), 'Signed package manifest')
        if _version(manifest.get('version')) != _version(row['version']):
            raise ValueError('Package manifest version differs from updater')
        payload = destination / COMPONENTS[role]['payload']
        if not payload.is_file():
            raise ValueError('Expected native payload missing')
        paths[role] = str(payload.relative_to(root))
        digests[role] = _digest(payload)
        components[role] = {**row, 'crx': str(source.relative_to(root)),
                            'verification': report, 'package_manifest': manifest}
    result = {'schema_version': 1, 'path_base': 'assets.json parent directory', 'paths': paths,
              'sha256': digests, 'components': components, 'provenance': provenance,
              'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'scope': 'Signed visual model, reference vectors and allowlist. Model execution alone is not an Edge enforcement verdict.'}
    _atomic_write(root, 'assets.json', (json.dumps(result, indent=2) + '\n').encode())
    return result


def fetch_assets(output_directory, *, edge_version=DEFAULT_EDGE_VERSION, architecture='arm64', timeout=600, transport='auto'):
    """Fetch current official metadata, reuse matching CRXs, verify and extract assets.

    Dependencies: cryptography; curl is optional. The updater response is HTTPS but
    its CUP signature is not verified here. Every package must independently match
    the advertised hash and the full signing-key hash pinned in the native binary.
    """
    if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError('Timeout must be positive and finite')
    if transport not in ('auto', 'curl', 'urllib'):
        raise ValueError('Unknown transport')
    root = Path(output_directory).resolve()
    root.mkdir(parents=True, exist_ok=True)
    provenance_dir = _inside(root, 'provenance')
    provenance_dir.mkdir(exist_ok=True)
    request = make_update_request(edge_version, architecture)
    body = json.dumps(request, separators=(',', ':'), sort_keys=True).encode()
    body_hash = hashlib.sha256(body).hexdigest()
    request_path = _output_path(provenance_dir, body_hash + '.request.json')
    _atomic_write(provenance_dir, request_path.name, body)
    nonce = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')
    endpoint = UPDATE_URL + '?cup2key=7:' + nonce + '&cup2hreq=' + body_hash
    headers = {'Content-Type': 'application/json',
               'X-Microsoft-Update-AppId': ','.join(v['id'] for v in COMPONENTS.values()),
               'X-Microsoft-Update-Interactivity': 'fg',
               'X-Microsoft-Update-Updater': 'msedge-' + edge_version,
               'Sec-Mesh-Client-Edge-Version': edge_version, 'Sec-Mesh-Client-Edge-Channel': 'stable',
               'Sec-Mesh-Client-OS': 'Windows', 'Sec-Mesh-Client-OS-Version': '10.0.22621',
               'Sec-Mesh-Client-Arch': architecture, 'Sec-Mesh-Client-WebView': '0'}
    response_path = _output_path(provenance_dir, body_hash + '.response.bin')
    record = _http(endpoint, response_path, body=body, headers=headers,
                   timeout=min(timeout, 60), max_bytes=16 * 1024 * 1024, transport=transport)
    provenance = {'endpoint': endpoint, 'request': str(request_path.relative_to(root)),
                  'request_sha256': body_hash, 'response': str(response_path.relative_to(root)),
                  'response_record': record, 'cup_response_signature_verified': False,
                  'identity_scope': 'Fresh standalone request using the verified Edge4.0 schema; synthetic rollout cohorts and hardware profile.'}
    _atomic_write(provenance_dir, body_hash + '.metadata.json', (json.dumps(provenance, indent=2) + '\n').encode())
    if record['http_status'] != 200:
        raise OSError('Component updater returned HTTP %s; response saved at %s' % (record['http_status'], response_path))
    downloads = parse_update_response(response_path.read_bytes())
    package_dir = _inside(root, 'packages')
    package_dir.mkdir(exist_ok=True)
    package_paths = {}
    for role, row in downloads.items():
        path = _output_path(package_dir, row['sha256'] + '.crx')
        if not path.is_file() or path.stat().st_size != row['size'] or _digest(path) != row['sha256']:
            with tempfile.NamedTemporaryFile(prefix=row['sha256'] + '.', suffix='.partial', dir=package_dir, delete=False) as stream:
                temporary = Path(stream.name)
            try:
                record = _http(row['url'], temporary, timeout=timeout, max_bytes=row['size'], transport=transport)
                if record['http_status'] != 200 or record['size'] != row['size'] or record['sha256'] != row['sha256']:
                    raise ValueError('Downloaded package failed HTTP/size/SHA256 checks for ' + role)
                temporary.replace(path)
            finally:
                temporary.unlink(missing_ok=True)
        package_paths[role] = path
    return _materialize(root, downloads, package_paths, provenance)


def verify_bundle(directory, *, verify_signatures=True):
    """Check paths, hashes and authenticated package content/metadata.

    Stored verification claims are refreshed from actual checks. URLs and request
    provenance remain unsigned metadata; CRX authenticity does not authenticate them.
    """
    root = Path(directory).resolve()
    manifest = _json_object(json.loads((root / 'assets.json').read_text()), 'Asset manifest')
    if type(manifest.get('schema_version')) is not int or manifest['schema_version'] != 1:
        raise ValueError('Unsupported or incomplete asset manifest')
    for key in ('paths', 'sha256', 'components'):
        mapping = _json_object(manifest.get(key), 'Asset manifest ' + key)
        if set(mapping) != set(COMPONENTS):
            raise ValueError('Incomplete asset manifest ' + key)
    for role, component in COMPONENTS.items():
        path = _inside(root, manifest['paths'][role])
        digest = _digest(path)
        if digest != _sha256_value(manifest['sha256'][role], 'Asset hash for ' + role):
            raise ValueError('Asset hash mismatch for ' + role)
        row = _json_object(manifest['components'][role], 'Component metadata for ' + role)
        for key, value in component.items():
            if row.get(key) != value:
                raise ValueError('Component identity metadata mismatch for ' + role + ': ' + key)
        if row.get('role') != role:
            raise ValueError('Component role metadata mismatch for ' + role)
        version = _version(row.get('version'))
        package_manifest = _json_object(row.get('package_manifest'), 'Package manifest for ' + role)
        _version(package_manifest.get('version'))
        package_hash = _sha256_value(row.get('sha256'), 'Package hash for ' + role)
        if type(row.get('size')) is not int or not 12 <= row['size'] <= MAX_ARCHIVE:
            raise ValueError('Invalid package size for ' + role)
        crx = _inside(root, row.get('crx'))
        if verify_signatures:
            archive, report = verify_crx(crx, component['key_sha256'], package_hash)
            if row['size'] != report['crx_size']:
                raise ValueError('Reported package size differs from signed package for ' + role)
            try:
                with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
                    payload = bundle.read(component['payload'])
                    signed_manifest_bytes = bundle.read('manifest.json')
                    signed_manifest = _json_object(json.loads(signed_manifest_bytes.decode('utf-8-sig')), 'Signed package manifest')
            except (KeyError, TypeError, zipfile.BadZipFile) as exc:
                raise ValueError('Malformed signed package contents for ' + role) from exc
            if hashlib.sha256(payload).hexdigest() != digest:
                raise ValueError('Asset differs from signed package for ' + role)
            if version != _version(signed_manifest.get('version')):
                raise ValueError('Reported component version differs from signed manifest for ' + role)
            if (json.dumps(package_manifest, sort_keys=True, allow_nan=False) !=
                    json.dumps(signed_manifest, sort_keys=True, allow_nan=False)):
                raise ValueError('Reported package manifest differs from signed manifest for ' + role)
            report['files'] = [
                {'path': 'manifest.json', 'size': len(signed_manifest_bytes),
                 'sha256': hashlib.sha256(signed_manifest_bytes).hexdigest()},
                {'path': component['payload'], 'size': len(payload), 'sha256': digest},
            ]
            row['verification'] = report
        else:
            row['verification'] = {'pinned_signature_verified': False,
                                    'scope': 'Only extracted-file hashes checked in this call'}
    return manifest


def fields(data):
    if not isinstance(data, bytes):
        raise ValueError('Protobuf message must be bytes')
    def varint(offset):
        value = 0
        for shift in range(0, 70, 7):
            if offset >= len(data):
                raise ValueError('truncated varint')
            byte = data[offset]
            offset += 1
            value |= (byte & 127) << shift
            if byte < 128:
                return value, offset
        raise ValueError('oversized varint')

    result = {}
    offset = 0
    while offset < len(data):
        tag, offset = varint(offset)
        number, wire = tag >> 3, tag & 7
        if number == 0:
            raise ValueError('invalid field number')
        if wire == 2:
            size, offset = varint(offset)
            if size > len(data) - offset:
                raise ValueError('truncated field')
            value = data[offset:offset + size]
            offset += size
        elif wire == 0:
            value, offset = varint(offset)
        elif wire in (1, 5):
            size = 8 if wire == 1 else 4
            value = data[offset:offset + size]
            if len(value) != size:
                raise ValueError('truncated fixed field')
            offset += size
        else:
            raise ValueError('unsupported protobuf wire type')
        result.setdefault(number, []).append(value)
    return result


def singleton(mapping, key):
    values = mapping.get(key, [])
    if len(values) != 1 or not isinstance(values[0], bytes):
        raise ValueError('missing, duplicated or non-bytes field %d' % key)
    return values[0]


def verify_crx(path, pinned_hash, expected_sha256=None):
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
    except ImportError as exc:
        raise RuntimeError("Install cryptography in this Python environment to verify model packages") from exc
    pinned_hash = _sha256_value(pinned_hash, 'Pinned signing key')
    if expected_sha256 is not None:
        expected_sha256 = _sha256_value(expected_sha256, 'Expected package hash')
    path = Path(path)
    if path.stat().st_size > MAX_ARCHIVE:
        raise ValueError('archive exceeds limit')
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if expected_sha256 and digest != expected_sha256.lower():
        raise ValueError('download SHA256 differs from update metadata')
    if len(raw) < 12 or raw[:4] != b'Cr24':
        raise ValueError('not CRX3')
    version, size = struct.unpack_from('<II', raw, 4)
    if version != 3 or size > MAX_HEADER or 12 + size > len(raw):
        raise ValueError('invalid CRX3 header')
    header = fields(raw[12:12 + size])
    signed = singleton(header, 10000)
    declared = singleton(fields(signed), 1)
    pinned = bytes.fromhex(pinned_hash)
    if len(pinned) != 32 or declared != pinned[:16]:
        raise ValueError('declared CRX ID does not match native pinned key')
    archive = raw[12 + size:]
    signed_hash = hashlib.sha256(b'CRX3 SignedData\0' + struct.pack('<I', len(signed)) + signed)
    signed_hash.update(archive)
    message_digest = signed_hash.digest()
    proofs = []
    pinned_verified = False
    for field, name in [(2, 'RSA_PKCS1_SHA256'), (3, 'ECDSA_SHA256')]:
        for proof in header.get(field, []):
            values = fields(proof)
            key_bytes, signature = singleton(values, 1), singleton(values, 2)
            key_hash = hashlib.sha256(key_bytes).hexdigest()
            key = serialization.load_der_public_key(key_bytes)
            try:
                if field == 2 and isinstance(key, rsa.RSAPublicKey):
                    key.verify(signature, message_digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
                elif field == 3 and isinstance(key, ec.EllipticCurvePublicKey):
                    key.verify(signature, message_digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
                else:
                    raise ValueError('signature key type mismatch')
            except InvalidSignature as exc:
                raise ValueError('CRX3 signature verification failed') from exc
            is_pinned = key_hash == pinned_hash.lower()
            pinned_verified |= is_pinned
            proofs.append({'algorithm': name, 'public_key_sha256': key_hash, 'native_pinned_key': is_pinned, 'signature_valid': True})
    if not pinned_verified:
        raise ValueError('native-pinned signer proof missing')
    report = {'crx_sha256': digest, 'crx_size': len(raw), 'header_size': size,
              'declared_id_hex': declared.hex(), 'proofs': proofs,
              'pinned_signature_verified': True}
    return archive, report


def extract(path, target, pinned_hash, expected_sha256=None):
    archive, report = verify_crx(path, pinned_hash, expected_sha256)
    target = Path(target)
    target.mkdir(parents=True, exist_ok=True)
    rows = []
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        if len(bundle.infolist()) > 1000 or sum(m.file_size for m in bundle.infolist()) > MAX_ARCHIVE:
            raise ValueError('expanded archive exceeds limits')
        seen = set()
        for member in bundle.infolist():
            name = PurePosixPath(member.filename)
            if name.is_absolute() or any(x in ('..', '.') for x in name.parts) or '\\' in member.filename:
                raise ValueError('unsafe member path')
            if member.filename in seen or stat.S_ISLNK(member.external_attr >> 16):
                raise ValueError('duplicate or symlink member')
            seen.add(member.filename)
            output = target.joinpath(*name.parts)
            if target.resolve() not in output.resolve().parents:
                raise ValueError('member escapes output directory')
            if member.is_dir():
                output.mkdir(parents=True, exist_ok=True)
                continue
            output.parent.mkdir(parents=True, exist_ok=True)
            _output_path(target, str(output.relative_to(target)))
            data = bundle.read(member)
            _atomic_write(target, str(output.relative_to(target)), data)
            rows.append({'path': member.filename, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
    report['files'] = rows
    _atomic_write(target, 'verification.json', (json.dumps(report, indent=2) + '\n').encode())
    return report

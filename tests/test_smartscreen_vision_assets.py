import copy
import hashlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from smartscreen import vision_assets as assets
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False


def _varint(n):
    out = bytearray()
    while n >= 128:
        out.append((n & 127) | 128)
        n >>= 7
    out.append(n)
    return bytes(out)


def _field(tag, value):
    return _varint((tag << 3) | 2) + _varint(len(value)) + value


def _package(key, filename, payload=b'benign fixture', unsafe=False):
    public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    signed = _field(1, hashlib.sha256(public).digest()[:16])
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as archive:
        archive.writestr('manifest.json', '\ufeff' + json.dumps({'version': '2026.01.02.3'}))
        archive.writestr('../outside' if unsafe else filename, payload)
    content = stream.getvalue()
    message = b'CRX3 SignedData\0' + struct.pack('<I', len(signed)) + signed + content
    if isinstance(key, rsa.RSAPrivateKey):
        proof_type, signature = 2, key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    else:
        proof_type, signature = 3, key.sign(message, ec.ECDSA(hashes.SHA256()))
    header = _field(proof_type, _field(1, public) + _field(2, signature)) + _field(10000, signed)
    return b'Cr24' + struct.pack('<II', 3, len(header)) + header + content, hashlib.sha256(public).hexdigest()


class MetadataTests(unittest.TestCase):
    def test_request_has_native_schema_and_no_reports(self):
        one, two = assets.make_update_request(), assets.make_update_request()
        request = one['request']
        self.assertEqual(request['protocol'], '4.0')
        self.assertIs(type(request['ismachine']), int)
        self.assertEqual(len(request['apps']), 3)
        self.assertNotEqual(request['requestid'], two['request']['requestid'])
        self.assertTrue(all('events' not in app and 'ping' not in app for app in request['apps']))
        for value in ['158', '../1.2.3.4', '1.2.3.4\nHeader: bad']:
            with self.assertRaises(ValueError):
                assets.make_update_request(value)

    def test_truncated_protobuf_rejected(self):
        for raw in [b'\x82', b'\x0a\xff', b'\x00', b'\x0a\x05ab', b'\x0b']:
            with self.assertRaises(ValueError):
                assets.fields(raw)

    def test_output_symlink_escape_rejected_before_network(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(assets, '_http') as http:
            root = Path(directory) / 'bundle'
            outside = Path(directory) / 'outside'
            root.mkdir()
            outside.mkdir()
            (root / 'provenance').symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'escapes'):
                assets.fetch_assets(root)
            http.assert_not_called()
            self.assertEqual(list(outside.iterdir()), [])


@unittest.skipUnless(HAVE_CRYPTO, 'cryptography unavailable for this Python architecture')
class AssetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.ec_key = ec.generate_private_key(ec.SECP256R1())

    def test_rsa_and_ec_signature_then_modified_content(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.crx'
            for key in [self.rsa_key, self.ec_key]:
                raw, pin = _package(key, 'data.bin')
                path.write_bytes(raw)
                _, report = assets.verify_crx(path, pin)
                self.assertTrue(report['pinned_signature_verified'])
                path.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
                with self.assertRaisesRegex(ValueError, 'signature verification failed'):
                    assets.verify_crx(path, pin)

    def test_wrong_signer_or_advertised_hash_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.crx'
            raw, pin = _package(self.rsa_key, 'data.bin')
            path.write_bytes(raw)
            with self.assertRaises(ValueError):
                assets.verify_crx(path, '0' * 64)
            with self.assertRaises(ValueError):
                assets.verify_crx(path, pin, '0' * 64)

    def test_signed_path_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.crx'
            raw, pin = _package(self.rsa_key, 'data.bin', unsafe=True)
            path.write_bytes(raw)
            with self.assertRaises(ValueError):
                assets.extract(path, Path(directory) / 'output', pin)
            self.assertFalse((Path(directory) / 'outside').exists())

    def _mock_data(self):
        components = copy.deepcopy(assets.COMPONENTS)
        bodies, apps = {}, []
        for index, (role, component) in enumerate(components.items()):
            raw, pin = _package(self.rsa_key if role == 'model' else self.ec_key, component['payload'])
            component['key_sha256'] = pin
            url = 'http://msedge.b.tlu.dl.delivery.mp.microsoft.com/fixture-' + role
            bodies[url] = raw
            digest = hashlib.sha256(raw).hexdigest()
            apps.append({'appid': component['id'], 'status': 'ok', 'updatecheck': {
                'status': 'ok', 'nextversion': '2026.1.2.3', 'pipelines': [{'operations': [
                    {'type': 'download', 'size': len(raw), 'urls': [{'url': url}], 'out': {'sha256': digest}},
                    {'type': 'crx3', 'in': {'sha256': digest}}]}]}})
        response = {'response': {'protocol': '4.0', 'apps': apps}}
        return components, bodies, response

    def _materialized_fixture(self, root):
        components, bodies, response = self._mock_data()
        with patch.object(assets, 'COMPONENTS', components):
            downloads = assets.parse_update_response(json.dumps(response).encode())
            (root / 'packages').mkdir()
            paths = {}
            for role, row in downloads.items():
                paths[role] = root / 'packages' / (row['sha256'] + '.crx')
                paths[role].write_bytes(bodies[row['url']])
            manifest = assets._materialize(root, downloads, paths, {})
        return components, manifest

    def test_reported_metadata_bound_to_signed_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            components, manifest = self._materialized_fixture(root)
            cases = []
            for key, value in [('version', '9999.1.1.1'), ('id', 'a' * 32),
                               ('key_sha256', '0' * 64), ('size', 14), ('payload', 'other.ort')]:
                changed = copy.deepcopy(manifest)
                changed['components']['model'][key] = value
                cases.append(changed)
            changed = copy.deepcopy(manifest)
            changed['components']['model']['package_manifest']['description'] = 'altered claim'
            cases.append(changed)
            with patch.object(assets, 'COMPONENTS', components):
                for changed in cases:
                    (root / 'assets.json').write_text(json.dumps(changed))
                    with self.assertRaises(ValueError):
                        assets.verify_bundle(root)
                # Numeric version equivalence preserves leading-zero manifest versions.
                manifest['components']['model']['version'] = '2026.01.02.3'
                manifest['components']['model']['verification'] = {'pinned_signature_verified': False}
                (root / 'assets.json').write_text(json.dumps(manifest))
                result = assets.verify_bundle(root)
                self.assertTrue(result['components']['model']['verification']['pinned_signature_verified'])

    def test_malformed_bundle_keys_raise_value_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            components, manifest = self._materialized_fixture(root)
            cases = [[], None, {}, {'schema_version': 1, 'paths': []}]
            for key in ('components', 'sha256', 'paths'):
                for value in [None, [], {}, 'invalid']:
                    changed = copy.deepcopy(manifest)
                    changed[key] = value
                    cases.append(changed)
            for key, value in [('package_manifest', None), ('crx', None), ('sha256', []), ('version', 1)]:
                changed = copy.deepcopy(manifest)
                changed['components']['model'][key] = value
                cases.append(changed)
            changed = copy.deepcopy(manifest)
            changed['components']['model'] = None
            cases.append(changed)
            with patch.object(assets, 'COMPONENTS', components):
                for changed in cases:
                    (root / 'assets.json').write_text(json.dumps(changed))
                    with self.assertRaises(ValueError):
                        assets.verify_bundle(root)

    def test_final_output_symlinks_cannot_overwrite_other_files(self):
        components, bodies, response = self._mock_data()
        def http(url, destination, **kwargs):
            raw = b")]}'\n" + json.dumps(response).encode() if url.startswith(assets.UPDATE_URL) else bodies[url]
            Path(destination).write_bytes(raw)
            return {'http_status': 200, 'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'headers': {}, 'transport': 'test'}
        with tempfile.TemporaryDirectory() as directory, patch.object(assets, 'COMPONENTS', components), patch.object(assets, '_http', side_effect=http):
            outer = Path(directory)
            root = outer / 'bundle'
            (root / 'packages').mkdir(parents=True)
            sentinel = outer / 'unrelated'
            sentinel.write_bytes(b'preserve this file')
            digest = response['response']['apps'][0]['updatecheck']['pipelines'][0]['operations'][0]['out']['sha256']
            (root / 'packages' / (digest + '.partial')).symlink_to(sentinel)
            (root / 'assets.json.tmp').symlink_to(sentinel)
            manifest = assets.fetch_assets(root)
            self.assertEqual(sentinel.read_bytes(), b'preserve this file')
            (root / 'assets.json').unlink()
            (root / 'assets.json').symlink_to(sentinel)
            with self.assertRaisesRegex(ValueError, 'symlink'):
                assets.fetch_assets(root)
            self.assertEqual(sentinel.read_bytes(), b'preserve this file')
            (root / 'assets.json').unlink()
            report = root / manifest['paths']['model']
            report = report.parent / 'verification.json'
            report.unlink()
            report.symlink_to(sentinel)
            with self.assertRaisesRegex(ValueError, 'symlink'):
                assets.fetch_assets(root)
            self.assertEqual(sentinel.read_bytes(), b'preserve this file')

    def test_fetch_cache_and_signed_bundle_integrity(self):
        components, bodies, response = self._mock_data()
        calls = []

        def http(url, destination, **kwargs):
            calls.append(url)
            raw = b")]}'\n" + json.dumps(response).encode() if url.startswith(assets.UPDATE_URL) else bodies[url]
            Path(destination).write_bytes(raw)
            return {'http_status': 200, 'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'headers': {}, 'transport': 'test'}

        with tempfile.TemporaryDirectory() as directory, patch.object(assets, 'COMPONENTS', components), patch.object(assets, '_http', side_effect=http):
            root = Path(directory)
            result = assets.fetch_assets(root)
            self.assertEqual(len(calls), 4)
            self.assertTrue(all(isinstance(value, str) and not Path(value).is_absolute() for value in result['paths'].values()))
            self.assertEqual(assets.verify_bundle(root)['sha256'], result['sha256'])
            assets.fetch_assets(root)
            self.assertEqual(len(calls), 5)  # only fresh updater query, cached package bytes
            path = root / result['paths']['model']
            path.write_bytes(b'tampered')
            result['sha256']['model'] = hashlib.sha256(b'tampered').hexdigest()
            (root / 'assets.json').write_text(json.dumps(result))
            with self.assertRaisesRegex(ValueError, 'signed package'):
                assets.verify_bundle(root)

    def test_update_pipeline_unknown_host_or_missing_component_rejected(self):
        _, _, response = self._mock_data()
        examples = []
        missing = copy.deepcopy(response)
        missing['response']['apps'].pop()
        examples.append(missing)
        host = copy.deepcopy(response)
        host['response']['apps'][0]['updatecheck']['pipelines'][0]['operations'][0]['urls'][0]['url'] = 'https://example.com/model'
        examples.append(host)
        action = copy.deepcopy(response)
        action['response']['apps'][0]['updatecheck']['pipelines'][0]['operations'][1]['type'] = 'run'
        examples.append(action)
        for example in examples:
            with self.assertRaises(ValueError):
                assets.parse_update_response(json.dumps(example).encode())
        for example in [{}, {'response': []}, {'response': {'protocol': '4.0', 'apps': [None]}}]:
            with self.assertRaises(ValueError):
                assets.parse_update_response(json.dumps(example).encode())

    def test_real_captured_components_if_available(self):
        base = Path(__file__).resolve().parents[1] / 'analysis/scareware_discovery'
        if not (base / 'downloads.json').exists():
            self.skipTest('Captured artifacts not installed')
        for row in json.loads((base / 'downloads.json').read_text()):
            path = base / row['crx_path']
            if not path.exists():
                self.skipTest('Captured artifacts not installed')
            _, result = assets.verify_crx(path, row['public_key_sha256'], row['expected_sha256'])
            self.assertTrue(result['pinned_signature_verified'])


if __name__ == '__main__':
    unittest.main()

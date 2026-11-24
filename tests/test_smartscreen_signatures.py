import base64
import copy
import contextlib
import datetime
import hashlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from smartscreen import signatures as signatures
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False


def tlv(tag, content):
    size = len(content)
    length = bytes([size]) if size < 128 else bytes([128 + (size.bit_length() + 7) // 8]) + size.to_bytes((size.bit_length() + 7) // 8, 'big')
    return bytes([tag]) + length + content


def seq(*values):
    return tlv(0x30, b''.join(values))


def integer(value):
    data = value.to_bytes(max(1, (value.bit_length() + 7) // 8), 'big')
    return tlv(2, b'\0' + data if data[0] & 128 else data)


def oid(value):
    values = list(map(int, value.split('.')))
    result = bytearray()
    for value in [values[0] * 40 + values[1]] + values[2:]:
        encoded = [value & 127]
        value >>= 7
        while value:
            encoded.insert(0, 128 | (value & 127))
            value >>= 7
        result.extend(encoded)
    return tlv(6, bytes(result))


def pe(*messages):
    data = bytearray(512)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 60, 128)
    data[128:132] = b'PE\0\0'
    struct.pack_into('<H', data, 132, 0xaa64)
    struct.pack_into('<H', data, 148, 240)
    struct.pack_into('<H', data, 152, 0x20b)
    struct.pack_into('<I', data, 152 + 60, 512)
    struct.pack_into('<I', data, 152 + 108, 16)
    table = bytearray()
    for message in messages:
        entry = struct.pack('<IHH', len(message) + 8, 0x200, 2) + message
        table.extend(entry + b'\0' * ((-len(entry)) % 8))
    struct.pack_into('<II', data, 152 + 112 + 32, 512 if table else 0, len(table))
    return bytes(data + table)


class InputTests(unittest.TestCase):
    def inspect(self, raw):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.bin'
            path.write_bytes(raw)
            return signatures.extract_signatures(path)

    def test_absent_embedded_is_not_a_trust_verdict(self):
        for raw, kind in [(b'benign text\n', 'other'), (pe(), 'pe')]:
            value = self.inspect(raw)
            self.assertEqual(value['format'], kind)
            self.assertFalse(value['embedded_signature_present'])
            self.assertEqual(value['wire_metadata'], {})
            self.assertIsNone(value['windows_trust'])
            self.assertEqual(value['catalog_lookup'], 'not_performed')
            self.assertEqual(value['file_sha256'], hashlib.sha256(raw).hexdigest())

    def test_certificate_bounds_and_alignment(self):
        malformed = [b'MZ', pe(b'\x30\x00')[:-1]]
        for offset, length in [(513, 8), (512, 0xffffffff), (0, 8), (511, 8)]:
            raw = bytearray(pe())
            struct.pack_into('<II', raw, 296, offset, length)
            malformed.append(raw)
        for value in malformed:
            with self.subTest(size=len(value)), self.assertRaises(ValueError):
                self.inspect(value)

    def test_bounded_der_rejects_malformed_lengths(self):
        for raw in [b'', b'\x30\x80', b'\x30\x82\x00\x80', b'\x30\x81\x01\x00', b'\x30\x02\x00']:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                signatures._DER(raw)

    def test_malformed_reports_have_clear_errors(self):
        for report in [None, [], {}, {'schema_version': 1, 'signatures': None},
                       {'schema_version': 1, 'signatures': [{'signed_data': {'signers': [None]}}]}]:
            with self.assertRaises(ValueError):
                signatures.authenticode_from_report(report)

    def test_windows_export_works_without_optional_portable_dependency(self):
        root = Path(__file__).resolve().parents[1]
        oracle = root / 'analysis/signatures/windows_oracle.json'
        if not oracle.exists():
            self.skipTest('Windows oracle not collected')
        native = json.loads(oracle.read_text())['files'][0]['native_cached_trust']
        if not native.get('authenticode'):
            self.skipTest('Native full-field oracle not collected')
        with patch.object(signatures, '_signed_data', side_effect=signatures.SignatureDependencyError('missing')), \
                patch.object(signatures, 'windows_trust', return_value=native):
            result = signatures.extract_signatures(root / 'artifacts/smartscreen.dll', verify_windows=True)
        self.assertEqual(result['wire_metadata'], native['authenticode'])
        self.assertTrue(result['embedded_signature_present'])
        self.assertIn('portable_parse_skipped', result['signatures'][0])


@unittest.skipUnless(HAVE_CRYPTO, 'cryptography unavailable')
class SignatureTests(unittest.TestCase):
    inspect = InputTests.inspect
    @classmethod
    def setUpClass(cls):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.issuer = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
                                x509.NameAttribute(NameOID.COMMON_NAME, 'Fixture Issuer')])
        cls.subject = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Fixture Publisher'),
                                 x509.NameAttribute(NameOID.COMMON_NAME, 'Metadata only')])
        now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
        def certificate(name, serial):
            return (x509.CertificateBuilder().subject_name(name).issuer_name(cls.issuer)
                    .public_key(key.public_key()).serial_number(serial)
                    .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=365))
                    .sign(key, hashes.SHA256()))
        cls.ca, cls.leaf = certificate(cls.issuer, 1), certificate(cls.subject, 2)
        cls.ca_der = cls.ca.public_bytes(serialization.Encoding.DER)
        cls.leaf_der = cls.leaf.public_bytes(serialization.Encoding.DER)

    @classmethod
    def cms(cls, *, nested=None, signers=1, duplicate_certificate=False):
        algorithm = seq(oid('2.16.840.1.101.3.4.2.1'), tlv(5, b''))
        raw = pe()
        image_hash = hashlib.sha256(raw[:216] + raw[220:296] + raw[304:]).digest()
        indirect = seq(seq(oid('1.3.6.1.4.1.311.2.1.15')), seq(algorithm, tlv(4, image_hash)))
        info = [integer(1), seq(cls.issuer.public_bytes(), integer(2)), algorithm,
                seq(oid('1.2.840.113549.1.1.1'), tlv(5, b'')), tlv(4, b'UNVERIFIED fixture signature')]
        if nested is not None:
            info.append(tlv(0xa1, seq(oid(signatures.NESTED_SIGNATURE), tlv(0x31, nested))))
        certs = cls.ca_der + cls.leaf_der + (cls.leaf_der if duplicate_certificate else b'')
        signed = seq(integer(1), tlv(0x31, algorithm),
                     seq(oid(signatures.SPC_INDIRECT_DATA), tlv(0xa0, indirect)),
                     tlv(0xa0, certs), tlv(0x31, seq(*info) * signers))
        return seq(oid(signatures.SIGNED_DATA), tlv(0xa0, signed))

    def test_signer_identity_uses_issuer_and_serial_not_first_certificate(self):
        value = self.inspect(pe(self.cms()))
        signed = value['signatures'][0]['signed_data']
        self.assertEqual(signed['signers'][0]['certificate_index'], 1)
        wire = value['wire_metadata']
        self.assertEqual(wire['signer']['subjectName'], 'Fixture Publisher, Metadata only')
        self.assertEqual(wire['issuer']['subjectName'], 'US, Fixture Issuer')
        self.assertEqual(base64.b64decode(wire['signer']['hash']), hashlib.sha1(self.leaf_der).digest())
        self.assertEqual(base64.b64decode(wire['hash']).hex(), signed['image_digest']['computed_hex'])
        self.assertTrue(signed['image_digest']['matches_file'])
        self.assertNotIn('valid', wire)
        self.assertNotIn('hash', wire['issuer'])
        self.assertIsNone(signed['cryptographic_signature_valid'])

    def test_unverified_publisher_claim_is_not_accepted_as_trust(self):
        value = self.inspect(pe(self.cms()))
        self.assertNotIn('valid', value['wire_metadata'])
        for trust in [None, {'trusted': False, 'status_hex': '0x800b0109'},
                      {'trusted': True, 'status_hex': '0x80096010'}]:
            value['windows_trust'] = trust
            self.assertNotIn('valid', signatures.authenticode_from_report(value))
        value['windows_trust'] = {'trusted': True, 'status_hex': '0x00000000', 'file_sha256': value['file_sha256']}
        self.assertTrue(signatures.authenticode_from_report(value)['valid'])
        value['windows_trust']['file_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'bound'):
            signatures.authenticode_from_report(value)

    def test_nested_and_multiple_signatures_inspect_without_silent_selection(self):
        for raw in [pe(self.cms(), self.cms()), pe(self.cms(signers=2)), pe(self.cms(nested=self.cms()))]:
            value = self.inspect(raw)
            self.assertIsNone(value['wire_metadata'])
            self.assertTrue(value['wire_error'])
        value = self.inspect(pe(self.cms(duplicate_certificate=True)))
        self.assertEqual(value['wire_metadata'], {})
        self.assertEqual(value['signatures'][0]['signed_data']['signers'][0]['certificate_match_count'], 2)

    def test_nonzero_cms_trailer_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Nonzero'):
            self.inspect(pe(self.cms() + b'not DER padding'))

    def test_lazy_invalid_x509_version_has_clear_error(self):
        malformed = self.cms().replace(bytes.fromhex('a003020102'), bytes.fromhex('a003020131'), 1)
        with self.assertRaisesRegex(ValueError, 'X.509'):
            self.inspect(pe(malformed))

    def test_mutated_image_and_ambiguous_layout_cannot_enrich(self):
        modified = bytearray(pe(self.cms()))
        modified[500] ^= 1
        report = self.inspect(modified)
        self.assertFalse(report['signatures'][0]['signed_data']['image_digest']['matches_file'])
        self.assertIsNone(report['wire_metadata'])
        bad_headers = bytearray(pe(self.cms()))
        struct.pack_into('<I', bad_headers, 152 + 60, 1024)
        report = self.inspect(bad_headers)
        self.assertIsNone(report['signatures'][0]['signed_data']['image_digest']['matches_file'])
        self.assertIn('overlaps headers', report['wire_error'])
        checksum = bytearray(pe(self.cms()))
        struct.pack_into('<I', checksum, 216, 0x12345678)
        report = self.inspect(checksum)
        self.assertTrue(report['signatures'][0]['signed_data']['image_digest']['matches_file'])
        for offset, length in [(480, 64), (512, 64), (2**31, 64)]:
            overlap = bytearray(pe(self.cms()))
            struct.pack_into('<H', overlap, 134, 1)
            struct.pack_into('<II', overlap, 392 + 16, length, offset)
            report = self.inspect(overlap)
            self.assertIsNone(report['wire_metadata'])
            self.assertIn('section', report['wire_error'])

    def test_native_full_metadata_is_bound_to_success_and_file(self):
        root = Path(__file__).resolve().parents[1]
        oracle = root / 'analysis/signatures/windows_oracle.json'
        if not oracle.exists():
            self.skipTest('Native full-field oracle not available')
        trust = json.loads(oracle.read_text())['files'][0]['native_cached_trust']
        if not trust.get('authenticode'):
            self.skipTest('Native full-field oracle not available')
        report = signatures.extract_signatures(root / 'artifacts/smartscreen.dll')
        report['windows_trust'] = trust
        actual = signatures.authenticode_from_report(report)
        self.assertEqual(actual, trust['authenticode'])
        signed = report['signatures'][0]['signed_data']
        self.assertEqual(actual['hash'], base64.b64encode(bytes.fromhex(signed['image_digest']['computed_hex'])).decode())
        self.assertEqual(hashlib.sha256(base64.b64decode(actual['signing']['message'])).hexdigest(), signed['cms_sha256'])
        issuer_hashes = [item['sha1'] for item in signed['certificates']]
        self.assertIn(base64.b64decode(actual['issuer']['hash']).hex(), issuer_hashes)
        report['file_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'bound'):
            signatures.authenticode_from_report(report)

    def test_cli_inspection_is_offline_and_protects_input(self):
        import smartscreen
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.exe'
            raw = pe(self.cms())
            path.write_bytes(raw)
            output = io.StringIO()
            with patch('sys.argv', ['smartscreen', 'inspect-signature', str(path)]), \
                    patch.object(smartscreen.SmartScreenClient, 'request') as request, contextlib.redirect_stdout(output):
                self.assertEqual(smartscreen.main(), 0)
                request.assert_not_called()
            self.assertNotIn('valid', json.loads(output.getvalue())['wire_metadata'])
            with patch('sys.argv', ['smartscreen', '--output', str(path), 'inspect-signature', str(path)]), \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                smartscreen.main()
            self.assertEqual(error.exception.code, 2)
            self.assertEqual(path.read_bytes(), raw)

    def test_cli_prepares_same_partial_fields_for_browser_and_shell(self):
        import smartscreen
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'fixture.exe'
            path.write_bytes(pe(self.cms()))
            for surface in ('browser', 'shell'):
                folder = root / surface
                output = io.StringIO()
                with patch('sys.argv', ['smartscreen', '--prepare', str(folder), 'file', str(path),
                           '--source', 'https://example.com/', '--surface', surface, '--include-signatures']), \
                        patch.object(smartscreen.SmartScreenClient, 'request') as request, contextlib.redirect_stdout(output):
                    self.assertEqual(smartscreen.main(), 0)
                    request.assert_not_called()
                wire = json.loads((folder / 'request.json').read_text())['file']['authenticode']
                self.assertEqual(wire['signer']['subjectName'], 'Fixture Publisher, Metadata only')
                self.assertNotIn('valid', wire)
                self.assertEqual(json.loads(output.getvalue())['local_signature_metadata']['wire_metadata'], wire)

    def test_cli_windows_trust_requires_signature_enrichment(self):
        import smartscreen
        with patch('sys.argv', ['smartscreen', 'file', 'unused.exe', '--source', 'https://example.com/',
                               '--signature-windows-trust']), \
                contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            smartscreen.main()
        self.assertEqual(error.exception.code, 2)

    def test_saved_windows_oracle_if_available(self):
        root = Path(__file__).resolve().parents[1]
        oracle = root / 'analysis/signatures/windows_oracle.json'
        if not oracle.exists():
            self.skipTest('Windows oracle not collected')
        document = json.loads(oracle.read_text())
        rows = document['files']
        for row in rows:
            path = root / 'artifacts' / row['path'].split('\\')[-1]
            if not row['matches_saved_binary']:
                continue
            value = signatures.extract_signatures(path)
            self.assertEqual(value['file_sha256'], row['sha256'])
            if row['signature_type'] == 'Catalog':
                self.assertEqual(value['catalog_lookup'], 'not_performed')
                if path.name in ('apprepapi.dll', 'smartscreen.exe'):
                    self.assertFalse(value['embedded_signature_present'])
                    self.assertEqual(row['native_cached_trust']['status_hex'], '0x800b0100')
            elif row['signature_type'] == 'Authenticode':
                cert = value['signatures'][0]['signed_data']['certificates'][
                    value['signatures'][0]['signed_data']['signers'][0]['certificate_index']]
                self.assertEqual(cert['sha1'], row['native_signer_names']['sha1'])
                self.assertEqual(cert['subject_name_simple'], row['native_signer_names']['subject'])
                self.assertEqual(cert['issuer_name_simple'], row['native_signer_names']['issuer'])
        for row in document.get('embedded_certificates', []):
            value = signatures.extract_signatures(root / row['source'])
            signed = value['signatures'][0]['signed_data']
            cert = signed['certificates'][signed['signers'][0]['certificate_index']]
            self.assertEqual(cert['sha1'], row['native_names']['sha1'])
            self.assertEqual(cert['subject_name_simple'], row['native_names']['subject'])
            self.assertEqual(cert['issuer_name_simple'], row['native_names']['issuer'])


if __name__ == '__main__':
    unittest.main()

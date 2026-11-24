import base64
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from smartscreen.catalog import catalog_authenticode
from smartscreen.signatures import extract_signatures


def observation(raw=b'fixture'):
    member = hashlib.sha256(raw).digest()
    metadata = {'hashAlgo':'SHA256', 'hash':base64.b64encode(member).decode(), 'valid':True,
                'signer':{'subjectName':'Catalog publisher'}, 'signing':{'time':'0','message':'AA=='}}
    return {'schema_version':1, 'kind':'windows_catalog_observations', 'catalog_lookup':'performed',
            'file_sha256':hashlib.sha256(raw).hexdigest(), 'catalogs':[
                {'signature_origin':'catalog','status_hex':'0x00000000','trusted':True,
                 'member_hash_algorithm':'SHA256','member_hash':member.hex(),'authenticode':metadata}]}


class CatalogTests(unittest.TestCase):
    def test_explicit_selection_and_independent_copy(self):
        value = observation()
        result = catalog_authenticode(value,0,file_sha256=value['file_sha256'])
        self.assertEqual(result['signer']['subjectName'],'Catalog publisher')
        result['valid'] = False
        self.assertTrue(value['catalogs'][0]['authenticode']['valid'])

    def test_reject_wrong_file_and_invalid_indices(self):
        value = observation()
        for index in (-1, True, None, 1):
            with self.subTest(index=index), self.assertRaises(ValueError):
                catalog_authenticode(value,index,file_sha256=value['file_sha256'])
        with self.assertRaises(ValueError):
            catalog_authenticode(value,0,file_sha256='0'*64)

    def test_reject_failed_or_unbound_member_metadata(self):
        for change in ({'trusted':False}, {'status_hex':'0x800b0100'}, {'signature_origin':'embedded'},
                       {'member_hash':'00'*32}, {'member_hash_algorithm':'SHA1'}, {'authenticode':None}):
            value = observation()
            value['catalogs'][0].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                catalog_authenticode(value,0,file_sha256=value['file_sha256'])

    def test_catalogs_never_silently_replace_embedded_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'fixture.bin'
            path.write_bytes(b'fixture')
            value=observation()
            value['catalogs'].append(copy.deepcopy(value['catalogs'][0]))
            value['catalogs'][1]['authenticode']['signer']['subjectName']='Second catalog'
            with patch('smartscreen.catalog.windows_catalog_trust',return_value=value):
                report=extract_signatures(path,lookup_catalog=True)
                self.assertEqual(report['wire_metadata'],{})
                self.assertEqual(len(report['windows_catalogs']['catalogs']),2)
                report=extract_signatures(path,lookup_catalog=True,catalog_index=1)
                self.assertEqual(report['wire_metadata']['signer']['subjectName'],'Second catalog')
                self.assertEqual(report['wire_origin'],'catalog')

    def test_catalog_lookup_binds_extracted_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'fixture.bin'
            path.write_bytes(b'fixture')
            with patch('smartscreen.catalog.windows_catalog_trust',return_value=observation(b'other')):
                with self.assertRaises(ValueError):
                    extract_signatures(path,lookup_catalog=True)
            with self.assertRaises(ValueError):
                extract_signatures(path,catalog_index=0)

    def test_native_fixture_catalog_digests_and_multiple_matches(self):
        path=Path(__file__).resolve().parents[1]/'analysis/signature_catalog_expansion/windows_catalog_oracle.json'
        if not path.exists(): self.skipTest('Native evidence absent')
        rows=json.loads(path.read_text())
        for row in rows:
            value=row['catalog']
            self.assertGreaterEqual(len(value['catalogs']),2)
            for index in range(len(value['catalogs'])):
                self.assertTrue(catalog_authenticode(value,index,file_sha256=value['file_sha256'])['valid'])

    def test_non_pe_container_claims_are_distinct_from_trust(self):
        cases=[('a.msi',bytes.fromhex('d0cf11e0a1b11ae1')+b'not a real MSI','msi'),
               ('a.psm1',b'# SIG # Begin signature block\n# fake\n','script'),
               ('a.appx',b'PK\x03\x04fake','appx_container')]
        with tempfile.TemporaryDirectory() as directory:
            for name,raw,kind in cases:
                path=Path(directory)/name
                path.write_bytes(raw)
                result=extract_signatures(path)
                self.assertEqual(result['format'],kind)
                self.assertIsNone(result['embedded_signature_present'])
                self.assertEqual(result['wire_metadata'],{})
                self.assertEqual(result['catalog_lookup'],'not_performed')

    def test_native_non_pe_export_can_enrich_only_bound_success(self):
        raw=b'# Inert fixture, not executed.\n'
        trust={'trusted':True,'status_hex':'0x00000000','file_sha256':hashlib.sha256(raw).hexdigest(),
               'authenticode':{'hashAlgo':'SHA256','valid':True,'signer':{'subjectName':'SIP publisher'}}}
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'a.psm1'
            path.write_bytes(raw)
            with patch('smartscreen.signatures.windows_trust',return_value=trust):
                result=extract_signatures(path,verify_windows=True)
                self.assertEqual(result['wire_origin'],'registered_sip')
                self.assertTrue(result['embedded_signature_present'])
                self.assertEqual(result['wire_metadata'],trust['authenticode'])


if __name__=='__main__': unittest.main()

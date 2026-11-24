import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile
from unittest.mock import patch

from smartscreen import package as package
MANIFEST=b'<Package xmlns="urn:test"><Identity Name="Fixture.Package" Publisher="CN=Fixture" Version="1.2.3.4" ProcessorArchitecture="arm64"/></Package>'
FULL_NAME='Fixture.Package_1.2.3.4_arm64__123456789abcd'


class PackageTests(unittest.TestCase):
    def write(self,directory,manifest=MANIFEST):
        path=Path(directory)
        (path/'AppxManifest.xml').write_bytes(manifest)
        (path/'AppxBlockMap.xml').write_bytes(b'A'*4096+b'B'*100)
        (path/'AppxSignature.p7x').write_bytes(b'PKCX'+b'C'*5000)
        return path

    def test_native_prefix_profile_preserves_input_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            path=self.write(directory)
            with patch.object(package.os,'name','posix'):
                value=package.extract_package(path,full_name=FULL_NAME)
            self.assertEqual(value['package']['hash'],base64.b64encode(hashlib.sha256(b'A'*4096).digest()).decode())
            self.assertEqual(len(base64.b64decode(value['package']['signature'])),4096)
            self.assertEqual(value['footprint'][1]['size'],4196)
            self.assertIsNone(value['signature_trust'])
            self.assertEqual(value['reader'],package.READER)

    def test_zip_and_directory_have_identical_wire_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            path=self.write(directory)
            archive=path/'fixture.msix'
            with zipfile.ZipFile(archive,'w') as output:
                for name in package.FOOTPRINT: output.write(path/name,name)
            self.assertEqual(package.extract_package(path,full_name=FULL_NAME)['package'],package.extract_package(archive,full_name=FULL_NAME)['package'])

    def test_package_fields_and_context_are_independent(self):
        with tempfile.TemporaryDirectory() as directory:
            row=package.extract_package(self.write(directory),full_name=FULL_NAME)['package']
        profile={'client':{'version':'1'}}
        value=package.package_payload(row,'https://example.com/app.msix',dependencies=[row],profile=profile)
        self.assertEqual(value['location'],{'$type':'uri','value':'https://example.com/app.msix'})
        self.assertFalse(value['uxEnabled'])
        value['package']['name']='changed'
        value['identity']['client']['version']='2'
        self.assertEqual(row['name'],'Fixture.Package')
        self.assertEqual(profile['client']['version'],'1')

    def test_malformed_context_is_rejected(self):
        row={'fullName':'x','name':'x','publisher':'x','hash':base64.b64encode(b'A'*32).decode(),'signature':'UEtDWA=='}
        for options in ({'dependencies':{}},{'ux_enabled':1},{'profile':[]},{'location_type':'unknown'},{'config':[]}):
            with self.subTest(options=options),self.assertRaises(ValueError):
                package.package_payload(row,'https://example.com',**options)
        for key,value in [('hash','a'),('signature',base64.b64encode(b'A'*4097).decode()),('name','')]:
            with self.subTest(key=key),self.assertRaises(ValueError):
                package.package_payload(dict(row,**{key:value}),'https://example.com')

    def test_bad_identity_and_xml_entities_rejected(self):
        malformed=[MANIFEST.replace(b'1.2.3.4',b'65536.0.0.0'),MANIFEST.replace(b'arm64',b'unknown'),
                   b'<!DOCTYPE Package [<!ENTITY x "hi">]>'+MANIFEST,MANIFEST.replace(b'<Identity',b'<Other')]
        for raw in malformed:
            with tempfile.TemporaryDirectory() as directory,self.subTest(raw=raw),self.assertRaises(ValueError):
                package.extract_package(self.write(directory,raw),full_name=FULL_NAME)
        with tempfile.TemporaryDirectory() as directory,self.assertRaises(ValueError):
            package.extract_package(self.write(directory),full_name=FULL_NAME.replace('1.2.3.4','1.2.3.5'))

    def test_duplicate_zip_and_redirected_footprint_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path=self.write(directory)
            archive=path/'fixture.msix'
            with zipfile.ZipFile(archive,'w') as output:
                for name in package.FOOTPRINT: output.write(path/name,name)
                output.writestr('appxmanifest.xml',MANIFEST)
            with self.assertRaises(ValueError): package.extract_package(archive,full_name=FULL_NAME)
            target=path/'AppxBlockMap.xml'
            target.unlink()
            target.symlink_to(path/'AppxManifest.xml')
            with self.assertRaises(ValueError): package.extract_package(path,full_name=FULL_NAME)

    def test_native_fixture_and_live_response_integrity(self):
        root=Path(__file__).resolve().parents[1]/'analysis/signature_catalog_expansion'
        if not (root/'package_response.json').exists(): self.skipTest('Live fixture absent')
        value=json.loads((root/'package_response.json').read_text())
        self.assertEqual(value['response_sha256'],hashlib.sha256((root/'package_response.bin').read_bytes()).hexdigest())
        self.assertEqual(value['http_status'],200)
        self.assertEqual(value['verdict'],'allow')
        metadata=json.loads((root/'package_metadata.json').read_text())
        for row in metadata['footprint']:
            self.assertEqual(row['sha256'],hashlib.sha256((root/'package_fixture'/row['name']).read_bytes()).hexdigest())


if __name__=='__main__': unittest.main()

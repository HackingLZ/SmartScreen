import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import smartscreen
from smartscreen import package as package
from tests.test_smartscreen_package import MANIFEST, FULL_NAME


class PackageCliTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.source=self.root/'package'
        self.source.mkdir()
        for name,raw in [('AppxManifest.xml',MANIFEST),('AppxBlockMap.xml',b'A'*5000),
                         ('AppxSignature.p7x',b'PKCX'+b'S'*5000),('payload.bin',b'inert payload')]:
            (self.source/name).write_bytes(raw)
        self.archive=self.root/'package.msix'
        with zipfile.ZipFile(self.archive,'w') as output:
            for path in self.source.iterdir(): output.write(path,path.name)

    def invoke(self,*args,response=None):
        output=io.StringIO()
        options={'return_value':response} if response is not None else {'side_effect':AssertionError('Unexpected network')}
        with patch('sys.argv',['smartscreen',*map(str,args)]),contextlib.redirect_stdout(output), \
             patch.object(smartscreen.SmartScreenClient,'request',**options) as request, \
             patch.object(package,'windows_package_full_name',return_value=FULL_NAME):
            status=smartscreen.main()
        return status,json.loads(output.getvalue()) if output.getvalue() else None,request

    def query_args(self,source=None):
        return ('package',source or self.source,'--full-name',FULL_NAME,'--location','https://example.com/app.msix')

    def assert_rejected(self,*args):
        with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit) as error:
            self.invoke(*args)
        self.assertEqual(error.exception.code,2)

    def test_inspect_is_offline_and_retains_reader_limits(self):
        status,result,request=self.invoke('inspect-package',self.archive,'--full-name',FULL_NAME)
        self.assertEqual(status,0)
        request.assert_not_called()
        self.assertEqual(result['reader'],package.READER)
        self.assertIsNone(result['signature_trust'])
        self.assertEqual(result['footprint'][1]['wire_bytes'],4096)

    def test_prepare_passes_explicit_dependencies_config_and_identity(self):
        row=package.extract_package(self.source,full_name=FULL_NAME)['package']
        dependencies=self.root/'dependencies.json'
        dependencies.write_text(json.dumps([row]))
        config=self.root/'config.json'
        config.write_text('{"device":{"appControl":{"level":"off"}}}')
        identity=self.root/'identity.json'
        profile=smartscreen.identity()
        profile['user']['locale']='en-GB'
        identity.write_text(json.dumps(profile))
        prepared=self.root/'prepared'
        status,result,request=self.invoke('--prepare',prepared,'--identity',identity,*self.query_args(),
            '--dependencies',dependencies,'--config',config,'--ux-enabled')
        self.assertEqual(status,0)
        request.assert_not_called()
        payload=json.loads((prepared/'request.json').read_text())
        self.assertEqual(payload['package'],row)
        self.assertEqual(payload['dependencies'],[row])
        self.assertEqual(payload['config'],json.loads(config.read_text()))
        self.assertEqual(payload['identity'],profile)
        self.assertTrue(payload['uxEnabled'])
        self.assertEqual(result['endpoint'],package.ENDPOINT)
        self.assertEqual(result['local_package_metadata']['reader'],package.READER)
        self.assertIn(package.ENDPOINT,(prepared/'curl.conf').read_text())

    def test_native_path_location_and_omitted_config(self):
        prepared=self.root/'prepared'
        self.invoke('--prepare',prepared,'package',self.source,'--full-name',FULL_NAME,
                    '--location',r'C:\Downloads\fixture.msix','--location-type','path')
        payload=json.loads((prepared/'request.json').read_text())
        self.assertEqual(payload['location'],{'$type':'path','value':r'C:\Downloads\fixture.msix'})
        self.assertNotIn('config',payload)
        self.assertEqual(payload['dependencies'],[])
        self.assertFalse(payload['uxEnabled'])

    def test_live_query_retains_exact_raw_response_and_metadata(self):
        raw=b'{"$type":"allow","responseCategory":"Allowed"}'
        record=smartscreen.response_record(package.ENDPOINT,200,{},raw)
        output=self.root/'response.json'
        body=self.root/'response.bin'
        status,_,request=self.invoke('--output',output,'--body-output',body,*self.query_args(),response=(record,raw))
        self.assertEqual(status,0)
        self.assertEqual(body.read_bytes(),raw)
        result=json.loads(output.read_text())
        self.assertEqual(result['verdict'],'allow')
        self.assertIsNone(result['local_package_metadata']['signature_trust'])
        self.assertEqual(request.call_args.args[0],package.ENDPOINT)
        self.assertEqual(request.call_args.args[1]['location']['value'],'https://example.com/app.msix')

    def test_non_success_http_remains_failure(self):
        raw=b'{"error":"fixture"}'
        record=smartscreen.response_record(package.ENDPOINT,503,{},raw)
        status,result,_=self.invoke(*self.query_args(),response=(record,raw))
        self.assertEqual(status,1)
        self.assertIsNone(result['verdict'])

    def test_reject_archive_output_aliases_before_network_or_writes(self):
        alias=self.root/'alias.bin'
        os.link(self.archive,alias)
        original=self.archive.read_bytes()
        for target in (self.archive,alias):
            self.assert_rejected('--output',target,'inspect-package',self.archive,'--full-name',FULL_NAME)
            self.assert_rejected('--body-output',target,*self.query_args(self.archive))
        prepared=self.root/'prepared'
        prepared.mkdir()
        os.link(self.archive,prepared/'curl.conf')
        self.assert_rejected('--prepare',prepared,*self.query_args(self.archive))
        self.assertEqual(self.archive.read_bytes(),original)
        self.assertFalse((prepared/'request.json').exists())

    def test_reject_outputs_inside_package_and_external_payload_hardlink(self):
        self.assert_rejected('--output',self.source/'new-output.json','inspect-package',self.source,'--full-name',FULL_NAME)
        self.assertFalse((self.source/'new-output.json').exists())
        self.assert_rejected('--prepare',self.source/'prepared',*self.query_args())
        self.assertFalse((self.source/'prepared').exists())
        for name in ('AppxBlockMap.xml','payload.bin'):
            alias=self.root/(name+'.alias')
            os.link(self.source/name,alias)
            original=alias.read_bytes()
            self.assert_rejected('--output',alias,*self.query_args())
            self.assertEqual(alias.read_bytes(),original)

    def test_reject_dependency_config_identity_and_prepared_collisions(self):
        dependency=self.root/'dependencies.json'
        dependency.write_text('[]')
        config=self.root/'config.json'
        config.write_text('{}')
        identity=self.root/'identity.json'
        identity.write_text('{}')
        for input_path,flag in ((dependency,'--dependencies'),(config,'--config')):
            self.assert_rejected('--output',input_path,*self.query_args(),flag,input_path)
        self.assert_rejected('--output',identity,'--identity',identity,*self.query_args())
        prepared=self.root/'prepared'
        for name in ('request.json','curl.conf'):
            self.assert_rejected('--prepare',prepared,'--output',prepared/name,*self.query_args())
            self.assertFalse((prepared/name).exists())
        prepared.mkdir()
        os.link(dependency,prepared/'request.json')
        self.assert_rejected('--prepare',prepared,*self.query_args(),'--dependencies',dependency)
        self.assertEqual(dependency.read_text(),'[]')
        self.assertFalse((prepared/'curl.conf').exists())

    def test_malformed_dependency_and_inspection_request_options_fail_closed(self):
        dependency=self.root/'dependencies.json'
        dependency.write_text('{}')
        prepared=self.root/'prepared'
        self.assert_rejected('--prepare',prepared,*self.query_args(),'--dependencies',dependency)
        self.assertFalse(prepared.exists())
        self.assert_rejected('--prepare',prepared,'inspect-package',self.source,'--full-name',FULL_NAME)
        self.assert_rejected('--body-output',self.root/'response.bin','inspect-package',self.source,'--full-name',FULL_NAME)

    def test_endpoint_catalog_names_validated_profile_and_limits(self):
        _,result,_=self.invoke('endpoints')
        row=next(x for x in result['api'] if x['name']=='package-install')
        self.assertEqual(row['validation'],'live_validated')
        self.assertEqual(row['reader'],package.READER)
        self.assertEqual(row['auth_id'],smartscreen.EDGE_AUTH_ID)
        self.assertIn('installation enforcement are not established',row['context'])


if __name__=='__main__': unittest.main()

import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import smartscreen
from tests.test_smartscreen_verdicts import observation


class ExpansionCliTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def run_cli(self,*args):
        out=io.StringIO()
        with patch('sys.argv',['smartscreen',*map(str,args)]),contextlib.redirect_stdout(out),patch.object(smartscreen.SmartScreenClient,'request',side_effect=AssertionError('Unexpected network')):
            status=smartscreen.main()
        return status,json.loads(out.getvalue()) if out.getvalue() else None

    def test_export_then_lookup_offline(self):
        source=self.root/'history.jsonl';source.write_text(json.dumps(observation())+'\n')
        output=self.root/'observed.json'
        self.assertEqual(self.run_cli('-o',output,'export-verdicts',source)[0],0)
        status,result=self.run_cli('observed-url','https://example.com/','--catalog',output)
        self.assertEqual(status,0);self.assertEqual(result['status'],'historical_matches')
        self.assertIsNone(result['cloud_verdict'])

    def test_export_cannot_clobber_input(self):
        source=self.root/'history.jsonl';original=json.dumps(observation())+'\n';source.write_text(original)
        with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):
            self.run_cli('-o',source,'export-verdicts',source)
        self.assertEqual(source.read_text(),original)

    def test_cache_import_expiry_and_raw_integrity(self):
        payload={'actions':[{'$type':'cache','key':{'uri':'example.com','inheritance':'path'},
                 'maxAge':1000000,'result':{'$type':'allow'}}]}
        raw=json.dumps(payload).encode()
        record=smartscreen.response_record(smartscreen.ENDPOINTS['url'],200,{},raw)
        record['collected_utc']='2026-11-23T12:00:00Z'
        source=self.root/'response.json';source.write_text(json.dumps(record));source.with_suffix('.bin').write_bytes(raw)
        cache=self.root/'cache.json'
        self.assertEqual(self.run_cli('-o',cache,'cache-import',source)[0],0)
        imported=json.loads(cache.read_text())
        self.assertTrue(imported['entries'][0]['provenance']['wire_bytes_verified'])
        _,result=self.run_cli('cache-url','https://example.com/docs','--cache',cache,'--at','2026-11-23T12:00:01Z')
        self.assertEqual(result['state'],'expired');self.assertIsNone(result['routing_action'])

    def test_inspect_cache_does_not_overwrite_pointer_target(self):
        pointer=self.root/'uriCache';target=self.root/'uriCache_'
        pointer.write_bytes(b'uriCache_');target.write_text('{"version":1,"cache_data":[]}')
        original=target.read_bytes()
        with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):
            self.run_cli('-o',target,'inspect-cache',pointer)
        self.assertEqual(target.read_bytes(),original)

    def test_explain_empty_cache_is_evidence_not_execution(self):
        source=self.root/'response.json';source.write_text('{"actions":[]}')
        cache=self.root/'cache.json';self.run_cli('-o',cache,'cache-import',source)
        _,result=self.run_cli('explain-url','https://example.com/','--cache',cache)
        self.assertFalse(result['is_execution_trace']);self.assertEqual(result['final_enforcement'],'unknown')

    def test_navigationcomplete_prepares_explicit_schema_without_request(self):
        context=self.root/'context.json';models=self.root/'models.json';signals=self.root/'signals.json'
        context.write_text(json.dumps(smartscreen.url_payload('https://example.com/')))
        models.write_text('[{"name":"explicit:test","score":1.0}]');signals.write_text('{"title":"Example Domain"}')
        identity=self.root/'identity.json'
        identity.write_text('{"client":{"version":"281483737628675"},"user":{"locale":"en-GB"}}')
        directory=self.root/'prepared'
        status,report=self.run_cli('--identity',identity,'--prepare',directory,'navigation-complete','--context',context,'--models',models,'--signals',signals)
        self.assertEqual(status,0);self.assertEqual(report['requests_sent'],0)
        payload=json.loads((directory/'request.json').read_text())
        self.assertNotIn('synchronous',payload);self.assertNotIn('forceServiceDetermination',payload)
        self.assertEqual(payload['models'][0]['name'],'explicit:test');self.assertEqual(payload['signals']['title'],'Example Domain')
        self.assertIsNone(payload['signals']['faviconUrl'])
        self.assertEqual(payload['identity'],json.loads(identity.read_text()))

    def test_navigationcomplete_requires_existing_explicit_inputs(self):
        with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):
            self.run_cli('navigation-complete','--context','absent','--models','absent','--signals','absent')

    def test_endpoint_catalog_distinguishes_captured_and_static_routes(self):
        _,result=self.run_cli('endpoints')
        route=next(x for x in result['api'] if x['name']=='navigationcomplete')
        self.assertEqual(route['validation'],'native_capture_and_benign_replay')
        self.assertIn('postnav-edge.',route['url'])
        package=next(x for x in result['api'] if x['name']=='package-install')
        self.assertEqual(package['validation'],'live_validated')
        self.assertEqual(package['reader'],'smartscreen-1.2.2312.1-prefix4096')

    def test_async_url_prepares_native_route(self):
        directory=self.root/'prepared'
        _,report=self.run_cli('--prepare',directory,'url','https://example.com/','--mode','async')
        self.assertEqual(report['endpoint'],smartscreen.ENDPOINTS['url-async'])
        self.assertFalse(json.loads((directory/'request.json').read_text())['synchronous'])

    def test_live_followup_preserves_response_and_http_failure(self):
        native=json.loads((Path(__file__).resolve().parents[1]/'tests/fixtures/navigation/followup_http_title.json').read_text())['request']['json']
        context=self.root/'context.json';models=self.root/'models.json';signals=self.root/'signals.json'
        context.write_text(json.dumps(native));models.write_text(json.dumps(native['models']));signals.write_text(json.dumps(native['signals']))
        raw=b'{"error":"control"}';body=self.root/'response.bin';output=self.root/'response.json'
        record=smartscreen.response_record('https://postnav-edge.smartscreen.microsoft.com/api/browser/edge/navigationcomplete/3',503,{},raw)
        with patch('sys.argv',['smartscreen','-o',str(output),'--body-output',str(body),'navigation-complete','--context',str(context),'--models',str(models),'--signals',str(signals)]),patch.object(smartscreen.SmartScreenClient,'request',return_value=(record,raw)) as send:
            self.assertEqual(smartscreen.main(),1)
        self.assertEqual(body.read_bytes(),raw)
        self.assertEqual(json.loads(output.read_text())['requests_sent'],1)
        sent=send.call_args.args[1]
        self.assertNotIn('serverContext',sent)
        self.assertNotIn('config',sent)
        self.assertEqual(sent,native)

    def test_prepared_file_report_cannot_overwrite_signed_wire_body(self):
        source=self.root/'benign.txt';source.write_text('benign')
        directory=self.root/'prepared'
        for filename in ('request.json','curl.conf'):
            with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):
                self.run_cli('--prepare',directory,'-o',directory/filename,'file',source,'--source','https://example.com/')
            self.assertFalse((directory/filename).exists())

    def test_inspect_netlog_rejects_hardlink_output(self):
        source=self.root/'netlog.json';source.write_text('{"constants":{},"events":[]}')
        target=self.root/'alias.json';os.link(source,target)
        with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):
            self.run_cli('-o',target,'inspect-netlog',source)
        self.assertEqual(source.read_text(),'{"constants":{},"events":[]}')


if __name__=='__main__':unittest.main()

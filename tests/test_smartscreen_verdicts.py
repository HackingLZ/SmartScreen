import base64
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from smartscreen import response_record
from smartscreen.batch import HistoryStore, canonical, prepare_job
from smartscreen.verdicts import export_observed, lookup_observed


def observation(verdict='warn', when='2026-11-23T12:00:00+00:00', *, url='https://example.com/', kind='url', profile=None):
    job=prepare_job({'type':kind,'url':url},profile=profile)
    body={'result':{'$type':verdict,'responseCategory':'Allowed' if verdict=='allow' else 'Malicious'}}
    raw=canonical(body).encode()
    response=response_record(job['endpoint'],200,{'content-type':'application/json'},raw)
    return {**{k:job[k] for k in ('kind','target','context','query_key')},
            'run_id':'test','line_no':1,'observed_utc':when,'status':'verdict','http_status':200,
            'verdict':verdict,'response_category':body['result']['responseCategory'],
            'raw_response_base64':base64.b64encode(raw).decode(),'response_record':response}


class ObservedVerdictsTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def export(self,records,**options):
        p=self.root/'results.jsonl'
        p.write_text(''.join(canonical(row)+'\n' for row in records))
        return export_observed([p],**options)

    def test_later_allow_withdraws_warning_before_filtering(self):
        report=self.export([observation(),observation('allow','2026-11-23T13:00:00Z')])
        self.assertEqual(report['entries'],[])
        self.assertEqual(report['summary']['latest_contexts'],1)

    def test_chronology_not_input_order_and_scoped_by_profile(self):
        earlier=observation('warn')
        later=observation('allow','2026-11-23T13:00:00Z')
        separate=observation('block',profile={'client':{'version':'5'}})
        report=self.export([later,earlier,separate])
        self.assertEqual([x['verdict'] for x in report['entries']],['block'])

    def test_failed_attempt_preserves_historical_warning(self):
        good=observation()
        failed=copy.deepcopy(good)
        failed.update(status='http_error',http_status=503,verdict=None,observed_utc='2026-11-23T13:00:00Z')
        report=self.export([good,failed])
        entry=report['entries'][0]
        self.assertEqual(entry['last_attempt']['http_status'],503)
        self.assertEqual(entry['freshness'],'historical_observation_no_validated_expiry')

    def test_digest_and_parsed_and_target_corruption_rejected(self):
        for field in ('raw','parsed','target','verdict','context','status'):
            with self.subTest(field=field):
                row=observation()
                if field=='raw':row['raw_response_base64']=base64.b64encode(b'{}').decode()
                if field=='parsed':row['response_record']['response']['result']['$type']='allow'
                if field=='target':row['target']['url']='https://other.example/'
                if field=='verdict':row['verdict']='allow'
                if field=='context':row['context']['auth_id']='different'
                if field=='status':row['http_status']=403
                report=self.export([row])
                self.assertEqual(report['entries'],[])
                self.assertFalse(report['summary']['validation_complete'])

    def test_downloads_remain_separate(self):
        records=[observation(),observation('block',kind='download')]
        self.assertEqual(len(self.export(records)['entries']),1)
        report=self.export(records,kinds=('url','download'))
        self.assertEqual(len(report['entries']),2)
        self.assertEqual({e['kind'] for e in report['entries']},{'url','download'})

    def test_unknown_withdraws_earlier_warning(self):
        self.assertEqual(self.export([observation(),observation('unknown','2026-11-23T13:00:00Z')])['entries'],[])

    def test_demo_label_and_exact_offline_lookup(self):
        url='https://demo.smartscreen.msft.net/other/malware.html'
        with mock.patch('socket.socket',side_effect=AssertionError('Network use')):
            report=self.export([observation(url=url)])
            self.assertTrue(report['entries'][0]['is_microsoft_demo'])
            self.assertEqual(lookup_observed(report,url)['status'],'historical_matches')
            miss=lookup_observed(report,'https://demo.smartscreen.msft.net/')
            self.assertEqual(miss['status'],'unknown')
            self.assertIsNone(miss['cloud_verdict'])

    def test_database_read_only_and_not_limited_to_history_query_page(self):
        p=self.root/'history.sqlite3'
        with HistoryStore(p) as store:
            for n in range(1002):
                store.append(observation(url=f'https://host{n}.example/'))
        before=hashlib.sha256(p.read_bytes()).hexdigest()
        result=export_observed([p],max_records=2000)
        self.assertEqual(result['summary']['exported'],1002)
        self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(),before)

    def test_limit_does_not_silently_export_partial(self):
        with self.assertRaisesRegex(ValueError,'max_records'):
            self.export([observation(),observation()],max_records=1)

    def test_reject_duplicate_json_and_timezone_missing(self):
        p=self.root/'duplicate.jsonl';p.write_text('{"x":1,"x":2}\n')
        with self.assertRaisesRegex(ValueError,'Duplicate'):
            export_observed([p])
        report=self.export([observation(when='2026-11-23T12:00:00')])
        self.assertFalse(report['summary']['validation_complete'])

    def test_malformed_catalog_fails(self):
        with self.assertRaises(ValueError):lookup_observed({},'https://example.com/')


if __name__=='__main__':
    unittest.main()

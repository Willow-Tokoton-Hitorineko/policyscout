import json
import tempfile
import threading
import unittest
import urllib.request
import urllib.error
from pathlib import Path
from unittest.mock import patch
from policyscout import server
from policyscout.boundaries import validate_region
from policyscout.dashboard import build_dashboard_html

class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.root=Path(self.tmp.name);self.cache=self.root/'cache';self.cache.mkdir()
        self.cache_patch=patch.object(server,'_CACHE_DIR',self.cache);self.cache_patch.start()
        self.http=server.ThreadingHTTPServer(('127.0.0.1',0),server.AgentHandler)
        self.thread=threading.Thread(target=self.http.serve_forever,daemon=True);self.thread.start()
        self.base=f'http://127.0.0.1:{self.http.server_port}'
        self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    def tearDown(self):
        self.http.shutdown();self.http.server_close();self.thread.join();self.cache_patch.stop();self.tmp.cleanup()
    def get(self,path,headers=None):
        try:
            with self.opener.open(urllib.request.Request(self.base+path,headers=headers or {})) as r:return r.status,r.read(),r.headers
        except urllib.error.HTTPError as e:return e.code,e.read(),e.headers
    def test_cache_traversal_and_cross_origin(self):
        (self.root/'sentinel.json').write_text('{"private":true}')
        for path in ('/api/cached/..%2Fsentinel.json','/api/cached/..%5Csentinel.json','/api/cached/C%3A%5Csentinel.json'):
            self.assertEqual(self.get(path)[0],404)
        code,_,headers=self.get('/api/cached',{'Origin':'https://example.invalid'})
        self.assertEqual(code,403);self.assertNotIn('Access-Control-Allow-Origin',headers)
        self.assertEqual(self.get('/',{'Host':'attacker.invalid'})[0],403)
    def test_valid_cache_and_session_page(self):
        (self.cache/'1234abcd_某市.json').write_text('{"city":"demo"}',encoding='utf8')
        self.assertEqual(self.get('/api/cached/1234abcd_%E6%9F%90%E5%B8%82.json')[0],200)
        code,body,_=self.get('/');self.assertEqual(code,200)
        self.assertIn(server._SESSION_TOKEN.encode(),body)
        self.assertIn(b'sandbox="allow-scripts allow-popups allow-downloads"',body)
    def test_collect_requires_token_and_valid_region(self):
        with patch.object(server.AgentHandler,'_handle_collect_sse') as collect:
            self.assertEqual(self.get('/api/collect?city=x&province=y')[0],403)
            path=f'/api/collect?city=..%2Fx&province=y&token={server._SESSION_TOKEN}'
            self.assertEqual(self.get(path)[0],400);collect.assert_not_called()
    def test_collection_default_and_opt_in(self):
        calls=[]
        def stub(handler,city,province,use_llm=False):
            calls.append(use_llm);handler.send_response(200);handler.end_headers()
        with patch.object(server.AgentHandler,'_handle_collect_sse',stub):
            p=f'/api/collect?city=x&province=y&token={server._SESSION_TOKEN}'
            self.assertEqual(self.get(p)[0],200);self.assertEqual(self.get(p+'&use_llm=1')[0],200)
        self.assertEqual(calls,[False,True])
    def test_concurrent_collection_rejected(self):
        server._COLLECT_LOCK.acquire()
        try:self.assertEqual(self.get(f'/api/collect?city=x&province=y&token={server._SESSION_TOKEN}')[0],429)
        finally:server._COLLECT_LOCK.release()
    def test_busy_port_does_not_kill_listener(self):
        with self.assertRaises(OSError):server.start_server(port=self.http.server_port)
        self.assertEqual(self.get('/')[0],200)
    def test_regions_reject_paths_before_collection(self):
        from policyscout.collect import collect_city
        with self.assertRaises(ValueError):collect_city('../outside','x',False)
        for v in ('../x','x/y','x\\y','x\n',''):
            with self.assertRaises(ValueError):validate_region(v)
        self.assertEqual(validate_region('某省'),'某省')
    def test_dashboard_script_boundary(self):
        malicious='</script><script>alert(1)</script>'
        gap={'city':malicious,'province':'某省','summary':{'city_level_n':0,'district_n':0,'year_range_city':'-', 'year_range_district':'-', 'gap_years':'-'},'city_texts':[],'district_texts':[],'year_timeline':[]}
        html=build_dashboard_html(gap,[{'title':malicious,'url':'javascript:alert(1)'}])
        self.assertEqual(html.count('<script>'),1)
        self.assertNotIn(malicious,html)
        self.assertIn(r'\u003c/script\u003e',html)
        self.assertIn("u.protocol!=='http:'&&u.protocol!=='https:'",html)

if __name__=='__main__':unittest.main()

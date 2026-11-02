"""Browser tests for the local demo; no external network or provider calls."""
import json, threading, unittest
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from playwright.sync_api import sync_playwright
ROOT=Path(__file__).resolve().parent
class QuietHandler(SimpleHTTPRequestHandler):
 def log_message(self,*args):pass
class DemoBrowserTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  handler=partial(QuietHandler,directory=str(ROOT/"_site"));cls.server=ThreadingHTTPServer(("127.0.0.1",0),handler);cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start();cls.base="http://127.0.0.1:%d"%cls.server.server_port;cls.pw=sync_playwright().start();cls.browser=cls.pw.chromium.launch()
 @classmethod
 def tearDownClass(cls):
  cls.browser.close();cls.pw.stop();cls.server.shutdown();cls.server.server_close();cls.thread.join(timeout=3)
 def test_renders_synthetic_data_and_makes_no_external_requests(self):
  page=self.browser.new_page();external=[];page.on("request",lambda req:external.append(req.url) if not req.url.startswith(self.base) else None);page.goto(self.base+"/dashboard_demo.html",wait_until="networkidle")
  self.assertIn("SIMULATED DATA",page.locator("body").inner_text());self.assertIn("NO PAYMENT WAS EXECUTED",page.locator("body").inner_text());self.assertIn("artifact SHA verified",page.locator("#snapshot-meta").inner_text());self.assertEqual(page.locator("#payments").inner_text(),"0");self.assertEqual(external,[]);page.close()
 def test_hostile_snapshot_values_render_as_text(self):
  page=self.browser.new_page();payload={"schema_version":1,"generated_at":"2026-11-02T00:00:00+00:00","demo_mode":"SIMULATED","data_source":"synthetic_local_fixture","external_provider_calls":False,"real_payment_executed":False,"statistics":{"simulated_scenarios":1,"simulated_allow":0,"simulated_block":0,"real_payments":0},"verification_capabilities":{"kyapay_issuer":"UNVERIFIED","merchant_identity":"UNVERIFIED","dpop_signature":"UNVERIFIED","paypal_authorization":"NOT_ATTEMPTED"},"latest_scenario":{"id":"test","status":"NOT_EXECUTED","merchant":"<img src=x onerror=window.__xss=2>","amount":None,"currency":None},"audit_trail":[{"time":"scenario-x","event":"<img src=x onerror=window.__xss=3>","result":"UNKNOWN_BLOCKED","classification":"UNKNOWN_BLOCKED"}]}
  page.add_init_script("window.__xss=0");page.route("**/hasil_demo.json",lambda route:route.fulfill(status=200,content_type="application/json",body=json.dumps(payload)));page.goto(self.base+"/dashboard_demo.html",wait_until="networkidle");self.assertEqual(page.locator("img").count(),0);self.assertEqual(page.evaluate("window.__xss"),0);self.assertIn("<img src=x",page.locator("#latest").inner_text());page.close()
 def test_invalid_snapshot_fails_closed(self):
  page=self.browser.new_page();page.route("**/hasil_demo.json",lambda route:route.fulfill(status=200,content_type="application/json",body=json.dumps({"demo_mode":"LIVE","real_payment_executed":True})));page.goto(self.base+"/dashboard_demo.html",wait_until="networkidle");self.assertIn("UNKNOWN_BLOCKED",page.locator("#snapshot-meta").inner_text());self.assertIn("UNKNOWN_BLOCKED",page.locator("#verification").inner_text());self.assertEqual(page.locator("#payments").inner_text(),"0");page.close()
if __name__=="__main__":unittest.main()

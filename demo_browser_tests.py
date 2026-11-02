"""Real browser checks for the isolated synthetic dashboard. No external network or provider calls."""
import json
import threading
import unittest
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent

class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        pass

class DemoBrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        handler = partial(QuietHandler, directory=str(ROOT))
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = "http://127.0.0.1:%d/dashboard_v2.html" % cls.server.server_port
        cls.playwright = sync_playwright().start()
        cls.browser = cls.playwright.chromium.launch()

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.playwright.stop()
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    def test_dashboard_renders_synthetic_status_without_provider_network(self):
        page = self.browser.new_page()
        external = []
        page.on("request", lambda req: external.append(req.url) if not req.url.startswith("http://127.0.0.1:") else None)
        page.goto(self.url, wait_until="networkidle")
        self.assertIn("SIMULATED DATA", page.locator("body").inner_text())
        self.assertIn("NO PAYMENT WAS EXECUTED", page.locator("body").inner_text())
        self.assertEqual(page.locator("#payments").inner_text(), "0")
        self.assertIn("UNKNOWN_BLOCKED", page.locator("#audit").inner_text())
        self.assertEqual(external, [])
        page.close()

    def test_hostile_snapshot_values_are_rendered_as_text(self):
        page = self.browser.new_page()
        payload = {
            "schema_version": 1, "generated_at": "2026-11-02T00:00:00+00:00",
            "demo_mode": "SIMULATED", "data_source": "<img src=x onerror=window.__xss=1>",
            "external_provider_calls": False, "real_payment_executed": False,
            "statistics": {"simulated_scenarios": 1, "simulated_allow": 0, "simulated_block": 0, "real_payments": 0},
            "verification_capabilities": {"merchant": "UNVERIFIED"},
            "latest_scenario": {"id": "test", "status": "NOT_EXECUTED", "merchant": "<img src=x onerror=window.__xss=2>", "amount": None},
            "audit_trail": [{"event": "<img src=x onerror=window.__xss=3>", "result": "UNKNOWN_BLOCKED", "classification": "UNKNOWN_BLOCKED"}]
        }
        page.route("**/hasil.json", lambda route: route.fulfill(status=200, content_type="application/json", body=json.dumps(payload)))
        page.goto(self.url, wait_until="networkidle")
        self.assertEqual(page.locator("img").count(), 0)
        self.assertIsNone(page.evaluate("window.__xss"))
        self.assertIn("<img src=x", page.locator("#snapshot-meta").inner_text())
        page.close()

    def test_invalid_snapshot_contract_fails_closed(self):
        page = self.browser.new_page()
        page.route("**/hasil.json", lambda route: route.fulfill(status=200, content_type="application/json", body=json.dumps({"demo_mode":"LIVE","real_payment_executed":True})))
        page.goto(self.url, wait_until="networkidle")
        self.assertIn("UNKNOWN_BLOCKED", page.locator("#verification").inner_text())
        self.assertIn("invalid", page.locator("#snapshot-meta").inner_text().lower())
        page.close()

if __name__ == "__main__":
    unittest.main()

"""Playwright runtime regression tests for TrustGuard static dashboards.

These tests exercise the browser DOM, responsive layout, console/network signals,
and hostile JSON values. They do not certify production deployment or backend trust.
"""
import json
import pathlib
import threading
import unittest
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

from playwright.sync_api import sync_playwright

ROOT = pathlib.Path(__file__).resolve().parent
ARTIFACTS = ROOT / "browser-artifacts"
VALID_DATA = {
    "schema_version": 1,
    "source_status": "UNVERIFIED",
    "timestamp": None,
    "transaksi_terakhir": {
        "order_id": None,
        "authentication_status": "UNKNOWN",
        "policy_status": "UNKNOWN",
        "delivery_status": "UNKNOWN",
        "merchant": None,
        "total": None,
    },
    "audit_trail": [],
}


class QuietHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return
        super().do_GET()

    def log_message(self, format, *args):
        pass


class DashboardBrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ARTIFACTS.mkdir(exist_ok=True)
        handler = partial(QuietHandler, directory=str(ROOT / "_site"))
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"
        cls.playwright = sync_playwright().start()
        cls.browser = cls.playwright.chromium.launch()

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.playwright.stop()
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=2)

    def setUp(self):
        self.context = self.browser.new_context(viewport={"width": 1440, "height": 1000})
        self.page = self.context.new_page()
        self.console_errors = []
        self.page_errors = []
        self.network_errors = []
        self.page.on("console", lambda message: self.console_errors.append(message.text) if message.type == "error" else None)
        self.page.on("pageerror", lambda error: self.page_errors.append(str(error)))
        self.page.on("requestfailed", lambda request: self.network_errors.append(f"{request.method} {request.url}: {request.failure}"))
        self.page.on("response", lambda response: self.network_errors.append(f"HTTP {response.status}: {response.url}") if response.status >= 400 else None)
        self.page.add_init_script("window.__xss = 0;")

    def tearDown(self):
        self.context.close()

    def open_v2(self, body):
        self.page.unroute_all()
        self.page.route(
            "**/hasil.json",
            lambda route: route.fulfill(status=200, content_type="application/json", body=body),
        )
        self.page.goto(f"{self.base_url}/dashboard_v2.html", wait_until="networkidle")
        self.page.wait_for_function(
            "() => { const n = document.querySelector('#source-notice'); return n && !n.textContent.startsWith('Memuat data.'); }"
        )

    def assert_no_runtime_errors(self):
        self.assertEqual(self.console_errors, [], f"Browser console errors: {self.console_errors}")
        self.assertEqual(self.page_errors, [], f"Uncaught page errors: {self.page_errors}")
        self.assertEqual(self.network_errors, [], f"Network errors: {self.network_errors}")

    def test_static_dashboard_desktop_mobile_and_status_claims(self):
        for filename in ("dashboard.html", "dashboard_v2.html"):
            for width, height, label in ((1440, 1000, "desktop"), (390, 844, "mobile"), (320, 740, "small-mobile")):
                with self.subTest(file=filename, viewport=label):
                    self.page.set_viewport_size({"width": width, "height": height})
                    if filename == "dashboard.html":
                        self.page.goto(f"{self.base_url}/{filename}", wait_until="networkidle")
                    else:
                        self.page.unroute_all()
                        self.page.route(
                            "**/hasil.json",
                            lambda route: route.fulfill(
                                status=200,
                                content_type="application/json",
                                body=json.dumps(VALID_DATA),
                            ),
                        )
                        self.page.goto(f"{self.base_url}/{filename}", wait_until="networkidle")
                        self.page.wait_for_function("() => document.querySelector('#source-notice').textContent.includes('UNVERIFIED')")
                    self.assertIn("UNKNOWN", self.page.locator("body").inner_text())
                    self.assertNotIn("100%", self.page.locator("body").inner_text())
                    self.assertNotIn("SUCCEEDED", self.page.locator("body").inner_text())
                    self.assertLessEqual(
                        self.page.evaluate("document.documentElement.scrollWidth"),
                        self.page.evaluate("document.documentElement.clientWidth"),
                        f"Horizontal overflow at {width}px for {filename}",
                    )
                    self.page.screenshot(path=str(ARTIFACTS / f"{pathlib.Path(filename).stem}-{label}.png"), full_page=True)
                    self.assert_no_runtime_errors()

    def test_valid_json_displays_separate_unknown_statuses_and_unverified_source(self):
        self.open_v2(json.dumps(VALID_DATA))
        text = self.page.locator("body").inner_text()
        self.assertIn("UNVERIFIED", text)
        self.assertIn("Autentikasi", text)
        self.assertIn("Kebijakan", text)
        self.assertIn("Delivery", text)
        self.assertGreaterEqual(text.count("UNKNOWN"), 3)
        self.assertIn("bukan bukti telemetry backend terautentikasi", text)
        self.assertNotIn("100%", text)
        self.page.screenshot(path=str(ARTIFACTS / "dashboard-v2-valid-desktop.png"), full_page=True)
        self.assert_no_runtime_errors()

    def test_empty_json_and_malformed_json_fail_closed(self):
        for label, body in (("empty", ""), ("malformed", "{"), ("empty-object", "{}")):
            with self.subTest(payload=label):
                self.open_v2(body)
                text = self.page.locator("body").inner_text()
                self.assertIn("Semua status harus dianggap UNKNOWN", text)
                self.assertIn("Data tidak tersedia.", text)
                self.assertNotIn("PASSED", text)
                self.assertNotIn("100%", text)
                self.assert_no_runtime_errors()

    def test_missing_field_and_wrong_type_fail_closed(self):
        missing = json.loads(json.dumps(VALID_DATA))
        del missing["transaksi_terakhir"]["policy_status"]
        wrong_type = json.loads(json.dumps(VALID_DATA))
        wrong_type["transaksi_terakhir"]["authentication_status"] = {"status": "UNKNOWN"}
        invalid_delivery = json.loads(json.dumps(VALID_DATA))
        invalid_delivery["transaksi_terakhir"]["delivery_status"] = "SUCCEEDED"

        for label, data in (("missing-field", missing), ("wrong-type", wrong_type), ("success-claim", invalid_delivery)):
            with self.subTest(payload=label):
                self.open_v2(json.dumps(data))
                text = self.page.locator("body").inner_text()
                self.assertIn("Semua status harus dianggap UNKNOWN", text)
                self.assertNotIn("SUCCEEDED", text)
                self.assertNotIn("PASSED", text)
                self.assert_no_runtime_errors()

    def test_unverified_json_cannot_claim_authentication_or_policy_passed(self):
        for field in ("authentication_status", "policy_status"):
            with self.subTest(field=field):
                data = json.loads(json.dumps(VALID_DATA))
                data["transaksi_terakhir"][field] = "PASSED"
                self.open_v2(json.dumps(data))
                text = self.page.locator("body").inner_text()
                self.assertIn("Semua status harus dianggap UNKNOWN", text)
                self.assertNotIn("PASSED", text)
                self.assert_no_runtime_errors()

    def test_order_created_is_explicitly_unverified_and_not_payment_success(self):
        data = json.loads(json.dumps(VALID_DATA))
        data["transaksi_terakhir"]["delivery_status"] = "ORDER_CREATED"
        self.open_v2(json.dumps(data))
        text = self.page.locator("body").inner_text()
        self.assertIn("UNVERIFIED · ORDER_CREATED (klaim file)", text)
        self.assertIn("bukan pembayaran sukses atau capture", text)
        self.assertNotIn("SUCCEEDED", text)
        self.assertNotIn("100%", text)
        self.page.set_viewport_size({"width": 320, "height": 740})
        self.assertLessEqual(
            self.page.evaluate("document.documentElement.scrollWidth"),
            self.page.evaluate("document.documentElement.clientWidth"),
        )
        self.page.screenshot(path=str(ARTIFACTS / "dashboard-v2-order-created-small-mobile.png"), full_page=True)
        self.assert_no_runtime_errors()


    def test_fetch_failure_fails_closed(self):
        self.page.route("**/build-info.json", lambda route: route.fulfill(
            status=200, content_type="application/json",
            body=(ROOT / "_site" / "build-info.json").read_text(encoding="utf-8"),
        ))
        self.page.route("**/hasil.json", lambda route: route.abort())
        self.page.goto(f"{self.base_url}/dashboard_v2.html", wait_until="networkidle")
        text = self.page.locator("body").inner_text()
        self.assertIn("Semua status harus dianggap UNKNOWN", text)
        self.assertIn("Data tidak tersedia.", text)
        self.assertNotIn("PASSED", text)
        self.assertEqual(self.page_errors, [])
        self.assertTrue(any("ERR_FAILED" in item for item in self.console_errors), self.console_errors)

    def test_stale_timestamp_fails_closed_and_suppresses_transaction_data(self):
        data = json.loads(json.dumps(VALID_DATA))
        data["timestamp"] = "2000-01-01T00:00:00Z"
        data["transaksi_terakhir"]["order_id"] = "STALE-ORDER-SHOULD-NOT-RENDER"
        data["transaksi_terakhir"]["merchant"] = "STALE-MERCHANT"
        data["transaksi_terakhir"]["total"] = "999.99"
        self.open_v2(json.dumps(data))
        text = self.page.locator("body").inner_text()
        self.assertIn("UNVERIFIED", text)
        self.assertIn("Data tidak tersedia.", text)
        self.assertNotIn("STALE-ORDER-SHOULD-NOT-RENDER", text)
        self.assertNotIn("STALE-MERCHANT", text)
        self.assertNotIn("999.99", text)
        self.assertGreaterEqual(text.count("UNKNOWN"), 3)
        self.assertNotIn("SUCCESS", text)
        self.assertNotIn("PASSED", text)
        self.assert_no_runtime_errors()

    def test_dashboard_manifest_sha_mismatch_fails_closed(self):
        self.page.route("**/build-info.json", lambda route: route.fulfill(
            status=200, content_type="application/json",
            body=json.dumps({
                "application": "PayPal AI Trust Engine",
                "frontend_commit": "0" * 40,
                "build_source": "GitHub Actions checkout",
                "status": "UNVERIFIED_STATIC_FRONTEND",
            }),
        ))
        self.page.route("**/hasil.json", lambda route: route.fulfill(
            status=200, content_type="application/json", body=json.dumps(VALID_DATA)
        ))
        self.page.goto(f"{self.base_url}/dashboard_v2.html", wait_until="networkidle")
        text = self.page.locator("body").inner_text()
        self.assertIn("Semua status harus dianggap UNKNOWN", text)
        self.assertIn("Data tidak tersedia.", text)
        self.assertNotIn("PASSED", text)
        self.assert_no_runtime_errors()

    def test_xss_payloads_render_as_text_and_do_not_create_elements_or_execute(self):
        data = json.loads(json.dumps(VALID_DATA))
        payload = '<img src=x onerror="window.__xss=1"><script>window.__xss=2</script>'
        data["timestamp"] = "2026-11-01T00:00:00Z"
        data["transaksi_terakhir"]["order_id"] = payload
        data["transaksi_terakhir"]["merchant"] = payload
        data["audit_trail"] = [{"waktu": payload, "event": payload, "hasil": payload}]
        self.open_v2(json.dumps(data))
        self.assertEqual(self.page.evaluate("window.__xss"), 0)
        self.assertEqual(self.page.locator("#transaksi-area img, #transaksi-area script").count(), 0)
        self.assertEqual(self.page.locator("#audit-area img, #audit-area script").count(), 0)
        self.assertIn("<img src=x", self.page.locator("#transaksi-area").inner_text())
        self.assertIn("<script>", self.page.locator("#audit-area").inner_text())
        self.assert_no_runtime_errors()

    def test_audit_result_cannot_spoof_verified_status(self):
        data = json.loads(json.dumps(VALID_DATA))
        data["timestamp"] = "2026-10-31T12:00:00Z"
        data["audit_trail"] = [{"waktu": "2026-10-31T12:00:00Z", "event": "token check", "hasil": "VERIFIED"}]
        self.open_v2(json.dumps(data))
        text = self.page.locator("body").inner_text()
        self.assertIn("Data tidak tersedia.", text)
        self.assertNotIn("VERIFIED", text)
        self.assert_no_runtime_errors()

    def test_both_dashboards_reject_manifest_sha_mismatch(self):
        self.page.route("**/build-info.json", lambda route: route.fulfill(
            status=200, content_type="application/json",
            body=json.dumps({
                "application": "PayPal AI Trust Engine",
                "frontend_commit": "0" * 40,
                "build_source": "GitHub Actions checkout",
                "status": "UNVERIFIED_STATIC_FRONTEND",
            }),
        ))
        for filename in ("dashboard.html", "dashboard_v2.html"):
            with self.subTest(filename=filename):
                self.page.goto(f"{self.base_url}/{filename}", wait_until="networkidle")
                text = self.page.locator("body").inner_text()
                self.assertIn("UNKNOWN", text)
                self.assertNotIn("PASSED", text)
                self.assert_no_runtime_errors()


if __name__ == "__main__":
    unittest.main()

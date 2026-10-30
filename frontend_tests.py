"""Regression checks for the static TrustGuard dashboard and its JSON contract.

These tests inspect the shipped HTML/JSON contract; they do not certify the live
browser, backend telemetry, or production security.
"""
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent


class FrontendHardeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dashboard = (ROOT / "dashboard.html").read_text(encoding="utf-8")
        cls.dashboard_v2 = (ROOT / "dashboard_v2.html").read_text(encoding="utf-8")
        cls.data = json.loads((ROOT / "hasil.json").read_text(encoding="utf-8"))

    def test_json_has_explicit_unverified_source_and_no_unsupported_metrics(self):
        self.assertEqual(self.data["schema_version"], 1)
        self.assertEqual(self.data["source_status"], "UNVERIFIED")
        self.assertIsNone(self.data["timestamp"])
        self.assertNotIn("statistik", self.data)
        self.assertNotIn("tingkat_keamanan", json.dumps(self.data))
        self.assertEqual(self.data["audit_trail"], [])

    def test_transaction_statuses_are_separate_and_unknown_by_default(self):
        trx = self.data["transaksi_terakhir"]
        self.assertEqual(trx["authentication_status"], "UNKNOWN")
        self.assertEqual(trx["policy_status"], "UNKNOWN")
        self.assertEqual(trx["delivery_status"], "UNKNOWN")
        self.assertIsNone(trx["order_id"])
        self.assertIsNone(trx["merchant"])
        self.assertIsNone(trx["total"])

    def test_dashboard_never_uses_inner_html(self):
        for html in (self.dashboard, self.dashboard_v2):
            self.assertNotIn("innerHTML", html.lower())

    def test_dynamic_dashboard_validates_json_structure_and_types(self):
        for required in (
            "function validateDashboardData(data)",
            "data.schema_version !== 1",
            'data.source_status !== "UNVERIFIED"',
            "isRecord(data.transaksi_terakhir)",
            "typeof trx.authentication_status !== \"string\"",
            "typeof trx.policy_status !== \"string\"",
            "typeof trx.delivery_status !== \"string\"",
            "Array.isArray(data.audit_trail)",
            "data.audit_trail.every(item =>",
        ):
            self.assertIn(required, self.dashboard_v2)

    def test_dynamic_rendering_uses_text_nodes_and_safe_dom_apis(self):
        self.assertIn("textContent", self.dashboard_v2)
        self.assertIn("document.createElement", self.dashboard_v2)
        self.assertIn("replaceChildren()", self.dashboard_v2)
        self.assertNotIn("insertAdjacentHTML", self.dashboard_v2)
        self.assertNotIn("document.write(", self.dashboard_v2)

    def test_order_created_is_never_described_as_payment_success(self):
        self.assertIn("ORDER_CREATED — order dibuat; bukan pembayaran sukses atau capture", self.dashboard_v2)
        self.assertIn("bukan status capture", self.dashboard_v2)
        self.assertIn("pembayaran selesai, capture", self.dashboard)
        self.assertNotIn('"status": "SUCCESS"', json.dumps(self.data))
        self.assertNotIn('"delivery_status": "SUCCEEDED"', json.dumps(self.data))

    def test_static_pages_do_not_claim_security_is_active_or_perfect(self):
        for html in (self.dashboard, self.dashboard_v2):
            self.assertNotIn("tingkat keamanan 100%", html)
            self.assertNotIn(">100%<", html)
            self.assertNotIn(">AKTIF<", html)
        self.assertIn("belum terhubung", self.dashboard.lower())
        self.assertIn("BELUM DIVERIFIKASI", self.dashboard_v2)


if __name__ == "__main__":
    unittest.main()

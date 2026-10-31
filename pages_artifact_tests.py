"""Contract tests for the exact generated GitHub Pages artifact."""
import json
import os
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent / "_site"
EXPECTED_SHA = os.environ.get("GITHUB_SHA", "").strip()
PLACEHOLDER = "__TRUSTGUARD_BUILD_COMMIT__"
LEGACY_MARKERS = (
    "Bukti Transaksi End-to-End (PayPal Sandbox)",
    "7R3064957MB0759941",
    "3HD92730V0626752B",
    "1U9063377E719994A",
)

# Only flag claims presented as live/status values, not explanatory prose.
UNSUPPORTED_STATUS_PATTERNS = (
    re.compile(r'class=["\'][^"\']*\bstatus-ok\b[^"\']*["\'][^>]*>\s*(?:ACTIVE|SUCCESS|SUCCEEDED|SUKSES)\s*<', re.I),
    re.compile(r'<(?:strong|b|span)[^>]*>\s*(?:Status\s*:\s*)?(?:ACTIVE|SUCCESS|SUCCEEDED|SUKSES)\s*</(?:strong|b|span)>', re.I),
    re.compile(r'(?:security score|tingkat keamanan(?: sistem)?)\s*[:=]?\s*[^<\n]{0,40}\b100\s*%', re.I),
    re.compile(r'(?:keamanan|security)\s*(?:score|skor|rating|nilai)\s*[:=]?\s*100\s*%', re.I),
)


class PagesArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not EXPECTED_SHA:
            raise RuntimeError("GITHUB_SHA must be set to the commit being tested")
        cls.dashboard_html = (ROOT / "dashboard.html").read_text(encoding="utf-8")
        cls.dashboard_v2_html = (ROOT / "dashboard_v2.html").read_text(encoding="utf-8")
        cls.index_html = (ROOT / "index.html").read_text(encoding="utf-8")
        cls.manifest = json.loads((ROOT / "build-info.json").read_text(encoding="utf-8"))
        cls.data = json.loads((ROOT / "hasil.json").read_text(encoding="utf-8"))

    def test_required_pages_exist(self):
        for name in ("dashboard.html", "dashboard_v2.html", "build-info.json", "hasil.json", "index.html"):
            with self.subTest(name=name):
                self.assertTrue((ROOT / name).is_file(), f"missing artifact: {name}")

    def test_manifest_is_valid_and_matches_source_commit(self):
        self.assertEqual(self.manifest.get("application"), "PayPal AI Trust Engine")
        self.assertEqual(self.manifest.get("frontend_commit"), EXPECTED_SHA)
        self.assertRegex(self.manifest.get("frontend_commit", ""), r"^[0-9a-f]{40}$")
        self.assertEqual(self.manifest.get("build_source"), "GitHub Actions checkout")
        self.assertEqual(self.manifest.get("status"), "UNVERIFIED_STATIC_FRONTEND")

    def test_both_dashboards_have_source_and_visible_sha(self):
        for name, html in (("dashboard.html", self.dashboard_html), ("dashboard_v2.html", self.dashboard_v2_html)):
            with self.subTest(name=name):
                meta = re.search(r'<meta name="trustguard-build-commit" content="([0-9a-f]{40})">', html)
                visible = re.search(r'<code id="build-commit">([0-9a-f]{40})</code>', html)
                self.assertIsNotNone(meta, f"{name}: missing valid build SHA metadata")
                self.assertIsNotNone(visible, f"{name}: missing visible build SHA")
                self.assertEqual(meta.group(1), EXPECTED_SHA)
                self.assertEqual(visible.group(1), EXPECTED_SHA)
                self.assertEqual(meta.group(1), visible.group(1))

    def test_index_and_both_dashboards_identify_the_same_build(self):
        for name, html in (
            ("index.html", self.index_html),
            ("dashboard.html", self.dashboard_html),
            ("dashboard_v2.html", self.dashboard_v2_html),
        ):
            with self.subTest(name=name):
                meta = re.search(r'<meta name="trustguard-build-commit" content="([0-9a-f]{40})">', html)
                visible = re.search(r'<code id="build-commit">([0-9a-f]{40})</code>', html)
                self.assertIsNotNone(meta, f"{name}: missing build metadata")
                self.assertIsNotNone(visible, f"{name}: missing visible build identity")
                self.assertEqual(meta.group(1), EXPECTED_SHA)
                self.assertEqual(visible.group(1), EXPECTED_SHA)
                self.assertEqual(meta.group(1), visible.group(1))

    def test_no_unexpanded_build_placeholder(self):
        for name in ("dashboard.html", "dashboard_v2.html", "index.html", "build-info.json"):
            with self.subTest(name=name):
                self.assertNotIn(PLACEHOLDER, (ROOT / name).read_text(encoding="utf-8"))

    def test_manifest_is_at_site_root_and_static_data_is_copied_unchanged(self):
        self.assertTrue((ROOT / "build-info.json").is_file(), "manifest must be at Pages artifact root")
        self.assertEqual(
            (ROOT / "hasil.json").read_bytes(),
            (ROOT.parent / "hasil.json").read_bytes(),
            "artifact must use the repository's unchanged fail-closed static data",
        )
        self.assertIn('fetch("hasil.json"', self.dashboard_html)
        self.assertIn('fetch("hasil.json"', self.dashboard_v2_html)
        self.assertEqual(self.data.get("source_status"), "UNVERIFIED")
        self.assertEqual(self.data.get("transaksi_terakhir", {}).get("authentication_status"), "UNKNOWN")
        self.assertEqual(self.data.get("transaksi_terakhir", {}).get("policy_status"), "UNKNOWN")
        self.assertEqual(self.data.get("transaksi_terakhir", {}).get("delivery_status"), "UNKNOWN")

    def test_no_legacy_transaction_ids_or_unverified_transaction_claim(self):
        combined = "\n".join((self.dashboard_html, self.dashboard_v2_html, json.dumps(self.data)))
        for marker in LEGACY_MARKERS:
            with self.subTest(marker=marker):
                self.assertNotIn(marker, combined)
        self.assertNotIn("Bukti Transaksi End-to-End (PayPal Sandbox)", combined)

    def test_no_unsupported_success_or_perfect_security_claims(self):
        for name, html in (("dashboard.html", self.dashboard_html), ("dashboard_v2.html", self.dashboard_v2_html)):
            for pattern in UNSUPPORTED_STATUS_PATTERNS:
                with self.subTest(name=name, pattern=pattern.pattern):
                    self.assertIsNone(pattern.search(html), f"{name}: unsupported claim matched {pattern.pattern}")
        # Safe explanatory prose is permitted and must not be treated as a claim.
        self.assertIn("tidak menyatakan tingkat keamanan sempurna", self.dashboard_html)
        self.assertIn("bukan pembayaran sukses atau capture", self.dashboard_v2_html)

    def test_static_data_fails_closed(self):
        self.assertEqual(self.data.get("source_status"), "UNVERIFIED")
        self.assertIsNone(self.data.get("timestamp"))
        trx = self.data.get("transaksi_terakhir", {})
        self.assertIsNone(trx.get("order_id"))
        self.assertEqual(trx.get("authentication_status"), "UNKNOWN")
        self.assertEqual(trx.get("policy_status"), "UNKNOWN")
        self.assertEqual(trx.get("delivery_status"), "UNKNOWN")
        self.assertIsNone(trx.get("merchant"))
        self.assertIsNone(trx.get("total"))
        self.assertEqual(self.data.get("audit_trail"), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)

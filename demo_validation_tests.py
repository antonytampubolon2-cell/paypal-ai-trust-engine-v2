"""Dependency-free tests for the offline synthetic demo contract."""
import unittest
from demo_snapshot import build_demo_snapshot
class DemoSafetyTests(unittest.TestCase):
 def test_explicit_simulation_and_no_real_payment(self):
  d=build_demo_snapshot();self.assertEqual(d["demo_mode"],"SIMULATED");self.assertFalse(d["external_provider_calls"]);self.assertFalse(d["real_payment_executed"]);self.assertEqual(d["statistics"]["real_payments"],0);self.assertEqual(d["latest_scenario"]["status"],"NOT_EXECUTED")
 def test_unknown_fails_closed(self):
  items=[e for e in build_demo_snapshot()["audit_trail"] if e["classification"]=="UNKNOWN_BLOCKED"];self.assertEqual(len(items),1);self.assertIn("FAIL_CLOSED",items[0]["result"]);self.assertIn("not attempted",items[0]["result"].lower())
 def test_external_verification_not_claimed(self):
  v=build_demo_snapshot()["verification_capabilities"];self.assertEqual(v["kyapay_issuer"],"UNVERIFIED");self.assertEqual(v["merchant_identity"],"UNVERIFIED");self.assertEqual(v["dpop_signature"],"UNVERIFIED");self.assertEqual(v["paypal_authorization"],"NOT_ATTEMPTED")
 def test_demo_entrypoint_is_offline_and_separate_from_payment_dispatcher(self):
  from pathlib import Path
  source=(Path(__file__).resolve().parent/"demo_snapshot.py").read_text(encoding="utf-8").lower()
  for marker in ("requests.","httpx.","urllib.request","urlopen(","paypal_client_secret","openai_api_key","paypal_agent_toolkit"):self.assertNotIn(marker,source)
 def test_dashboard_has_safe_rendering_and_artifact_contract(self):
  from pathlib import Path
  h=(Path(__file__).resolve().parent/"dashboard_demo.html").read_text(encoding="utf-8")
  self.assertIn("textContent",h);self.assertIn("build-info.json",h);self.assertIn("UNKNOWN_BLOCKED",h);self.assertNotIn("innerHTML",h.lower());self.assertNotIn("100%",h)
if __name__=="__main__":unittest.main()
